# Informe de implementación

Documento de nivel de desarrollador: qué se construyó, cómo funciona por dentro, qué
se decidió y por qué, qué se rompió por el camino y qué queda fuera.

**Estado**: 5 de 5 pasos del roadmap completados · 376 tests · `ruff` y `mypy --strict`
limpios · CI verde en 3 versiones de Python.
**Verificación de requisitos**: [`docs/requirements.md`](requirements.md)
**Decisiones arquitectónicas**: [`docs/architecture.md`](architecture.md) (16 ADRs)

---

## 1. Resumen en una página

AEGIS es un gate de commits que analiza el contenido staged con un LLM **en el
servidor**, bloquea el commit si encuentra una vulnerabilidad del OWASP Top 10, y
adjunta al commit una **attestation firmada** que CI verifica de forma offline.

La tesis de diseño: **el cliente es hostil**. Un `pre-commit` que llama a un LLM es
trivial de evadir (`--no-verify`, `amend`, rebase, hook manipulado). Por eso el hook
es *telemetría de conveniencia* y el control real es la verificación en CI de un
digest canónico firmado por el servidor. Bypassear el hook no oculta nada: produce un
commit sin attestation y CI lo rechaza.

| Métrica | Valor |
|---|---|
| Líneas de código (`src/`) | 10.368 |
| Líneas de test (`tests/`) | 5.391 |
| Tests | 376 (32 % del código productivo en tests) |
| Cobertura | 81 % global; 87–99 % en los módulos de seguridad |
| Categorías OWASP | 4 (requisito: 3) |
| Ataques de prompt injection probados | 15 |
| Fallos de regresión documentados | 14 |
| Latencia por fichero analizado | 2,7 – 8,3 s · 1,5 – 3 k tokens |

---

## 2. Arquitectura implementada

```text
┌── Máquina del desarrollador ───────────────────────────────────────────────┐
│  git commit                                                                │
│    └─ pre-commit ──► aegis-hook                                            │
│         · lee el ÍNDICE (no el working tree)                                │
│         · StagedFile[] + CodeFragment[] por hunk                            │
│         · commit_digest = sha256(canon v2)                                  │
│         ├─► POST /v1/analyze  (Bearer de usuario)                           │
│         └─ block → exit 1 · allow → .git/aegis/pending.json                 │
│  git commit (fin) ──► post-commit ──► aegis-attest                          │
│         · recalcula el digest del commit REAL                               │
│         · si coincide → git note refs/notes/aegis                           │
│  git push ──► pre-push ──► aegis-pre-push (mismo verificador que CI)         │
└────────────────────────────────────────────────────────────────────────────┘
                    │ HTTPS                        ▲ JWS verificado con JWKS
                    ▼                              │
┌── Servidor ───────────────────────────────────┐   │
│  POST /v1/analyze                             │   │
│   Bearer → scope → binding → allowlist        │   │
│   → engine:                                   │   │
│      ① normalización (topes, exclusiones)     │   │
│      ② prefilter determinista (13 reglas)     │   │
│      ③ LLM (Command Code)                     │   │
│      ④ validación estricta + anclaje          │   │
│      ⑤ política (severidad ∧ confianza)       │   │
│   → attestation JWS EdDSA + audit chain       │   │
└───────────────────────────────────────────────┘   │
┌── CI (GitHub Actions) ────────────────────────────┴────────────────────────┐
│  job integrity: para cada commit del push                                   │
│    1. recalcula commit_digest desde el objeto git                           │
│    2. lee refs/notes/aegis                                                  │
│    3. verifica el JWS (offline, sin llamar al servidor)                     │
│    4. compara digest ∧ aud ∧ decisión ∧ expiración                          │
└─────────────────────────────────────────────────────────────────────────────┘
```

---

## 3. Módulo por módulo

### 3.1 `canon.py` — el digest canónico (409 líneas)

El primitivo sobre el que descansa todo. Produce el digest de un commit a partir
**solo de datos de objeto git**:

```text
aegis-commit-digest
version=aegis-digest/v2
repo=github.com/mercadolibre/appsec-demo
parent=<sha40|->
author=dev@mercadolibre.com
files=2
file A 100644 <sha256> src/app.py
file M 100755 <sha256> src/lib/x.sh
```

Propiedades exigidas y su razón:

| Propiedad | Por qué |
|---|---|
| Solo datos de objeto git | cliente (`diff --cached`) y servidor (`diff parent commit`) derivan lo mismo sin confiar uno en otro |
| SHA-256 del **contenido** del blob, no el OID | independiente del formato de objeto (SHA-1 vs SHA-256) |
| Ordenado | APFS, ext4 y NTFS iteran distinto |
| Sin timestamps | rebase/cherry-pick cosmético no invalida la attestation |
| Sin el texto del diff | el render de hunks depende de la versión de git |
| Sin el mensaje del commit (v2) | **no es observable en pre-commit** (ver §5.1) |
| Valor dorado en un test | cambiar el formato rompe CI por su nombre |

Funciones auxiliares: `normalize_repo_id` (5 sintaxis de remote → un id estable,
incluye SCP-like y rutas locales), `normalize_path` (NFC, sin `..`, sin NUL),
`canonical_json`, `chain_hash` (cadena de auditoría).

### 3.2 `contracts.py` — el contrato congelado (736 líneas)

Modelos pydantic v2 con `extra="forbid"` y `frozen=True`: un campo desconocido es un
error, no un privilegio escalado silencioso. 30+ modelos: `AnalyzeRequest`,
`AnalyzeResponse`, `Finding`, `AttestationClaims`, device flow, auditoría,
verificación.

Detalle interesante: `AnalyzeRequest` **se auto-valida** recalculando su propio
`commit_digest` desde `files`. Un hook con un bug de digest falla en local, antes de
gastar tokens o escribir auditoría.

### 3.3 `auth/` — identidad y tokens (2.591 líneas)

| Fichero | Contenido |
|---|---|
| `keys.py` | Ed25519: carga/creación atómica, modo 0600 verificado (si alguien lo amplió, **falla**: es un incidente, no un bug), `kid` = hash de la clave pública |
| `jwt.py` | JWT EdDSA con allowlist literal de algoritmo; tiempos verificados con reloj inyectable (PyJWT lee `datetime.now()` y eso no es testeable) |
| `service.py` | Device Flow RFC 8628: `slow_down` acumulativo persistido, single-use, rotación de refresh con **detección de reuso** que revoca la familia |
| `store.py` | SQLite con `device_code`/refresh **hasheados**; audit log encadenado con `chain_hash` |
| `provider.py` | IdP `local` (scrypt con parámetros autodescriptivos, anti-enumeración por tiempo constante) y `github` (token exchange exigiendo e-mail verificado y primario) |
| `binding.py` | `token.email == commit.author.email`, normalizado con el mismo helper que el digest |
| `client.py` | Cache de token: keyring → fichero 0600 atómico; comprueba permisos y falla si están ampliados |

### 3.4 `detectors/` — el suelo determinista (644 líneas)

13 reglas regex sobre 4 categorías, **en proceso** (no semgrep: el hook está en el
camino crítico y semgrep cuesta segundos por commit). Tres funciones:

1. **suelo**: se detecta aunque el modelo esté caído o manipulado;
2. **grounding**: las anclas se pasan al modelo con número de línea;
3. **cross-check**: si el modelo dice "limpio" y hay un ancla de alta confianza, el
   análisis se marca `degraded` y bloquea.

Diseño de reglas no obvio: `Rule` tiene `suppress_if` (el arreglo no debe disparar),
`all_of` (conjunción imposible de expresar en un regex: "hay SQL **y** interpolación")
y `also_fires_on` (la interpolación es evidencia por sí misma). Sin ellos, las reglas
marcaban `subprocess.run([...], shell=False)` — el remedio — como vulnerabilidad.

También detecta intentos de manipular al revisor (override de instrucciones, role
switch, exfiltración del prompt, falso "approved by AppSec") y los **registra sin
borrarlos**: borrarlos destruiría la evidencia.

### 3.5 `llm/` — el adapter de Command Code (842 líneas)

`base.py` define el protocolo (una llamada, sin tools, sin streaming, sin estado).
Nada de eso es casualidad: sin herramientas no hay acción posible; sin estado no hay
envenenamiento de turnos; sin streaming no hay estado a medio parsear.

`commandcode.py` implementa Chat Completions y Anthropic Messages, elige el wire por
`supported_endpoints` del catálogo (cacheado 15 min) y resuelve la credencial en 4
pasos con **procedencia visible**.

Tres hallazgos operativos que costaron depuración real (ver §5.3).

### 3.6 `engine/` — la orquestación (1.364 líneas)

`analyzer.py` es el orden del pipeline, y el orden **es** el argumento de seguridad:

| Etapa | ¿Puede bloquear? | ¿Puede desbloquear? |
|---|---|---|
| exclusiones, topes de tamaño | no | — |
| anclas deterministas | **sí** | no |
| findings del LLM | **sí** | no |
| schema + anclaje de evidencia | no (solo descarta) | no |
| política | **sí** | no |
| `fail_mode` | **sí** | no |

`prompts.py` carga el prompt y **valida su consistencia**: falla si falta el bloque
de "datos ≠ instrucciones", si el prompt está truncado (<800 chars) o si el schema
permite una categoría que el prompt no menciona. `prompt_version` es el hash del
contenido, no un número a mano.

`cache.py` cachea veredictos por `(payload, prompt_version, modelo, huella de
política)`; los `degraded` no se cachean (dependen de una condición transitoria) y la
attestation **nunca** se reutiliza (reutilizaría `jti` e `iat`).

### 3.7 `validate/` — la frontera de seguridad (349 líneas)

Donde se gana o se pierde la resistencia a inyección. Cinco puertas: forma (JSON, no
prosa), schema cerrado, vocabularios cerrados, **anclaje de evidencia** (cada finding
debe citar una subcadena literal del fragmento enviado) y política.

El anclaje es la puerta que más aporta: elimina los hallazgos inventados, los
números de línea falsos y las citas de código que nunca se envió — los tres
resultados más comunes de una inyección exitosa.

### 3.8 `gitx/` — plumbing de git (657 líneas)

`repo.py` habla con los comandos de plumbing cuyo formato es contrato estable.
Decisiones que importan:

- **Lee el índice, no el working tree**: el índice es lo que se commitea.
- **Sanea `GIT_DIR`/`GIT_INDEX_FILE`**: git los pone durante rebase y en worktrees.
  Sin esto, el hook analizaba el repo equivocado (`test_foreign_git_env_...`).
- **`classify_change` compartido** entre hook y verificador: un `chmod` es `M` con
  oids idénticos, y dos implementaciones de "qué entra en el digest" es cómo un
  verificador se separa de lo que verifica.
- **Solo hunks cambiados + contexto**: `test_hunks_are_limited_to_changed_regions`
  exige que 100 líneas con un cambio envíen <60.

`verify.py` (gitx) expone `commit_digest(sha)` — la ruta del verificador — y
`resolve_range`/`all_commits`. `resolve_range` **lanza** si el rango es inválido:
devolver `[]` convertía un typo en CI en un verde global.

### 3.9 `attest/` — firmado y verificación (566 líneas)

`signer.py`: JWS compacto EdDSA con `commit_digest`, `payload_sha256`,
`findings_sha256`, `prompt_version`, modelo, scope y referencia al audit log.

`verify.py`: verificación offline con JWKS. Orden de comprobaciones (cada una para un
ataque concreto): allowlist de algoritmo → firma por `kid` → issuer → audiencia (repo)
→ vigencia temporal → `commit_digest` recalculado → decisión permitida → `commit_sha`
si está presente.

El `kid` se **deriva de la clave pública**: un JWKS donde el `kid` no corresponda a su
clave se rechaza al cargar, o dos claves podrían reclamar el mismo id.

### 3.10 `server/` y `cli/` (1.890 líneas)

FastAPI con 11 endpoints. El orden de `/v1/analyze` es deliberado: token → scope →
binding → allowlist → motor, para no gastar tokens en commits no autorizados.

CLI: `login`, `logout`, `whoami`, `token`, `doctor`, `analyze`, `models`, `verify`,
`keys show|export`, `user add|list`, `serve`, más los tres hooks `aegis-hook`,
`aegis-attest`, `aegis-pre-push`.

---

## 4. Los datos: qué se midió

### 4.1 Ejemplos, ejecución real con `gpt-6-luna`

| Fichero | Veredicto | Hallazgos | Categoría | Latencia |
|---|---|---|---|---|
| `vulnerable/app.py` | 🚨 BLOCK | 1 (0.99) | A03 command injection | 4,0 s |
| `vulnerable/user_lookup.py` | 🚨 BLOCK | 1 (0.99) | A03 SQLi + patch | 2,8 s |
| `vulnerable/xss.py` | 🚨 BLOCK | 1 (0.99) | A03 XSS (CWE-79) | 3,1 s |
| `vulnerable/fetch.py` | 🚨 BLOCK | 1 | A10 SSRF (bypass de `startswith`) | 2,7 s |
| `vulnerable/session.py` | 🚨 BLOCK | 4 | A02 secretos, MD5, PRNG | 8,2 s |
| `vulnerable/notes.py` | 🚨 BLOCK | 2 | A01 IDOR + admin desde request | 3,9 s |
| `vulnerable/injected.py` | 🚨 BLOCK | 1 | A03 SQLi **ignorando** la inyección | 3,1 s |
| `clean/app.py` | ✅ ALLOW | 0 | — | 4,9 s |
| `clean/repository.py` | ✅ ALLOW | 0 | — | 1,5 s |
| `clean/hashing.py` | ✅ ALLOW | 0 | — | 3,2 s |

### 4.2 Evasiones, probadas en vivo

| Evasión | Resultado observado |
|---|---|
| `git commit --no-verify` | commit creado, **sin attestation**; `aegis verify` → `missing_attestation`, exit 5 |
| `amend` tras un `allow` | commit nuevo sin nota; el digest cambió |
| Analizar A y commitear B con `--no-verify` | `post-commit` compara digests, no coincide y **no ancla** nada |
| `git push` con un commit sin attestation | `pre-push` falla con exit 5 y el push se aborta |
| Servidor caído | `fail_mode=closed` bloquea con explicación; `open` permite dejando constancia |
| Nota falsificada (otra clave) | `unknown_key` |
| Attestation de otro repo | `wrong_audience` |
| Attestation expirada | `expired` |

### 4.3 Prompt injection: 15 ataques, todos contenidos

`tests/test_injection_resistance.py`. La propiedad demostrada **no** es "el modelo
resiste", es: *ningún comportamiento aislado del modelo puede convertir un commit
vulnerable en un allow*.

El caso más interesante es el más barato: `{"findings": []}` es schema-válido, no
tiene evidencia y pasa todos los validadores. Solo lo detecta el cross-check
determinista, porque el regex no lee comentarios como instrucciones.

Dos endurecimientos que salieron de escribir esos tests:

- **Rebajar la severidad** del hallazgo real no silencia el ancla (la cobertura exige
  confirmación *bloqueante*).
- **Reportar otra categoría** para "colaborar" tampoco (la cobertura es por categoría
  del ancla).

---

## 5. Fallos encontrados y corregidos

Esta sección existe porque los bugs que aparecen al *ejecutar* son los que enseñan
dónde estaba mal el diseño. Todos tienen test de regresión.

### 5.1 Fallos de diseño (detectados por tests o por la demo)

| # | Fallo | Cómo se detectó | Corrección |
|---|---|---|---|
| 1 | El digest v1 incluía el mensaje del commit | Paso 4: en `pre-commit` no existe `.git/COMMIT_EDITMSG`, y tras un commit contiene el mensaje **anterior** | `aegis-digest/v2` sin mensaje (ADR-014). El valor dorado del test **forzó** el bump |
| 2 | La attestation se escribía en `HEAD` desde pre-commit | Demo: `git notes show HEAD` decía "no note found" | Dos stages: pre-commit deja pendiente, post-commit ancla tras verificar (ADR-015) |
| 3 | `head_sha()` no saneaba el entorno | `test_foreign_git_env_does_not_redirect_the_repo` | Con `GIT_DIR` (rebase), el hook creía ser el primer commit y analizaba el repo entero |
| 4 | `normalize_repo_id` trataba `git@host:owner/repo` como puerto | Test parametrizado | Dos repos compartían audiencia de attestation → cross-repo replay |
| 5 | `normalize_repo_id` lanzaba `ValueError` con un remote de ruta local | Demo: push con remote `/tmp/...git` mostraba un traceback | Ruta local → `file/<path>`; remotes no parseables se saltan |
| 6 | `resolve_range` devolvía `[]` ante un rango inválido | Al escribir el fixture de tests | Ahora lanza: un typo en CI era un verde global |
| 7 | El signer emitía una claim `cat` que el propio contrato rechazaba (`extra=forbid`) | `test_full_signer_integration` | La claim pasa a ser campo del contrato |
| 8 | Un finding rebajado a severidad baja silenciaba el ancla | `test_low_confidence_finding_is_reported_but_not_blocking` | La cobertura exige confirmación bloqueante |
| 9 | `subprocess.run([...], shell=False)` — el remedio — disparaba la regla | `test_safe_subprocess_list_does_not_fire` | `suppress_if` por regla |
| 10 | `%s` (placeholder) se confundía con interpolación en SQL | `test_parameterised_sql_does_not_fire` | `all_of` con marcador de interpolación real |
| 11 | `aegis logout` no revocaba en el servidor | Demo + consulta a la DB | Un `204` sin cuerpo se interpretaba como error; la excepción se tragaba con `suppress` |
| 12 | Cada análisis hacía 2 peticiones (catálogo + inferencia) | Test del adapter con transporte inyectado | Catálogo cacheado 15 min |
| 13 | `python-multipart` no estaba declarado | Un re-resolve de uv rompió la página del device flow | Declarado en el extra `server` |
| 14 | Fuga de conexiones SQLite | CI solo en py3.13 (`unraisable exception`) | Protocolo de contexto + `__del__` best-effort |
| 15 | `check-yaml` falló con un hook local sin `name` | Demo de instalación | Corregido el manifiesto de ejemplo |

### 5.2 Fallos de seguridad encontrados en el propio proceso

- **XSS reflejado** en `/device?user_code=`: el código se interpolaba en un atributo
  HTML. Ahora se escapa y hay test.
- **Oráculo de enumeración** en la página de aprobación: distinguía "código
  inexistente" de "contraseña incorrecta". Ahora un único mensaje; el motivo real va
  al log.
- **`alg: none` y confusión HS256/EdDSA**: no "mitigados", sino inexpresables con una
  allowlist literal. Tests que construyen el token a mano (un atacante escribe bytes,
  no llamadas a PyJWT).
- **README con secretos ficticios** → GitHub Push Protection rechazó el push. Dos
  controles en conflicto resueltos haciendo el valor inerte, no pulsando "unblock".

### 5.3 Fallos de integración con la API real

| Síntoma | Causa real | Resolución |
|---|---|---|
| `403` que parecía auth | Cloudflare `error code: 1010`: sin `User-Agent` reconocible | UA obligatorio + traducción del 403 a un mensaje que lo explica |
| `content` vacío | Modelo de razonamiento agotando `max_tokens` en su canal de razonamiento | `TRUNCATED` → `fail_mode`; un `content` vacío **nunca** es un allow |
| `403 MODEL_NOT_IN_PLAN` | Entitlement por modelo (`claude-*` requiere Pro) | Error de despliegue no reintentable + `aegis models` lista lo que el plan sirve |

### 5.4 Un falso positivo que no lo era

La primera versión de `examples/clean/hashing.py` fue **bloqueada** con un A01 "login
emite token sin autenticar". El modelo tenía razón: el ejemplo no verificaba la
contraseña. Se corrigió el ejemplo, no la regla. Es el mejor argumento disponible de
que el gate detecta fallos reales en vez de patrones.

---

## 6. Decisiones y sus contrapartidas

Las 16 ADRs están en [`docs/architecture.md`](architecture.md). Las cuatro con más
consecuencias:

1. **Digest sobre blobs, no sobre el diff** (ADR-001): reproducible entre versiones de
   git, pero obliga al verificador a recalcular desde objetos y no a confiar en la nota.
2. **`fail_mode=closed`** (ADR-005): el fallo más probable (servidor caído) no se
   convierte en bypass global, pero exige que el override sea rápido o el equipo
   aprenderá `--no-verify`.
3. **Prompt en ficheros versionados** (ADR-003): revisable por PR y auditable por hash,
   a costa de exigir revisión de AppSec para cada cambio de criterio.
4. **Caché de veredictos, nunca de attestations** (ADR-013): el hook no paga latencia
   dos veces, y cada respuesta lleva una prueba fresca.

---

## 7. Deuda técnica conocida

| Deuda | Impacto | Mitigación |
|---|---|---|
| `store.py` usa un lock global y una conexión | ~decenas de análisis/s | Documentado: escalar requiere un escritor único para la cadena de auditoría |
| El prefilter es sintáctico | No detecta flujos entre ficheros | Es el suelo, no el detector: el LLM cubre la semántica (ADR-011) |
| El prompt no cubre A04–A09 | Fuera del alcance elegido | Añadir categorías = editar el prompt + el schema; el test de consistencia lo exige |
| No hay rotación automática de claves | Operativo | `kid` + JWKS preparados para convivencia de claves |
| El modo asíncrono no está implementado | Opcional en el enunciado | El contrato ya modela `decision` no binaria (ADR-008) |
| Cobertura del CLI baja | Riesgo de regresión en UX | Los caminos críticos están cubiertos por los tests de hook y verify |

---

## 8. Cómo reproducir todo

```bash
git clone https://github.com/Sierris/aegis-gate && cd aegis-gate
uv sync --all-extras --group dev
uv run pre-commit install --install-hooks

make check                     # ruff + mypy --strict + 376 tests

# servidor + identidad
cp .env.example .env           # añade AEGIS_LLM_API_KEY o usa ~/.commandcode/auth.json
uv run aegis serve &           # crea la clave Ed25519 y la DB en .aegis/
uv run aegis user add --email dev@mercadolibre.com --name "Tu Nombre"
uv run aegis login
uv run aegis doctor            # identidad, modelo y de dónde sale la API key

# demo de detección
uv run aegis analyze examples/vulnerable/app.py --local     # BLOQUEA
uv run aegis analyze examples/clean/repository.py --local   # APRUEBA

# demo del gate completo en un repo de consumidor
# (ver README §"El hook en acción")
```

---

## 9. Cronología

| Paso | Commit | Contenido | Tests al cierre |
|---|---|---|---|
| 1 | `579e830` | Contrato congelado + digest canónico + tooling + CI | 67 |
| — | `2665e98`, `563db4f` | Licencia, single-source de versiones, `.gitignore` | 67 |
| 2 | `0b8a677` | OAuth 2.0 Device Flow, JWT EdDSA, binding, auditoría, CLI, API | 155 |
| — | `f4d7f81` | Fix de CI (`--all-extras`) | 155 |
| 3 | `5b009e0` | Motor GenAI: Command Code, prefilter, validación, prompts, ejemplos | 281 |
| — | `6f912fb` | Push Protection y su resolución | 281 |
| — | `7c8ebf1` | Fuga de conexiones SQLite (py3.13) | 281 |
| 4 | `9fd4159` | Hook pre-commit + post-commit, gitx, digest v2 | 325 |
| 5 | *(este)* | Verificación offline, `aegis verify`, pre-push, XSS, job `integrity` | 376 |

---

## 10. Qué miraría un revisor (y dónde está la respuesta)

| Pregunta típica | Dónde está la respuesta |
|---|---|
| "¿Esto no se evade con `--no-verify`?" | §4.2 + `aegis verify` + job `integrity` |
| "¿Y si el LLM alucina?" | Anclaje de evidencia (§3.7) + cross-check determinista (§3.4) |
| "¿Y si le meto un comentario al modelo?" | §4.3, 15 ataques, 6 capas estructurales |
| "¿El prompt está en el cliente?" | No: `prompts/` solo en el servidor; test que lo comprueba |
| "¿Cómo sé que el commit es el que se analizó?" | `commit_digest` + attestation + recálculo en post-commit y en CI |
| "¿Qué pasa si el servidor está caído?" | `fail_mode` (§4.2), con override firmado en lugar de `--no-verify` |
| "¿Esto escala?" | `docs/architecture.md` §7: caché, presupuesto de latencia, degradación |
| "¿Cómo detecto que alguien lo está evadiendo?" | `docs/architecture.md` §8: 12 señales con alerta + canary commits |
