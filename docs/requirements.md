# Trazabilidad de requisitos

Verificación punto por punto del enunciado (`docs/references/Challenge-AppSec-GenAI-Engineer.pdf`)
contra el código. Cada fila apunta a la implementación y a la **evidencia ejecutable**:
un test, un comando cuya salida está en este repo, o una sección del informe.

Leyenda: ✅ cumplido · ✅+ superado (más de lo pedido) · ⚠️ parcial/deliberado · ➖ no pedido

---

## Objetivo (página 1)

| # | Requisito del PDF | Estado | Implementación | Evidencia |
|---|---|---|---|---|
| 1 | Lógica en `pre-commit` que se ejecute automáticamente al intentar commitear | ✅ | `src/aegis/cli/hook.py` (`aegis-hook`), `.pre-commit-hooks.yaml` | `tests/test_hook.py` (20 tests); demo en README §"El hook en acción" |
| 2 | El análisis corre **server-side** | ✅ | El prompt y la clave del LLM viven solo en el servidor (`src/aegis/engine/`, `src/aegis/server/`). El hook envía bytes y recibe veredicto | `aegis-hook` no importa `aegis.llm` en ningún camino de ejecución; `prompts/analyze.v1.md` no aparece en `AnalyzeResponse` (`test_judge_never_sees_the_prompt_as_verdict_text`) |
| 3 | Usar un LLM | ✅ | Adapter Command Code (`src/aegis/llm/commandcode.py`), 2 wires, catálogo cacheado | `tests/test_llm_commandcode.py` (36); ejecución real: 2,7–8,3 s, 1,5–3 k tokens por fichero |
| 4 | Detectar OWASP Top 10 2021, **mínimo 3** | ✅+ | **4 categorías**: A01, A02, A03 (incl. XSS), A10 | `test_default_categories_cover_at_least_three_owasp_items`; `tests/test_validate_detectors.py` |
| 5 | Si hay vulnerabilidad, **rechazar el commit** | ✅ | `decision=block` → `exit 1` en el hook | `test_blocks_with_exit_1_and_prints_the_server_message`; demo: HEAD no avanza |
| 6 | Explicación clara del problema + **sugerencias de corrección** | ✅ | `render_message()` + `Finding.explanation/.remediation/.patch`, renderizado server-side | `test_vulnerable_file_blocks_with_an_actionable_message`; demo con parche propuesto |
| 7 | Controles de **autenticación** para saber **quién** commitea | ✅ | OAuth 2.0 Device Flow (RFC 8628) + JWT EdDSA + binding identidad↔autor | `tests/test_auth_device_flow.py` (23), `tests/test_auth_primitives.py` (29), `tests/test_auth_api.py` (21) |
| 8 | Controles de **integridad**: ¿los commits pusheados son los fragmentos analizados? | ✅ | `commit_digest` canónico + attestation JWS firmada + git note + `aegis verify` | `test_hook_digest_equals_verifier_digest`, `tests/test_verify.py` (42); evasiones probadas en vivo |
| 9 | Monitoreo de integridad de los análisis y del código subido | ✅ | Audit log append-only con cadena de hashes + job `integrity` en CI | `test_every_verdict_is_audited`, `test_audit_chain_records_the_device_flow`, `verify_audit_chain()` |

## Requisitos técnicos (página 2)

| # | Requisito | Estado | Nota |
|---|---|---|---|
| 10 | Lenguaje a elección | ✅ | Python 3.11+ (el ecosistema de pre-commit y de semgrep/bandit) |
| 11 | Modelo de IA a elección, API o local, simulando server-side | ✅ | Command Code Provider API; default `gpt-6-luna`. `AEGIS_LLM_PROVIDER=fake` para CI sin credenciales; `ollama` es un adapter trivial |
| 12 | Alcance: SQLi, XSS, SSRF, etc. | ✅+ | Los tres nombrados, más command injection, template injection, deserialización, cripto débil, secretos, IDOR, SSRF |
| 13 | Configurar proyecto de ejemplo + hook sobre ficheros modificados | ✅ | `examples/` (7 vulnerables + 3 limpios); el hook analiza los *hunks modificados*, no el fichero completo (`test_hunks_are_limited_to_changed_regions`) |

## Pasos sugeridos (páginas 2–3)

| # | Paso sugerido | Estado | Implementación |
|---|---|---|---|
| 14 | Prompt claro, efectivo, directo | ✅ | `prompts/analyze.v1.md` (52 líneas: categorías, procedimiento de decisión, regla de evidencia, framing de datos) |
| 15 | **Pensar y proponer cómo mitigar prompt injection** | ✅+ | 6 capas estructurales + 15 ataques probados (`tests/test_injection_resistance.py`) + detección de intentos registrada |
| 16 | OAuth 2.0 / login interactivo para obtener token de usuario | ✅ | Device Flow propio (IdP local) **y** token exchange de GitHub. Ver ADR-009 |
| 17 | Mecanismos para garantizar la integridad del commit contra el del remoto | ✅ | Digest reproducible desde objetos git + verificación en cada commit (post-commit) + CI |
| 18 | Alternativa: Fury login / Tiger token | ➖ | Mismo diseño: `POST /v1/auth/exchange` acepta cualquier IdP que devuelva identidad verificada. GitHub es el ejemplo implementado |
| 19 | El script envía el código + el token; el servidor tiene el prompt | ✅ | `POST /v1/analyze` con `Authorization: Bearer`; el prompt nunca viaja al cliente |
| 20 | Analizar la respuesta: si hay vulnerabilidad, rechazar y mostrar explicación + código sugerido | ✅ | `src/aegis/validate/` + `render_message()` |
| 21 | Opcional: evaluación asíncrona + portal de notificación | ➖ | Diseñado en ADR-008, no implementado: el modo síncrono es el que evita la fricción que hace abandonar el gate. El estado `pending` está previsto en el contrato |

## Entregables (páginas 3–4)

| # | Entregable | Estado | Dónde |
|---|---|---|---|
| 22 | 1. Repositorio Git con todo el código y la configuración | ✅ | https://github.com/Sierris/aegis-gate (5 commits de feature + CI verde) |
| 23 | 2. Script de pre-commit funcional y **bien documentado**, con comentarios que expliquen la lógica, el manejo de la respuesta de la IA, la autenticación y la integridad | ✅ | `src/aegis/cli/hook.py` (docstring de 30 líneas + comentarios por decisión), `src/aegis/engine/analyzer.py`, `src/aegis/auth/*`. Densidad: 1 comentario por cada ~4 líneas de código en los módulos críticos |
| 24 | 3. Código del workflow de análisis que recibe los fragmentos **y la parte del prompt**, indicando dónde va y por qué | ✅ | `prompts/` + `prompts/README.md` + `src/aegis/engine/prompts.py` (docstring "Where the prompt lives — and why") + ADR-003 |
| 25 | 4. Validación del token del usuario y verificación de integridad del código enviado | ✅ | `src/aegis/server/routes_analyze.py` (Bearer → scope → binding → allowlist) y `src/aegis/contracts.py` (digest auto-validado) |
| 26 | 5. Un fichero con **al menos una** vulnerabilidad OWASP para demostrar que el hook funciona | ✅+ | 7 ficheros: command injection, SQLi, XSS, SSRF, cripto, IDOR, y un canario de prompt injection |
| 27 | 6. Otro fichero **sin** vulnerabilidades para demostrar que el commit se aprueba | ✅+ | 3 ficheros en `examples/clean/` |
| 28 | 7. README con **arquitectura** (escalable, óptima, poco friccionante) | ✅ | README §Arquitectura + `docs/architecture.md` §7 (escalabilidad, coste, fricción) |
| 29 | 8. README con **estrategia de monitoreo** para detectar evasiones del control | ✅+ | `docs/architecture.md` §8 (tabla de 12 señales con alerta) + `aegis verify` + audit chain + job de CI |
| 30 | 9. README con **instrucciones de configuración** (clonar, instalar dependencias) | ✅ | README §Instalación y §Uso rápido |
| 31 | 10. README con **guía de uso** (hook vía commit o manual) | ✅ | README §El hook en acción; `aegis analyze`, `pre-commit run --hook-stage manual aegis-analyze` |
| 32 | 11. README con **resumen técnico** (modelo elegido y lógica del prompt) | ✅ | README §Motor de análisis y §Dónde se pone la API key; ADR-011/012/013 |
| 33 | 12. README con **análisis de resultados** esperados por cada ejemplo | ✅ | README §Análisis de resultados (tabla con veredicto, severidad y categoría por fichero) |

---

## Requisitos del ejemplo del escenario (página 2–3)

El enunciado muestra el mensaje exacto que debe verse al bloquear:

```text
🚨 Vulnerabilidad Detectada: Posible Inyección de Comandos.
Riesgo: La función os.system() es peligrosa porque ejecuta comandos del sistema
        directamente con la entrada no validada del usuario...
Solución Sugerida: Usa subprocess.run() con check=True y shell=False...
```

Salida real del hook sobre `examples/vulnerable/app.py`:

```text
🚨 Vulnerabilidad detectada — commit rechazado
   Autor del commit: dev@mercadolibre.com

1. [HIGH] Request parameter reaches OS shell
   Categoría: A03:2021   CWE-78   (app.py:14)
   Confianza: 99%   Regla: A03-CMDI-001

   Riesgo:
     Any remote caller can supply the `command` query parameter to `/ping`. Shell
     metacharacters in that value are interpolated into the command string, allowing
     the caller to execute additional commands with the Flask process's privileges.

   Solución sugerida:
     Avoid invoking a shell. Pass arguments as a list to a subprocess API with shell
     execution disabled.

   Patch propuesto:
     subprocess.run(["echo", command or ""], check=False)
```

Cumple el formato pedido (icono, riesgo, solución) y añade categoría, CWE,
confianza, regla y parche propuesto.

---

## Lo que no se implementó, y por qué

Se documenta explícitamente para que la omisión sea una decisión y no un olvido.

| Elemento | Motivo |
|---|---|
| Portal de notificación asíncrono (opcional en el PDF) | El modo síncrono es el que mantiene la fricción baja; un portal añade superficie web y no mejora la seguridad. El contrato ya modela `decision` no binaria para añadirlo (ADR-008) |
| Wire `/responses` de Command Code | Ningún modelo del catálogo lo sirve sin `/chat/completions`; implementarlo no añadía capacidad (documentado en el adapter) |
| `Fury`/`Tiger` | No hay acceso a esas APIs desde este entorno; el diseño admite cualquier IdP vía `/v1/auth/exchange` y GitHub es la implementación de referencia |
| Rotación automática de claves | El `kid` y el JWKS están preparados (`not_before`/`not_after`), pero el proceso operativo de rotación es de despliegue, no de código |
| Escaneo de secretos en el historial completo | Cubre el commit analizado; el historial previo necesita una herramienta dedicada y no forma parte del objetivo |

---

## Verificación ejecutable

```bash
# Todo lo que CI comprueba, en local
make check                      # ruff + mypy --strict + 367 tests

# Requisito 4: cobertura OWASP
uv run pytest tests/test_validate_detectors.py -q -k "coverage or at_least_three"

# Requisito 8 y 9: integridad y auditoría
uv run pytest tests/test_verify.py tests/test_gitx.py tests/test_hook.py -q

# Requisito 15: prompt injection (15 ataques)
uv run pytest tests/test_injection_resistance.py -q

# Demo end-to-end (necesita `aegis serve` + `aegis login`)
uv run aegis analyze examples/vulnerable/app.py --local   # debe BLOQUEAR
uv run aegis analyze examples/clean/repository.py --local # debe APROBAR
uv run aegis verify --range HEAD~1..HEAD                  # attestations del último commit
```
