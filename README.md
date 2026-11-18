# AEGIS — AppSec GenAI Integrity Sentinel

Gate de commits con análisis **server-side** de OWASP Top 10 usando un LLM, con
**atribución de identidad** (OAuth 2.0 Device Flow) y **attestations firmadas** que
permiten demostrar, en CI, que los commits que llegaron al remoto son exactamente
los que el analizador inspeccionó.

> **Estado:** paso 1 de N — fundamentos. Ver [Roadmap](#roadmap).

---

## El problema en una frase

Un `pre-commit` que llama a un LLM es fácil de escribir y fácil de evadir:

```bash
git commit --no-verify      # el hook nunca corre
git commit --amend          # analizaste A, pusheaste B
git rebase -i               # idem
# o el dev edita el prompt / usa su propio token
```

AEGIS trata el hook como **telemetría de conveniencia, no como el control**. El
control real es un digest canónico de los *objetos git* que se envían al remoto,
firmado por el servidor y verificado en CI. Bypassear el hook ya no oculta nada:
produce un commit sin attestation y CI lo rechaza.

```text
dev machine                          server-side                    CI (GitHub Actions)
───────────                          ───────────                    ───────────────────
git commit
   │
   ├─ hook: staged index ──► digest ──► POST /v1/analyze ──► LLM + SAST ──► veredicto
   │                                     (Bearer user token)      │
   │◄──────────── AnalyzeResponse + JWS attestation ──────────────┘
   │
   ├─ allow: escribe git note refs/notes/aegis → commit procede
   │
   └─ push ───────────────────────────────────────────────►  recomputa digest
                                                              verifica JWS (offline)
                                                              ¿coincide? allow : reject
```

---

## Documentación

| Documento | Contenido |
|---|---|
| [`docs/architecture.md`](docs/architecture.md) | Arquitectura, modelo de integridad, threat model, anti-evasión, escalabilidad, ADRs |
| [`docs/references/`](docs/references) | Enunciado original del challenge |
| `src/aegis/contracts.py` | Contrato congelado cliente ↔ servidor (fuente de verdad) |
| `src/aegis/canon.py` | Primitivas de canonicalización y digest (la base de la integridad) |

---

## Instalación (dev)

Requiere Python ≥ 3.11, [`uv`](https://docs.astral.sh/uv/) y `git`.

```bash
git clone https://github.com/jesierra20/aegis-gate.git
cd aegis-gate
uv sync --all-extras        # o: make install
uv run pre-commit install --install-hooks
```

Calidad local:

```bash
make lint      # ruff
make type      # mypy --strict
make test      # pytest + coverage
make check     # las tres anteriores (lo mismo que corre CI)
```

---

## Cobertura OWASP (objetivo: ≥ 3, entregamos 4)

| Categoría | Qué se detecta | Ejemplo canónico |
|---|---|---|
| **A03:2021** Injection | SQLi, command injection, `eval`/`exec`, SSTI, deserialización | `os.system(f"echo {user_input}")` |
| **A01:2021** Broken Access Control | IDOR, endpoints sin autorización, `is_admin` desde input del cliente | `user_id = request.args["id"]; return db.get(user_id)` |
| **A02:2021** Cryptographic Failures | hashes débiles, `md5`/`sha1` para passwords, `verify=False`, secretos hardcodeados | `hashlib.md5(password)` |
| **A10:2021** SSRF | `requests.get(url_from_user)`, validación por blacklist de hostnames | `requests.get(request.args["url"])` |

Las cuatro se eligen porque **requieren razonamiento de flujo de datos**: un
regex/semgrep encuentra el sink, pero no decide si el dato es controlable por el
atacante. Ahí es donde el LLM aporta sobre un linter determinista — y por eso el
pipeline es híbrido (SAST primero, LLM después).

---

## Publicar en GitHub

El repositorio ya está inicializado con un commit en `main`. Falta el remoto
(no hay credenciales de GitHub en esta máquina: `gh` no está instalado y no hay
clave SSH para `github.com`).

```bash
# Opción A — GitHub CLI (recomendada: crea el repo y hace el push)
brew install gh
git remote add origin https://github.com/jesierra20/aegis-gate.git   # o el nombre que uses
gh auth login
gh repo create aegis-gate --public --source=. --remote=origin --push

# Opción B — repo creado a mano en la web, luego push
git remote add origin git@github.com:<usuario>/aegis-gate.git
git push -u origin main
```

> **Antes del primer push**: `refs/notes/aegis` (donde vivirán las attestations,
> paso 5) no se pushea por defecto. Cuando el hook exista habrá que añadir
> `git push origin refs/notes/aegis` o configurar
> `remote.origin.push = refs/heads/*:refs/heads/*`. Está previsto en el diseño
> (ADR-006).

Una vez en GitHub, el workflow [`ci.yml`](.github/workflows/ci.yml) se ejecuta en
cada push y en cada PR. **No requiere secretos**: los jobs `quality` (pre-commit),
`tests` (matriz 3.11–3.13) y `digest-stability` (golden digest) son offline.

---

## Roadmap

- [x] **Paso 1 — Fundamentos**: contrato de datos, digest canónico, `errors`,
      scaffolding del repo, tooling (`ruff`/`mypy`/`pytest`), CI con pre-commit.
- [ ] **Paso 2 — Auth**: OAuth 2.0 Device Flow + emisión/validación de tokens +
      `aegis login`.
- [ ] **Paso 3 — Servidor**: FastAPI `POST /v1/analyze`, pipeline híbrido
      (SAST → LLM → validación estricta), prompts versionados, mitigación de
      prompt injection.
- [ ] **Paso 4 — Hook**: `aegis-hook` como `language: system`/`python` de
      pre-commit, render del mensaje de bloqueo, git notes.
- [ ] **Paso 5 — Integridad end-to-end**: firmado de attestations, verificación
      en `pre-push` y en GitHub Actions.
- [ ] **Paso 6 — Ejemplos y demo**: `examples/vulnerable/*` vs `examples/clean/*`,
      resultados esperados, monitoreo de evasiones.
- [ ] **Paso 7 — README final**: arquitectura, guía de uso, resumen técnico,
      análisis de resultados.

---

## Licencia

Apache-2.0.
