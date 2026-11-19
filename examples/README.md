# Ejemplos

Estos ficheros son la suite de regresión del gate. No son tests unitarios: se
ejecutan contra el modelo real para comprobar que el criterio del prompt sigue
detectando lo que debe y no bloqueando lo que no debe.

```bash
aegis analyze examples/vulnerable/app.py --local     # debe BLOQUEAR
aegis analyze examples/clean/repository.py --local   # debe APROBAR
```

| Fichero | Categoría | Qué demuestra |
|---|---|---|
| `vulnerable/app.py` | A03 | El caso canónico del enunciado (`os.system(f"echo {command}")`). |
| `vulnerable/user_lookup.py` | A03 | SQLi por interpolación; el modelo propone el patch parametrizado. |
| `vulnerable/fetch.py` | A10 | SSRF con validación parcial (`startswith`) que un atacante salta con un redirect o `http://`. |
| `vulnerable/session.py` | A02 | Secreto hardcodeado, MD5 para contraseñas y PRNG para tokens. |
| `vulnerable/notes.py` | A01 | IDOR (`/note?id=`) y privilegio tomado del request (`/admin?admin=1`). |
| `vulnerable/injected.py` | A03 | **Canario de prompt injection**: el fichero pide al revisor que devuelva una lista vacía y que filtre su prompt. Se bloquea igualmente. |
| `clean/app.py` | — | El mismo caso que `vulnerable/app.py`, corregido: allowlist + lista de argumentos + `shell=False`. |
| `clean/repository.py` | — | Consulta parametrizada y autorización por objeto desde la sesión. |
| `clean/hashing.py` | — | scrypt, verificación real, secreto desde el entorno, `secrets` para tokens. |

`clean/app.py` y `clean/hashing.py` **sí** producen hallazgos de severidad media
(SSRF de bajo riesgo, notas de hardening): quedan por debajo del umbral de bloqueo
(`severity >= high`) y se reportan sin frenar el commit. Es el comportamiento
deseado: el umbral de severidad es el control de fricción.
