"""``aegis`` — the developer/admin CLI.

Commands (step 2 scope):

    aegis login       device flow, stores the refresh token
    aegis logout      revokes server-side and wipes the cache
    aegis whoami      prints the authenticated identity and scopes
    aegis token       prints a usable access token (for scripts/CI)
    aegis doctor      checks cache permissions, server reachability, key fingerprint
    aegis user add    creates a local-provider user (server-side, same machine)
    aegis keys        prints the JWKS and the local key id
    aegis serve       runs the API server (convenience wrapper)

Exit codes are documented in ``aegis.errors``; ``aegis`` never exits 0 on error.
"""

from __future__ import annotations

import argparse
import getpass
import json
import sys
from pathlib import Path

import httpx

from aegis import __version__
from aegis.auth.client import AuthClient, cache_mode_report
from aegis.auth.provider import LocalIdentityProvider
from aegis.auth.store import AuthStore
from aegis.config import get_client_settings, get_server_settings
from aegis.errors import AegisError
from aegis.llm.commandcode import resolve_api_key_source
from aegis.server.main import main as server_main

PROG = "aegis"


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog=PROG, description="AEGIS · AppSec GenAI commit gate")
    p.add_argument("--version", action="version", version=f"{PROG} {__version__}")
    sub = p.add_subparsers(dest="command", required=True)

    login = sub.add_parser("login", help="autenticarse con OAuth 2.0 Device Flow")
    login.add_argument("--scope", default="analyze", help="scopes solicitados (default: analyze)")
    login.add_argument("--no-browser", action="store_true", help="no intentar abrir el navegador")

    sub.add_parser("logout", help="revocar el token y limpiar la cache local")
    sub.add_parser("whoami", help="mostrar identidad y scopes del token")
    sub.add_parser("token", help="imprimir un access token válido")
    sub.add_parser("doctor", help="diagnóstico del entorno cliente")

    analyze = sub.add_parser("analyze", help="analizar un fichero (server-side o --local)")
    analyze.add_argument("path", type=Path, help="fichero a analizar")
    analyze.add_argument("--local", action="store_true", help="ejecutar el motor en proceso")
    analyze.add_argument("--json", action="store_true", help="salida JSON completa")

    models = sub.add_parser("models", help="listar modelos disponibles de Command Code")
    models.add_argument("pattern", nargs="?", default=None, help="filtro por substring")

    verify = sub.add_parser("verify", help="verificar attestations de un rango de commits")
    verify.add_argument("--range", dest="range_spec", default=None, help="A..B (default: upstream..HEAD)")
    verify.add_argument("--jwks", default=None, help="fichero o URL del JWKS de confianza")
    verify.add_argument("--issuer", default=None, help="issuer esperado (default: el del .env)")
    verify.add_argument(
        "--report-only",
        action="store_true",
        help="no fallar si falta la attestation (modo inventario)",
    )
    verify.add_argument("--json", action="store_true", help="salida JSON")
    verify.add_argument("--include-merges", action="store_true", help="no omitir merge commits")

    keys = sub.add_parser("keys", help="claves de firma del servidor")
    keys_sub = keys.add_subparsers(dest="keys_command", required=True)
    keys_show = keys_sub.add_parser("show", help="mostrar el JWKS del servidor")
    keys_show.add_argument("--jwks", default=None, help="origen alternativo (fichero o URL)")
    keys_export = keys_sub.add_parser("export", help="fijar el JWKS en un fichero (ancla de confianza)")
    keys_export.add_argument("--out", type=Path, default=Path(".aegis/jwks.json"))
    keys_export.add_argument("--jwks", default=None)

    user = sub.add_parser("user", help="gestión de usuarios del proveedor local")
    user_sub = user.add_subparsers(dest="user_command", required=True)
    user_add = user_sub.add_parser("add", help="crear o actualizar un usuario local")
    user_add.add_argument("--email", required=True)
    user_add.add_argument("--name", default="")
    user_add.add_argument("--password", help="si se omite, se pide por terminal")
    user_sub.add_parser("list", help="listar usuarios")

    serve = sub.add_parser("serve", help="arrancar el servidor de análisis")
    serve.add_argument("--listen", default=None)
    serve.add_argument("--reload", action="store_true")
    return p


def _fail(exc: AegisError) -> int:
    print(f"✗ {exc.render()}", file=sys.stderr)
    return exc.exit_code


def cmd_login(args: argparse.Namespace) -> int:
    settings = get_client_settings()
    with AuthClient(settings) as client:
        client.login(scope=args.scope, open_browser=not args.no_browser)
        print(f"  cache: {client.cache!r}", flush=True)
    return 0


def cmd_logout() -> int:
    settings = get_client_settings()
    with AuthClient(settings) as client:
        revoked = client.logout()
    print(f"  {'sesión revocada en el servidor' if revoked else 'cache local limpiada'}")
    return 0


def cmd_whoami() -> int:
    settings = get_client_settings()
    with AuthClient(settings) as client:
        info = client.whoami()
    print(json.dumps(info, indent=2, ensure_ascii=False))
    return 0


def cmd_token() -> int:
    settings = get_client_settings()
    with AuthClient(settings) as client:
        # Only the token goes to stdout: it is meant for `$(aegis token)`.
        print(client.access_token())
    return 0


def cmd_doctor() -> int:
    settings = get_client_settings()
    print(f"aegis {__version__}")
    print(f"server_url        : {settings.server_url}")
    print(f"token_cache       : {settings.token_cache} ({cache_mode_report(settings.token_cache)})")
    print(f"fail_mode         : {settings.fail_mode}")
    print(f"env_token_allowed : {settings.allow_env_token}")
    # --- LLM side: which model, and crucially *which key* --------------
    llm = get_server_settings()
    # Pass the *raw* setting, not ``llm.llm_key``: that property is already the
    # resolved key, so attributing it back to "settings" would always be wrong and
    # the whole point of the provenance line is to be right.
    raw_explicit = llm.llm_api_key.get_secret_value() if llm.llm_api_key else None
    key, source = resolve_api_key_source(raw_explicit)
    preview = f"{key[:5]}…{key[-4:]} (len {len(key)})" if key else "(ninguna)"
    print(f"llm_provider      : {llm.llm_provider}")
    print(f"llm_model         : {llm.llm_model}")
    print(f"llm_wire          : {llm.llm_wire}")
    print(f"llm_api_key       : {preview}")
    print(f"llm_key_source    : {source}")
    print(f"prompt            : {llm.prompt_dir}/{llm.prompt_file}")

    try:
        with AuthClient(settings) as client:
            info = client.whoami()
        print(f"auth              : OK as {info.get('sub')} scopes={info.get('scopes')}")
        return 0
    except AegisError as exc:
        print(f"auth              : {exc.slug} ({exc.message})")
        return exc.exit_code


def cmd_keys() -> int:
    settings = get_client_settings()
    try:
        r = httpx.get(f"{settings.server_url}/v1/keys", timeout=10.0)
        r.raise_for_status()
    except httpx.HTTPError as exc:
        print(f"✗ cannot fetch JWKS: {exc}", file=sys.stderr)
        return 4
    print(json.dumps(r.json(), indent=2))
    return 0


def cmd_user(args: argparse.Namespace) -> int:
    cfg = get_server_settings()
    store = AuthStore(cfg.db_path)
    try:
        provider = LocalIdentityProvider(store)
        if args.user_command == "add":
            password = args.password or getpass.getpass("Password: ")
            if len(password) < 12:
                print("✗ password must be at least 12 characters", file=sys.stderr)
                return 2
            identity = provider.create_user(
                email=args.email, name=args.name or args.email.split("@")[0], password=password
            )
            print(f"  ✓ usuario {identity.email} creado/actualizado en {cfg.db_path}")
            return 0
        if args.user_command == "list":
            rows = store.list_users()
            if not rows:
                print("  (sin usuarios)")
            for row in rows:
                state = "disabled" if row.disabled else "active"
                print(f"  {row.email:<40} {row.provider:<8} {state}")
            return 0
    finally:
        store.close()
    return 2


def cmd_serve(args: argparse.Namespace) -> int:
    argv: list[str] = []
    if args.listen:
        argv += ["--listen", args.listen]
    if args.reload:
        argv.append("--reload")
    return server_main(argv)


def main(argv: list[str] | None = None) -> int:  # noqa: PLR0911, PLR0912 - a return per subcommand reads better than a dispatch dict
    args = build_parser().parse_args(argv)
    try:
        match args.command:
            case "login":
                return cmd_login(args)
            case "logout":
                return cmd_logout()
            case "whoami":
                return cmd_whoami()
            case "token":
                return cmd_token()
            case "doctor":
                return cmd_doctor()
            case "keys":
                from aegis.cli import verify as verify_cli  # noqa: PLC0415 - keeps startup fast

                return (
                    verify_cli.cmd_keys_export(out=args.out, jwks=args.jwks)
                    if args.keys_command == "export"
                    else verify_cli.cmd_keys_show(args.jwks)
                )
            case "verify":
                from aegis.cli import verify as verify_cli  # noqa: PLC0415

                return verify_cli.cmd_verify(
                    range_spec=args.range_spec,
                    jwks=args.jwks,
                    issuer=args.issuer,
                    require_attestation=not args.report_only,
                    as_json=args.json,
                    include_merges=args.include_merges,
                )
            case "analyze":
                from aegis.cli.analyze import analyze_local, analyze_remote  # noqa: PLC0415

                if not args.path.is_file():
                    print(f"✗ not a file: {args.path}", file=sys.stderr)
                    return 2
                return (
                    analyze_local(args.path, as_json=args.json)
                    if args.local
                    else analyze_remote(args.path, as_json=args.json)
                )
            case "models":
                from aegis.cli.analyze import cmd_models  # noqa: PLC0415

                return cmd_models(args.pattern)
            case "user":
                return cmd_user(args)
            case "serve":
                return cmd_serve(args)
    except AegisError as exc:
        return _fail(exc)
    except KeyboardInterrupt:  # pragma: no cover - interactive
        print("\ninterrupted", file=sys.stderr)
        return 130
    return 2


# ``aegis-hook`` lives in ``aegis.cli.hook`` (step 4); imported lazily there so
# that installing the CLI does not pull the git plumbing into every invocation.
def hook_main(argv: list[str] | None = None) -> int:  # pragma: no cover - placeholder
    del argv
    print("aegis-hook is implemented in step 4 of the roadmap", file=sys.stderr)
    return 6


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
