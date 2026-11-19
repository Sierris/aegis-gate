"""``aegis-server`` entrypoint: uvicorn with sane, security-first defaults."""

from __future__ import annotations

import argparse
import logging
import os
import sys

import uvicorn

from aegis.config import ServerSettings, get_server_settings


def _split_listen(listen: str) -> tuple[str, int]:
    host, _, port = listen.rpartition(":")
    if not host:
        host, port = "127.0.0.1", listen
    return host, int(port)


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="aegis-server", description="AEGIS analysis server")
    p.add_argument("--env", choices=("local", "ci", "prod"), default=None, help="environment profile")
    p.add_argument("--listen", default=None, help="HOST:PORT (default 127.0.0.1:8088)")
    p.add_argument("--reload", action="store_true", help="auto-reload (local development only)")
    p.add_argument("--log-level", default="info")
    return p


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)

    # The env var must be set *before* the settings object is built, otherwise the
    # cached instance would ignore the CLI flag.
    if args.env:
        os.environ["AEGIS_ENV"] = args.env
    if args.listen:
        os.environ["AEGIS_LISTEN"] = args.listen
    get_server_settings.cache_clear()
    settings: ServerSettings = get_server_settings()

    if args.reload and settings.env == "prod":
        print("refusing --reload in prod", file=sys.stderr)  # noqa: T201 - CLI diagnostic
        return 2

    logging.basicConfig(
        level=args.log_level.upper(),
        format="%(asctime)s %(levelname)-7s %(name)s: %(message)s",
    )

    host, port = _split_listen(settings.listen)
    uvicorn.run(
        "aegis.server.app:create_app",
        factory=True,
        host=host,
        port=port,
        reload=args.reload,
        log_level=args.log_level,
        # Do not trust proxy headers unless the deployment actually sits behind a
        # proxy: honouring them blindly lets a client spoof its IP in the audit log
        # and bypass per-IP rate limits.
        proxy_headers=False,
        server_header=False,
    )
    return 0


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
