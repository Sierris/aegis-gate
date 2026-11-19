"""Server side of AEGIS (FastAPI)."""

from __future__ import annotations

from aegis.server.app import create_app

__all__ = ["create_app"]
