"""FastAPI application factory.

Layout of the surface (all under ``/v1`` except the human-facing device page):

===================================  ==================================================
``POST /v1/auth/device``             RFC 8628 step 1 — start the device flow
``POST /v1/auth/token``              RFC 8628 step 3 — poll for tokens
``POST /v1/auth/refresh``            rotation + reuse detection
``POST /v1/auth/revoke``             RFC 7009
``POST /v1/auth/exchange``           upstream IdP token → AEGIS token
``GET  /v1/userinfo``                who am I (Bearer)
``GET  /v1/keys``                    JWKS (public signing keys)
``GET  /device``                     the human approval page (HTML)
``POST /device``                     approve / deny
``GET  /healthz``                    liveness + key fingerprint
===================================  ==================================================

Notes that matter
-----------------
* **Stateful resources are ``def``, not ``async def``.** SQLite access is
  blocking; running it in the threadpool keeps the event loop free instead of
  making every request wait on one global lock *and* blocking the loop.
* **Error shape is uniform**: OAuth documents for auth endpoints, RFC 7807-ish
  problem details elsewhere. A client never has to guess.
* **No ``/v1/analyze`` yet** — that is step 3. The router is mounted here so the
  auth surface can be exercised end to end today.
"""

from __future__ import annotations

import html
import logging
import time
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from dataclasses import dataclass
from pathlib import Path
from typing import Annotated, Any

from fastapi import Depends, FastAPI, Header, HTTPException, Request, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import HTMLResponse, JSONResponse, Response
from pydantic import BaseModel, Field

from aegis.auth.client import TokenCache  # noqa: F401  (re-exported for tests)
from aegis.auth.keys import SigningKey
from aegis.auth.provider import IdentityProvider, build_provider
from aegis.auth.service import AuthService, OAuthError, OAuthErrorCode
from aegis.auth.store import AuthStore
from aegis.config import ServerSettings, get_server_settings
from aegis.contracts import (
    DeviceAuthorizationRequest,
    DeviceAuthorizationResponse,
    TokenRequest,
    TokenResponse,
    UserInfo,
)

logger = logging.getLogger("aegis.server")

_SCOPE_MAX_LEN = 256


# --------------------------------------------------------------------------- #
# Request/response models not worth putting in the frozen contract
# --------------------------------------------------------------------------- #
class RefreshRequest(BaseModel):
    refresh_token: str = Field(min_length=8, max_length=512)
    client_id: str = Field(max_length=128)


class RevokeRequest(BaseModel):
    refresh_token: str = Field(min_length=8, max_length=512)
    client_id: str = Field(max_length=128)


class ExchangeRequest(BaseModel):
    """Upstream IdP token exchange (e.g. a GitHub device-flow token)."""

    upstream_token: str = Field(min_length=8, max_length=1024)
    client_id: str = Field(max_length=128)
    scope: str = Field(default="", max_length=_SCOPE_MAX_LEN)


class HealthResponse(BaseModel):
    status: str
    env: str
    kid: str
    issuer: str
    provider: str


@dataclass(slots=True)
class AppContext:
    """Everything the routes need, assembled once at startup."""

    settings: ServerSettings
    store: AuthStore
    key: SigningKey
    provider: IdentityProvider
    service: AuthService
    #: None until the engine is wired (see ``_build_analyzer``); the analyze route
    #: answers 500 with a clear message instead of pretending to analyse.
    analyzer: Any = None
    audit_key: bytes | None = None
    cache: Any = None


# --------------------------------------------------------------------------- #
# Errors
# --------------------------------------------------------------------------- #
def oauth_error_response(code: OAuthErrorCode, description: str = "", **extra: Any) -> JSONResponse:
    """RFC 6749 §5.2 error document. Always 400 for the device-flow errors."""
    body: dict[str, Any] = {"error": code.value}
    if description:
        body["error_description"] = description
    body.update(extra)
    return JSONResponse(body, status_code=400, headers={"Cache-Control": "no-store"})


def _problem(status_code: int, title: str, detail: str = "") -> JSONResponse:
    return JSONResponse(
        {"status": status_code, "title": title, "detail": detail},
        status_code=status_code,
    )


# --------------------------------------------------------------------------- #
# App factory
# --------------------------------------------------------------------------- #
def create_app(
    settings: ServerSettings | None = None,
    *,
    store: AuthStore | None = None,
    key: SigningKey | None = None,
    provider: IdentityProvider | None = None,
    llm_provider: Any = None,
    analyzer: Any = None,
    cache: Any = None,
    now: Any = time.time,
) -> FastAPI:
    """Build the app. All collaborators are injectable so tests need no network,
    no real clock and no filesystem beyond a temp SQLite file."""

    @asynccontextmanager
    async def lifespan(app: FastAPI) -> AsyncIterator[None]:
        cfg = settings or get_server_settings()
        the_store = store or AuthStore(cfg.db_path, clock=now)
        the_key = key or SigningKey.load_or_create(Path(cfg.signing_key_path))
        the_provider = provider or build_provider(
            cfg.auth_provider, store=the_store, github_api_url=cfg.github_api_url
        )
        ctx = AppContext(
            settings=cfg,
            store=the_store,
            key=the_key,
            provider=the_provider,
            service=AuthService(
                store=the_store,
                key=the_key,
                settings=cfg,
                provider=the_provider,
                now=now,
            ),
        )
        # The engine is optional at import time so tests can build the app with a
        # fake provider (or none at all) without touching prompts or the network.
        if analyzer is not None:
            ctx.analyzer = analyzer
            ctx.cache = cache
        else:
            ctx.analyzer = _build_analyzer(cfg, the_store, the_key, now, llm_provider)
            ctx.cache = ctx.analyzer.cache
        app.state.cache = ctx.cache
        app.state.ctx = ctx
        logger.info(
            "aegis server ready: env=%s issuer=%s kid=%s provider=%s",
            cfg.env,
            cfg.issuer,
            the_key.kid,
            cfg.auth_provider,
        )
        try:
            yield
        finally:
            cache_handle = app.state.cache
            if cache_handle is not None and cache is None:
                cache_handle.close()
            if store is None:  # only close what we opened
                the_store.close()

    app = FastAPI(
        title="AEGIS",
        version="0.1.0",
        description="AppSec GenAI commit gate — authentication and analysis API",
        docs_url="/docs" if (settings or get_server_settings()).env != "prod" else None,
        redoc_url=None,
        lifespan=lifespan,
    )
    if settings and settings.cors_origins:
        app.add_middleware(
            CORSMiddleware,
            allow_origins=list(settings.cors_origins),
            allow_methods=["GET", "POST"],
            allow_headers=["Authorization", "Content-Type"],
        )

    _register_routes(app)
    from aegis.server.routes_analyze import router as analyze_router  # noqa: PLC0415 - breaks a cycle

    app.include_router(analyze_router)
    return app


def _build_analyzer(
    cfg: ServerSettings,
    store: AuthStore,
    key: SigningKey,
    now: Any,
    llm_provider: Any = None,
) -> Any:
    """Assemble the analysis engine (prompt bundle, provider, cache).

    Kept out of ``create_app`` so that the expensive/fallible parts (reading the
    prompt from disk, resolving an API key) are one clearly named function and so
    that a test can substitute any of them.
    """
    from aegis.engine.analyzer import Analyzer, EngineDeps  # noqa: PLC0415 - optional dep
    from aegis.engine.cache import AnalysisCache  # noqa: PLC0415 - optional dep
    from aegis.engine.prompts import load_bundle  # noqa: PLC0415 - optional dep
    from aegis.llm import CommandCodeProvider, FakeProvider  # noqa: PLC0415 - optional dep

    bundle = load_bundle(cfg.prompt_dir, prompt_file=cfg.prompt_file)

    provider = llm_provider
    if provider is None:
        provider = (
            FakeProvider()
            if cfg.llm_provider == "fake"
            else CommandCodeProvider(
                base_url=cfg.llm_base_url,
                api_key=cfg.llm_key,
                model=cfg.llm_model,
                timeout=cfg.llm_timeout_seconds,
                wire=cfg.llm_wire,
                zdr=cfg.llm_zdr,
                clock=now,
            )
        )

    analysis_cache = (
        AnalysisCache(
            cfg.db_path.parent / "aegis-cache.db",
            ttl_seconds=cfg.analysis_cache_ttl_seconds,
            clock=now,
        )
        if cfg.analysis_cache_enabled
        else None
    )
    return Analyzer(
        EngineDeps(
            provider=provider,
            bundle=bundle,
            key=key,
            issuer=cfg.issuer or cfg.public_url,
            fail_mode="closed",  # policy: fail-closed; see ADR-005
            strict_cross_check=cfg.strict_cross_check,
            max_output_tokens=cfg.llm_max_output_tokens,
            temperature=cfg.llm_temperature,
            cache=analysis_cache,
            store=store,
            now=now,
        )
    )


def _ctx(request: Request) -> AppContext:
    ctx: AppContext = request.app.state.ctx
    return ctx


Ctx = Annotated[AppContext, Depends(_ctx)]


def _bearer(authorization: Annotated[str | None, Header()] = None) -> str:
    if not authorization:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="missing Authorization header")
    scheme, _, token = authorization.partition(" ")
    if scheme.lower() != "bearer" or not token.strip():
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="expected a Bearer token")
    return token.strip()


BearerToken = Annotated[str, Depends(_bearer)]


def _register_routes(app: FastAPI) -> None:
    # -- auth ---------------------------------------------------------------
    @app.post("/v1/auth/device", response_model=DeviceAuthorizationResponse)
    def start_device(req: DeviceAuthorizationRequest, ctx: Ctx) -> Any:
        try:
            return ctx.service.start_device_authorization(client_id=req.client_id, requested_scope=req.scope)
        except OAuthError as exc:
            return oauth_error_response(exc.code, exc.description)

    @app.post("/v1/auth/token", response_model=TokenResponse)
    def poll_token(req: TokenRequest, ctx: Ctx) -> Any:
        try:
            return ctx.service.poll_token(device_code=req.device_code, client_id=req.client_id)
        except OAuthError as exc:
            # ``interval`` is echoed so the client can honour slow_down without
            # parsing prose.
            return oauth_error_response(exc.code, exc.description)

    @app.post("/v1/auth/refresh", response_model=TokenResponse)
    def refresh(req: RefreshRequest, ctx: Ctx) -> Any:
        try:
            return ctx.service.refresh(refresh_token=req.refresh_token, client_id=req.client_id)
        except OAuthError as exc:
            return oauth_error_response(exc.code, exc.description)

    @app.post("/v1/auth/revoke", status_code=status.HTTP_204_NO_CONTENT)
    def revoke(req: RevokeRequest, ctx: Ctx) -> Response:
        ctx.service.revoke(refresh_token=req.refresh_token, client_id=req.client_id)
        return Response(status_code=status.HTTP_204_NO_CONTENT)

    @app.post("/v1/auth/exchange", response_model=TokenResponse)
    async def exchange(req: ExchangeRequest, ctx: Ctx) -> Any:
        try:
            return await ctx.service.exchange_upstream_token(
                upstream_token=req.upstream_token, client_id=req.client_id, requested_scope=req.scope
            )
        except OAuthError as exc:
            return oauth_error_response(exc.code, exc.description)

    # -- identity -----------------------------------------------------------
    @app.get("/v1/userinfo", response_model=UserInfo)
    def userinfo(ctx: Ctx, token: BearerToken) -> Any:
        try:
            claims = ctx.service.verify_access_token(token)
        except Exception as exc:  # normalised into a 401 below
            return _problem(401, "invalid_token", str(exc))
        return ctx.service.userinfo(claims)

    # -- keys ---------------------------------------------------------------
    @app.get("/v1/keys")
    def keys(ctx: Ctx) -> Any:
        """JWKS. Public by design: verifiers need it, and it contains no secret.

        Cached aggressively because the key set changes only on rotation, and CI
        may fetch this on every job.
        """
        jwk = ctx.key.public_jwk().model_dump()
        return JSONResponse(
            {"keys": [jwk]},
            headers={"Cache-Control": "public, max-age=3600"},
        )

    @app.get("/healthz", response_model=HealthResponse)
    def healthz(ctx: Ctx) -> Any:
        return HealthResponse(
            status="ok",
            env=ctx.settings.env,
            kid=ctx.key.kid,
            issuer=ctx.settings.issuer or "",
            provider=ctx.settings.auth_provider,
        )

    # -- device approval page ----------------------------------------------
    @app.get("/device", response_class=HTMLResponse)
    def device_page(ctx: Ctx, user_code: str = "") -> HTMLResponse:
        return HTMLResponse(_render_device_page(ctx, user_code=user_code))

    @app.post("/device", response_class=HTMLResponse)
    async def device_submit(ctx: Ctx, request: Request) -> HTMLResponse:
        form = await request.form()
        user_code = str(form.get("user_code", ""))
        email = str(form.get("email", ""))
        password = str(form.get("password", ""))
        action = str(form.get("action", "approve"))

        if action == "deny":
            ctx.service.deny_user_code(user_code=user_code)
            return HTMLResponse(_render_message_page("Solicitud rechazada", "No se emitió ningún token."))

        try:
            identity = await ctx.service.approve_user_code(
                user_code=user_code, email=email, password=password
            )
        except Exception as exc:
            # The page shows ONE generic message on purpose: distinguishing "no
            # such code" from "bad password" from "account disabled" would turn a
            # public surface into a login/enumeration oracle. The precise reason
            # goes to the server log, where only operators can see it.
            logger.info("device approval failed for user_code=%r: %s", user_code, exc)
            return HTMLResponse(
                _render_device_page(ctx, user_code=user_code, error="Código o credenciales inválidos"),
                status_code=400,
            )
        return HTMLResponse(
            _render_message_page(
                "Autorización concedida",
                f"Ya puedes volver a la terminal. Sesión iniciada como {identity.email}.",
            )
        )


# --------------------------------------------------------------------------- #
# HTML (hand-written, escaped; no template engine to keep the dependency surface
# and the injection surface small)
# --------------------------------------------------------------------------- #
_CSS = """
:root{color-scheme:light dark;--bg:#0d1117;--card:#161b22;--fg:#e6edf3;--muted:#8b949e;
--accent:#3fb950;--danger:#f85149;--border:#30363d}
*{box-sizing:border-box}
body{margin:0;min-height:100vh;display:grid;place-items:center;background:var(--bg);
color:var(--fg);font:16px/1.5 ui-sans-serif,system-ui,-apple-system,Segoe UI,sans-serif}
main{width:min(420px,92vw);background:var(--card);border:1px solid var(--border);
border-radius:12px;padding:28px}
h1{font-size:1.15rem;margin:0 0 4px}
p.sub{color:var(--muted);margin:0 0 20px;font-size:.9rem}
label{display:block;font-size:.8rem;text-transform:uppercase;letter-spacing:.04em;
color:var(--muted);margin:14px 0 6px}
input{width:100%;padding:10px 12px;border-radius:8px;border:1px solid var(--border);
background:#0d1117;color:var(--fg);font-size:1rem;font-family:ui-monospace,monospace}
input#user_code{letter-spacing:.18em;text-transform:uppercase}
button{margin-top:20px;width:100%;padding:11px;border:0;border-radius:8px;
background:var(--accent);color:#052e16;font-weight:600;font-size:1rem;cursor:pointer}
button.deny{background:transparent;color:var(--danger);border:1px solid var(--danger);margin-top:10px}
.err{background:rgba(248,81,73,.12);border:1px solid var(--danger);color:#ffb3af;
padding:10px 12px;border-radius:8px;font-size:.875rem;margin-bottom:16px}
code{font-family:ui-monospace,monospace;background:#0d1117;padding:2px 6px;border-radius:5px}
"""


def _render_device_page(ctx: AppContext, *, user_code: str = "", error: str = "") -> str:
    """Approval page.

    Everything interpolated is escaped with :func:`html.escape`: ``user_code``
    comes from the query string and lands in an HTML attribute, which is a
    textbook reflected-XSS sink. Escaped, it is inert.
    """
    code = html.escape(user_code.upper(), quote=True)
    error_html = f'<div class="err">{html.escape(error)}</div>' if error else ""
    provider = html.escape(ctx.settings.auth_provider)
    return f"""<!doctype html>
<html lang="es"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>AEGIS · autorizar dispositivo</title><style>{_CSS}</style></head>
<body><main>
  <h1>AEGIS</h1>
  <p class="sub">Autoriza este dispositivo para analizar commits (proveedor: {provider}).</p>
  {error_html}
  <form method="post" action="/device" autocomplete="off">
    <label for="user_code">Código del dispositivo</label>
    <input id="user_code" name="user_code" value="{code}" required
           inputmode="latin" autocapitalize="characters" maxlength="12" autofocus>
    <label for="email">Email</label>
    <input id="email" name="email" type="email" required>
    <label for="password">Contraseña</label>
    <input id="password" name="password" type="password" required>
    <button type="submit" name="action" value="approve">Autorizar</button>
    <button type="submit" name="action" value="deny" class="deny">Rechazar</button>
  </form>
</main></body></html>"""


def _render_message_page(title: str, message: str) -> str:
    return f"""<!doctype html>
<html lang="es"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>AEGIS · {html.escape(title)}</title><style>{_CSS}</style></head>
<body><main>
  <h1>{html.escape(title)}</h1>
  <p class="sub">{html.escape(message)}</p>
</main></body></html>"""


__all__ = ["AppContext", "create_app", "oauth_error_response"]
