"""``POST /v1/analyze`` — the endpoint the pre-commit hook calls.

Request pipeline, in order (each step can only make the outcome stricter):

    1. Bearer token      → identity (a valid, unexpired Ed25519 token)
    2. scope             → "analyze"
    3. identity binding  → token e-mail == commit author e-mail
    4. contract          → AnalyzeRequest validates its own digest
    5. engine            → prefilter → LLM → validation → policy
    6. response          → verdict + findings + signed attestation

Why binding happens *before* the engine: an analysis is only meaningful if it is
attributable. Running the LLM first and rejecting afterwards would burn tokens on
commits the caller was never authorised to submit, and would let an attacker use the
gate as a free (and unaudited) code-review oracle.
"""

from __future__ import annotations

from typing import Annotated, Any

from fastapi import APIRouter, Depends, Header, Request
from fastapi.responses import JSONResponse

from aegis import canon
from aegis.auth import scopes as scopes_mod
from aegis.auth.binding import bind_identity
from aegis.auth.jwt import AccessTokenClaims
from aegis.auth.service import OAuthErrorCode
from aegis.contracts import AnalyzeRequest, AnalyzeResponse, AuditAction
from aegis.errors import AegisError, AuthError
from aegis.server.app import (
    AppContext,
    _bearer,
    oauth_error_response,
)

router = APIRouter()

BearerToken = Annotated[str, Depends(_bearer)]


def _ctx(request: Request) -> AppContext:
    ctx: AppContext = request.app.state.ctx
    return ctx


Ctx = Annotated[AppContext, Depends(_ctx)]


@router.post("/v1/analyze", response_model=AnalyzeResponse)
def analyze(
    payload: AnalyzeRequest,
    ctx: Ctx,
    token: BearerToken,
    x_aegis_client: Annotated[str | None, Header()] = None,
) -> Any:
    # --- 1. identity ------------------------------------------------------
    try:
        claims: AccessTokenClaims = ctx.service.verify_access_token(token)
    except AegisError as exc:
        return JSONResponse({"error": "invalid_token", "error_description": str(exc)}, status_code=401)

    # --- 2. authorisation -------------------------------------------------
    try:
        scopes_mod.require_scope(claims.scopes, scopes_mod.Scope.ANALYZE, actor=claims.email)
    except AuthError as exc:
        return JSONResponse({"error": "insufficient_scope", "error_description": str(exc)}, status_code=403)

    # --- 3. attribution ---------------------------------------------------
    try:
        actor = bind_identity(claims, author_email=payload.commit.author.email)
    except AuthError as exc:
        ctx.store.append_audit(
            action=AuditAction.ANALYZE_ERROR,
            actor=claims.email,
            detail={
                "event": "identity_binding_failed",
                "commit_author": payload.commit.author.email,
                "reason": str(exc),
            },
            commit_digest=payload.commit_digest,
            repo_id=payload.commit.repo_id,
            key=getattr(ctx, "audit_key", None),
        )
        return JSONResponse(
            {"error": "identity_mismatch", "error_description": str(exc), "hint": exc.hint},
            status_code=403,
        )

    # --- 4. repository allowlist ------------------------------------------
    settings = ctx.settings
    repo_id = payload.commit.repo_id
    if settings.allowed_repos and repo_id not in {_norm(r) for r in settings.allowed_repos}:
        return JSONResponse(
            {
                "error": "repo_not_allowed",
                "error_description": f"{repo_id} is not in AEGIS_ALLOWED_REPOS",
            },
            status_code=403,
        )

    # --- 5. engine --------------------------------------------------------
    analyzer = getattr(ctx, "analyzer", None)
    if analyzer is None:  # pragma: no cover - misconfiguration, surfaced loudly
        return oauth_error_response(
            OAuthErrorCode.SERVER_ERROR,
            "the analysis engine is not configured on this server",
        )

    if x_aegis_client:
        # Client fingerprint is advisory: recorded for drift detection (an old hook
        # may compute an outdated digest version), never trusted for decisions.
        ctx.store.append_audit(
            action=AuditAction.ANALYZE_REQUEST,
            actor=actor,
            detail={"event": "client_seen", "client": x_aegis_client[:64]},
            repo_id=repo_id,
            key=getattr(ctx, "audit_key", None),
        )

    return analyzer.analyze(
        payload,
        actor=actor,
        scope=scopes_mod.format_scopes(claims.scopes),
    )


def _norm(value: str) -> str:
    return canon.normalize_repo_id(value)


__all__ = ["router"]
