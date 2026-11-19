"""``aegis analyze`` — run the engine locally against a file or a staged commit.

Two modes, and the difference matters:

``--local``
    Builds the request in-process and calls the engine directly. No server, no
    token, no attestation trust: it is a developer convenience for *seeing what the
    gate would say* before committing. The verdict it prints is advisory, and it
    says so, because a locally-produced verdict is not evidence of anything — the
    whole point of the design is that the client cannot vouch for itself.

default
    Talks to ``POST /v1/analyze`` with the cached user token, exactly like the hook
    will in step 4. Use ``--local`` when the server is unavailable and you only need
    a hint.
"""

from __future__ import annotations

import json
import sys
import time
from pathlib import Path

import httpx

from aegis import canon
from aegis.auth.client import AuthClient
from aegis.config import get_client_settings, get_server_settings
from aegis.contracts import (
    AnalysisPolicy,
    AnalyzeRequest,
    ChangeKind,
    ClientInfo,
    CommitRef,
    Identity,
    StagedFile,
)
from aegis.engine import Analyzer, EngineDeps, fragments_from_content, load_bundle
from aegis.errors import AegisError, ConfigError
from aegis.llm import CommandCodeProvider, FakeProvider, resolve_api_key


def build_request_for_file(
    path: Path,
    *,
    repo_id: str = "github.com/local/local",
    author_email: str = "dev@local",
) -> AnalyzeRequest:
    """Construct a valid ``AnalyzeRequest`` for a single file.

    ``files`` and ``fragments`` must agree: the contract recomputes the commit
    digest from ``files`` and rejects a mismatch, so the hook and this helper cannot
    drift into sending a digest that describes something else.
    """
    content = path.read_text(encoding="utf-8")
    fragments = tuple(fragments_from_content(str(path), content))
    digest = canon.compute_commit_digest(
        repo_id=repo_id,
        parent_sha=None,
        author_email=author_email,
        message_sha256=canon.message_digest(f"aegis analyze {path.name}"),
        entries=[("A", "100644", canon.sha256_text(content), str(path), None)],
    )
    return AnalyzeRequest(
        commit_digest=digest,
        commit=CommitRef(
            repo_id=repo_id,
            ref="refs/heads/main",
            parent_sha=None,
            author=Identity(name="Local", email=author_email),
            committer=Identity(name="Local", email=author_email),
            message_sha256=canon.message_digest(f"aegis analyze {path.name}"),
            branch="main",
        ),
        files=(
            StagedFile(
                path=str(path),
                change=ChangeKind.ADDED,
                mode="100644",
                blob_sha256=canon.sha256_text(content),
                size_bytes=len(content),
            ),
        ),
        fragments=fragments,
        policy=AnalysisPolicy(),
        client=ClientInfo(
            version="0.1.0",
            os=sys.platform,
            python=f"{sys.version_info.major}.{sys.version_info.minor}",
            nonce=canon.sha256_text(f"{path}{time.time()}")[:32],
        ),
    )


def analyze_local(path: Path, *, as_json: bool) -> int:
    settings = get_server_settings()
    provider = (
        FakeProvider()
        if settings.llm_provider == "fake"
        else CommandCodeProvider(
            base_url=settings.llm_base_url,
            api_key=resolve_api_key(settings.llm_key or None),
            model=settings.llm_model,
            timeout=settings.llm_timeout_seconds,
            wire=settings.llm_wire,
            zdr=settings.llm_zdr,
        )
    )
    from aegis.auth.keys import SigningKey  # noqa: PLC0415 - keeps CLI startup fast

    key = SigningKey.load_or_create(Path(settings.signing_key_path))
    analyzer = Analyzer(
        EngineDeps(
            provider=provider,
            bundle=load_bundle(settings.prompt_dir, prompt_file=settings.prompt_file),
            key=key,
            issuer=settings.issuer or settings.public_url,
            fail_mode="closed",
            strict_cross_check=settings.strict_cross_check,
            max_output_tokens=settings.llm_max_output_tokens,
            temperature=settings.llm_temperature,
        )
    )
    request = build_request_for_file(path)
    response = analyzer.analyze(request, actor=request.commit.author.email)
    if as_json:
        print(response.model_dump_json(indent=2))
    else:
        print(response.message)
        print(
            f"\n   (análisis local, no vinculante · {response.meta.model} · "
            f"{response.meta.usage.total_tokens} tokens · {response.meta.latency_ms} ms)"
        )
    return 0 if response.decision.value == "allow" else 1


def analyze_remote(path: Path, *, as_json: bool) -> int:
    settings = get_client_settings()
    with AuthClient(settings) as client:
        token = client.access_token()
        # The synthetic commit must be authored by the authenticated user: the
        # server binds `token.email == commit.author.email` and would (correctly)
        # reject anything else. Doing it here means the binding is exercised by the
        # CLI too, instead of being a check only the hook ever hits.
        info = client.whoami()
    request = build_request_for_file(path, author_email=str(info["email"]))
    try:
        r = httpx.post(
            f"{settings.server_url}/v1/analyze",
            json=json.loads(request.model_dump_json()),
            headers={"Authorization": f"Bearer {token}"},
            timeout=settings.timeout_seconds,
        )
    except httpx.HTTPError as exc:
        raise AegisError(f"cannot reach {settings.server_url}: {exc}") from exc
    if r.status_code == 401:
        raise AegisError("server rejected the token", hint="Run `aegis login`.")
    if r.status_code >= 400:
        raise AegisError(f"analysis failed: HTTP {r.status_code} {r.text[:300]}")
    body = r.json()
    if as_json:
        print(json.dumps(body, indent=2, ensure_ascii=False))
    else:
        print(body.get("message", ""))
        print(f"\n   attestation: {body['attestation'][:48]}…")
    return 0 if body["decision"] == "allow" else 1


def cmd_models(pattern: str | None = None) -> int:
    """List the models the configured Command Code plan actually serves."""
    settings = get_server_settings()
    provider = CommandCodeProvider(
        base_url=settings.llm_base_url,
        api_key=resolve_api_key(settings.llm_key or None),
        model=settings.llm_model,
        timeout=settings.llm_timeout_seconds,
        wire="chat",
    )
    try:
        models = provider.list_models(use_cache=False)
    except AegisError as exc:
        print(f"✗ {exc.render()}", file=sys.stderr)
        return 4
    if not models:
        raise ConfigError("the provider returned an empty catalog")
    print(f"{'model':<34} {'context':>9}  endpoints")
    for entry in sorted(models, key=lambda m: str(m.get("id"))):
        model_id = str(entry.get("id"))
        if pattern and pattern.lower() not in model_id.lower():
            continue
        context = entry.get("context_length") or entry.get("context_window") or "?"
        endpoints = ",".join(entry.get("supported_endpoints") or []) or "(chat default)"
        marker = " ←" if model_id == settings.llm_model else ""
        print(f"{model_id:<34} {context:>9}  {endpoints}{marker}")
    return 0
