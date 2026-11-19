"""``aegis-hook`` — the pre-commit entrypoint.

Contract with git and with pre-commit
-------------------------------------
* **Exit 0** allows the commit, **any non-zero** aborts it (exit 1 = vulnerability).
* It returns quickly and never prompts: a hook that asks a question breaks
  ``git commit`` in scripts, IDEs and CI.
* It **ignores the filenames pre-commit passes** (see ``gitx.repo``): it re-derives
  the staged set from the index, because the contract recomputes the commit digest
  from `files` and a mismatch would be caught as tampering.

Two stages, because the commit does not exist yet when we analyse
------------------------------------------------------------------
``pre-commit`` (``aegis-hook``)
    1. Read the index: entries, blob hashes, fragments of the changed regions.
    2. Build the canonical commit digest from git object data only.
    3. POST it to `/v1/analyze` with the user's Bearer token.
    4. On `block`: print the server-rendered message and exit 1.
       On `allow`: stash the attestation in ``.git/aegis/pending.json``, exit 0.
    5. On failure: apply `fail_mode` (default: block, loudly).

``post-commit`` (``aegis-attest``)
    The commit now exists, so the note can be attached — but only after
    **recomputing the digest from the committed object** and comparing it with the
    one that was analysed. That comparison is the integrity control, executed on
    every commit; if it fails, no attestation is attached and the developer is told
    the commit changed after the analysis.

Attaching the note from ``pre-commit`` is impossible, not merely awkward: there is
no commit object to hang it on. ``git head_sha()`` at that moment is the *parent*, so
writing there would attach a proof of this commit's analysis to the previous one.

The key asymmetry: the *client* never decides anything. It reports what is staged
and renders what the server said. A tampered hook can only refuse to run, which CI
then notices as a missing attestation.
"""

from __future__ import annotations

import contextlib
import json
import os
import platform
import subprocess
import sys
import time
from pathlib import Path
from typing import Any

import httpx

from aegis import __version__, canon
from aegis.auth.client import AuthClient
from aegis.config import ClientSettings, get_client_settings
from aegis.contracts import (
    AnalysisPolicy,
    AnalyzeRequest,
    ClientInfo,
    CommitRef,
)
from aegis.errors import AegisError, AuthError, TransportError
from aegis.gitx import GitRepo

#: Header so the server can tell an old hook from a current one (drift detection).
CLIENT_NAME = "aegis-hook"


def _client_info() -> ClientInfo:
    git_version = _git_version()
    return ClientInfo(
        name=CLIENT_NAME,
        version=_version(),
        os=f"{platform.system().lower()}/{platform.machine()}",
        python=f"{sys.version_info.major}.{sys.version_info.minor}.{sys.version_info.micro}",
        git_version=git_version,
        # A fresh nonce per attempt: the server refuses to replay a cached verdict.
        nonce=canon.sha256_text(f"{time.time_ns()}-{id(object())}")[:32],
    )


def _version() -> str:
    return __version__


def _git_version() -> str | None:
    """Advisory only: an old git can render hunks differently, and the server wants
    to know which client produced the payload."""
    try:
        # S607 is fine here: `git` must resolve through PATH (the developer's git,
        # which is the one running the hook). Only `--version` is queried.
        out = subprocess.run(
            ["git", "--version"],  # noqa: S607
            capture_output=True,
            text=True,
            check=False,
            timeout=10,
        ).stdout.strip()
    except (OSError, subprocess.SubprocessError):
        return None
    return out.split()[-1] if out else None


def build_request(repo: GitRepo, *, policy: AnalysisPolicy | None = None) -> AnalyzeRequest:
    """Assemble the wire request from the index.

    The digest is computed here with exactly the same function the server uses on
    the pushed commit — same code path, same inputs, so a mismatch is not possible
    unless the content actually differs.
    """
    files = repo.staged_files()
    parent = repo.head_sha()
    author = repo.author_identity()
    digest = canon.compute_commit_digest(
        repo_id=repo.repo_id(),
        parent_sha=parent,
        author_email=author.email,
        entries=[(f.change.value, f.mode, f.blob_sha256, f.path, f.old_path) for f in files],
    )
    return AnalyzeRequest(
        commit_digest=digest,
        commit=CommitRef(
            repo_id=repo.repo_id(),
            ref=repo.branch() or "refs/heads/detached",
            parent_sha=parent,
            author=author,
            committer=author,
            # Deliberately absent: at pre-commit time git has not composed the
            # message (see canon's module docstring). Not part of the digest.
            message_sha256=None,
            is_merge_commit=repo.is_merge_in_progress(),
            branch=repo.branch(),
        ),
        files=tuple(files),
        fragments=tuple(repo.build_fragments(files)),
        policy=policy or AnalysisPolicy(),
        client=_client_info(),
    )


def _post(payload: dict[str, Any], settings: ClientSettings, token: str) -> dict[str, Any]:
    timeout = httpx.Timeout(settings.timeout_seconds, connect=settings.connect_timeout_seconds)
    try:
        response = httpx.post(
            f"{settings.server_url}/v1/analyze",
            json=payload,
            headers={
                "Authorization": f"Bearer {token}",
                "User-Agent": f"{CLIENT_NAME}/{_version()}",
                "X-Aegis-Client": f"{CLIENT_NAME}/{_version()}",
            },
            timeout=timeout,
        )
    except httpx.HTTPError as exc:
        raise TransportError(
            f"cannot reach the AEGIS server at {settings.server_url}: {exc}",
            hint="Start it with `aegis serve`, or set AEGIS_FAIL_MODE=open to commit "
            "without analysis (audited as degraded).",
        ) from exc

    if response.status_code == 401:
        raise AuthError(
            "the server rejected your token",
            hint="Run `aegis login` (the token may have expired or been revoked).",
        )
    if response.status_code == 403:
        try:
            body = response.json()
        except ValueError:
            body = {}
        raise AuthError(
            str(body.get("error_description") or "the server denied the analysis"),
            hint=str(body.get("hint") or "Check your identity and repository access."),
        )
    if response.status_code >= 400:
        raise TransportError(f"analysis failed: HTTP {response.status_code} {response.text[:300]}")
    body = response.json()
    if not isinstance(body, dict):
        raise TransportError("the server returned a non-JSON response")
    return body


def pending_path(repo: GitRepo) -> Path:
    """Where the pre-commit stage leaves the attestation for post-commit."""
    return repo.git_dir() / "aegis" / "pending.json"


def save_pending(repo: GitRepo, *, digest: str, response: dict[str, Any]) -> None:
    path = pending_path(repo)
    path.parent.mkdir(parents=True, exist_ok=True)
    payload = {
        "commit_digest": digest,
        "response": response,
        "created_at": time.time(),
    }
    tmp = path.with_suffix(".tmp")
    tmp.write_text(json.dumps(payload), encoding="utf-8")
    os.chmod(tmp, 0o600)
    tmp.replace(path)


def load_pending(repo: GitRepo) -> dict[str, Any] | None:
    path = pending_path(repo)
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return None
    return data if isinstance(data, dict) else None


def clear_pending(repo: GitRepo) -> None:
    with contextlib.suppress(OSError):
        pending_path(repo).unlink()


def _note_payload(response: dict[str, Any]) -> str:
    """The note is JSON so a verifier does not have to parse prose."""
    return json.dumps(
        {
            "version": 1,
            "commit_digest": response.get("commit_digest"),
            "decision": response.get("decision"),
            "analysis_id": (response.get("meta") or {}).get("analysis_id"),
            "attestation": response.get("attestation"),
        },
        indent=2,
        sort_keys=True,
    )


def main(argv: list[str] | None = None) -> int:
    # ``argv`` is received from pre-commit (the changed filenames) and intentionally
    # unused: the staged set is re-derived from the index.
    del argv
    settings = get_client_settings()

    try:
        repo = GitRepo.discover(Path.cwd())
        request = build_request(repo)
    except AegisError as exc:
        return _fail(exc)

    if not request.fragments:
        # Nothing analysable (lockfiles, binaries, empty commit). Still ask the
        # server so the audit trail has an entry — and so CI finds an attestation.
        _info("nada que analizar en este commit (solo ficheros excluidos o binarios)")

    try:
        with AuthClient(settings) as client:
            token = client.access_token()
    except AegisError as exc:
        return _fail(exc)

    try:
        body = _post(json.loads(request.model_dump_json()), settings, token)
    except AegisError as exc:
        return _on_failure(exc, settings)

    decision = body.get("decision")
    message = str(body.get("message") or "")
    if decision == "block":
        print(message or "🚨 AEGIS: commit rechazado por el análisis de seguridad.", file=sys.stderr)
        return 1

    if decision not in {"allow", "allow_override"}:
        print(f"🚨 AEGIS: respuesta inesperada del servidor ({decision!r}).", file=sys.stderr)
        return 6

    # The commit does not exist yet, so the attestation is stashed and the
    # post-commit stage binds it to the real object (after verifying the digest).
    try:
        save_pending(repo, digest=request.commit_digest, response=body)
    except OSError as exc:
        _warn(f"no se pudo guardar la attestation pendiente: {exc}")

    _info(f"análisis correcto · {decision} · {request.commit_digest[:12]} · {body.get('analysis_id', '')}")
    return 0


def attest_main(argv: list[str] | None = None) -> int:  # noqa: PLR0911 - one return per early exit
    """``post-commit`` stage: bind the attestation to the commit that was created.

    This is the only place where the two digest computations meet: the index one
    (from ``pre-commit``) and the object one (from the commit git just made). They
    agreeing is the whole claim of the design, so it is checked on every single
    commit rather than only in CI.
    """
    del argv
    try:
        repo = GitRepo.discover(Path.cwd())
    except AegisError as exc:
        _warn(str(exc))
        return 0  # never block a post-commit hook that has nothing to do

    pending = load_pending(repo)
    if pending is None:
        return 0

    expected = str(pending.get("commit_digest") or "")
    response = pending.get("response")
    if not isinstance(response, dict) or not expected:
        clear_pending(repo)
        return 0

    head = repo.head_sha()
    if head is None:
        _warn("no HEAD after commit; sin attestation")
        return 0

    try:
        actual = repo.commit_digest(head)
    except AegisError as exc:
        _warn(f"no se pudo recalcular el digest del commit: {exc}")
        return 0

    if actual != expected:
        # The commit is not the one that was analysed. Refusing to attach the
        # attestation turns a silent mismatch into a CI failure with a reason.
        clear_pending(repo)
        _warn(
            "el commit difiere de lo analizado (digest distinto); NO se adjunta la "
            "attestation. Se rechazará en CI."
        )
        return 0

    try:
        repo.write_note(head, _note_payload(response))
    except AegisError as exc:
        _warn(f"no se pudo escribir la git note: {exc}")
    else:
        _info(f"attestation adjuntada a {head[:12]}")
    clear_pending(repo)
    return 0


def _on_failure(exc: AegisError, settings: ClientSettings) -> int:
    """Apply ``fail_mode`` when the analysis could not be produced."""
    if settings.fail_mode == "open":
        print(
            f"⚠  AEGIS: análisis no disponible ({exc.slug}). "
            "AEGIS_FAIL_MODE=open: se permite el commit, queda registrado como degradado.",
            file=sys.stderr,
        )
        print(f"   detalle: {exc.render()}", file=sys.stderr)
        return 0
    print(
        "🚨 AEGIS: no se pudo completar el análisis y la política es fail-closed.",
        file=sys.stderr,
    )
    print(f"   {exc.render()}", file=sys.stderr)
    print(
        "   Esto NO es un bypass: el commit no se analizó. Reintenta el commit; si el\n"
        "   servidor está caído, un operador autorizado puede emitir un override\n"
        "   firmado y auditado (`aegis override`), a diferencia de `--no-verify`.",
        file=sys.stderr,
    )
    return exc.exit_code


def _fail(exc: AegisError) -> int:
    print(f"🚨 AEGIS: {exc.render()}", file=sys.stderr)
    return exc.exit_code


def _info(text: str) -> None:
    print(f"  AEGIS · {text}", file=sys.stderr)


def _warn(text: str) -> None:
    print(f"  AEGIS · ⚠ {text}", file=sys.stderr)


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
