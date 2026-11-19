"""Tests for ``aegis-hook``.

The hook is the piece a developer actually runs, so these tests are about the
*contract with git* rather than about the analysis: exit codes, fail modes, and the
one thing that must never happen — a hook that returns 0 when it did not analyse.

The server is a stub transport: what is under test is the hook's decision logic and
the request it builds from a real index.
"""

from __future__ import annotations

import json
import subprocess
from pathlib import Path
from typing import Any

import httpx
import pytest

from aegis.cli import hook as hook_mod
from aegis.config import ClientSettings
from aegis.gitx import GitError, GitRepo


def git(repo: Path, *args: str) -> str:
    return subprocess.run(
        ["git", *args], cwd=str(repo), capture_output=True, text=True, check=True
    ).stdout.strip()


@pytest.fixture
def worktree(tmp_path: Path) -> Path:
    root = tmp_path / "repo"
    root.mkdir()
    git(root, "init", "-q", "-b", "main")
    git(root, "config", "user.name", "Dev")
    git(root, "config", "user.email", "dev@mercadolibre.com")
    git(root, "remote", "add", "origin", "git@github.com:mercadolibre/demo.git")
    (root / "README.md").write_text("# demo\n")
    git(root, "add", "README.md")
    git(root, "commit", "-q", "-m", "chore: init")
    return root


@pytest.fixture
def settings(tmp_path: Path) -> ClientSettings:
    return ClientSettings(
        server_url="http://aegis.test",
        token_cache=tmp_path / "token.json",
        timeout_seconds=5,
        fail_mode="closed",
    )


def install_stubs(
    monkeypatch: pytest.MonkeyPatch,
    *,
    settings: ClientSettings,
    response: dict[str, Any] | Exception,
) -> list[dict[str, Any]]:
    """Replace the token lookup and the HTTP call; record the payloads sent."""
    sent: list[dict[str, Any]] = []

    class FakeAuthClient:
        def __init__(self, _settings: ClientSettings) -> None:
            pass

        def __enter__(self) -> FakeAuthClient:
            return self

        def __exit__(self, *exc: object) -> None:
            return None

        def access_token(self, *, force_refresh: bool = False) -> str:
            del force_refresh
            return "test-token"

    def fake_post(payload: dict[str, Any], _settings: ClientSettings, token: str) -> dict[str, Any]:
        assert token == "test-token"
        sent.append(payload)
        if isinstance(response, Exception):
            raise response
        return response

    monkeypatch.setattr(hook_mod, "get_client_settings", lambda: settings)
    monkeypatch.setattr(hook_mod, "AuthClient", FakeAuthClient)
    monkeypatch.setattr(hook_mod, "_post", fake_post)
    return sent


def allow_response(digest: str = "") -> dict[str, Any]:
    return {
        "decision": "allow",
        "message": "✅ AEGIS: sin hallazgos bloqueantes.",
        "commit_digest": digest,
        "attestation": "header.payload.signature",
        "analysis_id": "an_test",
        "meta": {"analysis_id": "an_test"},
    }


# --------------------------------------------------------------------------- #
# Exit codes
# --------------------------------------------------------------------------- #
def test_blocks_with_exit_1_and_prints_the_server_message(
    worktree: Path,
    settings: ClientSettings,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    (worktree / "app.py").write_text("import os\nos.system(input())\n")
    git(worktree, "add", "app.py")
    monkeypatch.chdir(worktree)
    install_stubs(
        monkeypatch,
        settings=settings,
        response={"decision": "block", "message": "🚨 Vulnerabilidad detectada\n   Riesgo: ..."},
    )

    assert hook_mod.main([]) == 1
    captured = capsys.readouterr()
    assert "Vulnerabilidad detectada" in captured.err
    # Nothing may reach stdout: pre-commit reserves it for its own display.
    assert captured.out == ""


def test_allows_with_exit_0_and_stashes_the_attestation(
    worktree: Path, settings: ClientSettings, monkeypatch: pytest.MonkeyPatch
) -> None:
    """pre-commit cannot write the note (no commit yet), so it stashes it."""
    (worktree / "app.py").write_text("print('safe')\n")
    git(worktree, "add", "app.py")
    monkeypatch.chdir(worktree)
    sent = install_stubs(monkeypatch, settings=settings, response=allow_response())

    assert hook_mod.main([]) == 0
    assert len(sent) == 1

    repo = GitRepo.discover(worktree)
    pending_file = hook_mod.pending_path(repo)
    assert pending_file.exists()
    assert oct(pending_file.stat().st_mode & 0o777) == "0o600"
    pending = json.loads(pending_file.read_text())
    assert pending["commit_digest"] == sent[0]["commit_digest"]
    assert pending["response"]["attestation"] == "header.payload.signature"
    # Nothing was attached to the *parent*, which is the failure mode this design
    # exists to prevent.
    assert repo.read_note(repo.head_sha() or "") is None


def test_post_commit_attaches_the_note_after_verifying_the_digest(
    worktree: Path, settings: ClientSettings, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The whole integrity claim, exercised on a real commit."""
    (worktree / "app.py").write_text("print('safe')\n")
    git(worktree, "add", "app.py")
    monkeypatch.chdir(worktree)
    sent = install_stubs(monkeypatch, settings=settings, response=allow_response())
    assert hook_mod.main([]) == 0

    git(worktree, "commit", "-q", "--no-verify", "-m", "feat: add app.py")
    assert hook_mod.attest_main([]) == 0

    repo = GitRepo.discover(worktree)
    head = repo.head_sha() or ""
    # The index digest and the object digest agree — that is what is being proven.
    assert repo.commit_digest(head) == sent[0]["commit_digest"]
    note = repo.read_note(head)
    assert note is not None
    payload = json.loads(note)
    assert payload["decision"] == "allow"
    assert payload["analysis_id"] == "an_test"
    assert not hook_mod.pending_path(repo).exists()


def test_post_commit_refuses_when_the_commit_differs(
    worktree: Path,
    settings: ClientSettings,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    """Analyse A, commit B: no attestation, and CI will reject it."""
    (worktree / "app.py").write_text("print('safe')\n")
    git(worktree, "add", "app.py")
    monkeypatch.chdir(worktree)
    install_stubs(monkeypatch, settings=settings, response=allow_response())
    assert hook_mod.main([]) == 0

    # The developer changes the staged content after the analysis.
    (worktree / "app.py").write_text("import os\nos.system(input())\n")
    git(worktree, "add", "app.py")
    git(worktree, "commit", "-q", "--no-verify", "-m", "feat: something else")

    assert hook_mod.attest_main([]) == 0
    repo = GitRepo.discover(worktree)
    assert repo.read_note(repo.head_sha() or "") is None
    assert "difiere de lo analizado" in capsys.readouterr().err


def test_post_commit_without_pending_is_a_noop(worktree: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.chdir(worktree)
    # Must never fail: post-commit runs after the commit is already made.
    assert hook_mod.attest_main([]) == 0


def test_unknown_decision_is_not_treated_as_allow(
    worktree: Path, settings: ClientSettings, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.chdir(worktree)
    install_stubs(monkeypatch, settings=settings, response={"decision": "maybe"})
    assert hook_mod.main([]) == 6


def test_not_in_a_repository_fails_with_config_error(
    tmp_path: Path, settings: ClientSettings, monkeypatch: pytest.MonkeyPatch
) -> None:
    outside = tmp_path / "outside"
    outside.mkdir()
    monkeypatch.chdir(outside)
    install_stubs(monkeypatch, settings=settings, response=allow_response())
    assert hook_mod.main([]) == 2


# --------------------------------------------------------------------------- #
# Failure handling
# --------------------------------------------------------------------------- #
def test_transport_failure_blocks_when_fail_closed(
    worktree: Path,
    settings: ClientSettings,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    monkeypatch.chdir(worktree)
    from aegis.errors import TransportError

    install_stubs(monkeypatch, settings=settings, response=TransportError("connection refused"))

    assert hook_mod.main([]) == 4
    err = capsys.readouterr().err
    assert "fail-closed" in err
    assert "aegis override" in err
    # The message must be explicit that this is not a bypass.
    assert "--no-verify" in err


def test_transport_failure_allows_when_fail_open(
    worktree: Path,
    settings: ClientSettings,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    monkeypatch.chdir(worktree)
    from aegis.errors import TransportError

    relaxed = settings.model_copy(update={"fail_mode": "open"})
    install_stubs(monkeypatch, settings=relaxed, response=TransportError("down"))

    assert hook_mod.main([]) == 0
    err = capsys.readouterr().err
    assert "AEGIS_FAIL_MODE=open" in err
    assert "degradado" in err


def test_expired_token_is_reported_as_an_auth_problem(
    worktree: Path,
    settings: ClientSettings,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    monkeypatch.chdir(worktree)
    from aegis.errors import AuthError

    install_stubs(monkeypatch, settings=settings, response=AuthError("expired"))

    assert hook_mod.main([]) == 3
    assert "aegis login" not in capsys.readouterr().err  # the hint comes from AuthError itself


# --------------------------------------------------------------------------- #
# What gets sent
# --------------------------------------------------------------------------- #
def test_request_is_built_from_the_index_not_the_arguments(
    worktree: Path, settings: ClientSettings, monkeypatch: pytest.MonkeyPatch
) -> None:
    """pre-commit passes filenames; the hook must ignore them."""
    (worktree / "staged.py").write_text("print('staged')\n")
    (worktree / "unstaged.py").write_text("print('unstaged')\n")
    git(worktree, "add", "staged.py")
    monkeypatch.chdir(worktree)
    sent = install_stubs(monkeypatch, settings=settings, response=allow_response())

    assert hook_mod.main(["unstaged.py", "whatever.py"]) == 0

    paths = [f["path"] for f in sent[0]["files"]]
    assert paths == ["staged.py"]
    fragment_paths = [f["path"] for f in sent[0]["fragments"]]
    assert fragment_paths == ["staged.py"]


def test_payload_has_a_valid_self_consistent_digest(
    worktree: Path, settings: ClientSettings, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The server re-validates the digest from the payload; a mismatch is a bug."""
    from aegis.contracts import AnalyzeRequest

    (worktree / "app.py").write_text("print(1)\n")
    git(worktree, "add", "app.py")
    monkeypatch.chdir(worktree)
    sent = install_stubs(monkeypatch, settings=settings, response=allow_response())

    assert hook_mod.main([]) == 0
    # Re-validating the exact JSON proves the contract's digest check passes.
    AnalyzeRequest.model_validate(sent[0])


def test_payload_reports_the_commit_context(
    worktree: Path, settings: ClientSettings, monkeypatch: pytest.MonkeyPatch
) -> None:
    (worktree / "app.py").write_text("print(1)\n")
    git(worktree, "add", "app.py")
    monkeypatch.chdir(worktree)
    sent = install_stubs(monkeypatch, settings=settings, response=allow_response())

    hook_mod.main([])
    commit = sent[0]["commit"]
    assert commit["repo_id"] == "github.com/mercadolibre/demo"
    assert commit["parent_sha"] is not None
    assert commit["author"]["email"] == "dev@mercadolibre.com"
    # The message is unknown at pre-commit time and is never invented.
    assert commit["message_sha256"] is None
    assert commit["is_merge_commit"] is False


def test_client_fingerprint_is_sent(
    worktree: Path, settings: ClientSettings, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.chdir(worktree)
    sent = install_stubs(monkeypatch, settings=settings, response=allow_response())
    hook_mod.main([])
    client = sent[0]["client"]
    assert client["name"] == "aegis-hook"
    assert client["version"]
    assert len(client["nonce"]) >= 16


def test_two_runs_use_different_nonces(
    worktree: Path, settings: ClientSettings, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Replay protection: the server refuses a repeated nonce for the same user."""
    monkeypatch.chdir(worktree)
    sent = install_stubs(monkeypatch, settings=settings, response=allow_response())
    hook_mod.main([])
    hook_mod.main([])
    assert sent[0]["client"]["nonce"] != sent[1]["client"]["nonce"]


def test_message_is_not_part_of_the_request_digest(
    worktree: Path, settings: ClientSettings, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Regression guard for the v2 digest decision."""
    from aegis import canon

    monkeypatch.chdir(worktree)
    sent = install_stubs(monkeypatch, settings=settings, response=allow_response())
    hook_mod.main([])
    payload = sent[0]
    expected = canon.compute_commit_digest(
        repo_id=payload["commit"]["repo_id"],
        parent_sha=payload["commit"]["parent_sha"],
        author_email=payload["commit"]["author"]["email"],
        entries=[
            (f["change"], f["mode"], f["blob_sha256"], f["path"], f["old_path"]) for f in payload["files"]
        ],
    )
    assert payload["commit_digest"] == expected


# --------------------------------------------------------------------------- #
# Notes
# --------------------------------------------------------------------------- #
def test_note_failure_in_post_commit_does_not_fail_the_hook(
    worktree: Path,
    settings: ClientSettings,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    """A lost note is recoverable (the audit log is authoritative); a broken
    post-commit stage must never look like a failed commit."""
    (worktree / "app.py").write_text("print('safe')\n")
    git(worktree, "add", "app.py")
    monkeypatch.chdir(worktree)
    install_stubs(monkeypatch, settings=settings, response=allow_response())
    assert hook_mod.main([]) == 0
    git(worktree, "commit", "-q", "--no-verify", "-m", "feat: add")

    def broken_note(*args: object, **kwargs: object) -> None:
        raise GitError("notes are broken")

    monkeypatch.setattr(GitRepo, "write_note", broken_note)
    assert hook_mod.attest_main([]) == 0
    assert "git note" in capsys.readouterr().err


def test_block_stashes_nothing(
    worktree: Path, settings: ClientSettings, monkeypatch: pytest.MonkeyPatch
) -> None:
    (worktree / "app.py").write_text("import os\nos.system(input())\n")
    git(worktree, "add", "app.py")
    monkeypatch.chdir(worktree)
    install_stubs(monkeypatch, settings=settings, response={"decision": "block", "message": "no"})
    assert hook_mod.main([]) == 1

    repo = GitRepo.discover(worktree)
    assert not hook_mod.pending_path(repo).exists()
    assert repo.read_note(repo.head_sha() or "") is None


def test_http_error_status_is_not_swallowed(
    worktree: Path, settings: ClientSettings, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A 500 from the server must not become "allow"."""
    monkeypatch.chdir(worktree)

    class FakeAuthClient:
        def __init__(self, _settings: ClientSettings) -> None:
            pass

        def __enter__(self) -> FakeAuthClient:
            return self

        def __exit__(self, *exc: object) -> None:
            return None

        def access_token(self, *, force_refresh: bool = False) -> str:
            del force_refresh
            return "tok"

    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(500, text="boom")

    real_post = httpx.post

    def fake_post(url: str, **kwargs: Any) -> httpx.Response:
        with httpx.Client(transport=httpx.MockTransport(handler)) as client:
            return client.post(url, **kwargs)

    monkeypatch.setattr(hook_mod, "get_client_settings", lambda: settings)
    monkeypatch.setattr(hook_mod, "AuthClient", FakeAuthClient)
    monkeypatch.setattr("httpx.post", fake_post)
    try:
        assert hook_mod.main([]) == 4
    finally:
        monkeypatch.setattr("httpx.post", real_post)


def test_unexpected_exception_is_not_swallowed(
    worktree: Path, settings: ClientSettings, monkeypatch: pytest.MonkeyPatch
) -> None:
    """An unhandled error must never be turned into exit 0.

    The dangerous shape for any gate is a bare ``except: return 0``: it converts a
    bug into a permanent silent bypass. Only ``AegisError`` has a defined policy;
    everything else propagates and git sees a non-zero exit.
    """
    monkeypatch.chdir(worktree)

    class FakeAuthClient:
        def __init__(self, _settings: ClientSettings) -> None:
            pass

        def __enter__(self) -> FakeAuthClient:
            return self

        def __exit__(self, *exc: object) -> None:
            return None

        def access_token(self, *, force_refresh: bool = False) -> str:
            del force_refresh
            return "tok"

    def fake_post(url: str, **kwargs: Any) -> httpx.Response:
        raise AssertionError("not reachable in this test")

    monkeypatch.setattr(hook_mod, "get_client_settings", lambda: settings)
    monkeypatch.setattr(hook_mod, "AuthClient", FakeAuthClient)
    monkeypatch.setattr("httpx.post", fake_post)
    # Without a stub the post raises AssertionError, which is not an AegisError —
    # the hook must not turn that into exit 0 either.
    with pytest.raises(AssertionError):
        hook_mod.main([])
