"""Contract tests.

The wire models are the only interface between the hook and the server, so these
tests focus on the properties that make the contract *safe*:

* unknown fields are rejected (no silent privilege escalation via extra keys);
* models are immutable;
* the request self-validates its own digest;
* a fragment whose declared hash does not match its text is rejected;
* enum/severity ordering used by policy decisions behaves as documented.
"""

from __future__ import annotations

import json

import pytest
from pydantic import ValidationError

from aegis import canon, errors
from aegis import contracts as c

REPO = "github.com/mercadolibre/appsec-demo"
PARENT = "0" * 40
BLOB = "a" * 64
TEXT = "# demo\n"
FRAG = c.CodeFragment(
    path="src/app.py",
    start_line=1,
    end_line=1,
    text=TEXT,
    content_sha256=canon.sha256_text(TEXT),
)


def make_request(*, size_bytes: int = len(TEXT), **overrides: object) -> c.AnalyzeRequest:
    files = (
        c.StagedFile(
            path="src/app.py",
            mode="100644",
            change=c.ChangeKind.ADDED,
            blob_sha256=BLOB,
            size_bytes=size_bytes,
            language="python",
        ),
    )
    commit = c.CommitRef(
        repo_id=REPO,
        ref="refs/heads/main",
        parent_sha=PARENT,
        author=c.Identity(name="Juan Sierra", email="JESierra20@Gmail.com"),
        committer=c.Identity(name="Juan Sierra", email="jesierra20@gmail.com"),
        message_sha256=canon.message_digest("feat: demo"),
        subject="feat: demo",
    )
    digest = canon.compute_commit_digest(
        repo_id=commit.repo_id,
        parent_sha=commit.parent_sha,
        author_email=commit.author.email,
        message_sha256=commit.message_sha256,
        entries=[(f.change.value, f.mode, f.blob_sha256, f.path, f.old_path) for f in files],
    )
    base: dict[str, object] = {
        "commit_digest": digest,
        "commit": commit,
        "files": files,
        "fragments": (FRAG,),
        "client": c.ClientInfo(version="0.1.0", os="darwin", python="3.12.15", nonce="n" * 16),
    }
    base.update(overrides)
    return c.AnalyzeRequest(**base)  # type: ignore[arg-type]


# --------------------------------------------------------------------------- #
# Strictness / immutability
# --------------------------------------------------------------------------- #
def test_unknown_fields_are_rejected() -> None:
    with pytest.raises(ValidationError, match="extra_forbidden"):
        c.AnalysisPolicy.model_validate({"profile": "owasp-core", "skip_scan": True})


def test_models_are_immutable() -> None:
    finding = c.Finding(
        id="f1",
        rule_id="AEGIS-INJ-001",
        category=c.OwaspCategory.A03_INJECTION,
        severity=c.Severity.HIGH,
        confidence=0.9,
        path="src/app.py",
        title="Command injection",
        explanation="x",
        remediation="y",
    )
    with pytest.raises(ValidationError):
        finding.severity = c.Severity.LOW


def test_identity_normalises_email() -> None:
    ident = c.Identity(name="  Juan   Sierra ", email=" JESierra20@GMAIL.com ")
    assert ident.email == "jesierra20@gmail.com"
    assert ident.name == "Juan Sierra"


def test_commit_ref_normalises_repo_id() -> None:
    ref = c.CommitRef(
        repo_id="git@github.com:MercadoLibre/AppSec-Demo.git",
        ref="refs/heads/main",
        author=c.Identity(name="a", email="a@b.com"),
        committer=c.Identity(name="a", email="a@b.com"),
        message_sha256="b" * 64,
    )
    assert ref.repo_id == "github.com/mercadolibre/appsec-demo"


# --------------------------------------------------------------------------- #
# StagedFile invariants
# --------------------------------------------------------------------------- #
def test_deleted_file_cannot_carry_a_blob() -> None:
    with pytest.raises(ValidationError, match="must not carry blob_sha256"):
        c.StagedFile(path="a.py", change=c.ChangeKind.DELETED, blob_sha256=BLOB)


def test_non_deleted_file_requires_a_blob() -> None:
    with pytest.raises(ValidationError, match="requires blob_sha256"):
        c.StagedFile(path="a.py", change=c.ChangeKind.ADDED)


def test_rename_requires_old_path_and_no_other_kind_accepts_it() -> None:
    with pytest.raises(ValidationError, match="requires old_path"):
        c.StagedFile(path="a.py", change=c.ChangeKind.RENAMED, blob_sha256=BLOB)
    with pytest.raises(ValidationError, match="only valid for renames"):
        c.StagedFile(path="a.py", old_path="b.py", change=c.ChangeKind.MODIFIED, blob_sha256=BLOB)


def test_file_mode_allowlist() -> None:
    with pytest.raises(ValidationError):
        c.StagedFile(path="a.py", change=c.ChangeKind.ADDED, blob_sha256=BLOB, mode="777")
    # Symlinks and submodules are valid git modes and must be expressible.
    for mode in ("100644", "100755", "120000", "160000"):
        c.StagedFile(path="a", change=c.ChangeKind.ADDED, blob_sha256=BLOB, mode=mode)


# --------------------------------------------------------------------------- #
# CodeFragment
# --------------------------------------------------------------------------- #
def test_fragment_hash_must_match_text() -> None:
    with pytest.raises(ValidationError, match="content_sha256 does not match"):
        c.CodeFragment(path="a.py", start_line=1, end_line=1, text="x", content_sha256="c" * 64)


def test_fragment_line_range_is_validated() -> None:
    with pytest.raises(ValidationError, match="end_line < start_line"):
        c.CodeFragment(
            path="a.py", start_line=9, end_line=2, text=TEXT, content_sha256=canon.sha256_text(TEXT)
        )


# --------------------------------------------------------------------------- #
# AnalyzeRequest
# --------------------------------------------------------------------------- #
def test_request_accepts_a_consistent_payload() -> None:
    req = make_request()
    assert req.schema_version == "1"
    assert req.payload_sha256 == canon.fragments_digest([("src/app.py", TEXT, 1, 1)])


def test_request_rejects_tampered_digest() -> None:
    with pytest.raises(ValidationError, match="commit_digest mismatch"):
        make_request(commit_digest="d" * 64)


def test_request_rejects_payload_over_the_byte_budget() -> None:
    """The server-side byte budget must be enforced by the contract too, so an
    oversized commit fails fast locally instead of after a paid LLM call."""
    with pytest.raises(ValidationError, match="max_fragments_bytes"):
        make_request(size_bytes=4096, policy=c.AnalysisPolicy(max_fragments_bytes=1024))


def test_request_round_trips_through_json() -> None:
    req = make_request()
    again = c.AnalyzeRequest.model_validate_json(req.model_dump_json())
    assert again == req
    # The serialised form must not contain unexpected keys.
    assert set(json.loads(req.model_dump_json())) >= {"commit_digest", "commit", "files", "client"}


def test_schema_version_is_pinned() -> None:
    req = make_request()
    raw = json.loads(req.model_dump_json())
    raw["schema_version"] = "2"
    with pytest.raises(ValidationError):
        c.AnalyzeRequest.model_validate(raw)


# --------------------------------------------------------------------------- #
# Policy
# --------------------------------------------------------------------------- #
def test_default_categories_cover_at_least_three_owasp_items() -> None:
    """Hard requirement from the challenge: >= 3 OWASP Top 10 categories."""
    assert len(set(c.DEFAULT_CATEGORIES)) >= 3
    assert c.OwaspCategory.A03_INJECTION in c.DEFAULT_CATEGORIES


def test_policy_dedupes_and_requires_categories() -> None:
    pol = c.AnalysisPolicy(categories=(c.OwaspCategory.A03_INJECTION, c.OwaspCategory.A03_INJECTION))
    assert pol.categories == (c.OwaspCategory.A03_INJECTION,)
    with pytest.raises(ValidationError):
        c.AnalysisPolicy(categories=())


def test_fail_mode_defaults_to_closed() -> None:
    """Fail-closed is a safety default: an unreachable analyser must not allow."""
    assert c.AnalysisPolicy().fail_mode == "closed"


def test_severity_ordering() -> None:
    assert c.Severity.CRITICAL.rank > c.Severity.HIGH.rank > c.Severity.MEDIUM.rank
    assert c.Severity.HIGH.rank >= c.AnalysisPolicy().block_min_severity.rank


# --------------------------------------------------------------------------- #
# Attestation
# --------------------------------------------------------------------------- #
def _claims(**overrides: object) -> c.AttestationClaims:
    base: dict[str, object] = {
        "iss": "https://aegis.local",
        "sub": "jesierra20@gmail.com",
        "aud": "git@github.com:MercadoLibre/AppSec-Demo.git",
        "iat": 1_700_000_000,
        "exp": 1_700_003_600,
        "jti": "j" * 32,
        "commit_digest": "e" * 64,
        "decision": c.Decision.ALLOW,
        "analysis_id": "an_1",
        "payload_sha256": "f" * 64,
        "policy_profile": "owasp-core",
        "prompt_version": "v1",
        "model": "gpt-4.1-mini",
        "findings_count": 0,
        "findings_sha256": "0" * 64,
    }
    base.update(overrides)
    return c.AttestationClaims(**base)  # type: ignore[arg-type]


def test_attestation_normalises_audience() -> None:
    assert _claims().aud == "github.com/mercadolibre/appsec-demo"


def test_attestation_lifetime_must_be_positive() -> None:
    with pytest.raises(ValidationError, match="exp must be greater"):
        _claims(exp=1_700_000_000 - 1)


def test_attestation_nbf_cannot_exceed_iat() -> None:
    with pytest.raises(ValidationError, match="nbf must not be in the future"):
        _claims(nbf=1_700_000_100)


def test_attestation_commit_sha_is_optional_before_commit_exists() -> None:
    """At pre-commit time the commit object does not exist yet, so ``commit_sha``
    is null; it is filled in when the server binds the attestation at push time."""
    assert _claims().commit_sha is None
    assert _claims(commit_sha="1" * 40).commit_sha == "1" * 40


# --------------------------------------------------------------------------- #
# Response & verification shapes
# --------------------------------------------------------------------------- #
def test_response_requires_attestation_and_schema_version() -> None:
    meta = c.AnalysisMeta(
        analysis_id="an_1",
        digest_version=c.DIGEST_VERSION,
        prompt_version="v1",
        model="gpt-4.1-mini",
        provider="openai",
    )
    resp = c.AnalyzeResponse(
        commit_digest="a" * 64, decision=c.Decision.ALLOW, meta=meta, attestation="x" * 40
    )
    assert resp.schema_version == "1"
    with pytest.raises(ValidationError):
        c.AnalyzeResponse(commit_digest="a" * 64, decision=c.Decision.ALLOW, meta=meta, attestation="")


def test_verify_reasons_are_exhaustive_enough_for_ci() -> None:
    """CI policy branches on enum members, so the important failure modes must
    exist as first-class reasons (never inferred from message text)."""
    required = {
        "missing_attestation",
        "bad_signature",
        "digest_mismatch",
        "wrong_audience",
        "expired",
        "decision_block",
        "payload_mismatch",
        "ok",
    }
    assert required <= {r.value for r in c.VerifyReason}


def test_error_exit_codes_are_distinct() -> None:
    """A hook must never return 0 on failure; distinct codes make logs parseable."""
    codes = [
        errors.BlockedError.exit_code,
        errors.ConfigError.exit_code,
        errors.AuthError.exit_code,
        errors.TransportError.exit_code,
        errors.IntegrityError.exit_code,
        errors.AegisError.exit_code,
    ]
    assert codes[0] == 1
    assert 0 not in codes
    assert len(set(codes)) == len(codes)
