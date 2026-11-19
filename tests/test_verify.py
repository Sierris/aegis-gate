"""Verifier tests: every way an attestation can lie, and what catches it.

This file is the counter-argument to "a signed JSON file must be fine". Each test
takes a valid attestation and breaks exactly one thing, so the reason reported by
the verifier can be asserted — CI policy branches on those reasons, so a wrong
reason is a wrong decision.
"""

from __future__ import annotations

import json
import subprocess
import time
from pathlib import Path
from typing import Any

import jwt
import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from aegis.attest import (
    AttestationVerifier,
    Jwks,
    VerificationError,
    check_commit,
    sign_attestation,
)
from aegis.auth.keys import SigningKey
from aegis.contracts import Decision, OwaspCategory, Severity, VerifyReason
from aegis.errors import ConfigError, IntegrityError
from aegis.gitx import GitRepo, all_commits, resolve_range, verify_range

ISSUER = "http://aegis.test"
REPO_ID = "github.com/mercadolibre/verify-test"
NOW = 1_700_000_000.0


def make_claims(**overrides: Any) -> dict[str, Any]:
    base: dict[str, Any] = {
        "iss": ISSUER,
        "sub": "dev@mercadolibre.com",
        "aud": REPO_ID,
        "iat": int(NOW) - 60,
        "nbf": int(NOW) - 60,
        "exp": int(NOW) + 3600,
        "jti": "j" * 32,
        "commit_digest": "a" * 64,
        "decision": "allow",
        "analysis_id": "an_1",
        "payload_sha256": "b" * 64,
        "policy_profile": "owasp-core",
        "prompt_version": "analyze.v1@abc123",
        "model": "commandcode/gpt-6-luna",
        "findings_count": 0,
        "findings_sha256": "c" * 64,
        "scope": "analyze",
    }
    base.update(overrides)
    return base


def sign(claims: dict[str, Any], key: SigningKey) -> str:
    return jwt.encode(claims, key.private_key, algorithm="EdDSA", headers={"kid": key.kid, "typ": "JWT"})


@pytest.fixture
def key() -> SigningKey:
    return SigningKey.generate()


@pytest.fixture
def verifier(key: SigningKey) -> AttestationVerifier:
    return AttestationVerifier(
        jwks=Jwks({key.kid: key.public_key}),
        issuer=ISSUER,
        now=lambda: NOW,
    )


# --------------------------------------------------------------------------- #
# JWKS
# --------------------------------------------------------------------------- #
def test_jwks_round_trip(key: SigningKey) -> None:
    jwks = Jwks.from_json({"keys": [key.public_jwk().model_dump()]})
    assert key.kid in jwks
    assert jwks.kids == (key.kid,)
    assert jwks.public_key(key.kid) is not None


def test_jwks_rejects_a_kid_that_does_not_match_its_key(key: SigningKey) -> None:
    """kid is derived from the key; a mismatch would let two keys claim one id."""
    entry = key.public_jwk().model_dump()
    entry["kid"] = "forged-kid"
    with pytest.raises(IntegrityError, match="does not match its key"):
        Jwks.from_json({"keys": [entry]})


def test_jwks_rejects_a_short_key() -> None:
    with pytest.raises(IntegrityError, match="32-byte"):
        Jwks.from_json({"keys": [{"kty": "OKP", "crv": "Ed25519", "kid": "x", "x": "AAAA"}]})


def test_jwks_rejects_an_empty_set() -> None:
    with pytest.raises(IntegrityError, match="no usable keys"):
        Jwks.from_json({"keys": []})


def test_jwks_skips_non_ed25519_entries(key: SigningKey) -> None:
    jwks = Jwks.from_json({"keys": [{"kty": "RSA", "kid": "rsa-1"}, key.public_jwk().model_dump()]})
    assert jwks.kids == (key.kid,)


def test_jwks_loads_from_a_file(key: SigningKey, tmp_path: Path) -> None:
    path = tmp_path / "jwks.json"
    path.write_text(json.dumps({"keys": [key.public_jwk().model_dump()]}), encoding="utf-8")
    assert key.kid in Jwks.load(path)


def test_jwks_missing_file_is_a_clear_error(tmp_path: Path) -> None:
    with pytest.raises(IntegrityError, match="cannot read JWKS"):
        Jwks.load(tmp_path / "nope.json")


# --------------------------------------------------------------------------- #
# Happy path
# --------------------------------------------------------------------------- #
def test_valid_attestation_verifies(verifier: AttestationVerifier, key: SigningKey) -> None:
    claims = verifier.verify(sign(make_claims(), key), audience=REPO_ID)
    assert claims.sub == "dev@mercadolibre.com"
    assert claims.decision is Decision.ALLOW


def test_full_signer_integration(verifier: AttestationVerifier, key: SigningKey) -> None:
    """The real signer's output must be accepted by the real verifier."""
    token = sign_attestation(
        key=key,
        issuer=ISSUER,
        audience=REPO_ID,
        subject="dev@mercadolibre.com",
        commit_digest="a" * 64,
        decision=Decision.ALLOW,
        analysis_id="an_1",
        payload_sha256="b" * 64,
        policy_profile="owasp-core",
        prompt_version="analyze.v1@abc123",
        model="commandcode/gpt-6-luna",
        findings=[],
        scope="analyze",
        jti="j" * 32,
        categories=[OwaspCategory.A03_INJECTION],
        now=lambda: NOW,
    )
    claims = verifier.verify(token, audience=REPO_ID)
    assert claims.commit_digest == "a" * 64
    assert claims.severity_max is Severity.INFO


# --------------------------------------------------------------------------- #
# Forgery attempts
# --------------------------------------------------------------------------- #
def test_alg_none_is_rejected(verifier: AttestationVerifier) -> None:
    header = jwt.utils.base64url_encode(
        json.dumps({"alg": "none", "typ": "JWT", "kid": "whatever"}).encode()
    ).decode()
    payload = jwt.utils.base64url_encode(json.dumps(make_claims()).encode()).decode()
    with pytest.raises(VerificationError) as exc:
        verifier.verify(f"{header}.{payload}.", audience=REPO_ID)
    assert exc.value.reason is VerifyReason.BAD_SIGNATURE
    assert "unsupported algorithm" in exc.value.detail


def test_hs256_signed_with_the_public_key_is_rejected(verifier: AttestationVerifier, key: SigningKey) -> None:
    """The classic confusion attack, assembled by hand."""
    import hashlib
    import hmac

    from aegis.auth.keys import b64url

    public_raw = key.raw_public
    header = b64url(json.dumps({"alg": "HS256", "typ": "JWT", "kid": key.kid}).encode())
    payload = b64url(json.dumps(make_claims()).encode())
    signature = b64url(hmac.new(public_raw, f"{header}.{payload}".encode(), hashlib.sha256).digest())
    with pytest.raises(VerificationError) as exc:
        verifier.verify(f"{header}.{payload}.{signature}", audience=REPO_ID)
    assert exc.value.reason is VerifyReason.BAD_SIGNATURE


def test_token_signed_by_another_key_is_rejected(verifier: AttestationVerifier) -> None:
    rogue = SigningKey.generate()
    token = jwt.encode(make_claims(), rogue.private_key, algorithm="EdDSA", headers={"kid": rogue.kid})
    with pytest.raises(VerificationError) as exc:
        verifier.verify(token, audience=REPO_ID)
    assert exc.value.reason is VerifyReason.UNKNOWN_KEY


def test_unsigned_edit_of_the_payload_is_rejected(verifier: AttestationVerifier, key: SigningKey) -> None:
    token = sign(make_claims(), key)
    header, _, signature = token.split(".")
    forged = jwt.utils.base64url_encode(
        json.dumps(make_claims(decision="allow", sub="attacker@evil.com")).encode()
    ).decode()
    with pytest.raises(VerificationError):
        verifier.verify(f"{header}.{forged}.{signature}", audience=REPO_ID)


def test_missing_kid_is_rejected(verifier: AttestationVerifier) -> None:
    token = jwt.encode(make_claims(), Ed25519PrivateKey.generate(), algorithm="EdDSA")
    with pytest.raises(VerificationError) as exc:
        verifier.verify(token, audience=REPO_ID)
    assert exc.value.reason is VerifyReason.BAD_SIGNATURE
    assert "no kid" in exc.value.detail


def test_oversized_token_is_rejected(verifier: AttestationVerifier) -> None:
    with pytest.raises(VerificationError) as exc:
        verifier.verify("a" * 10_000, audience=REPO_ID)
    assert exc.value.reason is VerifyReason.BAD_SIGNATURE


# --------------------------------------------------------------------------- #
# Claim-level failures
# --------------------------------------------------------------------------- #
def test_wrong_audience_is_rejected(verifier: AttestationVerifier, key: SigningKey) -> None:
    """An attestation for another repo must not cover this one."""
    token = sign(make_claims(aud="github.com/other/repo"), key)
    with pytest.raises(VerificationError) as exc:
        verifier.verify(token, audience=REPO_ID)
    assert exc.value.reason is VerifyReason.WRONG_AUDIENCE


def test_wrong_issuer_is_rejected(verifier: AttestationVerifier, key: SigningKey) -> None:
    token = sign(make_claims(iss="http://evil.test"), key)
    with pytest.raises(VerificationError) as exc:
        verifier.verify(token, audience=REPO_ID)
    assert exc.value.reason is VerifyReason.ISSUER_MISMATCH


def test_expired_attestation_is_rejected(verifier: AttestationVerifier, key: SigningKey) -> None:
    token = sign(make_claims(iat=int(NOW) - 7200, nbf=int(NOW) - 7200, exp=int(NOW) - 3600), key)
    with pytest.raises(VerificationError) as exc:
        verifier.verify(token, audience=REPO_ID)
    assert exc.value.reason is VerifyReason.EXPIRED


def test_not_yet_valid_attestation_is_rejected(verifier: AttestationVerifier, key: SigningKey) -> None:
    token = sign(make_claims(iat=int(NOW) + 7200, nbf=int(NOW) + 7200, exp=int(NOW) + 9000), key)
    with pytest.raises(VerificationError) as exc:
        verifier.verify(token, audience=REPO_ID)
    assert exc.value.reason is VerifyReason.NOT_YET_VALID


def test_issue_date_in_the_future_is_rejected(verifier: AttestationVerifier, key: SigningKey) -> None:
    token = sign(make_claims(iat=int(NOW) + 7200), key)
    with pytest.raises(VerificationError) as exc:
        verifier.verify(token, audience=REPO_ID)
    assert exc.value.reason is VerifyReason.NOT_YET_VALID


def test_leeway_tolerates_small_clock_skew(key: SigningKey) -> None:
    """30 s of skew is normal between hosts; 300 s of leeway must absorb it."""
    verifier = AttestationVerifier(
        jwks=Jwks({key.kid: key.public_key}),
        issuer=ISSUER,
        leeway_seconds=300,
        now=lambda: NOW,
    )
    token = sign(make_claims(iat=int(NOW) - 600, nbf=int(NOW) - 600, exp=int(NOW) - 60), key)
    assert verifier.verify(token, audience=REPO_ID).decision is Decision.ALLOW


def test_missing_required_claim_is_rejected(verifier: AttestationVerifier, key: SigningKey) -> None:
    claims = make_claims()
    claims.pop("payload_sha256")
    with pytest.raises(VerificationError):
        verifier.verify(sign(claims, key), audience=REPO_ID)


# --------------------------------------------------------------------------- #
# Commit-level checks
# --------------------------------------------------------------------------- #
def note_for(token: str, **overrides: Any) -> str:
    payload = {"version": 1, "decision": "allow", "attestation": token}
    payload.update(overrides)
    return json.dumps(payload)


def test_check_commit_ok(verifier: AttestationVerifier, key: SigningKey) -> None:
    token = sign(make_claims(commit_digest="d" * 64), key)
    result = check_commit(
        verifier=verifier,
        note=note_for(token),
        commit_sha="1" * 40,
        commit_digest="d" * 64,
        repo_id=REPO_ID,
    )
    assert result.ok is True
    assert result.reason is VerifyReason.OK


def test_check_commit_detects_a_different_tree(verifier: AttestationVerifier, key: SigningKey) -> None:
    """The core claim: analyse A, push B."""
    token = sign(make_claims(commit_digest="d" * 64), key)
    result = check_commit(
        verifier=verifier,
        note=note_for(token),
        commit_sha="1" * 40,
        commit_digest="e" * 64,  # the real commit
        repo_id=REPO_ID,
    )
    assert result.ok is False
    assert result.reason is VerifyReason.DIGEST_MISMATCH
    assert "modified after analysis" in result.detail


def test_check_commit_detects_a_named_commit_mismatch(verifier: AttestationVerifier, key: SigningKey) -> None:
    token = sign(make_claims(commit_digest="d" * 64, commit_sha="2" * 40), key)
    result = check_commit(
        verifier=verifier,
        note=note_for(token),
        commit_sha="1" * 40,
        commit_digest="d" * 64,
        repo_id=REPO_ID,
    )
    assert result.reason is VerifyReason.DIGEST_MISMATCH
    assert "names commit" in result.detail


def test_check_commit_rejects_a_block_attestation(verifier: AttestationVerifier, key: SigningKey) -> None:
    """A signed `block` is proof of the opposite of permission."""
    token = sign(make_claims(commit_digest="d" * 64, decision="block"), key)
    result = check_commit(
        verifier=verifier,
        note=note_for(token),
        commit_sha="1" * 40,
        commit_digest="d" * 64,
        repo_id=REPO_ID,
    )
    assert result.ok is False
    assert result.reason is VerifyReason.DECISION_BLOCK


def test_allow_override_is_accepted(verifier: AttestationVerifier, key: SigningKey) -> None:
    token = sign(make_claims(commit_digest="d" * 64, decision="allow_override"), key)
    result = check_commit(
        verifier=verifier,
        note=note_for(token),
        commit_sha="1" * 40,
        commit_digest="d" * 64,
        repo_id=REPO_ID,
    )
    assert result.ok is True


@pytest.mark.parametrize("note", [None, "not json", "{}", '{"attestation": ""}'])
def test_missing_or_broken_note_is_reported(verifier: AttestationVerifier, note: str | None) -> None:
    result = check_commit(
        verifier=verifier,
        note=note,
        commit_sha="1" * 40,
        commit_digest="d" * 64,
        repo_id=REPO_ID,
    )
    assert result.ok is False
    assert result.reason is VerifyReason.MISSING_ATTESTATION


def test_report_only_mode_does_not_fail_for_a_missing_note(
    verifier: AttestationVerifier,
) -> None:
    result = check_commit(
        verifier=verifier,
        note=None,
        commit_sha="1" * 40,
        commit_digest="d" * 64,
        repo_id=REPO_ID,
        require_attestation=False,
    )
    assert result.ok is True
    assert result.reason is VerifyReason.UNVERIFIED_LOCAL


# --------------------------------------------------------------------------- #
# Against real repositories
# --------------------------------------------------------------------------- #
def git(repo: Path, *args: str) -> str:
    return subprocess.run(
        ["git", *args], cwd=str(repo), capture_output=True, text=True, check=True
    ).stdout.strip()


@pytest.fixture
def attested_repo(tmp_path: Path, key: SigningKey) -> tuple[GitRepo, list[str], str]:
    """A repository with two commits, each carrying a valid attestation."""
    root = tmp_path / "repo"
    root.mkdir()
    git(root, "init", "-q", "-b", "main")
    git(root, "config", "user.name", "Dev")
    git(root, "config", "user.email", "dev@mercadolibre.com")
    git(root, "remote", "add", "origin", "git@github.com:mercadolibre/verify-test.git")
    (root / "a.py").write_text("print('one')\n")
    git(root, "add", "a.py")
    git(root, "commit", "-q", "-m", "feat: one")
    (root / "b.py").write_text("print('two')\n")
    git(root, "add", "b.py")
    git(root, "commit", "-q", "-m", "feat: two")

    repo = GitRepo.discover(root)
    commits = all_commits(repo)
    for sha in commits:
        digest = repo.commit_digest(sha)
        token = sign(make_claims(commit_digest=digest, commit_sha=sha), key)
        repo.write_note(sha, note_for(token))
    return repo, commits, REPO_ID


def test_verify_range_accepts_a_fully_attested_range(
    attested_repo: tuple[GitRepo, list[str], str], key: SigningKey
) -> None:
    repo, commits, _ = attested_repo
    verifier = AttestationVerifier(jwks=Jwks({key.kid: key.public_key}), issuer=ISSUER, now=lambda: NOW)
    report = verify_range(repo, commits, verifier=verifier)
    assert report.all_ok is True
    assert len(report.results) == 2
    assert report.counts() == {"ok": 2}


def test_verify_range_catches_a_commit_rewritten_after_attestation(
    attested_repo: tuple[GitRepo, list[str], str], key: SigningKey, tmp_path: Path
) -> None:
    """The exact scenario the control exists for: amend after an allow."""
    repo, commits, _ = attested_repo
    verifier = AttestationVerifier(jwks=Jwks({key.kid: key.public_key}), issuer=ISSUER, now=lambda: NOW)
    # Rewrite the last commit (new tree, same note is now stale).
    (repo.root / "a.py").write_text("import os\nos.system(input())\n")
    git(repo.root, "add", "a.py")
    git(repo.root, "commit", "-q", "--amend", "--no-edit")
    rewritten = repo.head_sha() or ""

    report = verify_range(repo, [rewritten], verifier=verifier)
    assert report.all_ok is False
    assert report.results[0].reason is VerifyReason.MISSING_ATTESTATION


def test_verify_range_detects_a_tampered_note(
    attested_repo: tuple[GitRepo, list[str], str], key: SigningKey
) -> None:
    """Anyone can write a note; nobody can forge the signature."""
    repo, commits, _ = attested_repo
    verifier = AttestationVerifier(jwks=Jwks({key.kid: key.public_key}), issuer=ISSUER, now=lambda: NOW)
    rogue = SigningKey.generate()
    digest = repo.commit_digest(commits[-1])
    forged = sign(make_claims(commit_digest=digest), rogue)
    repo.write_note(commits[-1], note_for(forged))

    report = verify_range(repo, [commits[-1]], verifier=verifier)
    assert report.all_ok is False
    assert report.results[0].reason is VerifyReason.UNKNOWN_KEY


def test_verify_range_reports_missing_attestations(
    attested_repo: tuple[GitRepo, list[str], str], key: SigningKey
) -> None:
    """The `--no-verify` case, which is what CI must catch."""
    repo, commits, _ = attested_repo
    verifier = AttestationVerifier(jwks=Jwks({key.kid: key.public_key}), issuer=ISSUER, now=lambda: NOW)
    git(repo.root, "notes", "--ref=aegis", "remove", commits[-1])
    report = verify_range(repo, commits, verifier=verifier)
    assert report.all_ok is False
    assert [r.reason for r in report.failures] == [VerifyReason.MISSING_ATTESTATION]
    assert "no-verify" in report.failures[0].detail


def test_merge_commits_are_skipped_by_default(
    attested_repo: tuple[GitRepo, list[str], str], key: SigningKey
) -> None:
    repo, commits, _ = attested_repo
    git(repo.root, "checkout", "-q", "-b", "side")
    (repo.root / "c.py").write_text("print('three')\n")
    git(repo.root, "add", "c.py")
    git(repo.root, "commit", "-q", "-m", "feat: three")
    git(repo.root, "checkout", "-q", "main")
    (repo.root / "d.py").write_text("print('four')\n")
    git(repo.root, "add", "d.py")
    git(repo.root, "commit", "-q", "-m", "feat: four")
    git(repo.root, "merge", "-q", "--no-ff", "-m", "merge", "side")

    verifier = AttestationVerifier(jwks=Jwks({key.kid: key.public_key}), issuer=ISSUER, now=lambda: NOW)
    report = verify_range(repo, resolve_range(repo, "HEAD~3..HEAD"), verifier=verifier)
    assert report.skipped_merges, "the merge commit must be skipped, not failed"


def test_audience_is_taken_from_the_repo_not_the_note(
    attested_repo: tuple[GitRepo, list[str], str], key: SigningKey
) -> None:
    """An attestation minted for another repository must not verify here."""
    repo, commits, _ = attested_repo
    other = sign(make_claims(commit_digest=repo.commit_digest(commits[-1]), aud="github.com/other/repo"), key)
    repo.write_note(commits[-1], note_for(other))
    verifier = AttestationVerifier(jwks=Jwks({key.kid: key.public_key}), issuer=ISSUER, now=lambda: NOW)
    report = verify_range(repo, [commits[-1]], verifier=verifier)
    assert report.results[0].reason is VerifyReason.WRONG_AUDIENCE


# --------------------------------------------------------------------------- #
# Trust anchor
# --------------------------------------------------------------------------- #
def test_missing_trust_anchor_is_a_config_error(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    from aegis.cli.verify import jwks_source

    monkeypatch.chdir(tmp_path)
    monkeypatch.delenv("AEGIS_JWKS", raising=False)
    monkeypatch.delenv("AEGIS_JWKS_FILE", raising=False)
    with pytest.raises(ConfigError, match="trust anchor"):
        jwks_source(None)


def test_pinned_jwks_file_is_discovered(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    from aegis.cli.verify import jwks_source

    monkeypatch.chdir(tmp_path)
    monkeypatch.delenv("AEGIS_JWKS", raising=False)
    monkeypatch.delenv("AEGIS_JWKS_FILE", raising=False)
    (tmp_path / ".aegis").mkdir()
    (tmp_path / ".aegis" / "jwks.json").write_text('{"keys":[]}', encoding="utf-8")
    assert jwks_source(None).endswith("jwks.json")


def test_signing_time_matches_verification_time(key: SigningKey) -> None:
    """The signer and the verifier must agree on the temporal window."""
    token = sign_attestation(
        key=key,
        issuer=ISSUER,
        audience=REPO_ID,
        subject="dev@mercadolibre.com",
        commit_digest="a" * 64,
        decision=Decision.ALLOW,
        analysis_id="an_1",
        payload_sha256="b" * 64,
        policy_profile="owasp-core",
        prompt_version="analyze.v1@abc123",
        model="model",
        findings=[],
        scope="analyze",
        jti="j" * 32,
        ttl_seconds=60,
        now=lambda: NOW,
    )
    verifier = AttestationVerifier(
        jwks=Jwks(dict.fromkeys([key.kid], key.public_key)),
        issuer=ISSUER,
        now=lambda: NOW + 30,
    )
    assert verifier.verify(token, audience=REPO_ID)
    expired = AttestationVerifier(jwks=Jwks({key.kid: key.public_key}), issuer=ISSUER, now=lambda: NOW + 600)
    with pytest.raises(VerificationError) as exc:
        expired.verify(token, audience=REPO_ID)
    assert exc.value.reason is VerifyReason.EXPIRED


def test_clock_is_injected_not_read_from_the_system(key: SigningKey) -> None:
    """Otherwise the tests would be time bombs and CI could flake at midnight."""
    token = sign(make_claims(exp=int(time.time()) - 10), key)
    verifier = AttestationVerifier(jwks=Jwks({key.kid: key.public_key}), issuer=ISSUER, now=lambda: NOW)
    # "now" is 2023 so a token that expired compared to the real clock is valid here.
    assert verifier.verify(token, audience=REPO_ID)
