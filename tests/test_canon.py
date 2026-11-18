"""Tests for the canonicalisation / digest primitives.

These are the highest-value tests in the project: if ``compute_commit_digest``
is not a *pure, order-independent function of git object data*, the whole
integrity story collapses into a signature over whatever the client felt like
sending.
"""

from __future__ import annotations

from collections.abc import Iterable

import pytest

from aegis import canon
from aegis.canon import FileEntry

REPO = "git@github.com:MercadoLibre/appsec-demo.git"
PARENT = "a" * 40
BLOB1 = "1" * 64
BLOB2 = "2" * 64
MSG = canon.message_digest("feat: add endpoint")


def _digest(
    entries: Iterable[FileEntry],
    *,
    repo_id: str = REPO,
    parent_sha: str | None = PARENT,
    email: str = "dev@mercadolibre.com",
) -> str:
    return canon.compute_commit_digest(
        repo_id=repo_id,
        parent_sha=parent_sha,
        author_email=email,
        message_sha256=MSG,
        entries=entries,
    )


# --------------------------------------------------------------------------- #
# normalize_repo_id
# --------------------------------------------------------------------------- #
@pytest.mark.parametrize(
    "raw",
    [
        "git@github.com:MercadoLibre/appsec-demo.git",
        "https://github.com/MercadoLibre/appsec-demo.git",
        "https://github.com/MercadoLibre/appsec-demo",
        "https://user:s3cr3t@github.com/MercadoLibre/appsec-demo.git",
        "ssh://git@github.com:22/MercadoLibre/appsec-demo.git",
        "  github.com/MercadoLibre/appsec-demo/  ",
    ],
)
def test_normalize_repo_id_collapses_all_clone_forms(raw: str) -> None:
    assert canon.normalize_repo_id(raw) == "github.com/mercadolibre/appsec-demo"


def test_normalize_repo_id_strips_credentials() -> None:
    """A token embedded in the remote URL must never reach a digest or a log."""
    out = canon.normalize_repo_id("https://x-access-token:ghp_deadbeef@github.com/o/r.git")
    assert "ghp_" not in out
    assert "x-access-token" not in out


@pytest.mark.parametrize("bad", ["", "   ", "github.com", "https://github.com/"])
def test_normalize_repo_id_rejects_incomplete(bad: str) -> None:
    with pytest.raises(ValueError, match=r"cannot derive|must not be empty"):
        canon.normalize_repo_id(bad)


# --------------------------------------------------------------------------- #
# normalize_path
# --------------------------------------------------------------------------- #
@pytest.mark.parametrize(
    ("raw", "expected"),
    [
        ("src/app.py", "src/app.py"),
        ("./src/app.py", "src/app.py"),
        ("/src/app.py", "src/app.py"),
        ("src//app.py", "src/app.py"),
        ("src\\app.py", "src/app.py"),
        ("src/app.py/", "src/app.py"),
    ],
)
def test_normalize_path(raw: str, expected: str) -> None:
    assert canon.normalize_path(raw) == expected


@pytest.mark.parametrize("bad", ["../etc/passwd", "a/../../b", "src/\x00app.py", "", "/"])
def test_normalize_path_rejects_escapes_and_empty(bad: str) -> None:
    with pytest.raises(ValueError, match=r"empty path|escapes the repository|NUL"):
        canon.normalize_path(bad)


def test_normalize_path_applies_nfc() -> None:
    """macOS can hand us decomposed Unicode while git stores NFC."""
    decomposed = "src/cafe\u0301.py"
    composed = "src/caf\u00e9.py"
    assert canon.normalize_path(decomposed) == canon.normalize_path(composed)


# --------------------------------------------------------------------------- #
# commit message
# --------------------------------------------------------------------------- #
def test_commit_message_trailers_are_not_part_of_the_digest() -> None:
    """Adding an AEGIS trailer after the analysis must not change the digest."""
    plain = "fix: validate input\n\nRefs: JIRA-1\n"
    with_trailer = plain + "Aegis-Attestation: eyJhbGciOiJFZERTQSJ9.x.y\n"
    assert canon.message_digest(plain) == canon.message_digest(with_trailer)


def test_commit_message_normalises_line_endings_and_blank_runs() -> None:
    a = "feat: x\r\n\r\n\r\nbody   \r\n"
    b = "feat: x\n\nbody\n"
    assert canon.message_digest(a) == canon.message_digest(b)


def test_commit_message_body_changes_do_change_the_digest() -> None:
    assert canon.message_digest("feat: x\n\nbody") != canon.message_digest("feat: x")


# --------------------------------------------------------------------------- #
# compute_commit_digest
# --------------------------------------------------------------------------- #
def test_digest_is_independent_of_file_order() -> None:
    """Directory iteration order differs across APFS/ext4/NTFS — the digest must not."""
    entries = [
        ("A", "100644", BLOB1, "src/b.py", None),
        ("M", "100755", BLOB2, "src/a.py", None),
        ("D", "100644", None, "src/c.py", None),
    ]
    assert _digest(entries) == _digest(list(reversed(entries)))


def test_digest_is_stable_and_matches_golden_value() -> None:
    """Golden value: locks the wire format. A change here invalidates every
    historical attestation, so it must be a deliberate, reviewed edit.
    """
    entries = [("A", "100644", BLOB1, "src/app.py", None)]
    assert _digest(entries) == _GOLDEN


def test_digest_changes_when_any_field_changes() -> None:
    base = [("A", "100644", BLOB1, "src/app.py", None)]
    variants = {
        "content": [("A", "100644", BLOB2, "src/app.py", None)],
        "path": [("A", "100644", BLOB1, "src/other.py", None)],
        "mode": [("A", "100755", BLOB1, "src/app.py", None)],
        "kind": [("M", "100644", BLOB1, "src/app.py", None)],
    }
    expected = _digest(base)
    for label, entries in variants.items():
        assert _digest(entries) != expected, f"{label} must affect the digest"


def test_digest_changes_with_context() -> None:
    entries = [("A", "100644", BLOB1, "src/app.py", None)]
    base = _digest(entries)
    assert _digest(entries, repo_id="github.com/other/repo") != base
    assert _digest(entries, parent_sha=None) != base
    assert _digest(entries, email="attacker@evil.com") != base


def test_root_commit_uses_null_parent_sentinel() -> None:
    payload = canon.commit_digest_payload(
        repo_id=REPO,
        parent_sha=None,
        author_email="dev@mercadolibre.com",
        message_sha256=MSG,
        entries=[],
    )
    assert "parent=-\n" in payload


def test_rename_entry_records_source_path() -> None:
    entries = [("R", "100644", BLOB1, "src/new.py", "src/old.py")]
    payload = canon.commit_digest_payload(
        repo_id=REPO, parent_sha=PARENT, author_email="d@e.com", message_sha256=MSG, entries=entries
    )
    assert "file R 100644 " + BLOB1 + " src/new.py -> src/old.py" in payload


def test_duplicate_paths_are_rejected() -> None:
    entries = [
        ("A", "100644", BLOB1, "src/app.py", None),
        ("M", "100644", BLOB2, "src/app.py", None),
    ]
    with pytest.raises(ValueError, match="duplicate path"):
        _digest(entries)


def test_unknown_digest_version_is_rejected() -> None:
    with pytest.raises(ValueError, match="unsupported digest version"):
        canon.compute_commit_digest(
            version="aegis-digest/v0",
            repo_id=REPO,
            parent_sha=PARENT,
            author_email="d@e.com",
            message_sha256=MSG,
            entries=[],
        )


def test_empty_commit_is_deterministic() -> None:
    assert _digest([]) == _digest([])


# --------------------------------------------------------------------------- #
# fragments_digest
# --------------------------------------------------------------------------- #
def test_fragments_digest_binds_text_not_only_paths() -> None:
    a = canon.fragments_digest([("src/app.py", "os.system(x)", 1, 1)])
    b = canon.fragments_digest([("src/app.py", "subprocess.run(x)", 1, 1)])
    assert a != b


def test_fragments_digest_is_order_independent() -> None:
    f1 = ("src/a.py", "x = 1", 1, 1)
    f2 = ("src/b.py", "y = 2", 10, 12)
    assert canon.fragments_digest([f1, f2]) == canon.fragments_digest([f2, f1])


# --------------------------------------------------------------------------- #
# canonical_json / chain_hash
# --------------------------------------------------------------------------- #
def test_canonical_json_is_key_order_independent() -> None:
    assert canon.canonical_json({"b": 1, "a": [2, 3]}) == canon.canonical_json({"a": [2, 3], "b": 1})


def test_canonical_json_produces_compact_bytes() -> None:
    assert canon.canonical_json({"a": 1}) == b'{"a":1}'


def test_chain_hash_links_events_and_detects_rewrites() -> None:
    genesis = canon.GENESIS_HASH
    h1 = canon.chain_hash(prev_hash=genesis, event={"action": "a", "seq": 0})
    h2 = canon.chain_hash(prev_hash=h1, event={"action": "b", "seq": 1})

    # Same events in same order -> same chain (reproducible verification).
    assert canon.chain_hash(prev_hash=genesis, event={"action": "a", "seq": 0}) == h1

    # Rewriting event 0 breaks link 1.
    forged = canon.chain_hash(prev_hash=genesis, event={"action": "a", "seq": 0, "actor": "x"})
    assert canon.chain_hash(prev_hash=forged, event={"action": "b", "seq": 1}) != h2


def test_chain_hash_keyed_mode_requires_the_key() -> None:
    key, other = b"k1" * 16, b"k2" * 16
    event = {"action": "analyze.block"}
    assert canon.chain_hash(prev_hash=canon.GENESIS_HASH, event=event) != (
        canon.chain_hash(prev_hash=canon.GENESIS_HASH, event=event, key=key)
    )
    assert canon.chain_hash(prev_hash=canon.GENESIS_HASH, event=event, key=key) != (
        canon.chain_hash(prev_hash=canon.GENESIS_HASH, event=event, key=other)
    )


#: Computed with the v1 format. Regenerate only with an explicit digest-version
#: bump — every historical attestation becomes unverifiable otherwise.
_GOLDEN = "fc4686151588a707e67b677475165157f06df105cb91944e9824904ddc010c73"
