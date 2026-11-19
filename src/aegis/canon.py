"""Canonicalisation and digest primitives — the integrity backbone of AEGIS.

Why this module exists
----------------------
AEGIS claims the following invariant:

    the bytes analysed at commit time  ==  the bytes that reach the remote

For that claim to be *verifiable* instead of *promised*, the client (git hook)
and the verifier (server, and the CI job) must be able to derive **the exact
same digest** from two different inputs:

    client :  the contents of the git *index* (what the developer is about to commit)
    server :  the git *commit object* (what actually landed in the repository)

Hence the digest must be a pure function of git object data only:

    * repository identity (``host/owner/repo``)
    * parent commit SHA (the base the diff is taken against)
    * author identity (name + e-mail, normalised)
    * the staged file *entries*: (change kind, mode, blob sha256, path, old_path)

The commit message is **not** part of v2, and the reason is empirical: a
``pre-commit`` hook runs *before* git composes the message. ``.git/COMMIT_EDITMSG``
does not exist for ``git commit -m`` and, on the second commit of a session,
contains the **previous** message. Binding a value the client cannot observe would
leave only two options — a permanent mismatch or a verification path that accepts
"unknown" — and the second one is a bypass. v1 included it; v2 removes it and the
golden test in ``tests/test_canon.py`` exists to force exactly this kind of change
to be deliberate.

Deliberate exclusions and why:

    * **Unified diff text** — excluded. Diff hunks depend on the diff algorithm,
      context width, ``core.*`` options and git version. Two different git
      versions can render the same change differently. Blob SHA-256 covers the
      full post-image content, which is strictly *stronger* evidence than a hunk
      list, and is bit-for-bit reproducible with ``git hash-object``.
    * **Timestamps** — excluded, so a ``rebase`` / ``cherry-pick`` that only
      rewrites committer/author *dates* keeps the digest valid. This is a
      friction/security trade-off documented in ``docs/architecture.md``.
    * **Line-ending / whitespace normalisation** — excluded on purpose. We hash
      the blob exactly as git stores it (post ``.gitattributes`` / autocrlf), so
      what we hash is what a reviewer clones.

Encoding
--------
The digest input is a **line-oriented, versioned, ASCII-only** text form. We do
not hash a JSON dump: JSON key ordering and float formatting are a recurring
source of cross-language drift, and a line format is auditable by eye and
re-implementable in ~15 lines of shell for an independent CI check.

>>> compute_commit_digest(...)  # doctest: +SKIP
"""

from __future__ import annotations

import hashlib
import hmac
import json
import unicodedata
from collections.abc import Iterable, Sequence
from typing import Final, Literal, TypeAlias

# --------------------------------------------------------------------------- #
# Constants
# --------------------------------------------------------------------------- #

#: Version tag for the line format below. Any change to the layout MUST bump it,
#: otherwise old and new attestations would be silently comparable.
DIGEST_VERSION: Final[Literal["aegis-digest/v2"]] = "aegis-digest/v2"

#: Sentinel written where a value is legitimately absent (root commit parent,
#: deleted blob, no rename source). Using a sentinel instead of an empty string
#: keeps the field count fixed and prevents ambiguity between "absent" and
#: "empty".
_NULL: Final = "-"

#: Header line of the canonical form; it doubles as the domain separator so that
#: a digest produced here can never collide with a digest of some other artefact.
_HEADER: Final = "aegis-commit-digest"

#: One file entry: (change_kind, mode, blob_sha256 | None, path, old_path | None).
#: ``None`` blob is only legal for deletions; ``None`` old_path unless renamed.
FileEntry: TypeAlias = tuple[str, str, "str | None", str, "str | None"]


# --------------------------------------------------------------------------- #
# Low level helpers
# --------------------------------------------------------------------------- #
def sha256_bytes(data: bytes) -> str:
    """Return the lowercase hex SHA-256 of ``data``."""
    return hashlib.sha256(data).hexdigest()


def sha256_text(text: str) -> str:
    """Return the lowercase hex SHA-256 of ``text`` encoded as UTF-8.

    Git stores paths and blobs as bytes; we standardise on UTF-8 so that the
    client (Python) and any verifier (Python, Go, bash) hash the same thing.
    """
    return sha256_bytes(text.encode("utf-8"))


def hmac_sha256_hex(key: bytes, message: bytes) -> str:
    """HMAC-SHA256 used to authenticate the audit-log hash chain."""
    return hmac.new(key, message, hashlib.sha256).hexdigest()


def canonical_json(obj: object) -> bytes:
    """Serialise ``obj`` deterministically (sorted keys, no insignificant space).

    Used everywhere a structured payload must be digested (analysis request
    fingerprint, findings digest, audit events). ``ensure_ascii=False`` keeps
    non-ASCII identifiers intact instead of turning them into ``\\uXXXX``; both
    sides must use this helper rather than ``json.dumps`` directly.
    """
    return json.dumps(
        obj,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        allow_nan=False,
        default=str,
    ).encode("utf-8")


# --------------------------------------------------------------------------- #
# Git-object normalisation
# --------------------------------------------------------------------------- #
def normalize_repo_id(repo_id: str) -> str:
    """Reduce a remote URL to a stable ``host/owner/repo`` identity.

    Accepted inputs::

        git@github.com:MercadoLibre/app.git
        https://github.com/MercadoLibre/app.git
        https://user:token@github.com/MercadoLibre/app
        ssh://git@github.com:22/MercadoLibre/app.git
        github.com/MercadoLibre/app

    All of them collapse to ``github.com/mercadolibre/app``. Lowercasing the
    host is safe (DNS is case-insensitive); owner/repo are lowercased too
    because GitHub treats them case-insensitively, and because a developer
    cloning with different casing must not invalidate an attestation.
    Credentials embedded in the URL are stripped: they must never reach a digest
    (or an audit log).
    """
    raw = repo_id.strip()
    if not raw:
        raise ValueError("repo_id must not be empty")

    # Two structurally different remote syntaxes must be handled separately,
    # because ':' means "port" in one and "path separator" in the other:
    #
    #   URL form      : ssh://git@github.com:22/owner/repo.git   -> ':' is a port
    #   SCP-like form : git@github.com:owner/repo.git            -> ':' is the path
    #
    # Treating SCP-like as a URL silently produces host="github.com" and
    # path="repo" (the owner segment is swallowed by the port split), which would
    # make two different repositories share an attestation audience.
    scheme = ""
    if "://" in raw:
        scheme, _, after_scheme = raw.partition("://")
        scheme = scheme.lower()
        if "@" in after_scheme:
            after_scheme = after_scheme.rsplit("@", 1)[1]
        if after_scheme.startswith("/") or scheme == "file":
            # Local path (``file:///tmp/x``). It has no host, so the scheme becomes
            # the namespace: a local repository can never collide with a hosted one,
            # and the same checkout path keeps a stable identity.
            local_path = after_scheme.strip("/").lower()
            if not local_path:
                raise ValueError(f"cannot derive a repository id from {repo_id!r}")
            return f"{scheme or 'file'}/{local_path}"
        host_part, _, path_part = after_scheme.partition("/")
        host = host_part.split(":", 1)[0]
        path = path_part
    else:
        scp_like = raw.rsplit("@", 1)[-1]
        head, sep, tail = scp_like.partition("/")
        if ":" in head:
            host, path = head.split(":", 1)[0], head.split(":", 1)[1] + sep + tail
        else:
            host, path = head, tail

    # Drop trailing .git / slashes and normalise case.
    host = host.strip().lower()
    path = path.strip().strip("/")
    if path.endswith(".git"):
        path = path[: -len(".git")]
    path = path.strip("/").lower()

    if not host or not path:
        raise ValueError(f"cannot derive host/owner/repo from {repo_id!r}")
    return f"{host}/{path}"


def normalize_path(path: str) -> str:
    """Normalise a repository path to the POSIX form used in the digest.

    Rules: forward slashes, no leading ``/`` or ``./``, no trailing slash, no
    ``..`` segment, no NUL byte, Unicode NFC (a macOS HFS/APFS path can arrive
    decomposed while git stores NFC, which would otherwise change the digest).
    """
    if "\x00" in path:
        raise ValueError("path must not contain NUL")
    p = unicodedata.normalize("NFC", path).replace("\\", "/").strip()
    while p.startswith("./"):
        p = p[2:]
    p = p.lstrip("/").rstrip("/")
    segments = [s for s in p.split("/") if s not in ("", ".")]
    if any(s == ".." for s in segments):
        raise ValueError(f"path escapes the repository: {path!r}")
    if not segments:
        raise ValueError(f"empty path: {path!r}")
    return "/".join(segments)


def normalize_identity(name: str, email: str) -> tuple[str, str]:
    """Normalise a git ``user.name`` / ``user.email`` pair.

    E-mail is lowercased and trimmed — this is the field the server binds an
    attestation to, so ``Juan.Sierra@x.com`` and ``juan.sierra@x.com`` must not
    produce two different identities. Whitespace inside the name is collapsed,
    because ``git`` allows tabs and repeated spaces and they carry no meaning.
    """
    clean_name = " ".join(name.split())
    clean_email = email.strip().lower()
    if not clean_email:
        raise ValueError("author e-mail must not be empty")
    return clean_name, clean_email


def canonical_commit_message(message: str) -> str:
    """Normalise a commit message before hashing it.

    Steps: CRLF -> LF, strip trailing spaces per line, collapse runs of blank
    lines, strip leading/trailing blank lines, and **remove AEGIS trailer lines**.

    Trailers (``Aegis-Attestation: ...``) are stripped because a trailer could
    otherwise be appended *after* the analysis and change the digest of a commit
    whose diff is untouched — the trailer is metadata about the analysis, not
    part of the reviewed content. Anything the hook adds must therefore live in
    trailers, never in the subject/body.
    """
    text = message.replace("\r\n", "\n").replace("\r", "\n")
    out: list[str] = []
    for line in text.split("\n"):
        if line.lower().startswith(("aegis-attestation:", "aegis-analysis:")):
            continue
        out.append(line.rstrip())
    # Collapse consecutive blank lines.
    collapsed: list[str] = []
    for line in out:
        if line == "" and collapsed and collapsed[-1] == "":
            continue
        collapsed.append(line)
    return "\n".join(collapsed).strip("\n")


def message_digest(message: str) -> str:
    """Digest of the *canonical* commit message (trailers excluded)."""
    return sha256_text(canonical_commit_message(message))


# --------------------------------------------------------------------------- #
# File entry rows
# --------------------------------------------------------------------------- #
def _row(
    *,
    change: str,
    mode: str,
    blob_sha256: str | None,
    path: str,
    old_path: str | None,
) -> str:
    """Render one file entry as a single unambiguous canonical line.

    Deleted files legitimately have no post-image blob, which is why the blob
    field is a sentinel rather than omitted: ``file D - path/a.py`` and
    ``file D 100644 - path/a.py`` differ, and both must be distinguishable from
    an ADDED entry that (illegally) carried no blob.
    """
    row = f"file {change} {mode} {blob_sha256 or _NULL} {path}"
    if old_path is not None:
        row += f" -> {old_path}"
    return row


def commit_digest_payload(
    *,
    version: str = DIGEST_VERSION,
    repo_id: str,
    parent_sha: str | None,
    author_email: str,
    entries: Iterable[FileEntry],
) -> str:
    """Build the canonical text whose SHA-256 *is* the commit digest.

    ``entries`` is an iterable of ``(change, mode, blob_sha256, path, old_path)``
    tuples. It is sorted here, so callers cannot accidentally make the digest
    order-dependent on filesystem iteration order (a real bug class: readdir order
    differs between APFS, ext4 and NTFS).
    """
    if version != DIGEST_VERSION:
        raise ValueError(f"unsupported digest version: {version!r}")

    rows: list[tuple[str, str]] = []
    for change, mode, blob, path, old_path in entries:
        norm = normalize_path(path)
        rows.append(
            (
                _row(
                    change=change.upper(),
                    mode=mode,
                    blob_sha256=blob,
                    path=norm,
                    old_path=normalize_path(old_path) if old_path else None,
                ),
                norm,
            )
        )

    # Total order over the full row text: stable and unambiguous.
    rows.sort(key=lambda item: item[0])

    paths = [p for _, p in rows]
    if len(set(paths)) != len(paths):
        raise ValueError("duplicate path in commit entries")

    lines = [
        _HEADER,
        f"version={version}",
        f"repo={normalize_repo_id(repo_id)}",
        f"parent={parent_sha or _NULL}",
        f"author={author_email.strip().lower()}",
        f"files={len(rows)}",
        *[row for row, _ in rows],
    ]
    return "\n".join(lines) + "\n"


def compute_commit_digest(**kwargs: object) -> str:
    """Return ``sha256(commit_digest_payload(**kwargs))`` as lowercase hex."""
    payload = commit_digest_payload(**kwargs)  # type: ignore[arg-type]
    return sha256_text(payload)


# --------------------------------------------------------------------------- #
# Analysis payload digest
# --------------------------------------------------------------------------- #
def fragments_digest(
    fragments: Sequence[tuple[str, str, int, int]],
) -> str:
    """Digest of exactly the code fragments shipped to the LLM.

    ``fragments`` is a sequence of ``(path, text, start_line, end_line)``. The
    resulting digest is embedded in the attestation as ``payload_sha256`` so the
    server can prove, later, *which* text the model was shown. Without it, an
    attestation would only prove which files were committed, not which snippets
    were inspected — a gap an attacker could exploit by truncating the payload.
    """
    rows = []
    for path, text, start, end in fragments:
        rows.append(
            "\t".join(
                (
                    normalize_path(path),
                    str(start),
                    str(end),
                    sha256_text(text),
                )
            )
        )
    rows.sort()
    body = "\n".join([f"version={DIGEST_VERSION}", *rows])
    return sha256_text(body + "\n")


# --------------------------------------------------------------------------- #
# Hash chain for the audit log
# --------------------------------------------------------------------------- #
GENESIS_HASH: Final = "0" * 64


def chain_hash(*, prev_hash: str, event: object, key: bytes | None = None) -> str:
    """Return the next link of the append-only audit chain.

    ``event`` is any JSON-serialisable object. When ``key`` is supplied the link
    is an HMAC instead of a plain hash, which stops an operator who only has
    database write access (but not the key) from recomputing the chain after
    rewriting history. Keyed mode is what production deployments should use; the
    demo runs unkeyed so the chain can be verified in CI without secrets.
    """
    material = prev_hash.encode("utf-8") + b"\n" + canonical_json(event)
    if key is not None:
        return hmac_sha256_hex(key, material)
    return sha256_bytes(material)
