"""Git plumbing for the hook: read the index the way git will commit it.

Why plumbing and not porcelain
------------------------------
``git status`` is for humans: it is lossy, localised, and its output format changes.
The commit gate needs *object identity*, so this module talks to the plumbing
commands whose output is a stable contract:

    git diff-index --cached --raw -z -M HEAD   -> (kind, mode, oid, path, old_path)
    git cat-file --batch                        -> exact blob bytes for hashing
    git diff-index --cached -U0 -M HEAD         -> hunk ranges (for fragments)
    git notes --ref=aegis                       -> the attestation carrier

Why the **index** and not the working tree
------------------------------------------
The index is what becomes the commit. A developer can have unstaged edits in the
same file; analysing the working tree would review code that is not being committed
(and could be used to hide a change by staging one version and leaving another in
the editor). Every read here goes through ``--cached`` or ``:path`` with an explicit
stage, never through the filesystem.

Why the hook ignores the filenames pre-commit passes it
-------------------------------------------------------
``pre-commit`` hands hooks a list of changed files. That list is computed by
porcelain heuristics and, more importantly, it is *not* the staged set: with
``git add -p`` or ``git add -N`` the two differ. The contract recomputes the commit
digest from ``files``, so the hook re-derives the staged set itself and treats the
argument list as advisory. This is also why the hook must be `pass_filenames: false`.
"""

from __future__ import annotations

import hashlib
import os
import subprocess
from dataclasses import dataclass
from pathlib import Path

from aegis import canon
from aegis.contracts import ChangeKind, CodeFragment, Identity, StagedFile
from aegis.detectors import should_skip
from aegis.errors import AegisError

#: A file is treated as binary when its first bytes contain NUL — the same
#: heuristic git itself uses, so our notion of "binary" matches `git diff`.
_BINARY_SNIFF_BYTES = 8000

#: Context lines around a changed region when building fragments.
DEFAULT_CONTEXT = 6


class GitError(AegisError):
    exit_code = 2
    slug = "git"


@dataclass(frozen=True, slots=True)
class RawEntry:
    """One row of ``git diff-index --cached --raw``."""

    kind: ChangeKind
    new_mode: str
    new_oid: str
    old_mode: str
    old_oid: str
    path: str
    old_path: str | None


class GitRepo:
    """Thin, explicit wrapper over the git commands the gate needs."""

    def __init__(self, path: Path, *, git_binary: str = "git") -> None:
        self._cwd = Path(path).resolve()
        self._git = git_binary

    # -- discovery ---------------------------------------------------------
    @classmethod
    def discover(cls, start: Path | None = None, *, git_binary: str = "git") -> GitRepo:
        """Open the repository containing ``start`` (default: cwd)."""
        probe = cls(start or Path.cwd(), git_binary=git_binary)
        try:
            top = probe._run("rev-parse", "--show-toplevel").decode().strip()
        except GitError as exc:
            raise GitError(
                "not inside a git repository",
                hint="AEGIS runs as a git hook; run it from a working tree.",
            ) from exc
        return cls(Path(top), git_binary=git_binary)

    # -- plumbing ----------------------------------------------------------
    def _run(self, *args: str, check: bool = True) -> bytes:
        """Run a git command with a sanitised environment.

        ``GIT_DIR``/``GIT_WORK_TREE``/``GIT_INDEX_FILE`` from the caller's
        environment would silently point us at a different repository or index than
        the one git is committing (this really happens inside rebase and in
        ``git worktree``). They are removed so the answer is always about *this*
        working tree.
        """
        env = {
            key: value
            for key, value in os.environ.items()
            if key not in {"GIT_DIR", "GIT_WORK_TREE", "GIT_INDEX_FILE", "GIT_PREFIX"}
        }
        # Deterministic output regardless of the developer's git config.
        base = ["-c", "core.quotepath=false", "-c", "color.ui=false", "-c", "diff.noprefix=false"]
        completed = subprocess.run(  # noqa: S603 - fixed argv, no shell, no user input
            [self._git, *base, *args],
            cwd=str(self._cwd),
            env=env,
            capture_output=True,
            check=False,
            timeout=120,
        )
        if check and completed.returncode != 0:
            raise GitError(
                f"git {' '.join(args)} failed: {completed.stderr.decode('utf-8', 'replace').strip()[:400]}"
            )
        return completed.stdout

    # -- identity ----------------------------------------------------------
    @property
    def root(self) -> Path:
        return self._cwd

    def repo_id(self) -> str:
        """``host/owner/repo`` from the remote, or a ``file://`` fallback.

        The fallback matters: a local-only repository (``git init`` with no remote)
        must still be analysable. ``file://<abspath>`` is used so the value is
        stable across machines in the sense that matters — the same repository path
        produces the same id, and a repo with no remote can never be confused with
        a hosted one.
        """
        candidates: list[str] = []
        for remote in ("origin", "upstream"):
            out = self._run("remote", "get-url", remote, check=False).decode().strip()
            if out:
                candidates.append(out)
        any_remote = self._run("remote", check=False).decode().split()
        if any_remote:
            out = self._run("remote", "get-url", any_remote[0], check=False).decode().strip()
            if out:
                candidates.append(out)
        for candidate in candidates:
            try:
                return canon.normalize_repo_id(candidate)
            except ValueError:
                # An unparseable remote must not crash a hook with a traceback; try
                # the next one and, if none works, fall back to the local path — the
                # repository identity is needed for the digest, so failing here is
                # never silently ignorable.
                continue
        return canon.normalize_repo_id(f"file://{self._cwd}")

    def head_sha(self) -> str | None:
        """HEAD commit, or ``None`` on an unborn branch (first commit).

        Goes through :meth:`_run` on purpose. This method used to call
        ``subprocess.run`` directly, which meant a ``GIT_DIR`` in the environment
        (git sets it during rebase and in worktrees) redirected ``rev-parse`` and
        made the hook believe it was a first commit — so it would compare against
        the empty tree and "analyse" every file in the repository.
        """
        out = self._run("rev-parse", "--verify", "-q", "HEAD", check=False).decode().strip()
        return out or None

    def branch(self) -> str | None:
        out = self._run("symbolic-ref", "-q", "HEAD", check=False).decode().strip()
        return out or None

    def is_merge_in_progress(self) -> bool:
        git_dir = Path(self._run("rev-parse", "--git-dir").decode().strip())
        if not git_dir.is_absolute():
            git_dir = self._cwd / git_dir
        return (git_dir / "MERGE_HEAD").exists()

    def author_identity(self) -> Identity:
        """The identity git will stamp on the commit (``GIT_AUTHOR_*`` aware)."""
        raw = self._run("var", "GIT_AUTHOR_IDENT").decode().strip()
        # Format: "Name <email> 1700000000 +0000"
        name, _, rest = raw.partition("<")
        email, _, _ = rest.partition(">")
        if not email:
            raise GitError(
                "git has no author identity configured",
                hint='Set it with `git config user.name "..."` and `git config user.email "..."`.',
            )
        return Identity(name=name.strip() or "unknown", email=email.strip())

    # -- staged state ------------------------------------------------------
    def staged_entries(self) -> list[RawEntry]:
        """The exact staged set, with renames resolved (``-M``)."""
        args = ["diff-index", "--cached", "--raw", "-z", "-M", "--find-renames"]
        if self.head_sha() is None:
            # Unborn branch: diff the empty tree so the first commit works.
            args.append(self._empty_tree())
        else:
            args.append("HEAD")

        raw = self._run(*args)
        return _parse_raw_diff(raw)

    def blob_bytes(self, oid: str) -> bytes:
        """Exact staged blob content. ``oid`` is a git object id (any format)."""
        return self._run("cat-file", "blob", oid)

    def staged_files(self) -> list[StagedFile]:
        """``RawEntry`` + content hash + size + binary flag, as the contract wants."""
        out: list[StagedFile] = []
        for entry in self.staged_entries():
            if entry.kind is ChangeKind.DELETED:
                out.append(
                    StagedFile(
                        path=entry.path,
                        change=entry.kind,
                        mode=_contract_mode(entry.old_mode),
                        blob_sha256=None,
                        size_bytes=0,
                    )
                )
                continue
            content = self.blob_bytes(entry.new_oid)
            out.append(
                StagedFile(
                    path=entry.path,
                    old_path=entry.old_path,
                    change=entry.kind,
                    mode=_contract_mode(entry.new_mode),
                    blob_sha256=hashlib.sha256(content).hexdigest(),
                    size_bytes=len(content),
                    is_binary=_looks_binary(content),
                )
            )
        return out

    def changed_ranges(self, path: str, *, context: int = DEFAULT_CONTEXT) -> list[tuple[int, int]]:
        """New-file line ranges touched by the staged diff, with context.

        ``-U0`` gives exact hunk boundaries; the context is added here so the model
        sees the surrounding code but the reported line numbers stay the file's.
        """
        base = ["diff-index", "--cached", f"-U{context}", "-M", "--no-color", "--no-ext-diff"]
        base.append("HEAD" if self.head_sha() else self._empty_tree())
        base.extend(["--", path])
        raw = self._run(*base, check=False).decode("utf-8", "surrogateescape")

        ranges: list[tuple[int, int]] = []
        for line in raw.splitlines():
            if not line.startswith("@@"):
                continue
            # @@ -old_start,old_count +new_start,new_count @@
            try:
                new_part = line.split("+", 1)[1].split(" ", 1)[0]
                start_text, _, count_text = new_part.partition(",")
                start = int(start_text)
                count = int(count_text) if count_text else 1
            except (IndexError, ValueError):
                continue
            if count == 0:
                # Pure deletion: there is no new line to point at, so anchor the
                # fragment on the line just before the deletion.
                start = max(1, start)
                count = 1
            ranges.append((max(1, start), start + count - 1))
        return ranges

    def build_fragments(
        self,
        files: list[StagedFile],
        *,
        context: int = DEFAULT_CONTEXT,
        max_fragment_chars: int = 20_000,
        max_total_chars: int = 200_000,
    ) -> list[CodeFragment]:
        """Fragments for every analysable staged file.

        Only changed regions plus context are sent: the whole file for an addition,
        the hunks for a modification. The blob hashes in ``StagedFile`` remain the
        ground truth for the full content; the fragment is what the model reads.
        """
        fragments: list[CodeFragment] = []
        budget = max_total_chars
        for staged in files:
            if staged.change is ChangeKind.DELETED or staged.is_binary:
                continue
            if should_skip(staged.path):
                continue
            if budget <= 0:
                break
            content = self.blob_bytes(
                next(
                    entry.new_oid
                    for entry in self.staged_entries()
                    if entry.path == staged.path and entry.kind is not ChangeKind.DELETED
                )
            )
            lines = content.decode("utf-8", "surrogateescape").splitlines()
            if not lines:
                continue
            ranges = (
                self.changed_ranges(staged.path, context=context)
                if staged.change is not ChangeKind.ADDED
                else [(1, len(lines))]
            )
            for start, end in _merge_ranges(ranges, len(lines)):
                if budget <= 0:
                    break
                chunk = "\n".join(lines[start - 1 : end])
                truncated = False
                if len(chunk) > min(max_fragment_chars, budget):
                    chunk = chunk[: min(max_fragment_chars, budget)]
                    truncated = True
                budget -= len(chunk)
                fragments.append(
                    CodeFragment(
                        path=staged.path,
                        start_line=start,
                        end_line=start + max(len(chunk.splitlines()), 1) - 1,
                        text=chunk,
                        content_sha256=canon.sha256_text(chunk),
                        truncated=truncated,
                    )
                )
        return fragments

    # -- digest of a committed object (the verifier path) ------------------
    def commit_digest(self, sha: str | None = None) -> str:
        """Recompute the canonical digest from a **committed** object.

        This is the function CI uses, and the one the post-commit hook uses to check
        itself. It must produce exactly what ``hook.build_request`` computed from the
        index; if the two ever disagree, the commit is not the one that was analysed
        and no attestation may be attached.

        Note it applies ``classify_change`` — the same refinement the index path uses
        — because two implementations of "what are the digest inputs" is precisely
        how a verifier drifts away from the thing it verifies.
        """
        target = sha or self.head_sha()
        if target is None:
            raise GitError("no commit to verify (unborn branch)")
        parent = self._run("rev-parse", "--verify", "-q", f"{target}^", check=False).decode().strip()
        base = parent or self._empty_tree()
        raw = self._run("diff", "--raw", "-z", "-M", base, target)
        entries = _parse_raw_diff(raw)
        email = self._run("log", "-1", "--format=%ae", target).decode().strip()
        if not email:
            raise GitError(f"cannot read the author of {target[:12]}")
        return canon.compute_commit_digest(
            repo_id=self.repo_id(),
            parent_sha=parent or None,
            author_email=email,
            entries=[
                (
                    e.kind.value,
                    _contract_mode(e.new_mode),
                    self._blob_sha(e),
                    e.path,
                    e.old_path,
                )
                for e in entries
            ],
        )

    def _blob_sha(self, entry: RawEntry) -> str | None:
        if entry.kind is ChangeKind.DELETED:
            return None
        return canon.sha256_bytes(self.blob_bytes(entry.new_oid))

    def _empty_tree(self) -> str:
        return self._run("hash-object", "-t", "tree", "/dev/null").decode().strip()

    def git_dir(self) -> Path:
        out = self._run("rev-parse", "--git-dir").decode().strip()
        path = Path(out)
        return path if path.is_absolute() else (self._cwd / path)

    # -- notes -------------------------------------------------------------
    def write_note(self, commit_sha: str, payload: str, *, ref: str = "aegis") -> None:
        """Attach the attestation to the commit as a git note.

        Notes do not change the commit SHA, which is what makes them usable: the
        digest of the commit is already fixed by the time we know the verdict.
        """
        self._run("notes", f"--ref={ref}", "add", "-f", "-m", payload, commit_sha)

    def read_note(self, commit_sha: str, *, ref: str = "aegis") -> str | None:
        out = self._run("notes", f"--ref={ref}", "show", commit_sha, check=False).decode().strip()
        return out or None


# --------------------------------------------------------------------------- #
# Helpers
# --------------------------------------------------------------------------- #
#: ``diff-index --raw`` status letters -> contract change kinds.
_KIND_BY_STATUS: dict[str, ChangeKind] = {
    "A": ChangeKind.ADDED,
    "C": ChangeKind.ADDED,  # a copy is, for our purposes, a new file
    "D": ChangeKind.DELETED,
    "M": ChangeKind.MODIFIED,
    "R": ChangeKind.RENAMED,
    "T": ChangeKind.MODE_CHANGED,
}


def _parse_raw_diff(raw: bytes) -> list[RawEntry]:
    """Parse ``git diff-index --raw -z`` into entries.

    The exact wire format, verified from the bytes rather than the man page::

        :<old_mode> <new_mode> <old_oid> <new_oid> <status>\0<path>\0
        :<old_mode> <new_mode> <old_oid> <new_oid> R<score>\0<src>\0<dst>\0

    Three details that are easy to get wrong and were, initially:

    * the header starts with ``:`` glued to ``old_mode``, so a naive ``split``
      leaves it attached;
    * the status is its own space-separated field, and for renames/copies it carries
      a similarity score (``R100``), so only the first character is the kind;
    * for renames the **source path comes first** and the destination second, which
      is the opposite of the order in the ``--name-status`` output.
    """
    fields = raw.split(b"\x00")
    entries: list[RawEntry] = []
    index = 0
    while index < len(fields):
        header = fields[index].lstrip(b"\n")
        index += 1
        if not header:
            continue
        parts = header.split(b" ")
        if len(parts) < 5:
            raise GitError(f"unexpected diff-index header: {header[:80]!r}")
        old_mode = parts[0].lstrip(b":").decode()
        new_mode = parts[1].decode()
        old_oid = parts[2].decode()
        new_oid = parts[3].decode()
        status = parts[4].decode()
        kind = _KIND_BY_STATUS.get(status[:1])
        if kind is None:
            # Unmerged entries (U*) do not fit the contract; guessing would produce
            # a digest for content that is not committable.
            raise GitError(f"unmerged or unsupported index entry ({status}); resolve the conflict first")
        path = fields[index].decode("utf-8", "surrogateescape")
        index += 1
        # `git diff --raw` reports a permission change as a modification with
        # identical object ids. It is security-relevant (a new executable, or a
        # script that lost its execute bit), so it gets its own kind here. Any
        # verifier must apply the same rule — see `classify_change`.
        kind = classify_change(kind, old_mode=old_mode, new_mode=new_mode, old_oid=old_oid, new_oid=new_oid)
        old_path: str | None = None
        if (
            kind in {ChangeKind.RENAMED, ChangeKind.ADDED} and status[:1] == "C"
        ) or kind is ChangeKind.RENAMED:
            old_path, path = path, fields[index].decode("utf-8", "surrogateescape")
            index += 1
        entries.append(
            RawEntry(
                kind=kind,
                new_mode=new_mode,
                new_oid=new_oid,
                old_mode=old_mode,
                old_oid=old_oid,
                path=path,
                old_path=old_path,
            )
        )
    return entries


def classify_change(
    kind: ChangeKind, *, old_mode: str, new_mode: str, old_oid: str, new_oid: str
) -> ChangeKind:
    """Refine git's status letter into what the contract models.

    Currently one rule: an ``M`` with identical blobs is a mode change. Exported so
    the CI verifier applies the same classification instead of re-deriving it (two
    implementations of the digest inputs is how they drift apart).
    """
    if kind is ChangeKind.MODIFIED and old_oid == new_oid and old_mode != new_mode and new_oid.strip("0"):
        return ChangeKind.MODE_CHANGED
    return kind


def _contract_mode(raw: str) -> str:
    """Map git's 6-digit mode to the contract's allowlist."""
    return raw if raw in {"100644", "100755", "120000", "160000"} else "100644"


def _looks_binary(content: bytes) -> bool:
    return b"\x00" in content[:_BINARY_SNIFF_BYTES]


def _merge_ranges(ranges: list[tuple[int, int]], line_count: int) -> list[tuple[int, int]]:
    """Clamp, sort and merge overlapping/adjacent ranges."""
    clamped = sorted((max(1, lo), min(hi, line_count)) for lo, hi in ranges if lo <= line_count)
    merged: list[tuple[int, int]] = []
    for lo, hi in clamped:
        if merged and lo <= merged[-1][1] + 1:
            merged[-1] = (merged[-1][0], max(merged[-1][1], hi))
        else:
            merged.append((lo, hi))
    return merged


__all__ = ["DEFAULT_CONTEXT", "GitError", "GitRepo", "RawEntry", "classify_change"]
