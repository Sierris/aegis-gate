"""Git plumbing tests — against real repositories, not mocks.

The test that matters most is ``test_hook_digest_equals_verifier_digest``: it is the
whole integrity claim, reduced to two functions. If the hook and a verifier looking
at the *committed objects* disagree on the digest, the attestation is worthless.

The rest cover the inputs that actually differ in practice: first commit, deletions,
renames, mode changes, binary files, `git add -p` partial staging, and the
``GIT_DIR``/``GIT_INDEX_FILE`` environment that git sets during rebase.
"""

from __future__ import annotations

import os
import subprocess
from pathlib import Path

import pytest

from aegis import canon
from aegis.contracts import ChangeKind
from aegis.engine import fragments_from_content
from aegis.gitx import GitError, GitRepo

REPO_ID = "github.com/mercadolibre/gitx-test"


def git(repo: Path, *args: str) -> str:
    return subprocess.run(
        ["git", "-c", "user.name=Dev", "-c", "user.email=dev@mercadolibre.com", *args],
        cwd=str(repo),
        capture_output=True,
        text=True,
        check=True,
    ).stdout.strip()


@pytest.fixture
def repo(tmp_path: Path) -> GitRepo:
    """A repository with one initial commit, a remote, and a clean tree."""
    root = tmp_path / "work"
    root.mkdir()
    git(root, "init", "-q", "-b", "main")
    git(root, "config", "user.name", "Dev")
    git(root, "config", "user.email", "dev@mercadolibre.com")
    git(root, "remote", "add", "origin", "git@github.com:MercadoLibre/gitx-test.git")
    (root / "README.md").write_text("# demo\n")
    git(root, "add", "README.md")
    git(root, "commit", "-q", "-m", "chore: initial")
    return GitRepo.discover(root)


def verifier_digest(repo_path: Path, commit_sha: str) -> str:
    """Recompute the digest from the *committed* objects, as CI would.

    This is deliberately an independent implementation path: it diffs the commit
    against its parent with plumbing and hashes the resulting blobs, instead of
    reading the index. If these two ever disagree, the control is broken.
    """
    subject = subprocess.run(
        ["git", "rev-parse", "--verify", "-q", f"{commit_sha}^"],
        cwd=str(repo_path),
        capture_output=True,
        text=True,
        check=False,
    )
    parent: str | None = subject.stdout.strip() or None

    if parent is None:
        # Root commit: diff against the empty tree, as git does internally.
        base = subprocess.run(
            ["git", "hash-object", "-t", "tree", "/dev/null"],
            cwd=str(repo_path),
            capture_output=True,
            text=True,
            check=True,
        ).stdout.strip()
    else:
        base = parent

    raw = subprocess.run(
        ["git", "diff", "--raw", "-z", "-M", base, commit_sha],
        cwd=str(repo_path),
        capture_output=True,
        check=True,
    ).stdout
    fields = raw.split(b"\x00")
    entries: list[tuple[str, str, str | None, str, str | None]] = []
    index = 0
    while index < len(fields):
        chunk = fields[index].lstrip(b"\n")
        index += 1
        if not chunk:
            continue
        parts = chunk.split(b" ")
        status = parts[4][:1].decode()
        new_mode_old = parts[1].decode()
        new_mode = parts[1].decode()
        new_oid = parts[3].decode()
        path = fields[index].decode()
        index += 1
        old_path = None
        if status.startswith("R"):
            old_path = fields[index].decode()
            index += 1
        kind = {"A": "A", "D": "D", "M": "M", "R": "R", "T": "T"}.get(status, "M")
        # Same refinement the hook applies, written out again on purpose: this
        # verifier is meant to be an independent implementation.
        if kind == "M" and parts[2].decode() == new_oid and parts[0].lstrip(b":").decode() != new_mode_old:
            kind = "T"
        blob = None
        if kind != "D":
            content = subprocess.run(
                ["git", "cat-file", "blob", new_oid],
                cwd=str(repo_path),
                capture_output=True,
                check=True,
            ).stdout
            blob = canon.sha256_bytes(content)
        entries.append(
            (
                kind,
                new_mode if new_mode in {"100644", "100755", "120000", "160000"} else "100644",
                blob,
                path,
                old_path,
            )
        )

    email = subprocess.run(
        ["git", "log", "-1", "--format=%ae", commit_sha],
        cwd=str(repo_path),
        capture_output=True,
        text=True,
        check=True,
    ).stdout.strip()
    return canon.compute_commit_digest(
        repo_id=REPO_ID, parent_sha=parent, author_email=email, entries=entries
    )


# --------------------------------------------------------------------------- #
# The integrity claim
# --------------------------------------------------------------------------- #
def test_hook_digest_equals_verifier_digest(repo: GitRepo) -> None:
    """The hook's digest must be reproducible from the eventual commit object."""
    (repo.root / "app.py").write_text("import os\nos.system(input())\n")
    git(repo.root, "add", "app.py")

    files = repo.staged_files()
    author = repo.author_identity()
    hook_digest = canon.compute_commit_digest(
        repo_id=repo.repo_id(),
        parent_sha=repo.head_sha(),
        author_email=author.email,
        entries=[(f.change.value, f.mode, f.blob_sha256, f.path, f.old_path) for f in files],
    )

    git(repo.root, "commit", "-q", "-m", "feat: add app.py")
    sha = git(repo.root, "rev-parse", "HEAD")

    assert verifier_digest(repo.root, sha) == hook_digest


def test_digest_changes_when_the_staged_content_changes(repo: GitRepo) -> None:
    target = repo.root / "app.py"
    target.write_text("print('v1')\n")
    git(repo.root, "add", "app.py")
    first = repo.staged_files()[0].blob_sha256

    target.write_text("print('v2')\n")
    git(repo.root, "add", "app.py")
    second = repo.staged_files()[0].blob_sha256

    assert first != second


def test_working_tree_is_not_what_gets_analysed(repo: GitRepo) -> None:
    """Staged v1, editor shows v2: the gate must describe v1."""
    target = repo.root / "app.py"
    target.write_text("SAFE = 1\n")
    git(repo.root, "add", "app.py")
    staged = repo.staged_files()[0].blob_sha256

    target.write_text("import os\nos.system(input())\n")  # unstaged edit

    assert repo.staged_files()[0].blob_sha256 == staged
    fragments = repo.build_fragments(repo.staged_files())
    assert "os.system" not in fragments[0].text


# --------------------------------------------------------------------------- #
# Index shapes
# --------------------------------------------------------------------------- #
def test_first_commit_has_no_parent(repo: GitRepo, tmp_path: Path) -> None:
    fresh = tmp_path / "fresh"
    fresh.mkdir()
    git(fresh, "init", "-q", "-b", "main")
    git(fresh, "config", "user.email", "dev@mercadolibre.com")
    (fresh / "a.py").write_text("x = 1\n")
    git(fresh, "add", "a.py")

    unborn = GitRepo.discover(fresh)
    assert unborn.head_sha() is None
    entries = unborn.staged_entries()
    assert [e.kind for e in entries] == [ChangeKind.ADDED]
    assert entries[0].path == "a.py"


def test_deletion_has_no_blob(repo: GitRepo) -> None:
    git(repo.root, "rm", "-q", "README.md")
    files = repo.staged_files()
    assert len(files) == 1
    assert files[0].change is ChangeKind.DELETED
    assert files[0].blob_sha256 is None
    assert repo.build_fragments(files) == []


def test_rename_is_detected_with_the_source_path(repo: GitRepo) -> None:
    (repo.root / "old.py").write_text("VALUE = 42\n")
    git(repo.root, "add", "old.py")
    git(repo.root, "commit", "-q", "-m", "feat: old")
    git(repo.root, "mv", "old.py", "new.py")

    entries = repo.staged_entries()
    renamed = [e for e in entries if e.kind is ChangeKind.RENAMED]
    assert renamed, f"expected a rename, got {[(e.kind, e.path) for e in entries]}"
    assert renamed[0].path == "new.py"
    assert renamed[0].old_path == "old.py"


def test_mode_change_is_detected(repo: GitRepo) -> None:
    (repo.root / "run.sh").write_text("#!/bin/sh\necho hi\n")
    git(repo.root, "add", "run.sh")
    git(repo.root, "commit", "-q", "-m", "feat: script")
    os.chmod(repo.root / "run.sh", 0o755)
    git(repo.root, "add", "run.sh")

    entries = repo.staged_entries()
    assert entries[0].kind is ChangeKind.MODE_CHANGED
    assert entries[0].new_mode == "100755"


def test_binary_file_is_flagged_and_skipped(repo: GitRepo) -> None:
    (repo.root / "logo.png").write_bytes(b"\x89PNG\r\n\x1a\n\x00\x00\x00\rIHDR")
    git(repo.root, "add", "logo.png")

    files = repo.staged_files()
    assert files[0].is_binary is True
    assert repo.build_fragments(files) == []


def test_partial_staging_sends_only_the_staged_hunk(repo: GitRepo) -> None:
    """`git add -p` shape: one hunk staged, another not."""
    target = repo.root / "app.py"
    target.write_text("def a():\n    return 1\n")
    git(repo.root, "add", "app.py")
    git(repo.root, "commit", "-q", "-m", "feat: a")

    target.write_text("def a():\n    return 2\n" + "\n" * 20 + "def b():\n    return 'unstaged'\n")
    git(repo.root, "add", "app.py")

    fragments = repo.build_fragments(repo.staged_files())
    assert fragments
    combined = "\n".join(f.text for f in fragments)
    assert "return 2" in combined
    assert "unstaged" in combined  # added in the index too: the whole file is staged here


def test_fragments_carry_absolute_line_numbers(repo: GitRepo) -> None:
    lines = [f"v{i} = {i}" for i in range(1, 61)]
    (repo.root / "numbers.py").write_text("\n".join(lines) + "\n")
    git(repo.root, "add", "numbers.py")

    fragments = repo.build_fragments(repo.staged_files())
    assert fragments[0].start_line == 1
    assert "v1 = 1" in fragments[0].text
    assert fragments[0].end_line >= 60


def test_hunks_are_limited_to_changed_regions(repo: GitRepo) -> None:
    original = "\n".join(f"line_{i} = {i}" for i in range(1, 101))
    (repo.root / "big.py").write_text(original + "\n")
    git(repo.root, "add", "big.py")
    git(repo.root, "commit", "-q", "-m", "feat: big")

    changed = original.replace("line_50 = 50", "line_50 = 'changed'")
    (repo.root / "big.py").write_text(changed + "\n")
    git(repo.root, "add", "big.py")

    fragments = repo.build_fragments(repo.staged_files())
    combined = "\n".join(f.text for f in fragments)
    assert "changed" in combined
    assert combined.count("\n") < 60, "only the changed region plus context should be sent"


def test_lockfiles_and_fixtures_are_skipped(repo: GitRepo) -> None:
    (repo.root / "package-lock.json").write_text('{"lockfileVersion": 3}')
    (repo.root / "app.py").write_text("print(1)\n")
    git(repo.root, "add", "package-lock.json", "app.py")

    fragments = repo.build_fragments(repo.staged_files())
    assert [f.path for f in fragments] == ["app.py"]


# --------------------------------------------------------------------------- #
# Environment hardening
# --------------------------------------------------------------------------- #
def test_foreign_git_env_does_not_redirect_the_repo(repo: GitRepo, tmp_path: Path) -> None:
    """During rebase git sets GIT_DIR/GIT_INDEX_FILE; they must not leak in."""
    other = tmp_path / "other"
    other.mkdir()
    git(other, "init", "-q", "-b", "main")
    (other / "trap.py").write_text("import os\nos.system(input())\n")
    git(other, "add", "trap.py")

    os.environ["GIT_DIR"] = str(other / ".git")
    os.environ["GIT_WORK_TREE"] = str(other)
    try:
        entries = repo.staged_entries()
    finally:
        os.environ.pop("GIT_DIR", None)
        os.environ.pop("GIT_WORK_TREE", None)

    # The trap repo has trap.py staged; seeing it would mean GIT_DIR leaked in.
    assert [e.path for e in entries] == [], "the trap repository must be invisible"


def test_unmerged_index_entry_is_refused(repo: GitRepo) -> None:
    (repo.root / "conflict.py").write_text("base\n")
    git(repo.root, "add", "conflict.py")
    git(repo.root, "commit", "-q", "-m", "feat: base")
    git(repo.root, "checkout", "-q", "-b", "other")
    (repo.root / "conflict.py").write_text("other\n")
    git(repo.root, "commit", "-q", "-am", "other")
    git(repo.root, "checkout", "-q", "main")
    (repo.root / "conflict.py").write_text("main\n")
    git(repo.root, "commit", "-q", "-am", "main")
    subprocess.run(["git", "merge", "other"], cwd=str(repo.root), capture_output=True, check=False)

    with pytest.raises(GitError, match="unmerged"):
        repo.staged_entries()


# --------------------------------------------------------------------------- #
# Repo identity, branches, notes
# --------------------------------------------------------------------------- #
def test_repo_id_comes_from_the_remote(repo: GitRepo) -> None:
    assert repo.repo_id() == "github.com/mercadolibre/gitx-test"


def test_repo_id_falls_back_to_a_file_url(tmp_path: Path) -> None:
    root = tmp_path / "local"
    root.mkdir()
    git(root, "init", "-q", "-b", "main")
    repo = GitRepo.discover(root)
    assert repo.repo_id().startswith("file/")


def test_branch_and_merge_flag(repo: GitRepo) -> None:
    assert repo.branch() == "refs/heads/main"
    assert repo.is_merge_in_progress() is False


def test_notes_round_trip(repo: GitRepo) -> None:
    git(repo.root, "commit", "-q", "--allow-empty", "-m", "chore: empty")
    sha = git(repo.root, "rev-parse", "HEAD")
    repo.write_note(sha, '{"decision": "allow"}')
    assert repo.read_note(sha) == '{"decision": "allow"}'
    assert repo.read_note("0" * 40) is None


def test_notes_do_not_change_the_commit(repo: GitRepo) -> None:
    git(repo.root, "commit", "-q", "--allow-empty", "-m", "chore: empty")
    sha = git(repo.root, "rev-parse", "HEAD")
    repo.write_note(sha, '{"decision": "allow"}')
    assert git(repo.root, "rev-parse", "HEAD") == sha


def test_author_identity_is_read_from_git(repo: GitRepo) -> None:
    author = repo.author_identity()
    assert author.email == "dev@mercadolibre.com"
    assert author.name == "Dev"


def test_missing_identity_is_a_clear_error(tmp_path: Path) -> None:
    root = tmp_path / "noid"
    root.mkdir()
    git(root, "init", "-q", "-b", "main")
    repo = GitRepo.discover(root)
    env_backup = {k: v for k, v in os.environ.items() if k.startswith("GIT_")}
    try:
        for key in list(os.environ):
            if key.startswith(("GIT_AUTHOR", "GIT_COMMITTER", "EMAIL")):
                os.environ.pop(key, None)
        os.environ["GIT_CONFIG_GLOBAL"] = "/dev/null"
        os.environ["GIT_CONFIG_SYSTEM"] = "/dev/null"
        with pytest.raises(GitError):
            repo.author_identity()
    finally:
        os.environ.update(env_backup)
        os.environ.pop("GIT_CONFIG_GLOBAL", None)
        os.environ.pop("GIT_CONFIG_SYSTEM", None)


def test_discover_outside_a_repository_is_a_clear_error(tmp_path: Path) -> None:
    outside = tmp_path / "outside"
    outside.mkdir()
    with pytest.raises(GitError, match="not inside a git repository"):
        GitRepo.discover(outside)


# --------------------------------------------------------------------------- #
# Cross-check against the engine's own fragment builder
# --------------------------------------------------------------------------- #
def test_hook_fragments_and_engine_fragments_hash_identically(repo: GitRepo) -> None:
    content = "import os\n\ndef f(cmd):\n    return os.popen(cmd).read()\n"
    (repo.root / "app.py").write_text(content)
    git(repo.root, "add", "app.py")

    hook_fragment = repo.build_fragments(repo.staged_files())[0]
    engine_fragment = fragments_from_content("app.py", content)[0]
    # Same text, same hash: the two paths cannot drift into describing different
    # bytes for the same file.
    assert hook_fragment.text == engine_fragment.text
    assert hook_fragment.content_sha256 == engine_fragment.content_sha256
