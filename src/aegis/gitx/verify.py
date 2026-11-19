"""Commit-range verification: the enforcement primitive shared by pre-push and CI.

Both callers need exactly the same thing — "for each commit in this range, is there
a valid attestation covering *this* tree?" — so it lives here once. The difference
between them is only the policy (what to do when a commit has no attestation), not
the mechanism.

Why the digest is recomputed and not read from the note
-------------------------------------------------------
The note is attacker-writable: anyone can `git notes add`. What an attacker cannot
do is forge the signature, so the note's *content* is only ever used as an opaque
JWS; the claim it must satisfy (`commit_digest`) is recomputed from the commit
object itself. Reading the digest from the note and comparing it with itself would
be the classic "verify the thing the attacker supplied" bug.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from aegis.attest.verify import AttestationVerifier, check_commit
from aegis.contracts import CommitVerification, VerifyReason
from aegis.gitx.repo import GitError, GitRepo

#: The notes ref that carries attestations. Named, not a business rule: a repo can
#: mirror it (`git push origin refs/notes/aegis`) for verifiers without repository
#: read access to the server's audit log.
NOTES_REF = "aegis"


@dataclass(slots=True)
class RangeReport:
    """Result of verifying a commit range."""

    results: list[CommitVerification] = field(default_factory=list)
    #: Merge commits are skipped by default: a merge introduces no new content of
    #: its own, and the commits it brings in were verified on their own branch.
    skipped_merges: list[str] = field(default_factory=list)

    @property
    def all_ok(self) -> bool:
        return all(r.ok for r in self.results)

    @property
    def failures(self) -> list[CommitVerification]:
        return [r for r in self.results if not r.ok]

    def counts(self) -> dict[str, int]:
        out: dict[str, int] = {}
        for result in self.results:
            out[result.reason.value] = out.get(result.reason.value, 0) + 1
        return dict(sorted(out.items()))


def resolve_range(repo: GitRepo, spec: str) -> list[str]:
    """Expand ``A..B`` (or a single rev) into the list of commits, oldest first.

    A bad range **raises**. Returning an empty list would turn a typo in CI's range
    (``origin/mian..HEAD``) into "no commits to verify -> green", which is a silent
    global bypass. The empty result of a *valid* range stays empty.
    """
    if ".." in spec:
        left, _, right = spec.partition("..")
        out = repo._run("rev-list", "--reverse", f"{left}..{right}").decode()
    else:
        out = repo._run("rev-list", "--reverse", "-n", "1", spec).decode()
    return [sha for sha in out.split() if sha]


def all_commits(repo: GitRepo, *, max_count: int | None = None) -> list[str]:
    """Every commit reachable from HEAD, oldest first.

    Used for the "verify the whole history once" mode and by tests: a range like
    ``HEAD~2..HEAD`` cannot include the root commit, and skipping the root is a real
    gap — the first commit is often the one carrying boilerplate secrets.
    """
    args = ["rev-list", "--reverse"]
    if max_count is not None:
        args += [f"--max-count={max_count}"]
    args.append("HEAD")
    out = repo._run(*args, check=False).decode()
    return [sha for sha in out.split() if sha]


def verify_range(
    repo: GitRepo,
    commits: list[str],
    *,
    verifier: AttestationVerifier,
    require_attestation: bool = True,
    skip_merges: bool = True,
    notes_ref: str = NOTES_REF,
) -> RangeReport:
    """Verify each commit. Never raises for a *failed* check, only for git errors."""
    report = RangeReport()
    repo_id = repo.repo_id()
    for sha in commits:
        parents = repo._run("rev-list", "--parents", "-n", "1", sha).decode().split()
        if skip_merges and len(parents) > 2:
            report.skipped_merges.append(sha)
            continue

        note = repo.read_note(sha, ref=notes_ref)
        try:
            digest = repo.commit_digest(sha)
        except GitError as exc:
            report.results.append(
                CommitVerification(
                    commit_sha=sha,
                    ok=False,
                    reason=VerifyReason.SCHEMA_UNSUPPORTED,
                    detail=f"cannot recompute the digest: {exc}",
                )
            )
            continue

        report.results.append(
            check_commit(
                verifier=verifier,
                note=note,
                commit_sha=sha,
                commit_digest=digest,
                repo_id=repo_id,
                require_attestation=require_attestation,
            )
        )
    return report


__all__ = ["NOTES_REF", "RangeReport", "all_commits", "resolve_range", "verify_range"]
