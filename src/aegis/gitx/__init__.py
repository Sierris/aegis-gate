"""Git plumbing for the commit gate."""

from __future__ import annotations

from aegis.gitx.repo import DEFAULT_CONTEXT, GitError, GitRepo, RawEntry, classify_change
from aegis.gitx.verify import NOTES_REF, RangeReport, all_commits, resolve_range, verify_range

__all__ = [
    "DEFAULT_CONTEXT",
    "NOTES_REF",
    "GitError",
    "GitRepo",
    "RangeReport",
    "RawEntry",
    "all_commits",
    "classify_change",
    "resolve_range",
    "verify_range",
]
