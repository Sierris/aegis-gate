"""Verdict cache.

Why cache a security decision at all
-----------------------------------
Two reasons, both about friction rather than cost:

1. **A hook in the commit path.** Re-analysing an unchanged file on every amend,
   rebase or re-`commit` adds seconds to an action the developer repeats dozens of
   times a day. That teaches people to use `--no-verify`, which is the failure mode
   that matters.
2. **Determinism.** A cached verdict is the *same* verdict: no sampling drift, no
   "it blocked yesterday" surprises. Model output is not stable; a cache keyed by
   everything that can affect it is.

What makes a key
----------------
``sha256(payload_sha256 ‖ prompt_version ‖ model ‖ policy fingerprint)``.

The policy fingerprint is a canonical dump of the *effective* (server-side) policy,
not what the client asked for. That is important: a client asking for a weaker
profile must not be able to read a cached `allow` produced under the strict one.

What is never cached: the attestation. Each response is signed fresh with a new
``jti`` and timestamps, so a cached hit still produces a unique, current proof.
"""

from __future__ import annotations

import json
import sqlite3
import threading
import time
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path

from aegis import canon
from aegis.contracts import AnalysisPolicy, Finding

_SCHEMA = """
CREATE TABLE IF NOT EXISTS analysis_cache (
    cache_key     TEXT PRIMARY KEY,
    prompt_version TEXT NOT NULL,
    model         TEXT NOT NULL,
    findings_json TEXT NOT NULL,
    meta_json     TEXT NOT NULL,
    created_at    REAL NOT NULL,
    expires_at    REAL NOT NULL,
    hits          INTEGER NOT NULL DEFAULT 0
);
CREATE INDEX IF NOT EXISTS analysis_cache_expiry ON analysis_cache(expires_at);
"""


def policy_fingerprint(policy: AnalysisPolicy) -> str:
    """Stable digest of the effective policy.

    ``profile`` is included by name *and* the concrete thresholds are included by
    value, because two profiles with the same name but different thresholds must
    not share a cache entry (that is how a policy change would be silently ignored
    until the TTL expires).
    """
    body = {
        "profile": policy.profile,
        "categories": sorted(c.value for c in policy.categories),
        "block_min_severity": policy.block_min_severity.value,
        "block_min_confidence": round(policy.block_min_confidence, 4),
        "fail_mode": policy.fail_mode,
    }
    return canon.sha256_bytes(canon.canonical_json(body))


def cache_key(
    *,
    payload_sha256: str,
    prompt_version: str,
    model: str,
    policy: AnalysisPolicy,
) -> str:
    return canon.sha256_bytes(
        canon.canonical_json(
            {
                "payload": payload_sha256,
                "prompt": prompt_version,
                "model": model,
                "policy": policy_fingerprint(policy),
            }
        )
    )


@dataclass(frozen=True, slots=True)
class CachedVerdict:
    findings: tuple[Finding, ...]
    meta: dict[str, object]
    created_at: float


class AnalysisCache:
    """Small SQLite-backed cache, separate connection from the auth store."""

    def __init__(
        self,
        path: Path,
        *,
        ttl_seconds: int,
        clock: Callable[[], float] = time.time,
    ) -> None:
        self._path = Path(path).expanduser()
        self._ttl = ttl_seconds
        self._clock = clock
        self._lock = threading.RLock()
        self._path.parent.mkdir(parents=True, exist_ok=True)
        self._conn = sqlite3.connect(str(self._path), check_same_thread=False, isolation_level=None)
        self._conn.row_factory = sqlite3.Row
        with self._lock:
            cur = self._conn.cursor()
            try:
                cur.execute("PRAGMA journal_mode=WAL")
                cur.execute("PRAGMA synchronous=NORMAL")  # a cache: durability is not the point
                cur.executescript(_SCHEMA)
            finally:
                cur.close()

    def close(self) -> None:
        with self._lock:
            self._conn.close()

    def get(self, key: str) -> CachedVerdict | None:
        if self._ttl <= 0:
            return None
        now = self._clock()
        with self._lock:
            row = self._conn.execute("SELECT * FROM analysis_cache WHERE cache_key = ?", (key,)).fetchone()
            if row is None:
                return None
            if row["expires_at"] <= now:
                self._conn.execute("DELETE FROM analysis_cache WHERE cache_key = ?", (key,))
                return None
            self._conn.execute("UPDATE analysis_cache SET hits = hits + 1 WHERE cache_key = ?", (key,))
        try:
            findings = tuple(Finding.model_validate(item) for item in json.loads(row["findings_json"]))
            meta = json.loads(row["meta_json"])
        except (json.JSONDecodeError, ValueError):
            # A corrupt entry must never be trusted: drop and re-analyse.
            self.invalidate(key)
            return None
        return CachedVerdict(findings=findings, meta=meta, created_at=row["created_at"])

    def put(
        self,
        key: str,
        *,
        prompt_version: str,
        model: str,
        findings: tuple[Finding, ...],
        meta: dict[str, object],
    ) -> None:
        now = self._clock()
        with self._lock, self._tx() as cur:
            cur.execute(
                """
                INSERT INTO analysis_cache(
                    cache_key, prompt_version, model, findings_json, meta_json, created_at, expires_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(cache_key) DO UPDATE SET
                    findings_json = excluded.findings_json,
                    meta_json = excluded.meta_json,
                    created_at = excluded.created_at,
                    expires_at = excluded.expires_at
                """,
                (
                    key,
                    prompt_version,
                    model,
                    json.dumps([f.model_dump(mode="json") for f in findings], sort_keys=True),
                    json.dumps(meta, sort_keys=True),
                    now,
                    now + self._ttl,
                ),
            )

    def invalidate(self, key: str) -> None:
        with self._lock:
            self._conn.execute("DELETE FROM analysis_cache WHERE cache_key = ?", (key,))

    def purge_expired(self) -> int:
        with self._lock:
            cur = self._conn.execute("DELETE FROM analysis_cache WHERE expires_at <= ?", (self._clock(),))
            return cur.rowcount

    def stats(self) -> dict[str, int]:
        with self._lock:
            row = self._conn.execute(
                "SELECT COUNT(*) AS n, COALESCE(SUM(hits), 0) AS hits FROM analysis_cache"
            ).fetchone()
        return {"entries": int(row["n"]), "hits": int(row["hits"])}

    def _tx(self) -> _Transaction:
        return _Transaction(self._conn)


class _Transaction:
    """Minimal BEGIN/COMMIT wrapper (``with cache._tx() as cur``)."""

    def __init__(self, conn: sqlite3.Connection) -> None:
        self._conn = conn
        self._cur: sqlite3.Cursor | None = None

    def __enter__(self) -> sqlite3.Cursor:
        self._cur = self._conn.cursor()
        self._cur.execute("BEGIN IMMEDIATE")
        return self._cur

    def __exit__(self, exc_type: object, exc: object, tb: object) -> None:
        assert self._cur is not None  # noqa: S101 - internal invariant
        try:
            self._cur.execute("ROLLBACK" if exc_type else "COMMIT")
        finally:
            self._cur.close()


__all__ = [
    "AnalysisCache",
    "CachedVerdict",
    "cache_key",
    "policy_fingerprint",
]
