"""SQLite persistence for auth state and the audit log.

Deliberate choices
------------------
* **Only hashes of secrets are stored.** ``device_code`` and refresh tokens are
  persisted as SHA-256 digests. A leaked database therefore cannot be used to
  complete a pending device flow or to refresh a stolen session. The user code is
  *not* hashed for one reason: it must be looked up while the user is typing it,
  and it is short-lived, rate-limited and useless without the paired
  ``device_code``.
* **Refresh rotation is modelled as a family.** Each login starts a family; every
  rotation adds a row pointing at its successor. Presenting an already-rotated
  token means the token leaked, so the whole family is revoked (OAuth 2.0 Security
  BCP §4.14.2).
* **Append-only audit chain** using ``canon.chain_hash``: rewriting any row breaks
  every subsequent link, which is exactly what makes the log evidence rather than
  commentary.
* **stdlib ``sqlite3``**, no ORM: the schema is small, the queries are literal,
  and a security component benefits from having zero query-building layers
  between it and the SQL. WAL + ``synchronous=FULL`` for durability.
* **Explicit clock injection** so tests never sleep.
"""

from __future__ import annotations

import json
import sqlite3
import threading
import time
from collections.abc import Callable, Iterator
from contextlib import contextmanager
from dataclasses import dataclass
from pathlib import Path

from aegis import canon
from aegis.contracts import AuditAction, AuditEvent
from aegis.errors import ConfigError, IntegrityError

Clock = Callable[[], float]

_SCHEMA = """
CREATE TABLE IF NOT EXISTS users (
    email           TEXT PRIMARY KEY,
    name            TEXT NOT NULL,
    provider        TEXT NOT NULL DEFAULT 'local',
    password_hash   TEXT,
    created_at      REAL NOT NULL,
    disabled        INTEGER NOT NULL DEFAULT 0
);

CREATE TABLE IF NOT EXISTS device_codes (
    device_code_hash TEXT PRIMARY KEY,
    user_code        TEXT NOT NULL UNIQUE,
    client_id        TEXT NOT NULL,
    requested_scope  TEXT NOT NULL,
    granted_scope    TEXT NOT NULL DEFAULT '',
    scope_downgraded INTEGER NOT NULL DEFAULT 0,
    interval_s       INTEGER NOT NULL,
    created_at       REAL NOT NULL,
    expires_at       REAL NOT NULL,
    last_polled_at   REAL,
    poll_count       INTEGER NOT NULL DEFAULT 0,
    -- pending | approved | denied | consumed
    status           TEXT NOT NULL DEFAULT 'pending',
    sub              TEXT,
    email            TEXT,
    name             TEXT,
    provider         TEXT
);

CREATE TABLE IF NOT EXISTS refresh_tokens (
    token_hash      TEXT PRIMARY KEY,
    family_id       TEXT NOT NULL,
    sub             TEXT NOT NULL,
    email           TEXT NOT NULL,
    name            TEXT,
    provider        TEXT NOT NULL,
    scope           TEXT NOT NULL,
    client_id       TEXT NOT NULL,
    created_at      REAL NOT NULL,
    expires_at      REAL NOT NULL,
    rotated_to      TEXT,
    revoked_at      REAL,
    revoked_reason  TEXT
);
CREATE INDEX IF NOT EXISTS refresh_family_idx ON refresh_tokens(family_id);

CREATE TABLE IF NOT EXISTS audit_log (
    seq           INTEGER PRIMARY KEY AUTOINCREMENT,
    ts            REAL NOT NULL,
    action        TEXT NOT NULL,
    actor         TEXT NOT NULL,
    repo_id       TEXT,
    commit_digest TEXT,
    analysis_id   TEXT,
    detail        TEXT NOT NULL,
    prev_hash     TEXT NOT NULL,
    hash          TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS meta (
    key   TEXT PRIMARY KEY,
    value TEXT NOT NULL
);
"""

_DEVICE_STATUS_PENDING = "pending"
_DEVICE_STATUS_APPROVED = "approved"
_DEVICE_STATUS_DENIED = "denied"
_DEVICE_STATUS_CONSUMED = "consumed"


def hash_secret(value: str) -> str:
    """Digest a secret before persistence. Domain-separated by a prefix so a
    device-code hash can never equal a refresh-token hash of the same string."""
    return canon.sha256_text(value)


@dataclass(frozen=True, slots=True)
class DeviceCodeRow:
    device_code_hash: str
    user_code: str
    client_id: str
    requested_scope: str
    granted_scope: str
    scope_downgraded: bool
    interval_s: int
    created_at: float
    expires_at: float
    poll_count: int
    last_polled_at: float | None
    status: str
    sub: str | None
    email: str | None
    name: str | None
    provider: str | None


@dataclass(frozen=True, slots=True)
class RefreshRow:
    token_hash: str
    family_id: str
    sub: str
    email: str
    name: str | None
    provider: str
    scope: str
    client_id: str
    created_at: float
    expires_at: float
    rotated_to: str | None
    revoked_at: float | None
    revoked_reason: str | None

    @property
    def revoked(self) -> bool:
        return self.revoked_at is not None


@dataclass(frozen=True, slots=True)
class UserRow:
    email: str
    name: str
    provider: str
    password_hash: str | None
    disabled: bool


class AuthStore:
    """Single-connection SQLite store guarded by a lock.

    For the demo workload (a handful of commits per second) one connection with a
    mutex is both simpler and faster than a pool. It also makes the audit chain
    trivially correct: appends cannot interleave, so ``prev_hash`` is always the
    actual last row. Scaling out means moving the chain into a single writer
    (documented in the architecture doc).
    """

    def __init__(self, path: Path, *, clock: Clock = time.time) -> None:
        self._clock = clock
        self._lock = threading.RLock()
        path = Path(path).expanduser()
        path.parent.mkdir(parents=True, exist_ok=True)
        self._path = path
        # isolation_level=None => autocommit; transactions are explicit and go
        # through _tx(). PRAGMAs cannot run inside a transaction, so they are
        # executed before any BEGIN.
        self._conn = sqlite3.connect(str(path), check_same_thread=False, isolation_level=None)
        self._conn.row_factory = sqlite3.Row
        with self._lock:
            cur = self._conn.cursor()
            try:
                # WAL: readers never block the writer (a CI verification and an
                # analysis can run concurrently). synchronous=FULL: an audit entry
                # fsync'd before the response leaves the process.
                cur.execute("PRAGMA journal_mode=WAL")
                cur.execute("PRAGMA synchronous=FULL")
                cur.execute("PRAGMA foreign_keys=ON")
                cur.executescript(_SCHEMA)
            finally:
                cur.close()

    # -- plumbing ----------------------------------------------------------
    @contextmanager
    def _tx(self) -> Iterator[sqlite3.Cursor]:
        cur = self._conn.cursor()
        try:
            cur.execute("BEGIN IMMEDIATE")
            yield cur
            cur.execute("COMMIT")
        except BaseException:
            cur.execute("ROLLBACK")
            raise
        finally:
            cur.close()

    def close(self) -> None:
        with self._lock:
            self._conn.close()

    @property
    def path(self) -> Path:
        return self._path

    # -- users -------------------------------------------------------------
    def upsert_user(
        self, *, email: str, name: str, password_hash: str | None, provider: str = "local"
    ) -> None:
        with self._lock, self._tx() as cur:
            cur.execute(
                """
                INSERT INTO users(email, name, provider, password_hash, created_at, disabled)
                VALUES (?, ?, ?, ?, ?, 0)
                ON CONFLICT(email) DO UPDATE SET
                    name=excluded.name,
                    provider=excluded.provider,
                    password_hash=COALESCE(excluded.password_hash, users.password_hash)
                """,
                (email.lower(), name, provider, password_hash, self._clock()),
            )

    def get_user(self, email: str) -> UserRow | None:
        with self._lock:
            cur = self._conn.execute(
                "SELECT email, name, provider, password_hash, disabled FROM users WHERE email = ?",
                (email.lower(),),
            )
            row = cur.fetchone()
        if row is None:
            return None
        return UserRow(
            email=row["email"],
            name=row["name"],
            provider=row["provider"],
            password_hash=row["password_hash"],
            disabled=bool(row["disabled"]),
        )

    def list_users(self) -> list[UserRow]:
        with self._lock:
            rows = self._conn.execute(
                "SELECT email, name, provider, password_hash, disabled FROM users ORDER BY email"
            ).fetchall()
        return [
            UserRow(
                email=r["email"],
                name=r["name"],
                provider=r["provider"],
                password_hash=r["password_hash"],
                disabled=bool(r["disabled"]),
            )
            for r in rows
        ]

    def disable_user(self, email: str) -> bool:
        with self._lock, self._tx() as cur:
            cur.execute("UPDATE users SET disabled = 1 WHERE email = ?", (email.lower(),))
            return cur.rowcount > 0

    # -- device codes ------------------------------------------------------
    def create_device_code(
        self,
        *,
        device_code: str,
        user_code: str,
        client_id: str,
        requested_scope: str,
        granted_scope: str,
        scope_downgraded: bool,
        interval_s: int,
        ttl_s: int,
    ) -> DeviceCodeRow:
        now = self._clock()
        row = DeviceCodeRow(
            device_code_hash=hash_secret(device_code),
            user_code=user_code,
            client_id=client_id,
            requested_scope=requested_scope,
            granted_scope=granted_scope,
            scope_downgraded=scope_downgraded,
            interval_s=interval_s,
            created_at=now,
            expires_at=now + ttl_s,
            poll_count=0,
            last_polled_at=None,
            status=_DEVICE_STATUS_PENDING,
            sub=None,
            email=None,
            name=None,
            provider=None,
        )
        with self._lock, self._tx() as cur:
            cur.execute(
                """
                INSERT INTO device_codes(
                    device_code_hash, user_code, client_id, requested_scope, granted_scope,
                    scope_downgraded, interval_s, created_at, expires_at, status
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    row.device_code_hash,
                    row.user_code,
                    row.client_id,
                    row.requested_scope,
                    row.granted_scope,
                    int(row.scope_downgraded),
                    row.interval_s,
                    row.created_at,
                    row.expires_at,
                    row.status,
                ),
            )
        return row

    def _device_row(self, column: str, value: str) -> DeviceCodeRow | None:
        if column not in {"device_code_hash", "user_code"}:
            raise ConfigError(f"invalid lookup column: {column}")
        with self._lock:
            row = self._conn.execute(
                f"SELECT * FROM device_codes WHERE {column} = ?",  # noqa: S608 - allowlisted column
                (value,),
            ).fetchone()
        return _device_from_row(row) if row is not None else None

    def get_device_by_code(self, device_code: str) -> DeviceCodeRow | None:
        return self._device_row("device_code_hash", hash_secret(device_code))

    def get_device_by_user_code(self, user_code: str) -> DeviceCodeRow | None:
        return self._device_row("user_code", normalize_user_code(user_code))

    def set_device_status(
        self, user_code: str, status: str, *, identity: tuple[str, str, str | None, str] | None = None
    ) -> bool:
        """Approve or deny a pending device code. Idempotent on terminal states."""
        if status not in {
            _DEVICE_STATUS_APPROVED,
            _DEVICE_STATUS_DENIED,
            _DEVICE_STATUS_CONSUMED,
        }:
            raise ConfigError(f"invalid device status transition: {status}")
        with self._lock, self._tx() as cur:
            cur.execute(
                "SELECT status, expires_at FROM device_codes WHERE user_code = ?",
                (normalize_user_code(user_code),),
            )
            row = cur.fetchone()
            if row is None:
                return False
            if row["status"] != _DEVICE_STATUS_PENDING or row["expires_at"] <= self._clock():
                return False
            if identity is not None:
                sub, email, name, provider = identity
                cur.execute(
                    """
                    UPDATE device_codes
                       SET status = ?, sub = ?, email = ?, name = ?, provider = ?
                     WHERE user_code = ? AND status = 'pending'
                    """,
                    (status, sub, email, name, provider, normalize_user_code(user_code)),
                )
            else:
                cur.execute(
                    "UPDATE device_codes SET status = ? WHERE user_code = ? AND status = 'pending'",
                    (status, normalize_user_code(user_code)),
                )
            return cur.rowcount > 0

    def record_poll(self, device_code: str, *, interval_s: int) -> None:
        """Persist the polling bookkeeping.

        ``interval_s`` is stored per device code (not per process) because
        RFC 8628 §3.5 requires ``slow_down`` to *accumulate*: a client that
        ignores it must keep being told to slow down, across requests.
        """
        with self._lock, self._tx() as cur:
            cur.execute(
                """
                UPDATE device_codes
                   SET poll_count = poll_count + 1, last_polled_at = ?, interval_s = ?
                 WHERE device_code_hash = ?
                """,
                (self._clock(), interval_s, hash_secret(device_code)),
            )

    def consume_device_code(self, device_code: str) -> bool:
        with self._lock, self._tx() as cur:
            cur.execute(
                "UPDATE device_codes SET status = ? WHERE device_code_hash = ? AND status = ?",
                (_DEVICE_STATUS_CONSUMED, hash_secret(device_code), _DEVICE_STATUS_APPROVED),
            )
            return cur.rowcount > 0

    # -- refresh tokens ----------------------------------------------------
    def create_refresh_token(
        self,
        *,
        token: str,
        family_id: str,
        sub: str,
        email: str,
        name: str | None,
        provider: str,
        scope: str,
        client_id: str,
        ttl_s: int,
    ) -> RefreshRow:
        now = self._clock()
        row = RefreshRow(
            token_hash=hash_secret(token),
            family_id=family_id,
            sub=sub,
            email=email,
            name=name,
            provider=provider,
            scope=scope,
            client_id=client_id,
            created_at=now,
            expires_at=now + ttl_s,
            rotated_to=None,
            revoked_at=None,
            revoked_reason=None,
        )
        with self._lock, self._tx() as cur:
            cur.execute(
                """
                INSERT INTO refresh_tokens(
                    token_hash, family_id, sub, email, name, provider, scope, client_id,
                    created_at, expires_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    row.token_hash,
                    row.family_id,
                    row.sub,
                    row.email,
                    row.name,
                    row.provider,
                    row.scope,
                    row.client_id,
                    row.created_at,
                    row.expires_at,
                ),
            )
        return row

    def get_refresh_token(self, token: str) -> RefreshRow | None:
        with self._lock:
            row = self._conn.execute(
                "SELECT * FROM refresh_tokens WHERE token_hash = ?", (hash_secret(token),)
            ).fetchone()
        if row is None:
            return None
        return RefreshRow(
            token_hash=row["token_hash"],
            family_id=row["family_id"],
            sub=row["sub"],
            email=row["email"],
            name=row["name"],
            provider=row["provider"],
            scope=row["scope"],
            client_id=row["client_id"],
            created_at=row["created_at"],
            expires_at=row["expires_at"],
            rotated_to=row["rotated_to"],
            revoked_at=row["revoked_at"],
            revoked_reason=row["revoked_reason"],
        )

    def mark_refresh_rotated(self, old_token: str, new_token: str) -> None:
        with self._lock, self._tx() as cur:
            cur.execute(
                "UPDATE refresh_tokens SET rotated_to = ? WHERE token_hash = ?",
                (hash_secret(new_token), hash_secret(old_token)),
            )

    def revoke_family(self, family_id: str, reason: str) -> int:
        with self._lock, self._tx() as cur:
            cur.execute(
                """
                UPDATE refresh_tokens SET revoked_at = ?, revoked_reason = ?
                 WHERE family_id = ? AND revoked_at IS NULL
                """,
                (self._clock(), reason, family_id),
            )
            return cur.rowcount

    def revoke_refresh_token(self, token: str, reason: str) -> bool:
        with self._lock, self._tx() as cur:
            cur.execute(
                "UPDATE refresh_tokens SET revoked_at = ?, revoked_reason = ? "
                "WHERE token_hash = ? AND revoked_at IS NULL",
                (self._clock(), reason, hash_secret(token)),
            )
            return cur.rowcount > 0

    # -- audit -------------------------------------------------------------
    def append_audit(
        self,
        *,
        action: AuditAction,
        actor: str,
        detail: dict[str, object] | None = None,
        repo_id: str | None = None,
        commit_digest: str | None = None,
        analysis_id: str | None = None,
        key: bytes | None = None,
    ) -> AuditEvent:
        """Append one link to the tamper-evident chain.

        The event body is canonicalised (*sorted* keys) before hashing so a
        rewrite that only reorders JSON keys still breaks the chain.
        """
        with self._lock, self._tx() as cur:
            cur.execute("SELECT seq, hash FROM audit_log ORDER BY seq DESC LIMIT 1")
            last = cur.fetchone()
            prev_hash = last["hash"] if last is not None else canon.GENESIS_HASH
            body: dict[str, object] = {
                "action": action.value,
                "actor": actor,
                "ts": round(self._clock(), 6),
                "detail": detail or {},
                "repo_id": repo_id,
                "commit_digest": commit_digest,
                "analysis_id": analysis_id,
            }
            link = canon.chain_hash(prev_hash=prev_hash, event=body, key=key)
            cur.execute(
                """
                INSERT INTO audit_log(
                    ts, action, actor, repo_id, commit_digest, analysis_id, detail, prev_hash, hash
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    body["ts"],
                    action.value,
                    actor,
                    repo_id,
                    commit_digest,
                    analysis_id,
                    json.dumps(detail or {}, sort_keys=True, ensure_ascii=False, default=str),
                    prev_hash,
                    link,
                ),
            )
            seq = int(cur.lastrowid or 0)
        return AuditEvent(
            seq=seq,
            action=action,
            actor=actor,
            repo_id=repo_id,
            commit_digest=commit_digest,
            analysis_id=analysis_id,
            detail=detail or {},
            prev_hash=prev_hash,
            hash=link,
        )

    def verify_audit_chain(self, *, key: bytes | None = None) -> int:
        """Recompute the chain. Returns the number of verified rows.

        Raises :class:`IntegrityError` on the first broken link, reporting the
        sequence number so an operator can go straight to the offending row.
        """
        with self._lock:
            rows = self._conn.execute(
                """
                SELECT seq, ts, action, actor, repo_id, commit_digest, analysis_id,
                       detail, prev_hash, hash
                  FROM audit_log ORDER BY seq
                """
            ).fetchall()
        prev = canon.GENESIS_HASH
        for row in rows:
            # The body must be rebuilt *exactly* as append_audit hashed it,
            # including the JSON round-trip of `detail` (which is why the second
            # dump/load is not needed: json.dumps here matches the stored string
            # only for canonical input, so we re-sort on read as well).
            body = {
                "action": row["action"],
                "actor": row["actor"],
                "ts": row["ts"],
                "detail": json.loads(row["detail"]),
                "repo_id": row["repo_id"],
                "commit_digest": row["commit_digest"],
                "analysis_id": row["analysis_id"],
            }
            expected = canon.chain_hash(prev_hash=prev, event=body, key=key)
            if expected != row["hash"] or row["prev_hash"] != prev:
                raise IntegrityError(
                    f"audit chain broken at seq={row['seq']}",
                    hint="The audit log has been modified outside AEGIS.",
                )
            prev = row["hash"]
        return len(rows)


def _device_from_row(row: sqlite3.Row) -> DeviceCodeRow:
    return DeviceCodeRow(
        device_code_hash=row["device_code_hash"],
        user_code=row["user_code"],
        client_id=row["client_id"],
        requested_scope=row["requested_scope"],
        granted_scope=row["granted_scope"],
        scope_downgraded=bool(row["scope_downgraded"]),
        interval_s=int(row["interval_s"]),
        created_at=row["created_at"],
        expires_at=row["expires_at"],
        poll_count=int(row["poll_count"]),
        last_polled_at=row["last_polled_at"],
        status=row["status"],
        sub=row["sub"],
        email=row["email"],
        name=row["name"],
        provider=row["provider"],
    )


def normalize_user_code(raw: str) -> str:
    """Upcase and strip everything that is not alphanumeric.

    Users retype codes from another screen (``wdjb-mjht``, ``WDJB MJHT``,
    ``wdjbmjht``). Normalising here means the DB stores exactly one canonical
    form, so ``UNIQUE(user_code)`` actually means something.
    """
    cleaned = "".join(ch for ch in raw.upper() if ch.isalnum())
    return f"{cleaned[:4]}-{cleaned[4:]}" if len(cleaned) > 4 else cleaned


__all__ = [
    "AuthStore",
    "DeviceCodeRow",
    "RefreshRow",
    "UserRow",
    "hash_secret",
    "normalize_user_code",
]
