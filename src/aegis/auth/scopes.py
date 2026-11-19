"""The closed set of AEGIS capabilities.

Why a closed set instead of free-form strings: an attestation carries the scope
that authorised it, and a verifier decides "was this token allowed to assert an
allow verdict?" by comparing scopes. Free strings would let a typo
(``anaylze``) silently produce a token that satisfies no check *and* no denial,
i.e. a fail-open path. Here, unknown scopes are a hard error at parse time.

Implication rules are explicit and total: ``admin`` implies everything, and
``analyze:any`` implies ``analyze`` (it is the same capability, minus the
identity binding). Nothing else implies anything.
"""

from __future__ import annotations

import enum

from aegis.errors import AuthError


class Scope(enum.StrEnum):
    #: Run an analysis on a commit whose author matches the token holder.
    ANALYZE = "analyze"
    #: Run an analysis on any commit (CI bots, pre-receive checks). Deliberately
    #: separate so a human token can never be replayed as a bot token.
    ANALYZE_ANY = "analyze:any"
    #: Mint an ``allow_override`` attestation after a second-identity approval.
    OVERRIDE = "override"
    #: Manage users, rotate keys, change profiles.
    ADMIN = "admin"


#: ``{granted: {implied, ...}}`` — the implication graph, written out in full.
_IMPLIES: dict[Scope, frozenset[Scope]] = {
    Scope.ADMIN: frozenset({Scope.ANALYZE, Scope.ANALYZE_ANY, Scope.OVERRIDE, Scope.ADMIN}),
    Scope.OVERRIDE: frozenset({Scope.OVERRIDE}),
    Scope.ANALYZE_ANY: frozenset({Scope.ANALYZE, Scope.ANALYZE_ANY}),
    Scope.ANALYZE: frozenset({Scope.ANALYZE}),
}

_SCOPE_SEPARATOR = " "

#: Scopes a client is never allowed to obtain by *asking* in the device flow.
NON_REQUESTABLE: frozenset[Scope] = frozenset({Scope.ADMIN, Scope.OVERRIDE})


def parse_scopes(raw: str | None) -> frozenset[Scope]:
    """Parse a space-delimited OAuth scope string.

    Empty/whitespace yields an empty set (a token that can do nothing, which is
    the safe reading of a missing scope claim). Unknown values raise rather than
    being ignored: a token asking for ``analyze,superuser`` is either a bug or an
    attack, and in both cases we want a loud failure.
    """
    if not raw:
        return frozenset()
    out: set[Scope] = set()
    for chunk in raw.split(_SCOPE_SEPARATOR):
        candidate = chunk.strip()
        if not candidate:
            continue
        try:
            out.add(Scope(candidate))
        except ValueError as exc:
            raise AuthError(f"unknown scope requested: {candidate!r}") from exc
    return frozenset(out)


def format_scopes(scopes: frozenset[Scope] | set[Scope] | tuple[Scope, ...]) -> str:
    """Serialise deterministically (sorted) so scope strings are comparable."""
    return _SCOPE_SEPARATOR.join(sorted(s.value for s in scopes))


def expand(scopes: frozenset[Scope]) -> frozenset[Scope]:
    """Apply the implication graph, returning what these scopes can *do*."""
    result: set[Scope] = set()
    for scope in scopes:
        result |= _IMPLIES[scope]
    return frozenset(result)


def has_scope(granted: frozenset[Scope], required: Scope) -> bool:
    """True when ``granted`` confers ``required`` after implication."""
    return required in expand(granted)


def require_scope(granted: frozenset[Scope], required: Scope, *, actor: str = "") -> None:
    """Raise :class:`AuthError` (HTTP 403 upstream) when the scope is missing."""
    if has_scope(granted, required):
        return
    who = f" for {actor}" if actor else ""
    raise AuthError(
        f"missing required scope {required.value!r}{who}",
        hint=f"Granted: {format_scopes(granted) or '<none>'}",
    )


def clamp_requested(requested: frozenset[Scope], allowed: frozenset[Scope]) -> frozenset[Scope]:
    """Intersect a requested scope set with what the server is willing to issue.

    Note the direction: we **downscope** to the intersection, never upscope. If a
    caller asks for ``admin`` and only ``analyze`` is issuable, they get
    ``analyze`` — matching RFC 6749 §3.3 ("the server MAY fully or partially
    ignore the scope requested"). The original request is logged by the caller so
    the downgrade attempt itself is observable.
    """
    return frozenset(s for s in requested if s in expand(allowed))
