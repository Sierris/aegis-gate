"""Identity ↔ commit-author binding.

The whole point of authenticating the developer is being able to answer "who
introduced this line?" with something stronger than what git records. Git's
``author.email`` is self-asserted: anyone can set it in ``.gitconfig``. The binding
check is what turns that self-assertion into an authenticated claim:

    token.sub / token.email  ==  commit.author.email   (unless scope analyze:any)

Consequences, deliberately chosen:

* A developer committing with a work e-mail while logged in with a personal one
  gets a **block**, with a message telling them exactly which two identities
  disagree — not a silent attribution to the wrong person.
* CI bots hold ``analyze:any``; their attestations are attributed to the bot, and
  the human behind the commit is still visible in the commit object. Impersonation
  is therefore always provable after the fact.
* Comparison is case-insensitive (git e-mails are case-preserving but
  effectively case-insensitive) and normalised with the same helper the digest
  uses, so the two can never disagree about what "the same identity" means.
"""

from __future__ import annotations

from aegis import canon
from aegis.auth import scopes as scopes_mod
from aegis.auth.jwt import AccessTokenClaims
from aegis.errors import AuthError


def bind_identity(claims: AccessTokenClaims, *, author_email: str) -> str:
    """Return the authenticated actor for this commit, or raise.

    Returning the actor (rather than ``None``) keeps the caller from having to
    re-derive it, which is how "the audit log says one thing and the token said
    another" bugs happen.
    """
    _, token_email = canon.normalize_identity(claims.name or "x", claims.email)
    _, commit_email = canon.normalize_identity("x", author_email)

    if token_email == commit_email:
        return claims.email

    if scopes_mod.has_scope(claims.scopes, scopes_mod.Scope.ANALYZE_ANY):
        # Authorised to analyse on behalf of others (bots, pre-receive checks).
        return claims.email

    raise AuthError(
        f"commit author {commit_email!r} does not match the authenticated user {token_email!r}",
        hint=(
            "Set `git config user.email` to your AEGIS identity, or ask for a token "
            "with the `analyze:any` scope if this is an automated account."
        ),
    )


__all__ = ["bind_identity"]
