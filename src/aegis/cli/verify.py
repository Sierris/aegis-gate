"""``aegis verify`` · ``aegis keys export`` · ``aegis-pre-push``.

These three commands are the enforcement side. The distinction they encode:

    pre-commit   developer convenience  → can be bypassed with --no-verify
    pre-push     local fast feedback    → can be bypassed with --no-verify
    CI           the actual control     → cannot be bypassed by the author

That is not a weakness of the design, it is the design: the client is untrusted, so
the only enforcement that means anything is the one that runs on infrastructure the
author does not control. ``verify`` is the same verifier in all three places, which
is why a local rejection and a CI rejection are the same message.
"""

from __future__ import annotations

import json
import os
import sys
from pathlib import Path

import httpx

from aegis import canon
from aegis.attest.verify import AttestationVerifier, Jwks
from aegis.config import get_server_settings
from aegis.contracts import VerifyReason
from aegis.errors import AegisError, ConfigError, IntegrityError
from aegis.gitx import GitRepo, verify_range
from aegis.gitx.verify import resolve_range

#: Exit code for a failed verification (documented in aegis.errors).
EXIT_INTEGRITY = 5

_ICON = {
    VerifyReason.OK: "✅",
    VerifyReason.MISSING_ATTESTATION: "⛔",
    VerifyReason.DIGEST_MISMATCH: "🚨",
    VerifyReason.BAD_SIGNATURE: "🚨",
    VerifyReason.UNKNOWN_KEY: "🔑",
    VerifyReason.WRONG_AUDIENCE: "🎯",
    VerifyReason.EXPIRED: "⌛",
    VerifyReason.NOT_YET_VALID: "⌛",
    VerifyReason.ISSUER_MISMATCH: "🎯",
    VerifyReason.DECISION_BLOCK: "⛔",
    VerifyReason.PAYLOAD_MISMATCH: "🚨",
    VerifyReason.SCHEMA_UNSUPPORTED: "⚠️ ",
    VerifyReason.UNVERIFIED_LOCAL: "· ",
    VerifyReason.MERGE_COMMIT_SKIPPED: "· ",
}


def jwks_source(explicit: str | None = None) -> str:
    """Where the trust anchor comes from.

    Order: ``--jwks`` → ``AEGIS_JWKS`` → ``AEGIS_JWKS_FILE`` → a pinned file at
    ``.aegis/jwks.json``.

    A pinned file in the repository is a legitimate production choice, not a
    shortcut: the trust anchor is the one artefact whose change *must* be reviewed
    as a commit. Fetching it at verification time means an attacker who controls
    the network path (or the server) can rotate the anchor without a review.
    """
    if explicit:
        return explicit
    env = os.environ.get("AEGIS_JWKS", "").strip() or os.environ.get("AEGIS_JWKS_FILE", "").strip()
    if env:
        return env
    pinned = Path(".aegis/jwks.json")
    if pinned.exists():
        return str(pinned)
    raise ConfigError(
        "no trust anchor for attestation verification",
        hint=(
            "Provide one with `--jwks <file|url>`, AEGIS_JWKS, or export it from the "
            "server with `aegis keys export --out .aegis/jwks.json`."
        ),
    )


def build_verifier(
    *, jwks: str | None = None, issuer: str | None = None, now: float | None = None
) -> AttestationVerifier:
    """Assemble the verifier from an explicit source or the environment."""
    settings = get_server_settings()
    source = jwks or jwks_source(None)
    return AttestationVerifier(
        jwks=Jwks.load(source),
        issuer=issuer or settings.issuer or settings.public_url,
        leeway_seconds=settings.clock_skew_seconds,
        now=(lambda: now) if now is not None else __import__("time").time,
    )


def cmd_verify(
    *,
    range_spec: str | None,
    jwks: str | None,
    issuer: str | None,
    require_attestation: bool,
    as_json: bool,
    include_merges: bool = False,
) -> int:
    try:
        repo = GitRepo.discover(Path.cwd())
        spec = range_spec or _default_range(repo)
        commits = resolve_range(repo, spec)
        verifier = build_verifier(jwks=jwks, issuer=issuer)
    except AegisError as exc:
        print(f"✗ {exc.render()}", file=sys.stderr)
        return exc.exit_code

    if not commits:
        print(f"  AEGIS · no hay commits en el rango {spec!r}")
        return 0

    report = verify_range(
        repo,
        commits,
        verifier=verifier,
        require_attestation=require_attestation,
        skip_merges=not include_merges,
    )

    if as_json:
        print(
            json.dumps(
                {
                    "repo_id": repo.repo_id(),
                    "range": spec,
                    "all_ok": report.all_ok,
                    "counts": report.counts(),
                    "results": [r.model_dump(mode="json") for r in report.results],
                    "skipped_merges": report.skipped_merges,
                },
                indent=2,
                default=str,
            )
        )
    else:
        print(f"\n  AEGIS · verificación de integridad  ({repo.repo_id()})")
        print(f"  rango: {spec}   commits: {len(commits)}   claves: {', '.join(verifier.kids)}")
        print()
        for result in report.results:
            icon = _ICON.get(result.reason, "•")
            print(f"  {icon} {result.commit_sha[:12]}  {result.reason.value}")
            print(f"       {result.detail}")
            if result.claims is not None:
                print(
                    f"       atestiguado por {result.claims.sub} · "
                    f"{result.claims.decision.value} · {result.claims.model}"
                )
        if report.skipped_merges:
            print(f"  ·  {len(report.skipped_merges)} merge commit(s) omitido(s)")
        print()
        print(f"  resumen: {report.counts() or '{}'}")

    if report.all_ok:
        return 0
    print(
        "\n  ✗ Verificación FALLIDA: los commits marcados no están cubiertos por una attestation válida.",
        file=sys.stderr,
    )
    if any(r.reason is VerifyReason.MISSING_ATTESTATION for r in report.failures):
        print(
            "    Un commit sin attestation suele significar `git commit --no-verify` o un\n"
            "    hook no instalado. Vuelve a hacer el commit con el hook activo.",
            file=sys.stderr,
        )
    if any(r.reason is VerifyReason.DIGEST_MISMATCH for r in report.failures):
        print(
            "    Un desajuste de digest significa que el commit cambió DESPUÉS del análisis\n"
            "    (amend, rebase o edición manual). Es exactamente lo que este control detecta.",
            file=sys.stderr,
        )
    return EXIT_INTEGRITY


def _default_range(repo: GitRepo) -> str:
    """Sensible default: what this branch is about to push."""
    upstream = repo._run("rev-parse", "--abbrev-ref", "--symbolic-full-name", "@{upstream}", check=False)
    if upstream.strip():
        return f"{upstream.decode().strip()}..HEAD"
    head = repo.head_sha()
    if head is None:
        return "HEAD"
    return "HEAD~1..HEAD"


def cmd_keys_show(source: str | None = None) -> int:
    """Print the JWKS a verifier would trust."""
    settings = get_server_settings()
    origin = source or f"{settings.public_url}/v1/keys"
    try:
        document = _fetch_jwks_document(origin)
        Jwks.from_json(document)  # fail early on a malformed or mismatched document
    except AegisError as exc:
        print(f"✗ {exc.render()}", file=sys.stderr)
        return exc.exit_code
    print(json.dumps(document, indent=2, sort_keys=True))
    return 0


def cmd_keys_export(*, out: Path, jwks: str | None) -> int:
    """Export the JWKS so a verifier can pin it (CI, another machine)."""
    settings = get_server_settings()
    source = jwks or f"{settings.public_url}/v1/keys"
    try:
        document = _fetch_jwks_document(source)
    except AegisError as exc:
        print(f"✗ {exc.render()}", file=sys.stderr)
        return exc.exit_code

    out = Path(out).expanduser()
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(document, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    raw_keys = document.get("keys")
    kids = [
        entry.get("kid")
        for entry in (raw_keys if isinstance(raw_keys, list) else [])
        if isinstance(entry, dict)
    ]
    print(f"  ✓ JWKS escrito en {out}  (kid: {', '.join(str(k) for k in kids)})")
    print("    Este fichero es un ancla de confianza: su cambio debe revisarse como un commit.")
    return 0


def _fetch_jwks_document(source: str) -> dict[str, object]:
    try:
        if source.startswith(("http://", "https://")):
            response = httpx.get(source, timeout=10.0)
            response.raise_for_status()
            data = response.json()
        else:
            data = json.loads(Path(source).expanduser().read_text(encoding="utf-8"))
    except (httpx.HTTPError, OSError, json.JSONDecodeError) as exc:
        raise IntegrityError(f"cannot read the JWKS from {source}: {exc}") from exc
    if not isinstance(data, dict):
        raise IntegrityError(f"the JWKS at {source} is not a JSON object")
    return data


def pre_push_main(stdin: str | None = None) -> int:
    """``pre-push`` stage: verify exactly the commits about to be sent.

    Git provides one line per ref on stdin:

        <local ref> <local sha> <remote ref> <remote sha>

    A zero ``local sha`` means the ref is being deleted: nothing to verify. A zero
    ``remote sha`` is a new branch, so the range is everything not on any remote.

    **When stdin is empty** (which is what happens under pre-commit.com: its
    ``hook-impl`` does not forward git's stdin to hooks) the range falls back to
    ``@{upstream}..HEAD``. That is the same set of commits in the normal "push a
    branch ahead of its upstream" case, and the chosen range is printed so it is
    never a guess the developer cannot see.

    This is *fast local feedback*, not the control: it uses the same verifier as CI
    precisely so that a developer who sees green here sees green there.
    """
    del stdin  # the real input is read below; the parameter exists for tests
    lines = [line for line in sys.stdin.read().splitlines() if line.strip()]

    try:
        repo = GitRepo.discover(Path.cwd())
        verifier = build_verifier()
    except AegisError as exc:
        print(f"  AEGIS · verificación omitida: {exc.render()}", file=sys.stderr)
        return 0  # never block a push because the local trust anchor is missing

    commits: list[str] = []
    for line in lines:
        parts = line.split()
        if len(parts) < 4:
            continue
        _local_ref, local_sha, _remote_ref, remote_sha = parts[:4]
        if set(local_sha) == {"0"}:
            continue  # ref deletion
        base = remote_sha if set(remote_sha) != {"0"} else _remote_base(repo)
        spec = f"{base}..{local_sha}" if base else local_sha
        commits.extend(resolve_range(repo, spec))

    if not lines:
        spec = _default_range(repo)
        print(f"  AEGIS · sin refs en stdin (pre-commit no los reenvía); usando {spec}", file=sys.stderr)
        try:
            commits = resolve_range(repo, spec)
        except AegisError as exc:
            print(f"  AEGIS · no se pudo resolver el rango: {exc.render()}", file=sys.stderr)
            return 0

    commits = list(dict.fromkeys(commits))
    if not commits:
        print("  AEGIS · no hay commits nuevos que verificar", file=sys.stderr)
        return 0

    report = verify_range(repo, commits, verifier=verifier, require_attestation=True)
    if report.all_ok:
        print(f"  AEGIS · ✓ {len(report.results)} commit(s) con attestation válida", file=sys.stderr)
        return 0

    print(
        f"\n  AEGIS · ✗ {len(report.failures)} de {len(report.results)} commit(s) sin attestation válida:",
        file=sys.stderr,
    )
    for failure in report.failures:
        print(f"    {failure.commit_sha[:12]}  {failure.reason.value}: {failure.detail}", file=sys.stderr)
    print(
        "\n  CI rechazará este push. Para arreglarlo, rehaz el commit con el hook activo\n"
        "  (`pre-commit install`) o reescribe la historia con commits analizados.\n"
        "  Si el servidor está caído, un operador puede emitir un override firmado.\n",
        file=sys.stderr,
    )
    return EXIT_INTEGRITY


def _remote_base(repo: GitRepo) -> str | None:
    """Best-effort base for a brand-new branch: the merge-base with origin/HEAD."""
    for candidate in ("origin/HEAD", "origin/main", "origin/master"):
        out = repo._run("rev-parse", "--verify", "-q", candidate, check=False).decode().strip()
        if out:
            merge_base = repo._run("merge-base", out, "HEAD", check=False).decode().strip()
            if merge_base:
                return merge_base
    return None


def repo_identity_hint(repo: GitRepo) -> str:
    """Used by ``aegis doctor`` to show what a verifier would see."""
    try:
        return canon.normalize_repo_id(repo.repo_id())
    except ValueError as exc:  # pragma: no cover - defensive
        return f"(unknown: {exc})"


__all__ = [
    "EXIT_INTEGRITY",
    "build_verifier",
    "cmd_keys_export",
    "cmd_keys_show",
    "cmd_verify",
    "jwks_source",
    "pre_push_main",
    "repo_identity_hint",
]
