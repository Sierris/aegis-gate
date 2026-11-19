"""Command Code Provider API adapter.

Wire protocol
-------------
Command Code exposes three inference wires under ``/provider/v1`` and advertises,
per model, which ones it answers on (``supported_endpoints`` in the catalog):

    /provider/v1/chat/completions   OpenAI Chat Completions   (every non-Claude model)
    /provider/v1/responses          OpenAI Responses          (models that advertise it)
    /provider/v1/messages           Anthropic Messages        (Claude models only)

This adapter implements **Chat Completions** and **Anthropic Messages**. Selection
is per model and comes from the live catalog, not from a hardcoded model list,
because the catalog changes weekly and a stale list is a silent outage.

> Why not the Responses wire: in the catalog published today every model that
> advertises ``/responses`` also advertises ``/chat/completions``, so the extra
> wire buys nothing. If that ever changes the adapter fails loudly with
> ``BAD_REQUEST`` and a message naming the model and the supported endpoints,
> instead of silently falling back to something that does not exist.

Operational facts discovered against the live API
-------------------------------------------------
* The edge (Cloudflare) returns **403 ``error code: 1010``** for a missing or
  unrecognised ``User-Agent``. ``urllib``/``requests`` defaults are blocked, so an
  explicit UA is mandatory — a bare ``httpx`` call fails here in a way that looks
  exactly like an auth problem. We always send ours.
* Reasoning models (``deepseek/*``) put everything in a separate
  ``reasoning_content`` channel and can return an **empty ``content``** with
  ``finish_reason=length`` when ``max_tokens`` is small. That is not "no
  findings"; it is a truncated answer and is surfaced as ``TRUNCATED``.
* Plan entitlement is per model: ``claude-*`` and some ``gpt-6.x`` tiers answer
  **403 MODEL_NOT_IN_PLAN**. That is a configuration error, not a retryable one.

Credential resolution
---------------------
In order: explicit setting (``AEGIS_LLM_API_KEY``), then ``COMMAND_CODE_API_KEY``,
then the Command Code CLI auth file, then the pi host auth file. All file reads are
read-only and the key is never logged, echoed in an error, or included in
``repr``.
"""

from __future__ import annotations

import json
import os
import time
import urllib.error
import urllib.request
from collections.abc import Callable, Iterable
from pathlib import Path
from typing import Any

from aegis.llm.base import ChatRequest, ChatResponse, LlmError, LlmErrorCode, Usage

DEFAULT_BASE_URL = "https://api.commandcode.ai/provider/v1"
CATALOG_PATH = "/models"
CHAT_PATH = "/chat/completions"
MESSAGES_PATH = "/messages"

#: Anthropic Messages requires a version header; the date is the current stable one.
ANTHROPIC_VERSION = "2023-06-01"

#: Explicit UA — see the module docstring. Without it the edge returns 403/1010.
USER_AGENT = "aegis-gate/0.1 (commit gate; +https://github.com/Sierris/aegis-gate)"

#: Sentinel used by the catalog when a model entry omits ``supported_endpoints``:
#: every non-Claude model serves Chat Completions, so that is the safe default.
_ENDPOINT_CHAT = "/chat/completions"
_ENDPOINT_RESPONSES = "/responses"
_ENDPOINT_MESSAGES = "/messages"

_WIRE_AUTO = "auto"
_WIRE_CHAT = "chat"
_WIRE_MESSAGES = "messages"

#: Credentials files, in the same order the official CLI/provider uses. Read-only.
_AUTH_FILES: tuple[Path, ...] = (
    Path("~/.commandcode/auth.json"),
    Path("~/.pi/agent/auth.json"),
    Path("~/.omp/agent/auth.json"),
)


def resolve_api_key_source(
    explicit: str | None = None,
    *,
    env: dict[str, str] | None = None,
    auth_files: Iterable[Path] = _AUTH_FILES,
) -> tuple[str, str]:
    """Find the Command Code API key and report **where it came from**.

    Returning the provenance is not a nicety. When a key is picked up from a file
    another tool wrote (the pi host auth file, the Command Code CLI file), nothing
    in the environment says so, and the next person to rotate a credential has no
    idea which one is in use. ``aegis doctor`` prints this line, so the answer to
    "which key am I running with?" is always one command away.

    Order: explicit setting → ``AEGIS_LLM_API_KEY`` → ``COMMAND_CODE_API_KEY`` →
    ``COMMANDCODE_API_KEY`` → the auth files, in the order the official CLI uses.
    """
    environ = env if env is not None else dict(os.environ)
    if explicit and explicit.strip():
        return explicit.strip(), "settings (AEGIS_LLM_API_KEY)"
    for var in ("AEGIS_LLM_API_KEY", "COMMAND_CODE_API_KEY", "COMMANDCODE_API_KEY"):
        value = environ.get(var, "").strip()
        if value:
            return value, f"environment ({var})"
    for path in auth_files:
        resolved = Path(path).expanduser()
        key = _read_auth_file(resolved)
        if key:
            return key, f"auth file ({resolved})"
    return "", "not found"


def resolve_api_key(
    explicit: str | None = None,
    *,
    env: dict[str, str] | None = None,
    auth_files: Iterable[Path] = _AUTH_FILES,
) -> str:
    """Find the Command Code API key, or return ``""``.

    Returning an empty string (instead of raising) lets the caller decide whether
    a missing key is fatal — the ``fake`` provider exists precisely so that a CI
    run can analyse commits with no credentials at all.
    """
    key, _ = resolve_api_key_source(explicit, env=env, auth_files=auth_files)
    return key


def _read_auth_file(path: Path) -> str:
    """Extract a key from the known auth-file shapes, tolerating anything else."""
    try:
        raw = path.read_text(encoding="utf-8")
    except OSError:
        return ""
    try:
        data = json.loads(raw)
    except json.JSONDecodeError:
        return ""
    if not isinstance(data, dict):
        return ""

    def _from(node: object) -> str:
        if isinstance(node, str):
            return node.strip()
        if isinstance(node, dict):
            for field_name in ("key", "apiKey", "api_key", "access_token", "token"):
                value = node.get(field_name)
                if isinstance(value, str) and value.strip():
                    return value.strip()
        return ""

    for node_name in ("commandcode", "command-code", "commandCode"):
        key = _from(data.get(node_name))
        if key:
            return key
    # Shape: {"apiKey": "user_..."}
    return _from(data)


class CommandCodeProvider:
    """Command Code Provider API client (inference only)."""

    name = "commandcode"

    def __init__(
        self,
        *,
        base_url: str = DEFAULT_BASE_URL,
        api_key: str = "",
        model: str = "gpt-6-luna",
        timeout: float = 60.0,
        wire: str = _WIRE_AUTO,
        zdr: bool = True,
        opener: Callable[[urllib.request.Request, float], bytes] | None = None,
        clock: Callable[[], float] = time.time,
        catalog_ttl_seconds: float = 900.0,
    ) -> None:
        self._base_url = base_url.rstrip("/")
        self._api_key = api_key
        self._model = model
        self._timeout = timeout
        self._wire = wire
        self._zdr = zdr
        self._opener = opener or _default_opener
        self._clock = clock
        # Catalog cache. Without it, every analysed commit pays an extra GET for
        # a document that changes weekly — two round-trips in the commit path
        # instead of one, for no information gain.
        self._catalog_ttl = catalog_ttl_seconds
        self._catalog: dict[str, set[str] | None] | None = None
        self._catalog_at: float = 0.0
        self._catalog_failed_at: float | None = None

    # -- introspection -----------------------------------------------------
    def describe(self, model: str | None = None) -> str:
        return f"{self.name}/{model or self._model}"

    @property
    def base_url(self) -> str:
        return self._base_url

    def __repr__(self) -> str:
        # Never include the key: this object ends up in logs and tracebacks.
        return (
            f"CommandCodeProvider(base_url={self._base_url!r}, model={self._model!r}, "
            f"wire={self._wire!r}, key_present={bool(self._api_key)})"
        )

    # -- catalog -----------------------------------------------------------
    def list_models(self, *, use_cache: bool = True) -> list[dict[str, Any]]:
        """``GET /provider/v1/models`` — used for diagnostics and wire selection."""
        if use_cache and self._catalog is not None and not self._catalog_expired():
            return [
                {"id": model_id, "supported_endpoints": sorted(endpoints) if endpoints else None}
                for model_id, endpoints in self._catalog.items()
            ]
        payload = self._request("GET", CATALOG_PATH)
        data = payload.get("data")
        if not isinstance(data, list):
            raise LlmError(LlmErrorCode.BAD_REQUEST, "model catalog has no 'data' array")
        models = [m for m in data if isinstance(m, dict)]
        self._catalog = {
            str(entry.get("id")): _endpoints(entry.get("supported_endpoints")) for entry in models
        }
        self._catalog_at = self._clock()
        self._catalog_failed_at = None
        return models

    def _catalog_expired(self) -> bool:
        return (self._clock() - self._catalog_at) > self._catalog_ttl

    def invalidate_catalog(self) -> None:
        self._catalog = None
        self._catalog_at = 0.0

    def wire_for(self, model: str | None = None) -> str:
        """Pick the wire for a model from its advertised ``supported_endpoints``."""
        if self._wire != _WIRE_AUTO:
            return self._wire
        target = model or self._model

        # Claude models answer only on /messages. This rule is stated by the
        # provider documentation, so it is applied before any network call: the
        # commit gate must not depend on a catalog fetch succeeding.
        if target.startswith("claude-"):
            return _WIRE_MESSAGES
        try:
            endpoints = self._endpoints_of(target)
        except LlmError as exc:
            if exc.code is LlmErrorCode.UNKNOWN_MODEL:
                # A typo in AEGIS_LLM_MODEL must not silently fall back to a wire
                # that the model may not serve; the operator has to see it.
                raise
            # Catalog unavailable: Chat Completions is the documented default for
            # every non-Claude model, so this is a safe degradation.
            return _WIRE_CHAT
        if endpoints is None or _ENDPOINT_CHAT in endpoints:
            return _WIRE_CHAT
        if _ENDPOINT_MESSAGES in endpoints:
            return _WIRE_MESSAGES
        if _ENDPOINT_RESPONSES in endpoints:
            raise LlmError(
                LlmErrorCode.BAD_REQUEST,
                f"model {target!r} only serves {_ENDPOINT_RESPONSES}, which this adapter "
                "does not implement; choose a model that advertises /chat/completions",
                model=target,
            )
        return _WIRE_CHAT

    def _endpoints_of(self, model: str) -> set[str] | None:
        # A recent catalog failure must not be retried on every request: the commit
        # gate would add a timeout to each analysis while the catalog is down.
        if (
            self._catalog_failed_at is not None
            and (self._clock() - self._catalog_failed_at) < self._catalog_ttl
            and self._catalog is not None
        ):
            return self._catalog.get(model)
        try:
            self.list_models()
        except LlmError:
            self._catalog_failed_at = self._clock()
            raise
        if self._catalog is None:  # pragma: no cover - list_models always populates it
            return None
        if model not in self._catalog:
            raise LlmError(
                LlmErrorCode.UNKNOWN_MODEL,
                f"model {model!r} is not in the catalog; run `aegis models` for the ids your plan exposes",
                model=model,
            )
        return self._catalog[model]

    # -- inference ---------------------------------------------------------
    def chat(self, request: ChatRequest) -> ChatResponse:
        if not self._api_key:
            raise LlmError(
                LlmErrorCode.UNAUTHORIZED,
                "no Command Code API key (set AEGIS_LLM_API_KEY or COMMAND_CODE_API_KEY)",
            )
        model = request.model or self._model
        wire = self.wire_for(model)
        started = self._clock()

        if wire == _WIRE_MESSAGES:
            body = self._messages_body(request, model)
            payload = self._request("POST", MESSAGES_PATH, body, model=model)
            response = self._parse_messages(payload, model)
        else:
            body = self._chat_body(request, model)
            try:
                payload = self._request("POST", CHAT_PATH, body, model=model)
            except LlmError as exc:
                # Some models reject ``response_format``. Retrying without it is
                # worth one round-trip: the prompt asks for JSON anyway and the
                # validator is the real gate, but only retry on a 4xx that is not
                # an auth/plan problem.
                if exc.code is LlmErrorCode.BAD_REQUEST and request.json_schema is not None:
                    body.pop("response_format", None)
                    payload = self._request("POST", CHAT_PATH, body, model=model)
                    response = self._parse_chat(payload, model)
                    return self._finish(response, started, schema_enforced=False)
                raise
            response = self._parse_chat(payload, model)

        return self._finish(response, started, schema_enforced=response.schema_enforced)

    def _finish(self, response: ChatResponse, started: float, *, schema_enforced: bool) -> ChatResponse:
        return ChatResponse(
            text=response.text,
            model=response.model,
            usage=response.usage,
            schema_enforced=schema_enforced,
            finish_reason=response.finish_reason,
            latency_ms=int((self._clock() - started) * 1000),
            had_reasoning=response.had_reasoning,
        )

    # -- request bodies ----------------------------------------------------
    def _chat_body(self, request: ChatRequest, model: str) -> dict[str, Any]:
        body: dict[str, Any] = {
            "model": model,
            "messages": [{"role": m.role, "content": m.content} for m in request.messages],
            "max_tokens": request.max_output_tokens,
            "temperature": request.temperature,
            # Determinism matters for a gate: the same commit re-analysed after a
            # cache miss must not flip verdict because of sampling.
            "stream": False,
        }
        if request.json_schema is not None:
            body["response_format"] = {
                "type": "json_schema",
                "json_schema": {
                    "name": "aegis_analysis",
                    "strict": True,
                    "schema": request.json_schema,
                },
            }
        return body

    def _messages_body(self, request: ChatRequest, model: str) -> dict[str, Any]:
        """Anthropic Messages shape: system is a top-level field, not a message."""
        system_parts = [m.content for m in request.messages if m.role == "system"]
        user_parts = [m.content for m in request.messages if m.role != "system"]
        if not user_parts:
            # The Messages API requires at least one user turn.
            user_parts = ["(no code to review)"]
        body: dict[str, Any] = {
            "model": model,
            "max_tokens": request.max_output_tokens,
            "temperature": request.temperature,
            "messages": [{"role": "user", "content": "\n\n".join(user_parts)}],
        }
        if system_parts:
            body["system"] = "\n\n".join(system_parts)
        if request.json_schema is not None:
            # Structured output on this wire is expressed as a tool the model must
            # call, which is the documented Anthropic mechanism.
            body["tools"] = [
                {
                    "name": "report_findings",
                    "description": "Report the security findings for the reviewed code.",
                    "input_schema": request.json_schema,
                }
            ]
            body["tool_choice"] = {"type": "tool", "name": "report_findings"}
        return body

    # -- response parsers --------------------------------------------------
    def _parse_chat(self, payload: dict[str, Any], model: str) -> ChatResponse:
        choices = payload.get("choices")
        if not isinstance(choices, list) or not choices:
            raise LlmError(LlmErrorCode.MODEL_OUTPUT, "response has no choices", model=model)
        choice = _as_dict(choices[0])
        message = _as_dict(choice.get("message"))
        content = message.get("content")
        text = content if isinstance(content, str) else ""
        reasoning = message.get("reasoning_content")
        finish = str(choice.get("finish_reason") or "stop")

        if not text.strip():
            if finish == "length":
                raise LlmError(
                    LlmErrorCode.TRUNCATED,
                    f"model {model!r} exhausted max_tokens inside the reasoning channel "
                    "and returned no answer; raise AEGIS_LLM_MAX_OUTPUT_TOKENS",
                    model=model,
                )
            raise LlmError(LlmErrorCode.MODEL_OUTPUT, f"model {model!r} returned empty content", model=model)

        usage_raw = _as_dict(payload.get("usage"))
        details = _as_dict(usage_raw.get("completion_tokens_details"))
        reasoning_tokens = _int(details.get("reasoning_tokens"))
        return ChatResponse(
            text=text,
            model=str(payload.get("model") or model),
            usage=Usage(
                prompt_tokens=_int(usage_raw.get("prompt_tokens")),
                completion_tokens=_int(usage_raw.get("completion_tokens")),
                reasoning_tokens=reasoning_tokens,
            ),
            schema_enforced=True,
            finish_reason=finish,
            had_reasoning=bool(reasoning),
        )

    def _parse_messages(self, payload: dict[str, Any], model: str) -> ChatResponse:
        blocks = payload.get("content")
        if not isinstance(blocks, list):
            raise LlmError(LlmErrorCode.MODEL_OUTPUT, "messages response has no content", model=model)

        text_parts: list[str] = []
        tool_json: str | None = None
        for block in blocks:
            if not isinstance(block, dict):
                continue
            if block.get("type") == "text" and isinstance(block.get("text"), str):
                text_parts.append(block["text"])
            elif block.get("type") == "tool_use":
                # The schema came back as a tool call; the analysis *is* its input.
                tool_json = json.dumps(block.get("input", {}))
        text = tool_json if tool_json is not None else "".join(text_parts)
        if not text.strip():
            raise LlmError(LlmErrorCode.MODEL_OUTPUT, "model returned no usable content", model=model)

        usage_raw = _as_dict(payload.get("usage"))
        return ChatResponse(
            text=text,
            model=str(payload.get("model") or model),
            usage=Usage(
                prompt_tokens=_int(usage_raw.get("input_tokens")),
                completion_tokens=_int(usage_raw.get("output_tokens")),
            ),
            schema_enforced=tool_json is not None,
            finish_reason=str(payload.get("stop_reason") or "stop"),
        )

    # -- transport ---------------------------------------------------------
    def _request(
        self,
        method: str,
        path: str,
        body: dict[str, Any] | None = None,
        *,
        model: str = "",
    ) -> dict[str, Any]:
        url = f"{self._base_url}{path}"
        headers = {
            "Authorization": f"Bearer {self._api_key}",
            "Accept": "application/json",
            # MANDATORY: the edge rejects requests without a recognised UA.
            "User-Agent": USER_AGENT,
            "X-Aegis-Client": "commit-gate",
        }
        if self._zdr:
            headers["x-cmd-zdr"] = "1"
        data: bytes | None = None
        if body is not None:
            headers["Content-Type"] = "application/json"
            data = json.dumps(body).encode("utf-8")
        if path == MESSAGES_PATH:
            headers["anthropic-version"] = ANTHROPIC_VERSION

        # S310 is not applicable: ``url`` is a configured https base plus one of the
        # three constant paths in this module. No caller-controlled scheme or host
        # can reach this line, and ``_default_opener`` uses urllib's https handler.
        request = urllib.request.Request(url, data=data, headers=headers, method=method)  # noqa: S310
        try:
            raw = self._opener(request, self._timeout)
        except urllib.error.HTTPError as exc:  # transport layer surfaced a status
            raise self._error_from_http(exc, model=model) from exc
        except (urllib.error.URLError, TimeoutError, OSError) as exc:
            raise LlmError(LlmErrorCode.UNAVAILABLE, f"cannot reach {url}: {exc}", model=model) from exc

        try:
            payload = json.loads(raw)
        except json.JSONDecodeError as exc:
            raise LlmError(
                LlmErrorCode.MODEL_OUTPUT, "provider returned non-JSON bytes", model=model
            ) from exc
        if not isinstance(payload, dict):
            raise LlmError(LlmErrorCode.MODEL_OUTPUT, "provider returned a non-object body", model=model)
        return payload

    def _error_from_http(self, exc: urllib.error.HTTPError, *, model: str) -> LlmError:
        """Map an HTTP failure to a code the engine can act on."""
        detail = _error_message(exc)
        if exc.code == 403:
            return LlmError(LlmErrorCode.FORBIDDEN, _explain_403(detail), model=model)
        if exc.code >= 500:
            return LlmError(LlmErrorCode.UNAVAILABLE, f"provider error {exc.code}: {detail}", model=model)
        mapping = {
            400: (LlmErrorCode.BAD_REQUEST, detail or "bad request"),
            401: (LlmErrorCode.UNAUTHORIZED, detail or "invalid API key"),
            404: (LlmErrorCode.BAD_REQUEST, detail or "not found"),
            429: (LlmErrorCode.RATE_LIMITED, detail or "rate limited"),
        }
        code, message = mapping.get(exc.code, (LlmErrorCode.BAD_REQUEST, f"HTTP {exc.code}: {detail}"))
        return LlmError(code, message, model=model)


def _default_opener(request: urllib.request.Request, timeout: float) -> bytes:
    # S310: the URL is built from a configured https base plus a fixed path; no
    # user-controlled scheme can reach here.
    with urllib.request.urlopen(request, timeout=timeout) as response:  # noqa: S310
        raw: bytes = response.read()
    return raw


def _endpoints(value: object) -> set[str] | None:
    """Normalise ``supported_endpoints``; ``None`` means "not advertised"."""
    if not isinstance(value, list):
        return None
    items = {item for item in value if isinstance(item, str)}
    return items or None


def _int(value: object) -> int:
    return value if isinstance(value, int) else 0


def _as_dict(value: object) -> dict[str, Any]:
    """Narrow ``object`` to a dict, or an empty one. Keeps the parsers flat."""
    return value if isinstance(value, dict) else {}


def _explain_403(detail: str) -> str:
    """Turn an opaque 403 into an actionable message.

    Two very different causes share this status code, and confusing them wastes
    hours: an edge/WAF rejection (Cloudflare 1010) looks exactly like a plan
    entitlement error if you only read the status.
    """
    if "1010" in detail:
        return (
            "edge rejected the request (Cloudflare 1010): the User-Agent header is missing or "
            "blocked. Keep AEGIS's User-Agent; library defaults are blocked"
        )
    if "MODEL_NOT_IN_PLAN" in detail or "plan" in detail.lower():
        return (
            f"{detail or 'model not in plan'} - pick a model your Command Code plan includes "
            "(`aegis models` lists the ones that answer for this key)"
        )
    return detail or "forbidden"


def _error_message(exc: urllib.error.HTTPError) -> str:
    try:
        raw = exc.read()[:2000]
    except Exception:
        # Best effort: never let body-parsing mask the HTTP status, which is the
        # information the caller needs.
        return ""
    text = raw.decode("utf-8", "replace")
    try:
        payload = json.loads(text)
    except json.JSONDecodeError:
        return text.strip()
    if isinstance(payload, dict):
        error = payload.get("error")
        if isinstance(error, dict):
            return str(error.get("message") or error.get("type") or "")
        if isinstance(error, str):
            return error
        if isinstance(payload.get("message"), str):
            return str(payload["message"])
    return text.strip()


__all__ = [
    "CATALOG_PATH",
    "DEFAULT_BASE_URL",
    "USER_AGENT",
    "CommandCodeProvider",
    "resolve_api_key",
    "resolve_api_key_source",
]
