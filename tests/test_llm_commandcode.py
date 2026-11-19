"""Command Code adapter tests.

The transport is injected (``opener``), so these tests assert the exact wire
contract — URL, headers, body shape — without a network call. The behaviours that
matter operationally get their own cases, because each one cost real debugging time
against the live API:

* a missing ``User-Agent`` yields ``403 error code: 1010`` from the edge, which looks
  like an auth failure and is not;
* reasoning models can return an empty ``content`` with ``finish_reason=length``,
  which is a truncation, not "no findings";
* ``403 MODEL_NOT_IN_PLAN`` is a configuration error, not something to retry.
"""

from __future__ import annotations

import json
import urllib.error
from typing import Any

import pytest

from aegis.llm import ChatMessage, ChatRequest, CommandCodeProvider, LlmError, LlmErrorCode
from aegis.llm.commandcode import (
    DEFAULT_BASE_URL,
    USER_AGENT,
    resolve_api_key,
)

SCHEMA: dict[str, Any] = {
    "type": "object",
    "additionalProperties": False,
    "required": ["findings"],
    "properties": {"findings": {"type": "array", "items": {"type": "object"}}},
}


class Recorder:
    """Captures requests and replays scripted responses."""

    def __init__(self, *responses: Any) -> None:
        self.responses = list(responses)
        self.requests: list[urllib.request.Request] = []
        self.timeouts: list[float] = []

    def __call__(self, request: urllib.request.Request, timeout: float) -> bytes:
        self.requests.append(request)
        self.timeouts.append(timeout)
        if not self.responses:
            raise AssertionError("unexpected extra request")
        item = self.responses.pop(0)
        if isinstance(item, Exception):
            raise item
        return item if isinstance(item, bytes) else json.dumps(item).encode()

    # -- assertions helpers ------------------------------------------------
    @property
    def last_body(self) -> dict[str, Any]:
        body = self.requests[-1].data
        assert isinstance(body, bytes), f"expected a JSON body, got {type(body).__name__}"
        parsed: dict[str, Any] = json.loads(body)
        return parsed

    @property
    def last_path(self) -> str:
        return self.requests[-1].full_url.removeprefix(DEFAULT_BASE_URL)

    @property
    def last_headers(self) -> dict[str, str]:
        return {k.lower(): v for k, v in self.requests[-1].header_items()}


def chat_completion(text: str = '{"findings": []}', *, finish: str = "stop") -> dict[str, Any]:
    return {
        "id": "x",
        "object": "chat.completion",
        "model": "gpt-6-luna",
        "choices": [{"index": 0, "message": {"role": "assistant", "content": text}, "finish_reason": finish}],
        "usage": {"prompt_tokens": 1234, "completion_tokens": 321, "total_tokens": 1555},
    }


def request(text: str = "review this", *, schema: bool = True) -> ChatRequest:
    return ChatRequest(
        messages=(
            ChatMessage(role="system", content="you are aegis"),
            ChatMessage(role="user", content=text),
        ),
        json_schema=SCHEMA if schema else None,
        max_output_tokens=1234,
        temperature=0.0,
    )


def provider(recorder: Recorder, **kwargs: Any) -> CommandCodeProvider:
    defaults: dict[str, Any] = {
        "api_key": "user_test_key",
        "model": "gpt-6-luna",
        "opener": recorder,
        "clock": lambda: 1_700_000_000.0,
        # Most tests are about the inference call; `auto` would add a catalog GET
        # first. Wire-selection tests opt back in explicitly.
        "wire": "chat",
    }
    defaults.update(kwargs)
    return CommandCodeProvider(**defaults)


# --------------------------------------------------------------------------- #
# Wire contract
# --------------------------------------------------------------------------- #
def test_chat_completions_request_shape() -> None:
    rec = Recorder(chat_completion())
    response = provider(rec).chat(request())

    assert rec.last_path == "/chat/completions"
    body = rec.last_body
    assert body["model"] == "gpt-6-luna"
    assert body["max_tokens"] == 1234
    assert body["temperature"] == 0
    assert body["stream"] is False
    assert body["response_format"]["type"] == "json_schema"
    assert body["response_format"]["json_schema"]["strict"] is True
    assert body["response_format"]["json_schema"]["schema"] == SCHEMA
    assert [m["role"] for m in body["messages"]] == ["system", "user"]
    assert response.text == '{"findings": []}'
    assert response.schema_enforced is True
    assert response.usage.prompt_tokens == 1234


def test_user_agent_is_mandatory_and_present() -> None:
    """Without it the edge answers 403/1010 and it looks like an auth error."""
    rec = Recorder(chat_completion())
    provider(rec).chat(request())
    headers = rec.last_headers
    assert headers["user-agent"] == USER_AGENT
    assert "aegis" in headers["user-agent"].lower()


def test_bearer_auth_and_zdr_header() -> None:
    rec = Recorder(chat_completion())
    provider(rec).chat(request())
    headers = rec.last_headers
    assert headers["authorization"] == "Bearer user_test_key"
    assert headers["x-cmd-zdr"] == "1"


def test_zdr_can_be_disabled() -> None:
    rec = Recorder(chat_completion())
    provider(rec, zdr=False).chat(request())
    assert "x-cmd-zdr" not in rec.last_headers


def test_no_response_format_when_no_schema() -> None:
    rec = Recorder(chat_completion())
    provider(rec).chat(request(schema=False))
    assert "response_format" not in rec.last_body


def test_timeout_is_forwarded() -> None:
    rec = Recorder(chat_completion())
    provider(rec, timeout=7.5).chat(request())
    assert rec.timeouts == [7.5]


# --------------------------------------------------------------------------- #
# Reasoning models and truncation
# --------------------------------------------------------------------------- #
def test_empty_content_with_length_is_a_truncation_not_a_clean_pass() -> None:
    payload = {
        "choices": [
            {
                "message": {"role": "assistant", "content": "", "reasoning_content": "thinking..."},
                "finish_reason": "length",
            }
        ],
        "usage": {"prompt_tokens": 10, "completion_tokens": 4000},
    }
    with pytest.raises(LlmError) as exc:
        provider(Recorder(payload)).chat(request())
    assert exc.value.code is LlmErrorCode.TRUNCATED
    assert "MAX_OUTPUT_TOKENS" in exc.value.message


def test_empty_content_without_length_is_model_output_error() -> None:
    payload = {"choices": [{"message": {"role": "assistant", "content": ""}, "finish_reason": "stop"}]}
    with pytest.raises(LlmError) as exc:
        provider(Recorder(payload)).chat(request())
    assert exc.value.code is LlmErrorCode.MODEL_OUTPUT


def test_reasoning_tokens_are_reported() -> None:
    payload = chat_completion()
    payload["usage"]["completion_tokens_details"] = {"reasoning_tokens": 42}
    response = provider(Recorder(payload)).chat(request())
    assert response.usage.reasoning_tokens == 42
    assert response.usage.total_tokens == 1555


# --------------------------------------------------------------------------- #
# HTTP error mapping
# --------------------------------------------------------------------------- #
def _http_error(code: int, body: bytes) -> urllib.error.HTTPError:
    import io

    return urllib.error.HTTPError(
        url="https://api.commandcode.ai/provider/v1/chat/completions",
        code=code,
        msg="error",
        hdrs=None,  # type: ignore[arg-type]
        fp=io.BytesIO(body),
    )


def test_cloudflare_1010_is_explained_as_a_user_agent_problem() -> None:
    """The single most misleading failure of this API."""
    rec = Recorder(_http_error(403, b"error code: 1010\n"))
    with pytest.raises(LlmError) as exc:
        provider(rec).chat(request())
    assert exc.value.code is LlmErrorCode.FORBIDDEN
    assert "User-Agent" in exc.value.message
    assert "1010" in exc.value.message


def test_model_not_in_plan_is_not_retried() -> None:
    body = json.dumps(
        {"error": {"type": "permission_error", "message": "MODEL_NOT_IN_PLAN: Pro and above"}}
    ).encode()
    rec = Recorder(_http_error(403, body))
    with pytest.raises(LlmError) as exc:
        provider(rec).chat(request())
    assert exc.value.code is LlmErrorCode.FORBIDDEN
    assert "MODEL_NOT_IN_PLAN" in exc.value.message
    assert len(rec.requests) == 1, "a plan error must never be retried"


@pytest.mark.parametrize(
    ("status", "expected"),
    [
        (401, LlmErrorCode.UNAUTHORIZED),
        (429, LlmErrorCode.RATE_LIMITED),
        (500, LlmErrorCode.UNAVAILABLE),
        (503, LlmErrorCode.UNAVAILABLE),
    ],
)
def test_status_mapping(status: int, expected: LlmErrorCode) -> None:
    rec = Recorder(_http_error(status, b'{"error": {"message": "nope"}}'))
    with pytest.raises(LlmError) as exc:
        provider(rec).chat(request())
    assert exc.value.code is expected


def test_schema_rejection_falls_back_to_plain_json() -> None:
    """Some models refuse `response_format`; the validator is the real gate."""
    rec = Recorder(
        _http_error(400, b'{"error": {"message": "response_format unsupported"}}'),
        chat_completion(),
    )
    response = provider(rec).chat(request())
    assert len(rec.requests) == 2
    assert "response_format" not in rec.last_body
    assert response.schema_enforced is False


def test_network_failure_is_unavailable() -> None:
    rec = Recorder(urllib.error.URLError("dns"))
    with pytest.raises(LlmError) as exc:
        provider(rec).chat(request())
    assert exc.value.code is LlmErrorCode.UNAVAILABLE


def test_non_json_body_is_model_output() -> None:
    with pytest.raises(LlmError) as exc:
        provider(Recorder(b"<html>oops</html>")).chat(request())
    assert exc.value.code is LlmErrorCode.MODEL_OUTPUT


def test_missing_api_key_fails_before_any_request() -> None:
    rec = Recorder()
    with pytest.raises(LlmError) as exc:
        provider(rec, api_key="").chat(request())
    assert exc.value.code is LlmErrorCode.UNAUTHORIZED
    assert rec.requests == []


# --------------------------------------------------------------------------- #
# Wire selection
# --------------------------------------------------------------------------- #
CATALOG = {
    "object": "list",
    "data": [
        {
            "id": "gpt-6-luna",
            "supported_endpoints": ["/chat/completions", "/responses"],
        },
        {"id": "claude-sonnet-5", "supported_endpoints": ["/messages"]},
        {"id": "weird-model", "supported_endpoints": ["/responses"]},
        {"id": "no-endpoints-model"},
    ],
}


def test_claude_models_use_the_messages_wire_without_a_catalog_call() -> None:
    """The rule is documented by the provider, so it must not need the network."""
    rec = Recorder()
    p = provider(rec, model="claude-sonnet-5", wire="auto")
    assert p.wire_for() == "messages"
    assert rec.requests == []


def test_wire_is_read_from_the_catalog() -> None:
    rec = Recorder(CATALOG)
    assert provider(rec, model="gpt-6-luna", wire="auto").wire_for() == "chat"
    assert rec.last_path == "/models"


def test_model_without_supported_endpoints_defaults_to_chat() -> None:
    rec = Recorder(CATALOG)
    assert provider(rec, model="no-endpoints-model", wire="auto").wire_for() == "chat"


def test_responses_only_model_is_a_clear_error() -> None:
    rec = Recorder(CATALOG)
    with pytest.raises(LlmError) as exc:
        provider(rec, model="weird-model", wire="auto").wire_for()
    assert "/responses" in exc.value.message
    assert "does not implement" in exc.value.message


def test_catalog_failure_degrades_to_chat() -> None:
    rec = Recorder(urllib.error.URLError("down"))
    assert provider(rec, model="gpt-6-luna", wire="auto").wire_for() == "chat"


def test_unknown_model_in_catalog_is_reported() -> None:
    rec = Recorder(CATALOG)
    with pytest.raises(LlmError, match="not in the catalog"):
        provider(rec, model="ghost-model", wire="auto").wire_for()


def test_forced_wire_overrides_the_catalog() -> None:
    rec = Recorder()
    assert provider(rec, wire="messages").wire_for() == "messages"
    assert rec.requests == []


# --------------------------------------------------------------------------- #
# Anthropic Messages wire
# --------------------------------------------------------------------------- #
def test_messages_wire_request_and_response() -> None:
    payload = {
        "type": "message",
        "model": "claude-sonnet-5",
        "content": [{"type": "text", "text": '{"findings": []}'}],
        "stop_reason": "end_turn",
        "usage": {"input_tokens": 500, "output_tokens": 60},
    }
    rec = Recorder(payload)
    response = provider(rec, model="claude-sonnet-5", wire="messages").chat(request())

    assert rec.last_path == "/messages"
    body = rec.last_body
    assert body["system"] == "you are aegis"
    assert body["messages"] == [{"role": "user", "content": "review this"}]
    assert "system" not in body["messages"][0]
    assert body["tools"][0]["name"] == "report_findings"
    assert body["tool_choice"] == {"type": "tool", "name": "report_findings"}
    assert rec.last_headers["anthropic-version"]

    assert response.text == '{"findings": []}'
    assert response.usage.prompt_tokens == 500


def test_messages_wire_extracts_a_tool_call_as_the_answer() -> None:
    payload = {
        "content": [
            {"type": "text", "text": "Here is my analysis."},
            {"type": "tool_use", "id": "t1", "name": "report_findings", "input": {"findings": []}},
        ],
        "usage": {"input_tokens": 1, "output_tokens": 2},
    }
    response = provider(Recorder(payload), model="claude-sonnet-5", wire="messages").chat(request())
    assert json.loads(response.text) == {"findings": []}
    assert response.schema_enforced is True


def test_messages_wire_requires_a_user_turn() -> None:
    rec = Recorder({"content": [{"type": "text", "text": '{"findings": []}'}], "usage": {}})
    only_system = ChatRequest(messages=(ChatMessage(role="system", content="sys"),))
    provider(rec, model="claude-sonnet-5", wire="messages").chat(only_system)
    assert rec.last_body["messages"] == [{"role": "user", "content": "(no code to review)"}]


# --------------------------------------------------------------------------- #
# API key resolution
# --------------------------------------------------------------------------- #
def test_explicit_key_wins() -> None:
    assert resolve_api_key("explicit", env={"COMMAND_CODE_API_KEY": "env"}, auth_files=()) == "explicit"


def test_env_var_is_used() -> None:
    assert resolve_api_key(None, env={"COMMAND_CODE_API_KEY": "env"}, auth_files=()) == "env"


def test_auth_file_is_used_when_no_env(tmp_path: Any) -> None:
    path = tmp_path / "auth.json"
    path.write_text(json.dumps({"commandcode": {"type": "api", "key": "user_from_file"}}), encoding="utf-8")
    assert resolve_api_key(None, env={}, auth_files=(path,)) == "user_from_file"


def test_flat_auth_file_shape_is_supported(tmp_path: Any) -> None:
    path = tmp_path / "auth.json"
    path.write_text(json.dumps({"apiKey": "user_flat"}), encoding="utf-8")
    assert resolve_api_key(None, env={}, auth_files=(path,)) == "user_flat"


def test_missing_key_returns_empty_not_an_exception(tmp_path: Any) -> None:
    assert resolve_api_key(None, env={}, auth_files=(tmp_path / "nope.json",)) == ""


def test_malformed_auth_file_is_ignored(tmp_path: Any) -> None:
    path = tmp_path / "auth.json"
    path.write_text("not json", encoding="utf-8")
    assert resolve_api_key(None, env={}, auth_files=(path,)) == ""


def test_repr_never_contains_the_key() -> None:
    p = provider(Recorder(), api_key="user_supersecret")
    assert "user_supersecret" not in repr(p)
    assert "key_present=True" in repr(p)
