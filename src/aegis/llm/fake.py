"""Deterministic provider for tests, CI and offline demos.

Two jobs:

1. **Test double.** It returns exactly what a test tells it to, including
   malformed JSON, fabricated evidence, an attempted prompt-injection payload —
   the failure modes the validator exists to catch.
2. **Offline mode.** `AEGIS_LLM_PROVIDER=fake` makes the whole pipeline runnable
   with no credentials and no network, which is what CI uses. It never pretends to
   be a real review: responses carry `model="fake"` so nothing downstream can
   mistake a fixture for an analysis.
"""

from __future__ import annotations

import json
import time
from collections.abc import Callable, Sequence

from aegis.llm.base import ChatRequest, ChatResponse, LlmError, LlmErrorCode, Usage


class FakeProvider:
    """Replays a script of responses; raises a scripted error when asked to."""

    name = "fake"

    def __init__(
        self,
        responses: Sequence[str | LlmError] | None = None,
        *,
        default_response: str | None = None,
        clock: Callable[[], float] = time.time,
    ) -> None:
        self._responses = list(responses or [])
        self._default = default_response if default_response is not None else json.dumps({"findings": []})
        self._clock = clock
        self.calls: list[ChatRequest] = []

    def describe(self, model: str | None = None) -> str:
        del model
        return "fake/deterministic"

    def chat(self, request: ChatRequest) -> ChatResponse:
        self.calls.append(request)
        if not self._responses:
            return self._wrap(self._default)
        item = self._responses.pop(0)
        if isinstance(item, LlmError):
            raise item
        return self._wrap(item)

    def _wrap(self, text: str) -> ChatResponse:
        return ChatResponse(
            text=text,
            model="fake",
            usage=Usage(prompt_tokens=len(text) // 4, completion_tokens=len(text) // 4),
            schema_enforced=True,
            latency_ms=int(self._clock() * 0),
        )


class UnavailableProvider:
    """Always fails with a given code. Used to prove `fail_mode` behaviour."""

    name = "unavailable"

    def __init__(self, code: LlmErrorCode = LlmErrorCode.UNAVAILABLE, message: str = "down") -> None:
        self._code = code
        self._message = message

    def describe(self, model: str | None = None) -> str:
        del model
        return "unavailable"

    def chat(self, request: ChatRequest) -> ChatResponse:
        del request
        raise LlmError(self._code, self._message)


__all__ = ["FakeProvider", "UnavailableProvider"]
