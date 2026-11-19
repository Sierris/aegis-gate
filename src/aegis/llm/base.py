"""Provider-agnostic LLM interface.

Why an interface at all, when there is only one production provider today:
the analysis engine must be testable without a network, without an API key and
without paying for tokens on every CI run. That is only possible if the engine
depends on this protocol instead of on HTTP.

The protocol is intentionally *narrow*: one shot, no tools, no streaming.

* **No tools.** A model with tools is a model that can act. The worst outcome of
  a successful prompt injection here must be a useless answer, never an action.
* **No streaming.** We need the complete JSON document before we can validate it;
  streaming would only create a half-parsed state that has no meaning for a
  commit gate.
* **No conversation state.** Each analysis is independent, so a poisoned previous
  turn cannot influence the next one. There is nothing to carry over.
"""

from __future__ import annotations

import enum
from dataclasses import dataclass, field
from typing import Protocol, runtime_checkable


class LlmErrorCode(enum.StrEnum):
    """Failure classes the engine reasons about, not just logs."""

    UNAVAILABLE = "unavailable"  # transport, DNS, timeout
    UNAUTHORIZED = "unauthorized"  # bad/missing key
    FORBIDDEN = "forbidden"  # plan/entitlement denies this model
    RATE_LIMITED = "rate_limited"
    BAD_REQUEST = "bad_request"  # schema or payload rejected by the provider
    MODEL_OUTPUT = "model_output"  # provider replied, but unusably
    TRUNCATED = "truncated"  # hit max_tokens, answer incomplete
    #: The configured model does not exist in the catalog. Distinct from
    #: ``BAD_REQUEST`` because it is a *deployment* mistake that must fail loudly
    #: instead of degrading to a default wire.
    UNKNOWN_MODEL = "unknown_model"


class LlmError(Exception):
    """Raised for every provider failure, with a machine-readable code."""

    def __init__(self, code: LlmErrorCode, message: str, *, model: str = "") -> None:
        super().__init__(message)
        self.code = code
        self.message = message
        self.model = model

    def __str__(self) -> str:
        return f"{self.code.value}: {self.message}" if self.message else self.code.value


@dataclass(frozen=True, slots=True)
class ChatMessage:
    role: str  # "system" | "user"
    content: str


@dataclass(frozen=True, slots=True)
class Usage:
    prompt_tokens: int = 0
    completion_tokens: int = 0
    reasoning_tokens: int = 0

    @property
    def total_tokens(self) -> int:
        return self.prompt_tokens + self.completion_tokens


@dataclass(frozen=True, slots=True)
class ChatRequest:
    """One analysis request."""

    messages: tuple[ChatMessage, ...]
    #: JSON Schema the answer must satisfy. Providers that support structured
    #: output get it as a hard constraint; the others get it described in the
    #: prompt and we validate the result ourselves (see ``validate.findings``).
    json_schema: dict[str, object] | None = None
    max_output_tokens: int = 4000
    temperature: float = 0.0
    #: Free-form tags for the provider (currently: model id override).
    model: str | None = None


@dataclass(frozen=True, slots=True)
class ChatResponse:
    text: str
    model: str
    usage: Usage = field(default_factory=Usage)
    #: True when the provider enforced the schema (structured output honoured).
    schema_enforced: bool = False
    finish_reason: str = "stop"
    latency_ms: int = 0
    #: Populated when the model emitted reasoning separately (some providers
    #: return an empty ``content`` with everything in a reasoning channel).
    had_reasoning: bool = False


@runtime_checkable
class LlmProvider(Protocol):
    """What the engine needs from a model provider."""

    name: str

    def chat(self, request: ChatRequest) -> ChatResponse:
        """Run one completion. Raises :class:`LlmError` on any failure."""
        ...

    def describe(self, model: str | None = None) -> str:
        """Human-readable description for ``AnalysisMeta.model``."""
        ...


__all__ = [
    "ChatMessage",
    "ChatRequest",
    "ChatResponse",
    "LlmError",
    "LlmErrorCode",
    "LlmProvider",
    "Usage",
]
