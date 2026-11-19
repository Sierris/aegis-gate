"""LLM provider layer.

The engine only ever sees :class:`aegis.llm.base.LlmProvider`. Adding a provider
(OpenAI, Anthropic direct, a local Ollama) means writing one ``chat`` method — no
engine change, because everything security-relevant (schema, validation, policy)
lives outside this package on purpose: a provider must never be able to skip
validation by "returning a nicely shaped answer".
"""

from __future__ import annotations

from aegis.llm.base import (
    ChatMessage,
    ChatRequest,
    ChatResponse,
    LlmError,
    LlmErrorCode,
    LlmProvider,
    Usage,
)
from aegis.llm.commandcode import CommandCodeProvider, resolve_api_key
from aegis.llm.fake import FakeProvider, UnavailableProvider

__all__ = [
    "ChatMessage",
    "ChatRequest",
    "ChatResponse",
    "CommandCodeProvider",
    "FakeProvider",
    "LlmError",
    "LlmErrorCode",
    "LlmProvider",
    "UnavailableProvider",
    "Usage",
    "resolve_api_key",
]
