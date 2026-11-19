"""Analysis engine: prompt assembly, caching, orchestration."""

from __future__ import annotations

from aegis.engine.analyzer import Analyzer, EngineDeps, build_analyzer, render_message
from aegis.engine.cache import AnalysisCache, cache_key, policy_fingerprint
from aegis.engine.fragments import (
    PreparedFragment,
    build_fragment,
    build_messages,
    fragments_from_content,
)
from aegis.engine.prompts import PromptBundle, load_bundle

__all__ = [
    "AnalysisCache",
    "Analyzer",
    "EngineDeps",
    "PreparedFragment",
    "PromptBundle",
    "build_analyzer",
    "build_fragment",
    "build_messages",
    "cache_key",
    "fragments_from_content",
    "load_bundle",
    "policy_fingerprint",
    "render_message",
]
