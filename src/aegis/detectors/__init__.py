"""Deterministic pre-filter.

Runs before the LLM and independently of it. See :mod:`aegis.detectors.patterns`
for why this layer exists at all in a "GenAI" product: it is the floor the model
cannot lower.
"""

from __future__ import annotations

from aegis.detectors.patterns import (
    Anchor,
    AnchorKind,
    InjectionSignal,
    coverage,
    detect_injection_attempts,
    language_of,
    rules,
    scan,
    scan_line,
    should_skip,
)

__all__ = [
    "Anchor",
    "AnchorKind",
    "InjectionSignal",
    "coverage",
    "detect_injection_attempts",
    "language_of",
    "rules",
    "scan",
    "scan_line",
    "should_skip",
]
