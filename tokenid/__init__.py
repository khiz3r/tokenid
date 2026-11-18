"""tokenid: offline token/identifier classification and predictability analysis.

Public API::

    from tokenid import analyze, compare, decode

    result = analyze("550e8400-e29b-41d4-a716-446655440000")
    result.candidates
    result.entropy
    result.predictability

No network access is performed anywhere in this package.
"""

from __future__ import annotations

from .core import analyze, analyze_batch, compare, decode, inspect
from .models import (
    AnalysisResult,
    CompareResult,
    Confidence,
    DecodeResult,
    EntropyStats,
    Evidence,
    Predictability,
    TokenFinding,
)

__version__ = "0.1.0"

__all__ = [
    "analyze",
    "compare",
    "decode",
    "inspect",
    "analyze_batch",
    "AnalysisResult",
    "CompareResult",
    "Confidence",
    "DecodeResult",
    "EntropyStats",
    "Evidence",
    "Predictability",
    "TokenFinding",
    "__version__",
]
