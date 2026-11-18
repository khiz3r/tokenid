"""Evidence helpers.

The canonical :class:`Evidence` dataclass lives in :mod:`tokenid.models` so
that structural models do not depend on the prediction package.  It is
re-exported here for ``tokenid.prediction.evidence.Evidence``.
"""

from __future__ import annotations

from typing import Any, Dict

from ..models import Confidence, Evidence

__all__ = ["Evidence", "make_evidence"]


def make_evidence(
    description: str,
    confidence: Confidence = Confidence.MEDIUM,
    source: str = "unknown",
    details: Dict[str, Any] = None,
) -> Evidence:
    return Evidence(
        description=description,
        confidence=confidence,
        source=source,
        details=details or {},
    )
