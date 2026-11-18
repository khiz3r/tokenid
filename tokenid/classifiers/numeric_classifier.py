"""Plain integer / decimal token detection."""

from __future__ import annotations

import re
from typing import List

from .._common import now_unix, timestamp_interpretations
from ..models import ClassifierContext, Confidence, TokenFinding
from ..registry import register

INT_RE = re.compile(r"^[+-]?[0-9]+$")
SMALL_INTEGER_LIMIT = 1_000_000


@register("numeric_classifier", "numeric", "Plain decimal integer and timestamp-shape checks", order=220)
def classify(token: str, ctx: ClassifierContext) -> List[TokenFinding]:
    raw = token.strip()
    if len(raw) > 40 or not INT_RE.match(raw):
        return []

    value = int(raw)
    interps = timestamp_interpretations(value, now=now_unix())
    units = [item["unit"] for item in interps]
    is_small = abs(value) <= SMALL_INTEGER_LIMIT

    reasons = ["The token is a plain decimal integer with %d digit(s)." % len(raw.lstrip("+-"))]
    if interps:
        best = interps[0]
        reasons.append(
            "Interpreted as %s it maps to %s, which is in a plausible recent range."
            % (best["unit"], best["iso"])
        )
        reasons.append(
            "This is a timestamp-shaped number, not proof that the field is a timestamp."
        )
    else:
        reasons.append("No common Unix timestamp unit produces a plausible recent value.")
    if is_small:
        reasons.append("The value is small enough to be a sequential record ID.")

    properties = {
        "value": value,
        "digits": len(raw.lstrip("+-")),
        "is_small_integer": is_small,
        "contains_timestamp": bool(interps),
        "time_ordered": bool(interps),
        "timestamp_interpretations": interps,
        "timestamp_units": units,
    }
    if interps:
        properties["timestamp_iso"] = interps[0]["iso"]

    confidence = Confidence.HIGH
    if not interps and len(raw.lstrip("+-")) < 3:
        confidence = Confidence.MEDIUM

    return [
        TokenFinding(
            token_type="numeric",
            family="numeric",
            confidence=confidence,
            reasoning=reasons,
            properties=properties,
        )
    ]
