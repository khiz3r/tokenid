"""MongoDB ObjectId: 4-byte timestamp + 5-byte random + 3-byte counter."""

from __future__ import annotations

from typing import List

from ..._common import format_unix, now_unix, plausible_unix_seconds
from ...models import ClassifierContext, Confidence, TokenFinding
from ...registry import register

HEX = set("0123456789abcdefABCDEF")


@register("objectid", "database", "MongoDB ObjectId: 24 hex chars with embedded timestamp", order=80)
def classify(token: str, ctx: ClassifierContext) -> List[TokenFinding]:
    raw = token.strip()
    if len(raw) != 24 or any(char not in HEX for char in raw):
        return []

    timestamp = int(raw[0:8], 16)
    random_hex = raw[8:18]
    counter = int(raw[18:24], 16)
    plausible = plausible_unix_seconds(timestamp, now=now_unix())

    reasons = [
        "24 hexadecimal characters match the MongoDB ObjectId layout.",
        "The first four bytes decode to a Unix second timestamp.",
        "The next five bytes are typically a per-process random value and the "
        "last three bytes are a counter.",
    ]
    if plausible:
        reasons.append("Decoded timestamp %s is plausible." % format_unix(timestamp))
        confidence = Confidence.HIGH
    else:
        reasons.append(
            "Decoded timestamp %s is outside the plausible window; this may be "
            "24 random hex characters instead." % format_unix(timestamp)
        )
        confidence = Confidence.MEDIUM

    return [
        TokenFinding(
            token_type="objectid",
            family="database",
            confidence=confidence,
            reasoning=reasons,
            properties={
                "contains_timestamp": True,
                "timestamp_unit": "seconds",
                "timestamp_unix": timestamp,
                "timestamp_iso": format_unix(timestamp),
                "timestamp_plausible": plausible,
                "time_ordered": True,
                "random_hex": random_hex,
                "random_bits": 40,
                "counter": counter,
                "counter_bits": 24,
            },
        )
    ]
