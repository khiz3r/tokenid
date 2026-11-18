"""CUID / CUID2 detection.

CUID v1 (``c`` + base36 timestamp + counter + fingerprint + random) is
time-ordered.  CUID2 is hash-based and not time-ordered, despite sharing the
``c``-looking prefix family.  Shape alone cannot prove which generator was
used, so both are reported as candidates.
"""

from __future__ import annotations

import re
from typing import List

from ..._common import (
    decode_base_n,
    format_unix,
    now_unix,
    plausible_unix_seconds,
)
from ...models import ClassifierContext, Confidence, TokenFinding
from ...registry import register

BASE36 = "0123456789abcdefghijklmnopqrstuvwxyz"
CUID1_RE = re.compile(r"^c[0-9a-z]{24}$")
CUID2_RE = re.compile(r"^[a-z][a-z0-9]{11,31}$")


def _cuid2_shape(raw: str) -> bool:
    if not CUID2_RE.match(raw):
        return False
    if not any(char.isdigit() for char in raw):
        return False
    if CUID1_RE.match(raw):
        return False
    return True


@register("cuid", "short_id", "CUID v1 (time-ordered) and CUID2 (hash-based)", order=110)
def classify(token: str, ctx: ClassifierContext) -> List[TokenFinding]:
    raw = token.strip()
    findings: List[TokenFinding] = []

    if CUID1_RE.match(raw):
        timestamp_ms = decode_base_n(raw[1:9], BASE36)
        plausible = False
        if timestamp_ms is not None:
            plausible = plausible_unix_seconds(timestamp_ms / 1000.0, now=now_unix())
        reasons = [
            "Starts with 'c' and matches the 25-character CUID v1 shape.",
            "CUID v1 reserves the first character as a literal 'c'.",
            "Characters 1-8 is a base36 millisecond timestamp in the reference layout.",
        ]
        if plausible:
            reasons.append("Decoded timestamp %s is plausible." % format_unix(timestamp_ms / 1000.0))
            confidence = Confidence.HIGH
        else:
            reasons.append(
                "The timestamp segment did not decode plausibly; this may be a "
                "different 25-character identifier."
            )
            confidence = Confidence.MEDIUM
        findings.append(
            TokenFinding(
                token_type="cuid_v1",
                family="short_id",
                confidence=confidence,
                reasoning=reasons,
                properties={
                    "variant": "cuid1",
                    "length": 25,
                    "contains_timestamp": plausible,
                    "timestamp_unit": "milliseconds",
                    "timestamp_unix_ms": timestamp_ms,
                    "time_ordered": True,
                    "random_bits_estimate": 32,
                },
            )
        )

    if _cuid2_shape(raw):
        is_default_length = len(raw) == 24
        reasons = [
            "Lowercase alphanumeric token beginning with a letter, consistent "
            "with CUID2 (default length 24).",
            "CUID2 is hash-based rather than time-ordered.",
        ]
        if not is_default_length:
            reasons.append(
                "Length %d is not the CUID2 default; confidence reduced." % len(raw)
            )
        findings.append(
            TokenFinding(
                token_type="cuid2",
                family="short_id",
                confidence=Confidence.MEDIUM if is_default_length else Confidence.LOW,
                reasoning=reasons,
                properties={
                    "variant": "cuid2",
                    "length": len(raw),
                    "contains_timestamp": False,
                    "time_ordered": False,
                },
            )
        )

    return findings
