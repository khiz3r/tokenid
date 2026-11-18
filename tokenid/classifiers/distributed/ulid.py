"""ULID: 26-character Crockford base32, 48-bit ms timestamp + 80 bits."""

from __future__ import annotations

from typing import List

from ..._common import (
    best_timestamp_interpretation,
    decode_base_n,
    format_unix,
    now_unix,
)
from ...models import ClassifierContext, Confidence, TokenFinding
from ...registry import register

CROCKFORD = "0123456789ABCDEFGHJKMNPQRSTVWXYZ"


@register("ulid", "distributed", "ULID: sortable 128-bit ID in Crockford base32", order=50)
def classify(token: str, ctx: ClassifierContext) -> List[TokenFinding]:
    raw = token.strip()
    canonical = raw.upper()
    if len(canonical) != 26:
        return []
    if any(char not in CROCKFORD for char in canonical):
        return []

    value = decode_base_n(canonical, CROCKFORD)
    if value is None or value >= (1 << 128):
        return []

    timestamp_ms = value >> 80
    randomness = value & ((1 << 80) - 1)
    interp = best_timestamp_interpretation(timestamp_ms, now=now_unix())
    plausible = interp is not None and interp["unit"] == "milliseconds"

    reasons = [
        "26 characters all belong to the Crockford base32 alphabet used by ULID.",
        "The 130-bit value fits in 128 bits, as required by ULID.",
        "The leading 48 bits decode to a millisecond timestamp %s."
        % format_unix(timestamp_ms / 1000.0),
    ]
    if not plausible:
        reasons.append(
            "That timestamp is outside the plausible window; the value may be "
            "synthetic or a different 26-character ID."
        )
    if raw != canonical:
        reasons.append("ULIDs are canonically uppercase; lowercase input is normalized for decoding.")

    if plausible and raw == canonical:
        confidence = Confidence.HIGH
    elif plausible:
        confidence = Confidence.MEDIUM
    else:
        confidence = Confidence.MEDIUM

    return [
        TokenFinding(
            token_type="ulid",
            family="distributed",
            confidence=confidence,
            reasoning=reasons,
            properties={
                "alphabet": "Crockford base32",
                "length": 26,
                "canonical_case": raw == canonical,
                "contains_timestamp": True,
                "timestamp_unit": "milliseconds",
                "timestamp_unix_ms": timestamp_ms,
                "timestamp_iso": format_unix(timestamp_ms / 1000.0),
                "timestamp_plausible": plausible,
                "time_ordered": True,
                "random_bits": 80,
                "randomness_hex": "%020x" % randomness,
            },
        )
    ]
