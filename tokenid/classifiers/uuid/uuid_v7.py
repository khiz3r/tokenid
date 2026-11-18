"""UUID version 7 (Unix millisecond timestamp)."""

from __future__ import annotations

from typing import List

from ..._common import (
    best_timestamp_interpretation,
    format_unix,
    now_unix,
    parse_uuid,
    uuid_v7_timestamp_ms,
)
from ...models import ClassifierContext, Confidence, TokenFinding
from ...registry import register


@register(
    "uuid_v7",
    "uuid",
    "UUID v7: 48-bit Unix millisecond timestamp prefix plus randomness",
    order=40,
)
def classify(token: str, ctx: ClassifierContext) -> List[TokenFinding]:
    fields = parse_uuid(token)
    if fields is None or fields["version"] != 7:
        return []

    timestamp_ms = uuid_v7_timestamp_ms(fields)
    interp = best_timestamp_interpretation(timestamp_ms, now=now_unix())
    plausible = interp is not None and interp["unit"] == "milliseconds"

    reasons = [
        "Version nibble is 7 and the field order matches UUID v7.",
        "The first 48 bits are a Unix millisecond timestamp, so IDs sort by "
        "creation time.",
    ]
    if plausible:
        reasons.append(
            "Decoded timestamp %s is in a plausible range." % format_unix(timestamp_ms / 1000.0)
        )
    else:
        reasons.append(
            "The leading 48 bits do not decode to a plausible millisecond "
            "timestamp; the token may be synthetic."
        )
    if not fields["variant_valid"]:
        reasons.append("Variant bits are not RFC 4122; confidence reduced.")

    if fields["hyphenated"] and fields["variant_valid"] and plausible:
        confidence = Confidence.HIGH
    elif fields["variant_valid"]:
        confidence = Confidence.MEDIUM
    else:
        confidence = Confidence.LOW

    return [
        TokenFinding(
            token_type="uuid_v7",
            family="uuid",
            confidence=confidence,
            reasoning=reasons,
            properties={
                "version": 7,
                "variant": fields["variant"],
                "variant_valid": fields["variant_valid"],
                "contains_timestamp": True,
                "timestamp_unit": "milliseconds",
                "timestamp_unix_ms": timestamp_ms,
                "timestamp_iso": format_unix(timestamp_ms / 1000.0),
                "timestamp_plausible": plausible,
                "time_ordered": True,
                "random_bits": 74,
                "hyphenated": fields["hyphenated"],
            },
        )
    ]
