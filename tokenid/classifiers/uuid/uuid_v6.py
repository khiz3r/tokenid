"""UUID version 6 (reordered Gregorian timestamp)."""

from __future__ import annotations

from typing import List

from ..._common import (
    format_unix,
    now_unix,
    parse_uuid,
    plausible_unix_seconds,
    uuid_v6_timestamp,
)
from ...models import ClassifierContext, Confidence, TokenFinding
from ...registry import register


@register(
    "uuid_v6",
    "uuid",
    "UUID v6: most-significant-first 60-bit timestamp for sortable IDs",
    order=30,
)
def classify(token: str, ctx: ClassifierContext) -> List[TokenFinding]:
    fields = parse_uuid(token)
    if fields is None or fields["version"] != 6:
        return []

    timestamp = uuid_v6_timestamp(fields)
    plausible = plausible_unix_seconds(timestamp, now=now_unix())

    reasons = [
        "Version nibble is 6 and the field order matches UUID v6.",
        "v6 puts the high 32 timestamp bits first, so IDs sort "
        "lexicographically by creation time.",
        "A 60-bit timestamp is embedded in the leading fields.",
    ]
    if plausible:
        reasons.append("Decoded timestamp %s is in a plausible range." % format_unix(timestamp))
    else:
        reasons.append(
            "Decoded timestamp %s is not plausible; the token may be synthetic."
            % format_unix(timestamp)
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
            token_type="uuid_v6",
            family="uuid",
            confidence=confidence,
            reasoning=reasons,
            properties={
                "version": 6,
                "variant": fields["variant"],
                "variant_valid": fields["variant_valid"],
                "contains_timestamp": True,
                "timestamp_unit": "100ns since 1582-10-15",
                "timestamp_unix": timestamp,
                "timestamp_iso": format_unix(timestamp),
                "timestamp_plausible": plausible,
                "time_ordered": True,
                "clock_seq": fields["clock_seq"] & 0x3FFF,
                "node": fields["node_mac"],
                "node_is_random": fields["node_is_random"],
                "hyphenated": fields["hyphenated"],
            },
        )
    ]
