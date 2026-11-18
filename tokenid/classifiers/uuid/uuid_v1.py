"""UUID version 1 (Gregorian timestamp + clock sequence + node)."""

from __future__ import annotations

from typing import List

from ..._common import (
    format_unix,
    now_unix,
    parse_uuid,
    plausible_unix_seconds,
    uuid_v1_timestamp,
)
from ...models import ClassifierContext, Confidence, TokenFinding
from ...registry import register


@register(
    "uuid_v1",
    "uuid",
    "UUID v1: 60-bit timestamp, clock sequence, and 48-bit node identifier",
    order=10,
)
def classify(token: str, ctx: ClassifierContext) -> List[TokenFinding]:
    fields = parse_uuid(token)
    if fields is None or fields["version"] != 1:
        return []

    timestamp = uuid_v1_timestamp(fields)
    plausible = plausible_unix_seconds(timestamp, now=now_unix())

    reasons = [
        "Version nibble is 1 and the layout matches UUID v1.",
        "v1 stores a 60-bit 100-nanosecond timestamp since 1582-10-15.",
        "The node multicast bit is %s."
        % (
            "set, so it is likely random"
            if fields["node_is_random"]
            else "clear, so it looks like a MAC address"
        ),
    ]
    if plausible:
        reasons.append("Decoded timestamp %s is in a plausible range." % format_unix(timestamp))
    else:
        reasons.append(
            "Decoded timestamp %s is not plausible for a real v1 value; "
            "the token may be synthetic." % format_unix(timestamp)
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
            token_type="uuid_v1",
            family="uuid",
            confidence=confidence,
            reasoning=reasons,
            properties={
                "version": 1,
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
