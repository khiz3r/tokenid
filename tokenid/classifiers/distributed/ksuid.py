"""KSUID: 27-character base62, 32-bit custom-epoch timestamp + 128-bit payload."""

from __future__ import annotations

from typing import List

from ..._common import (
    decode_base_n,
    format_unix,
    now_unix,
    plausible_unix_seconds,
)
from ...models import ClassifierContext, Confidence, TokenFinding
from ...registry import register

BASE62 = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"
KSUID_EPOCH = 1400000000  # 2014-05-13T16:53:20Z
MAX_VALUE = 1 << 160


@register("ksuid", "distributed", "KSUID: 27-char base62 with custom-epoch timestamp", order=60)
def classify(token: str, ctx: ClassifierContext) -> List[TokenFinding]:
    raw = token.strip()
    if len(raw) != 27:
        return []
    if any(char not in BASE62 for char in raw):
        return []

    value = decode_base_n(raw, BASE62)
    if value is None or value >= MAX_VALUE:
        return []

    ts_offset = value >> 128
    payload = value & ((1 << 128) - 1)
    unix_seconds = KSUID_EPOCH + ts_offset
    plausible = plausible_unix_seconds(unix_seconds, now=now_unix())

    reasons = [
        "27 characters all belong to the base62 alphabet used by KSUID.",
        "The decoded 160-bit value fits the KSUID 20-byte layout.",
        "The leading 32 bits are a timestamp offset from the KSUID epoch "
        "(2014-05-13T16:53:20Z).",
    ]
    if plausible:
        reasons.append("Decoded timestamp %s is in a plausible range." % format_unix(unix_seconds))
        confidence = Confidence.HIGH
    else:
        reasons.append(
            "Decoded timestamp %s is outside the plausible window; confidence reduced."
            % format_unix(unix_seconds)
        )
        confidence = Confidence.MEDIUM

    return [
        TokenFinding(
            token_type="ksuid",
            family="distributed",
            confidence=confidence,
            reasoning=reasons,
            properties={
                "alphabet": "base62",
                "length": 27,
                "contains_timestamp": True,
                "timestamp_unit": "seconds since custom epoch",
                "timestamp_unix": unix_seconds,
                "timestamp_iso": format_unix(unix_seconds),
                "timestamp_plausible": plausible,
                "epoch_unix": KSUID_EPOCH,
                "time_ordered": True,
                "payload_bits": 128,
                "payload_hex": "%032x" % payload,
            },
        )
    ]
