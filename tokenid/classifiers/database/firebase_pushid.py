"""Firebase Realtime Database push IDs.

A push ID is 20 characters from Firebase's 64-character alphabet: the first
eight characters encode a 48-bit millisecond timestamp and the remaining
twelve encode 72 random bits.  Many samples created together share the same
timestamp prefix; that is useful structural evidence, not a vulnerability by
itself.
"""

from __future__ import annotations

from typing import Any, Dict, List

from ..._common import format_unix, now_unix, plausible_unix_seconds
from ...models import ClassifierContext, Confidence, TokenFinding
from ...registry import register

PUSH_CHARS = "-0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ_abcdefghijklmnopqrstuvwxyz"
INDEX = {char: i for i, char in enumerate(PUSH_CHARS)}


def decode_timestamp(raw: str) -> Any:
    if len(raw) < 8:
        return None
    value = 0
    for char in raw[:8]:
        if char not in INDEX:
            return None
        value = value * 64 + INDEX[char]
    return value


def _shared_windows(samples: List[str], own_ms: int) -> List[Dict[str, Any]]:
    windows: List[Dict[str, Any]] = []
    seen: Dict[int, int] = {}
    for sample in samples:
        if len(sample) != 20 or any(char not in INDEX for char in sample):
            continue
        ts = decode_timestamp(sample)
        if ts is None:
            continue
        seen[ts] = seen.get(ts, 0) + 1
    for ts, count in sorted(seen.items()):
        if count > 1:
            windows.append(
                {
                    "timestamp_unix_ms": ts,
                    "timestamp_iso": format_unix(ts / 1000.0),
                    "count": count,
                    "is_current": ts == own_ms,
                }
            )
    return windows


@register("firebase_pushid", "database", "Firebase push ID: 20 chars, 48-bit time + 72 random bits", order=90)
def classify(token: str, ctx: ClassifierContext) -> List[TokenFinding]:
    raw = token.strip()
    if len(raw) != 20:
        return []
    if any(char not in INDEX for char in raw):
        return []

    timestamp_ms = decode_timestamp(raw)
    if timestamp_ms is None:
        return []
    plausible = plausible_unix_seconds(timestamp_ms / 1000.0, now=now_unix())
    windows = _shared_windows(ctx.samples or [raw], timestamp_ms)

    reasons = [
        "20 characters and this exact 64-character alphabet match Firebase push IDs.",
        "The first eight characters decode to a 48-bit millisecond timestamp.",
        "The trailing twelve characters encode 72 nominally random bits.",
    ]
    if plausible:
        reasons.append("Decoded timestamp %s is plausible." % format_unix(timestamp_ms / 1000.0))
        confidence = Confidence.HIGH
    else:
        reasons.append(
            "Decoded timestamp %s is outside the plausible window; confidence reduced."
            % format_unix(timestamp_ms / 1000.0)
        )
        confidence = Confidence.MEDIUM
    if windows:
        reasons.append(
            "Multiple supplied samples share a timestamp window, which is "
            "consistent with a batch created by the same client."
        )

    return [
        TokenFinding(
            token_type="firebase_pushid",
            family="database",
            confidence=confidence,
            reasoning=reasons,
            properties={
                "contains_timestamp": True,
                "timestamp_unit": "milliseconds",
                "timestamp_unix_ms": timestamp_ms,
                "timestamp_iso": format_unix(timestamp_ms / 1000.0),
                "timestamp_plausible": plausible,
                "time_ordered": True,
                "random_bits": 72,
                "shared_timestamp_windows": windows,
            },
        )
    ]
