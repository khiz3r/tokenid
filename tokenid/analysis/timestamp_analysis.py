"""Timestamp detection in decimals, hex, and base36."""

from __future__ import annotations

import re
from typing import Any, Dict, List, Optional

from .._common import (
    best_timestamp_interpretation,
    decode_base_n,
    format_unix,
    parse_uuid,
    timestamp_interpretations,
)
from ..models import Confidence, TimestampHit

DECIMAL_RUN_RE = re.compile(r"[0-9]{8,19}")
HEX_RUN_RE = re.compile(r"(?<![0-9A-Fa-f])([0-9A-Fa-f]{8,16})(?![0-9A-Fa-f])")
ALNUM_RE = re.compile(r"^[0-9A-Za-z]+$")
BASE36 = "0123456789abcdefghijklmnopqrstuvwxyz"


def _hit_from_interpretation(
    raw: str,
    value: int,
    encoding: str,
    position: Optional[tuple],
    confidence: Confidence,
) -> Optional[TimestampHit]:
    interp = best_timestamp_interpretation(value)
    if interp is None:
        return None
    return TimestampHit(
        raw=raw,
        value=value,
        unit=interp["unit"],
        encoding=encoding,
        timestamp_iso=interp["iso"],
        plausible=True,
        position=position,
        confidence=confidence,
        description="A %s value interpreted as %s maps to %s."
        % (encoding, interp["unit"], interp["iso"]),
    )


def detect_timestamps(
    text: str, now: Optional[float] = None, max_hits: int = 12
) -> List[TimestampHit]:
    """Find plausible embedded timestamps in a token.

    All hits are candidates.  A number being in a plausible range is not proof
    the field is a timestamp.
    """
    if not text:
        return []
    hits: List[TimestampHit] = []
    raw_token = text.strip()
    uuid_like = parse_uuid(raw_token) is not None
    # Long pure-hex values are hashes/ObjectIds; scanning their character runs
    # as decimals produces noise.  Other alphanumeric IDs may still embed a
    # decimal timestamp, so keep scanning those.
    hex_like = len(raw_token) >= 20 and all(
        char in "0123456789abcdefABCDEF" for char in raw_token
    )
    structured_token = uuid_like or hex_like

    if not structured_token:
        for match in DECIMAL_RUN_RE.finditer(text):
            raw = match.group(0)
            value = int(raw)
            hit = _hit_from_interpretation(
                raw, value, "decimal", (match.start(), match.end()), Confidence.MEDIUM
            )
            if hit is not None:
                hits.append(hit)
            if len(hits) >= max_hits:
                return hits

    if not uuid_like:
        for match in HEX_RUN_RE.finditer(text):
            raw = match.group(1)
            if raw.isdigit():
                continue
            value = int(raw, 16)
            interp = best_timestamp_interpretation(value, now=now)
            if interp is None:
                continue
            if interp["unit"] not in ("seconds", "milliseconds"):
                continue
            hits.append(
                TimestampHit(
                    raw=raw,
                    value=value,
                    unit=interp["unit"],
                    encoding="hex",
                    timestamp_iso=interp["iso"],
                    plausible=True,
                    position=(match.start(1), match.end(1)),
                    confidence=Confidence.LOW,
                    description="A hex value interpreted as %s maps to %s; this is "
                    "a weak timestamp candidate." % (interp["unit"], interp["iso"]),
                )
            )
            if len(hits) >= max_hits:
                return hits

    raw = text.strip()
    if 6 <= len(raw) <= 12 and ALNUM_RE.match(raw) and any(c.isalpha() for c in raw):
        value = decode_base_n(raw.lower(), BASE36)
        if value is not None:
            interp = best_timestamp_interpretation(value, now=now)
            if interp is not None and interp["unit"] in ("seconds", "milliseconds"):
                hits.append(
                    TimestampHit(
                        raw=raw,
                        value=value,
                        unit=interp["unit"],
                        encoding="base36",
                        timestamp_iso=interp["iso"],
                        plausible=True,
                        position=(0, len(raw)),
                        confidence=Confidence.LOW,
                        description="A base36 value interpreted as %s maps to %s; this "
                        "is a weak timestamp candidate."
                        % (interp["unit"], interp["iso"]),
                    )
                )

    # De-duplicate while preserving order.
    seen = set()
    unique: List[TimestampHit] = []
    for hit in hits:
        key = (hit.encoding, hit.raw, hit.value, hit.unit)
        if key in seen:
            continue
        seen.add(key)
        unique.append(hit)
    return unique[:max_hits]


def timestamp_for_sequence(
    values: List[int], field: str = "", now: Optional[float] = None
) -> Optional[Dict[str, Any]]:
    """Check whether a numeric sequence is consistent with a timestamp.

    Returns None unless every value has the same plausible unit.
    """
    if not values:
        return None
    shared_units: Optional[set] = None
    isos: List[str] = []
    for value in values:
        interp = best_timestamp_interpretation(value, now=now)
        if interp is None:
            return None
        current_units = {
            item["unit"] for item in timestamp_interpretations(value, now=now)
        }
        shared_units = current_units if shared_units is None else shared_units & current_units
        if not shared_units:
            return None
        isos.append(interp["iso"])
    if not shared_units:
        return None
    unit = sorted(shared_units)[0]
    monotonic = all(b >= a for a, b in zip(values, values[1:]))
    return {
        "field": field,
        "unit": unit,
        "values": values,
        "timestamps_iso": isos,
        "monotonic_increasing": monotonic,
        "first_iso": format_unix(values[0] / {"seconds": 1, "milliseconds": 1000,
                                              "microseconds": 1_000_000,
                                              "nanoseconds": 1_000_000_000}[unit]),
        "last_iso": format_unix(values[-1] / {"seconds": 1, "milliseconds": 1000,
                                              "microseconds": 1_000_000,
                                              "nanoseconds": 1_000_000_000}[unit]),
    }
