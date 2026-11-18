"""Internal helpers shared by tokenid modules.

Nothing in this module performs network I/O.  It only contains small,
dependency-free parsing and time helpers used across classifiers/analyzers.
"""

from __future__ import annotations

import hashlib
import re
import time
from datetime import datetime, timezone
from typing import Any, Dict, Iterable, List, Optional, Tuple

MIN_PLAUSIBLE_UNIX = 631152000  # 1990-01-01T00:00:00Z
MAX_FUTURE_DAYS = 366
SECONDS_PER_DAY = 86400

_UNIX_EPOCH = datetime(1970, 1, 1, tzinfo=timezone.utc)

HEX_RE = re.compile(r"^[0-9a-fA-F]+$")
UUID_HYPHEN_RE = re.compile(
    r"^([0-9a-fA-F]{8})-([0-9a-fA-F]{4})-([0-9a-fA-F]{4})-"
    r"([0-9a-fA-F]{4})-([0-9a-fA-F]{12})$"
)
UUID_NODASH_RE = re.compile(r"^[0-9a-fA-F]{32}$")


def now_unix() -> float:
    return time.time()


def normalize_token(token: str) -> str:
    """Normalize a raw token for analysis without destroying the original.

    Callers must keep the untouched input separately.  Only surrounding
    whitespace is removed here; no URL/base64 padding is silently rewritten.
    """
    if not isinstance(token, str):
        raise TypeError("token must be a string")
    return token.strip()


def redact(token: str, keep: int = 4) -> str:
    """Return a short, non-reversible preview of a token.

    Short values are fully masked or expose only one character at each end so
    that a redacted report does not contain most of a small token.
    """
    if not token:
        return ""
    if keep < 1:
        keep = 1
    if len(token) <= keep * 2:
        return "*" * len(token)
    if len(token) <= keep * 3:
        edge = max(1, keep // 2)
        return "%s...%s" % (token[:edge], token[-edge:])
    return "%s...%s" % (token[:keep], token[-keep:])


def fingerprint(token: str) -> str:
    return hashlib.sha256(token.encode("utf-8", "surrogatepass")).hexdigest()[:16]


def format_unix(seconds: float) -> str:
    try:
        dt = datetime.fromtimestamp(float(seconds), tz=timezone.utc)
    except (OverflowError, OSError, ValueError):
        return "out-of-range"
    return dt.strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z"


def plausible_unix_seconds(
    seconds: float,
    now: Optional[float] = None,
    min_seconds: float = MIN_PLAUSIBLE_UNIX,
    max_future_days: int = MAX_FUTURE_DAYS,
) -> bool:
    if now is None:
        now = now_unix()
    return min_seconds <= seconds <= now + max_future_days * SECONDS_PER_DAY


def timestamp_interpretations(
    value: int, now: Optional[float] = None
) -> List[Dict[str, Any]]:
    """Interpret an integer as a Unix timestamp in common units.

    Returns only interpretations that land in a plausible window.  The caller
    must treat these as candidates, not proof.
    """
    units = (
        ("seconds", 1),
        ("milliseconds", 1_000),
        ("microseconds", 1_000_000),
        ("nanoseconds", 1_000_000_000),
    )
    out: List[Dict[str, Any]] = []
    if value < 0:
        return out
    for unit, factor in units:
        seconds = value / float(factor)
        if not plausible_unix_seconds(seconds, now=now):
            continue
        out.append(
            {
                "unit": unit,
                "seconds": int(seconds),
                "iso": format_unix(seconds),
                "value": value,
            }
        )
    return out


def best_timestamp_interpretation(
    value: int, now: Optional[float] = None
) -> Optional[Dict[str, Any]]:
    """Pick the most likely timestamp unit for an integer, if any.

    Preference order favours the unit whose digit count is conventional for
    that magnitude (seconds ~10 digits, ms ~13, us ~16, ns ~19).
    """
    interps = timestamp_interpretations(value, now=now)
    if not interps:
        return None
    digits = len(str(value))
    target = {"seconds": 10, "milliseconds": 13, "microseconds": 16, "nanoseconds": 19}
    return min(interps, key=lambda item: abs(target.get(item["unit"], 0) - digits))


def parse_uuid(token: str) -> Optional[Dict[str, Any]]:
    """Parse a hyphenated or 32-hex UUID into RFC 4122 fields."""
    s = token.strip()
    match = UUID_HYPHEN_RE.match(s)
    if match:
        groups = list(match.groups())
        hyphenated = True
    elif UUID_NODASH_RE.match(s):
        groups = [s[0:8], s[8:12], s[12:16], s[16:20], s[20:32]]
        hyphenated = False
    else:
        return None

    time_low = int(groups[0], 16)
    time_mid = int(groups[1], 16)
    time_hi_and_version = int(groups[2], 16)
    clock_seq = int(groups[3], 16)
    node = int(groups[4], 16)

    version = (time_hi_and_version >> 12) & 0xF
    variant_nibble = (clock_seq >> 12) & 0xF
    if (variant_nibble & 0xC) == 0x8:
        variant = "RFC4122"
        variant_valid = True
    elif (variant_nibble & 0xC) == 0xC:
        variant = "Microsoft/legacy"
        variant_valid = False
    elif (variant_nibble & 0x8) == 0x0:
        variant = "NCS/legacy"
        variant_valid = False
    else:
        variant = "future/reserved"
        variant_valid = False

    return {
        "groups": groups,
        "hyphenated": hyphenated,
        "time_low": time_low,
        "time_mid": time_mid,
        "time_hi_and_version": time_hi_and_version,
        "clock_seq": clock_seq,
        "node": node,
        "version": version,
        "variant": variant,
        "variant_valid": variant_valid,
        "node_is_random": bool(node & 0x010000000000),
        "node_mac": "-".join(
            "%02x" % ((node >> shift) & 0xFF) for shift in (40, 32, 24, 16, 8, 0)
        ),
    }


def uuid_v1_timestamp(fields: Dict[str, Any]) -> float:
    ts = (
        ((fields["time_hi_and_version"] & 0x0FFF) << 48)
        | (fields["time_mid"] << 32)
        | fields["time_low"]
    )
    return (ts - 0x01B21DD213814000) / 1e7


def uuid_v6_timestamp(fields: Dict[str, Any]) -> float:
    ts = (
        (fields["time_low"] << 28)
        | (fields["time_mid"] << 12)
        | (fields["time_hi_and_version"] & 0x0FFF)
    )
    return (ts - 0x01B21DD213814000) / 1e7


def uuid_v7_timestamp_ms(fields: Dict[str, Any]) -> int:
    return (fields["time_low"] << 16) | fields["time_mid"]


def decode_base_n(text: str, alphabet: str) -> Optional[int]:
    """Decode an unsigned integer from an arbitrary positional alphabet."""
    if not text:
        return None
    base = len(alphabet)
    if base < 2:
        return None
    index = {char: i for i, char in enumerate(alphabet)}
    value = 0
    for char in text:
        if char not in index:
            return None
        value = value * base + index[char]
    return value


def int_to_bytes(value: int, min_length: int = 1) -> bytes:
    if value < 0:
        raise ValueError("negative values are not supported")
    if value == 0:
        return b"\x00" * max(1, min_length)
    length = max(1, (value.bit_length() + 7) // 8, min_length)
    return value.to_bytes(length, "big")


def printable_ratio(data: bytes) -> float:
    """Fraction of decoded characters that are printable text."""
    if not data:
        return 0.0
    try:
        text = data.decode("utf-8")
    except UnicodeDecodeError:
        return 0.0
    if not text:
        return 0.0
    printable = sum(
        1 for char in text if char.isprintable() or char in ("\r", "\n", "\t")
    )
    return printable / float(len(text))


def looks_like_text(data: bytes, threshold: float = 0.85) -> bool:
    if b"\x00" in data:
        return False
    return printable_ratio(data) >= threshold


def text_preview(data: bytes, limit: int = 160) -> str:
    try:
        text = data.decode("utf-8")
    except UnicodeDecodeError:
        return "<%d bytes binary: %s>" % (
            len(data),
            data[:24].hex(),
        )
    if len(text) > limit:
        return text[:limit] + "..."
    return text


def safe_int(text: str) -> Optional[int]:
    try:
        return int(text, 10)
    except (TypeError, ValueError):
        return None


def chunk(iterable: Iterable[Any], size: int) -> Iterable[List[Any]]:
    bucket: List[Any] = []
    for item in iterable:
        bucket.append(item)
        if len(bucket) >= size:
            yield bucket
            bucket = []
    if bucket:
        yield bucket


def humanize_bytes(data: bytes) -> Tuple[int, str]:
    return len(data), data[:32].hex()
