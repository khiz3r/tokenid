"""Recursive encoding detection and decoding.

Safety limits are mandatory: decoding stops at ``max_depth``, refuses output
larger than ``max_bytes``, detects cycles, and never crashes on malformed input.
Decoding is not decryption; the report says so explicitly.
"""

from __future__ import annotations

import base64
import binascii
import re
import urllib.parse
from typing import Any, Dict, List, Optional, Set

from .._common import (
    HEX_RE,
    decode_base_n,
    int_to_bytes,
    looks_like_text,
    text_preview,
)
from ..models import (
    ClassifierContext,
    Confidence,
    DecodeResult,
    DecodeStep,
    TokenFinding,
)
from ..registry import register

MAX_DEPTH = 5
MAX_BYTES = 1024 * 1024

BASE32 = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567"
BASE58 = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
BASE36 = "0123456789abcdefghijklmnopqrstuvwxyz"
BASE62 = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"

BASE64_STD_RE = re.compile(r"^[A-Za-z0-9+/]+={0,2}$")
BASE64_URL_RE = re.compile(r"^[A-Za-z0-9_-]+={0,2}$")
BASE32_RE = re.compile(r"^[A-Z2-7]+=*$")
BASE58_RE = re.compile(r"^[1-9A-HJ-NP-Za-km-z]+$")
BASE36_RE = re.compile(r"^[0-9A-Za-z]+$")


def _b64_decode(text: str, urlsafe: bool) -> Optional[bytes]:
    padded = text + "=" * (-len(text) % 4)
    try:
        if urlsafe:
            return base64.urlsafe_b64decode(padded)
        return base64.b64decode(padded, validate=True)
    except (binascii.Error, ValueError):
        return None


def _b64_round_trip(data: bytes, text: str, urlsafe: bool) -> bool:
    if urlsafe:
        encoded = base64.urlsafe_b64encode(data).decode("ascii")
    else:
        encoded = base64.b64encode(data).decode("ascii")
    return encoded.rstrip("=") == text.rstrip("=")


def _decode_base_x(text: str, alphabet: str, preserve_leading_zeros: str = "") -> Optional[bytes]:
    value = decode_base_n(text, alphabet)
    if value is None:
        return None
    leading = 0
    if preserve_leading_zeros:
        for char in text:
            if char != preserve_leading_zeros:
                break
            leading += 1
    try:
        return b"\x00" * leading + int_to_bytes(value)
    except ValueError:
        return None


def _candidates(text: str) -> List[Dict[str, Any]]:
    """Return plausible decodings of *text*, most reliable first."""
    out: List[Dict[str, Any]] = []
    if not text:
        return out

    if "%" in text:
        unquoted = urllib.parse.unquote_to_bytes(text)
        if unquoted != text.encode("utf-8", "surrogatepass"):
            out.append(
                {
                    "encoding": "url",
                    "data": unquoted,
                    "printable": looks_like_text(unquoted),
                    "confidence": Confidence.HIGH,
                }
            )

    if len(text) >= 4 and len(text) % 2 == 0 and HEX_RE.match(text):
        data = bytes.fromhex(text)
        out.append(
            {
                "encoding": "hex",
                "data": data,
                "printable": looks_like_text(data),
                "confidence": Confidence.HIGH,
            }
        )

    if len(text) >= 8 and BASE64_STD_RE.match(text) and len(text.rstrip("=")) % 4 in (0, 2, 3):
        data = _b64_decode(text, urlsafe=False)
        if data is not None and _b64_round_trip(data, text, urlsafe=False):
            out.append(
                {
                    "encoding": "base64",
                    "data": data,
                    "printable": looks_like_text(data),
                    "confidence": Confidence.MEDIUM,
                }
            )

    if len(text) >= 8 and BASE64_URL_RE.match(text) and ("-" in text or "_" in text):
        data = _b64_decode(text, urlsafe=True)
        if data is not None and _b64_round_trip(data, text, urlsafe=True):
            out.append(
                {
                    "encoding": "base64url",
                    "data": data,
                    "printable": looks_like_text(data),
                    "confidence": Confidence.MEDIUM,
                }
            )

    upper = text.upper()
    stripped = upper.rstrip("=")
    if (
        len(stripped) >= 8
        and len(stripped) % 8 in (0, 2, 4, 5, 7)
        and BASE32_RE.match(upper)
    ):
        padded = stripped + "=" * (-len(stripped) % 8)
        try:
            data = base64.b32decode(padded)
        except (binascii.Error, ValueError):
            data = None
        if data is not None:
            out.append(
                {
                    "encoding": "base32",
                    "data": data,
                    "printable": looks_like_text(data),
                    "confidence": Confidence.MEDIUM,
                }
            )

    if len(text) >= 8 and BASE58_RE.match(text):
        data = _decode_base_x(text, BASE58, preserve_leading_zeros="1")
        if data is not None:
            out.append(
                {
                    "encoding": "base58",
                    "data": data,
                    "printable": looks_like_text(data),
                    "confidence": Confidence.LOW,
                }
            )

    if len(text) >= 8 and BASE36_RE.match(text) and any(char.isalpha() for char in text):
        data = _decode_base_x(text.lower(), BASE36)
        if data is not None:
            out.append(
                {
                    "encoding": "base36",
                    "data": data,
                    "printable": looks_like_text(data),
                    "confidence": Confidence.LOW,
                }
            )

    if len(text) >= 10 and BASE36_RE.match(text) and any(char.isalpha() for char in text):
        data = _decode_base_x(text, BASE62)
        if data is not None:
            out.append(
                {
                    "encoding": "base62",
                    "data": data,
                    "printable": looks_like_text(data),
                    "confidence": Confidence.LOW,
                }
            )

    # De-duplicate by (encoding, bytes) while preserving reliability order.
    seen = set()
    unique: List[Dict[str, Any]] = []
    for candidate in out:
        key = (candidate["encoding"], candidate["data"])
        if key in seen:
            continue
        seen.add(key)
        unique.append(candidate)
    return unique


def decode_chain(
    token: str,
    max_depth: int = MAX_DEPTH,
    max_bytes: int = MAX_BYTES,
    allow_binary: bool = False,
) -> DecodeResult:
    """Recursively decode a token, returning every step.

    ``allow_binary`` is used by the explicit ``decode`` command; analysis only
    follows decodings that produce text, which avoids treating raw hashes as an
    "encoding".
    """
    if max_depth < 1:
        max_depth = 1
    if max_bytes < 1:
        max_bytes = 1

    original = token or ""
    steps: List[DecodeStep] = []
    current = original
    seen: Set[str] = {original}
    cycle = False
    stopped = "no further encoding detected"
    depth = 0

    while depth < max_depth and current:
        choices = _candidates(current)
        text_choices = [c for c in choices if c["printable"]]
        choice = text_choices[0] if text_choices else None
        if choice is None and allow_binary and depth == 0:
            binary = [c for c in choices if c["encoding"] in ("hex", "base64", "base64url")]
            choice = binary[0] if binary else None
            if choice is not None:
                stopped = "binary output; recursion stopped"
        if choice is None:
            break

        data: bytes = choice["data"]
        truncated = False
        if len(data) > max_bytes:
            data = data[:max_bytes]
            truncated = True
            stopped = "decoded size limit reached"
        try:
            decoded_text = data.decode("utf-8")
        except UnicodeDecodeError:
            decoded_text = None

        steps.append(
            DecodeStep(
                encoding=choice["encoding"],
                input_preview=text_preview(current.encode("utf-8", "surrogatepass"), 120),
                output_preview=text_preview(data, 160),
                output_length=len(data),
                printable=choice["printable"],
                truncated=truncated,
            )
        )
        depth += 1

        if truncated or decoded_text is None:
            current = ""
            if not truncated:
                stopped = "non-text output; recursion stopped"
            break
        if decoded_text in seen:
            cycle = True
            stopped = "cycle detected"
            current = decoded_text
            break
        seen.add(decoded_text)
        current = decoded_text
        if not choice["printable"]:
            stopped = "non-text output; recursion stopped"
            break

    return DecodeResult(
        original=original,
        original_preview=text_preview(original.encode("utf-8", "surrogatepass"), 120),
        steps=steps,
        final_preview=text_preview(
            (current if current or steps else original).encode(
                "utf-8", "surrogatepass"
            ),
            200,
        ),
        stopped_reason=stopped,
        depth=depth,
        cycle_detected=cycle,
    )


@register("encoding_classifier", "encoding", "Recursive detection of common encodings", order=210)
def classify(token: str, ctx: ClassifierContext) -> List[TokenFinding]:
    result = decode_chain(token)
    if not result.steps:
        return []

    first = result.steps[0].encoding
    reasons = [
        "The token decodes as %s." % " -> ".join(result.encodings),
        "Decoding is reversible obfuscation, not encryption.",
    ]
    if result.cycle_detected:
        reasons.append("A decoding cycle was detected; recursion stopped safely.")
    if result.stopped_reason:
        reasons.append("Stopped: %s." % result.stopped_reason)

    return [
        TokenFinding(
            token_type=first,
            family="encoding",
            confidence=Confidence.HIGH if result.steps[-1].printable else Confidence.MEDIUM,
            reasoning=reasons,
            properties={
                "encodings": result.encodings,
                "depth": result.depth,
                "decoded_preview": result.final_preview,
                "cycle_detected": result.cycle_detected,
                "stop_reason": result.stopped_reason,
                "contains_timestamp": False,
                "time_ordered": False,
                "is_encryption": False,
            },
        )
    ]
