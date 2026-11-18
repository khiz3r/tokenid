"""GraphQL Relay-style global IDs.

Two common forms are recognised:

* ``gid://shopify/Product/1234567890`` (Shopify global ID)
* ``base64("Type:raw-id")`` (Relay global ID, e.g. GitHub node IDs)

These are *encodings*, not encryption.  The underlying identifier is
recoverable by anyone who knows the convention.
"""

from __future__ import annotations

import base64
import binascii
import re
import urllib.parse
from typing import Any, Dict, List, Optional, Tuple

from ..._common import looks_like_text
from ...models import ClassifierContext, Confidence, TokenFinding
from ...registry import register

GID_RE = re.compile(r"^gid://([^/]+)/([^/]+)/(.+)$")
TYPE_ID_RE = re.compile(r"^([A-Za-z0-9_]{1,40}):([^\s:]+)$")


def _b64_variants(raw: str) -> List[Tuple[str, bytes]]:
    candidates: List[Tuple[str, bytes]] = []
    padded = raw + "=" * (-len(raw) % 4)
    try:
        standard = base64.b64decode(padded, validate=True)
    except (binascii.Error, ValueError):
        standard = None
    if standard and looks_like_text(standard):
        candidates.append(("base64", standard))

    url_alphabet = padded.replace("-", "+").replace("_", "/")
    try:
        urlsafe = base64.b64decode(url_alphabet, validate=True)
    except (binascii.Error, ValueError):
        urlsafe = None
    if urlsafe and looks_like_text(urlsafe) and urlsafe != standard:
        candidates.append(("base64url", urlsafe))
    return candidates


def _parse_gid(raw: str) -> Optional[Dict[str, Any]]:
    match = GID_RE.match(raw)
    if not match:
        return None
    platform, resource_type, raw_id = match.groups()
    return {
        "wrapper": "gid_uri",
        "scheme": "gid",
        "platform": urllib.parse.unquote(platform),
        "resource_type": urllib.parse.unquote(resource_type),
        "raw_id": urllib.parse.unquote(raw_id),
        "encoding": "plaintext URI",
    }


def _parse_wrapped(raw: str) -> Optional[Dict[str, Any]]:
    for encoding, decoded in _b64_variants(raw):
        try:
            text = decoded.decode("utf-8")
        except UnicodeDecodeError:
            continue
        nested = _parse_gid(text)
        if nested is not None:
            nested["wrapper"] = encoding + "(gid_uri)"
            return nested
        match = TYPE_ID_RE.match(text)
        if not match:
            continue
        resource_type, raw_id = match.groups()
        platform = "github_like" if resource_type.isdigit() else "unknown"
        return {
            "wrapper": encoding,
            "scheme": "relay_global_id",
            "platform": platform,
            "resource_type": resource_type,
            "raw_id": raw_id,
            "encoding": "base64-obfuscated",
        }
    return None


def _finding(parsed: Dict[str, Any], confidence: Confidence, reasons: List[str]) -> TokenFinding:
    return TokenFinding(
        token_type="relay_global_id",
        family="application",
        confidence=confidence,
        reasoning=reasons,
        properties={
            "wrapper": parsed["wrapper"],
            "scheme": parsed["scheme"],
            "platform": parsed["platform"],
            "resource_type": parsed["resource_type"],
            "raw_id": parsed["raw_id"],
            "encoding": parsed["encoding"],
            "is_plaintext": parsed["scheme"] == "gid",
            "is_obfuscated": parsed["scheme"] == "relay_global_id",
            "is_encrypted": False,
            "time_ordered": False,
            "contains_timestamp": False,
        },
    )


@register(
    "relay_style_id",
    "application",
    "GraphQL Relay global ID (gid:// URI or base64-wrapped Type:id)",
    order=100,
)
def classify(token: str, ctx: ClassifierContext) -> List[TokenFinding]:
    raw = token.strip()

    decoded_url = urllib.parse.unquote(raw)
    parsed = _parse_gid(decoded_url)
    if parsed is not None:
        confidence = Confidence.HIGH
        reasons = [
            "Matches the gid://platform/Type/id URI convention.",
            "The URI is plaintext; the identifier is encoded in the path, not encrypted.",
            "Resource type %r on platform %r is directly readable."
            % (parsed["resource_type"], parsed["platform"]),
        ]
        return [_finding(parsed, confidence, reasons)]

    parsed = _parse_wrapped(raw)
    if parsed is not None:
        letter_type = not parsed["resource_type"].isdigit()
        confidence = Confidence.HIGH if letter_type else Confidence.MEDIUM
        reasons = [
            "The token is base64-compatible and decodes to a printable 'Type:id' string.",
            "This matches Relay global IDs (for example GitHub node IDs), which are "
            "obfuscated rather than encrypted.",
            "Decoded resource type is %r." % parsed["resource_type"],
        ]
        return [_finding(parsed, confidence, reasons)]

    return []
