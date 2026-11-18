"""Hash-shaped token candidate detection.

This is deliberately *not* a secret scanner and does not try to prove a digest.
Length + charset is weak evidence: a random 128-bit value, an NTLM hash, and an
MD5 digest are indistinguishable offline.  The finding is therefore always one
candidate among others and never a sole conclusion.
"""

from __future__ import annotations

import re
from typing import Dict, List

from ..models import ClassifierContext, Confidence, TokenFinding
from ..registry import register

HEX_RE = re.compile(r"^[0-9a-fA-F]+$")

# length -> (canonical name, possible algorithms, digest bits)
HASH_SHAPES: Dict[int, Dict] = {
    32: {
        "name": "md5",
        "algorithms": ["MD5", "NTLM", "MD4", "128-bit hex value"],
        "bits": 128,
    },
    40: {
        "name": "sha1",
        "algorithms": ["SHA-1", "RIPEMD-160", "160-bit hex value"],
        "bits": 160,
    },
    56: {"name": "sha224", "algorithms": ["SHA-224", "224-bit hex value"], "bits": 224},
    64: {
        "name": "sha256",
        "algorithms": ["SHA-256", "SHA3-256", "BLAKE2s-256", "256-bit hex value"],
        "bits": 256,
    },
    96: {"name": "sha384", "algorithms": ["SHA-384", "384-bit hex value"], "bits": 384},
    128: {
        "name": "sha512",
        "algorithms": ["SHA-512", "SHA3-512", "BLAKE2b-512", "512-bit hex value"],
        "bits": 512,
    },
}


@register("hash_classifier", "hash", "Length/charset candidate for common hash digests", order=200)
def classify(token: str, ctx: ClassifierContext) -> List[TokenFinding]:
    raw = token.strip()
    shape = HASH_SHAPES.get(len(raw))
    if shape is None:
        return []
    if not HEX_RE.match(raw):
        return []

    return [
        TokenFinding(
            token_type=shape["name"],
            family="hash",
            confidence=Confidence.MEDIUM,
            reasoning=[
                "Length %d and a hexadecimal charset match the shape of %s."
                % (len(raw), shape["name"].upper()),
                "Content is not verified; other values of the same length are "
                "indistinguishable offline.",
                "Possible identities: %s." % ", ".join(shape["algorithms"]),
            ],
            properties={
                "length": len(raw),
                "charset": "hex",
                "digest_bits": shape["bits"],
                "possible_algorithms": shape["algorithms"],
                "content_verified": False,
                "contains_timestamp": False,
                "time_ordered": False,
            },
        )
    ]
