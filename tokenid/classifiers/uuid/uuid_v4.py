"""UUID version 4 (random)."""

from __future__ import annotations

from typing import List

from ..._common import parse_uuid
from ...models import ClassifierContext, Confidence, TokenFinding
from ...registry import register


@register(
    "uuid_v4",
    "uuid",
    "UUID v4: 122 random bits with version/variant nibbles",
    order=20,
)
def classify(token: str, ctx: ClassifierContext) -> List[TokenFinding]:
    fields = parse_uuid(token)
    if fields is None or fields["version"] != 4:
        return []

    reasons = [
        "Version nibble is 4 and the layout matches UUID v4.",
        "The variant field is %s." % fields["variant"],
        "The remaining 122 bits are nominally random; this says nothing about "
        "the generator's quality.",
    ]
    if fields["hyphenated"] and fields["variant_valid"]:
        confidence = Confidence.HIGH
    elif fields["variant_valid"]:
        confidence = Confidence.MEDIUM
        reasons.append("UUID is not hyphenated, so the shape is weaker evidence.")
    else:
        confidence = Confidence.LOW
        reasons.append("Variant bits are not RFC 4122; confidence reduced.")

    return [
        TokenFinding(
            token_type="uuid_v4",
            family="uuid",
            confidence=confidence,
            reasoning=reasons,
            properties={
                "version": 4,
                "variant": fields["variant"],
                "variant_valid": fields["variant_valid"],
                "contains_timestamp": False,
                "time_ordered": False,
                "random_bits": 122,
                "hyphenated": fields["hyphenated"],
            },
        )
    ]
