"""Name structural patterns discovered by :mod:`sample_compare`.

Pattern names are descriptive.  ``UNKNOWN_VARYING`` is used instead of
``RANDOM`` because variation is not proof of randomness; a caller may still
treat the varying part as unknown.
"""

from __future__ import annotations

from typing import List

from ..models import CompareResult, Confidence, Pattern

ROLE_NAMES = {
    "PREFIX": "PREFIX",
    "SUFFIX": "SUFFIX",
    "CONSTANT": "CONSTANT",
    "COUNTER": "COUNTER",
    "TIMESTAMP": "TIMESTAMP",
    "NUMBER": "NUMBER",
    "HEX": "UNKNOWN_VARYING",
    "ENCODED": "UNKNOWN_VARYING",
    "VARYING": "UNKNOWN_VARYING",
}


def detect_patterns(result: CompareResult) -> List[Pattern]:
    segments = result.all_segments
    patterns: List[Pattern] = []

    if not result.varying_segments:
        return [
            Pattern(
                name="CONSTANT",
                description="All supplied samples are identical; no varying region was found.",
                confidence=Confidence.HIGH if result.sample_count >= 2 else Confidence.LOW,
                segment_indexes=list(range(len(segments))),
            )
        ]

    names = [ROLE_NAMES.get(segment.role, segment.role) for segment in segments]
    whole_name = "+".join(names)
    has_counter = any(segment.kind == "counter" for segment in result.varying_segments)
    has_timestamp = any(segment.kind == "timestamp" for segment in result.varying_segments)
    only_unknown = all(
        segment.kind in ("unknown_varying", "absent_varying", "encoded_varying", "hex_varying")
        for segment in result.varying_segments
    )

    if has_counter:
        description = (
            "The samples differ by a consistent counter in the indicated region. "
            "A counter is a behavioural observation, not proof the server accepts "
            "guessed values."
        )
        confidence = Confidence.HIGH if result.sample_count >= 3 else Confidence.MEDIUM
    elif has_timestamp:
        description = (
            "A varying region decodes as a plausible timestamp.  This suggests "
            "time ordering, not full predictability."
        )
        confidence = Confidence.MEDIUM
    elif only_unknown:
        description = (
            "The samples share fixed structure but the varying region does not "
            "match a counter, timestamp, or known encoding.  It is left as "
            "UNKNOWN_VARYING rather than assumed random."
        )
        confidence = Confidence.LOW
    else:
        description = "Samples share a fixed structure with a partially classified varying region."
        confidence = Confidence.LOW

    patterns.append(
        Pattern(
            name=whole_name,
            description=description,
            confidence=confidence,
            segment_indexes=list(range(len(segments))),
            properties={
                "has_counter": has_counter,
                "has_timestamp": has_timestamp,
                "varying_is_assumed_random": False,
            },
        )
    )

    for index, segment in enumerate(segments):
        if segment.kind == "counter":
            step = segment.properties.get("step")
            patterns.append(
                Pattern(
                    name="COUNTER",
                    description="Segment at positions %d-%d increments by %s."
                    % (segment.start, segment.end, step),
                    confidence=Confidence.HIGH if step in (1, -1) else Confidence.MEDIUM,
                    segment_indexes=[index],
                    properties={"step": step, "segment_kind": segment.kind},
                )
            )
        elif segment.kind == "timestamp":
            timestamp = segment.properties.get("timestamp") or {}
            patterns.append(
                Pattern(
                    name="TIMESTAMP",
                    description="Segment at positions %d-%d is consistent with a %s timestamp."
                    % (segment.start, segment.end, timestamp.get("unit", "unknown")),
                    confidence=Confidence.MEDIUM,
                    segment_indexes=[index],
                    properties={
                        "unit": timestamp.get("unit"),
                        "monotonic_increasing": timestamp.get("monotonic_increasing"),
                    },
                )
            )
        elif segment.kind in ("hex_varying", "encoded_varying"):
            patterns.append(
                Pattern(
                    name="ENCODED_VARYING",
                    description="Segment at positions %d-%d uses a restricted character set; "
                    "it may encode a counter or random value." % (segment.start, segment.end),
                    confidence=Confidence.LOW,
                    segment_indexes=[index],
                    properties={"charset": segment.properties.get("charset")},
                )
            )

    return patterns
