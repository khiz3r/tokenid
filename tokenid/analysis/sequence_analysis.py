"""Arithmetic sequence / counter detection, including inside encoded segments."""

from __future__ import annotations

import re
from typing import Any, Dict, Iterable, List, Optional, Sequence, Tuple

from .._common import decode_base_n
from ..models import Confidence, Segment, SequenceFinding

BASE36 = "0123456789abcdefghijklmnopqrstuvwxyz"
BASE62 = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"
HEX = set("0123456789abcdefABCDEF")
DIGITS_RE = re.compile(r"^[0-9]+$")


def classify_sequence(values: Sequence[int]) -> Dict[str, Any]:
    if len(values) < 2:
        return {
            "kind": "insufficient",
            "step": None,
            "deltas": [],
            "confidence": Confidence.LOW,
        }
    deltas = [b - a for a, b in zip(values, values[1:])]
    if all(delta == deltas[0] for delta in deltas):
        step = deltas[0]
        if step == 0:
            kind = "constant"
            confidence = Confidence.LOW
        elif abs(step) == 1:
            kind = "counter"
            confidence = Confidence.HIGH
        else:
            kind = "arithmetic"
            confidence = Confidence.MEDIUM
    elif all(delta > 0 for delta in deltas):
        kind = "monotonic_increasing"
        step = None
        confidence = Confidence.LOW
    elif all(delta < 0 for delta in deltas):
        kind = "monotonic_decreasing"
        step = None
        confidence = Confidence.LOW
    else:
        kind = "non_sequential"
        step = None
        confidence = Confidence.LOW
    return {
        "kind": kind,
        "step": step,
        "deltas": deltas,
        "confidence": confidence,
        "arithmetic": kind in ("counter", "arithmetic"),
    }


def _is_finding(kind: str) -> bool:
    return kind in ("counter", "arithmetic", "monotonic_increasing", "monotonic_decreasing")


def finding_from_sequence(
    values: Sequence[int],
    field: str,
    description_prefix: str = "",
    properties: Optional[Dict[str, Any]] = None,
) -> Optional[SequenceFinding]:
    info = classify_sequence(values)
    if not _is_finding(info["kind"]):
        return None
    if info["kind"] == "counter":
        description = "%s is a counter with step %+d in the supplied order." % (
            field,
            info["step"],
        )
    elif info["kind"] == "arithmetic":
        description = "%s changes by a constant step of %+d." % (field, info["step"])
    elif info["kind"] == "monotonic_increasing":
        description = "%s increases monotonically but not by a constant step." % field
    else:
        description = "%s decreases monotonically but not by a constant step." % field
    if description_prefix:
        description = description_prefix + description
    props = {
        "deltas": info["deltas"],
        "order_assumed": "input_order",
        "inside_encoding": False,
    }
    if properties:
        props.update(properties)
    return SequenceFinding(
        field=field,
        kind=info["kind"],
        values=list(values),
        step=info["step"],
        confidence=info["confidence"],
        description=description,
        properties=props,
    )


def _encoded_integers(values: Sequence[str]) -> List[Tuple[str, List[int]]]:
    """Try to decode every value with one consistent encoding."""
    attempts: List[Tuple[str, List[int]]] = []

    if all(value and all(char in HEX for char in value) and len(value) % 2 == 0 for value in values):
        try:
            attempts.append(("hex", [int(value, 16) for value in values]))
        except ValueError:
            pass

    if all(value and value.isalnum() for value in values):
        decoded36 = [decode_base_n(value.lower(), BASE36) for value in values]
        if all(item is not None for item in decoded36):
            attempts.append(("base36", [int(item) for item in decoded36]))  # type: ignore[arg-type]
        decoded62 = [decode_base_n(value, BASE62) for value in values]
        if all(item is not None for item in decoded62):
            attempts.append(("base62", [int(item) for item in decoded62]))  # type: ignore[arg-type]

    return attempts


def analyze_segments(segments: Iterable[Segment]) -> List[SequenceFinding]:
    findings: List[SequenceFinding] = []
    for segment in segments:
        values = segment.sample_values
        if len(values) < 2:
            continue
        field = "segment[%d:%d]" % (segment.start, segment.end)
        if values and all(DIGITS_RE.match(value) for value in values):
            finding = finding_from_sequence(
                [int(value) for value in values],
                field,
                properties={"source": "numeric_segment"},
            )
            if finding is not None:
                findings.append(finding)
            continue

        for encoding, integers in _encoded_integers(values):
            finding = finding_from_sequence(
                integers,
                field,
                description_prefix="After %s decoding, " % encoding,
                properties={"source": "encoded_segment", "inside_encoding": True, "encoding": encoding},
            )
            # Monotonic-but-not-arithmetic is too easy to hit by chance in a
            # random encoded segment; only report it for plain decimals.
            if finding is not None and finding.kind in ("counter", "arithmetic"):
                findings.append(finding)
                break
    return findings


def analyze_numeric_groups(groups: Iterable[Dict[str, Any]]) -> List[SequenceFinding]:
    findings: List[SequenceFinding] = []
    for group in groups:
        values = group.get("values") or []
        if len(values) < 2:
            continue
        field = group.get("field") or "numeric_group_%s" % group.get("index", "?")
        finding = finding_from_sequence(
            values,
            field,
            properties={"source": "numeric_group", "span": group.get("spans")},
        )
        if finding is not None:
            findings.append(finding)
    return findings


def analyze_all(
    segments: Iterable[Segment], numeric_groups: Iterable[Dict[str, Any]]
) -> List[SequenceFinding]:
    combined: List[SequenceFinding] = []
    seen = set()
    for finding in list(analyze_segments(segments)) + list(
        analyze_numeric_groups(numeric_groups)
    ):
        key = (finding.kind, finding.step, tuple(finding.values))
        if key in seen:
            continue
        seen.add(key)
        combined.append(finding)
    return combined
