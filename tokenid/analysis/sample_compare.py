"""Cross-sample structural comparison.

The central rule is that a varying section is labelled ``unknown_varying``
until a concrete pattern (counter, timestamp, encoding) matches.  Varying is
never silently relabelled "random".
"""

from __future__ import annotations

import re
from typing import Any, Dict, List

from .._common import fingerprint
from ..models import CompareResult, Segment
from .sequence_analysis import classify_sequence
from .timestamp_analysis import timestamp_for_sequence

DIGITS_RE = re.compile(r"^[0-9]+$")
NUMERIC_RUN_RE = re.compile(r"[0-9]+")
HEX = set("0123456789abcdefABCDEF")
BASE64ISH = set("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=_-")


def _segment_analysis(values: List[str]) -> Dict[str, Any]:
    """Classify one varying slice across all samples."""
    non_empty = [value for value in values if value != ""]
    result: Dict[str, Any] = {
        "kind": "unknown_varying",
        "role": "UNKNOWN_VARYING",
        "properties": {},
    }
    if not non_empty:
        result["kind"] = "absent_varying"
        result["role"] = "UNKNOWN_VARYING"
        return result

    if all(DIGITS_RE.match(value) for value in non_empty) and len(non_empty) == len(values):
        integers = [int(value) for value in values]
        sequence = classify_sequence(integers)
        timestamp = timestamp_for_sequence(integers)
        properties: Dict[str, Any] = {
            "deltas": sequence["deltas"],
            "step": sequence["step"],
            "sequence_kind": sequence["kind"],
        }
        if timestamp is not None:
            properties["timestamp"] = timestamp
        if timestamp is not None:
            result.update(kind="timestamp", role="TIMESTAMP")
        elif sequence["arithmetic"]:
            result.update(kind="counter", role="COUNTER")
        else:
            result.update(kind="numeric_varying", role="NUMBER")
        result["properties"] = properties
        return result

    if all(len(value) == len(non_empty[0]) for value in non_empty):
        chars = set("".join(non_empty))
        if chars <= HEX:
            result.update(kind="hex_varying", role="UNKNOWN_VARYING")
            result["properties"] = {"charset": "hex"}
        elif chars <= BASE64ISH:
            result.update(kind="encoded_varying", role="UNKNOWN_VARYING")
            result["properties"] = {"charset": "alphanumeric/base64-ish"}
    return result


def _build_segments(samples: List[str]) -> List[Segment]:
    min_len = min(len(sample) for sample in samples)
    max_len = max(len(sample) for sample in samples)

    kinds: List[str] = []
    for index in range(min_len):
        first = samples[0][index]
        kinds.append("fixed" if all(sample[index] == first for sample in samples) else "varying")
    kinds.extend(["varying"] * (max_len - min_len))

    runs: List[tuple] = []
    if not kinds:
        return []
    start = 0
    current = kinds[0]
    for index in range(1, len(kinds)):
        if kinds[index] != current:
            runs.append((current, start, index))
            start = index
            current = kinds[index]
    runs.append((current, start, len(kinds)))

    segments: List[Segment] = []
    for kind, start, end in runs:
        if kind == "fixed":
            value = samples[0][start:end]
            segments.append(
                Segment(
                    kind="fixed",
                    role="PREFIX" if start == 0 else "CONSTANT",
                    start=start,
                    end=end,
                    length=end - start,
                    common_value=value,
                    description="Fixed segment at positions %d-%d." % (start, end),
                )
            )
        else:
            values = [sample[start:end] for sample in samples]
            analysis = _segment_analysis(values)
            segments.append(
                Segment(
                    kind=analysis["kind"],
                    role=analysis["role"],
                    start=start,
                    end=end,
                    length=end - start,
                    sample_values=values,
                    description="Varying positions %d-%d classified as %s."
                    % (start, end, analysis["kind"]),
                    properties=analysis["properties"],
                )
            )
    return segments


def _inside_opaque_segment(
    start: int, end: int, segments: List[Segment]
) -> bool:
    for segment in segments:
        if segment.kind in ("hex_varying", "encoded_varying") and segment.start <= start and end <= segment.end:
            return True
    return False


def _numeric_groups(
    samples: List[str], segments: List[Segment]
) -> List[Dict[str, Any]]:
    matches_per_sample = [list(NUMERIC_RUN_RE.finditer(sample)) for sample in samples]
    counts = {len(matches) for matches in matches_per_sample}
    if len(samples) < 2 or len(counts) != 1:
        return []

    groups: List[Dict[str, Any]] = []
    for index in range(len(matches_per_sample[0])):
        matches = [sample_matches[index] for sample_matches in matches_per_sample]
        if any(
            _inside_opaque_segment(match.start(), match.end(), segments)
            for match in matches
        ):
            continue
        raw_values = [match.group(0) for match in matches]
        values = [int(raw) for raw in raw_values]
        sequence = classify_sequence(values)
        timestamp = timestamp_for_sequence(values, field="numeric_group[%d]" % index)
        groups.append(
            {
                "index": index,
                "field": "numeric_group[%d]" % index,
                "values": values,
                "raw_values": raw_values,
                "spans": [[match.start(), match.end()] for match in matches],
                "sequence_kind": sequence["kind"],
                "deltas": sequence["deltas"],
                "step": sequence["step"],
                "timestamp": timestamp,
            }
        )
    return groups


def compare_samples(samples: List[str]) -> CompareResult:
    samples = [sample if isinstance(sample, str) else str(sample) for sample in samples]
    if not samples:
        raise ValueError("compare requires at least one sample")

    lengths = [len(sample) for sample in samples]
    segments = _build_segments(samples)
    varying = [segment for segment in segments if segment.kind != "fixed"]
    fixed = [segment for segment in segments if segment.kind == "fixed"]

    if not varying:
        structure = "CONSTANT"
        for segment in fixed:
            segment.role = "CONSTANT"
    else:
        max_len = max(lengths)
        for segment in fixed:
            if segment.start == 0:
                segment.role = "PREFIX"
            elif segment.end == max_len:
                segment.role = "SUFFIX"
            else:
                segment.role = "CONSTANT"
        structure = " + ".join(segment.role for segment in segments)

    numeric_groups = _numeric_groups(samples, segments)

    notes = [
        "Varying sections are treated as unknown until a concrete pattern matches.",
        "Sequence direction assumes the samples are supplied in the order of interest.",
    ]
    if len(set(lengths)) > 1:
        notes.append("Samples have different lengths; comparison uses the shortest common prefix and marks the remainder as varying.")
    if len(samples) < 3:
        notes.append("Fewer than three samples limits pattern confidence.")

    return CompareResult(
        sample_count=len(samples),
        lengths=lengths,
        structure=structure,
        fixed_segments=fixed,
        varying_segments=varying,
        all_segments=segments,
        numeric_groups=numeric_groups,
        notes=notes,
        sample_fingerprints=[fingerprint(sample) for sample in samples],
        samples=list(samples),
    )
