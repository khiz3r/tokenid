"""Cross-sample correlation between segments and optional context values."""

from __future__ import annotations

from typing import Any, Dict, Iterable, List, Optional, Sequence, Tuple

from ..models import CorrelationFinding, Confidence, Segment

RESERVED_CONTEXT_KEYS = {
    "hash_algorithms",
    "hash_separators",
    "hash_templates",
    "hashids_salt",
    "hashid_salt",
    "hashids_alphabet",
    "hashids_min_length",
    "sqids_alphabet",
    "sqids_min_length",
    "salt",
}


def _deltas(values: Sequence[int]) -> List[int]:
    return [b - a for a, b in zip(values, values[1:])]


def _is_proportional(a: Sequence[int], b: Sequence[int]) -> Optional[float]:
    if len(a) != len(b) or not a:
        return None
    ratios = []
    for left, right in zip(a, b):
        if left == 0 and right == 0:
            continue
        if left == 0:
            return None
        ratios.append(right / float(left))
    if not ratios:
        return None
    first = ratios[0]
    if first == 0:
        return None
    if all(abs(ratio - first) < 1e-9 for ratio in ratios):
        return first
    return None


def _context_vectors(
    context: Dict[str, str], sample_count: int
) -> List[Tuple[str, List[str]]]:
    vectors: List[Tuple[str, List[str]]] = []
    for key, raw in (context or {}).items():
        if key in RESERVED_CONTEXT_KEYS:
            continue
        parts = [part.strip() for part in raw.split(",")]
        if len(parts) == sample_count and sample_count >= 2:
            vectors.append((key, parts))
        elif sample_count == 1:
            vectors.append((key, [raw]))
    return vectors


def find_correlations(
    numeric_groups: Iterable[Dict[str, Any]],
    segments: Iterable[Segment],
    context: Optional[Dict[str, str]] = None,
    sample_count: int = 0,
) -> List[CorrelationFinding]:
    groups = [group for group in numeric_groups if len(group.get("values") or []) >= 2]
    findings: List[CorrelationFinding] = []
    seen = set()

    for i in range(len(groups)):
        for j in range(i + 1, len(groups)):
            left, right = groups[i], groups[j]
            left_deltas = _deltas(left["values"])
            right_deltas = _deltas(right["values"])
            if not left_deltas or not right_deltas:
                continue
            if left_deltas == right_deltas and any(delta != 0 for delta in left_deltas):
                key = ("co_vary", left.get("field"), right.get("field"))
                if key not in seen:
                    seen.add(key)
                    findings.append(
                        CorrelationFinding(
                            field_a=left.get("field", "numeric_group"),
                            field_b=right.get("field", "numeric_group"),
                            kind="co_vary",
                            description="Two numeric regions change by the same deltas across samples.",
                            confidence=Confidence.HIGH,
                            properties={"deltas": left_deltas},
                        )
                    )
                continue
            ratio = _is_proportional(left_deltas, right_deltas)
            if ratio is not None and ratio != 1.0:
                key = ("proportional", left.get("field"), right.get("field"))
                if key not in seen:
                    seen.add(key)
                    findings.append(
                        CorrelationFinding(
                            field_a=left.get("field", "numeric_group"),
                            field_b=right.get("field", "numeric_group"),
                            kind="proportional",
                            description="Two numeric regions vary proportionally across samples.",
                            confidence=Confidence.MEDIUM,
                            properties={"ratio": ratio, "deltas_a": left_deltas, "deltas_b": right_deltas},
                        )
                    )

    vectors = _context_vectors(context or {}, sample_count)
    for key, parts in vectors:
        for group in groups:
            raw_values = [str(value) for value in group.get("values") or []]
            if raw_values == parts:
                dedupe = ("context", key, group.get("field"))
                if dedupe in seen:
                    continue
                seen.add(dedupe)
                findings.append(
                    CorrelationFinding(
                        field_a=key,
                        field_b=group.get("field", "numeric_group"),
                        kind="context_match",
                        description="A numeric region exactly matches the supplied --context "
                        "vector for %r." % key,
                        confidence=Confidence.HIGH,
                        properties={"context_key": key, "matched": True},
                    )
                )
        for segment in segments:
            if segment.sample_values and segment.sample_values == parts:
                dedupe = ("context_segment", key, segment.start, segment.end)
                if dedupe in seen:
                    continue
                seen.add(dedupe)
                findings.append(
                    CorrelationFinding(
                        field_a=key,
                        field_b="segment[%d:%d]" % (segment.start, segment.end),
                        kind="context_match",
                        description="A varying segment exactly matches the supplied --context "
                        "vector for %r." % key,
                        confidence=Confidence.HIGH,
                        properties={"context_key": key, "matched": True},
                    )
                )

    return findings
