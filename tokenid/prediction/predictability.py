"""Predictability verdicts.

This module owns every security-flavoured statement.  Classifiers and
analyzers only report structure.  A verdict always carries the disclaimer that
a detected pattern is evidence, not proof that the server accepts guesses.
"""

from __future__ import annotations

from typing import Any, Dict, Iterable, List, Optional

from ..models import (
    AnalysisResult,
    CompareResult,
    Confidence,
    EntropyStats,
    HashMatch,
    Predictability,
    TimestampHit,
    TokenFinding,
)
from .evidence import make_evidence

DISCLAIMER = (
    "A detected pattern is evidence, not proof that the server accepts guessed "
    "values. A predictable-looking token is only a security concern if it is "
    "used as an authorization secret and the server fails to validate access."
)

TIME_ORDERED_TYPES = {
    "uuid_v1",
    "uuid_v6",
    "uuid_v7",
    "ulid",
    "ksuid",
    "snowflake",
    "objectid",
    "firebase_pushid",
    "cuid_v1",
}

RANDOM_OR_HASH_TYPES = {
    "uuid_v4",
    "cuid2",
    "md5",
    "sha1",
    "sha224",
    "sha256",
    "sha384",
    "sha512",
}


def _level_for_score(score: int) -> Confidence:
    if score >= 4:
        return Confidence.HIGH
    if score >= 2:
        return Confidence.MEDIUM
    return Confidence.LOW


def _rationale(level: Confidence, evidence: List[Any], structure: str = "") -> str:
    if not evidence:
        return "Insufficient evidence to claim the generation is guessable."
    strongest = sorted(
        evidence, key=lambda item: item.confidence.rank, reverse=True
    )[:3]
    summary = " ".join(item.description for item in strongest)
    prefix = "Structure: %s. " % structure if structure else ""
    return (
        "%sPredictability is %s. %s This verdict describes generation structure "
        "only; it does not establish that guessed values are accepted."
        % (prefix, level.value, summary)
    )


def assess_single(
    findings: Iterable[TokenFinding],
    timestamps: Iterable[TimestampHit],
    entropy: Optional[EntropyStats] = None,
    decoded: Any = None,
    hash_matches: Iterable[HashMatch] = (),
    context: Optional[Dict[str, str]] = None,
) -> Predictability:
    findings = list(findings)
    timestamps = [hit for hit in timestamps if hit.plausible]
    hash_matches = [match for match in hash_matches if match.matched]
    evidence = []
    score = 0

    time_ordered = [f for f in findings if f.properties.get("time_ordered")]
    random_like = [
        f
        for f in findings
        if f.token_type in RANDOM_OR_HASH_TYPES
        or (f.properties.get("random_bits") and not f.properties.get("time_ordered"))
    ]
    numeric = [f for f in findings if f.token_type == "numeric"]

    time_ordered_by_type: Dict[str, List[TokenFinding]] = {}
    for finding in time_ordered:
        if finding.token_type == "numeric":
            continue  # handled once by the numeric branch below
        time_ordered_by_type.setdefault(finding.token_type, []).append(finding)

    for token_type, group in time_ordered_by_type.items():
        finding = group[0]
        timestamp_iso = finding.properties.get("timestamp_iso", "unknown time")
        suffix = (
            " (%d epoch interpretations)" % len(group)
            if len(group) > 1
            else ""
        )
        evidence.append(
            make_evidence(
                "Classifier %r reports a time-ordered layout with an embedded "
                "timestamp (%s)%s."
                % (token_type, timestamp_iso, suffix),
                confidence=finding.confidence,
                source="classifier:%s" % (finding.classifier or token_type),
                details={
                    "token_type": token_type,
                    "timestamp_iso": timestamp_iso,
                    "time_ordered": True,
                    "epoch_interpretations": len(group),
                },
            )
        )
        score += (
            2
            if finding.confidence == Confidence.HIGH
            or finding.properties.get("timestamp_plausible")
            else 1
        )
        if (
            finding.token_type == "uuid_v1"
            and finding.properties.get("timestamp_plausible")
            and not finding.properties.get("node_is_random")
        ):
            evidence.append(
                make_evidence(
                    "UUID v1 uses a MAC-style node and a clock sequence, both of "
                    "which can reduce the guessing space when observed together.",
                    confidence=Confidence.MEDIUM,
                    source="classifier:uuid_v1",
                )
            )
            score += 2

    for hit in timestamps:
        if any(
            finding.properties.get("timestamp_iso") == hit.timestamp_iso
            for finding in time_ordered
        ):
            continue
        evidence.append(
            make_evidence(
                "A plausible %s timestamp was detected (%s) as %s."
                % (hit.unit, hit.timestamp_iso, hit.encoding),
                confidence=hit.confidence,
                source="timestamp_analysis",
                details={"unit": hit.unit, "iso": hit.timestamp_iso},
            )
        )
        if hit.confidence == Confidence.LOW:
            score += 1
        else:
            score += 2 if hit.unit in ("seconds", "milliseconds") else 1

    for match in hash_matches:
        evidence.append(
            make_evidence(
                "Token exactly matches %s, a construction derived from supplied "
                "context values." % match.redacted_construction,
                confidence=Confidence.HIGH,
                source="hash_guess",
                details={"algorithm": match.algorithm, "context_keys": match.context_keys},
            )
        )
        score += 4

    if numeric:
        finding = numeric[0]
        if finding.properties.get("timestamp_units"):
            evidence.append(
                make_evidence(
                    "The token is a plain integer in a plausible timestamp range; "
                    "nearby timestamps are cheap to enumerate if this field is used "
                    "as a secret.",
                    confidence=Confidence.MEDIUM,
                    source="classifier:numeric_classifier",
                )
            )
            score += 2
        elif finding.properties.get("is_small_integer"):
            digits = int(finding.properties.get("digits") or len(str(finding.properties.get("value", ""))))
            evidence.append(
                make_evidence(
                    "The token is a small integer, so a brute-force or enumeration "
                    "attempt would cover a modest keyspace.",
                    confidence=Confidence.HIGH if digits <= 4 else Confidence.MEDIUM,
                    source="classifier:numeric_classifier",
                )
            )
            score += 4 if digits <= 4 else 2

    if decoded is not None and getattr(decoded, "steps", None):
        evidence.append(
            make_evidence(
                "The token is encoded (%s); encoding is reversible and is not "
                "encryption." % " -> ".join(decoded.encodings),
                confidence=Confidence.LOW,
                source="encoding_classifier",
            )
        )

    relay = [f for f in findings if f.token_type == "relay_global_id"]
    for finding in relay:
        evidence.append(
            make_evidence(
                "The Relay-style wrapper only obfuscates the underlying identifier; "
                "the raw ID is recoverable without a key.",
                confidence=Confidence.LOW,
                source="classifier:relay_style_id",
                details={
                    "wrapper": finding.properties.get("wrapper"),
                    "resource_type": finding.properties.get("resource_type"),
                },
            )
        )

    for finding in random_like:
        if finding.family == "hash" and (hash_matches or time_ordered):
            continue
        evidence.append(
            make_evidence(
                "Candidate %r is consistent with a random or hash-based generator; "
                "no time ordering was identified for it." % finding.token_type,
                confidence=Confidence.LOW,
                source="classifier:%s" % (finding.classifier or finding.token_type),
            )
        )
        score -= 1

    if entropy is not None:
        if entropy.length and entropy.length < 8:
            evidence.append(
                make_evidence(
                    "The token is very short (%d characters), which limits the "
                    "available keyspace." % entropy.length,
                    confidence=Confidence.MEDIUM,
                    source="entropy",
                )
            )
            score += 1
        if entropy.unique_chars <= 1 and entropy.length > 0:
            evidence.append(
                make_evidence(
                    "The token has only one distinct character, suggesting a "
                    "placeholder or fixed value rather than a random secret.",
                    confidence=Confidence.MEDIUM,
                    source="entropy",
                )
            )
            score += 1

    score = max(score, 0)
    level = _level_for_score(score)
    if hash_matches:
        level = Confidence.HIGH
    if not evidence:
        evidence.append(
            make_evidence(
                "No timestamp, counter, hash match, or time-ordered structure was found.",
                confidence=Confidence.LOW,
                source="predictability",
            )
        )
        level = Confidence.LOW

    return Predictability(
        level=level,
        evidence=evidence,
        rationale=_rationale(level, evidence),
        disclaimer=DISCLAIMER,
    )


def assess_compare(result: CompareResult) -> Predictability:
    evidence = []
    score = 0

    matched_hashes = [match for match in result.hash_matches if match.matched]
    if result.sample_count < 2 or not result.varying_segments:
        if matched_hashes:
            for match in matched_hashes:
                evidence.append(
                    make_evidence(
                        "A sample exactly matches %s, a construction derived from "
                        "supplied context values." % match.redacted_construction,
                        confidence=Confidence.HIGH,
                        source="hash_guess",
                        details={
                            "algorithm": match.algorithm,
                            "context_keys": match.context_keys,
                        },
                    )
                )
            return Predictability(
                level=Confidence.HIGH,
                evidence=evidence,
                rationale=_rationale(Confidence.HIGH, evidence, result.structure),
                disclaimer=DISCLAIMER,
            )
        evidence.append(
            make_evidence(
                "No variation was found across the supplied samples.",
                confidence=Confidence.LOW,
                source="sample_compare",
            )
        )
        return Predictability(
            level=Confidence.LOW,
            evidence=evidence,
            rationale=_rationale(Confidence.LOW, evidence, result.structure),
            disclaimer=DISCLAIMER,
        )

    timestamp_ranges = [
        (segment.start, segment.end)
        for segment in result.varying_segments
        if segment.kind == "timestamp"
    ]
    timestamp_fields = {
        "segment[%d:%d]" % (start, end) for start, end in timestamp_ranges
    }
    timestamp_groups = []
    for group in result.numeric_groups:
        if not group.get("timestamp"):
            continue
        values = group.get("values") or []
        if len(set(values)) <= 1:
            continue
        spans = group.get("spans") or []
        if spans:
            timestamp_ranges.extend((span[0], span[1]) for span in spans)
        timestamp_fields.add(group.get("field"))
        timestamp_groups.append(group)

    def _inside_timestamp(field: str) -> bool:
        if field in timestamp_fields:
            return True
        if field.startswith("segment[") and field.endswith("]"):
            try:
                start, end = field[8:-1].split(":")
                start_i, end_i = int(start), int(end)
            except (TypeError, ValueError):
                return False
            return any(
                begin <= start_i and end_i <= finish
                for begin, finish in timestamp_ranges
            )
        return False

    for finding in result.sequence_findings:
        if _inside_timestamp(finding.field):
            continue
        if finding.kind == "counter" and finding.step in (1, -1):
            evidence.append(
                make_evidence(
                    "%s is a step-%+d counter." % (finding.field, finding.step),
                    confidence=Confidence.HIGH,
                    source="sequence_analysis",
                    details={"field": finding.field, "step": finding.step},
                )
            )
            score += 4
        elif finding.kind == "counter":
            evidence.append(
                make_evidence(
                    "%s advances by a constant step of %+d." % (finding.field, finding.step),
                    confidence=Confidence.MEDIUM,
                    source="sequence_analysis",
                )
            )
            score += 3
        elif finding.kind == "arithmetic":
            evidence.append(
                make_evidence(
                    "%s changes arithmetically with step %s."
                    % (finding.field, finding.step),
                    confidence=Confidence.MEDIUM,
                    source="sequence_analysis",
                )
            )
            score += 3
        elif finding.kind in ("monotonic_increasing", "monotonic_decreasing"):
            evidence.append(
                make_evidence(
                    "%s is monotonic in the supplied order." % finding.field,
                    confidence=Confidence.LOW,
                    source="sequence_analysis",
                )
            )
            score += 1

    seen_timestamp_keys = set()
    for segment in result.varying_segments:
        if segment.kind == "timestamp":
            timestamp = segment.properties.get("timestamp") or {}
            key = (
                timestamp.get("unit"),
                timestamp.get("first_iso"),
                timestamp.get("last_iso"),
            )
            if key in seen_timestamp_keys:
                continue
            seen_timestamp_keys.add(key)
            evidence.append(
                make_evidence(
                    "Segment %d-%d is consistent with a %s timestamp%s."
                    % (
                        segment.start,
                        segment.end,
                        timestamp.get("unit", "plausible"),
                        " and increases monotonically"
                        if timestamp.get("monotonic_increasing")
                        else "",
                    ),
                    confidence=Confidence.MEDIUM,
                    source="sample_compare",
                )
            )
            score += 2

    for group in timestamp_groups:
        timestamp = group.get("timestamp") or {}
        key = (
            timestamp.get("unit"),
            timestamp.get("first_iso"),
            timestamp.get("last_iso"),
        )
        if key in seen_timestamp_keys:
            continue
        seen_timestamp_keys.add(key)
        evidence.append(
            make_evidence(
                "%s is consistent with a %s timestamp%s."
                % (
                    group.get("field", "A numeric region"),
                    timestamp.get("unit", "plausible"),
                    " and increases monotonically"
                    if timestamp.get("monotonic_increasing")
                    else "",
                ),
                confidence=Confidence.MEDIUM,
                source="timestamp_analysis",
            )
        )
        score += 2

    classifier_types: Dict[str, TokenFinding] = {}
    for finding in result.candidates:
        if finding.token_type == "numeric":
            continue
        if finding.properties.get("time_ordered"):
            classifier_types.setdefault(finding.token_type, finding)

    for token_type, finding in classifier_types.items():
        evidence.append(
            make_evidence(
                "Classifier %r reports a time-ordered layout across the supplied samples."
                % token_type,
                confidence=finding.confidence,
                source="classifier:%s" % (finding.classifier or token_type),
                details={
                    "token_type": token_type,
                    "timestamp_iso": finding.properties.get("timestamp_iso"),
                    "time_ordered": True,
                },
            )
        )
        score += (
            2
            if finding.confidence == Confidence.HIGH
            or finding.properties.get("timestamp_plausible")
            else 1
        )

    for match in result.hash_matches:
        if not match.matched:
            continue
        evidence.append(
            make_evidence(
                "A sample exactly matches %s, a construction derived from supplied "
                "context values." % match.redacted_construction,
                confidence=Confidence.HIGH,
                source="hash_guess",
                details={"algorithm": match.algorithm, "context_keys": match.context_keys},
            )
        )
        score += 4

    for correlation in result.correlations:
        if correlation.kind in ("co_vary", "context_match"):
            evidence.append(
                make_evidence(
                    correlation.description,
                    confidence=correlation.confidence,
                    source="correlation",
                    details=correlation.properties,
                )
            )
            score += 4 if correlation.confidence == Confidence.HIGH else 2

    if not evidence:
        evidence.append(
            make_evidence(
                "A fixed structure was found but no counter, timestamp, or "
                "correlation matched. The varying region is left as unknown, not "
                "assumed random.",
                confidence=Confidence.LOW,
                source="sample_compare",
            )
        )

    has_unknown_varying = any(
        segment.kind
        in ("unknown_varying", "absent_varying", "encoded_varying", "hex_varying")
        for segment in result.varying_segments
    )
    if has_unknown_varying:
        for note in result.notes:
            if "Varying sections are treated as unknown" in note:
                evidence.append(
                    make_evidence(
                        note, confidence=Confidence.LOW, source="sample_compare"
                    )
                )

    score = max(score, 0)
    level = _level_for_score(score)
    if any(match.matched for match in result.hash_matches):
        level = Confidence.HIGH
    elif result.sample_count < 3 and level == Confidence.HIGH:
        level = Confidence.MEDIUM
    return Predictability(
        level=level,
        evidence=evidence,
        rationale=_rationale(level, evidence, result.structure),
        disclaimer=DISCLAIMER,
    )


__all__ = ["assess_single", "assess_compare", "DISCLAIMER", "AnalysisResult"]
