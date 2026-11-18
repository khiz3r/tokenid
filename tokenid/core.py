"""Orchestration: classifiers -> analysis -> prediction -> report data."""

from __future__ import annotations

from typing import Dict, Iterable, List, Optional

from ._common import fingerprint, normalize_token, redact
from .analysis.correlation import find_correlations
from .analysis.entropy import compute_entropy
from .analysis.hash_guess import describe_attempts, guess_hashes
from .analysis.pattern_detection import detect_patterns
from .analysis.sample_compare import compare_samples
from .analysis.sequence_analysis import analyze_all
from .analysis.timestamp_analysis import detect_timestamps
from .classifiers import load_all, load_errors
from .classifiers.encoding_classifier import MAX_BYTES, MAX_DEPTH, decode_chain
from .models import (
    AnalysisResult,
    ClassifierContext,
    CompareResult,
    Confidence,
    DecodeResult,
    TokenFinding,
)
from .prediction.predictability import assess_compare, assess_single
from .registry import run_classifiers


FAMILY_PRIORITY = {
    "uuid": 0,
    "distributed": 1,
    "database": 2,
    "application": 3,
    "short_id": 4,
    "numeric": 5,
    "hash": 6,
    "encoding": 7,
}


def _sorted(findings: Iterable[TokenFinding]) -> List[TokenFinding]:
    return sorted(
        findings,
        key=lambda finding: (
            -finding.confidence.rank,
            FAMILY_PRIORITY.get(finding.family, 99),
            finding.token_type,
            finding.classifier,
        ),
    )


def _load() -> List[str]:
    load_all()
    return load_errors()


def analyze(
    token: str,
    context: Optional[Dict[str, str]] = None,
    options: Optional[Dict[str, object]] = None,
) -> AnalysisResult:
    """Analyze one token offline.

    Returns all matching candidates, entropy statistics, decoded chain,
    timestamp candidates, optional hash guesses, and a predictability verdict.
    """
    if not isinstance(token, str):
        raise TypeError("token must be a string")
    load_issues = _load()
    original = token
    normalized = normalize_token(token)
    context = {str(key): str(value) for key, value in dict(context or {}).items()}

    ctx = ClassifierContext(
        samples=[normalized], context=context, options=dict(options or {})
    )
    findings = _sorted(run_classifiers(normalized, ctx))
    entropy = compute_entropy(normalized)
    timestamps = detect_timestamps(normalized)
    decoded = decode_chain(normalized)
    hash_matches = guess_hashes(normalized, context)
    predictability = assess_single(
        findings,
        timestamps,
        entropy=entropy,
        decoded=decoded,
        hash_matches=hash_matches,
        context=context,
    )

    notes: List[str] = []
    if load_issues:
        notes.append("Some classifier modules failed to load: %s" % "; ".join(load_issues))
    attempts = describe_attempts(context)
    if attempts and not hash_matches:
        notes.append(
            "Hash guessing tried %d construction(s) from context; no match." % attempts
        )
    if decoded.steps:
        notes.append(
            "Token content was decoded (%s); decoding does not imply the token is "
            "weak." % " -> ".join(decoded.encodings)
        )

    return AnalysisResult(
        original=original,
        normalized=normalized,
        candidates=findings,
        entropy=entropy,
        predictability=predictability,
        decoded=decoded,
        timestamps=timestamps,
        hash_matches=hash_matches,
        evidence=list(predictability.evidence),
        notes=notes,
        token_fingerprint=fingerprint(normalized),
        redacted_token=redact(normalized),
    )


def compare(
    samples: Iterable[str], context: Optional[Dict[str, str]] = None
) -> CompareResult:
    """Compare multiple samples (one token per sample)."""
    if isinstance(samples, str):
        raise TypeError("compare expects a list of samples, not a single string")
    sample_list = list(samples)
    if not sample_list:
        raise ValueError("compare requires at least one sample")
    if any(not isinstance(sample, str) for sample in sample_list):
        raise TypeError("every sample must be a string")

    load_issues = _load()
    context = {str(key): str(value) for key, value in dict(context or {}).items()}
    normalized = [normalize_token(sample) for sample in sample_list]

    ctx = ClassifierContext(
        samples=normalized, context=context, options={}
    )
    findings = []
    seen_findings = set()
    for sample in normalized:
        for finding in run_classifiers(sample, ctx):
            key = (
                finding.token_type,
                finding.family,
                finding.classifier,
                finding.confidence,
                finding.properties.get("epoch"),
            )
            if key in seen_findings:
                continue
            seen_findings.add(key)
            findings.append(finding)
    findings = _sorted(findings)

    result = compare_samples(normalized)
    result.samples = list(sample_list)
    if any(original != cleaned for original, cleaned in zip(sample_list, normalized)):
        result.notes.append(
            "Surrounding whitespace was ignored for analysis; sample values show "
            "the original input."
        )
    result.candidates = findings
    result.sequence_findings = analyze_all(
        result.all_segments, result.numeric_groups
    )

    timestamp_hits = []
    seen_hits = set()
    for sample in normalized:
        for hit in detect_timestamps(sample):
            key = (hit.encoding, hit.raw, hit.value, hit.unit)
            if key in seen_hits:
                continue
            seen_hits.add(key)
            timestamp_hits.append(hit)
    result.timestamp_findings = timestamp_hits[:30]

    result.patterns = detect_patterns(result)
    result.correlations = find_correlations(
        result.numeric_groups,
        result.varying_segments,
        context,
        sample_count=result.sample_count,
    )

    hash_matches = []
    seen_matches = set()
    for sample in normalized:
        for match in guess_hashes(sample, context):
            key = (match.algorithm, match.template, match.matched)
            if key in seen_matches:
                continue
            seen_matches.add(key)
            hash_matches.append(match)
    result.hash_matches = hash_matches

    predictability = assess_compare(result)
    result.predictability = predictability
    result.evidence = list(predictability.evidence)

    if load_issues:
        result.notes.append(
            "Some classifier modules failed to load: %s" % "; ".join(load_issues)
        )
    attempts = describe_attempts(context)
    if attempts and not hash_matches:
        result.notes.append(
            "Hash guessing tried %d construction(s) per sample; no match." % attempts
        )
    return result


def decode(
    token: str,
    max_depth: int = MAX_DEPTH,
    max_bytes: int = MAX_BYTES,
    allow_binary: bool = True,
) -> DecodeResult:
    """Recursively decode a token and return the chain."""
    if not isinstance(token, str):
        raise TypeError("token must be a string")
    _load()
    return decode_chain(
        normalize_token(token),
        max_depth=max_depth,
        max_bytes=max_bytes,
        allow_binary=allow_binary,
    )


def inspect(
    token: str, context: Optional[Dict[str, str]] = None
) -> AnalysisResult:
    """Verbose structural breakdown, reusing :func:`analyze`."""
    return analyze(token, context=context)


def analyze_batch(
    tokens: Iterable[str], context: Optional[Dict[str, str]] = None
) -> Iterable[AnalysisResult]:
    for token in tokens:
        yield analyze(token, context=context)


__all__ = [
    "analyze",
    "compare",
    "decode",
    "inspect",
    "analyze_batch",
    "Confidence",
]
