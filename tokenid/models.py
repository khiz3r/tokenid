"""Data models used across tokenid.

Design rule: a :class:`TokenFinding` describes *shape* only.  Statements such as
"time ordered" or "contains a timestamp" are structural properties.  Security
conclusions ("this is predictable") live exclusively in
:class:`~tokenid.prediction.predictability.Predictability`.
"""

from __future__ import annotations

from dataclasses import dataclass, field, fields, is_dataclass
from enum import Enum
from typing import Any, Dict, List, Optional, Tuple

from ._common import redact


class Confidence(str, Enum):
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"

    @property
    def rank(self) -> int:
        return {"LOW": 1, "MEDIUM": 2, "HIGH": 3}[self.value]


def _redact_nested(value: Any) -> Any:
    """Redact raw sample values inside nested report structures."""
    if isinstance(value, dict):
        out = {}
        for key, item in value.items():
            if key in ("values", "raw_values") and isinstance(item, (list, tuple)):
                out[key] = [redact(str(entry), 2) for entry in item]
            elif key in (
                "raw",
                "value",
                "raw_id",
                "decoded_preview",
                "random_hex",
                "randomness_hex",
                "payload_hex",
                "node",
            ) and isinstance(item, str):
                out[key] = redact(item, 2)
            elif key in (
                "raw",
                "value",
                "seconds",
                "worker_id",
                "sequence",
            ) and isinstance(item, int):
                out[key] = redact(str(item), 2)
            else:
                out[key] = _redact_nested(item)
        return out
    if isinstance(value, (list, tuple)):
        return [_redact_nested(item) for item in value]
    return value


def _json_safe(value: Any) -> Any:
    if isinstance(value, Enum):
        return value.value
    if is_dataclass(value):
        return {f.name: _json_safe(getattr(value, f.name)) for f in fields(value)}
    if isinstance(value, dict):
        return {str(k): _json_safe(v) for k, v in value.items()}
    if isinstance(value, (list, tuple, set)):
        return [_json_safe(v) for v in value]
    if isinstance(value, bytes):
        return value.hex()
    return value


@dataclass
class Evidence:
    """A single piece of supporting evidence for (or against) predictability."""

    description: str
    confidence: Confidence = Confidence.MEDIUM
    source: str = "unknown"
    details: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return _json_safe(self)


@dataclass
class ClassifierContext:
    """Input available to classifiers.

    ``samples`` lets multi-sample-aware classifiers (e.g. Firebase push IDs)
    compare a token against its siblings.  ``context`` is the user-supplied
    ``--context key=value`` mapping and may contain a Hashids salt.
    """

    samples: List[str] = field(default_factory=list)
    context: Dict[str, str] = field(default_factory=dict)
    options: Dict[str, Any] = field(default_factory=dict)


@dataclass
class TokenFinding:
    """One candidate identity for a token.

    ``properties`` is intentionally structural.  Never put a security verdict
    in here; use predictions for that.
    """

    token_type: str
    family: str
    confidence: Confidence
    reasoning: List[str] = field(default_factory=list)
    properties: Dict[str, Any] = field(default_factory=dict)
    classifier: str = ""
    details: Dict[str, Any] = field(default_factory=dict)

    @property
    def reasoning_text(self) -> str:
        return " ".join(self.reasoning)

    def to_dict(self, include_token: bool = False) -> Dict[str, Any]:
        data = _json_safe(self)
        if not include_token:
            data["properties"] = _redact_nested(data.get("properties") or {})
            data["details"] = _redact_nested(data.get("details") or {})
        return data


@dataclass
class EntropyStats:
    length: int
    unique_chars: int
    charset_size: int
    charset: str
    charset_class: str
    shannon_entropy_per_char: float
    observed_entropy_bits: float
    estimated_entropy_bits: float
    theoretical_entropy_bits: float
    max_char_frequency: int
    repeated_char_count: int
    actual_entropy_bits: Optional[float] = None
    repetition_ratio: float = 0.0
    char_frequencies: Dict[str, int] = field(default_factory=dict)
    notes: List[str] = field(default_factory=list)

    def to_dict(self, include_token: bool = False) -> Dict[str, Any]:
        data = _json_safe(self)
        if not include_token:
            data["charset"] = "<redacted>"
            data["char_frequencies"] = {}
        return data


@dataclass
class Segment:
    kind: str
    start: int
    end: int
    length: int
    role: str = "VARYING"
    common_value: Optional[str] = None
    sample_values: List[str] = field(default_factory=list)
    description: str = ""
    properties: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self, include_token: bool = False) -> Dict[str, Any]:
        data = _json_safe(self)
        if not include_token:
            if data.get("common_value"):
                value = str(data["common_value"])
                if self.role == "CONSTANT" or len(value) > 12:
                    data["common_value"] = redact(value, 2 if self.role == "CONSTANT" else 6)
                    data["common_value_redacted"] = True
            if self.sample_values:
                data["sample_values"] = [redact(value, 3) for value in self.sample_values]
                data["sample_values_redacted"] = True
            data["properties"] = _redact_nested(data.get("properties") or {})
        return data


@dataclass
class SequenceFinding:
    field: str
    kind: str
    values: List[int] = field(default_factory=list)
    step: Optional[int] = None
    confidence: Confidence = Confidence.LOW
    description: str = ""
    properties: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self, include_token: bool = False) -> Dict[str, Any]:
        data = _json_safe(self)
        if not include_token:
            data["values"] = [redact(str(value), 2) for value in self.values]
            data["values_redacted"] = True
            data["properties"] = _redact_nested(data.get("properties") or {})
        return data


@dataclass
class TimestampHit:
    raw: str
    value: int
    unit: str
    encoding: str
    timestamp_iso: str
    plausible: bool
    position: Optional[Tuple[int, int]] = None
    confidence: Confidence = Confidence.LOW
    description: str = ""

    def to_dict(self, include_token: bool = False) -> Dict[str, Any]:
        data = _json_safe(self)
        if not include_token:
            data["raw"] = redact(self.raw, 2)
            data["value"] = redact(str(self.value), 2)
        return data


@dataclass
class Pattern:
    name: str
    description: str
    confidence: Confidence = Confidence.MEDIUM
    segment_indexes: List[int] = field(default_factory=list)
    properties: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return _json_safe(self)


@dataclass
class CorrelationFinding:
    field_a: str
    field_b: str
    kind: str
    description: str
    confidence: Confidence = Confidence.LOW
    properties: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return _json_safe(self)


@dataclass
class DecodeStep:
    encoding: str
    input_preview: str
    output_preview: str
    output_length: int
    printable: bool
    truncated: bool = False
    properties: Dict[str, Any] = field(default_factory=dict)

    def to_dict(
        self, include_input: bool = True, include_output: bool = True
    ) -> Dict[str, Any]:
        data = _json_safe(self)
        if not include_input:
            data["input_preview"] = redact(self.input_preview, 4)
        if not include_output:
            data["output_preview"] = "<redacted>"
            data["output_preview_redacted"] = True
        return data


@dataclass
class DecodeResult:
    original_preview: str
    original: str = field(default="", repr=False)
    steps: List[DecodeStep] = field(default_factory=list)
    final_preview: str = ""
    stopped_reason: str = ""
    depth: int = 0
    cycle_detected: bool = False

    @property
    def encodings(self) -> List[str]:
        return [step.encoding for step in self.steps]

    def to_dict(
        self, include_token: bool = False, include_output: bool = True
    ) -> Dict[str, Any]:
        data = _json_safe(self)
        original = data.pop("original", "")
        data.pop("original", None)
        data["steps"] = [
            step.to_dict(
                include_input=include_token,
                include_output=include_output
                and (include_token or step.printable),
            )
            for step in self.steps
        ]
        if include_token:
            if original:
                data["original"] = original
        else:
            data["original_preview"] = redact(self.original_preview, 4)
            if not include_output:
                data["final_preview"] = "<redacted>"
            elif not self.steps:
                data["final_preview"] = redact(self.final_preview, 2)
        return data


@dataclass
class HashMatch:
    algorithm: str
    template: str
    redacted_construction: str
    matched: bool
    confidence: Confidence = Confidence.LOW
    context_keys: List[str] = field(default_factory=list)
    raw_construction: Optional[str] = field(default=None, repr=False)

    def to_dict(self, include_context: bool = False) -> Dict[str, Any]:
        data = {
            "algorithm": self.algorithm,
            "template": self.template,
            "redacted_construction": self.redacted_construction,
            "matched": self.matched,
            "confidence": self.confidence.value,
            "context_keys": list(self.context_keys),
        }
        if include_context and self.raw_construction is not None:
            data["construction"] = self.raw_construction
        return data


@dataclass
class Predictability:
    level: Confidence
    evidence: List[Evidence] = field(default_factory=list)
    rationale: str = ""
    disclaimer: str = (
        "A detected pattern is evidence, not proof that the server accepts "
        "guessed values. Validate authorization and server-side controls "
        "separately."
    )

    def to_dict(self) -> Dict[str, Any]:
        return _json_safe(self)


@dataclass
class AnalysisResult:
    original: str
    normalized: str
    candidates: List[TokenFinding] = field(default_factory=list)
    entropy: Optional[EntropyStats] = None
    predictability: Optional[Predictability] = None
    decoded: Optional[DecodeResult] = None
    timestamps: List[TimestampHit] = field(default_factory=list)
    hash_matches: List[HashMatch] = field(default_factory=list)
    evidence: List[Evidence] = field(default_factory=list)
    notes: List[str] = field(default_factory=list)
    token_fingerprint: str = ""
    redacted_token: str = ""

    @property
    def best_candidate(self) -> Optional[TokenFinding]:
        return self.candidates[0] if self.candidates else None

    def to_dict(
        self, include_token: bool = False, include_context: bool = False
    ) -> Dict[str, Any]:
        return {
            "kind": "analysis",
            "token": self.original if include_token else self.redacted_token,
            "token_fingerprint": self.token_fingerprint,
            "normalization_changed": self.original != self.normalized,
            "candidates": [
                c.to_dict(include_token=include_token) for c in self.candidates
            ],
            "entropy": (
                self.entropy.to_dict(include_token=include_token)
                if self.entropy
                else None
            ),
            "timestamps": [
                t.to_dict(include_token=include_token) for t in self.timestamps
            ],
            "decoded": (
                self.decoded.to_dict(
                    include_token=include_token,
                    include_output=include_token,
                )
                if self.decoded
                else None
            ),
            "hash_matches": [
                h.to_dict(include_context=include_context) for h in self.hash_matches
            ],
            "evidence": [e.to_dict() for e in self.evidence],
            "predictability": (
                self.predictability.to_dict() if self.predictability else None
            ),
            "notes": list(self.notes),
        }


@dataclass
class CompareResult:
    sample_count: int
    lengths: List[int]
    structure: str
    fixed_segments: List[Segment] = field(default_factory=list)
    varying_segments: List[Segment] = field(default_factory=list)
    all_segments: List[Segment] = field(default_factory=list)
    numeric_groups: List[Dict[str, Any]] = field(default_factory=list)
    sequence_findings: List[SequenceFinding] = field(default_factory=list)
    timestamp_findings: List[TimestampHit] = field(default_factory=list)
    patterns: List[Pattern] = field(default_factory=list)
    correlations: List[CorrelationFinding] = field(default_factory=list)
    candidates: List[TokenFinding] = field(default_factory=list)
    hash_matches: List[HashMatch] = field(default_factory=list)
    predictability: Optional[Predictability] = None
    evidence: List[Evidence] = field(default_factory=list)
    notes: List[str] = field(default_factory=list)
    sample_fingerprints: List[str] = field(default_factory=list)
    samples: List[str] = field(default_factory=list)

    def to_dict(
        self, include_token: bool = False, include_context: bool = False
    ) -> Dict[str, Any]:
        numeric_groups = _json_safe(self.numeric_groups)
        if not include_token:
            numeric_groups = _redact_nested(numeric_groups)
        segments = [
            s.to_dict(include_token=include_token) for s in self.all_segments
        ]
        return {
            "kind": "compare",
            "sample_count": self.sample_count,
            "samples": (
                list(self.samples)
                if include_token
                else [redact(sample, 4) for sample in self.samples]
            ),
            "lengths": list(self.lengths),
            "structure": self.structure,
            "fixed_segments": [
                s.to_dict(include_token=include_token) for s in self.fixed_segments
            ],
            "varying_segments": [
                s.to_dict(include_token=include_token) for s in self.varying_segments
            ],
            "segments": segments,
            "numeric_groups": numeric_groups,
            "sequence_findings": [
                f.to_dict(include_token=include_token) for f in self.sequence_findings
            ],
            "timestamp_findings": [
                t.to_dict(include_token=include_token)
                for t in self.timestamp_findings
            ],
            "patterns": [p.to_dict() for p in self.patterns],
            "correlations": [c.to_dict() for c in self.correlations],
            "candidates": [
                c.to_dict(include_token=include_token) for c in self.candidates
            ],
            "hash_matches": [
                h.to_dict(include_context=include_context) for h in self.hash_matches
            ],
            "evidence": [e.to_dict() for e in self.evidence],
            "predictability": (
                self.predictability.to_dict() if self.predictability else None
            ),
            "notes": list(self.notes),
            "sample_fingerprints": list(self.sample_fingerprints),
        }
