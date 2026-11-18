"""Human-readable reports.

By default tokens and context values are redacted.  Pass ``show_token`` /
``show_context`` only when the operator explicitly opts in.
"""

from __future__ import annotations

import json
import textwrap
from typing import Any, Iterable, List, Optional

from .._common import redact
from ..models import (
    AnalysisResult,
    CompareResult,
    DecodeResult,
    EntropyStats,
    Segment,
)

SENSITIVE_PROPERTY_KEYS = {
    "raw_id",
    "decoded_preview",
    "randomness_hex",
    "payload_hex",
    "node",
    "mac",
    "input_preview",
    "output_preview",
    "value",
    "values",
    "raw_values",
    "random_hex",
    "worker_id",
    "sequence",
}


def _title(title: str) -> str:
    return "%s\n%s" % (title, "=" * len(title))


def _wrapped(label: str, text: str, width: int = 88, indent: str = "  ") -> List[str]:
    if not text:
        return [label.rstrip()]
    return textwrap.fill(
        label + text, width=width, subsequent_indent=indent
    ).splitlines()


def _maybe(value: str, show: bool, limit: int = 120) -> str:
    if value is None:
        return ""
    if show:
        return value if len(value) <= limit else value[:limit] + "..."
    return redact(value, 4)


def _structural(value: str, show: bool, limit: int = 32) -> str:
    """Fixed prefixes/counter values are structural, not the whole token."""
    if value is None:
        return ""
    if show:
        return value if len(value) <= limit else value[:limit] + "..."
    if len(value) <= 12:
        return value
    return redact(value, 6)


def _prop_value(value: Any, show_token: bool, key: str = "") -> Any:
    if not show_token and key in SENSITIVE_PROPERTY_KEYS:
        if isinstance(value, list):
            return [redact(str(item), 2) for item in value]
        if isinstance(value, dict):
            return {
                item_key: _prop_value(item, show_token, item_key)
                for item_key, item in value.items()
            }
        return redact(str(value), 4)
    if isinstance(value, str):
        if not show_token and len(value) > 64:
            return redact(value, 4)
        return value
    if isinstance(value, list):
        return [_prop_value(item, show_token) for item in value]
    if isinstance(value, dict):
        return {
            item_key: _prop_value(item, show_token, item_key)
            for item_key, item in value.items()
        }
    return value


def _render_evidence(pred: Any) -> List[str]:
    lines: List[str] = [""]
    if pred is None:
        lines.append("Predictability: unknown (no prediction was produced)")
        return lines
    lines.append("Predictability: %s" % pred.level.value)
    if pred.rationale:
        lines.extend(_wrapped("Rationale: ", pred.rationale))
    lines.append("Evidence:")
    for item in pred.evidence:
        lines.extend(
            _wrapped(
                "  - [%s/%s] " % (item.source, item.confidence.value),
                item.description,
                indent="    ",
            )
        )
    lines.append("")
    lines.extend(_wrapped("Note: ", pred.disclaimer, indent="      "))
    return lines


def _render_entropy_lines(stats: Optional[EntropyStats]) -> List[str]:
    if stats is None:
        return ["Entropy: unavailable"]
    lines = [
        "Entropy: length=%d unique=%d charset=%s (reference size %d)"
        % (stats.length, stats.unique_chars, stats.charset_class, stats.charset_size)
    ]
    lines.extend(
        _wrapped(
            "  Shannon: ",
            "%.3f bits/char; observed %.3f bits; estimated %.3f bits; "
            "theoretical %.3f bits; actual: not observable from one token"
            % (
                stats.shannon_entropy_per_char,
                stats.observed_entropy_bits,
                stats.estimated_entropy_bits,
                stats.theoretical_entropy_bits,
            ),
            indent="    ",
        )
    )
    lines.append(
        "  Repetition: %d repeated char(s), max frequency %d"
        % (stats.repeated_char_count, stats.max_char_frequency)
    )
    return lines


def render_entropy(stats: EntropyStats) -> str:
    lines = [_title("Entropy Analysis"), ""]
    lines.extend(_render_entropy_lines(stats))
    if stats.notes:
        lines.append("")
        lines.append("Notes:")
        for note in stats.notes:
            lines.extend(_wrapped("  - ", note, indent="    "))
    return "\n".join(lines)


def render_analysis(
    result: AnalysisResult, show_token: bool = False, show_context: bool = False
) -> str:
    lines = [_title("Token Pattern Analysis")]
    token_line = result.original if show_token else result.redacted_token
    lines.append("Token: %s" % token_line)
    lines.append("Fingerprint: sha256:%s" % result.token_fingerprint)
    if result.original != result.normalized:
        lines.append("Normalization: surrounding whitespace was ignored for analysis.")
    best = result.best_candidate
    lines.append("Format: %s" % (best.token_type if best else "unknown"))
    lines.append("")

    if result.candidates:
        lines.append("Candidates:")
        for index, finding in enumerate(result.candidates, 1):
            lines.append(
                "  %d. %s [%s] confidence=%s"
                % (index, finding.token_type, finding.family, finding.confidence.value)
            )
            for reason in finding.reasoning:
                lines.extend(_wrapped("     - ", reason, indent="       "))
    else:
        lines.append("Candidates: none matched a known shape.")

    lines.append("")
    lines.extend(_render_entropy_lines(result.entropy))

    if result.decoded and result.decoded.steps:
        lines.append("")
        lines.append(
            "Decoding chain: %s" % " -> ".join(result.decoded.encodings)
        )
        lines.append(
            "  final preview: %s"
            % (
                result.decoded.final_preview
                if show_token
                else "<redacted>"
            )
        )

    if result.timestamps:
        lines.append("")
        lines.append("Timestamp candidates:")
        for hit in result.timestamps[:8]:
            lines.append(
                "  - %s %s (%s) -> %s [%s]"
                % (
                    hit.encoding,
                    _maybe(hit.raw, show_token, 40),
                    hit.unit,
                    hit.timestamp_iso,
                    hit.confidence.value,
                )
            )

    if result.hash_matches:
        lines.append("")
        lines.append("Hash construction matches:")
        for match in result.hash_matches:
            label = (
                match.raw_construction
                if show_context and match.raw_construction
                else match.redacted_construction
            )
            lines.append("  - %s" % label)

    if result.notes:
        lines.append("")
        lines.append("Notes:")
        for note in result.notes:
            lines.extend(_wrapped("  - ", note, indent="    "))

    lines.extend(_render_evidence(result.predictability))
    return "\n".join(lines)


def _segment_label(segment: Segment) -> str:
    if segment.role in ("PREFIX", "SUFFIX", "CONSTANT"):
        if segment.common_value is None:
            return "%s [%d:%d]" % (segment.role, segment.start, segment.end)
        return "%s %r" % (segment.role, segment.common_value)
    return "%s [%d:%d]" % (segment.role, segment.start, segment.end)


def _segment_detail(segment: Segment, show_token: bool) -> str:
    if segment.kind == "fixed":
        return ""
    values = segment.sample_values
    if segment.properties.get("step") is not None:
        step = segment.properties["step"]
        preview = values[0] if values else ""
        return "values start at %s, step %+d" % (
            _maybe(str(preview), show_token, 32),
            step,
        )
    if segment.properties.get("timestamp"):
        ts = segment.properties["timestamp"]
        return "%s timestamp, monotonic=%s" % (
            ts.get("unit", "plausible"),
            ts.get("monotonic_increasing"),
        )
    if values:
        return "first=%s last=%s" % (
            _maybe(str(values[0]), show_token, 32),
            _maybe(str(values[-1]), show_token, 32),
        )
    return ""


def render_compare(
    result: CompareResult, show_token: bool = False, show_context: bool = False
) -> str:
    lines = [_title("Token Pattern Analysis")]
    lines.append("Samples: %d" % result.sample_count)
    lines.append("Lengths: %s" % ", ".join(str(length) for length in result.lengths))
    if show_token and result.samples:
        lines.append("Sample values:")
        for index, sample in enumerate(result.samples, 1):
            lines.append("  %d. %s" % (index, sample))
    lines.append("Format: %s" % result.structure)
    lines.append("")

    if result.candidates:
        lines.append("Candidates:")
        for finding in result.candidates:
            lines.append(
                "  - %s [%s] confidence=%s"
                % (finding.token_type, finding.family, finding.confidence.value)
            )
        lines.append("")

    for segment in result.fixed_segments:
        if segment.role in ("PREFIX", "SUFFIX"):
            value = segment.common_value or ""
            lines.append(
                "Fixed %s: %s"
                % (segment.role.lower(), _structural(value, show_token, 32))
            )
        elif segment.role == "CONSTANT":
            value = segment.common_value or ""
            lines.append(
                "Constant section: %s"
                % (value if show_token else redact(value, 2))
            )

    if result.varying_segments:
        lines.append("Variable section(s):")
        for segment in result.varying_segments:
            detail = _segment_detail(segment, show_token)
            lines.append(
                "  - %s%s"
                % (_segment_label(segment), (": " + detail) if detail else "")
            )
    else:
        lines.append("Variable section: none")

    if result.timestamp_findings:
        lines.append("")
        lines.append("Timestamp candidates:")
        for hit in result.timestamp_findings[:8]:
            lines.append(
                "  - %s %s (%s) -> %s [%s]"
                % (
                    hit.encoding,
                    _maybe(hit.raw, show_token, 40),
                    hit.unit,
                    hit.timestamp_iso,
                    hit.confidence.value,
                )
            )

    if result.sequence_findings:
        lines.append("")
        lines.append("Sequences:")
        for finding in result.sequence_findings:
            lines.extend(_wrapped("  - ", finding.description, indent="    "))

    if result.correlations:
        lines.append("")
        lines.append("Correlations:")
        for correlation in result.correlations:
            lines.extend(
                _wrapped(
                    "  - [%s] " % correlation.confidence.value,
                    correlation.description,
                    indent="    ",
                )
            )

    if result.patterns:
        lines.append("")
        lines.append("Patterns:")
        for pattern in result.patterns[:8]:
            lines.extend(
                _wrapped(
                    "  - %s [%s] " % (pattern.name, pattern.confidence.value),
                    pattern.description,
                    indent="    ",
                )
            )

    if result.hash_matches:
        lines.append("")
        lines.append("Hash construction matches:")
        for match in result.hash_matches:
            label = (
                match.raw_construction
                if show_context and match.raw_construction
                else match.redacted_construction
            )
            lines.append("  - %s" % label)

    if result.notes:
        lines.append("")
        lines.append("Notes:")
        for note in result.notes:
            lines.extend(_wrapped("  - ", note, indent="    "))

    lines.extend(_render_evidence(result.predictability))
    return "\n".join(lines)


def render_decode(
    result: DecodeResult,
    token: Optional[str] = None,
    show_token: bool = False,
) -> str:
    lines = [_title("Decode Chain")]
    if token is None:
        source = result.original if show_token else redact(result.original_preview, 4)
    else:
        source = token if show_token else redact(token, 4)
    lines.append("Input: %s" % source)
    if not result.steps:
        lines.append("")
        lines.append("No decodable encoding was detected.")
        return "\n".join(lines)

    lines.append("")
    for index, step in enumerate(result.steps, 1):
        input_text = step.input_preview if show_token else redact(step.input_preview, 4)
        output_text = (
            step.output_preview
            if show_token or step.printable
            else "<redacted binary output>"
        )
        lines.append(
            "  %d. %s: %s -> %s (%d bytes, printable=%s)"
            % (
                index,
                step.encoding,
                input_text,
                output_text,
                step.output_length,
                step.printable,
            )
        )
    lines.append("")
    lines.append("Final: %s" % result.final_preview)
    lines.append("Stopped: %s" % result.stopped_reason)
    if result.cycle_detected:
        lines.append("Cycle detected: recursion stopped safely.")
    lines.append("")
    lines.append("Note: decoding is reversible obfuscation, not decryption.")
    return "\n".join(lines)


def render_inspect(
    result: AnalysisResult, show_token: bool = False, show_context: bool = False
) -> str:
    lines = [_title("Token Structure")]
    lines.append("Token: %s" % (result.original if show_token else result.redacted_token))
    lines.append("Fingerprint: sha256:%s" % result.token_fingerprint)
    best = result.best_candidate
    lines.append("Best candidate: %s" % (best.token_type if best else "unknown"))

    for index, finding in enumerate(result.candidates, 1):
        lines.append("")
        lines.append(
            "%d. %s [%s] confidence=%s"
            % (index, finding.token_type, finding.family, finding.confidence.value)
        )
        for reason in finding.reasoning:
            lines.extend(_wrapped("   - ", reason, indent="     "))
        if finding.properties:
            lines.append("   Properties:")
            for key in sorted(finding.properties):
                value = finding.properties[key]
                value = _prop_value(value, show_token, key)
                rendered = (
                    json.dumps(value, ensure_ascii=False)
                    if isinstance(value, (dict, list))
                    else value
                )
                lines.append("     %s: %s" % (key, rendered))

    lines.append("")
    lines.extend(_render_entropy_lines(result.entropy))
    if result.timestamps:
        lines.append("")
        lines.append("Timestamp candidates:")
        for hit in result.timestamps:
            lines.append(
                "  - %s %s (%s) -> %s"
                % (hit.encoding, _maybe(hit.raw, show_token, 40), hit.unit, hit.timestamp_iso)
            )
    if result.hash_matches:
        lines.append("")
        lines.append("Hash construction matches:")
        for match in result.hash_matches:
            label = (
                match.raw_construction
                if show_context and match.raw_construction
                else match.redacted_construction
            )
            lines.append("  - %s" % label)
    if result.notes:
        lines.append("")
        lines.append("Notes:")
        for note in result.notes:
            lines.extend(_wrapped("  - ", note, indent="    "))
    lines.extend(_render_evidence(result.predictability))
    return "\n".join(lines)


def render_batch(
    results: Iterable[AnalysisResult],
    show_token: bool = False,
    show_context: bool = False,
) -> str:
    return "\n\n".join(
        render_analysis(result, show_token=show_token, show_context=show_context)
        for result in results
    )
