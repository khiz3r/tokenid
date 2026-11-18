"""Snowflake-style 64-bit IDs.

The exact bit split is deployment-specific.  This classifier tries several
well-known epochs/splits and returns a candidate per plausible interpretation
rather than pretending one is certain.
"""

from __future__ import annotations

from typing import Any, Dict, List

from ..._common import format_unix, now_unix, plausible_unix_seconds
from ...models import ClassifierContext, Confidence, TokenFinding
from ...registry import register

# name, epoch in Unix milliseconds, worker bits, sequence bits
EPOCHS = (
    ("twitter", 1288834974657, 10, 12),
    ("discord", 1420070400000, 10, 12),
    ("instagram", 1314220021721, 13, 10),
)


@register("snowflake", "distributed", "Snowflake: 64-bit integer with timestamp/worker/sequence", order=70)
def classify(token: str, ctx: ClassifierContext) -> List[TokenFinding]:
    raw = token.strip()
    if not raw.isdigit():
        return []
    if not (15 <= len(raw) <= 20):
        return []
    value = int(raw)
    if value >= (1 << 63):
        return []

    plausible: List[Dict[str, Any]] = []
    tried: List[Dict[str, Any]] = []
    for name, epoch_ms, worker_bits, sequence_bits in EPOCHS:
        ts_ms = (value >> (worker_bits + sequence_bits)) + epoch_ms
        seconds = ts_ms / 1000.0
        is_plausible = plausible_unix_seconds(seconds, now=now_unix())
        record = {
            "epoch": name,
            "epoch_unix_ms": epoch_ms,
            "timestamp_unix_ms": ts_ms,
            "timestamp_iso": format_unix(seconds),
            "plausible": is_plausible,
            "worker_bits": worker_bits,
            "sequence_bits": sequence_bits,
            "worker_id": (value >> sequence_bits) & ((1 << worker_bits) - 1),
            "sequence": value & ((1 << sequence_bits) - 1),
        }
        tried.append(record)
        if is_plausible:
            plausible.append(record)

    if not plausible:
        return [
            TokenFinding(
                token_type="snowflake",
                family="distributed",
                confidence=Confidence.LOW,
                reasoning=[
                    "The value is a 63-bit positive integer with a snowflake-like "
                    "digit count.",
                    "None of the common epochs yield a plausible timestamp, so "
                    "this may be a different 64-bit identifier.",
                ],
                properties={
                    "value_digits": len(raw),
                    "contains_timestamp": False,
                    "time_ordered": False,
                    "epochs_tried": tried,
                },
            )
        ]

    findings: List[TokenFinding] = []
    unique = len(plausible) == 1
    for record in plausible:
        findings.append(
            TokenFinding(
                token_type="snowflake",
                family="distributed",
                confidence=Confidence.HIGH if unique else Confidence.MEDIUM,
                reasoning=[
                    "Value fits a signed 63-bit snowflake layout.",
                    "Using the %s epoch and a %d/%d worker/sequence split, the "
                    "timestamp decodes to %s."
                    % (
                        record["epoch"],
                        record["worker_bits"],
                        record["sequence_bits"],
                        record["timestamp_iso"],
                    ),
                    "Other epochs also fit, so the deployment cannot be inferred "
                    "from shape alone." if not unique else "Only one common epoch fit.",
                ],
                properties={
                    "contains_timestamp": True,
                    "timestamp_unit": "milliseconds since custom epoch",
                    "timestamp_unix_ms": record["timestamp_unix_ms"],
                    "timestamp_iso": record["timestamp_iso"],
                    "timestamp_plausible": True,
                    "time_ordered": True,
                    "epoch": record["epoch"],
                    "worker_id": record["worker_id"],
                    "sequence": record["sequence"],
                    "epoch_candidates": [r["epoch"] for r in plausible],
                },
            )
        )
    return findings
