"""Small, dependency-free ANSI colorizer for text reports.

Only labels, headings, and the predictability level are colored.  Long
reasoning text is left alone so terminal wrapping stays readable and no color
codes are inserted into JSON output.
"""

from __future__ import annotations

import os
import re
import sys
from typing import Optional, TextIO

RESET = "\033[0m"
BOLD = "\033[1m"
DIM = "\033[2m"
CYAN = "\033[36m"
RED = "\033[31m"
YELLOW = "\033[33m"
GREEN = "\033[32m"

TITLES = {"Token Pattern Analysis", "Token Structure", "Decode Chain", "Entropy Analysis"}

LABELS = {
    "Token",
    "Fingerprint",
    "Format",
    "Best candidate",
    "Input",
    "Final",
    "Stopped",
    "Samples",
    "Lengths",
    "Normalization",
    "Fixed prefix",
    "Fixed suffix",
    "Constant section",
    "Variable section",
    "Variable section(s)",
    "Sample values",
    "Candidates",
    "Entropy",
    "Shannon",
    "Repetition",
    "Timestamp candidates",
    "Sequences",
    "Correlations",
    "Patterns",
    "Hash construction matches",
    "Decoding chain",
    "Rationale",
    "Evidence",
    "Notes",
    "Properties",
    "Note",
    "Cycle detected",
}

PREDICTABILITY_COLORS = {"HIGH": RED, "MEDIUM": YELLOW, "LOW": GREEN}
STEP_RE = re.compile(r"^(\s+\d+\.\s+)([A-Za-z0-9_-]+)(:)")


def supports_color(stream: Optional[TextIO] = None) -> bool:
    """Return whether ANSI color is appropriate for *stream*."""
    if os.environ.get("NO_COLOR"):
        return False
    if os.environ.get("TERM", "").lower() == "dumb":
        return False
    stream = stream if stream is not None else sys.stdout
    return bool(getattr(stream, "isatty", lambda: False)())


def _paint(text: str, code: str) -> str:
    return "%s%s%s" % (code, text, RESET)


def _label_line(line: str) -> Optional[str]:
    match = re.match(r"^(\s*)([A-Za-z][A-Za-z0-9 _()/-]*:)(.*)$", line)
    if not match:
        return None
    indent, label, rest = match.groups()
    if label.rstrip(":").strip() not in LABELS:
        return None
    return "%s%s%s%s" % (indent, _paint(label, BOLD + CYAN), rest, "")


def colorize_text(text: str, enabled: bool = True) -> str:
    if not enabled or not text:
        return text
    out = []
    underline_title = False
    for line in text.split("\n"):
        if underline_title:
            out.append(_paint(line, CYAN))
            underline_title = False
            continue
        if line in TITLES:
            out.append(_paint(line, BOLD + CYAN))
            underline_title = True
            continue
        match = re.match(r"^(Predictability: )(HIGH|MEDIUM|LOW)(.*)$", line)
        if match:
            label, level, rest = match.groups()
            out.append(
                "%s %s%s"
                % (_paint(label.rstrip(), BOLD), _paint(level, PREDICTABILITY_COLORS[level]), rest)
            )
            continue
        step = STEP_RE.match(line)
        if step:
            prefix, encoding, suffix = step.groups()
            out.append(
                "%s%s%s%s"
                % (prefix, _paint(encoding, CYAN), suffix, line[step.end():])
            )
            continue
        painted = _label_line(line)
        out.append(painted if painted is not None else line)
    return "\n".join(out)
