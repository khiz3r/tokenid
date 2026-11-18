"""Guess hash constructions from user-supplied context values.

No values are hardcoded.  The caller supplies ``--context key=value`` and may
also override the algorithms, separators, or templates.  Context values are
redacted from every report unless ``--show-context`` is passed.
"""

from __future__ import annotations

import base64
import hashlib
import re
from typing import Dict, Iterable, List, Tuple

from ..models import Confidence, HashMatch

DEFAULT_ALGORITHMS = ("md5", "sha1", "sha256")
DEFAULT_SEPARATORS = ("", "-", "_", ":", "|", ".", "/")
MAX_CONSTRUCTIONS = 500
PLACEHOLDER_RE = re.compile(r"\{([A-Za-z0-9_.-]+)\}")

RESERVED_KEYS = {
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


def _available_algorithms(context: Dict[str, str]) -> List[str]:
    raw = context.get("hash_algorithms")
    algorithms = [item.strip().lower() for item in raw.split(",")] if raw else list(DEFAULT_ALGORITHMS)
    out = []
    for name in algorithms:
        if not name:
            continue
        try:
            hashlib.new(name)
        except (ValueError, TypeError):
            continue
        out.append(name)
    return out


def _separators(context: Dict[str, str]) -> List[str]:
    raw = context.get("hash_separators")
    if raw is None:
        return list(DEFAULT_SEPARATORS)
    return [item for item in raw.split(",")] or [""]


def _values(context: Dict[str, str]) -> List[Tuple[str, str]]:
    return [
        (key, value)
        for key, value in context.items()
        if key not in RESERVED_KEYS and value != ""
    ]


def _constructions(context: Dict[str, str]) -> Iterable[Tuple[str, str, List[str]]]:
    """Yield ``(template, raw_string, context_keys)`` constructions."""
    values = _values(context)
    templates = context.get("hash_templates")
    if templates:
        for template in templates.split(","):
            template = template.strip()
            if not template:
                continue
            keys = PLACEHOLDER_RE.findall(template)
            if not keys or any(key not in context for key in keys):
                continue
            raw = template
            for key in keys:
                raw = raw.replace("{%s}" % key, context[key])
            yield template, raw, keys
        return

    count = 0
    for key, value in values:
        yield "{%s}" % key, value, [key]
        count += 1
        if count >= MAX_CONSTRUCTIONS:
            return

    for key_a, value_a in values:
        for key_b, value_b in values:
            if key_a == key_b:
                continue
            for separator in _separators(context):
                template = "{%s}%s{%s}" % (key_a, separator, key_b)
                yield template, value_a + separator + value_b, [key_a, key_b]
                count += 1
                if count >= MAX_CONSTRUCTIONS:
                    return


def _digest_candidates(algorithm: str, raw: str) -> List[Tuple[str, str]]:
    digest = hashlib.new(algorithm, raw.encode("utf-8", "surrogatepass")).digest()
    hexdigest = digest.hex()
    return [
        ("hex-lower", hexdigest),
        ("hex-upper", hexdigest.upper()),
        ("base64", base64.b64encode(digest).decode("ascii")),
        ("base64url", base64.urlsafe_b64encode(digest).decode("ascii")),
        ("base64-nopad", base64.b64encode(digest).decode("ascii").rstrip("=")),
    ]


def guess_hashes(token: str, context: Dict[str, str]) -> List[HashMatch]:
    if not context:
        return []
    raw_token = token.strip()
    algorithms = _available_algorithms(context)
    if not algorithms:
        return []

    matches: List[HashMatch] = []
    seen = set()
    for template, raw, keys in _constructions(context):
        for algorithm in algorithms:
            for encoding, candidate in _digest_candidates(algorithm, raw):
                if encoding.startswith("hex"):
                    matched = raw_token.lower() == candidate.lower()
                else:
                    matched = raw_token == candidate
                if not matched:
                    continue
                dedupe = (
                    algorithm,
                    template,
                    candidate.lower() if encoding.startswith("hex") else candidate,
                )
                if dedupe in seen:
                    continue
                seen.add(dedupe)
                label = "%s(%s)" % (algorithm, template)
                matches.append(
                    HashMatch(
                        algorithm=algorithm,
                        template=template,
                        redacted_construction=label,
                        matched=True,
                        confidence=Confidence.HIGH,
                        context_keys=list(keys),
                        raw_construction="%s(%s) [%s]"
                        % (algorithm, raw, encoding),
                    )
                )
    return matches


def describe_attempts(context: Dict[str, str]) -> int:
    if not context:
        return 0
    return sum(1 for _ in _constructions(context)) * max(
        1, len(_available_algorithms(context))
    )
