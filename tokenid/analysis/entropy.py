"""Entropy statistics for a single token.

Three different numbers are reported and kept separate:

* theoretical -- length * log2(reference alphabet size), the maximum if every
  character were independent and uniform over the assumed alphabet.
* observed -- Shannon entropy of this sample, times length.
* estimated -- bias-corrected observed entropy (Miller-Madow).

"The actual" source entropy is not observable from one token, so it stays
``None``.  None of these numbers is a security guarantee.
"""

from __future__ import annotations

import math
from collections import Counter
from typing import Dict, Tuple

from ..models import EntropyStats

DIGITS = set("0123456789")
HEX = set("0123456789abcdefABCDEF")
BASE32 = set("ABCDEFGHIJKLMNOPQRSTUVWXYZ234567")
BASE64 = set("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=")
BASE64URL = set("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_=")
CROCKFORD = set("0123456789ABCDEFGHJKMNPQRSTVWXYZ")
ALPHANUM = set("0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ")


def _charset_class(chars: set, token: str) -> Tuple[str, int]:
    if not chars:
        return "empty", 1
    if chars <= DIGITS:
        return "digits", 10
    if chars <= set("0123456789abcdefABCDEF-") and "-" in token:
        return "uuid-hex", 17
    if chars <= HEX:
        return "hex", 16
    if len(token) == 26 and chars <= CROCKFORD and token == token.upper():
        return "crockford-base32", 32
    if chars <= BASE32:
        return "base32", 32
    if chars <= set("0123456789abcdefghijklmnopqrstuvwxyz"):
        return "lowercase-alphanumeric", 36
    if chars <= set("0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ"):
        return "uppercase-alphanumeric", 36
    if chars <= ALPHANUM:
        if any(char.isdigit() for char in token):
            return "alphanumeric", 62
        return "alphabetic", 52
    if chars <= BASE64URL and ("-" in token or "_" in token):
        return "base64url", 64
    if chars <= BASE64:
        return "base64", 64
    return "text", len(chars)


def compute_entropy(token: str) -> EntropyStats:
    length = len(token)
    frequencies = Counter(token)
    unique = len(frequencies)
    char_frequencies: Dict[str, int] = dict(sorted(frequencies.items()))
    chars = set(frequencies)
    charset_class, reference_size = _charset_class(chars, token)

    if length == 0:
        shannon = 0.0
    elif unique == 1:
        shannon = 0.0
    else:
        shannon = -sum(
            (count / float(length)) * math.log(count / float(length), 2)
            for count in frequencies.values()
        )

    observed_bits = shannon * length
    if length > 0 and unique > 1:
        miller_madow = shannon + (unique - 1) / (2.0 * length * math.log(2))
        estimated_bits = min(miller_madow, math.log2(reference_size) if reference_size > 1 else 0.0) * length
    else:
        estimated_bits = observed_bits
    theoretical_bits = (
        length * math.log(reference_size, 2) if reference_size > 1 else 0.0
    )

    repeated = length - unique
    notes = [
        "Shannon entropy here is a sample statistic; it is not proof of randomness.",
        "Theoretical entropy assumes independent uniform characters and is an upper bound, not a security guarantee.",
        "Actual source entropy cannot be measured from a single token.",
    ]
    if length < 16:
        notes.append("Short samples make entropy estimates unstable.")
    if unique == 1 and length > 0:
        notes.append("Only one distinct character is present; this looks like a placeholder or fixed value.")
    if unique == length and length > 1:
        notes.append("Every character is unique, so sample entropy is high even if the generator is predictable.")

    return EntropyStats(
        length=length,
        unique_chars=unique,
        charset_size=reference_size,
        charset="".join(sorted(chars)),
        charset_class=charset_class,
        shannon_entropy_per_char=round(shannon, 6),
        observed_entropy_bits=round(observed_bits, 6),
        estimated_entropy_bits=round(estimated_bits, 6),
        theoretical_entropy_bits=round(theoretical_bits, 6),
        max_char_frequency=max(frequencies.values()) if frequencies else 0,
        repeated_char_count=repeated,
        actual_entropy_bits=None,
        repetition_ratio=round(repeated / float(length), 6) if length else 0.0,
        char_frequencies=char_frequencies,
        notes=notes,
    )
