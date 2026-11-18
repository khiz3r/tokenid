"""Hashids / Sqids detection and optional decoding.

Hashids and Sqids turn one or more integers into short alphanumeric strings.
Without the salt (Hashids) or custom alphabet (Sqids), a token cannot be
reliably decoded or even proven to be a Hashid.  Detection is therefore
deliberately a LOW-confidence candidate unless ``--context`` supplies the
required material and the value round-trips.
"""

from __future__ import annotations

import math
from typing import Iterable, List, Sequence

from ...models import ClassifierContext, Confidence, TokenFinding
from ...registry import register

HASHIDS_ALPHABET = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890"
HASHIDS_SEPARATORS = "cfhistuCFHISTU"
RATIO_SEPARATORS = 3.5
RATIO_GUARDS = 12

SQIDS_ALPHABET = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"


def _split(text: str, splitters: str) -> Iterable[str]:
    part = ""
    for char in text:
        if char in splitters:
            yield part
            part = ""
        else:
            part += char
    yield part


def _reorder(text: str, salt: str) -> str:
    if not salt:
        return text
    chars = list(text)
    index = 0
    integer_sum = 0
    for i in range(len(chars) - 1, 0, -1):
        integer = ord(salt[index])
        integer_sum += integer
        j = (integer + index + integer_sum) % i
        chars[i], chars[j] = chars[j], chars[i]
        index = (index + 1) % len(salt)
    return "".join(chars)


def _hash(number: int, alphabet: str) -> str:
    hashed = ""
    if number < 0:
        raise ValueError("negative values are not supported")
    while True:
        hashed = alphabet[number % len(alphabet)] + hashed
        number //= len(alphabet)
        if not number:
            return hashed


def _unhash(hashed: str, alphabet: str) -> int:
    number = 0
    for char in hashed:
        number = number * len(alphabet) + alphabet.index(char)
    return number


def _ensure_length(
    encoded: str, min_length: int, alphabet: str, guards: str, values_hash: int
) -> str:
    guard_index = (values_hash + ord(encoded[0])) % len(guards)
    encoded = guards[guard_index] + encoded
    if len(encoded) < min_length:
        guard_index = (values_hash + ord(encoded[2])) % len(guards)
        encoded += guards[guard_index]
    split_at = len(alphabet) // 2
    while len(encoded) < min_length:
        alphabet = _reorder(alphabet, alphabet)
        encoded = alphabet[split_at:] + encoded + alphabet[:split_at]
        excess = len(encoded) - min_length
        if excess > 0:
            from_index = excess // 2
            encoded = encoded[from_index : from_index + min_length]
    return encoded


class HashidsCodec:
    """Small, dependency-free Hashids implementation (encode + decode)."""

    def __init__(self, salt: str = "", min_length: int = 0, alphabet: str = HASHIDS_ALPHABET):
        self._min_length = max(int(min_length), 0)
        self._salt = salt

        separators = "".join(char for char in HASHIDS_SEPARATORS if char in alphabet)
        seen = set()
        cleaned = []
        for char in alphabet:
            if char in separators or char in seen:
                continue
            seen.add(char)
            cleaned.append(char)
        alphabet = "".join(cleaned)

        len_alphabet = len(alphabet)
        len_separators = len(separators)
        if len_alphabet + len_separators < 16:
            raise ValueError("alphabet must contain at least 16 unique characters")

        separators = _reorder(separators, salt)

        min_separators = int(math.ceil(float(len_alphabet) / RATIO_SEPARATORS))
        missing = min_separators - len_separators
        if missing > 0:
            separators += alphabet[:missing]
            alphabet = alphabet[missing:]
            len_alphabet = len(alphabet)

        alphabet = _reorder(alphabet, salt)
        num_guards = int(math.ceil(float(len_alphabet) / RATIO_GUARDS))
        if len_alphabet < 3:
            guards = separators[:num_guards]
            separators = separators[num_guards:]
        else:
            guards = alphabet[:num_guards]
            alphabet = alphabet[num_guards:]

        self._alphabet = alphabet
        self._separators = separators
        self._guards = guards
        if not self._guards:
            raise ValueError("alphabet produces no guard characters")

    def encode(self, values: Sequence[int]) -> str:
        if not values:
            return ""
        values_hash = sum(value % (index + 100) for index, value in enumerate(values))
        alphabet = self._alphabet
        encoded = lottery = alphabet[values_hash % len(alphabet)]
        for index, value in enumerate(values):
            alphabet_salt = (lottery + self._salt + alphabet)[: len(alphabet)]
            alphabet = _reorder(alphabet, alphabet_salt)
            last = _hash(value, alphabet)
            encoded += last
            value %= ord(last[0]) + index
            encoded += self._separators[value % len(self._separators)]
        encoded = encoded[:-1]
        if len(encoded) >= self._min_length:
            return encoded
        return _ensure_length(
            encoded, self._min_length, alphabet, self._guards, values_hash
        )

    def decode(self, token: str) -> List[int]:
        if not token:
            return []
        parts = tuple(_split(token, self._guards))
        body = parts[1] if 2 <= len(parts) <= 3 else parts[0]
        if not body:
            return []
        lottery = body[0]
        body = body[1:]
        out: List[int] = []
        alphabet = self._alphabet
        for part in _split(body, self._separators):
            alphabet_salt = (lottery + self._salt + alphabet)[: len(alphabet)]
            alphabet = _reorder(alphabet, alphabet_salt)
            if not part:
                return []
            out.append(_unhash(part, alphabet))
        return out


class SqidsCodec:
    """Minimal Sqids codec using the standard alphabet shuffle."""

    def __init__(self, alphabet: str = SQIDS_ALPHABET, min_length: int = 0):
        if len(set(alphabet)) != len(alphabet) or len(alphabet) < 3:
            raise ValueError("invalid Sqids alphabet")
        self._min_length = max(int(min_length), 0)
        self._alphabet = self._shuffle(alphabet)

    @staticmethod
    def _shuffle(alphabet: str) -> str:
        chars = list(alphabet)
        i, j = 0, len(chars) - 1
        while j > 0:
            r = (i * j + ord(chars[i]) + ord(chars[j])) % len(chars)
            chars[i], chars[r] = chars[r], chars[i]
            i += 1
            j -= 1
        return "".join(chars)

    @staticmethod
    def _to_number(text: str, alphabet: str) -> int:
        chars = list(alphabet)
        return sum(chars.index(c) * (len(chars) ** i) for i, c in enumerate(text[::-1]))

    @staticmethod
    def _to_id(number: int, alphabet: str) -> str:
        chars: List[str] = []
        while True:
            chars.insert(0, alphabet[number % len(alphabet)])
            number //= len(alphabet)
            if not number:
                break
        return "".join(chars)

    def decode(self, token: str) -> List[int]:
        if not token or any(char not in self._alphabet for char in token):
            return []
        offset = self._alphabet.index(token[0])
        alphabet = (self._alphabet[offset:] + self._alphabet[:offset])[::-1]
        body = token[1:]
        out: List[int] = []
        while body:
            separator = alphabet[0]
            chunks = body.split(separator)
            if not chunks[0]:
                return out
            out.append(self._to_number(chunks[0], alphabet[1:]))
            if len(chunks) > 1:
                alphabet = self._shuffle(alphabet)
            body = separator.join(chunks[1:])
        return out

    def encode(self, numbers: Sequence[int]) -> str:
        if not numbers:
            return ""
        if any(number < 0 for number in numbers):
            raise ValueError("negative values are not supported")
        alphabet = self._alphabet
        offset = sum(
            ord(alphabet[value % len(alphabet)]) + index
            for index, value in enumerate(numbers)
        )
        offset = (offset + len(numbers)) % len(alphabet)
        alphabet = alphabet[offset:] + alphabet[:offset]
        prefix = alphabet[0]
        alphabet = alphabet[::-1]
        parts = [prefix]
        for index, number in enumerate(numbers):
            parts.append(self._to_id(number, alphabet[1:]))
            if index >= len(numbers) - 1:
                continue
            parts.append(alphabet[0])
            alphabet = self._shuffle(alphabet)
        token = "".join(parts)
        if self._min_length > len(token):
            token += alphabet[0]
            while self._min_length - len(token) > 0:
                alphabet = self._shuffle(alphabet)
                token += alphabet[: self._min_length - len(token)]
        return token


def _shape_candidate(raw: str) -> bool:
    if not (4 <= len(raw) <= 32):
        return False
    if not raw.isalnum():
        return False
    has_letter = any(char.isalpha() for char in raw)
    has_digit = any(char.isdigit() for char in raw)
    return has_letter and has_digit


def _context_int(ctx: ClassifierContext, key: str) -> int:
    try:
        return int(ctx.context.get(key, "0"))
    except (TypeError, ValueError):
        return 0


@register(
    "hashids",
    "short_id",
    "Hashids/Sqids: reversible obfuscation of integers; decode needs salt/alphabet",
    order=120,
)
def classify(token: str, ctx: ClassifierContext) -> List[TokenFinding]:
    raw = token.strip()
    findings: List[TokenFinding] = []
    context = ctx.context or {}

    salt = context.get("hashids_salt", context.get("hashid_salt", context.get("salt")))
    hashids_alphabet = context.get("hashids_alphabet", HASHIDS_ALPHABET)
    if salt is not None:
        try:
            codec = HashidsCodec(
                salt=salt,
                min_length=_context_int(ctx, "hashids_min_length"),
                alphabet=hashids_alphabet,
            )
            decoded = codec.decode(raw)
            round_trip = bool(decoded) and codec.encode(decoded) == raw
        except Exception:
            decoded, round_trip = [], False
        if decoded:
            findings.append(
                TokenFinding(
                    token_type="hashids",
                    family="short_id",
                    confidence=Confidence.HIGH if round_trip else Confidence.LOW,
                    reasoning=[
                        "Decoded with the Hashids salt supplied via --context.",
                        "Round-trip re-encoding matches the input."
                        if round_trip
                        else "Decoded values did not round-trip; the supplied salt or "
                        "alphabet is probably wrong.",
                        "Hashids is reversible obfuscation, not encryption.",
                    ],
                    properties={
                        "decoded_ids": decoded,
                        "round_trip": round_trip,
                        "contains_timestamp": False,
                        "time_ordered": False,
                        "reversible": True,
                    },
                )
            )

    sqids_alphabet = context.get("sqids_alphabet")
    if sqids_alphabet is not None:
        try:
            sqids = SqidsCodec(
                alphabet=sqids_alphabet,
                min_length=_context_int(ctx, "sqids_min_length"),
            )
            decoded = sqids.decode(raw)
            round_trip = bool(decoded) and sqids.encode(decoded) == raw
        except Exception:
            decoded, round_trip = [], False
        if decoded:
            findings.append(
                TokenFinding(
                    token_type="sqids",
                    family="short_id",
                    confidence=Confidence.HIGH if round_trip else Confidence.LOW,
                    reasoning=[
                        "Decoded with the Sqids alphabet supplied via --context.",
                        "Round-trip re-encoding matches the input."
                        if round_trip
                        else "Decoded values did not round-trip; the supplied alphabet "
                        "is probably wrong.",
                    ],
                    properties={
                        "decoded_ids": decoded,
                        "round_trip": round_trip,
                        "contains_timestamp": False,
                        "time_ordered": False,
                        "reversible": True,
                    },
                )
            )

    if not findings and _shape_candidate(raw):
        findings.append(
            TokenFinding(
                token_type="hashids_or_sqids",
                family="short_id",
                confidence=Confidence.LOW,
                reasoning=[
                    "Length and alphanumeric charset are compatible with Hashids/Sqids.",
                    "Many unrelated identifiers also fit this shape.",
                    "Without a salt or custom alphabet this likely represents an "
                    "obfuscated sequential integer, but decoding is not possible; "
                    "supply --context hashids_salt=... (or sqids_alphabet=...) to try.",
                ],
                properties={
                    "decode_attempted": False,
                    "salt_known": False,
                    "contains_timestamp": False,
                    "time_ordered": False,
                    "reversible": True,
                },
            )
        )

    return findings
