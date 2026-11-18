# tokenid

`tokenid` is an offline token/identifier classifier and predictability analyzer
for authorized bug bounty and web security testing (HackerOne/Bugcrowd scope
only).

It answers three separate questions:

1. **Identification** — what family/shape is this token, with confidence and
   reasoning.
2. **Behaviour** — across multiple samples, which positions are fixed, which
   vary, and what structure do they form.
3. **Predictability** — is there evidence that generation is guessable?

A detected pattern is **evidence, not proof** that a server accepts guessed
values. Every predictability verdict says this explicitly.

## Scope

In scope:

- UUID v1/v4/v6/v7, ULID, KSUID, Snowflake-style IDs
- MongoDB ObjectId, Firebase push IDs
- Relay/GraphQL global IDs (`gid://...`, base64 `Type:id`)
- CUID/CUID2, Hashids/Sqids (detect-only without a salt/alphabet)
- Hash-shaped values, encodings, decimal integers
- Multi-sample positional comparison, counters, timestamps, correlations,
  entropy, and optional hash-construction guessing from `--context`

Explicitly out of scope:

- JWT/JWE/PASETO
- Burp Suite integration
- API key / secret detection
- Any network request. `tokenid` is pure offline analysis.

## Install

```bash
pip install -e .
```

The package has **no runtime dependencies** beyond the Python standard library
(Python 3.9+). Development tests use `pytest`.

## CLI

```bash
tokenid analyze 550e8400-e29b-41d4-a716-446655440000
tokenid compare samples.txt
tokenid decode NDg2NTZjNmM2Zg==
tokenid inspect 01ARZ3NDEKTSV4RRFFQ69G5FAV
tokenid entropy abc123
cat tokens.txt | tokenid batch
```

Shared flags:

| Flag | Meaning |
|---|---|
| `--format text\|json` | Output format (default `text`) |
| `-o FILE` | Write the report to a file |
| `--context KEY=VALUE` | Context value for hash guessing (repeatable) |
| `--show-context` | Include context values in the report |
| `--show-token` | Include full token/sample values in the report |
| `--color auto\|always\|never` | Colorize text output (default `auto`) |

Color is used automatically only on a terminal. `--color always` forces it,
`--color never` disables it, and `NO_COLOR` is respected.

By default, tokens, decoded text, and context values are **redacted** in
reports. Short fixed structural prefixes/suffixes may be shown to describe the
shape, but full samples and decoded content require `--show-token`. Explicit
`tokenid decode` is the exception: decoding is its purpose, so it shows the
decoded output while still redacting binary intermediates. The library result
holds the original in memory; serializers only include it when explicitly
asked.

`compare` accepts a file with one token per line, or `-` for stdin. Blank lines
are ignored.

### Hashids / Sqids decoding

Detection without key material is intentionally LOW confidence:

```bash
tokenid analyze NkK9
# LOW: likely obfuscated sequential integer, salt unknown
```

Supply the salt to decode and round-trip verify:

```bash
tokenid analyze NkK9 --context hashids_salt='this is my salt'
```

For Sqids:

```bash
tokenid analyze 86Rf07 --context sqids_alphabet='abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789'
```

### Hash guessing

```bash
tokenid analyze c160f8cc69a4f0bf2b0362752353d060 \
  --context email=alice@example.com
```

`--context` values are never printed unless `--show-context` is passed.

## Library API

```python
from tokenid import analyze, compare, decode

result = analyze("550e8400-e29b-41d4-a716-446655440000")
result.candidates          # list[TokenFinding], sorted by confidence
result.entropy             # EntropyStats
result.predictability      # Predictability

comparison = compare(["USER-000001-END", "USER-000002-END"])
comparison.structure       # "PREFIX + COUNTER + SUFFIX"
comparison.fixed_segments
comparison.varying_segments
comparison.predictability

chain = decode("NDg2NTZjNmM2Zg==")
chain.encodings            # ["base64", "hex"]
chain.final_preview        # "Hello"
```

Library-only use never imports the CLI.

## Design notes

- Every classifier returns zero or more `TokenFinding` candidates with a
  confidence and reasoning. There is no single hard guess.
- `TokenFinding.properties` is strictly structural (`contains_timestamp`,
  `time_ordered`, `random_bits`, ...). Security conclusions live only in
  `tokenid.prediction.predictability`.
- A varying sample region is labelled `unknown_varying` until a concrete
  pattern (counter, timestamp, encoding) matches. It is never silently called
  "random".
- Entropy reports theoretical, observed, and bias-corrected estimated values.
  "Actual" source entropy is `None`; it cannot be measured from one token, and
  none of these values is a bit-security guarantee.
- Recursive decoding enforces a maximum depth, maximum output size, and cycle
  detection. Malformed input cannot crash analysis.
- Classifiers are discovered by dropping a module into `tokenid/classifiers/`
  and decorating a `classify(token, ctx)` function with
  `tokenid.registry.register(...)`.

## Tests

```bash
pytest
```

Tests include known-good fixtures, known-bad fixtures, explicit
false-positive cases, redaction checks, and CLI smoke tests.

## License

MIT.
