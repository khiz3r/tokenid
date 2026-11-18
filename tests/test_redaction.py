import hashlib

from tokenid import analyze, compare
from tokenid.reporting.json_report import (
    analysis_to_dict,
    compare_to_dict,
    dumps,
    entropy_to_dict,
)


def test_numeric_token_is_redacted_by_default():
    token = "1699999999"
    payload = dumps(analysis_to_dict(analyze(token)))
    assert token not in payload
    assert payload.count("16...99") >= 2
    assert "<redacted>" in payload


def test_numeric_token_is_revealed_on_request():
    token = "1699999999"
    payload = dumps(analysis_to_dict(analyze(token), include_token=True))
    assert token in payload


def test_entropy_charset_is_redacted_by_default():
    stats = analyze("1234567890").entropy
    assert stats is not None
    payload = entropy_to_dict(stats)
    assert payload["charset"] == "<redacted>"
    assert payload["char_frequencies"] == {}
    revealed = entropy_to_dict(stats, include_token=True)
    assert "0" in revealed["charset"]


def test_compare_redacts_small_sample_values_by_default():
    samples = ["ID-0001", "ID-0002", "ID-0003"]
    payload = dumps(compare_to_dict(compare(samples)))
    for sample in samples:
        assert sample not in payload
    revealed = dumps(compare_to_dict(compare(samples), include_token=True))
    assert samples[-1] in revealed


def test_hash_match_hex_duplicates_are_collapsed():
    token = hashlib.md5(b"alice@example.com").hexdigest()
    result = analyze(token, context={"email": "alice@example.com"})
    assert len(result.hash_matches) == 1
    payload = dumps(analysis_to_dict(result))
    assert "alice@example.com" not in payload
    assert "md5({email})" in payload


def test_hyphenless_uuid_is_preferred_over_hash_shape():
    result = analyze("550e8400e29b41d4a716446655440000")
    assert result.best_candidate is not None
    assert result.best_candidate.token_type == "uuid_v4"


def test_decode_binary_output_is_redacted_by_default():
    token = "d41d8cd98f00b204e9800998ecf8427e"
    from tokenid import decode
    from tokenid.reporting.json_report import decode_to_dict

    payload = dumps(decode_to_dict(decode(token)))
    assert token not in payload
    assert "<redacted>" in payload
    revealed = dumps(decode_to_dict(decode(token), include_token=True))
    assert token in revealed


def test_analysis_hides_decoded_text_by_default():
    import base64

    from tokenid import analyze
    from tokenid.reporting.json_report import analysis_to_dict

    token = base64.b64encode(b"secret-value").decode()
    payload = dumps(analysis_to_dict(analyze(token)))
    assert "secret-value" not in payload
    revealed = dumps(analysis_to_dict(analyze(token), include_token=True))
    assert "secret-value" in revealed


def test_decode_json_can_reveal_the_full_original():
    from tokenid import decode
    from tokenid.reporting.json_report import decode_to_dict

    token = "SGVsbG8gV29ybGQ="
    hidden = decode_to_dict(decode(token))
    assert "original" not in hidden
    revealed = decode_to_dict(decode(token), include_token=True)
    assert revealed["original"] == token
