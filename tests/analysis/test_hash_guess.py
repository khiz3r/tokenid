import hashlib

from tokenid.analysis.hash_guess import guess_hashes
from tokenid.reporting.json_report import analysis_to_dict, dumps
from tokenid import analyze


def test_md5_of_single_context_value_matches():
    token = hashlib.md5(b"alice@example.com").hexdigest()
    matches = guess_hashes(token, {"email": "alice@example.com"})
    assert matches
    assert matches[0].algorithm == "md5"
    assert matches[0].matched is True
    assert matches[0].redacted_construction == "md5({email})"
    assert "alice@example.com" not in matches[0].redacted_construction


def test_sha256_of_concatenation_matches():
    raw = "alice" + ":" + "42"
    token = hashlib.sha256(raw.encode()).hexdigest()
    matches = guess_hashes(token, {"user": "alice", "id": "42"})
    assert any(match.matched for match in matches)


def test_template_is_configurable():
    token = hashlib.sha1(b"alice-42").hexdigest()
    context = {
        "name": "alice",
        "id": "42",
        "hash_algorithms": "sha1",
        "hash_templates": "{name}-{id}",
    }
    matches = guess_hashes(token, context)
    assert matches and matches[0].algorithm == "sha1"


def test_no_context_means_no_guess():
    assert guess_hashes("deadbeef", {}) == []


def test_context_values_are_redacted_in_report_by_default():
    token = hashlib.sha256(b"top-secret@example.com").hexdigest()
    result = analyze(token, context={"email": "top-secret@example.com"})
    payload = dumps(analysis_to_dict(result))
    assert "top-secret@example.com" not in payload
    assert "sha256({email})" in payload

    revealed = dumps(analysis_to_dict(result, include_context=True))
    assert "top-secret@example.com" in revealed
