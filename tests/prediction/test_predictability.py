from tokenid import analyze, compare
from tokenid.models import Confidence


def test_random_uuid_is_low_predictability():
    result = analyze("550e8400-e29b-41d4-a716-446655440000")
    assert result.predictability.level == Confidence.LOW
    assert "not proof" in result.predictability.disclaimer


def test_time_ordered_uuid_is_at_least_medium():
    result = analyze("1ec9414c-232a-6b00-b3c8-9f6bdeced846")
    assert result.predictability.level in (Confidence.MEDIUM, Confidence.HIGH)
    assert any("time-ordered" in item.description for item in result.predictability.evidence)


def test_counter_compare_is_high():
    result = compare(["ID-0001", "ID-0002", "ID-0003"])
    assert result.predictability.level == Confidence.HIGH
    assert any(item.source == "sequence_analysis" for item in result.predictability.evidence)
    assert "not proof" in result.predictability.disclaimer


def test_unknown_varying_is_not_overstated():
    result = compare(["TOKEN-A8F92D", "TOKEN-B7F31A", "TOKEN-C6E54B"])
    assert result.predictability.level == Confidence.LOW
    assert result.predictability.disclaimer


def test_exact_hash_match_is_high_predictability():
    import hashlib

    token = hashlib.md5(b"known@example.com").hexdigest()
    result = analyze(token, context={"email": "known@example.com"})
    assert result.predictability.level == Confidence.HIGH
    assert any(item.source == "hash_guess" for item in result.predictability.evidence)


def test_compare_exact_hash_match_is_high_without_variation():
    import hashlib

    token = hashlib.md5(b"known@example.com").hexdigest()
    result = compare([token, token], context={"email": "known@example.com"})
    assert result.predictability.level == Confidence.HIGH
    assert any(item.source == "hash_guess" for item in result.predictability.evidence)


def test_snowflake_epoch_ambiguity_does_not_stack_evidence():
    result = analyze("175928847299117063")
    assert result.predictability.level != Confidence.HIGH
    assert sum(
        1 for item in result.predictability.evidence
        if item.source == "classifier:snowflake"
    ) == 1
