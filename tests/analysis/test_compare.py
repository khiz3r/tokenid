from tokenid import compare
from tokenid.analysis.correlation import find_correlations


def test_counter_structure_and_predictability():
    result = compare(["ITEM-0001-END", "ITEM-0002-END", "ITEM-0003-END"])
    assert result.structure == "PREFIX + COUNTER + SUFFIX"
    assert result.fixed_segments
    assert result.varying_segments
    counter = result.varying_segments[0]
    assert counter.kind == "counter"
    assert counter.properties["step"] == 1
    assert result.predictability.level.value == "HIGH"
    assert any("not proof" in item.description or "not proof" in result.predictability.disclaimer
               for item in result.predictability.evidence)


def test_timestamp_analysis_correlates_numeric_region():
    samples = ["T-1700000000-X", "T-1700000123-X", "T-1700000246-X"]
    result = compare(samples)
    assert any(group.get("timestamp") for group in result.numeric_groups)
    assert any(hit.unit == "seconds" for hit in result.timestamp_findings)
    assert result.predictability.level.value in ("MEDIUM", "HIGH")


def test_varying_is_not_labelled_random():
    result = compare(
        [
            "USER-A8F92D",
            "USER-B7F31A",
            "USER-C6E54B",
        ]
    )
    assert result.varying_segments
    assert all(segment.kind != "random" for segment in result.varying_segments)
    assert any("unknown" in segment.kind or segment.kind in ("hex_varying",)
               for segment in result.varying_segments)
    assert result.predictability.level.value == "LOW"


def test_identical_samples_are_constant():
    result = compare(["same-token", "same-token", "same-token"])
    assert result.structure == "CONSTANT"
    assert result.varying_segments == []
    assert result.predictability.level.value == "LOW"


def test_numeric_group_extraction_ignores_random_hex_region():
    result = compare(["USER-000001-A8F92D", "USER-000002-B7F31A", "USER-000003-C6E54B"])
    # Only the real counter group survives; digits inside the hex suffix are skipped.
    for group in result.numeric_groups:
        values = group["values"]
        assert not any(100000 <= value <= 999999 for value in values)


def test_context_vector_correlation():
    samples = ["X-10", "X-20", "X-30"]
    result = compare(samples, context={"user_id": "10,20,30"})
    assert any(
        correlation.kind == "context_match"
        for correlation in result.correlations
    )


def test_correlation_function_directly():
    groups = [
        {"field": "a", "values": [10, 20, 30]},
        {"field": "b", "values": [11, 21, 31]},
    ]
    findings = find_correlations(groups, [], {}, sample_count=3)
    assert any(finding.kind == "co_vary" for finding in findings)

    proportional = [
        {"field": "a", "values": [10, 20, 30]},
        {"field": "b", "values": [100, 200, 300]},
    ]
    findings = find_correlations(proportional, [], {}, sample_count=3)
    assert any(finding.kind == "proportional" for finding in findings)


def test_length_variation_is_handled():
    result = compare(["ABC-1", "ABC-22", "ABC-333"])
    assert len(set(result.lengths)) == 3
    assert any("different lengths" in note for note in result.notes)


def test_length_variation_with_empty_varying_slice_does_not_crash():
    result = compare(["ABX", "ABX1", "ABX22"])
    assert result.structure == "PREFIX + UNKNOWN_VARYING"
    assert result.predictability is not None


def test_time_ordered_classifier_with_unclassified_varying_region():
    samples = [
        "507f1f77bcf86cd799439011",
        "507f2000bcf86cd799439011",
        "507f3a12bcf86cd799439011",
    ]
    result = compare(samples)
    assert result.predictability.level.value in ("MEDIUM", "HIGH")
    assert any(
        item.source.startswith("classifier:") and "time-ordered" in item.description
        for item in result.predictability.evidence
    )


def test_compare_keeps_distinct_epoch_candidates():
    result = compare(
        [
            "175928847299117063",
            "175928847299117064",
            "175928847299117065",
        ]
    )
    snowflakes = [c for c in result.candidates if c.token_type == "snowflake"]
    assert len(snowflakes) >= 2
    assert {c.properties.get("epoch") for c in snowflakes} >= {"twitter", "discord"}
