from tokenid.classifiers.distributed.ksuid import classify as ksuid
from tokenid.classifiers.distributed.snowflake import classify as snowflake
from tokenid.classifiers.distributed.ulid import classify as ulid
from tokenid.models import ClassifierContext, Confidence

CTX = ClassifierContext()


def test_ulid_decodes_known_timestamp():
    findings = ulid("01ARZ3NDEKTSV4RRFFQ69G5FAV", CTX)
    assert findings
    finding = findings[0]
    assert finding.confidence == Confidence.HIGH
    assert finding.properties["timestamp_iso"] == "2016-07-30T23:54:10.259Z"
    assert finding.properties["random_bits"] == 80


def test_ulid_lowercase_is_lower_confidence():
    findings = ulid("01arz3ndektsv4rrffq69g5fav", CTX)
    assert findings and findings[0].confidence == Confidence.MEDIUM


def test_ulid_rejects_overflowing_first_char():
    # 26 Crockford chars but the value needs more than 128 bits.
    assert ulid("8ZZZZZZZZZZZZZZZZZZZZZZZZZ", CTX) == []


def test_ksuid_decodes_known_example():
    findings = ksuid("0ujtsYcgvSTl8PAuAdqWYSMnLOv", CTX)
    assert findings
    assert findings[0].properties["timestamp_iso"] == "2017-10-10T04:00:47.000Z"
    assert findings[0].properties["time_ordered"] is True


def test_ksuid_rejects_wrong_length():
    assert ksuid("0ujtsYcgvSTl8PAuAdqWYSMnLO", CTX) == []


def test_snowflake_epoch_ambiguity_is_reported():
    findings = snowflake("175928847299117063", CTX)
    assert findings
    assert {finding.properties["epoch"] for finding in findings} >= {
        "twitter",
        "discord",
    }
    assert all(finding.properties["contains_timestamp"] for finding in findings)


def test_snowflake_rejects_non_63_bit():
    assert snowflake("9999999999999999999", CTX) == []
