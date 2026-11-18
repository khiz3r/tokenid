from tokenid.classifiers.database.firebase_pushid import classify as pushid
from tokenid.classifiers.database.objectid import classify as objectid
from tokenid.models import ClassifierContext, Confidence

CTX = ClassifierContext()


def test_objectid_known_example():
    findings = objectid("507f1f77bcf86cd799439011", CTX)
    assert findings
    finding = findings[0]
    assert finding.confidence == Confidence.HIGH
    assert finding.properties["timestamp_iso"] == "2012-10-17T21:13:27.000Z"
    assert finding.properties["counter_bits"] == 24


def test_objectid_implausible_timestamp_is_not_high():
    findings = objectid("000000000000000000000000", CTX)
    assert findings and findings[0].confidence == Confidence.MEDIUM


def test_objectid_rejects_non_hex():
    assert objectid("507f1f77bcf86cd79943901z", CTX) == []


def test_firebase_pushid_decodes_timestamp():
    findings = pushid("-Mq7Yq0xJ7X8kZ3A1b2C", CTX)
    assert findings
    assert findings[0].properties["timestamp_iso"].startswith("2021-12-05T03:07:17")
    assert findings[0].properties["random_bits"] == 72


def test_firebase_pushid_flags_shared_timestamp_window():
    samples = ["-Mq7Yq0xJ7X8kZ3A1b2C", "-Mq7Yq0xJ7X8kZ3A1b2D"]
    findings = pushid(samples[0], ClassifierContext(samples=samples))
    assert findings
    windows = findings[0].properties["shared_timestamp_windows"]
    assert windows and windows[0]["count"] == 2
