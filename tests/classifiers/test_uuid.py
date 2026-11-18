from tokenid.classifiers.uuid.uuid_v1 import classify as v1
from tokenid.classifiers.uuid.uuid_v4 import classify as v4
from tokenid.classifiers.uuid.uuid_v6 import classify as v6
from tokenid.classifiers.uuid.uuid_v7 import classify as v7
from tokenid.models import ClassifierContext, Confidence

CTX = ClassifierContext()

V1 = "c232ab00-9414-11ec-b3c8-9f6bdeced846"
V4 = "550e8400-e29b-41d4-a716-446655440000"
V6 = "1ec9414c-232a-6b00-b3c8-9f6bdeced846"
V7 = "01890a5d-ac96-774b-bcce-b302099a8057"


def test_uuid_v1_valid_has_timestamp():
    findings = v1(V1, CTX)
    assert findings
    finding = findings[0]
    assert finding.confidence == Confidence.HIGH
    assert finding.properties["contains_timestamp"] is True
    assert finding.properties["time_ordered"] is True
    assert finding.properties["timestamp_iso"] == "2022-02-22T19:22:22.000Z"


def test_uuid_v1_rejects_v4():
    assert v1(V4, CTX) == []


def test_uuid_v4_valid_and_rejects_v1():
    findings = v4(V4, CTX)
    assert findings and findings[0].confidence == Confidence.HIGH
    assert findings[0].properties["time_ordered"] is False
    assert v4(V1, CTX) == []


def test_uuid_v4_invalid_variant_downgrades():
    # Fourth group begins with 0 -> NCS/legacy variant, not RFC 4122.
    findings = v4("550e8400-e29b-41d4-0716-446655440000", CTX)
    assert findings
    assert findings[0].confidence == Confidence.LOW


def test_uuid_v6_valid():
    findings = v6(V6, CTX)
    assert findings and findings[0].confidence == Confidence.HIGH
    assert findings[0].properties["time_ordered"] is True


def test_uuid_v7_valid():
    findings = v7(V7, CTX)
    assert findings and findings[0].confidence == Confidence.HIGH
    assert findings[0].properties["contains_timestamp"] is True


def test_uuid_cross_rejection():
    assert v6(V7, CTX) == []
    assert v7(V6, CTX) == []
