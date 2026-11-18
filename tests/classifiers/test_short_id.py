from tokenid.classifiers.short_id.cuid import classify as cuid
from tokenid.classifiers.short_id.hashids import classify as hashids
from tokenid.models import ClassifierContext, Confidence

CTX = ClassifierContext()


def test_cuid_v1_known_example():
    findings = cuid("cjld2cjxh0000qzrmn831i7rn", CTX)
    assert findings
    v1 = [f for f in findings if f.token_type == "cuid_v1"][0]
    assert v1.confidence == Confidence.HIGH
    assert v1.properties["time_ordered"] is True


def test_cuid2_known_example_is_hash_based():
    findings = cuid("tz4a98xxat96iws9zmbrgj3a", CTX)
    assert findings
    v2 = [f for f in findings if f.token_type == "cuid2"][0]
    assert v2.properties["time_ordered"] is False


def test_hashids_without_salt_is_low_confidence_only():
    findings = hashids("NkK9", CTX)
    assert findings
    assert all(f.confidence == Confidence.LOW for f in findings)
    assert findings[0].properties["decode_attempted"] is False


def test_hashids_with_salt_decodes_and_round_trips():
    findings = hashids(
        "NkK9", ClassifierContext(context={"hashids_salt": "this is my salt"})
    )
    assert findings
    finding = findings[0]
    assert finding.token_type == "hashids"
    assert finding.confidence == Confidence.HIGH
    assert finding.properties["decoded_ids"] == [12345]
    assert finding.properties["round_trip"] is True


def test_hashids_wrong_salt_does_not_claim_high():
    findings = hashids(
        "NkK9", ClassifierContext(context={"hashids_salt": "wrong salt"})
    )
    assert findings
    assert findings[0].confidence == Confidence.LOW
    assert findings[0].properties["round_trip"] is False


def test_sqids_decodes_with_supplied_alphabet():
    alphabet = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
    findings = hashids(
        "86Rf07", ClassifierContext(context={"sqids_alphabet": alphabet})
    )
    assert findings
    sqids = [f for f in findings if f.token_type == "sqids"]
    assert sqids and sqids[0].properties["decoded_ids"] == [1, 2, 3]


def test_sqids_min_length_padding_round_trips():
    alphabet = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
    findings = hashids(
        "86Rf07xd",
        ClassifierContext(context={"sqids_alphabet": alphabet, "sqids_min_length": "8"}),
    )
    sqids = [f for f in findings if f.token_type == "sqids"]
    assert sqids
    assert sqids[0].properties["decoded_ids"] == [1, 2, 3]
    assert sqids[0].properties["round_trip"] is True


def test_hashids_min_length_padding_round_trips():
    findings = hashids(
        "gB0NV05e",
        ClassifierContext(
            context={"hashids_salt": "this is my salt", "hashids_min_length": "8"}
        ),
    )
    assert findings
    assert findings[0].token_type == "hashids"
    assert findings[0].properties["decoded_ids"] == [1]
    assert findings[0].properties["round_trip"] is True
