from tokenid.classifiers.encoding_classifier import classify as encoding
from tokenid.classifiers.encoding_classifier import decode_chain
from tokenid.classifiers.hash_classifier import classify as hashes
from tokenid.classifiers.numeric_classifier import classify as numeric
from tokenid.models import ClassifierContext, Confidence

CTX = ClassifierContext()


def test_md5_shape_is_medium_and_unverified():
    findings = hashes("d41d8cd98f00b204e9800998ecf8427e", CTX)
    assert findings
    finding = findings[0]
    assert finding.token_type == "md5"
    assert finding.confidence == Confidence.MEDIUM
    assert finding.properties["content_verified"] is False


def test_32_hex_false_positive_is_still_a_candidate_not_high():
    # Not derived from a known digest; shape alone must not produce HIGH.
    findings = hashes("0123456789abcdef0123456789abcdef", CTX)
    assert findings and findings[0].confidence != Confidence.HIGH


def test_hash_rejects_wrong_charset_and_length():
    assert hashes("g" * 32, CTX) == []
    assert hashes("a" * 31, CTX) == []


def test_base64_decode_and_classification():
    findings = encoding("SGVsbG8gV29ybGQ=", CTX)
    assert findings
    assert findings[0].properties["encodings"] == ["base64"]
    assert "Hello World" in findings[0].properties["decoded_preview"]


def test_recursive_decode_base64_then_hex():
    chain = decode_chain("NDg2NTZjNmM2Zg==", allow_binary=True)
    assert [step.encoding for step in chain.steps] == ["base64", "hex"]
    assert chain.final_preview == "Hello"


def test_hex_that_is_actually_a_hash_is_not_claimed_as_encoding():
    # 32 hex decodes to binary, so analysis-time encoding detection ignores it.
    assert encoding("d41d8cd98f00b204e9800998ecf8427e", CTX) == []


def test_url_encoding_decode():
    findings = encoding("hello%20world", CTX)
    assert findings
    assert findings[0].properties["encodings"] == ["url"]


def test_decode_respects_max_depth():
    token = "Hello"
    for _ in range(4):
        import base64

        token = base64.b64encode(token.encode()).decode()
    chain = decode_chain(token, max_depth=2)
    assert len(chain.steps) <= 2


def test_garbage_input_does_not_crash():
    for token in ("", "%", "====", "0x", "\x00\x01", "!!!", "a" * 5000):
        result = decode_chain(token)
        assert result.depth <= 5


def test_numeric_timestamp_and_small_integer():
    ts = numeric("1699999999", CTX)[0]
    assert ts.properties["timestamp_units"]
    assert ts.properties["contains_timestamp"] is True

    small = numeric("123", CTX)[0]
    assert small.properties["is_small_integer"] is True
    assert small.properties["contains_timestamp"] is False


def test_numeric_rejects_non_integer():
    assert numeric("12a3", CTX) == []


def test_base32_unpadded_lengths_decode():
    chain = decode_chain("MZXW6YTBOI", allow_binary=True)
    assert [step.encoding for step in chain.steps] == ["base32"]
    assert chain.final_preview == "foobar"
