import base64

from tokenid.classifiers.application.relay_style_id import classify
from tokenid.models import ClassifierContext, Confidence

CTX = ClassifierContext()


def test_shopify_gid_is_plaintext():
    findings = classify("gid://shopify/Product/1234567890", CTX)
    assert findings
    props = findings[0].properties
    assert findings[0].confidence == Confidence.HIGH
    assert props["scheme"] == "gid"
    assert props["platform"] == "shopify"
    assert props["resource_type"] == "Product"
    assert props["raw_id"] == "1234567890"
    assert props["is_encrypted"] is False
    assert props["is_plaintext"] is True


def test_github_node_id_decodes():
    token = base64.b64encode(b"04:User1").decode()
    findings = classify(token, CTX)
    assert findings
    props = findings[0].properties
    assert props["scheme"] == "relay_global_id"
    assert props["platform"] == "github_like"
    assert props["raw_id"] == "User1"
    assert props["is_encrypted"] is False


def test_plain_base64_without_type_prefix_is_not_a_relay_id():
    token = base64.b64encode(b"just some text without a colon").decode()
    assert classify(token, CTX) == []


def test_gid_uri_with_wrong_shape_is_rejected():
    assert classify("gid://shopify/Product", CTX) == []
