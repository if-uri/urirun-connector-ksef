# Author: Tom Sapletta · https://tom.sapletta.com
import datetime
import xml.etree.ElementTree as ET

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID

from urirun_connector_ksef import auth, core, xades


def _self_signed():
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "NIP-1234567890")])
    now = datetime.datetime(2026, 1, 1)
    cert = (x509.CertificateBuilder().subject_name(name).issuer_name(name)
            .public_key(key.public_key()).serial_number(x509.random_serial_number())
            .not_valid_before(now).not_valid_after(now + datetime.timedelta(days=365))
            .sign(key, hashes.SHA256()))
    key_pem = key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                                serialization.NoEncryption()).decode()
    cert_pem = cert.public_bytes(serialization.Encoding.PEM).decode()
    return key_pem, cert_pem


def test_auth_token_request_structure():
    xml = xades.build_auth_token_request("CH-1", "1234567890")
    root = ET.fromstring(xml)
    ns = "{http://ksef.mf.gov.pl/auth/token/2.0}"
    assert root.tag == f"{ns}AuthTokenRequest"
    assert root.find(f"{ns}Challenge").text == "CH-1"
    assert root.find(f"{ns}ContextIdentifier/{ns}Nip").text == "1234567890"


def test_sign_and_verify_round_trip():
    key_pem, cert_pem = _self_signed()
    unsigned = xades.build_auth_token_request("CH-9", "1234567890")
    signed = xades.sign_xml_enveloped(unsigned, key_pem, cert_pem)
    assert b"Signature" in signed and b"SignatureValue" in signed
    assert xades.verify_xml_enveloped(signed) is True


def test_tampering_breaks_verification():
    key_pem, cert_pem = _self_signed()
    signed = xades.sign_xml_enveloped(xades.build_auth_token_request("CH-1", "1234567890"), key_pem, cert_pem)
    tampered = signed.replace(b"1234567890", b"9999999999")
    assert xades.verify_xml_enveloped(tampered) is False


def test_xades_authenticate_flow_submits_signed_xml():
    key_pem, cert_pem = _self_signed()
    captured = {}

    def fake_http(method, url, body, headers):
        if url.endswith("/auth/challenge"):
            return 200, {"challenge": "CH-XADES"}
        if url.endswith("/auth/xades-signature"):
            captured["body"] = body
            return 202, {"referenceNumber": "REF-X", "authenticationToken": "temp"}
        if "/auth/REF-X" in url:
            return 200, {"processingCode": 200}
        if url.endswith("/auth/token/redeem"):
            return 200, {"accessToken": "JWT-x"}
        raise AssertionError(url)

    result = auth.authenticate_xades("test", context_nip="1234567890",
                                     private_key_pem=key_pem, cert_pem=cert_pem, http=fake_http)
    assert result["ok"] and result["method"] == "xades" and result["accessToken"] == "JWT-x"
    assert isinstance(captured["body"], str) and "Signature" in captured["body"]   # raw signed XML
    assert xades.verify_xml_enveloped(captured["body"].encode()) is True


def test_core_sign_auth_request_self_verifies():
    key_pem, cert_pem = _self_signed()
    out = core.sign_auth_request("CH-1", "1234567890", key_pem, cert_pem)
    assert out["ok"] and out["verified"] is True
