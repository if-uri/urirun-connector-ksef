# Author: Tom Sapletta · https://tom.sapletta.com
# Part of the ifURI solution.

"""KSeF 2.0 XAdES authentication (§3, the signature variant).

Builds the ``AuthTokenRequest`` XML and signs it with an **enveloped** XML-DSig
(RSA-SHA256 over C14N) — the core of XAdES-BES. The signer/verifier round-trips
with the stdlib (`xml.etree.ElementTree.canonicalize`), no native deps.

PRODUCTION NOTE: KSeF requires a **qualified** signature/seal and the full XAdES
qualifying properties (SigningTime, SigningCertificate v2). Add those — and prefer
``xmlsec`` for canonicalization robustness — before a real PRD run. Detached
signatures are **not** accepted; enveloped/enveloping only. Identity is read from
the signing certificate.
"""

from __future__ import annotations

import base64
import hashlib
import xml.etree.ElementTree as ET
from typing import Any

DS = "http://www.w3.org/2000/09/xmldsig#"
AUTH_NS = "http://ksef.mf.gov.pl/auth/token/2.0"  # verify against openapi.json / XSD
_C14N = "http://www.w3.org/TR/2001/REC-xml-c14n-20010315"
_RSA_SHA256 = "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256"
_SHA256 = "http://www.w3.org/2001/04/xmlenc#sha256"
_ENVELOPED = "http://www.w3.org/2000/09/xmldsig#enveloped-signature"


def build_auth_token_request(challenge: str, context_nip: str,
                             subject_type: str = "certificateSubject") -> bytes:
    """The unsigned ``AuthTokenRequest`` (challenge + context + subject type)."""
    root = ET.Element(f"{{{AUTH_NS}}}AuthTokenRequest")
    ET.SubElement(root, f"{{{AUTH_NS}}}Challenge").text = challenge
    context = ET.SubElement(root, f"{{{AUTH_NS}}}ContextIdentifier")
    ET.SubElement(context, f"{{{AUTH_NS}}}Nip").text = context_nip
    ET.SubElement(root, f"{{{AUTH_NS}}}SubjectIdentifierType").text = subject_type
    return ET.tostring(root, encoding="utf-8")


def _digest_b64(text: str) -> str:
    return base64.b64encode(hashlib.sha256(text.encode("utf-8")).digest()).decode("ascii")


def _c14n(element: ET.Element) -> str:
    return ET.canonicalize(ET.tostring(element, encoding="unicode"))


def sign_xml_enveloped(xml_bytes: bytes, private_key_pem: str | bytes, cert_pem: str | bytes) -> bytes:
    """Return ``xml_bytes`` with an appended enveloped ``ds:Signature`` (RSA-SHA256)."""
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import padding

    key = serialization.load_pem_private_key(
        private_key_pem.encode() if isinstance(private_key_pem, str) else private_key_pem, password=None)
    cert = x509.load_pem_x509_certificate(cert_pem.encode() if isinstance(cert_pem, str) else cert_pem)

    root = ET.fromstring(xml_bytes)
    digest_value = _digest_b64(_c14n(root))  # enveloped: signature not yet present

    signature = ET.Element(f"{{{DS}}}Signature")
    signed_info = ET.SubElement(signature, f"{{{DS}}}SignedInfo")
    ET.SubElement(signed_info, f"{{{DS}}}CanonicalizationMethod", {"Algorithm": _C14N})
    ET.SubElement(signed_info, f"{{{DS}}}SignatureMethod", {"Algorithm": _RSA_SHA256})
    reference = ET.SubElement(signed_info, f"{{{DS}}}Reference", {"URI": ""})
    transforms = ET.SubElement(reference, f"{{{DS}}}Transforms")
    ET.SubElement(transforms, f"{{{DS}}}Transform", {"Algorithm": _ENVELOPED})
    ET.SubElement(reference, f"{{{DS}}}DigestMethod", {"Algorithm": _SHA256})
    ET.SubElement(reference, f"{{{DS}}}DigestValue").text = digest_value

    signed = key.sign(_c14n(signed_info).encode("utf-8"), padding.PKCS1v15(), hashes.SHA256())
    ET.SubElement(signature, f"{{{DS}}}SignatureValue").text = base64.b64encode(signed).decode("ascii")
    key_info = ET.SubElement(signature, f"{{{DS}}}KeyInfo")
    x509_data = ET.SubElement(key_info, f"{{{DS}}}X509Data")
    der = cert.public_bytes(serialization.Encoding.DER)
    ET.SubElement(x509_data, f"{{{DS}}}X509Certificate").text = base64.b64encode(der).decode("ascii")

    root.append(signature)  # enveloped
    return ET.tostring(root, encoding="utf-8")


def verify_xml_enveloped(signed_xml: bytes) -> bool:
    """Verify an enveloped signature produced by :func:`sign_xml_enveloped`
    (digest of the document with the signature removed + RSA-SHA256 of SignedInfo)."""
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.asymmetric import padding
    from cryptography.exceptions import InvalidSignature

    root = ET.fromstring(signed_xml)
    signature = root.find(f"{{{DS}}}Signature")
    if signature is None:
        return False
    signed_info = signature.find(f"{{{DS}}}SignedInfo")
    digest_value = signed_info.find(f"{{{DS}}}Reference/{{{DS}}}DigestValue").text
    signature_value = base64.b64decode(signature.find(f"{{{DS}}}SignatureValue").text)
    cert_b64 = signature.find(f"{{{DS}}}KeyInfo/{{{DS}}}X509Data/{{{DS}}}X509Certificate").text

    si_c14n = _c14n(signed_info)
    root.remove(signature)
    if _digest_b64(_c14n(root)) != digest_value:
        return False
    cert = x509.load_der_x509_certificate(base64.b64decode(cert_b64))
    try:
        cert.public_key().verify(signature_value, si_c14n.encode("utf-8"), padding.PKCS1v15(), hashes.SHA256())
        return True
    except InvalidSignature:
        return False


def signed_auth_request(challenge: str, context_nip: str, private_key_pem: str, cert_pem: str) -> dict[str, Any]:
    """Build + sign an AuthTokenRequest, ready to POST to ``/auth/xades-signature``."""
    unsigned = build_auth_token_request(challenge, context_nip)
    signed = sign_xml_enveloped(unsigned, private_key_pem, cert_pem)
    return {"signedXml": signed.decode("utf-8"), "contextNip": context_nip}
