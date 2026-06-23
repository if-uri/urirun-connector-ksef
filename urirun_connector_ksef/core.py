# Author: Tom Sapletta · https://tom.sapletta.com
# Part of the ifURI solution.

"""KSeF 2.0 reference connector — routes (declarative) + auth/crypto helpers.

The HTTP surface is declarative (the urirun ``fetch`` adapter resolves
``environments[<env>] + path`` and templates path params / the ``Authorization``
header). The two imperative escape hatches — the ``ksef-token`` auth handshake and
client-side AES/RSA crypto — live in :mod:`auth` and :mod:`crypto`. The access
token is addressed by reference (`getv://KSEF_ACCESS_TOKEN`), never embedded.
"""

from __future__ import annotations

from typing import Any

import urirun
from urirun.connectors import declarative

from . import auth, crypto, xades

CONNECTOR_ID = "ksef"

_BEARER = {"Authorization": "Bearer {getv:KSEF_ACCESS_TOKEN}"}

SPEC = {
    "connector": CONNECTOR_ID,
    "scheme": "ksef",
    "environments": auth.BASE_URLS,
    "routes": [
        {"uri": "ksef://{env}/auth/challenge", "method": "POST", "path": "/auth/challenge",
         "label": "Request auth challenge"},
        {"uri": "ksef://{env}/session/online/{ref}/send", "method": "POST",
         "path": "/sessions/online/{ref}/invoices", "label": "Send invoice (FA(3), encrypted)",
         "required": ["ref"], "headers": dict(_BEARER),
         "input": {"ref": {"type": "string"}, "invoiceHash": {"type": "string"},
                   "encryptedInvoiceContent": {"type": "string"}},
         "body": {"invoiceHash": "{invoiceHash}", "encryptedInvoiceContent": "{encryptedInvoiceContent}"}},
        {"uri": "ksef://{env}/session/{ref}/invoices", "method": "GET",
         "path": "/sessions/{ref}/invoices", "label": "Accepted invoices (ksefNumber)",
         "required": ["ref"], "headers": dict(_BEARER), "input": {"ref": {"type": "string"}}},
        {"uri": "ksef://{env}/session/{ref}/upo", "method": "GET",
         "path": "/sessions/{ref}/upo", "label": "Session UPO",  # verify path
         "required": ["ref"], "headers": dict(_BEARER), "input": {"ref": {"type": "string"}}},
        {"uri": "ksef://{env}/invoice/{ksefNumber}", "method": "GET",
         "path": "/invoices/{ksefNumber}", "label": "Download invoice",
         "required": ["ksefNumber"], "headers": dict(_BEARER), "input": {"ksefNumber": {"type": "string"}}},
        # batch session (§5.2): ZIP parts <=100MB, encrypted individually
        {"uri": "ksef://{env}/session/batch/open", "method": "POST", "path": "/sessions/batch",
         "label": "Open batch session", "headers": dict(_BEARER)},
        {"uri": "ksef://{env}/session/{ref}/close", "method": "POST", "path": "/sessions/{ref}/close",
         "label": "Close session", "required": ["ref"], "headers": dict(_BEARER), "input": {"ref": {"type": "string"}}},
        {"uri": "ksef://{env}/session/{ref}/failed", "method": "GET", "path": "/sessions/{ref}/invoices/failed",
         "label": "Rejected invoices", "required": ["ref"], "headers": dict(_BEARER), "input": {"ref": {"type": "string"}}},
        {"uri": "ksef://{env}/sessions/query/list", "method": "GET", "path": "/sessions",
         "label": "List sessions", "headers": dict(_BEARER)},
        # incremental invoice download (§6): pageSize <= 1000
        {"uri": "ksef://{env}/invoices/query", "method": "POST", "path": "/invoices/query",
         "label": "Query/incremental invoices", "headers": dict(_BEARER)},
        # certificates (§7): enrollment data -> CSR -> limits
        {"uri": "ksef://{env}/cert/enrollment-data", "method": "GET", "path": "/certificates/enrollments/data",
         "label": "Certificate DN data (after XAdES)", "headers": dict(_BEARER)},
        {"uri": "ksef://{env}/cert/enroll", "method": "POST", "path": "/certificates/enrollments",
         "label": "Submit CSR", "headers": dict(_BEARER)},
        {"uri": "ksef://{env}/cert/limits", "method": "GET", "path": "/certificates/limits",
         "label": "Certificate limits", "headers": dict(_BEARER)},
    ],
}


def connector_manifest() -> dict[str, Any]:
    return urirun.load_manifest(__package__)


def urirun_bindings() -> dict[str, Any]:
    return declarative.bindings_from_spec(SPEC)


def authenticate(env: str, nip: str, token: str = "", public_key: str = "", execute: bool = False,
                 *, method: str = "token", private_key: str = "", cert: str = "") -> dict[str, Any]:
    """Run (or plan) a KSeF auth handshake (``method`` = ``token`` or ``xades``)."""
    if method == "xades":
        if not (execute and private_key and cert):
            plan = auth.dry_run_plan(env, nip)
            plan["method"] = "xades"
            plan["note"] = "set --key + --cert (qualified) + --execute to sign for real (use TEST env)"
            return plan
        return auth.authenticate_xades(env, context_nip=nip, private_key_pem=private_key, cert_pem=cert)
    if not (execute and token and public_key):
        plan = auth.dry_run_plan(env, nip)
        plan["method"] = "token"
        plan["note"] = "set token + public_key + execute=True to authenticate for real (use TEST env)"
        return plan
    return auth.authenticate(env, token=token, context_nip=nip, public_key_material=public_key)


def sign_auth_request(challenge: str, nip: str, private_key_pem: str, cert_pem: str) -> dict[str, Any]:
    """Build + sign an AuthTokenRequest locally (offline XAdES demo / debugging)."""
    out = xades.signed_auth_request(challenge, nip, private_key_pem, cert_pem)
    return {"ok": True, "connector": CONNECTOR_ID, "verified": xades.verify_xml_enveloped(out["signedXml"].encode()),
            **out}


def encrypt_invoice(invoice_xml: bytes, symmetric_key: bytes | None = None) -> dict[str, Any]:
    """Encrypt one invoice (fresh AES key by default) -> send-request fields."""
    key = symmetric_key or crypto.aes_key()
    return {"ok": True, "connector": CONNECTOR_ID, **crypto.encrypt_invoice(key, invoice_xml)}


def prepare_batch(zip_bytes: bytes, symmetric_key: bytes | None = None) -> dict[str, Any]:
    """Split a ZIP into <=100MB parts and encrypt each -> fileParts metadata (§5.2)."""
    key = symmetric_key or crypto.aes_key()
    return {"ok": True, "connector": CONNECTOR_ID, **crypto.split_and_encrypt_batch(zip_bytes, key)}


def make_csr(common_name: str, *, organization: str = "", country: str = "", serial: str = "",
             key_type: str = "rsa") -> dict[str, Any]:
    """Generate a certificate-enrollment CSR (§7)."""
    subject = {"common_name": common_name}
    if organization:
        subject["organization_name"] = organization
    if country:
        subject["country_name"] = country
    if serial:
        subject["serial_number"] = serial
    return {"ok": True, "connector": CONNECTOR_ID, **crypto.generate_csr(subject, key_type=key_type)}
