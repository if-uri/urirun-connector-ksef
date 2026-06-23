# Author: Tom Sapletta · https://tom.sapletta.com
# Part of the ifURI solution.

"""KSeF 2.0 ``ksef-token`` authentication flow (§3 of the connector spec).

Auth is decoupled from sessions in 2.0 and yields a JWT pair. This implements the
token variant: challenge -> RSA-OAEP encrypt ``token|timestampMs`` -> submit ->
poll -> redeem -> ``accessToken``. The HTTP client is injectable so the flow is
unit-tested offline; the security-critical invariant (the KSeF token is **never
sent in plaintext**, only RSA-OAEP encrypted) is asserted in the tests.

JSON field names marked ``# verify`` should be confirmed against the live
``openapi.json`` (https://api-test.ksef.mf.gov.pl/docs/v2/openapi.json) before a
production run; the shape is centralised here so that is a one-file change.
"""

from __future__ import annotations

import base64
import json
import urllib.request
from typing import Any, Callable

from . import crypto, xades

BASE_URLS = {
    "test": "https://api-test.ksef.mf.gov.pl/api/v2",
    "demo": "https://api-demo.ksef.mf.gov.pl/api/v2",   # verify host
    "prod": "https://api.ksef.mf.gov.pl/api/v2",
}

HttpClient = Callable[[str, str, dict | None, dict | None], tuple]


def _urllib_http(method: str, url: str, body, headers: dict | None) -> tuple:
    # str body is raw XML (the XAdES signature submit); dict body is JSON
    if isinstance(body, str):
        data, content_type = body.encode("utf-8"), "application/xml"
    elif body is not None:
        data, content_type = json.dumps(body).encode("utf-8"), "application/json"
    else:
        data, content_type = None, None
    request = urllib.request.Request(url, data=data, method=method, headers=headers or {})
    if content_type:
        request.add_header("Content-Type", content_type)
    with urllib.request.urlopen(request, timeout=30) as response:
        text = response.read().decode("utf-8") or "{}"
        return int(response.status), json.loads(text)


def _poll_and_redeem(base: str, call: HttpClient, reference: str, temp_token: str | None, poll_max: int) -> dict:
    auth_header = {"Authorization": f"Bearer {temp_token}"} if temp_token else None
    for _ in range(poll_max):
        _, status_resp = call("GET", f"{base}/auth/{reference}", None, auth_header)
        code = status_resp.get("processingCode") or (status_resp.get("status") or {}).get("code")
        if code in (200, "200", "success", "Authenticated"):  # verify
            break
    else:
        return {"ok": False, "connector": "ksef", "error": "authentication did not reach success", "referenceNumber": reference}
    _, redeem_resp = call("POST", f"{base}/auth/token/redeem", None, auth_header)
    return {"ok": True, "connector": "ksef", "referenceNumber": reference,
            "accessToken": redeem_resp.get("accessToken"), "refreshToken": redeem_resp.get("refreshToken")}


def dry_run_plan(env: str, context_nip: str) -> dict[str, Any]:
    base = BASE_URLS[env]
    return {"ok": True, "connector": "ksef", "dryRun": True, "env": env, "context": context_nip,
            "steps": [f"GET {base}/security/public-key-certificates",
                      f"POST {base}/auth/challenge",
                      "RSA-OAEP encrypt token|timestampMs (token stays secret)",
                      f"POST {base}/auth/ksef-token",
                      f"GET {base}/auth/{{referenceNumber}} (poll)",
                      f"POST {base}/auth/token/redeem -> accessToken"]}


def authenticate(env: str, *, token: str, context_nip: str, public_key_material: bytes | str,
                 http: HttpClient | None = None, poll_max: int = 12) -> dict[str, Any]:
    """Run the ksef-token handshake and return ``{accessToken, refreshToken, ...}``."""
    base = BASE_URLS[env]
    call = http or _urllib_http
    pub = crypto.load_public_key(public_key_material)

    context = {"type": "onip", "value": context_nip}  # verify: ContextIdentifier shape

    _, challenge_resp = call("POST", f"{base}/auth/challenge", {"contextIdentifier": context}, None)
    challenge = challenge_resp["challenge"]                       # verify
    timestamp = challenge_resp.get("timestampMs") or challenge_resp.get("timestamp")  # verify

    # the token never travels in plaintext: RSA-OAEP(token|timestampMs)
    encrypted_token = base64.b64encode(
        crypto.rsa_oaep_encrypt(pub, f"{token}|{timestamp}".encode("utf-8"))
    ).decode("ascii")

    submit_body = {"challenge": challenge, "encryptedToken": encrypted_token, "contextIdentifier": context}  # verify
    _, submit_resp = call("POST", f"{base}/auth/ksef-token", submit_body, None)
    reference = submit_resp.get("referenceNumber") or submit_resp.get("authenticationToken")  # verify
    result = _poll_and_redeem(base, call, reference, submit_resp.get("authenticationToken"), poll_max)
    result["env"] = env
    return result


def authenticate_xades(env: str, *, context_nip: str, private_key_pem: str, cert_pem: str,
                       http: HttpClient | None = None, poll_max: int = 12) -> dict[str, Any]:
    """XAdES variant (§3): sign the AuthTokenRequest and submit the enveloped XML.
    Unlike the token, only requesting a KSeF certificate (CSR) is allowed after this
    XAdES login. Identity is read from the signing certificate."""
    base = BASE_URLS[env]
    call = http or _urllib_http
    context = {"type": "onip", "value": context_nip}  # verify

    _, challenge_resp = call("POST", f"{base}/auth/challenge", {"contextIdentifier": context}, None)
    challenge = challenge_resp["challenge"]  # verify

    signed = xades.sign_xml_enveloped(
        xades.build_auth_token_request(challenge, context_nip), private_key_pem, cert_pem)
    _, submit_resp = call("POST", f"{base}/auth/xades-signature", signed.decode("utf-8"), None)  # raw XML body
    reference = submit_resp.get("referenceNumber") or submit_resp.get("authenticationToken")  # verify
    result = _poll_and_redeem(base, call, reference, submit_resp.get("authenticationToken"), poll_max)
    result["env"] = env
    result["method"] = "xades"
    return result
