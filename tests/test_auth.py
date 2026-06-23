# Author: Tom Sapletta · https://tom.sapletta.com
import base64

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa

from urirun_connector_ksef import auth, core


def _keypair():
    private = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    pem = private.public_key().public_bytes(serialization.Encoding.PEM,
                                            serialization.PublicFormat.SubjectPublicKeyInfo)
    return private, pem


def test_token_is_never_sent_in_plaintext():
    private, pem = _keypair()
    token = "KSEF-TOKEN-SECRET-do-not-leak"
    captured = {}

    def fake_http(method, url, body, headers):
        if url.endswith("/auth/challenge"):
            return 200, {"challenge": "CH-1", "timestampMs": 1700000000000}
        if url.endswith("/auth/ksef-token"):
            captured["submit"] = body
            return 202, {"referenceNumber": "REF-1", "authenticationToken": "temp-xyz"}
        if "/auth/REF-1" in url:
            return 200, {"processingCode": 200}
        if url.endswith("/auth/token/redeem"):
            return 200, {"accessToken": "JWT-access", "refreshToken": "JWT-refresh"}
        raise AssertionError(url)

    result = auth.authenticate("test", token=token, context_nip="1234567890",
                               public_key_material=pem, http=fake_http)
    assert result["ok"] and result["accessToken"] == "JWT-access"

    submit = captured["submit"]
    assert token not in str(submit)                       # plaintext token must not appear
    decrypted = private.decrypt(base64.b64decode(submit["encryptedToken"]),
                                padding.OAEP(mgf=padding.MGF1(hashes.SHA256()),
                                             algorithm=hashes.SHA256(), label=None))
    assert decrypted == f"{token}|1700000000000".encode()  # server-side it decrypts to token|timestamp


def test_authenticate_dry_run_without_credentials():
    plan = core.authenticate("test", "1234567890")
    assert plan["dryRun"] is True
    assert any("challenge" in step for step in plan["steps"])
    assert "KSEF-TOKEN" not in str(plan)
