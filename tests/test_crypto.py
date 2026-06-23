# Author: Tom Sapletta · https://tom.sapletta.com
import base64
import hashlib

from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes, serialization

from urirun_connector_ksef import crypto


def test_aes_cbc_round_trip_with_iv_prefix():
    key = crypto.aes_key()
    assert len(key) == 32
    plaintext = b"<Faktura>FA(3)</Faktura>"
    blob = crypto.encrypt_aes_cbc(key, plaintext)
    assert blob[:16] != plaintext[:16]                 # IV prefix, not plaintext
    assert crypto.decrypt_aes_cbc(key, blob) == plaintext
    assert crypto.encrypt_aes_cbc(key, plaintext) != blob   # fresh IV each call


def test_sha256_matches_hashlib():
    data = b"invoice-bytes"
    assert crypto.sha256(data) == hashlib.sha256(data).hexdigest()
    assert crypto.sha256_b64(data) == base64.b64encode(hashlib.sha256(data).digest()).decode()


def test_rsa_oaep_wrap_unwrap():
    private = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    pem = private.public_key().public_bytes(serialization.Encoding.PEM,
                                            serialization.PublicFormat.SubjectPublicKeyInfo)
    sym = crypto.aes_key()
    wrapped = crypto.rsa_oaep_encrypt(crypto.load_public_key(pem), sym)
    unwrapped = private.decrypt(wrapped, padding.OAEP(mgf=padding.MGF1(hashes.SHA256()),
                                                      algorithm=hashes.SHA256(), label=None))
    assert unwrapped == sym


def test_encrypt_invoice_fields():
    key = crypto.aes_key()
    xml = b"<Faktura/>"
    fields = crypto.encrypt_invoice(key, xml)
    assert fields["invoiceHash"] == crypto.sha256_b64(xml)
    assert fields["invoiceSize"] == len(xml)
    enc = base64.b64decode(fields["encryptedInvoiceContent"])
    assert crypto.decrypt_aes_cbc(key, enc) == xml
    assert fields["encryptedInvoiceHash"] == crypto.sha256_b64(enc)


def test_batch_split_and_encrypt_round_trip():
    key = crypto.aes_key()
    data = b"PK\x03\x04" + b"x" * 250          # pretend ZIP
    out = crypto.split_and_encrypt_batch(data, key, part_size=100, file_name="b.zip")
    assert out["partCount"] == 3               # 250+4 bytes / 100
    rebuilt = b""
    for part in out["fileParts"]:
        assert part["fileHash"] == crypto.sha256_b64(data[
            (part["ordinalNumber"] - 1) * 100:(part["ordinalNumber"] - 1) * 100 + part["fileSize"]])
        rebuilt += crypto.decrypt_aes_cbc(key, base64.b64decode(part["encryptedContent"]))
    assert rebuilt == data
    assert out["fileParts"][0]["fileName"] == "b.zip.0001"


def test_generate_csr_rsa_and_ec():
    from cryptography import x509
    from cryptography.hazmat.primitives.asymmetric import ec, rsa

    for key_type, expect in (("rsa", rsa.RSAPublicKey), ("ec", ec.EllipticCurvePublicKey)):
        out = crypto.generate_csr({"common_name": "NIP-1234567890", "organization_name": "Acme"}, key_type=key_type)
        csr = x509.load_pem_x509_csr(out["csrPem"].encode())
        assert csr.is_signature_valid
        cn = csr.subject.get_attributes_for_oid(x509.oid.NameOID.COMMON_NAME)[0].value
        assert cn == "NIP-1234567890"
        assert isinstance(csr.public_key(), expect)
        assert "BEGIN PRIVATE KEY" in out["privateKeyPem"]
