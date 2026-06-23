# Author: Tom Sapletta · https://tom.sapletta.com
# Part of the ifURI solution.

"""KSeF 2.0 client-side cryptography (the imperative escape hatch).

Mirrors the official SDK ``CryptographyService`` (§4 of the KSeF connector spec):

* invoice symmetric key: **AES-256-CBC, PKCS#7 padding, 128-bit IV prefixed** to
  the ciphertext;
* key wrapping: **RSAES-OAEP (SHA-256 / MGF1-SHA-256)** with the KSeF public key;
* invoice hash: **SHA-256** of the original XML (before encryption).

All of this is real and unit-tested offline (round-trips with a generated key
pair); the network/auth flow lives in ``auth.py``.
"""

from __future__ import annotations

import base64
import hashlib
import os
from typing import Any


def _lazy_crypto():
    try:
        from cryptography.hazmat.primitives import hashes, padding as sym_padding, serialization
        from cryptography.hazmat.primitives.asymmetric import padding as asym_padding
        from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
    except ImportError as exc:  # pragma: no cover
        raise RuntimeError("KSeF crypto needs the 'cryptography' package (pip install cryptography)") from exc
    return hashes, sym_padding, serialization, asym_padding, Cipher, algorithms, modes


def aes_key() -> bytes:
    """A fresh AES-256 key (recommended once per session)."""
    return os.urandom(32)


def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def sha256_b64(data: bytes) -> str:
    return base64.b64encode(hashlib.sha256(data).digest()).decode("ascii")


def encrypt_aes_cbc(key: bytes, plaintext: bytes) -> bytes:
    """AES-256-CBC + PKCS#7, with a fresh 16-byte IV prefixed to the ciphertext."""
    _h, sym_padding, _s, _a, Cipher, algorithms, modes = _lazy_crypto()
    iv = os.urandom(16)
    padder = sym_padding.PKCS7(128).padder()
    padded = padder.update(plaintext) + padder.finalize()
    encryptor = Cipher(algorithms.AES(key), modes.CBC(iv)).encryptor()
    return iv + encryptor.update(padded) + encryptor.finalize()


def decrypt_aes_cbc(key: bytes, blob: bytes) -> bytes:
    """Inverse of :func:`encrypt_aes_cbc` (IV is the first 16 bytes)."""
    _h, sym_padding, _s, _a, Cipher, algorithms, modes = _lazy_crypto()
    iv, ciphertext = blob[:16], blob[16:]
    decryptor = Cipher(algorithms.AES(key), modes.CBC(iv)).decryptor()
    padded = decryptor.update(ciphertext) + decryptor.finalize()
    unpadder = sym_padding.PKCS7(128).unpadder()
    return unpadder.update(padded) + unpadder.finalize()


def load_public_key(material: bytes | str):
    """Load a KSeF RSA public key from PEM, DER, or a base64 DER certificate/key."""
    hashes, _sp, serialization, _a, _c, _al, _m = _lazy_crypto()
    from cryptography import x509

    if isinstance(material, str):
        text = material.strip()
        if "BEGIN" in text:
            material = text.encode()
        else:
            material = base64.b64decode(text)
    if b"BEGIN CERTIFICATE" in material:
        return x509.load_pem_x509_certificate(material).public_key()
    if b"BEGIN PUBLIC KEY" in material:
        return serialization.load_pem_public_key(material)
    try:
        return x509.load_der_x509_certificate(material).public_key()
    except Exception:  # noqa: BLE001
        return serialization.load_der_public_key(material)


def rsa_oaep_encrypt(public_key, data: bytes) -> bytes:
    """RSAES-OAEP with SHA-256 and MGF1-SHA-256 (used for the AES key and the token)."""
    hashes, _sp, _s, asym_padding, _c, _al, _m = _lazy_crypto()
    pad = asym_padding.OAEP(mgf=asym_padding.MGF1(algorithm=hashes.SHA256()),
                            algorithm=hashes.SHA256(), label=None)
    return public_key.encrypt(data, pad)


def encryption_info(symmetric_key: bytes, ksef_public_key) -> dict[str, Any]:
    """The ``encryptionInfo`` block for opening a session (§5.1): the AES key
    wrapped with the KSeF public key, base64-encoded."""
    wrapped = rsa_oaep_encrypt(ksef_public_key, symmetric_key)
    return {"encryptedSymmetricKey": base64.b64encode(wrapped).decode("ascii"), "algorithm": "RSA-OAEP-256/AES-256-CBC"}


def encrypt_invoice(symmetric_key: bytes, invoice_xml: bytes) -> dict[str, Any]:
    """Encrypt one invoice and return the fields a send request needs (§5.1)."""
    encrypted = encrypt_aes_cbc(symmetric_key, invoice_xml)
    return {
        "invoiceHash": sha256_b64(invoice_xml),
        "invoiceSize": len(invoice_xml),
        "encryptedInvoiceHash": sha256_b64(encrypted),
        "encryptedInvoiceSize": len(encrypted),
        "encryptedInvoiceContent": base64.b64encode(encrypted).decode("ascii"),
    }


# Batch sessions (§5.2): ZIP split into parts <=100MB *before* encryption, each
# part encrypted and described separately so one bad invoice never fails the batch.
BATCH_PART_LIMIT = 100 * 1000 * 1000


def split_and_encrypt_batch(data: bytes, symmetric_key: bytes, *, part_size: int = BATCH_PART_LIMIT,
                            file_name: str = "invoices.zip") -> dict[str, Any]:
    parts = []
    for offset in range(0, len(data), part_size) or [0]:
        chunk = data[offset:offset + part_size]
        encrypted = encrypt_aes_cbc(symmetric_key, chunk)
        parts.append({
            "ordinalNumber": len(parts) + 1,
            "fileName": f"{file_name}.{len(parts) + 1:04d}",
            "fileSize": len(chunk),
            "fileHash": sha256_b64(chunk),
            "encryptedFileSize": len(encrypted),
            "encryptedFileHash": sha256_b64(encrypted),
            "encryptedContent": base64.b64encode(encrypted).decode("ascii"),
        })
    return {"fileParts": parts, "partCount": len(parts)}


def generate_csr(subject: dict[str, str], key_type: str = "rsa") -> dict[str, Any]:
    """Build a KSeF certificate-enrollment CSR (§7). DN attributes come from
    ``/certificates/enrollments/data`` (modifying them = rejection); the key is
    RSA-2048 or EC P-256 (``25010`` on a wrong type/length)."""
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import ec, rsa
    from cryptography.x509.oid import NameOID

    key = ec.generate_private_key(ec.SECP256R1()) if key_type == "ec" else \
        rsa.generate_private_key(public_exponent=65537, key_size=2048)
    oid_map = {
        "common_name": NameOID.COMMON_NAME, "organization_name": NameOID.ORGANIZATION_NAME,
        "organizational_unit_name": NameOID.ORGANIZATIONAL_UNIT_NAME, "country_name": NameOID.COUNTRY_NAME,
        "serial_number": NameOID.SERIAL_NUMBER, "surname": NameOID.SURNAME, "given_name": NameOID.GIVEN_NAME,
    }
    attributes = [x509.NameAttribute(oid_map[name], str(value)) for name, value in subject.items() if name in oid_map]
    csr = x509.CertificateSigningRequestBuilder().subject_name(x509.Name(attributes)).sign(key, hashes.SHA256())
    return {
        "keyType": key_type,
        "privateKeyPem": key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                                           serialization.NoEncryption()).decode("ascii"),
        "csrPem": csr.public_bytes(serialization.Encoding.PEM).decode("ascii"),
        "csrDer": base64.b64encode(csr.public_bytes(serialization.Encoding.DER)).decode("ascii"),
    }
