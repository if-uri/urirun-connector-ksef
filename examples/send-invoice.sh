#!/usr/bin/env bash
# KSeF: encrypt an FA(3) invoice, plan the auth handshake, generate a CSR.
# All offline / dry-run — no live KSeF call, no credentials needed.
set -euo pipefail
cd "$(dirname "$0")"
printf '<Faktura>FA(3) demo</Faktura>' > /tmp/fa3.xml

echo "== 1) encrypt the invoice (AES-256-CBC + hashes) =="
urirun-connector-ksef encrypt-invoice /tmp/fa3.xml | python3 -c 'import json,sys;d=json.load(sys.stdin);print("   invoiceHash:",d["invoiceHash"][:16]+"...","| encrypted bytes (b64):",len(d["encryptedInvoiceContent"]))'

echo "== 2) plan the ksef-token auth handshake (dry-run) =="
urirun-connector-ksef authenticate --env test --nip 1234567890 | python3 -c 'import json,sys;d=json.load(sys.stdin);print("   method:",d["method"],"steps:",len(d["steps"]))'

echo "== 3) generate a certificate-enrollment CSR (EC P-256) =="
urirun-connector-ksef csr --cn "NIP-1234567890" --org "Demo Sp. z o.o." --key-type ec | python3 -c 'import json,sys;d=json.load(sys.stdin);print("   keyType:",d["keyType"],"| CSR:",("BEGIN CERTIFICATE REQUEST" in d["csrPem"]))'

echo "== 4) the live route surface (declarative, 39 routes) =="
urirun-connector-ksef bindings | urirun validate -
