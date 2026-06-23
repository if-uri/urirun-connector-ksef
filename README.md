# urirun-connector-ksef

KSeF 2.0 (Polish national e-invoicing) connector for [ifURI](https://ifuri.com) /
urirun. The HTTP surface is **declarative** (the urirun `fetch` adapter); the two
imperative escape hatches — the `ksef-token` auth handshake and client-side
crypto — are small, tested helpers.

| URI | Operation |
| --- | --- |
| `ksef://{env}/auth/challenge` | request an auth challenge |
| `ksef://{env}/session/online/{ref}/send` | send an encrypted FA(3) invoice |
| `ksef://{env}/session/{ref}/invoices` | accepted invoices (ksefNumber) |
| `ksef://{env}/session/{ref}/upo` | session UPO |
| `ksef://{env}/invoice/{ksefNumber}` | download an invoice |

`{env}` ∈ `test` / `demo` / `prod` → 15 routes. The access token is addressed
**by reference** (`getv://KSEF_ACCESS_TOKEN`), never embedded.

## Auth (ksef-token) + crypto

```bash
urirun-connector-ksef authenticate --env test --nip 1234567890        # dry-run plan
KSEF_TOKEN=... urirun-connector-ksef authenticate --env test --nip 1234567890 \
  --public-key ksef-test-pubkey.pem --execute                          # real (TEST)
urirun-connector-ksef encrypt-invoice invoice.xml                      # AES-256-CBC + hashes
```

- Auth (token): `challenge → RSA-OAEP(token|timestampMs) → poll → redeem → accessToken`.
  The token **never travels in plaintext** (asserted in tests).
- Auth (XAdES): `authenticate --method xades --key … --cert …` signs the AuthTokenRequest
  (enveloped XML-DSig). `sign-auth` runs it offline. Needs a qualified cert for PRD.
- Crypto (`crypto.py`): AES-256-CBC + PKCS#7, 16-byte IV prefix; RSAES-OAEP
  (SHA-256 / MGF1-SHA-256) key wrapping; SHA-256 invoice hash. Real and
  round-trip-tested offline.

> JSON field names in `auth.py` marked `# verify` should be confirmed against the
> live `openapi.json` before a production run. Use the **TEST** environment
> (self-signed certs, random NIPs) first.

## Routes from OpenAPI

The route surface can also be regenerated from the official contract:

```bash
urirun add-openapi https://api-test.ksef.mf.gov.pl/docs/v2/openapi.json \
  --scheme ksef --target test | urirun validate -
```

## Examples

Runnable walkthrough: [`examples/`](examples/) — `./examples/send-invoice.sh`.

## Test

```bash
pip install -e ".[test]" && pytest -q     # crypto round-trips + auth flow (HTTP mocked)
```
