# Changelog

## [0.2.0] - 2026-06-21

### Added
- Batch sessions (§5.2): `prepare_batch` / `batch-prepare` split a ZIP into
  <=100MB parts and encrypt each (fileParts metadata); routes `session/batch/open`,
  `session/{ref}/close`, `session/{ref}/failed`, `sessions/query/list`.
- Certificates (§7): `make_csr` / `csr` generate an RSA-2048 or EC P-256 CSR from
  enrollment DN; routes `cert/enrollment-data`, `cert/enroll`, `cert/limits`.
- Incremental invoice query route (§6) `invoices/query`. 39 routes total (13 x 3 envs).
- XAdES auth variant (§3): `xades.py` builds the `AuthTokenRequest` and signs it with
  an enveloped XML-DSig (RSA-SHA256 over C14N, stdlib only); `authenticate --method xades`
  and `sign-auth` (offline). Production needs a qualified cert + full XAdES qualifying
  properties (note in `xades.py`).

## [0.1.0] - 2026-06-21

### Added
- Initial KSeF 2.0 reference connector: declarative `ksef://{env}/...` routes
  (auth/challenge, session send, query, UPO, invoice download) over the urirun
  fetch adapter; `ksef-token` auth handshake (`auth.py`) and client-side crypto
  (`crypto.py`: AES-256-CBC + RSAES-OAEP + SHA-256). Access token by reference
  (`getv://KSEF_ACCESS_TOKEN`). CLI, manifest, pytest suite (crypto round-trips +
  mocked auth flow), smoke, CI and the `urirun.bindings` entry point.
