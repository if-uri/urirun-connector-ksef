# TODO
- [ ] Confirm `# verify` JSON field names against the live openapi.json.
- [x] XAdES auth variant: enveloped XML-DSig (RSA-SHA256). TODO: qualified cert + full XAdES qualifying properties (SigningTime, SigningCertificate v2) for PRD.
- [x] Batch session (ZIP parts <=100MB) + fileParts; bulk UPO.
- [ ] Attachments (<=3MB, batch-only) — needs prior e-US/testdata registration.
- [x] Certificate enrollment (CSR) and offline24 QR.
- [x] Incremental invoice download (pageSize<=1000).
- [ ] Live smoke against TEST in CI (gated by a secret test token).
