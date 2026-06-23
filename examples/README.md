# KSeF connector — examples

`./send-invoice.sh` — offline/dry-run walkthrough: encrypt an FA(3) invoice
(AES-256-CBC), plan the `ksef-token` auth handshake, generate an enrollment CSR,
and validate the 39 declarative `ksef://{env}/...` routes. No credentials or
network needed. For a real run use the **TEST** environment with a test token and
`--execute` (see the package README).
