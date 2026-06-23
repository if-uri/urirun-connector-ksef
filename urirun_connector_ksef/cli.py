# Author: Tom Sapletta · https://tom.sapletta.com
# Part of the ifURI solution.

from __future__ import annotations

import os
import sys
from pathlib import Path

import urirun

from .core import (
    authenticate,
    connector_manifest,
    encrypt_invoice,
    make_csr,
    prepare_batch,
    sign_auth_request,
    urirun_bindings,
)


def register(sub) -> None:
    auth_p = sub.add_parser("authenticate", help="Run (or plan) a KSeF auth handshake (token or xades)")
    auth_p.add_argument("--env", default="test", choices=["test", "demo", "prod"])
    auth_p.add_argument("--nip", default="", help="context NIP")
    auth_p.add_argument("--method", default="token", choices=["token", "xades"])
    auth_p.add_argument("--public-key", default="", help="token: path to the KSeF public key/cert")
    auth_p.add_argument("--key", default="", help="xades: path to the (qualified) private key PEM")
    auth_p.add_argument("--cert", default="", help="xades: path to the signing certificate PEM")
    auth_p.add_argument("--execute", action="store_true", help="actually authenticate (else dry-run plan)")

    signp = sub.add_parser("sign-auth", help="Build + sign an AuthTokenRequest locally (offline XAdES)")
    signp.add_argument("--challenge", required=True)
    signp.add_argument("--nip", required=True)
    signp.add_argument("--key", required=True, help="private key PEM")
    signp.add_argument("--cert", required=True, help="certificate PEM")

    enc = sub.add_parser("encrypt-invoice", help="Encrypt an invoice XML -> send-request fields")
    enc.add_argument("file", help="path to the invoice XML")

    batch = sub.add_parser("batch-prepare", help="Split a ZIP into <=100MB parts and encrypt -> fileParts")
    batch.add_argument("file", help="path to the invoice ZIP")

    csr = sub.add_parser("csr", help="Generate a certificate-enrollment CSR (RSA/EC)")
    csr.add_argument("--cn", required=True, help="common name (from enrollment-data)")
    csr.add_argument("--org", default="")
    csr.add_argument("--country", default="")
    csr.add_argument("--serial", default="")
    csr.add_argument("--key-type", default="rsa", choices=["rsa", "ec"])


def dispatch(args) -> int:
    if args.command == "authenticate":
        token = os.environ.get("KSEF_TOKEN", "")
        public_key = Path(args.public_key).read_text(encoding="utf-8") if args.public_key else ""
        private_key = Path(args.key).read_text(encoding="utf-8") if args.key else ""
        cert = Path(args.cert).read_text(encoding="utf-8") if args.cert else ""
        result = authenticate(args.env, args.nip, token=token, public_key=public_key, execute=args.execute,
                              method=args.method, private_key=private_key, cert=cert)
    elif args.command == "sign-auth":
        result = sign_auth_request(args.challenge, args.nip,
                                   Path(args.key).read_text(encoding="utf-8"), Path(args.cert).read_text(encoding="utf-8"))
    elif args.command == "encrypt-invoice":
        result = encrypt_invoice(Path(args.file).read_bytes())
    elif args.command == "batch-prepare":
        result = prepare_batch(Path(args.file).read_bytes())
    elif args.command == "csr":
        result = make_csr(args.cn, organization=args.org, country=args.country, serial=args.serial,
                          key_type=args.key_type)
    else:
        return 1
    urirun.connector_emit(result)
    return 0 if result.get("ok") else 2


def main(argv: list[str] | None = None) -> int:
    return urirun.connector_cli(
        "urirun-connector-ksef",
        manifest=connector_manifest,
        bindings=urirun_bindings,
        register=register,
        dispatch=dispatch,
        argv=argv,
    )


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
