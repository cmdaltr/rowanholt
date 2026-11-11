"""Issue Rowanholt licences (licensor only). Run where the signing key is, never on a server.

    sign_licence.py keygen PATH                 a new keypair: the private key to PATH, the public to stdout
    sign_licence.py public                      the public key to put in licence.PUBLIC_KEYS (src/web/backend)
    sign_licence.py sign --licensee "Northwind Ltd" --edition services --seats 25 --expires 2027-11-30

The private key comes from ROWANHOLT_LICENCE_KEY: a path to the key file, or the key itself. Either
holds a PEM private key or the 32-byte seed as hex (or base64). A key file must be readable by its
owner only. Every product has its own key (docs/LICENSING_MODEL.md).

With LICENCE_LEDGER_DIR set (or --ledger), a signed licence goes into that licensing repo: the line
to issued/rowanholt/<licence_id>.licence and a row to ledger.csv, with the terms version it's under.
"""

from __future__ import annotations

import argparse
import base64
import binascii
import csv
import os
import sys
from datetime import date, datetime, timezone
from pathlib import Path

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import (
    Encoding,
    NoEncryption,
    PrivateFormat,
    PublicFormat,
    load_pem_private_key,
)

# licence.py needs only the standard library, cryptography and samarkand, so it imports without the backend's settings
sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "src" / "web" / "backend"))
import licence  # noqa: E402

KEY_ENV = "ROWANHOLT_LICENCE_KEY"
LEDGER_ENV = "LICENCE_LEDGER_DIR"
LEDGER_FIELDS = (
    "licence_id", "product", "licensee", "email", "edition", "seats", "features", "issued",
    "not_before", "expires", "terms_version", "order", "file", "notes",
)  # fmt: skip


def _record(ledger: Path, lic: licence.Licence, line: str) -> Path:
    """The licence into the licensing repo: its file, and a ledger row."""
    if not (ledger / "ledger.csv").is_file():
        sys.exit(f"{ledger} isn't the licensing repo (no ledger.csv).")
    out = ledger / "issued" / lic.product / f"{lic.licence_id}.licence"
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(line + "\n")
    with (ledger / "ledger.csv").open("a", newline="") as f:
        csv.DictWriter(f, LEDGER_FIELDS).writerow(
            {
                "licence_id": lic.licence_id,
                "product": lic.product,
                "licensee": lic.licensee,
                "email": lic.email,
                "edition": lic.edition.value,
                "seats": "unlimited" if lic.seats is None else lic.seats,
                "features": " ".join(lic.features),
                "issued": lic.issued.isoformat(),
                "not_before": lic.not_before.isoformat() if lic.not_before else "",
                "expires": lic.expires.isoformat() if lic.expires else "perpetual",
                "terms_version": licence.terms()[0],
                "file": str(out.relative_to(ledger)),
            }
        )
    return out


def _key() -> Ed25519PrivateKey:
    value = os.environ.get(KEY_ENV, "").strip()
    if not value:
        sys.exit(f"Set {KEY_ENV} to the signing key file (or the key itself).")
    path = Path(value).expanduser()
    if path.is_file():
        if path.stat().st_mode & 0o077:
            sys.exit(f"{path} is readable by others: chmod 600 it first.")
        value = path.read_text().strip()
    if value.startswith("-----BEGIN"):
        key = load_pem_private_key(value.encode(), password=None)
        if not isinstance(key, Ed25519PrivateKey):
            sys.exit("That PEM key isn't Ed25519.")
        return key
    try:
        seed = bytes.fromhex(value) if len(value) == 64 else base64.b64decode(value, validate=True)
    except (ValueError, binascii.Error):
        sys.exit(f"{KEY_ENV} isn't a PEM key or a 32-byte seed in hex or base64.")
    return Ed25519PrivateKey.from_private_bytes(seed)


def _public_hex(key: Ed25519PrivateKey) -> str:
    return key.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw).hex()


def _day(text: str) -> date | None:
    return None if text in ("perpetual", "-") else date.fromisoformat(text)


def main() -> int:
    parser = argparse.ArgumentParser(prog="sign_licence")
    do = parser.add_subparsers(dest="command", required=True)
    gen = do.add_parser("keygen", help="a new signing keypair")
    gen.add_argument("path", type=Path, help="where to write the private key (PEM); it must not exist")
    do.add_parser("public", help="the public key, hex, for licence.PUBLIC_KEYS")
    sign = do.add_parser("sign", help="print a licence line for a customer")
    sign.add_argument("--licensee", required=True, help="the organisation, as the Licence page shows it")
    sign.add_argument("--edition", required=True, choices=["pro", "services"])
    sign.add_argument("--seats", required=True, help="a number, or 'unlimited'")
    sign.add_argument("--expires", required=True, help="last day, YYYY-MM-DD, or 'perpetual'")
    sign.add_argument("--email", default="")
    sign.add_argument("--not-before", type=date.fromisoformat, help="first day it works, YYYY-MM-DD")
    sign.add_argument("--features", default="", help="extra feature ids, comma-separated, or '*'")
    sign.add_argument("--out", type=Path, help="also write to this file")
    sign.add_argument(
        "--ledger",
        type=Path,
        default=os.environ.get(LEDGER_ENV) or None,
        help=f"the licensing repo to record it in (default: ${LEDGER_ENV})",
    )
    args = parser.parse_args()

    if args.command == "keygen":
        key = Ed25519PrivateKey.generate()
        pem = key.private_bytes(Encoding.PEM, PrivateFormat.PKCS8, NoEncryption())
        fd = os.open(args.path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        os.write(fd, pem)
        os.close(fd)
        print(_public_hex(key))  # noqa: T201
        return 0
    key = _key()
    if args.command == "public":
        print(_public_hex(key))  # noqa: T201
        return 0

    issued = datetime.now(timezone.utc).date()
    expires = _day(args.expires)
    if expires and expires <= issued:
        sys.exit("The expiry must be after today.")
    features = tuple(f.strip() for f in args.features.split(",") if f.strip())
    unknown = set(features) - {*licence.FEATURES, licence.WILDCARD}
    if unknown:
        sys.exit(f"Unknown feature ids: {', '.join(sorted(unknown))}. Known: {', '.join(licence.FEATURES)}.")
    lic = licence.Licence(
        licence_id=licence.new_id(),
        licensee=args.licensee.strip(),
        email=args.email.strip(),
        edition=licence.Edition(args.edition),
        seats=None if args.seats == "unlimited" else int(args.seats),
        features=features,
        issued=issued,
        not_before=args.not_before,
        expires=expires,
    )
    # samarkand reads licences but never signs: it gives the text to sign and puts the line together
    head = licence.head_of(lic)
    line = licence.line_of(head, key.sign(head.encode()))
    licence.parse(line)  # signed by the key Rowanholt trusts, or this stops here
    seats = lic.seats or "unlimited"
    summary = f"{lic.edition.value} for {lic.licensee}, {seats} seats, to {lic.expires or 'no end date'}"
    if args.ledger:
        print(f"{lic.licence_id}: {summary} -> {_record(args.ledger.expanduser(), lic, line)}")  # noqa: T201
    if args.out:
        args.out.write_text(line + "\n")
        args.out.chmod(0o600)
        print(f"{lic.licence_id}: {summary} -> {args.out}")  # noqa: T201
    print(line)  # noqa: T201
    return 0


if __name__ == "__main__":
    sys.exit(main())
