"""
Licence Administration CLI

Run inside the backend container (`rowanholt server licence ...` does this, passing the file on stdin):
    python -m manage_licence show
    python -m manage_licence install FILE|- --accept-terms "Name <email>"
    python -m manage_licence remove

For when no admin can sign in to do it from the Licence page. An install from here is recorded like
an admin's, with the name given for whoever accepted the terms.
"""

import argparse
import sys

try:
    from .auth.users import load_users
    from . import licence
except ImportError:
    from auth.users import load_users
    import licence


def _show() -> int:
    st = licence.current()
    lic = st.licence
    print(f"Edition: {st.edition.value} ({st.state})")
    if lic:
        print(f"Licensed to {lic.licensee} ({lic.licence_id}), runs to {lic.expires or 'no end date'}")
        if st.state == "grace":
            print(f"Expired: in grace until {licence.grace_ends(lic)}, then the free edition")
        print(f"Features: {', '.join(sorted(st.features)) or 'none'}")
    record = licence.installed()
    if record and record.get("accepted_at"):
        print(f"Commercial licence v{record['terms_version']} accepted by {record['accepted_by_name']} "
              f"on {record['accepted_at'][:10]}")
    print(f"Places: {licence.places_held(load_users())} of {st.seats or 'unlimited'} taken")
    return 0


def _install(source: str, accepted_by: str) -> int:
    version = licence.terms()[0]
    if not accepted_by.strip():
        print(f"Installing a licence accepts the Rowanholt Commercial Licence, version {version}, on the "
              "licensee's behalf. Read COMMERCIAL-LICENSE.md, then run this again with "
              '--accept-terms "Your Name <you@example.org>".', file=sys.stderr)
        return 1
    text = (sys.stdin.read() if source == "-" else open(source).read()).strip()
    try:
        lic = licence.parse(text)
    except licence.LicenceProblem as exc:
        print(exc, file=sys.stderr)
        return 1
    if licence.standing(lic).state == "lapsed":
        print(f"That licence ran out on {lic.expires}.", file=sys.stderr)
        return 1
    licence.record_install(text, accepted_by=None, accepted_by_name=accepted_by.strip())
    licence.audit("licence_installed", None, licence=lic.licence_id, edition=lic.edition.value,
                  licensee=lic.licensee, seats=lic.seats,
                  expires=lic.expires.isoformat() if lic.expires else "perpetual",
                  terms_version=version, accepted_by=accepted_by.strip(), via="cli")
    print(f"Installed {lic.edition.value} for {lic.licensee}: {lic.seats or 'unlimited'} seats "
          f"to {lic.expires or 'no end date'}.")
    return 0


def _remove() -> int:
    had = licence.current().licence
    if not licence.remove():
        print("No licence is installed.")
        return 0
    licence.audit("licence_removed", None, licence=had.licence_id if had else None, via="cli")
    print("Removed. Rowanholt is on the free edition; nobody has been deactivated.")
    return 0


def _audited() -> None:
    """The audit log is the jobs database; outside the API it's reached the same way main.py does."""
    try:
        from .storage import JobStorage
    except ImportError:
        from storage import JobStorage
    try:
        licence.configure(JobStorage())
    except Exception as exc:  # noqa: BLE001 - say so, but a down database mustn't block an admin's fix
        print(f"Warning: the audit log is unavailable ({exc}); this change won't be in it.", file=sys.stderr)


def main(argv: list) -> int:
    """Entry point; returns the exit status."""
    parser = argparse.ArgumentParser(prog="rowanholt server licence", description="A team server's licence")
    sub = parser.add_subparsers(dest="command", required=True)
    sub.add_parser("show", help="The edition, who accepted the terms, and places taken")
    put = sub.add_parser("install", help="Install a licence from a file (- for stdin)")
    put.add_argument("file")
    put.add_argument("--accept-terms", default="", metavar='"NAME <EMAIL>"',
                     help="accept the commercial licence terms on the licensee's behalf")
    sub.add_parser("remove", help="Back to the free edition; nobody is deactivated")
    args = parser.parse_args(argv)
    if args.command == "show":
        return _show()
    if args.command == "install":
        if not args.accept_terms.strip():
            return _install(args.file, "")
        _audited()
        return _install(args.file, args.accept_terms)
    _audited()
    return _remove()


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
