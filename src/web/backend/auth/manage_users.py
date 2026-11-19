"""
User Administration CLI

Run inside the backend container (`rowanholt server users ...` does this):
    python -m auth.manage_users list
    python -m auth.manage_users invite <email> [--role user|admin] [--name NAME]   (a one-time link)
    python -m auth.manage_users invitations                        (pending ones)
    python -m auth.manage_users revoke-invitation <id>
    python -m auth.manage_users add <username> <email> [--admin]   (local mode only; password prompted)
    python -m auth.manage_users password <username>                (local mode only; prompted)
    python -m auth.manage_users role <username> admin|user
    python -m auth.manage_users disable|enable <username>
    python -m auth.manage_users mfa-reset <username>               (lost authenticator; audited)
    python -m auth.manage_users reset-access <username|email>      (a one-time link; audited)

reset-access is for someone who's lost their password, authenticator or backup codes: it prints a
link to choose a new password and set up a new authenticator (auth/reset_access.py). Their sessions
end and their API tokens are revoked at once; a new link replaces an earlier one.

On a team server accounts are made by invitation (auth/invitations.py): invite prints a link where
the person chooses their username, password and authenticator, so `add`, which has an admin choose
someone's password, is refused there, and so is `password`: reset-access instead, where they choose
it. A local stack keeps both.
"""

import argparse
import getpass
import sys

try:
    from ..config import settings
    from .users import find_user, init_default_admin, load_users, new_user, save_users, set_password
    from . import invitations, mfa, reset_access
    from .. import licence
except ImportError:
    from config import settings
    from auth.users import find_user, init_default_admin, load_users, new_user, save_users, set_password
    from auth import invitations, mfa, reset_access
    import licence

MIN_PASSWORD = 12


def _password(prompt: str = "Password: ") -> str:
    first = getpass.getpass(prompt)
    if len(first) < MIN_PASSWORD:
        raise SystemExit(f"Passwords need at least {MIN_PASSWORD} characters")
    if getpass.getpass("Again: ") != first:
        raise SystemExit("The passwords don't match")
    return first


def _room_for_one_more(users: dict) -> None:
    """Adding or re-enabling someone needs a free place on the licence; nobody already in is affected."""
    refusal = licence.seat_refusal(users, settings.rowanholt_server_mode)
    if refusal:
        raise SystemExit(refusal)


def _user(users: dict, name: str) -> dict:
    user = find_user(users, name)
    if not user:
        raise SystemExit(f"No user '{name}'")
    return user


def _audit_storage():
    """The audit log is the jobs database; from the CLI it's reached as main.py reaches it."""
    try:
        from ..storage import JobStorage
    except ImportError:
        from storage import JobStorage
    try:
        return JobStorage()
    except Exception as exc:  # noqa: BLE001 - say so, but a down database mustn't block the reset
        print(f"Warning: the audit log is unavailable ({exc}); this reset won't be in it.", file=sys.stderr)
        return None


def _mfa_reset(users: dict, user: dict) -> None:
    if not mfa.is_enabled(user) and not user.get("mfa_pending_secret"):
        raise SystemExit(f"MFA isn't on for {user['username']}")
    mfa.disable(user)
    save_users(users)
    mfa.audit("mfa_admin_reset", {"username": "server-cli"}, user, storage=_audit_storage(), via="cli")


def _reset_access(users: dict, user: dict) -> None:
    storage = _audit_storage()
    try:
        link, _ = reset_access.issue(user, {"username": "server-cli"}, storage=storage, via="cli")
    except reset_access.ResetRefused as exc:
        raise SystemExit(str(exc))
    save_users(users)
    print(f"Reset for {user['username']}: their sessions have ended"
          f"{'' if storage else ' (API tokens not revoked: the database is unavailable)'}. Pass this link on; "
          f"it works once, for {reset_access.RESET_HOURS} hours:\n\n  {link}\n")
    if not link.startswith("http"):
        print("ROWANHOLT_PUBLIC_URL isn't set: open the link on the server's own address.", file=sys.stderr)


def _invite(users: dict, email: str, role: str, name: str | None) -> None:
    try:
        invitation, link = invitations.create(users, email, role, name, {"username": "server-cli"},
                                              storage=_audit_storage(), via="cli")
    except invitations.InvitationRefused as exc:
        raise SystemExit(str(exc))
    print(f"Invited {invitation['email']} as {invitation['role']}. Pass this link on; it works once, for "
          f"{reset_access.RESET_HOURS} hours:\n\n  {link}\n")
    if not link.startswith("http"):
        print("ROWANHOLT_PUBLIC_URL isn't set: open the link on the server's own address.", file=sys.stderr)


def _list_invitations() -> None:
    print(f"{'ID':<36}  {'EMAIL':<32} {'ROLE':<6} {'BY':<16} EXPIRES")
    for inv in invitations.pending():
        print(f"{inv['id']:<36}  {inv['email']:<32} {inv['role']:<6} {inv['invited_by'] or '-':<16} "
              f"{inv['expires_at'][:16].replace('T', ' ')}")


def main(argv: list) -> int:
    """Entry point; returns the exit status."""
    parser = argparse.ArgumentParser(prog="rowanholt server users", description="Administer Rowanholt's users")
    sub = parser.add_subparsers(dest="command", required=True)
    sub.add_parser("list", help="Every user")
    invite = sub.add_parser("invite", help="Invite someone: a one-time link to make their account")
    invite.add_argument("email")
    invite.add_argument("--role", choices=["user", "admin"], default="user")
    invite.add_argument("--name", help="their full name, which they can change")
    sub.add_parser("invitations", help="Pending invitations")
    sub.add_parser("revoke-invitation", help="Withdraw a pending invitation").add_argument("id")
    add = sub.add_parser("add", help="Create a password user (local mode; a server invites)")
    add.add_argument("username")
    add.add_argument("email")
    add.add_argument("--admin", action="store_true")
    for name in ("password", "disable", "enable"):
        sub.add_parser(name).add_argument("username")
    sub.add_parser("mfa-reset", help="Turn a user's MFA off (a lost authenticator)").add_argument("username")
    sub.add_parser("reset-access", help="A one-time link to a new password and authenticator").add_argument("username")
    role = sub.add_parser("role")
    role.add_argument("username")
    role.add_argument("role", choices=["admin", "user"])
    args = parser.parse_args(argv)

    if args.command == "invitations":
        _list_invitations()
        return 0
    if args.command == "revoke-invitation":
        if not invitations.revoke(args.id, {"username": "server-cli"}, storage=_audit_storage(), via="cli"):
            raise SystemExit(f"No pending invitation {args.id}")
        print(f"Done: invitation {args.id} withdrawn")
        return 0
    users = init_default_admin() if args.command != "list" else load_users()
    if args.command == "invite":
        _invite(users, args.email, args.role, args.name)
        return 0
    if args.command == "list":
        print(f"{'USERNAME':<28} {'ROLE':<6} {'SIGN-IN':<9} {'ACTIVE':<7} {'MFA':<4} LAST SIGN-IN")
        for u in sorted(users.values(), key=lambda u: u["username"]):
            print(f"{u['username']:<28} {u['role']:<6} {'sso' if u.get('oidc_subject') else 'password':<9} "
                  f"{'yes' if u.get('is_active', True) else 'no':<7} {'on' if mfa.is_enabled(u) else '-':<4} "
                  f"{u.get('last_login') or '-'}")
        return 0
    if args.command == "mfa-reset":
        _mfa_reset(users, _user(users, args.username))
        print(f"Done: MFA is off for {args.username}; they set it up again from Account")
        return 0
    if args.command == "reset-access":
        _reset_access(users, _user(users, args.username))
        return 0
    if args.command == "add":
        if settings.rowanholt_server_mode:
            raise SystemExit(invitations.INVITE_INSTEAD_CLI)
        if find_user(users, args.username) or find_user(users, args.email):
            raise SystemExit("Username or email already taken")
        _room_for_one_more(users)
        user = new_user(args.username, args.email, role="admin" if args.admin else "user", password=_password())
        users[user["id"]] = user
    else:
        user = _user(users, args.username)
        active_admins = [u for u in users.values() if u["role"] == "admin" and u.get("is_active", True)]
        losing_admin = user["role"] == "admin" and (args.command == "disable" or getattr(args, "role", None) == "user")
        if losing_admin and len(active_admins) <= 1:
            raise SystemExit("That's the last active admin")
        if args.command == "password":
            if settings.rowanholt_server_mode:
                raise SystemExit(reset_access.RESET_INSTEAD_CLI)
            set_password(user, _password("New password: "))
        elif args.command == "role":
            user["role"] = args.role
        else:
            if args.command == "enable" and not user.get("is_active", True):
                _room_for_one_more(users)
            user["is_active"] = args.command == "enable"
    save_users(users)
    print(f"Done: {args.command} {args.username}")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
