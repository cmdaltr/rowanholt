"""
User Administration CLI

Run inside the backend container (`rowanholt server users ...` does this):
    python -m auth.manage_users list
    python -m auth.manage_users first-admin <email> [--force] [--link-only]   (a server's first admin)
    python -m auth.manage_users has-admin                          (true or false: an active admin?)
    python -m auth.manage_users invite <email> [--role user|admin] [--name NAME]   (a one-time link)
    python -m auth.manage_users invitations                        (pending ones)
    python -m auth.manage_users revoke-invitation <id>
    python -m auth.manage_users role <username> admin|user
    python -m auth.manage_users disable|enable <username>
    python -m auth.manage_users mfa-reset <username>               (lost authenticator; audited)
    python -m auth.manage_users reset-access <username|email>      (a one-time link; audited)

reset-access is for someone who's lost their password, authenticator or backup codes: it prints a
link to choose a new password and set up a new authenticator (auth/reset_access.py). Their sessions
end and their API tokens are revoked at once; a new link replaces an earlier one. It works on a local
stack too.

A team server has no seeded account: its first admin comes from first-admin, an admin's invitation
that needs no free licence place while no admin can sign in. Only the newest one works, and it's
refused once an active admin exists (exit 5) unless --force. --link-only prints the link and nothing
else, for the launcher (`rowanholt start` offers it when server init was given --admin).

On a team server accounts are made by invitation (auth/invitations.py): invite prints a link where
the person chooses their username, password and authenticator. Nobody sets another person's password,
on a server or a local stack (the add and password commands went on 20 November 2026): reset-access
gives them a link to choose it. disable ends the account's sessions and revokes its API tokens.

Every link printed points at ROWANHOLT_PUBLIC_URL, else this machine, with a warning on stderr. The
commands hold users.locked() while they read and write the users, as the API does.
"""

import argparse
import sys

try:
    from ..config import settings
    from .users import active_admin, deactivate, find_user, init_default_admin, load_users, locked, save_users
    from . import invitations, mfa, reset_access
    from .. import licence
except ImportError:
    from config import settings
    from auth.users import active_admin, deactivate, find_user, init_default_admin, load_users, locked, save_users
    from auth import invitations, mfa, reset_access
    import licence

# first-admin's exit when an active admin exists already: the launcher reads it as nothing to do
ADMIN_EXISTS = 5


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
        print(f"Warning: the database is unavailable ({exc}): this won't be in the audit log, and API tokens "
              "can't be revoked.", file=sys.stderr)
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
    reset_access.warn_without_public_url()


def _invite(users: dict, email: str, role: str, name: str | None) -> None:
    try:
        invitation, link = invitations.create(users, email, role, name, {"username": "server-cli"},
                                              storage=_audit_storage(), via="cli")
    except invitations.InvitationRefused as exc:
        raise SystemExit(str(exc))
    print(f"Invited {invitation['email']} as {invitation['role']}. Pass this link on; it works once, for "
          f"{reset_access.RESET_HOURS} hours:\n\n  {link}\n")
    reset_access.warn_without_public_url()


def _first_admin(users: dict, email: str, force: bool, link_only: bool) -> int:
    if not settings.rowanholt_server_mode:
        raise SystemExit(f"first-admin is for a team server: on your own machine the first sign-in is "
                         f"admin / {settings.default_admin_password} (docs/USAGE.md)")
    if active_admin(users) and not force:
        print(invitations.ADMIN_EXISTS, file=sys.stderr)
        return ADMIN_EXISTS
    try:
        invitation, link = invitations.create(users, email, "admin", None, {"username": "server-cli"},
                                              storage=_audit_storage(), first_admin=True, via="cli")
    except invitations.InvitationRefused as exc:
        raise SystemExit(str(exc))
    if link_only:
        print(link)
    else:
        print(f"The first admin's invitation, for {invitation['email']}: open it within "
              f"{reset_access.RESET_HOURS} hours to choose a username and password and set up an authenticator. "
              f"Only the newest such link works:\n\n  {link}\n")
    reset_access.warn_without_public_url()
    return 0


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
    first = sub.add_parser("first-admin", help="A server's first admin: a one-time invitation link")
    first.add_argument("email")
    first.add_argument("--force", action="store_true", help="even if an active admin exists")
    first.add_argument("--link-only", action="store_true", help="print only the link, for the launcher")
    sub.add_parser("has-admin", help="Print true or false: whether an active admin exists")
    invite = sub.add_parser("invite", help="Invite someone: a one-time link to make their account")
    invite.add_argument("email")
    invite.add_argument("--role", choices=["user", "admin"], default="user")
    invite.add_argument("--name", help="their full name, which they can change")
    sub.add_parser("invitations", help="Pending invitations")
    sub.add_parser("revoke-invitation", help="Withdraw a pending invitation").add_argument("id")
    sub.add_parser("disable", help="Disable a user: sessions ended, API tokens revoked").add_argument("username")
    sub.add_parser("enable", help="Enable a disabled user").add_argument("username")
    sub.add_parser("mfa-reset", help="Turn a user's MFA off (a lost authenticator)").add_argument("username")
    sub.add_parser("reset-access", help="A one-time link to a new password and authenticator").add_argument("username")
    role = sub.add_parser("role")
    role.add_argument("username")
    role.add_argument("role", choices=["admin", "user"])
    args = parser.parse_args(argv)
    with locked():
        return _run(args)


def _run(args: argparse.Namespace) -> int:
    if args.command == "invitations":
        _list_invitations()
        return 0
    if args.command == "revoke-invitation":
        if not invitations.revoke(args.id, {"username": "server-cli"}, storage=_audit_storage(), via="cli"):
            raise SystemExit(f"No pending invitation {args.id}")
        print(f"Done: invitation {args.id} withdrawn")
        return 0
    users = init_default_admin() if args.command != "list" else load_users()
    if args.command == "has-admin":
        print("true" if active_admin(users) else "false")
        return 0
    if args.command == "first-admin":
        return _first_admin(users, args.email, args.force, args.link_only)
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
    user = _user(users, args.username)
    active_admins = [u for u in users.values() if u["role"] == "admin" and u.get("is_active", True)]
    losing_admin = user["role"] == "admin" and (args.command == "disable" or getattr(args, "role", None) == "user")
    if losing_admin and len(active_admins) <= 1:
        raise SystemExit("That's the last active admin")
    if args.command == "role":
        user["role"] = args.role
    elif args.command == "disable":
        if user.get("is_active", True):
            deactivate(user, {"username": "server-cli"}, storage=_audit_storage(), via="cli")
    else:
        if not user.get("is_active", True):
            _room_for_one_more(users)
        user["is_active"] = True
    save_users(users)
    print(f"Done: {args.command} {args.username}")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
