"""
User Administration CLI

Run inside the backend container (`rivendell server users ...` does this):
    python -m auth.manage_users list
    python -m auth.manage_users add <username> <email> [--admin]   (password prompted)
    python -m auth.manage_users password <username>                (prompted)
    python -m auth.manage_users role <username> admin|user
    python -m auth.manage_users disable|enable <username>
"""

import argparse
import getpass
import sys

try:
    from .security import hash_password
    from .users import find_user, init_default_admin, load_users, new_user, save_users
except ImportError:
    from auth.security import hash_password
    from auth.users import find_user, init_default_admin, load_users, new_user, save_users

MIN_PASSWORD = 12


def _password(prompt: str = "Password: ") -> str:
    first = getpass.getpass(prompt)
    if len(first) < MIN_PASSWORD:
        raise SystemExit(f"Passwords need at least {MIN_PASSWORD} characters")
    if getpass.getpass("Again: ") != first:
        raise SystemExit("The passwords don't match")
    return first


def _user(users: dict, name: str) -> dict:
    user = find_user(users, name)
    if not user:
        raise SystemExit(f"No user '{name}'")
    return user


def main(argv: list) -> int:
    """Entry point; returns the exit status."""
    parser = argparse.ArgumentParser(prog="rivendell server users", description="Administer Rivendell's users")
    sub = parser.add_subparsers(dest="command", required=True)
    sub.add_parser("list", help="Every user")
    add = sub.add_parser("add", help="Create a password user")
    add.add_argument("username")
    add.add_argument("email")
    add.add_argument("--admin", action="store_true")
    for name in ("password", "disable", "enable"):
        sub.add_parser(name).add_argument("username")
    role = sub.add_parser("role")
    role.add_argument("username")
    role.add_argument("role", choices=["admin", "user"])
    args = parser.parse_args(argv)

    users = init_default_admin() if args.command != "list" else load_users()
    if args.command == "list":
        print(f"{'USERNAME':<28} {'ROLE':<6} {'SIGN-IN':<9} {'ACTIVE':<7} LAST SIGN-IN")
        for u in sorted(users.values(), key=lambda u: u["username"]):
            print(f"{u['username']:<28} {u['role']:<6} {'sso' if u.get('oidc_subject') else 'password':<9} "
                  f"{'yes' if u.get('is_active', True) else 'no':<7} {u.get('last_login') or '-'}")
        return 0
    if args.command == "add":
        if find_user(users, args.username) or find_user(users, args.email):
            raise SystemExit("Username or email already taken")
        user = new_user(args.username, args.email, role="admin" if args.admin else "user", password=_password())
        users[user["id"]] = user
    else:
        user = _user(users, args.username)
        active_admins = [u for u in users.values() if u["role"] == "admin" and u.get("is_active", True)]
        losing_admin = user["role"] == "admin" and (args.command == "disable" or getattr(args, "role", None) == "user")
        if losing_admin and len(active_admins) <= 1:
            raise SystemExit("That's the last active admin")
        if args.command == "password":
            user["hashed_password"] = hash_password(_password("New password: "))
        elif args.command == "role":
            user["role"] = args.role
        else:
            user["is_active"] = args.command == "enable"
    save_users(users)
    print(f"Done: {args.command} {args.username}")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
