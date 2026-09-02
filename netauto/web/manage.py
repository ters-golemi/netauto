"""Manage web GUI accounts.

    python -m netauto.web.manage add alice --admin
    python -m netauto.web.manage list
    python -m netauto.web.manage passwd alice
    python -m netauto.web.manage remove bob

Passwords are prompted for, never taken as arguments, so they stay out of
shell history and the process table.
"""

from __future__ import annotations

import argparse
import getpass
import sys

from netauto.web.users import UserError, UserStore


def _prompt_password(name: str) -> str:
    first = getpass.getpass(f"New password for {name}: ")
    second = getpass.getpass("Repeat: ")
    if first != second:
        raise UserError("Passwords do not match.")
    return first


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="netauto.web.manage", description=__doc__)
    parser.add_argument("--file", help="accounts file (default: users.yaml)")
    sub = parser.add_subparsers(dest="cmd", required=True)

    p_add = sub.add_parser("add", help="create an account")
    p_add.add_argument("name")
    p_add.add_argument("--admin", action="store_true", help="may view the activity log")

    sub.add_parser("list", help="list accounts")

    p_pw = sub.add_parser("passwd", help="change a password")
    p_pw.add_argument("name")

    p_rm = sub.add_parser("remove", help="delete an account")
    p_rm.add_argument("name")

    p_ad = sub.add_parser("admin", help="grant or revoke admin")
    p_ad.add_argument("name")
    p_ad.add_argument("--revoke", action="store_true")

    args = parser.parse_args(argv)
    store = UserStore(args.file)

    try:
        if args.cmd == "add":
            store.add(args.name, _prompt_password(args.name), admin=args.admin)
            print(f"Created {args.name}{' (admin)' if args.admin else ''} in {store.path}")

        elif args.cmd == "list":
            users = store.list()
            if not users:
                print(f"No accounts in {store.path}.")
                print("Create the first one:  python -m netauto.web.manage add <name> --admin")
                return 0
            print(f"{len(users)} account(s) in {store.path}:")
            for u in users:
                print(f"  {u.name}{'  [admin]' if u.admin else ''}")

        elif args.cmd == "passwd":
            store.set_password(args.name, _prompt_password(args.name))
            print(f"Password updated for {args.name}. Existing sessions stay valid "
                  f"until they expire.")

        elif args.cmd == "remove":
            store.remove(args.name)
            print(f"Removed {args.name}.")

        elif args.cmd == "admin":
            store.set_admin(args.name, not args.revoke)
            print(f"{args.name} is {'no longer' if args.revoke else 'now'} an admin.")

    except UserError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1
    except (KeyboardInterrupt, EOFError):
        print("\naborted", file=sys.stderr)
        return 130
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
