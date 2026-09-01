#!/home/adiscato/Work/netauto/.venv/bin/python
"""Pull the client list from the Deco gateway.

The Deco's own client table carries DHCP hostnames that a LAN scan cannot see,
so this is what resolves devices that arp-scan can only identify by OUI.

The password is never stored. Supply it via the DECO_PASSWORD environment
variable, or let the script prompt for it:

    DECO_PASSWORD=... ./deco_clients.py
    ./deco_clients.py --fingerprint >> scans/latest.txt
"""

import argparse
import getpass
import os
import sys

from tplink_deco_api import AuthenticationError, DecoClient, DecoError

DEFAULT_HOST = "192.168.68.1"
DEFAULT_USER = "admin"


def sort_key(client):
    """Sort by final octet, keeping non-numeric addresses at the end."""
    try:
        return (0, int(client.ip.rsplit(".", 1)[1]))
    except (AttributeError, IndexError, ValueError):
        return (1, 0)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--host", default=DEFAULT_HOST)
    parser.add_argument("--user", default=DEFAULT_USER)
    parser.add_argument(
        "--fingerprint",
        action="store_true",
        help="emit 'ip mac' lines for diffing against a baseline",
    )
    args = parser.parse_args()

    password = os.environ.get("DECO_PASSWORD") or getpass.getpass(
        f"Deco password for {args.user}@{args.host}: "
    )

    client = DecoClient(args.host, args.user, password)
    try:
        client.login()
        clients = client.get_client_list()
    except AuthenticationError:
        sys.exit("Authentication failed. Check the Deco admin password.")
    except DecoError as exc:
        sys.exit(f"Deco API error: {exc}")
    finally:
        try:
            client.logout()
        except DecoError:
            pass

    clients.sort(key=sort_key)

    if args.fingerprint:
        for c in clients:
            print(f"{c.ip:<16} {c.mac.lower()}")
        return

    print(f"{'IP':<16} {'MAC':<19} {'LINK':<9} NAME")
    print("-" * 72)
    for c in clients:
        link = "wired" if c.wire_type == "wired" else (c.connection_type or "wifi")
        print(f"{c.ip:<16} {c.mac.lower():<19} {link:<9} {c.name or '-'}")
    print(f"\n{len(clients)} clients reported by the Deco.")


if __name__ == "__main__":
    main()
