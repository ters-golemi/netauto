#!/usr/bin/env bash
# Start the Netauto web GUI.
#
#   ./run-web.sh                              # localhost only
#   NETAUTO_WEB_HOST=0.0.0.0 ./run-web.sh     # reachable by the team
#
# Accounts live in users.yaml. Create the first one with:
#   .venv/bin/python -m netauto.web.manage add <name> --admin
#
# Device credentials come from this same environment, so export those for the
# devices you want reachable through the GUI.

set -euo pipefail
cd "$(dirname "$0")"

if ! .venv/bin/python -m netauto.web.manage list 2>/dev/null | grep -q '^  '; then
  echo "No accounts exist yet." >&2
  echo "This server exposes device configuration and will not start without one:" >&2
  echo "    .venv/bin/python -m netauto.web.manage add <name> --admin" >&2
  exit 1
fi

if [ -z "${NETAUTO_SECRET_KEY:-}" ]; then
  echo "note: NETAUTO_SECRET_KEY unset — generating a temporary one." >&2
  echo "      Everyone is signed out on restart. Set it to keep sessions." >&2
fi

HOST="${NETAUTO_WEB_HOST:-127.0.0.1}"
PORT="${NETAUTO_WEB_PORT:-8080}"
echo "Netauto GUI on http://${HOST}:${PORT}"
[ "$HOST" = "0.0.0.0" ] && echo "Reachable from the network. Plain HTTP — see README on TLS." >&2

exec .venv/bin/python -m netauto.web.app
