#!/usr/bin/env bash
# Start the Netauto web GUI.
#
#   ./run-web.sh            # localhost only, for trying it out
#   NETAUTO_WEB_HOST=0.0.0.0 ./run-web.sh    # reachable by the team
#
# NETAUTO_WEB_PASSWORD must be set. Device credentials come from the same
# environment the MCP server uses, so export those too for the devices you
# want reachable through the GUI.

set -euo pipefail
cd "$(dirname "$0")"

if [ -z "${NETAUTO_WEB_PASSWORD:-}" ]; then
  echo "NETAUTO_WEB_PASSWORD is not set." >&2
  echo "This server exposes device configuration, so it will not start without one:" >&2
  echo "    export NETAUTO_WEB_PASSWORD='<a password to share with your team>'" >&2
  exit 1
fi

if [ -z "${NETAUTO_SECRET_KEY:-}" ]; then
  echo "note: NETAUTO_SECRET_KEY unset — generating a temporary one." >&2
  echo "      Sessions will be invalidated on restart. Set it to keep them." >&2
fi

HOST="${NETAUTO_WEB_HOST:-127.0.0.1}"
PORT="${NETAUTO_WEB_PORT:-8080}"
echo "Netauto GUI on http://${HOST}:${PORT}"
[ "$HOST" = "0.0.0.0" ] && echo "Reachable from the network. Plain HTTP — see README on TLS." >&2

exec .venv/bin/python -m netauto.web.app
