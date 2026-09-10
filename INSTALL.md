# Installing Netauto on Ubuntu

A production-shaped install: dedicated service user, systemd unit, TLS, and
firewall. Tested against **Ubuntu 24.04 LTS**, which ships Python 3.12.

**Python 3.11 is the floor**, and it is a hard one: the Meraki SDK requires it,
so `pip install -r requirements-app.txt` fails outright on anything older
rather than degrading. That rules out **22.04 LTS** with its stock Python 3.10
-- install a newer interpreter there (deadsnakes) or use 24.04.

Budget about 20 minutes.

## Before you start

Netauto reads configuration from network devices, so **where you put this VM
matters more than how you install it**. It needs:

- Network reachability to the devices you intend to manage
- Ideally a management VLAN rather than a general user network
- 2 GB RAM, 1 vCPU, 5 GB disk — the venv is roughly 200 MB
- `sudo` on the VM

The server holds device credentials in its environment. Anyone who can reach
it and has an account can read your network's configuration. Treat it as
infrastructure, not as a convenience box.

---

## 1. System packages

```bash
sudo apt update
sudo apt install -y python3 python3-venv python3-dev git arp-scan
```

Optional but useful for troubleshooting from the same VM:

```bash
sudo apt install -y nmap bind9-dnsutils tcpdump
```

`bind9-dnsutils` is what provides `dig` on Ubuntu — there is no `bind-tools`
package.

If dependency installation later fails while building a wheel, add the
toolchain and retry:

```bash
sudo apt install -y build-essential libssl-dev libffi-dev
```

## 2. Service user and directories

Run as a dedicated system account with no login shell, never as root and never
as your own user.

```bash
sudo useradd --system --home /opt/netauto --shell /usr/sbin/nologin netauto
sudo mkdir -p /opt/netauto /etc/netauto /var/lib/netauto
sudo chown netauto:netauto /opt/netauto /var/lib/netauto
sudo chmod 750 /etc/netauto
```

Three locations, deliberately separate:

| Path | Holds | Written by |
|---|---|---|
| `/opt/netauto` | code and venv | you, at install and upgrade |
| `/etc/netauto` | secrets (env file) | you |
| `/var/lib/netauto` | accounts, activity log | the service |

## 3. Get the code

From your existing repository — over SSH, from a Git remote, or by copying the
directory:

```bash
sudo -u netauto git clone <your-repo-url> /opt/netauto
```

No remote? Copy it from your workstation and fix ownership:

```bash
# on your workstation
rsync -a --exclude .venv --exclude '*.pyc' ~/Work/netauto/ ubuntu@vm:/tmp/netauto/
# on the VM
sudo cp -r /tmp/netauto/. /opt/netauto/ && sudo chown -R netauto:netauto /opt/netauto
```

## 4. Virtual environment

Ubuntu marks its system Python as externally managed, so a venv is required —
`pip install` outside one will refuse.

```bash
cd /opt/netauto
sudo -u netauto python3 -m venv .venv
sudo -u netauto .venv/bin/pip install --upgrade pip
sudo -u netauto .venv/bin/pip install -r requirements-app.txt
```

Use `requirements-app.txt`, not `requirements.txt`. The latter is an exact
freeze from Python 3.14 and will fight a different interpreter; the former
pins minimum versions and resolves cleanly on 3.11–3.14.

Confirm it imported. The test tools are a separate file, since the service
does not need them at runtime:

```bash
sudo -u netauto .venv/bin/pip install -r requirements-dev.txt
sudo -u netauto .venv/bin/python -m pytest tests/ -q
```

You should see **398 passed**. These tests need no network devices, so this
validates the install before any device credentials exist.

## 5. Let discovery work without root

`arp-scan` needs raw sockets. Grant the binary the capability rather than
running anything as root:

```bash
sudo setcap cap_net_raw+ep "$(command -v arp-scan)"
getcap "$(command -v arp-scan)"
```

Skip this if you do not need the Discover page. Only the ARP sweep needs the
capability: the SSH/telnet port check is an ordinary TCP connect, so it works
as an unprivileged user with or without this step.

## 6. Configuration and inventory

```bash
cd /opt/netauto
sudo -u netauto cp config.example.yaml config.yaml
sudo -u netauto cp inventory/devices.example.yaml inventory/devices.yaml
sudo -u netauto nano inventory/devices.yaml
```

Each device names a `credentials` prefix rather than carrying a password. A
device with prefix `CORE_SW` is authenticated from `CORE_SW_USERNAME` and
`CORE_SW_PASSWORD` in the environment, which is why the inventory is safe to
keep in Git.

Leave `allow_writes: false` in `config.yaml`. Nothing in this toolkit
implements a commit path; the setting exists so that any future write support
has to be turned on deliberately.

## 7. Secrets

One file, readable only by the service:

```bash
sudo tee /etc/netauto/netauto.env >/dev/null <<EOF
# Session signing. Changing this signs everyone out.
NETAUTO_SECRET_KEY=$(python3 -c 'import secrets;print(secrets.token_urlsafe(48))')

# Bind to localhost; nginx terminates TLS in front (step 10).
NETAUTO_WEB_HOST=127.0.0.1
NETAUTO_WEB_PORT=8080

# State outside the code directory, which systemd mounts read-only.
NETAUTO_USERS_FILE=/var/lib/netauto/users.yaml
NETAUTO_ACTIVITY_LOG=/var/lib/netauto/activity.log

# Device credentials, one pair per inventory prefix.
CORE_SW_USERNAME=readonly
CORE_SW_PASSWORD=change-me
EOF

sudo chown root:netauto /etc/netauto/netauto.env
sudo chmod 640 /etc/netauto/netauto.env
```

Create a **read-only account on each device** for these credentials. Netauto
never needs write privileges, and giving it any means a mistake elsewhere can
become a change to your network.

## 8. First administrator account

```bash
cd /opt/netauto
sudo -u netauto env NETAUTO_USERS_FILE=/var/lib/netauto/users.yaml \
  .venv/bin/python -m netauto.web.manage add adis --admin
```

It prompts for the password twice. Minimum 10 characters, stored as a bcrypt
hash at mode `0600`.

The service refuses to start with no accounts, so this step is not optional.

## 9. systemd service

```bash
sudo tee /etc/systemd/system/netauto-web.service >/dev/null <<'EOF'
[Unit]
Description=Netauto web GUI
Documentation=file:/opt/netauto/README.md
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User=netauto
Group=netauto
WorkingDirectory=/opt/netauto
EnvironmentFile=/etc/netauto/netauto.env
ExecStart=/opt/netauto/.venv/bin/python -m netauto.web.app
Restart=on-failure
RestartSec=5

# Discovery needs raw sockets. Remove both lines if you do not use the
# Discover page -- they grant CAP_NET_RAW to the Python process itself, which
# is broader than the setcap in step 5. File capabilities alone will not work
# here, because NoNewPrivileges suppresses them.
AmbientCapabilities=CAP_NET_RAW
CapabilityBoundingSet=CAP_NET_RAW

NoNewPrivileges=true
PrivateTmp=true
ProtectSystem=strict
ProtectHome=true
ProtectKernelTunables=true
ProtectKernelModules=true
ProtectControlGroups=true
RestrictSUIDSGID=true
RestrictRealtime=true
LockPersonality=true
ReadWritePaths=/var/lib/netauto

[Install]
WantedBy=multi-user.target
EOF

sudo systemctl daemon-reload
sudo systemctl enable --now netauto-web
sudo systemctl status netauto-web --no-pager
```

`ProtectSystem=strict` mounts the whole filesystem read-only apart from
`ReadWritePaths`. That is why accounts and the activity log live in
`/var/lib/netauto` rather than beside the code.

Check it answers:

```bash
curl -s http://127.0.0.1:8080/health
# {"status":"ok","version":"0.1.0"}
```

## 10. TLS

The application speaks plain HTTP. Left as-is on a shared network, passwords
and retrieved device configurations cross the wire in clear text. Put nginx in
front of it.

```bash
sudo apt install -y nginx
sudo openssl req -x509 -nodes -days 825 -newkey rsa:2048 \
  -keyout /etc/ssl/private/netauto.key \
  -out /etc/ssl/certs/netauto.crt \
  -subj "/CN=netauto.internal" \
  -addext "subjectAltName=DNS:netauto.internal,IP:<VM-IP>"
sudo chmod 640 /etc/ssl/private/netauto.key
```

Replace `<VM-IP>` with the VM's address, and use your own hostname if you have
internal DNS.

```bash
sudo tee /etc/nginx/sites-available/netauto >/dev/null <<'EOF'
server {
    listen 80;
    server_name netauto.internal;
    return 301 https://$host$request_uri;
}

server {
    listen 443 ssl;
    server_name netauto.internal;

    ssl_certificate     /etc/ssl/certs/netauto.crt;
    ssl_certificate_key /etc/ssl/private/netauto.key;
    ssl_protocols       TLSv1.2 TLSv1.3;

    add_header Strict-Transport-Security "max-age=31536000" always;
    add_header X-Frame-Options DENY always;
    add_header X-Content-Type-Options nosniff always;

    # Audits, topology runs and sweeps are slow -- each opens a session per
    # device -- so do not cut them off mid-run.
    proxy_read_timeout 300s;

    location / {
        proxy_pass http://127.0.0.1:8080;
        proxy_set_header Host              $host;
        proxy_set_header X-Real-IP         $remote_addr;
        proxy_set_header X-Forwarded-For   $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
    }
}
EOF

sudo ln -sf /etc/nginx/sites-available/netauto /etc/nginx/sites-enabled/
sudo rm -f /etc/nginx/sites-enabled/default
sudo nginx -t && sudo systemctl reload nginx
```

Now that TLS terminates in front, mark the session cookie secure. Edit
`/opt/netauto/netauto/web/app.py`, set `https_only=True` in the
`SessionMiddleware` block, and restart:

```bash
sudo systemctl restart netauto-web
```

HTTP/2 is deliberately omitted: the `http2 on;` directive needs nginx 1.25.1,
and Ubuntu ships 1.24 on 24.04 and 1.18 on 22.04. It buys nothing for an
internal admin GUI, but if you want it on an older nginx the syntax is
`listen 443 ssl http2;`.

A self-signed certificate will warn in browsers. For a clean padlock, issue the
certificate from your internal CA and distribute its root, or use a real
hostname with Let's Encrypt DNS-01.

## 11. Firewall

Restrict to the networks that should reach it. Do not expose this to the
internet.

```bash
sudo ufw allow from <MGMT-SUBNET> to any port 443 proto tcp
sudo ufw allow from <MGMT-SUBNET> to any port 22 proto tcp
sudo ufw enable
sudo ufw status verbose
```

Port 8080 needs no rule — the service binds to localhost only.

---

## Verify the install

| Check | Command | Expected |
|---|---|---|
| Service is up | `systemctl is-active netauto-web` | `active` |
| Health endpoint | `curl -s localhost:8080/health` | `{"status":"ok"...}` |
| TLS responds | `curl -kI https://localhost/` | `303` to `/login` |
| Auth is enforced | `curl -ks https://localhost/devices \| head -1` | redirect, not device data |
| Accounts exist | `manage list` (step 8 form) | your admin account |
| Tests | `.venv/bin/python -m pytest tests/ -q` | `207 passed` |

Then open `https://<vm>/` in a browser, sign in, and confirm the device list
loads. Inspecting a device opens a live connection using the credentials from
step 7 — the first inspection is the real test of the whole chain.

## Day-two operations

**Add a colleague.** Takes effect immediately; no restart.

```bash
cd /opt/netauto
sudo -u netauto env NETAUTO_USERS_FILE=/var/lib/netauto/users.yaml \
  .venv/bin/python -m netauto.web.manage add teammate
```

Omit `--admin` for a standard account: they can use every device page but
cannot read the activity log.

**Who did what.**

```bash
sudo tail -f /var/lib/netauto/activity.log
sudo grep '"action": "run-command"' /var/lib/netauto/activity.log | tail -20
```

JSON lines, one per action, attributed to an account. Admins can read the same
thing at `/activity`.

Mind the space after the colon: the log is written by `json.dumps`, so
`'"action":"run-command"'` matches nothing and reads as "no commands were ever
run", which is the wrong answer to an audit question. When it matters, parse
rather than grep:

```bash
sudo python3 -c '
import json, sys
for line in open("/var/lib/netauto/activity.log"):
    e = json.loads(line)
    if e["action"] == "run-command":
        print(e["ts"], e["user"], e["target"], e["detail"])'
```

**Service logs.**

```bash
sudo journalctl -u netauto-web -f
```

**Upgrade.**

```bash
cd /opt/netauto
sudo -u netauto git pull
sudo -u netauto .venv/bin/pip install -r requirements-app.txt
sudo -u netauto .venv/bin/python -m pytest tests/ -q
sudo systemctl restart netauto-web
```

**Back up.** Three things, none of them the venv:

```bash
sudo tar czf netauto-backup-$(date +%F).tar.gz \
  /etc/netauto/netauto.env \
  /var/lib/netauto/users.yaml \
  /opt/netauto/inventory/devices.yaml
```

The archive contains device credentials in clear text. Store it accordingly.

## Troubleshooting

**Service will not start, "No accounts exist"** — step 8 was skipped, or it
wrote to a different path than `NETAUTO_USERS_FILE` in the env file. Check
both agree.

**"Read-only file system" in the journal** — something is writing outside
`ReadWritePaths`. Confirm `NETAUTO_USERS_FILE` and `NETAUTO_ACTIVITY_LOG` both
point into `/var/lib/netauto`.

**Discover page reports arp-scan errors** — the `AmbientCapabilities` lines are
missing from the unit, or `arp-scan` is not installed. The `setcap` from step 5
alone is not enough under `NoNewPrivileges=true`; systemd must grant the
capability.

**A device shows "Missing environment variable(s)"** — the message names
exactly which variable. Add it to `/etc/netauto/netauto.env` and restart. This
is the intended failure: credentials are never read from the inventory.

**Signed out after every restart** — `NETAUTO_SECRET_KEY` is unset, so a new
one is generated each boot. Set it in the env file.

**Audit or topology times out in the browser** — raise `proxy_read_timeout` in
nginx. Both open a session per device and run while the request is held open,
so a large estate takes minutes.

## Uninstalling

```bash
sudo systemctl disable --now netauto-web
sudo rm /etc/systemd/system/netauto-web.service
sudo rm -f /etc/nginx/sites-enabled/netauto /etc/nginx/sites-available/netauto
sudo systemctl daemon-reload && sudo systemctl reload nginx
sudo rm -rf /opt/netauto /var/lib/netauto /etc/netauto
sudo userdel netauto
```

## What this install does not do

It does not change your network. There is no commit path in the codebase,
`net_run_show` is checked against a per-vendor read-only allowlist, and a test
asserts the only POST routes in the web application are `/login` and
`/logout`.

The vendor drivers for Cisco, Juniper, Aruba, Meraki and Fortinet are written
against each SDK's documented API but have not been exercised against physical
hardware. Expect to adjust response parsing on first contact with real gear —
budget time for that on your first device, not on your fiftieth.
