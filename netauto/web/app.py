"""FastAPI application serving the netauto GUI.

Read-only throughout: the routes here call the same drivers the MCP server
uses, and there is no route that writes to a device. Accounts are per-user so
that every device-touching action is attributable in the activity log.

Anyone with an account can read device configuration, so this is meant to run
on an internal network, never on a public address.
"""

from __future__ import annotations

import hmac
import os
import secrets
import time
from pathlib import Path
from typing import Any

from fastapi import FastAPI, Form, Request
from fastapi.responses import HTMLResponse, RedirectResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from starlette.middleware.sessions import SessionMiddleware
from starlette.status import HTTP_303_SEE_OTHER

from netauto import __version__
from netauto.audit import audit_device
from netauto.drivers import supported_platforms
from netauto.drivers.base import platform_family
from netauto.errors import NetautoError
from netauto.session import connect, load_context
from netauto.web import activity
from netauto.web.users import UserStore

HERE = Path(__file__).resolve().parent
templates = Jinja2Templates(directory=str(HERE / "templates"))

#: Login throttle keyed by (client address, username).
_FAILURES: dict[tuple[str, str], tuple[int, float]] = {}
MAX_FAILURES = 5
LOCKOUT_SECONDS = 300


def create_app(users: UserStore | None = None) -> FastAPI:
    store = users or UserStore()
    if not store.list():
        raise RuntimeError(
            f"No accounts exist in {store.path}. The GUI serves device "
            f"configuration and will not start without one.\n"
            f"Create the first account:\n"
            f"    .venv/bin/python -m netauto.web.manage add <name> --admin"
        )
    secret_key = os.environ.get("NETAUTO_SECRET_KEY") or secrets.token_urlsafe(48)

    app = FastAPI(title="Netauto", docs_url=None, redoc_url=None)
    app.add_middleware(
        SessionMiddleware,
        secret_key=secret_key,
        session_cookie="netauto_session",
        max_age=8 * 3600,
        same_site="strict",
        https_only=False,  # set true behind TLS
    )
    app.mount("/static", StaticFiles(directory=str(HERE / "static")), name="static")

    # -- helpers ---------------------------------------------------------

    def current_user(request: Request) -> str | None:
        return request.session.get("user")

    def is_admin(request: Request) -> bool:
        return bool(request.session.get("admin"))

    def csrf(request: Request) -> str:
        token = request.session.get("csrf")
        if not token:
            token = secrets.token_urlsafe(32)
            request.session["csrf"] = token
        return token

    def csrf_ok(request: Request, submitted: str) -> bool:
        expected = request.session.get("csrf", "")
        return bool(expected) and hmac.compare_digest(expected, submitted or "")

    def page(request: Request, name: str, **ctx: Any) -> HTMLResponse:
        return templates.TemplateResponse(
            request=request,
            name=name,
            context={
                "version": __version__,
                "csrf_token": csrf(request),
                "user": current_user(request),
                "is_admin": is_admin(request),
                **ctx,
            },
        )

    def login_redirect() -> RedirectResponse:
        return RedirectResponse("/login", status_code=HTTP_303_SEE_OTHER)

    def client_addr(request: Request) -> str:
        return request.client.host if request.client else "unknown"

    def throttled(key: tuple[str, str]) -> int:
        count, first = _FAILURES.get(key, (0, 0.0))
        if count >= MAX_FAILURES and time.time() - first < LOCKOUT_SECONDS:
            return int(LOCKOUT_SECONDS - (time.time() - first))
        return 0

    def log(request: Request, action: str, target: str = "", detail: str = "") -> None:
        activity.record(current_user(request) or "anonymous", action, target, detail)

    # -- auth ------------------------------------------------------------

    @app.get("/login", response_class=HTMLResponse)
    def login_form(request: Request):
        if current_user(request):
            return RedirectResponse("/", status_code=HTTP_303_SEE_OTHER)
        return page(request, "login.html", error=None, username="")

    @app.post("/login", response_class=HTMLResponse)
    def login(request: Request, username: str = Form(""),
              password_input: str = Form(""), csrf_token: str = Form("")):
        username = username.strip().lower()
        key = (client_addr(request), username)
        wait = throttled(key)
        if wait:
            return page(request, "login.html", username=username,
                        error=f"Too many attempts. Try again in {wait} seconds.")
        if not csrf_ok(request, csrf_token):
            return page(request, "login.html", username=username,
                        error="Session expired. Try again.")
        try:
            user = store.verify(username, password_input)
        except NetautoError as exc:
            return page(request, "login.html", username=username, error=str(exc))
        if user:
            _FAILURES.pop(key, None)
            request.session.clear()
            request.session["user"] = user.name
            request.session["admin"] = user.admin
            request.session["csrf"] = secrets.token_urlsafe(32)
            activity.record(user.name, "login", client_addr(request))
            return RedirectResponse("/", status_code=HTTP_303_SEE_OTHER)
        count, first = _FAILURES.get(key, (0, time.time()))
        _FAILURES[key] = (count + 1, first if count else time.time())
        activity.record(username or "unknown", "login-failed", client_addr(request))
        return page(request, "login.html", username=username,
                    error="Incorrect username or password.")

    @app.post("/logout")
    def logout(request: Request):
        if current_user(request):
            log(request, "logout")
        request.session.clear()
        return login_redirect()

    # -- pages -----------------------------------------------------------

    @app.get("/", response_class=HTMLResponse)
    def dashboard(request: Request):
        if not current_user(request):
            return login_redirect()
        error, devices = None, []
        try:
            _, inventory = load_context()
            devices = list(inventory)
        except NetautoError as exc:
            error = str(exc)
        families: dict[str, int] = {}
        tags: dict[str, int] = {}
        for d in devices:
            fam = platform_family(d.platform)
            families[fam] = families.get(fam, 0) + 1
            for t in d.tags:
                tags[t] = tags.get(t, 0) + 1
        return page(request, "dashboard.html", devices=devices, error=error,
                    families=families, tags=sorted(tags.items()),
                    platforms=supported_platforms(),
                    recent=activity.tail(8) if is_admin(request) else [])

    @app.get("/devices", response_class=HTMLResponse)
    def device_list(request: Request, tag: str = "", platform: str = ""):
        if not current_user(request):
            return login_redirect()
        error, devices = None, []
        try:
            _, inventory = load_context()
            devices = inventory.select(tag=tag or None, platform=platform or None)
        except NetautoError as exc:
            error = str(exc)
        return page(request, "devices.html", devices=devices, error=error,
                    tag=tag, platform=platform, family_of=platform_family)

    @app.get("/devices/{name}", response_class=HTMLResponse)
    def device_detail(request: Request, name: str, show: str = ""):
        if not current_user(request):
            return login_redirect()
        facts = config = error = cmd_output = cmd_error = None
        try:
            settings, inventory = load_context()
            dev = inventory.get(name)
            log(request, "inspect-device", name)
            with connect(dev, settings) as driver:
                facts = driver.facts()
                try:
                    config = driver.get_config("running")
                except NetautoError as exc:
                    error = f"Configuration unavailable: {exc}"
                if show:
                    try:
                        cmd_output = driver.run_read(show)
                        log(request, "run-command", name, show)
                    except NetautoError as exc:
                        cmd_error = str(exc)
                        log(request, "command-refused", name, f"{show} — {exc}")
        except NetautoError as exc:
            error = str(exc)
        return page(request, "device.html", name=name, facts=facts, config=config,
                    error=error, show=show, cmd_output=cmd_output, cmd_error=cmd_error)

    @app.get("/audit", response_class=HTMLResponse)
    def audit_page(request: Request, tag: str = "", device: str = ""):
        if not current_user(request):
            return login_redirect()
        results, error, ran = [], None, bool(tag or device)
        tags: list[str] = []
        try:
            settings, inventory = load_context()
            tags = sorted({t for d in inventory for t in d.tags})
            if ran:
                targets = [inventory.get(device)] if device else inventory.select(tag=tag)
                log(request, "audit", device or f"tag:{tag}", f"{len(targets)} devices")
                results = [audit_device(d, settings) for d in targets]
        except NetautoError as exc:
            error = str(exc)
        totals = {"devices": len(results), "fail": 0, "pass": 0, "errors": 0}
        for r in results:
            if r.get("error"):
                totals["errors"] += 1
            totals["fail"] += r.get("summary", {}).get("fail", 0)
            totals["pass"] += r.get("summary", {}).get("pass", 0)
        return page(request, "audit.html", results=results, error=error, ran=ran,
                    tag=tag, device=device, tags=tags, totals=totals)

    @app.get("/discover", response_class=HTMLResponse)
    def discover_page(request: Request, cidr: str = "", interface: str = ""):
        if not current_user(request):
            return login_redirect()
        hosts, error = [], None
        if cidr:
            import shutil
            import subprocess

            binary = shutil.which("arp-scan")
            if not binary:
                error = "arp-scan is not installed on this server."
            else:
                cmd = [binary, cidr, "--plain"]
                if interface:
                    cmd += ["-I", interface]
                log(request, "discover", cidr, interface)
                try:
                    proc = subprocess.run(cmd, capture_output=True, text=True,
                                          timeout=180, check=False)
                    if proc.returncode != 0:
                        error = proc.stderr.strip() or f"arp-scan exited {proc.returncode}"
                    else:
                        for line in proc.stdout.splitlines():
                            parts = line.split("\t")
                            if len(parts) >= 2:
                                hosts.append({"ip": parts[0], "mac": parts[1].lower(),
                                              "vendor": parts[2] if len(parts) > 2 else ""})
                except subprocess.TimeoutExpired:
                    error = f"arp-scan timed out sweeping {cidr}"
        return page(request, "discover.html", hosts=hosts, error=error,
                    cidr=cidr, interface=interface)

    @app.get("/activity", response_class=HTMLResponse)
    def activity_page(request: Request):
        if not current_user(request):
            return login_redirect()
        if not is_admin(request):
            return page(request, "denied.html")
        return page(request, "activity.html", entries=activity.tail(200),
                    accounts=store.list(), log_path=activity.default_path())

    @app.get("/health")
    def health():
        return {"status": "ok", "version": __version__}

    return app


def main() -> None:
    import uvicorn

    host = os.environ.get("NETAUTO_WEB_HOST", "127.0.0.1")
    port = int(os.environ.get("NETAUTO_WEB_PORT", "8080"))
    uvicorn.run(create_app(), host=host, port=port, log_level="info")


if __name__ == "__main__":
    main()
