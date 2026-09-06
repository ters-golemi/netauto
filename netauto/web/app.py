"""FastAPI application serving the netauto GUI.

Read-only throughout: the routes here call the same drivers the MCP server
uses, and there is no route that writes to a device. Accounts are per-user so
that every device-touching action is attributable in the activity log.

Anyone with an account can read device configuration, so this is meant to run
on an internal network, never on a public address.
"""

from __future__ import annotations

import contextlib
import hmac
import os
import secrets
import time
from pathlib import Path
from typing import Any

from fastapi import FastAPI, Form, Request, Response
from fastapi.responses import HTMLResponse, PlainTextResponse, RedirectResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from starlette.middleware.sessions import SessionMiddleware
from starlette.status import HTTP_303_SEE_OTHER

from netauto import __version__, drawio, metrics, topology
from netauto.audit import audit_device
from netauto.drivers import supported_platforms
from netauto.drivers.base import platform_family
from netauto.errors import NetautoError
from netauto.session import connect, load_context
from netauto.web import activity
from netauto.web.users import UserStore

HERE = Path(__file__).resolve().parent
#: Repository root, so pages can print commands the reader can actually
#: run. A relative path is useless in a browser: nobody viewing the page
#: knows what directory the server was started from.
REPO_ROOT = HERE.parent.parent
templates = Jinja2Templates(directory=str(HERE / "templates"))

#: Login throttle keyed by (client address, username).
_FAILURES: dict[tuple[str, str], tuple[int, float]] = {}
MAX_FAILURES = 5
LOCKOUT_SECONDS = 300

#: UID of the provisioned dashboard in deploy/grafana/dashboards/.
GRAFANA_DASHBOARD_UID = "netauto-compliance"


def grafana_health(base_url: str, timeout: float = 2.0) -> tuple[bool, str]:
    """Ask Grafana whether it is up, so a blank frame can be explained.

    An embedded iframe that fails renders as an empty rectangle with no clue
    why -- Grafana not running, or embedding not allowed. Checking server-side
    lets the page say which.
    """
    import json as jsonlib
    import urllib.error
    import urllib.request

    if not base_url.startswith(("http://", "https://")):
        return False, f"NETAUTO_GRAFANA_URL must be http(s), got {base_url!r}"
    try:
        with urllib.request.urlopen(f"{base_url}/api/health", timeout=timeout) as resp:
            body = jsonlib.loads(resp.read().decode() or "{}")
            return True, str(body.get("version", ""))
    except urllib.error.HTTPError as exc:
        # 401 or 403 still means Grafana is there and answering.
        return exc.code < 500, f"HTTP {exc.code}"
    except Exception as exc:
        return False, str(exc)


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

    # Metrics stay off unless a scrape token is set. Prometheus cannot hold a
    # session cookie, so this endpoint sits outside the login wall entirely and
    # the token is the only thing between a local process and your inventory.
    metrics_token = os.environ.get("NETAUTO_METRICS_TOKEN", "")
    collector = metrics.Collector() if metrics_token else None

    # The Metrics tab appears only when a Grafana URL is configured, so people
    # not running the stack do not get a nav item that leads nowhere.
    grafana_url = os.environ.get("NETAUTO_GRAFANA_URL", "").rstrip("/")

    @contextlib.asynccontextmanager
    async def lifespan(_app: FastAPI):
        if collector:
            collector.start()
        try:
            yield
        finally:
            if collector:
                collector.stop()

    app = FastAPI(title="Netauto", docs_url=None, redoc_url=None, lifespan=lifespan)
    app.state.collector = collector
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
                "grafana_enabled": bool(grafana_url),
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

    # The last collected graph, keyed by the tag filter that produced it. A
    # download then matches the table the operator just looked at, instead of
    # re-opening a session to every device the moment they click Save.
    last_topo: dict[str, Any] = {"tag": None, "topo": None}

    def collect_topology(request: Request, tag: str) -> Any:
        settings, inventory = load_context()
        devices = inventory.select(tag=tag) if tag else list(inventory)
        log(request, "topology", tag or "all", f"{len(devices)} devices")
        built = topology.build(inventory, settings, devices)
        last_topo.update(tag=tag, topo=built)
        return built

    def topology_for(request: Request, tag: str) -> Any:
        if last_topo["topo"] is not None and last_topo["tag"] == tag:
            return last_topo["topo"]
        return collect_topology(request, tag)

    @app.get("/topology", response_class=HTMLResponse)
    def topology_page(request: Request, run: str = "", tag: str = ""):
        if not current_user(request):
            return login_redirect()
        error, topo, tags = None, None, []
        try:
            _, inventory = load_context()
            tags = sorted({t for d in inventory for t in d.tags})
        except NetautoError as exc:
            error = str(exc)
        if run and not error:
            try:
                topo = collect_topology(request, tag)
            except NetautoError as exc:
                error = str(exc)
        return page(request, "topology.html", topo=topo, error=error, tag=tag,
                    tags=tags, ran=bool(run) and not error,
                    legend=drawio.legend_note(topo) if topo else "")

    @app.get("/topology.drawio")
    def topology_drawio(request: Request, tag: str = ""):
        """The editable file: open in draw.io, or in Visio via draw.io."""
        if not current_user(request):
            return login_redirect()
        try:
            topo = topology_for(request, tag)
        except NetautoError as exc:
            return PlainTextResponse(str(exc), status_code=409)
        return Response(
            drawio.render(topo),
            media_type="application/xml",
            headers={"Content-Disposition":
                     'attachment; filename="network-topology.drawio"'},
        )

    @app.get("/topology.json")
    def topology_json(request: Request, tag: str = ""):
        if not current_user(request):
            return login_redirect()
        try:
            topo = topology_for(request, tag)
        except NetautoError as exc:
            return PlainTextResponse(str(exc), status_code=409)
        return topology.as_dict(topo)

    @app.get("/grafana", response_class=HTMLResponse)
    def grafana_page(request: Request):
        """The Metrics tab: the provisioned dashboard, embedded.

        Grafana keeps its own login. Both services are same-site (ports do not
        affect SameSite), so a Grafana session cookie is sent inside this frame
        once the viewer has signed in there too.
        """
        if not current_user(request):
            return login_redirect()
        if not grafana_url:
            return page(request, "grafana.html", grafana_url="", reachable=False,
                        detail="", embed_url="", dashboard_url="",
                        deploy_dir=REPO_ROOT / "deploy" / "grafana")
        reachable, detail = grafana_health(grafana_url)
        dashboard_url = f"{grafana_url}/d/{GRAFANA_DASHBOARD_UID}"
        return page(request, "grafana.html", grafana_url=grafana_url,
                    reachable=reachable, detail=detail,
                    dashboard_url=dashboard_url, deploy_dir=REPO_ROOT / "deploy" / "grafana",
                    # kiosk drops Grafana's own chrome, which would otherwise
                    # put a second nav bar inside our page.
                    embed_url=f"{dashboard_url}?kiosk&from=now-7d&to=now&refresh=1m")

    @app.get("/health")
    def health():
        return {"status": "ok", "version": __version__}

    @app.get("/metrics", response_class=PlainTextResponse)
    def prometheus_metrics(request: Request):
        """Prometheus scrape target: serves the cached audit, never a live one.

        Scraping this touches no device. The background collector is what talks
        to the estate, on its own interval.
        """
        if collector is None:
            return PlainTextResponse(
                "Metrics are disabled. Set NETAUTO_METRICS_TOKEN to enable them.",
                status_code=404)
        supplied = request.headers.get("authorization", "")
        if not hmac.compare_digest(supplied, f"Bearer {metrics_token}"):
            # Not logged to the activity log: Prometheus scrapes every 30s and
            # would drown the record of what people did.
            return PlainTextResponse("Unauthorized", status_code=401)
        return PlainTextResponse(metrics.render(collector.snapshot),
                                 media_type=metrics.CONTENT_TYPE)

    return app


def main() -> None:
    import uvicorn

    host = os.environ.get("NETAUTO_WEB_HOST", "127.0.0.1")
    port = int(os.environ.get("NETAUTO_WEB_PORT", "8080"))
    uvicorn.run(create_app(), host=host, port=port, log_level="info")


if __name__ == "__main__":
    main()
