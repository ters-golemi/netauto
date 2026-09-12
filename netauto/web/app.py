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

from netauto import __version__, adhoc, drawio, metrics, scan, topology
from netauto.audit import audit_device
from netauto.config import Settings
from netauto.drivers import supported_platforms
from netauto.workflows import runner as workflows
from netauto.workflows import spec as workflow_spec
from netauto.workflows.document import build as build_document
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
    # Runs live here and nowhere else. See workflows/runner.py for why they are
    # not written to disk.
    workflow_service = workflows.WorkflowService()
    app.state.workflows = workflow_service
    # Addresses this process has actually seen on the wire. An ad-hoc
    # connection may target nothing else, so this is a safety boundary rather
    # than a cache -- see netauto/adhoc.py for what it is defending against.
    discovered = adhoc.Discovered()
    app.state.discovered = discovered
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

    def page(request: Request, template: str, /, **ctx: Any) -> HTMLResponse:
        """Render a template with the context every page needs.

        The template is positional-only, and its parameter is not called
        "name". It used to be, which collided with the context every device
        page passes -- "name" is the device -- so /devices/<name> raised
        TypeError for anyone logged in, and only for anyone logged in.
        """
        return templates.TemplateResponse(
            request=request,
            name=template,
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

    def inspect(request: Request, dev: Any, settings: Settings,
                show: str) -> dict[str, Any]:
        """Facts, running config and one guarded command, for any device.

        Shared by the inventory page and an ad-hoc session, because the two
        differ only in where the Device came from. Nothing here knows which,
        which is the point: a discovered host gets the same guard and the same
        audit trail as a managed one.
        """
        ctx: dict[str, Any] = {"facts": None, "config": None, "error": None,
                               "cmd_output": None, "cmd_error": None}
        try:
            with connect(dev, settings) as driver:
                ctx["facts"] = driver.facts()
                try:
                    ctx["config"] = driver.get_config("running")
                except NetautoError as exc:
                    ctx["error"] = f"Configuration unavailable: {exc}"
                if show:
                    try:
                        ctx["cmd_output"] = driver.run_read(show)
                        log(request, "run-command", dev.name, show)
                    except NetautoError as exc:
                        ctx["cmd_error"] = str(exc)
                        log(request, "command-refused", dev.name, f"{show} — {exc}")
        except NetautoError as exc:
            ctx["error"] = str(exc)
        return ctx

    def not_inspected(error: str) -> dict[str, Any]:
        return {"facts": None, "config": None, "error": error,
                "cmd_output": None, "cmd_error": None}

    @app.get("/devices/{name}", response_class=HTMLResponse)
    def device_detail(request: Request, name: str, show: str = ""):
        if not current_user(request):
            return login_redirect()
        try:
            settings, inventory = load_context()
            dev = inventory.get(name)
            log(request, "inspect-device", name)
            ctx = inspect(request, dev, settings, show)
        except NetautoError as exc:
            ctx = not_inspected(str(exc))
        return page(request, "device.html", name=name, show=show, **ctx)

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
                # Audits are the only thing that contacts devices, so they are
                # also what feeds the metrics. Nothing polls on a timer.
                if collector is not None:
                    collector.record(results)
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
    def discover_page(request: Request, cidr: str = "", interface: str = "",
                      probe: str = "", ports: str = ""):
        if not current_user(request):
            return login_redirect()
        hosts: list[scan.Host] = []
        error = None
        wanted: tuple[int, ...] = ()
        if cidr:
            try:
                wanted = scan.parse_ports(ports) if probe else ()
                # Logged before the sweep runs: an attempted scan is worth
                # attributing whether or not it finds anything.
                detail = interface
                if wanted:
                    detail = f"{interface} ports={','.join(str(p) for p in wanted)}".strip()
                log(request, "discover", cidr, detail)
                hosts = scan.arp_sweep(cidr, interface)
                if wanted and hosts:
                    hosts = scan.probe_hosts(hosts, wanted)
                # Knowing which answers are already managed is most of the
                # value: what is left is what nobody put in the inventory.
                with contextlib.suppress(NetautoError):
                    hosts = scan.annotate_known(hosts, load_context()[1])
                # Only these addresses become connectable, and only for a while.
                discovered.record(hosts)
            except NetautoError as exc:
                error = str(exc)
        return page(request, "discover.html", hosts=hosts, error=error,
                    cidr=cidr, interface=interface, probe=bool(probe),
                    ports=ports, wanted=wanted, port_names=scan.PORT_NAMES)

    @app.get("/connect", response_class=HTMLResponse)
    def connect_page(request: Request, ip: str = "", platform: str = "",
                     credentials: str = "", show: str = ""):
        """Open a read-only session against a host the inventory has never met.

        Same drivers, same guard, same log as a managed device. The Device is
        built per request and stored nowhere; what makes that safe is that the
        address must be one this server swept, not one a URL supplied.
        """
        if not current_user(request):
            return login_redirect()
        ip = ip.strip()
        seen = discovered.get(ip)
        # Say up front what pressing Connect would say, rather than letting
        # someone pick a platform and a prefix for a target that cannot be
        # reached. Same call the submit path makes, so the wording is one
        # sentence in one place.
        blocked = None
        if ip:
            try:
                adhoc.assert_connectable(ip, discovered)
            except NetautoError as exc:
                blocked = str(exc)
        form: dict[str, Any] = {
            "ip": ip, "seen": seen, "credentials": credentials,
            "platform": platform or adhoc.guess_for(seen),
            "platforms": adhoc.connectable_platforms(),
            "prefixes": adhoc.credential_prefixes(),
            "blocked": blocked,
            "segment": adhoc.likely_segment(ip) if blocked else "",
        }
        if not (platform and credentials):
            # Nothing chosen yet: ask, with the sweep's evidence in view.
            return page(request, "connect.html", error=None, **form)
        try:
            dev = adhoc.build_device(ip, platform, credentials, discovered)
            log(request, "connect", dev.name, f"{platform} as {dev.credentials_prefix}")
            ctx = inspect(request, dev, Settings.load(), show)
        except NetautoError as exc:
            return page(request, "connect.html", error=str(exc), **form)
        return page(request, "device.html", name=dev.name, show=show, adhoc=True,
                    crumb_href="/discover", crumb_label="Discover",
                    carry={"ip": ip, "platform": platform, "credentials": credentials},
                    **ctx)

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

    # -- workflows -------------------------------------------------------

    @app.get("/workflows", response_class=HTMLResponse)
    def workflows_page(request: Request):
        if not current_user(request):
            return login_redirect()
        error, by_platform = None, []
        try:
            _settings, inventory = load_context()
            counts: dict[str, int] = {}
            for device in inventory:
                counts[device.platform] = counts.get(device.platform, 0) + 1
            for platform in supported_platforms():
                by_platform.append({
                    "platform": platform,
                    "devices": counts.get(platform, 0),
                    "workflows": sorted(workflow_spec.for_platform(platform),
                                        key=lambda w: w.kind),
                })
        except NetautoError as exc:
            error = str(exc)
        return page(request, "workflows.html", error=error,
                    by_platform=by_platform, runs=workflow_service.store.list()[:10])

    @app.post("/workflows/{workflow_id}/start")
    def workflow_start(request: Request, workflow_id: str,
                       csrf_token: str = Form(""), tag: str = Form(""),
                       image: str = Form(""), server: str = Form(""),
                       stage_only: str = Form("")):
        if not current_user(request):
            return login_redirect()
        if not csrf_ok(request, csrf_token):
            return page(request, "denied.html", reason="Invalid form token.")
        try:
            spec_ = workflow_spec.get(workflow_id)
        except KeyError:
            return PlainTextResponse("No such workflow.", status_code=404)
        try:
            settings, inventory = load_context()
        except NetautoError as exc:
            return page(request, "denied.html", reason=str(exc))

        targets = [d for d in inventory.select(platform=spec_.platform)
                   if not tag or tag in d.tags]
        if not targets:
            return page(request, "denied.html", reason=(
                f"No {spec_.platform} devices in the inventory"
                + (f" tagged {tag!r}." if tag else ".")
                + " A workflow with nothing to run against would report a "
                  "clean result, which would be a lie."))
        params = {}
        if spec_.kind == workflow_spec.SOFTWARE_UPGRADE:
            params = {"image": image.strip(), "server": server.strip(),
                      "stage_only": bool(stage_only)}
        armed = "armed" if (params.get("image") and params.get("server")
                            and settings.allow_writes) else "read-only"
        log(request, "workflow", spec_.id, f"{len(targets)} devices ({armed})")
        run = workflow_service.start(spec_, inventory, settings, targets,
                                     current_user(request) or "anonymous",
                                     params=params)
        return RedirectResponse(f"/workflows/runs/{run.id}",
                                status_code=HTTP_303_SEE_OTHER)

    # Declared before the {run_id} page route: FastAPI matches in order,
    # and "{run_id}" happily swallows "abc.docx".
    @app.get("/workflows/runs/{run_id}.docx")
    def workflow_document(request: Request, run_id: str):
        """The editable Word document, built on demand and never stored."""
        if not current_user(request):
            return login_redirect()
        run = workflow_service.store.get(run_id)
        if run is None:
            return PlainTextResponse("No such run.", status_code=404)
        if run.running:
            return PlainTextResponse(
                "This run has not finished. The document would describe a "
                "partial collection.", status_code=409)
        log(request, "workflow-document", run.workflow_id, run_id)
        stem = f"{run.kind}-{run.platform}-{run.created_label[:10]}"
        return Response(
            build_document(run),
            media_type=("application/vnd.openxmlformats-officedocument"
                        ".wordprocessingml.document"),
            headers={"Content-Disposition": f'attachment; filename="{stem}.docx"'},
        )

    @app.get("/workflows/runs/{run_id}", response_class=HTMLResponse)
    def workflow_run_page(request: Request, run_id: str):
        if not current_user(request):
            return login_redirect()
        run = workflow_service.store.get(run_id)
        if run is None:
            return page(request, "denied.html", reason=(
                "No such run. Runs are held in memory only -- restarting "
                "netauto-web discards them, because they hold full device "
                "configurations and those do not belong on disk."))
        return page(request, "workflow_run.html", run=run,
                    spec=workflow_spec.get(run.workflow_id))

    @app.get("/workflows/runs/{run_id}/status")
    def workflow_run_status(request: Request, run_id: str):
        """Polled by the progress page. Small on purpose."""
        if not current_user(request):
            return PlainTextResponse("", status_code=401)
        run = workflow_service.store.get(run_id)
        if run is None:
            return PlainTextResponse("", status_code=404)
        return {
            "status": run.status,
            "progress": run.progress,
            "error": run.error,
            "steps": [{"key": s.key, "status": s.status, "message": s.message}
                      for s in run.steps],
            "totals": run.totals(),
        }

    @app.post("/workflows/runs/{run_id}/cancel")
    def workflow_run_cancel(request: Request, run_id: str,
                            csrf_token: str = Form("")):
        if not current_user(request):
            return login_redirect()
        if not csrf_ok(request, csrf_token):
            return page(request, "denied.html", reason="Invalid form token.")
        run = workflow_service.store.get(run_id)
        if run is not None:
            run.cancel()
            log(request, "workflow-cancel", run.workflow_id, run_id)
        return RedirectResponse(f"/workflows/runs/{run_id}",
                                status_code=HTTP_303_SEE_OTHER)

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
