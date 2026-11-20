"""Real-engine validation of the Nmap/Nuclei/ZAP profiles against loopback only.

Starts local fixtures (HTTP app with API/SPA routes and an unauthenticated
Redis-protocol responder), then runs the production ExternalTools methods with
the installed binaries. Nothing leaves 127.0.0.1. Evidence is written to
version_backups/engine_power_<timestamp>/.

Usage: python -B tools/validate_engine_power.py [--skip-zap] [--skip-nuclei] [--skip-nmap]
"""
from __future__ import annotations

import argparse
import asyncio
import html
import json
import socket
import sys
from datetime import datetime
from pathlib import Path
from types import SimpleNamespace

from aiohttp import web

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
import main as launcher  # noqa: E402

launcher.configure_environment()
launcher.engine_path_ready()
from Main import ExternalTools, RuntimeConfig, build_argparser  # noqa: E402
from modules.common import Target  # noqa: E402

REDIS_INFO = (
    "# Server\r\nredis_version:7.2.4\r\nredis_mode:standalone\r\nos:Linux 5.15.0 x86_64\r\n"
    "arch_bits:64\r\nprocess_id:1\r\ntcp_port:6379\r\nuptime_in_seconds:100\r\n"
    "# Clients\r\nconnected_clients:1\r\n"
)


async def redis_handler(reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
    """Minimal RESP responder: answers INFO/PING like an unauthenticated Redis."""
    try:
        while True:
            data = await asyncio.wait_for(reader.read(4096), timeout=10)
            if not data:
                break
            lowered = data.lower()
            if b"info" in lowered:
                payload = REDIS_INFO.encode()
                writer.write(b"$%d\r\n%s\r\n" % (len(payload), payload))
            elif b"ping" in lowered:
                writer.write(b"+PONG\r\n")
            else:
                writer.write(b"-ERR unknown command\r\n")
            await writer.drain()
    except (asyncio.TimeoutError, ConnectionError):
        pass
    finally:
        writer.close()


OPENAPI = {
    "openapi": "3.0.0", "info": {"title": "fixture", "version": "1"},
    "paths": {"/api/search": {"get": {"parameters": [
        {"name": "q", "in": "query", "schema": {"type": "string"}}],
        "responses": {"200": {"description": "ok"}}}}},
}


def build_app(base: dict) -> web.Application:
    app = web.Application()

    async def login(request):
        return web.Response(content_type="text/html", text=(
            "<html><head><title>Fixture login</title></head><body>"
            '<a href="/api/item?id=1">item</a> <a href="/admin/">admin</a>'
            '<form method="GET" action="/app/login"><input name="user"></form>'
            '<div id="spa"></div><script>document.getElementById("spa").innerHTML='
            "'<a href=\"/spa/hidden-route?view=1\">spa</a>';</script></body></html>"))

    async def item(request):
        # Reflected, unencoded parameter: a deliberate XSS sink for DAST engines.
        value = request.query.get("id", "")
        return web.Response(content_type="text/html", text=f"<html><body>Item {value}</body></html>")

    async def search(request):
        value = request.query.get("q", "")
        return web.Response(content_type="text/html", text=f"<html><body>Search {value}</body></html>")

    async def plain(request):
        return web.Response(content_type="text/html", text=f"<html><body>{html.escape(request.path)}</body></html>")

    async def spec(request):
        servers = [{"url": base["url"].rstrip("/")}]
        return web.json_response({**OPENAPI, "servers": servers})

    app.router.add_get("/", login)
    app.router.add_get("/app/login", login)
    app.router.add_get("/api/item", item)
    app.router.add_get("/api/search", search)
    app.router.add_get("/openapi.json", spec)
    app.router.add_get("/admin/", plain)
    app.router.add_get("/spa/hidden-route", plain)
    return app


def free_port() -> int:
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]


async def validate(args: argparse.Namespace) -> dict:
    evidence = ROOT / "version_backups" / f"engine_power_{datetime.now():%Y%m%d_%H%M%S}"
    evidence.mkdir(parents=True, exist_ok=True)
    base: dict = {}
    runner = web.AppRunner(build_app(base))
    await runner.setup()
    site = web.TCPSite(runner, "127.0.0.1", 0)
    await site.start()
    http_port = site._server.sockets[0].getsockname()[1]
    base["url"] = f"http://127.0.0.1:{http_port}/"
    redis_port = 6379
    try:
        redis_server = await asyncio.start_server(redis_handler, "127.0.0.1", redis_port)
    except OSError:
        redis_port = free_port()
        redis_server = await asyncio.start_server(redis_handler, "127.0.0.1", redis_port)
    url = f"http://127.0.0.1:{http_port}/app/login"
    results: dict = {"fixture": {"http": base["url"], "redis_port": redis_port, "evidence": str(evidence)}}
    try:
        cfg = RuntimeConfig(build_argparser().parse_args([]))
        cfg.telemetry = None
        cfg.external_reports_dir = evidence
        # Loopback-only guarantees for the harness (production keeps all three):
        # no template download, no vulners.com lookup, no interactsh registration.
        cfg.nuclei_update_templates = False
        tools = ExternalTools(cfg)
        original_run = tools._run_command
        skipped: list[str] = []

        async def loopback_only(cmd, timeout):
            cmd = list(cmd)
            if "--script" in cmd and cmd[cmd.index("--script") + 1] == "vulners":
                skipped.append("nmap vulners_cvss (external API)")
                return "", "", False, 0, 0.0
            if Path(cmd[0]).stem.lower() == "nuclei" and "-ni" not in cmd:
                cmd.insert(1, "-ni")
            return await original_run(cmd, timeout)

        tools._run_command = loopback_only
        results["harness_skipped"] = skipped
        ctx = SimpleNamespace(
            target=Target(url, url, "127.0.0.1", "127.0.0.1", "http", http_port),
            recon={"open_ports": [f"{http_port}/tcp", f"{redis_port}/tcp"],
                   "api_specs": [base["url"] + "openapi.json"],
                   "endpoints": [{"url": base["url"] + "api/item?id=1"}]},
            heartbeat=lambda *a: None, http=SimpleNamespace(request=None))

        if not args.skip_nmap:
            cfg.nmap_profiles = {"network_vulnerability_scan", "vulners_cvss", "ssh_security", "udp_services"}
            nmap_findings = await tools.run_nmap(ctx)
            results["nmap"] = {
                "coverage": [c for c in ctx.recon.get("external_coverage", []) if c.get("tool") == "nmap"],
                "findings": [(f.severity, f.title, f.source) for f in nmap_findings],
                "open_ports": ctx.recon.get("open_ports", []),
                "redis_unauth_detected": any("Redis responde" in f.title for f in nmap_findings),
            }

        if not args.skip_nuclei:
            cfg.nuclei_profiles = {"vulnerability_scan", "network_services_scan", "dast_scan"}
            nuclei_findings = await tools.run_nuclei(ctx)
            results["nuclei"] = {
                "templates": ctx.recon.get("nuclei_templates"),
                "coverage": [c for c in ctx.recon.get("external_coverage", []) if c.get("tool") == "nuclei"],
                "findings": [(f.severity, f.title, f.param, f.url) for f in nuclei_findings],
            }

        if not args.skip_zap and tools._resolve_zap_binary():
            cfg.zap_port = free_port()
            cfg.zap_host = "127.0.0.1"
            cfg.zap_api_url = f"http://127.0.0.1:{cfg.zap_port}"
            cfg.zap_api_key = ""
            cfg.zap_mode = "active"
            cfg.zap_start_daemon = True
            cfg.zap_shutdown_after_scan = True
            cfg.zap_spider_timeout = 60
            cfg.zap_ajax_spider_timeout = 60
            cfg.zap_active_timeout = 300
            cfg.zap_passive_timeout = 60
            cfg.zap_progress_timeout = 120

            async def keep_alerts(_ctx, alerts):
                return alerts, []

            tools._filter_zap_soft_auth_redirect_alerts = keep_alerts
            zap_findings = await tools.run_zap(ctx)
            export = next(Path(c["export"]) for c in ctx.recon["external_coverage"]
                          if c.get("tool") == "zap" and c.get("export"))
            payload = json.loads(export.read_text(encoding="utf-8"))
            urls = sorted({a.get("url", "") for a in payload.get("alerts", [])})
            results["zap"] = {
                "coverage": [c for c in ctx.recon["external_coverage"] if c.get("tool") == "zap"],
                "active_scope": payload.get("active_scope"),
                "active_records": payload.get("active_records"),
                "ajax_spider_records": payload.get("ajax_spider_records"),
                "api_definitions_imported": payload.get("api_definitions_imported"),
                "api_imports": ctx.recon.get("zap_api_imports"),
                "alert_urls_outside_target_subtree": [u for u in urls if "/app/login" not in u],
                "findings": [(f.severity, f.title, f.url) for f in zap_findings],
            }
    finally:
        redis_server.close()
        await redis_server.wait_closed()
        await runner.cleanup()
    (evidence / "engine_power_results.json").write_text(
        json.dumps(results, indent=2, ensure_ascii=False, default=str), encoding="utf-8")
    return results


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--skip-zap", action="store_true")
    parser.add_argument("--skip-nuclei", action="store_true")
    parser.add_argument("--skip-nmap", action="store_true")
    results = asyncio.run(validate(parser.parse_args()))
    print(json.dumps(results, indent=2, ensure_ascii=False, default=str))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
