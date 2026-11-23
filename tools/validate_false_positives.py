"""Loopback validation of false-positive controls with the real HTTP client.

Starts local fixtures that reproduce the false positives observed in real scans
and runs PathDiscoveryModule and AdvancedLogicModule against them:

  catchall  every unknown path -> HTTP 200 SPA shell (contains "error"/"warning")
  django    every unknown path -> HTTP 200 framework debug page with a traceback
  waf       *.jsp -> HTTP 403 block page; other unknown paths -> 404
  real      genuine /.env, /access.log and /package.json; unknown paths -> 404

Only 127.0.0.1 is contacted. Exit code 0 means every expectation held.
"""
from __future__ import annotations

import asyncio
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src" / "scan_titan"))

import aiohttp  # noqa: E402
from aiohttp import web  # noqa: E402

from Main import Target  # noqa: E402
from modules.advanced_logic import AdvancedLogicModule  # noqa: E402
from modules.common import AsyncHttpClient, ScanContext, ScanLimits  # noqa: E402
from modules.paths import PathDiscoveryModule  # noqa: E402

WORDLIST = ["/.env", "/.git/config", "/backup.zip", "/admin", "/debug", "/package.json",
            "/actuator/env", "/server-status", '/%0a%0a<script>alert("x")</script>.jsp', "/manager/html.jsp"]
ACCESS_LOG = "\n".join(
    f'10.0.0.{i} - - [10/Oct/2026:13:55:3{i} -0700] "GET /item?id={i} HTTP/1.1" 200 2326' for i in range(5))


def app_for(kind: str) -> web.Application:
    async def handler(request: web.Request) -> web.Response:
        path = request.path
        if kind == "catchall":
            return web.Response(text=("<!doctype html><html><head><title>Portal</title></head><body><div id=app>"
                                      f"</div><script>onerror=function(){{console.warn('error')}};route='{path}'"
                                      "</script></body></html>"), content_type="text/html")
        if kind == "django":
            return web.Response(text=(f"<!doctype html><html><head><title>Page not found at {path}</title></head>"
                                      "<body><pre>Traceback (most recent call last):\n  File \"/app/urls.py\", line 7"
                                      f"</pre><p>Request URL: {request.url}</p></body></html>"), content_type="text/html")
        if kind == "waf":
            if path.endswith(".jsp"):
                return web.Response(status=403, text=f"<html><title>Request blocked</title>id {len(path)}</html>",
                                    content_type="text/html")
            return web.Response(status=404, text="Not found")
        if path == "/.env":
            return web.Response(text="APP_KEY=base64:fixture\nDB_PASSWORD=fixture", content_type="text/plain")
        if path == "/access.log":
            return web.Response(text=ACCESS_LOG, content_type="text/plain")
        if path == "/package.json":
            return web.json_response({"name": "fixture", "dependencies": {"lodash": "4.17.20"}})
        return web.Response(status=404, text="<html><title>404</title></html>", content_type="text/html")

    app = web.Application()
    app.router.add_route("*", "/{tail:.*}", handler)
    return app


async def scan(kind: str) -> dict:
    runner = web.AppRunner(app_for(kind))
    await runner.setup()
    site = web.TCPSite(runner, "127.0.0.1", 0)
    await site.start()
    port = site._server.sockets[0].getsockname()[1]
    base = f"http://127.0.0.1:{port}/"
    try:
        async with aiohttp.ClientSession() as session:
            limits = ScanLimits(max_tests_per_module=60, timeout=5)
            client = AsyncHttpClient(session, asyncio.Semaphore(8), limits)
            target = Target(raw=base, url=base, host="127.0.0.1", ip="127.0.0.1", scheme="http", port=port)
            ctx = ScanContext(target=target, http=client, wordlists={"rutas": WORDLIST, "403bypass": []},
                              limits=limits, recon={}, heartbeat=lambda *args: None)
            findings = await PathDiscoveryModule().run(ctx) + await AdvancedLogicModule()._logs(ctx)
            return {"findings": sorted(f"{item.severity}: {item.title}" for item in findings),
                    "soft404_filtered": len(ctx.recon.get("soft404_filtered_paths", [])),
                    "requests": client.requests_completed}
    finally:
        await runner.cleanup()


EXPECTED = {
    "catchall": [],
    "django": [],
    "waf": [],
    "real": ["High: Exposed log/debug content: /access.log", "High: Exposed or restricted path: /.env",
             "Low: Exposed or restricted path: /package.json"],
}


async def main() -> int:
    ok = True
    report = {}
    for kind, expected in EXPECTED.items():
        result = await scan(kind)
        result["expected"] = expected
        result["pass"] = result["findings"] == expected
        ok &= result["pass"]
        report[kind] = result
    print(json.dumps(report, indent=2, ensure_ascii=False))
    print("RESULT:", "PASS" if ok else "FAIL")
    return 0 if ok else 1


if __name__ == "__main__":
    raise SystemExit(asyncio.run(main()))
