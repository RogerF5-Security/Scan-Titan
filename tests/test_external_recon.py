"""Offline checks for bounded external reconnaissance adapters."""

from __future__ import annotations

import asyncio
import os
import sys
import tempfile
import threading
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch


ROOT = Path(__file__).resolve().parents[1]
os.environ.setdefault("SCAN_TITAN_BASE_DIR", str(ROOT))
os.environ.setdefault("SCAN_TITAN_CONFIG_FILE", str(ROOT / "config" / "config.yaml"))
os.environ.setdefault("SCAN_TITAN_REPORTS_DIR", str(ROOT / "reports"))
sys.path.insert(0, str(ROOT / "src" / "scan_titan"))

from external_recon import (  # noqa: E402
    ExternalCommandQueue,
    is_projectdiscovery_httpx_help,
    parse_katana,
    parse_projectdiscovery_httpx,
    same_origin_url,
)
import Main as titan_main  # noqa: E402
from Main import ExternalTools  # noqa: E402


class ReconParserTests(unittest.TestCase):
    def test_same_origin_filters_host_port_credentials_and_fragment(self) -> None:
        origin = "https://app.example.test:8443/"
        self.assertEqual(
            same_origin_url("https://app.example.test:8443/api?q=1#section", origin),
            "https://app.example.test:8443/api?q=1",
        )
        for bad in (
            "https://other.example.test:8443/api",
            "https://app.example.test/api",
            "http://app.example.test:8443/api",
            "https://user:pass@app.example.test:8443/api",
            "https://app.example.test:8443/\nmalformed",
        ):
            with self.subTest(url=bad):
                self.assertIsNone(same_origin_url(bad, origin))

    def test_katana_parses_jsonl_deduplicates_and_rejects_off_scope(self) -> None:
        output = (
            '{"request":{"endpoint":"https://app.example.test/search?q=1"}}\n'
            '{"request":{"endpoint":"https://app.example.test/search?q=1"}}\n'
            '{"request":{"endpoint":"https://foreign.example.test/"}}\n'
        )
        self.assertEqual(parse_katana(output, "https://app.example.test/"), [
            {"url": "https://app.example.test/search?q=1", "params": ["q"], "source": "katana"}
        ])

    def test_httpx_is_recon_only_and_python_cli_is_rejected(self) -> None:
        self.assertFalse(is_projectdiscovery_httpx_help("HTTPX - A next generation HTTP client"))
        self.assertTrue(is_projectdiscovery_httpx_help("-tech-detect -status-code -json"))
        output = (
            '{"url":"https://app.example.test/","status_code":200,'
            '"tech":["nginx"],"webserver":"nginx"}\n'
            '{"url":"https://other.example.test/","status_code":200}\n'
        )
        self.assertEqual(len(parse_projectdiscovery_httpx(output, "https://app.example.test/")), 1)


class ReconExecutionTests(unittest.IsolatedAsyncioTestCase):
    async def test_queue_limits_one_process_and_drains_on_cancel(self) -> None:
        current = 0
        peak = 0

        async def runner(command: list[str], timeout: int):
            nonlocal current, peak
            current += 1
            peak = max(peak, current)
            try:
                await asyncio.sleep(0.02)
            finally:
                current -= 1
            return command[0], "", False, 0, 0.02

        queue = ExternalCommandQueue(runner, max_pending=2)
        results = await asyncio.gather(*(queue.run([str(i)], 1) for i in range(3)))
        await queue.close()
        self.assertEqual(peak, 1)
        self.assertEqual([item[0] for item in results], ["0", "1", "2"])

    async def test_cancellation_stops_active_queue_worker(self) -> None:
        started = asyncio.Event()
        stopped = asyncio.Event()

        async def runner(_command: list[str], _timeout: int):
            started.set()
            try:
                await asyncio.sleep(60)
            finally:
                stopped.set()
            return "", "", False, 0, 60.0

        queue = ExternalCommandQueue(runner)
        task = asyncio.create_task(queue.run(["fixture"], 10))
        await asyncio.wait_for(started.wait(), timeout=2)
        task.cancel()
        with self.assertRaises(asyncio.CancelledError):
            await task
        await asyncio.wait_for(stopped.wait(), timeout=2)
        await queue.close()

    async def test_orchestrator_adds_only_same_origin_recon_no_findings(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            policy = SimpleNamespace(enable_katana=True, enable_httpx=True, external_observability=False)
            config = SimpleNamespace(
                skip_external=False,
                policy=policy,
                runtime_control=SimpleNamespace(wait_if_paused=self._ready, finish_requested=False),
                telemetry=None,
                config_data={"tools": {}},
                external_reports_dir=Path(tmp),
                katana_timeout=15,
                httpx_timeout=10,
            )
            tools = ExternalTools(config)
            ctx = SimpleNamespace(
                target=SimpleNamespace(display="app.example.test", url="https://app.example.test/"),
                recon={"endpoints": [], "technologies": []},
            )

            async def fake_command(command: list[str], _timeout: int):
                if command[-1] == "-h":
                    return "-tech-detect -status-code -json", "", False, 0, 0.01
                if command[0] == "katana":
                    return (
                        '{"request":{"endpoint":"https://app.example.test/a?p=1"}}\n'
                        '{"request":{"endpoint":"https://else.example.test/"}}',
                        "", False, 0, 0.01,
                    )
                return (
                    '{"url":"https://app.example.test/","tech":["nginx"]}',
                    "", False, 0, 0.01,
                )

            with patch.object(tools, "_resolve_binary", side_effect=lambda name, _: name), \
                    patch.object(tools, "_run_command", side_effect=fake_command), \
                    patch.object(tools, "_log_external"):
                await tools.run_recon_extensions(ctx)
            self.assertEqual(ctx.recon["endpoints"][0]["params"], ["p"])
            self.assertEqual(ctx.recon["technologies"], ["nginx"])
            self.assertEqual(len(ctx.recon["external_coverage"]), 2)
            self.assertTrue(all(item["state"] == "completed" for item in ctx.recon["external_coverage"]))

    @unittest.skipUnless(os.environ.get("SCAN_TITAN_REAL_TOOL_SMOKE"), "requiere binarios locales")
    async def test_real_katana_httpx_on_loopback_fixture(self) -> None:
        class Handler(BaseHTTPRequestHandler):
            hits: list[str] = []

            def do_GET(self) -> None:
                self.hits.append(self.path)
                body = (
                    b'<html><h1>Detail page</h1></html>'
                    if self.path.startswith('/page')
                    else b'<html><a href="/page?q=1">page</a></html>'
                )
                self.send_response(200)
                self.send_header("Content-Type", "text/html")
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)

            def log_message(self, *_args: object) -> None:
                pass

        server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        try:
            with tempfile.TemporaryDirectory() as tmp, patch.object(titan_main, "REPORTS_DIR", Path(tmp)):
                url = f"http://127.0.0.1:{server.server_port}/"
                config = SimpleNamespace(
                    skip_external=False,
                    policy=SimpleNamespace(enable_katana=True, enable_httpx=True, external_observability=False),
                    runtime_control=SimpleNamespace(wait_if_paused=self._ready, finish_requested=False),
                    telemetry=None,
                    config_data={"tools": {}},
                    external_reports_dir=Path(tmp),
                    katana_timeout=20,
                    httpx_timeout=20,
                )
                ctx = SimpleNamespace(
                    target=SimpleNamespace(display="localhost-fixture", url=url),
                    recon={"endpoints": [], "technologies": []},
                )
                await ExternalTools(config).run_recon_extensions(ctx)
                diagnostics = {
                    "endpoints": ctx.recon["endpoints"],
                    "coverage": ctx.recon["external_coverage"],
                    "logs": {
                        path.name: path.read_text(encoding="utf-8", errors="replace")[-1000:]
                        for path in Path(tmp).glob("katana*.log")
                    },
                    "hits": Handler.hits,
                }
                self.assertTrue(
                    any("/page?q=1" in item["url"] for item in ctx.recon["endpoints"]),
                    diagnostics,
                )
                self.assertTrue(ctx.recon["httpx_metadata"], diagnostics)
                self.assertTrue(all(item["state"] == "completed" for item in ctx.recon["external_coverage"]))
        finally:
            server.shutdown()
            server.server_close()
            thread.join(timeout=2)

    @staticmethod
    async def _ready() -> None:
        return None


if __name__ == "__main__":
    unittest.main()
