from __future__ import annotations

import asyncio
import json
import os
import sys
import tempfile
import unittest
from datetime import datetime, timedelta
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import AsyncMock, Mock, patch

import aiohttp
from aiohttp import web

ROOT = Path(__file__).resolve().parents[1]
os.environ.setdefault("SCAN_TITAN_BASE_DIR", str(ROOT))
os.environ.setdefault("SCAN_TITAN_CONFIG_FILE", str(ROOT / "config" / "config.yaml"))
os.environ.setdefault("SCAN_TITAN_REPORTS_DIR", str(ROOT / "reports"))
os.environ.setdefault("SCAN_TITAN_TARGETS_FILE", str(ROOT / "targets" / "targets.txt"))
sys.path.insert(0, str(ROOT / "src" / "scan_titan"))

from modules.common import AsyncHttpClient, ScanContext, ScanLimits, Target, run_bounded


class RuntimeProgressTests(unittest.IsolatedAsyncioTestCase):
    def test_adaptive_guard_stops_repeated_waf_signature(self) -> None:
        from modules.adaptive_guard import AdaptiveResponseGuard

        guard = AdaptiveResponseGuard(block_threshold=6)
        response = SimpleNamespace(
            status=403,
            text="Access denied. Request blocked. Cloudflare Ray ID 123456789012",
            content_type="text/html",
            body_len=72,
            headers={"CF-Ray": "fixture"},
        )

        decisions = []
        for index in range(6):
            response.text = f"Access denied. Request blocked. Cloudflare Ray ID 12345678901{index}"
            response.headers = {"CF-Ray": f"fixture-{index}"}
            decisions.append(
                guard.observe(response, input_key=f"/endpoint|q{index}", probe_value=f"payload-{index}")
            )

        self.assertFalse(any(item.stop_module for item in decisions[:5]))
        self.assertTrue(decisions[-1].stop_module)
        self.assertTrue(decisions[-1].blocked)
        self.assertIn("status=403", decisions[-1].reason)
        self.assertIn("Cloudflare", decisions[-1].reason)

    def test_adaptive_guard_does_not_stop_on_size_alone(self) -> None:
        from modules.adaptive_guard import AdaptiveResponseGuard

        guard = AdaptiveResponseGuard(plateau_threshold=8)
        decisions = []
        for marker in "abcdefgh":
            response = SimpleNamespace(
                status=200,
                text=f"<html>distinct response {marker}</html>",
                content_type="text/html",
                body_len=40,
                headers={},
            )
            decisions.append(
                guard.observe(response, input_key="/search|q", probe_value=f"payload-{marker}")
            )

        self.assertFalse(any(item.stop_input or item.stop_module for item in decisions))

    def test_adaptive_guard_stops_only_stable_input(self) -> None:
        from modules.adaptive_guard import AdaptiveResponseGuard

        guard = AdaptiveResponseGuard(plateau_threshold=8)
        response = SimpleNamespace(
            status=200,
            text="<html>same application response</html>",
            content_type="text/html",
            body_len=38,
            headers={},
        )

        decision = None
        for index in range(8):
            decision = guard.observe(
                response,
                input_key="/search|q",
                probe_value=f"payload-{index}",
                baseline=response,
            )

        self.assertIsNotNone(decision)
        self.assertTrue(decision.stop_input)
        self.assertFalse(decision.stop_module)
        self.assertTrue(guard.input_stopped("/search|q"))
        self.assertFalse(guard.input_stopped("/other|q"))
        self.assertIn("iguales al control", decision.reason)

    async def test_xss_repeated_waf_page_short_circuits_module(self) -> None:
        from modules.xss import XssModule

        calls = []

        async def request(_method, url, *, params, **_kwargs):
            calls.append((url, dict(params)))
            return SimpleNamespace(
                status=403,
                text="Access denied. Request blocked. Cloudflare Ray ID 123456789012",
                content_type="text/html",
                body_len=72,
                headers={"CF-Ray": "fixture"},
            )

        target = Target("https://example.test/", "https://example.test/", "example.test", "192.0.2.1", "https", 443)
        ctx = ScanContext(
            target=target,
            http=SimpleNamespace(request=request, circuit_open=False),
            wordlists={},
            limits=ScanLimits(max_tests_per_module=1200),
            recon={"endpoints": [{"url": f"https://example.test/{i}", "params": ["q"]} for i in range(100)]},
            heartbeat=lambda *_args: None,
        )

        findings = await XssModule().run(ctx)

        summary = ctx.recon["xss_active_summary"]["adaptive_guard"]
        self.assertEqual(findings, [])
        self.assertTrue(summary["module_stopped"])
        self.assertLessEqual(len(calls), 13)
        self.assertEqual(ctx.recon["adaptive_stops"][0]["module"], "xss")

    async def test_lfi_repeated_waf_page_short_circuits_module(self) -> None:
        from modules.lfi import LfiModule

        calls = []

        async def request(_method, url, *, params, **_kwargs):
            value = next(iter(params.values()))
            calls.append((url, value))
            if value == "scan_titan_control":
                return SimpleNamespace(
                    status=200,
                    text="normal application page",
                    content_type="text/html",
                    body_len=23,
                    headers={},
                )
            return SimpleNamespace(
                status=403,
                text="Access denied. Request blocked. Cloudflare Ray ID 123456789012",
                content_type="text/html",
                body_len=72,
                headers={"CF-Ray": "fixture"},
            )

        target = Target("https://example.test/", "https://example.test/", "example.test", "192.0.2.1", "https", 443)
        ctx = ScanContext(
            target=target,
            http=SimpleNamespace(request=request, circuit_open=False),
            wordlists={},
            limits=ScanLimits(max_tests_per_module=1200),
            recon={},
            heartbeat=lambda *_args: None,
        )

        findings = await LfiModule().run(ctx)

        summary = ctx.recon["lfi_active_summary"]["adaptive_guard"]
        self.assertEqual(findings, [])
        self.assertTrue(summary["module_stopped"])
        self.assertLess(len(calls), 30)
        self.assertEqual(ctx.recon["adaptive_stops"][0]["module"], "lfi")

    async def test_pool_is_bounded_and_preserves_all_jobs(self) -> None:
        active = peak = 0
        completed = []

        async def probe(value: int) -> None:
            nonlocal active, peak
            active += 1
            peak = max(peak, active)
            try:
                await asyncio.sleep(0)
                completed.append(value)
            finally:
                active -= 1

        await run_bounded(range(1000), probe, limit=500)
        self.assertLessEqual(peak, 20)
        self.assertEqual(sorted(completed), list(range(1000)))
        self.assertEqual(active, 0)

    async def test_cancellation_drains_worker_tasks(self) -> None:
        entered = asyncio.Event()
        active = 0

        async def probe(_value: int) -> None:
            nonlocal active
            active += 1
            entered.set()
            try:
                await asyncio.Event().wait()
            finally:
                active -= 1

        task = asyncio.create_task(run_bounded(range(10000), probe))
        await asyncio.wait_for(entered.wait(), 1)
        task.cancel()
        with self.assertRaises(asyncio.CancelledError):
            await task
        self.assertEqual(active, 0)

    async def test_finish_does_not_consume_remaining_wordlist(self) -> None:
        calls = []

        async def probe(value: int) -> None:
            calls.append(value)

        await run_bounded(range(10000), probe, should_stop=lambda: bool(calls))
        self.assertEqual(calls, [0])

    async def test_payload_progress_counts_completed_not_queued_probes(self) -> None:
        from modules.lfi import LfiModule
        from modules.xss import XssModule
        from modules.ssrf import SsrfModule

        for module in (LfiModule(), XssModule(), SsrfModule()):
            with self.subTest(module=module.name):
                expected_capacity = 8 if module.name in {"lfi", "xss"} else 20
                gate = asyncio.Event()
                at_capacity = asyncio.Event()
                starts = 0
                completed = 0
                progress = []
                response = SimpleNamespace(status=200, text="fixture", content_type="text/html")

                async def request(_method, _url, *, params, **_kwargs):
                    nonlocal starts, completed
                    if params and "scan_titan_control" in params.values():
                        return response
                    starts += 1
                    if starts == expected_capacity:
                        at_capacity.set()
                    await gate.wait()
                    completed += 1
                    reflected = next(iter(params.values())) if module.name == "xss" else "fixture"
                    return SimpleNamespace(status=200, text=reflected, content_type="text/html")

                target = Target("https://example.test/", "https://example.test/", "example.test", "192.0.2.1", "https", 443)
                param_name = {"lfi": "file", "xss": "q", "ssrf": "url"}[module.name]
                ctx = ScanContext(
                    target=target,
                    http=SimpleNamespace(request=request, circuit_open=False),
                    wordlists={},
                    limits=ScanLimits(max_tests_per_module=80),
                    recon={"endpoints": [{"url": f"https://example.test/api/{i}", "params": [param_name]} for i in range(30)]},
                    heartbeat=lambda _m, _d, tested, _h: progress.append((tested, completed)),
                )
                with patch("modules.lfi.lfi_payloads", return_value=[(f"fixture-{i}", "missing-marker") for i in range(80)]), patch(
                    "modules.xss.xss_payloads", return_value=[f"fixture-{i}" for i in range(80)]
                ):
                    task = asyncio.create_task(module.run(ctx))
                    try:
                        await asyncio.wait_for(at_capacity.wait(), 1)
                        self.assertEqual(starts, expected_capacity)
                        self.assertEqual(progress, [])
                        gate.set()
                        await asyncio.wait_for(task, 2)
                    finally:
                        task.cancel()
                        await asyncio.gather(task, return_exceptions=True)
                self.assertEqual(completed, 80)
                self.assertEqual(progress[-1], (80, 80))
                self.assertTrue(all(tested <= done for tested, done in progress))

    async def test_xss_non_reflecting_surface_stops_after_canary_stage(self) -> None:
        from modules.xss import XssModule

        calls = []

        async def request(_method, url, *, params, **_kwargs):
            calls.append((url, dict(params)))
            return SimpleNamespace(status=200, text="no reflection", content_type="text/html")

        target = Target("https://example.test/", "https://example.test/", "example.test", "192.0.2.1", "https", 443)
        ctx = ScanContext(
            target=target,
            http=SimpleNamespace(request=request, circuit_open=False),
            wordlists={"xss": ["<script>alert(1)</script>"] * 2000},
            limits=ScanLimits(max_tests_per_module=1200),
            recon={},
            heartbeat=lambda *_args: None,
        )

        findings = await XssModule().run(ctx)

        self.assertEqual(findings, [])
        self.assertEqual(len(calls), min(10, len(XssModule.DEFAULT_PARAMS)))
        self.assertEqual(ctx.recon["xss_active_summary"]["payload_probes"], 0)
        self.assertTrue(ctx.recon["xss_active_completed"])

    async def test_xss_reflecting_surface_escalates_and_confirms_once(self) -> None:
        from modules.xss import XssModule

        calls = []

        async def request(_method, url, *, params, **_kwargs):
            value = next(iter(params.values()))
            calls.append((url, value))
            return SimpleNamespace(
                status=200,
                text=f"<html>{value}</html>",
                content_type="text/html",
                body_len=len(value) + 13,
                elapsed=0.01,
            )

        target = Target("https://example.test/?q=base", "https://example.test/?q=base", "example.test", "192.0.2.1", "https", 443)
        ctx = ScanContext(
            target=target,
            http=SimpleNamespace(request=request, circuit_open=False),
            wordlists={},
            limits=ScanLimits(max_tests_per_module=1200),
            recon={},
            heartbeat=lambda *_args: None,
        )

        findings = await XssModule().run(ctx)

        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].param, "q")
        self.assertEqual(ctx.recon["xss_active_summary"]["reflected_inputs"], 1)
        self.assertLessEqual(ctx.recon["xss_active_summary"]["payload_probes"], XssModule.ZERO_TOUCH_PAYLOADS_PER_INPUT)
        self.assertLess(len(calls), 60)

    async def test_lfi_without_observed_parameters_uses_high_signal_fallback(self) -> None:
        from modules.lfi import LfiModule

        calls = []

        async def request(_method, url, *, params, **_kwargs):
            calls.append((url, dict(params)))
            return SimpleNamespace(status=200, text="control page", content_type="text/html")

        target = Target("https://example.test/", "https://example.test/", "example.test", "192.0.2.1", "https", 443)
        ctx = ScanContext(
            target=target,
            http=SimpleNamespace(request=request, circuit_open=False),
            wordlists={"lfi": ["../../../../etc/passwd"] * 2000},
            limits=ScanLimits(max_tests_per_module=1200),
            recon={},
            heartbeat=lambda *_args: None,
        )

        findings = await LfiModule().run(ctx)

        summary = ctx.recon["lfi_active_summary"]
        self.assertEqual(findings, [])
        self.assertEqual(summary["mode"], "fallback-high-signal")
        self.assertLessEqual(summary["planned"], 8 * LfiModule.FALLBACK_PAYLOADS_PER_INPUT)
        self.assertLess(len(calls), 200)

    async def test_finish_interrupts_throttle_without_sending_requests(self) -> None:
        control = SimpleNamespace(finish_requested=False, wait_if_paused=AsyncMock())
        limits = ScanLimits(jitter_min_seconds=30, jitter_max_seconds=30, throttle_batch_size=1, runtime_control=control)
        session = SimpleNamespace(request=Mock(side_effect=AssertionError("Request must stay queued")))
        client = AsyncHttpClient(session, asyncio.Semaphore(20), limits)
        tasks = [asyncio.create_task(client.request("GET", "https://example.test/")) for _ in range(50)]
        await asyncio.sleep(0)
        control.finish_requested = True
        await asyncio.wait_for(asyncio.gather(*tasks), 1)
        session.request.assert_not_called()
        self.assertEqual(client.requests_waiting, 0)

    async def test_finish_is_rechecked_after_semaphore_wait(self) -> None:
        control = SimpleNamespace(finish_requested=False, wait_if_paused=AsyncMock())
        limits = ScanLimits(jitter_min_seconds=0, jitter_max_seconds=0, runtime_control=control)
        session = SimpleNamespace(request=Mock())
        semaphore = asyncio.Semaphore(0)
        client = AsyncHttpClient(session, semaphore, limits)
        task = asyncio.create_task(client.request("GET", "https://example.test/"))
        await asyncio.sleep(0)
        control.finish_requested = True
        semaphore.release()
        await asyncio.wait_for(task, 1)
        session.request.assert_not_called()

    async def test_open_circuit_discards_waiting_requests(self) -> None:
        session = SimpleNamespace(request=Mock(side_effect=aiohttp.ClientConnectionError("fixture failure")))
        client = AsyncHttpClient(session, asyncio.Semaphore(2), ScanLimits(jitter_min_seconds=0, jitter_max_seconds=0), circuit_after=1)
        await asyncio.gather(*(client.request("GET", "https://example.test/") for _ in range(100)))
        self.assertEqual(session.request.call_count, 1)
        self.assertEqual(client.requests_completed, 1)
        self.assertTrue(client.circuit_open)

    async def test_local_http_timeout_clears_activity_counters(self) -> None:
        gate = asyncio.Event()

        async def slow(_request):
            await gate.wait()
            return web.Response(text="fixture")

        app = web.Application()
        app.router.add_get("/", slow)

        async def ready(_request):
            return web.Response(text="fixture", headers={"X-Fixture": "ready"})

        app.router.add_get("/ready", ready)
        runner = web.AppRunner(app)
        await runner.setup()
        try:
            site = web.TCPSite(runner, "127.0.0.1", 0)
            await site.start()
            port = runner.addresses[0][1]
            async with aiohttp.ClientSession() as session:
                client = AsyncHttpClient(session, asyncio.Semaphore(1), ScanLimits(timeout=0.05, jitter_min_seconds=0, jitter_max_seconds=0))
                ready_result = await client.request("GET", f"http://127.0.0.1:{port}/ready", timeout=2)
                self.assertEqual(ready_result.status, 200)
                self.assertEqual(ready_result.text, "fixture")
                self.assertEqual(ready_result.headers["X-Fixture"], "ready")
                result = await client.request("GET", f"http://127.0.0.1:{port}/")
                self.assertIsNone(result)
                self.assertEqual(client.requests_completed, 2)
                self.assertEqual(client.requests_active, 0)
                self.assertEqual(client.requests_waiting, 0)
        finally:
            gate.set()
            await runner.cleanup()

    async def test_module_pulse_updates_during_pending_request(self) -> None:
        from Main import RuntimeTelemetry, ScanTitan

        with tempfile.TemporaryDirectory() as tmp:
            scanner = object.__new__(ScanTitan)
            scanner.MODULE_HEARTBEAT_SECONDS = 0.01
            scanner.config = SimpleNamespace(runtime_control=SimpleNamespace(is_paused=False))
            scanner.telemetry = RuntimeTelemetry(Path(tmp) / "runtime.json")
            http = SimpleNamespace(requests_completed=0, requests_active=1, requests_waiting=3, last_completed_at=0)
            with patch("Main.Console.step"):
                task = asyncio.create_task(scanner._module_pulse("lfi", SimpleNamespace(http=http)))
                try:
                    await asyncio.sleep(0.04)
                finally:
                    task.cancel()
                    await asyncio.gather(task, return_exceptions=True)
            data = json.loads(scanner.telemetry.path.read_text(encoding="utf-8"))
            self.assertEqual(data["http_activity"]["completed"], 0)
            self.assertEqual(data["http_activity"]["active"], 1)
            self.assertEqual(data["http_activity"]["waiting"], 2)


class MonitorPathTests(unittest.TestCase):
    def test_empty_reports_does_not_hide_runtime_in_audit_reports(self) -> None:
        from ScanTitan_Monitor import resolve_runtime_file

        with tempfile.TemporaryDirectory() as tmp, patch.dict(os.environ, {}, clear=True):
            base = Path(tmp)
            (base / "reports").mkdir()
            (base / "audit_reports").mkdir()
            runtime = base / "audit_reports" / "scan_titan_runtime.json"
            runtime.write_text("{}", encoding="utf-8")
            self.assertTrue(resolve_runtime_file(base).samefile(runtime))

    def test_other_copy_ignores_launchers_runtime_override(self) -> None:
        from ScanTitan_Monitor import resolve_runtime_file

        with tempfile.TemporaryDirectory() as tmp:
            base = Path(tmp)
            for name in ("a", "b"):
                (base / name / "reports").mkdir(parents=True)
                (base / name / "reports" / "scan_titan_runtime.json").write_text("{}", encoding="utf-8")
            with patch.dict(os.environ, {
                "SCAN_TITAN_BASE_DIR": str(base / "a"),
                "SCAN_TITAN_RUNTIME_FILE": str(base / "a" / "reports" / "scan_titan_runtime.json"),
            }):
                expected = base / "b" / "reports" / "scan_titan_runtime.json"
                self.assertTrue(resolve_runtime_file(base / "b").samefile(expected))

    def test_running_stale_snapshot_is_not_shown_as_live(self) -> None:
        from ScanTitan_Monitor import runtime_is_stale

        old = (datetime.now() - timedelta(hours=4)).strftime("%Y-%m-%d %H:%M:%S")
        self.assertTrue(runtime_is_stale({"status": "running", "updated_at": old}))
        self.assertFalse(runtime_is_stale({"status": "finished", "updated_at": old}))
        self.assertFalse(runtime_is_stale({"status": "running", "updated_at": datetime.now().strftime("%Y-%m-%d %H:%M:%S")}))


if __name__ == "__main__":
    unittest.main()
