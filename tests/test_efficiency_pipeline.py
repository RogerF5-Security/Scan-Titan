"""Focused regression tests for route reuse and long-running Nuclei profiles."""
from __future__ import annotations

import asyncio
import os
import sys
import tempfile
import unittest
from dataclasses import replace
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import AsyncMock


ROOT = Path(__file__).resolve().parents[1]
os.environ.setdefault("SCAN_TITAN_BASE_DIR", str(ROOT))
sys.path.insert(0, str(ROOT / "src" / "scan_titan"))

from Main import RuntimeConfig, RuntimeTelemetry, build_argparser  # noqa: E402
from modules.common import AsyncHttpClient, HttpResult, ScanContext, ScanLimits  # noqa: E402
from modules.paths import PathDiscoveryModule  # noqa: E402
from modules.recon_surface import ReconSurfaceModule  # noqa: E402
from modules.role_audit import RoleAuditor  # noqa: E402
from test_external_tool_hotfixes import external_tools, target  # noqa: E402


class RouteReuseTests(unittest.IsolatedAsyncioTestCase):
    async def test_anonymous_route_is_requested_only_once(self) -> None:
        client = AsyncHttpClient(None, asyncio.Semaphore(2), ScanLimits())
        response = HttpResult(
            url="https://app.example.com/admin", final_url="https://app.example.com/admin",
            status=403, headers={}, text="Forbidden", body_len=9, elapsed=0.1,
        )
        client.request = AsyncMock(return_value=response)
        first = await client.request_route(response.url)
        second = await client.request_route(response.url)
        self.assertIs(first, second)
        client.request.assert_awaited_once()
        self.assertEqual(client.route_cache_hits, 1)
        self.assertIn(response.url, client.route_probed_urls)

    async def test_failed_route_is_retried(self) -> None:
        client = AsyncHttpClient(None, asyncio.Semaphore(2), ScanLimits())
        client.request = AsyncMock(return_value=None)
        await client.request_route("https://app.example.com/temporary")
        await client.request_route("https://app.example.com/temporary")
        self.assertEqual(client.request.await_count, 2)

    async def test_rate_limited_route_is_not_frozen_or_skipped_by_ffuf(self) -> None:
        client = AsyncHttpClient(None, asyncio.Semaphore(2), ScanLimits())
        url = "https://app.example.com/admin"
        limited = HttpResult(url=url, final_url=url, status=429, headers={},
                             text="Retry later", body_len=11, elapsed=0.1)
        client.request = AsyncMock(return_value=limited)
        await client.request_route(url)
        await client.request_route(url)
        self.assertEqual(client.request.await_count, 2)
        self.assertNotIn(url, client.route_probed_urls)

    async def test_role_audit_ignores_discovery_parameter_name_lists(self) -> None:
        manager = SimpleNamespace(
            authenticated_names=lambda: [],
            resolve=lambda url: url,
            request=AsyncMock(return_value=None),
            summary=lambda: {},
        )
        ctx = SimpleNamespace(
            sessions=manager,
            policy=SimpleNamespace(stateful={"roles": {}}),
            recon={"endpoints": [{"url": "https://app.example.com/?q=1", "params": ["q"]}]},
            should_stop=lambda: False,
            heartbeat=lambda *args: None,
        )
        await RoleAuditor().run(ctx)
        self.assertIsNone(manager.request.await_args.args[1].params)

    async def test_recon_and_paths_share_response_without_losing_evidence(self) -> None:
        client = AsyncHttpClient(None, asyncio.Semaphore(12), ScanLimits(max_tests_per_module=50))
        counts: dict[str, int] = {}

        async def response(_method: str, url: str, **_kwargs) -> HttpResult:
            counts[url] = counts.get(url, 0) + 1
            exposed = url.endswith('/.env')
            text = 'APP_KEY=fixture' if exposed else 'Not found'
            return HttpResult(url=url, final_url=url, status=200 if exposed else 404,
                              headers={}, text=text, body_len=len(text), elapsed=0.01)

        client.request = AsyncMock(side_effect=response)
        ctx = ScanContext(target=target(), http=client, wordlists={'rutas': ['/.env', '/admin']},
                          limits=client.limits, recon={}, heartbeat=lambda *args: None)
        recon_findings = await ReconSurfaceModule()._fuzz_paths(ctx)
        path_findings = await PathDiscoveryModule().run(ctx)
        self.assertTrue(any('Sensitive path discovered' in item.title for item in recon_findings))
        self.assertTrue(any('Exposed or restricted path' in item.title for item in path_findings))
        self.assertEqual(counts['https://app.example.com/.env'], 1)
        self.assertGreater(client.route_cache_hits, 0)


class ExternalEfficiencyTests(unittest.IsolatedAsyncioTestCase):
    async def test_nuclei_stats_split_across_chunks_count_as_progress(self) -> None:
        tool = external_tools()
        stream = asyncio.StreamReader()
        stats = {"request_count": -1, "last_progress": 0.0}
        stream.feed_data(b'{"requests":12')
        stream.feed_data(b'3}\n')
        stream.feed_eof()
        await tool._read_stream_limited(stream, stats=stats)
        self.assertEqual(stats["request_count"], 123)
        self.assertGreater(stats["last_progress"], 0)

    def test_nuclei_profiles_have_no_wall_clock_limit(self) -> None:
        config = RuntimeConfig(build_argparser().parse_args([]))
        self.assertEqual(config.target_concurrency, 2)
        for profile in ("vulnerability_scan", "conservative_scan", "cve_scan"):
            self.assertEqual(config.external_profile_timeout("nuclei", profile, 1), 0)
        self.assertGreater(config.nuclei_idle_timeout, 0)
        override = RuntimeConfig(build_argparser().parse_args(["--nuclei-timeout", "120"]))
        self.assertEqual(override.external_profile_timeout("nuclei", "conservative_scan", 0), 120)

    def test_two_targets_keep_separate_module_progress(self) -> None:
        first = target()
        second = replace(first, raw="https://other.example.com/",
                         url="https://other.example.com/", host="other.example.com")
        with tempfile.TemporaryDirectory() as tmp:
            telemetry = RuntimeTelemetry(Path(tmp) / "runtime.json")
            telemetry.start([first, second], SimpleNamespace(
                policy=SimpleNamespace(profile="zero-touch"), full_power=False,
            ))
            telemetry.target_start(first)
            telemetry.target_start(second)
            telemetry.module_start(first, "paths", 100, 900)
            telemetry.module_start(second, "paths", 100, 900)
            telemetry.heartbeat("paths", "/admin", 10, 0, target=first.display)
            telemetry.heartbeat("paths", "/login", 20, 0, target=second.display)
            records = {item["target"]: item for item in telemetry.state["modules"]}
            self.assertEqual(records[first.display]["tested"], 10)
            self.assertEqual(records[second.display]["tested"], 20)
            telemetry.module_end("paths", [], target=first.display)
            telemetry.target_end(first, [], 1.0)
            self.assertEqual(telemetry.state["targets_completed"], 1)
            telemetry.module_end("paths", [], target=second.display)
            telemetry.target_end(second, [], 2.0)
            self.assertEqual(telemetry.state["targets_completed"], 2)
            self.assertEqual(telemetry.state["global_percent"], 100.0)

    def test_ffuf_receives_unprobed_tail(self) -> None:
        tool = external_tools(ffuf_max_words=10000)
        ctx = SimpleNamespace(target=target(), wordlists={"rutas": ["alpha", "beta", "gamma"]},
                              http=SimpleNamespace(route_probed_urls=set()))
        first = tool._write_ffuf_wordlist(ctx)
        try:
            smart = first.read_text(encoding="utf-8").splitlines()
            ctx.http.route_probed_urls.update(
                f"https://app.example.com/{path}" for path in smart
                if path not in {"alpha", "beta", "gamma"}
            )
            ctx.http.route_probed_urls.add("https://app.example.com/alpha")
            tool.config.ffuf_max_words = 2
            second = tool._write_ffuf_wordlist(ctx)
            self.assertEqual(second.read_text(encoding="utf-8").splitlines(), ["beta", "gamma"])
        finally:
            first.unlink(missing_ok=True)


if __name__ == "__main__":
    unittest.main()
