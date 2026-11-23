"""Regression tests for false-positive controls.

Covers routes that do not exist (catch-all / soft-404 / WAF 403), log exposure
without log content, version correlation noise, unproven scanner alerts and
stale findings kept ACTIVE by partial scans.
"""
from __future__ import annotations

import asyncio
import os
import sys
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace

ROOT = Path(__file__).resolve().parents[1]
os.environ.setdefault("SCAN_TITAN_BASE_DIR", str(ROOT))
sys.path.insert(0, str(ROOT / "src" / "scan_titan"))

from Main import Finding, ScanTitan, StateStore  # noqa: E402
from modules.advanced_logic import AdvancedLogicModule  # noqa: E402
from modules.common import AsyncHttpClient, HttpResult, ScanContext, ScanLimits  # noqa: E402
from modules.paths import PathDiscoveryModule  # noqa: E402
from modules.soft_not_found import SoftNotFoundOracle  # noqa: E402
from quality_rules import finding_quality_exclusion  # noqa: E402
from test_external_tool_hotfixes import target  # noqa: E402
from version_intelligence import VersionAuditor  # noqa: E402

SPA_SHELL = ("<!doctype html><html><head><title>Portal</title></head><body><div id=app></div>"
             "<script>/* error handler: warning */ window.route='{path}';</script></body></html>")
DJANGO_404 = ("<!doctype html><html><head><title>Page not found at {path}</title></head><body>"
              "<h1>Page not found (404)</h1><pre>Traceback (most recent call last):\n  File \"/app/urls.py\", "
              "line 7</pre><p>Request URL: https://app.example.com{path}</p></body></html>")
ACCESS_LOG = "\n".join(
    f'10.0.0.{i} - - [10/Oct/2026:13:55:3{i} -0700] "GET /item?id={i} HTTP/1.1" 200 2326' for i in range(5))


def response(url: str, status: int, text: str, content_type: str = "text/html") -> HttpResult:
    return HttpResult(url=url, final_url=url, status=status, headers={}, text=text,
                      body_len=len(text), elapsed=0.01, content_type=content_type)


def context(handler, paths: list[str] | None = None) -> ScanContext:
    client = AsyncHttpClient(None, asyncio.Semaphore(8), ScanLimits(max_tests_per_module=60))

    async def request(_method: str, url: str, **_kwargs):
        return handler(url)

    client.request = request
    return ScanContext(target=target(), http=client, wordlists={"rutas": paths or []},
                       limits=client.limits, recon={}, heartbeat=lambda *args: None)


def path_of(url: str) -> str:
    return "/" + url.split("://", 1)[1].split("/", 1)[1] if "/" in url.split("://", 1)[1] else "/"


class SoftNotFoundTests(unittest.IsolatedAsyncioTestCase):
    async def test_catch_all_spa_does_not_produce_path_findings(self) -> None:
        def handler(url):
            path = path_of(url)
            if path == "/.env":
                return response(url, 200, "APP_KEY=base64:fixture\nDB_PASSWORD=x", "text/plain")
            return response(url, 200, SPA_SHELL.format(path=path))

        ctx = context(handler, ["/.git/config", "/backup.zip", "/admin", "/debug", "/.env"])
        findings = await PathDiscoveryModule().run(ctx)
        titles = [item.title for item in findings]
        self.assertEqual(titles, ["Exposed or restricted path: /.env"])
        self.assertIn("APP_KEY=", findings[0].evidence)
        filtered = {item["path"] for item in ctx.recon["soft404_filtered_paths"]}
        self.assertIn("/.git/config", filtered)
        self.assertIn("/admin", filtered)

    async def test_extension_specific_waf_403_is_not_a_route_nor_a_bypass(self) -> None:
        def handler(url):
            path = path_of(url)
            if path.endswith(".jsp"):
                return response(url, 403, "<html><title>Request blocked</title>Ref {}</html>".format(len(path)))
            return response(url, 404, "Not found")

        ctx = context(handler, ['/%0a%0a<script>alert("x")</script>.jsp', "/manager/html.jsp"])
        findings = await PathDiscoveryModule().run(ctx)
        self.assertEqual(findings, [])

    async def test_protected_path_is_recon_not_a_vulnerability(self) -> None:
        def handler(url):
            path = path_of(url)
            if path == "/admin":
                return response(url, 403, "<html><title>Forbidden</title>Admin area</html>")
            return response(url, 404, "<html><title>Not found</title></html>")

        ctx = context(handler, ["/admin"])
        findings = await PathDiscoveryModule().run(ctx)
        self.assertEqual(findings, [])
        self.assertIn("/admin (403)", ctx.recon["discovered_paths"])

    async def test_real_route_is_distinct_from_baseline(self) -> None:
        oracle = SoftNotFoundOracle(None)
        baseline = response("https://app.example.com/st404abc", 200, SPA_SHELL.format(path="/st404abc"))
        same = response("https://app.example.com/admin", 200, SPA_SHELL.format(path="/admin"))
        real = response("https://app.example.com/admin", 200,
                        "<html><title>Portal</title><form>user list: alice bob carol</form></html>" * 3)
        self.assertTrue(oracle.compare(same, baseline, "/admin", "st404abc"))
        self.assertEqual(oracle.compare(real, baseline, "/admin", "st404abc"), "")


class LogExposureTests(unittest.IsolatedAsyncioTestCase):
    async def run_logs(self, handler):
        ctx = context(handler)
        return await AdvancedLogicModule()._logs(ctx)

    async def test_html_with_error_words_is_not_a_log(self) -> None:
        findings = await self.run_logs(lambda url: response(url, 200, SPA_SHELL.format(path=path_of(url))))
        self.assertEqual(findings, [])

    async def test_framework_debug_404_for_every_path_is_not_reported_per_log_path(self) -> None:
        findings = await self.run_logs(lambda url: response(url, 200, DJANGO_404.format(path=path_of(url))))
        self.assertEqual(findings, [])

    async def test_real_access_log_is_reported_with_sample(self) -> None:
        def handler(url):
            if path_of(url) == "/access.log":
                return response(url, 200, ACCESS_LOG, "text/plain")
            return response(url, 404, "Not found", "text/plain")

        findings = await self.run_logs(handler)
        self.assertEqual([item.title for item in findings], ["Exposed log/debug content: /access.log"])
        self.assertEqual(findings[0].severity, "High")
        self.assertIn("lineas con formato de log", findings[0].evidence)
        self.assertIn('"GET /item?id=0', findings[0].evidence)


class VersionSummaryTests(unittest.IsolatedAsyncioTestCase):
    async def test_advisories_are_grouped_and_capped(self) -> None:
        issues = [dict(id=f"CVE-2026-{n:04d}", kind="advisory", severity=("Critical" if n == 0 else "Low"),
                       fixed="2.4.99", reference="https://httpd.apache.org/security/", detail="Aviso")
                  for n in range(40)]
        catalog = SimpleNamespace(issues=lambda product, version: issues, data={"sources": {}})
        http = SimpleNamespace(version_observations=[dict(product="apache-http-server", version="2.4.58",
                                                          url="https://example.test/", source="header",
                                                          evidence="Server: Apache/2.4.58")])
        ctx = SimpleNamespace(http=http, target=SimpleNamespace(url="https://example.test/", display="example.test"),
                              recon={}, limits=SimpleNamespace(timeout=8), should_stop=lambda: False,
                              heartbeat=lambda *a: None)
        findings = await VersionAuditor(catalog).run(ctx)
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].severity, "Medium")
        self.assertIn("apache-http-server 2.4.58", findings[0].title)
        self.assertIn("avisos publicados=40", findings[0].evidence)
        self.assertIn("CVE-2026-0000 (Critical)", findings[0].evidence)
        self.assertEqual(finding_quality_exclusion(findings[0]), "")


class QualityRuleTests(unittest.TestCase):
    def record(self, **values):
        base = {"title": "", "source": "", "last_evidence": "", "state": "ACTIVE"}
        base.update(values)
        return base

    def test_legacy_unproven_records_become_candidates(self) -> None:
        cases = {
            "version_advisory_superseded_by_component_summary": self.record(
                title="Componente con aviso de seguridad: apache-http-server | CVE-2024-38476"),
            "legacy_log_marker_without_log_structure": self.record(
                title="Exposed log/debug content: /var/log",
                last_evidence="Marcadores de log/debug observados en la respuesta."),
            "path_without_content_proof": self.record(
                title="Exposed or restricted path: /x.jsp",
                last_evidence="Sensitive=False | ConfirmedContent=False | Content-Tipo=text/html"),
            "slowloris_nse_heuristic_requires_manual_validation": self.record(
                title="Nmap network_vulnerability_scan: CVE-2007-6750 on 443/tcp",
                correlated_sources=["nmap:http-slowloris-check"],
                last_evidence="VULNERABLE: ataque DoS Slowloris Estado: PROBABLEMENTE VULNERABLE"),
            "byterange_nse_check_requires_version_validation": self.record(
                title="Nmap network_vulnerability_scan: Apache Range header denial-of-service CVE-2011-3192",
                correlated_sources=["nmap:http-vuln-cve2011-3192"]),
            "nmap_vulners_version_correlation_requires_validation": self.record(
                title="Nmap vulners_cvss: CVEs potenciales inferidos por la version del servicio: CVE-2024-6387",
                correlated_sources=["nmap:vulners"],
                last_evidence="Version/CPE correlation; vendor patch state unverified | cpe:/a:openbsd:openssh:8.9p1"),
            "zap_active_alert_without_response_evidence": self.record(
                title="ZAP: Format String Error", correlated_sources=["zap:30002"],
                last_evidence="Riesgo=Medium | Confianza=Medium | Evidencia=- | Parametro=password | Plugin=30002"),
        }
        for reason, record in cases.items():
            with self.subTest(reason=reason):
                self.assertEqual(finding_quality_exclusion(record), reason)

    def test_proven_records_are_kept(self) -> None:
        kept = [
            self.record(title="Exposed log/debug content: /access.log",
                        last_evidence="5 lineas con formato de log | Content-Type=text/plain | Muestra: ..."),
            self.record(title="Exposed or restricted path: /.env",
                        last_evidence="Sensitive=True | ConfirmedContent=True | Marcadores=app_key="),
            self.record(title="ZAP: Redireccion Externa", correlated_sources=["zap:20019"],
                        last_evidence="Risk=High | Confidence=Medium | Evidence=evil.example | Param=next"),
            self.record(title="ZAP: Cookie No HttpOnly Flag", correlated_sources=["zap:10010"],
                        last_evidence="Riesgo=Low | Confianza=Medium | Evidencia=- | Parametro=sid"),
        ]
        for record in kept:
            with self.subTest(title=record["title"]):
                self.assertEqual(finding_quality_exclusion(record), "")


class LifecycleTests(unittest.TestCase):
    def test_partial_scan_retires_findings_of_completed_sources_only(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            store = StateStore(Path(tmp) / "state.json")
            stale_zap = Finding(target="fixture", category="External/ZAP", severity="High",
                                title="ZAP: Redireccion Externa", source="zap:20019")
            stale_xss = Finding(target="fixture", category="XSS", severity="High", title="Reflected XSS: q",
                                source="xss")
            store.enrich([stale_zap, stale_xss], "fixture", "2026-01-01")
            store.enrich([], "fixture", "2026-01-02", complete=False, completed_sources={"zap", "headers"})
            states = {item["title"]: item["state"] for item in store.data["findings"].values()}
            self.assertEqual(states["ZAP: Redireccion Externa"], "NOT_SEEN")
            self.assertEqual(states["Reflected XSS: q"], "ACTIVE")

    def test_unproven_findings_become_state_candidates_not_report_findings(self) -> None:
        runner = ScanTitan.__new__(ScanTitan)
        runner.config = SimpleNamespace(report_min_severity="Low", include_pipeline_findings=False,
                                        include_recon_info_findings=False)
        vulners = Finding(target="fixture", category="External/Nmap", severity="High",
                          title="Nmap vulners_cvss: CVEs potenciales inferidos por la version del servicio: CVE-1",
                          source="nmap:vulners", confidence="medium")
        header = Finding(target="fixture", category="Headers", severity="Medium", title="HSTS ausente",
                         source="headers", confidence="high")
        candidates: list = []
        reportable = runner._reportable_findings([vulners, header], candidates)
        self.assertEqual([item.title for item in reportable], ["HSTS ausente"])
        self.assertEqual(candidates, [vulners])
        with tempfile.TemporaryDirectory() as tmp:
            store = StateStore(Path(tmp) / "state.json")
            store.enrich(reportable + candidates, "fixture", "2026-01-01")
            self.assertEqual(len(store.active_records()), 1)
            self.assertEqual(len(store.data["findings"]), 2)

    def test_completed_sources_exclude_timeouts_errors_and_partial_tools(self) -> None:
        runner = ScanTitan.__new__(ScanTitan)
        runner.config = SimpleNamespace(runtime_control=SimpleNamespace(finish_requested=False))
        recon = {
            "completed_modules": ["headers", "xss", "path_discovery", "component_versions"],
            "timeout_skips": [{"module": "path_discovery", "reason": "probe_timeout"}],
            "module_errors": [{"module": "xss", "reason": "boom"}],
            "external_coverage": [
                {"tool": "nmap", "profile": "a", "state": "completed"},
                {"tool": "zap", "state": "failed_partial"},
                {"tool": "nuclei", "profile": "a", "state": "completed"},
                {"tool": "nuclei", "profile": "b", "state": "timeout"},
            ],
        }
        self.assertEqual(runner._completed_sources(recon),
                         {"headers", "component_versions", "version_intelligence", "nmap"})
        runner.config.runtime_control.finish_requested = True
        self.assertEqual(runner._completed_sources(recon), set())


if __name__ == "__main__":
    unittest.main()
