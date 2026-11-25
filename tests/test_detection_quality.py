"""Regression tests for detection recall, identity/dedup, manual commands and the Daily."""
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

from Main import Finding, StateStore, decode_tool_bytes  # noqa: E402
from daily_report import render_daily  # noqa: E402
from finding_triage import injection_family  # noqa: E402
from modules.common import (AsyncHttpClient, HttpResult, ScanContext, ScanLimits, build_manual_command,  # noqa: E402
                            canonical_vulnerability_family, canonical_vulnerability_id)
from modules.cors import CorsModule  # noqa: E402
from modules.injection_validation import InjectionValidator, replay_command  # noqa: E402
from modules.open_redirect import OpenRedirectModule  # noqa: E402
from modules.paths import PathDiscoveryModule  # noqa: E402
from owasp_2025 import normalize_owasp_2025  # noqa: E402
from test_external_tool_hotfixes import target  # noqa: E402


def response(url, status=200, text="", headers=None, ctype="text/html"):
    return HttpResult(url=url, final_url=url, status=status, headers=headers or {}, text=text,
                      body_len=len(text), elapsed=0.01, content_type=ctype)


def context(handler, recon=None, rutas=None):
    client = AsyncHttpClient(None, asyncio.Semaphore(8), ScanLimits(max_tests_per_module=60))

    async def request(method, url, **kwargs):
        return handler(method, url, kwargs)

    client.request = request
    return ScanContext(target=target(), http=client, wordlists={"rutas": rutas or []}, limits=client.limits,
                       recon=recon or {}, heartbeat=lambda *a: None)


class IdentityTests(unittest.TestCase):
    def test_spanish_and_english_titles_share_one_identity(self):
        pairs = [
            ("CSP ausente", "CSP missing"),
            ("Cache-Control no restrictivo", "Cache-Control not restrictive"),
            ("ZAP: Cookie con el atributo SameSite a None", "ZAP: Cookie with SameSite Attribute None"),
            ("Validacion de certificado TLS fallida", "TLS certificate validation failed"),
            ("ZAP: Exploraci�n de Directorios", "ZAP: Directory Browsing"),
            ("ZAP: Redirecci�n Externa", "ZAP: External Redirect"),
        ]
        for spanish, english in pairs:
            with self.subTest(spanish=spanish):
                a = {"title": spanish, "url": "https://app.example.com/login"}
                b = {"title": english, "url": "https://app.example.com/login"}
                self.assertEqual(canonical_vulnerability_family(a), canonical_vulnerability_family(b))
                self.assertEqual(canonical_vulnerability_id(a), canonical_vulnerability_id(b))

    def test_misleading_names_do_not_change_family(self):
        cookie = {"title": "Cookie missing security flags: csrftoken"}
        self.assertEqual(canonical_vulnerability_family(cookie), "cookie-security-flags-missing")

    def test_version_correlation_identity_is_stable_across_cve_lists(self):
        base = {"title": "Nmap vulners_cvss: CVEs potenciales inferidos por la version del servicio",
                "source": "nmap:vulners", "url": "https://app.example.com/"}
        a = {**base, "evidence": "cpe:/a:openbsd:openssh:9.6p1: CVE-2024-6387 8.1"}
        b = {**base, "evidence": "cpe:/a:openbsd:openssh:9.6p1: CVE-2026-1111 9.8 CVE-2025-26465 6.8"}
        apache = {**base, "evidence": "cpe:/a:apache:http_server:2.4.52: CVE-2023-25690"}
        self.assertEqual(canonical_vulnerability_id(a), canonical_vulnerability_id(b))
        self.assertNotEqual(canonical_vulnerability_id(a), canonical_vulnerability_id(apache))

    def test_state_migration_merges_language_duplicates_keeping_newest(self):
        with tempfile.TemporaryDirectory() as tmp:
            store = StateStore(Path(tmp) / "state.json")
            old = {"title": "CSP missing", "target": "t", "asset": "t", "canonical_id": "STV-OLD1",
                   "last_url": "https://app.example.com/", "state": "NOT_SEEN", "last_seen": "2026-10-01",
                   "first_seen": "2026-09-01", "severity": "Medium"}
            new = {"title": "CSP ausente", "target": "t", "asset": "t", "canonical_id": "STV-OLD2",
                   "last_url": "https://app.example.com/", "state": "ACTIVE", "last_seen": "2026-11-20",
                   "first_seen": "2026-11-01", "severity": "Medium"}
            merged = store._migrate_records({"a": old, "b": new})
            self.assertEqual(len(merged), 1)
            record = next(iter(merged.values()))
            self.assertEqual((record["state"], record["title"], record["first_seen"]),
                             ("ACTIVE", "CSP ausente", "2026-09-01"))
            self.assertEqual(record["rule_id"], "csp-missing")

    def test_tool_bytes_decode_without_mojibake(self):
        self.assertEqual(decode_tool_bytes("Exploración".encode("cp1252")), "Exploración")
        self.assertEqual(decode_tool_bytes("Exploración".encode("utf-8")), "Exploración")

    def test_hardening_headers_are_not_injections(self):
        self.assertEqual(injection_family({"title": "CSP ausente", "category": "Client-Side", "cwe": "CWE-79"}), "")
        self.assertEqual(injection_family({"title": "Reflected XSS: q", "category": "XSS"}), "xss")

    def test_cwe_corrects_persisted_owasp_label(self):
        self.assertTrue(normalize_owasp_2025("A04:2025 - Fallos criptográficos", cwe="CWE-601").startswith("A01:2025"))


class RecallTests(unittest.IsolatedAsyncioTestCase):
    async def test_high_value_paths_survive_huge_alphabetical_wordlist(self):
        junk = ["!", "! Game", "$100_laptop", "%00.asp"] + [f"/aaa{n}" for n in range(500)]
        paths = PathDiscoveryModule()._prioritized_paths(junk, 60)
        self.assertEqual(paths[0], "/.env")
        self.assertIn("/.git/config", paths)
        self.assertNotIn("/!", paths)
        self.assertNotIn("/$100_laptop", paths)

    async def test_open_redirect_requires_external_host_differential(self):
        def handler(method, url, kwargs):
            from urllib.parse import parse_qs, urlsplit
            nxt = parse_qs(urlsplit(url).query).get("next", [""])[0]
            return response(url, 302, "", {"Location": nxt or "/"})

        ctx = context(handler, recon={"endpoints": [{"url": "https://app.example.com/go?next=/home"}]})
        findings = await OpenRedirectModule().run(ctx)
        self.assertEqual([f.title for f in findings], ["Open redirect: next"])
        self.assertIn("repetido 2/2", findings[0].evidence)

    async def test_same_site_redirect_is_not_open_redirect(self):
        def handler(method, url, kwargs):
            return response(url, 302, "", {"Location": "/login"})

        ctx = context(handler, recon={"endpoints": [{"url": "https://app.example.com/go?next=/home"}]})
        self.assertEqual(await OpenRedirectModule().run(ctx), [])

    async def test_cors_checks_discovered_api_endpoints(self):
        def handler(method, url, kwargs):
            origin = (kwargs.get("headers") or {}).get("Origin", "")
            if url.endswith("/api/profile"):
                return response(url, 200, "{}", {"Access-Control-Allow-Origin": origin,
                                                 "Access-Control-Allow-Credentials": "true"}, "application/json")
            return response(url, 200, "<html></html>")

        ctx = context(handler, recon={"endpoints": [{"url": "https://app.example.com/api/profile?id=1"}]})
        findings = await CorsModule().run(ctx)
        self.assertEqual([(f.title, f.severity, f.url) for f in findings],
                         [("CORS reflects arbitrary origin", "High", "https://app.example.com/api/profile")])

    async def test_xss_validator_escalates_to_context_payload(self):
        def handler(method, url, kwargs):
            from urllib.parse import parse_qs, urlsplit
            q = parse_qs(urlsplit(url).query).get("q", [""])[0]
            return response(url, 200, f"<html><body><h2>Results for {q}</h2></body></html>")

        ctx = context(handler)
        finding = Finding(target="t", category="XSS", severity="High", title="Reflected XSS candidate: q",
                          url='https://app.example.com/search?q=%22+onfocus%3D%22alert%281%29', param="q",
                          payload='" onfocus="alert(1)', source="xss")
        await InjectionValidator().validate_all(ctx, [finding])
        self.assertEqual(finding.validation["state"], "CONFIRMED")
        self.assertIn("<svg onload=alert(", finding.payload)
        self.assertEqual(finding.title, "Reflected XSS: q")
        self.assertIn("Select-String -SimpleMatch", finding.manual_command)

    async def test_xss_in_escaped_output_is_not_confirmed(self):
        import html

        def handler(method, url, kwargs):
            from urllib.parse import parse_qs, urlsplit
            q = parse_qs(urlsplit(url).query).get("q", [""])[0]
            return response(url, 200, f"<html><body><h2>Results for {html.escape(q)}</h2></body></html>")

        ctx = context(handler)
        finding = Finding(target="t", category="XSS", severity="High", title="Reflected XSS candidate: q",
                          url="https://app.example.com/safe?q=%3Csvg%3E", param="q", payload="<svg>", source="xss")
        await InjectionValidator().validate_all(ctx, [finding])
        self.assertNotEqual(finding.validation["state"], "CONFIRMED")

    async def test_directory_listing_requires_index_signature(self):
        def handler(method, url, kwargs):
            if url.endswith("/static/"):
                return response(url, 200, '<html><title>Index of /static</title><a href="app.js">app.js</a></html>')
            return response(url, 200, "<html><title>Portal</title><div id=app></div></html>")

        ctx = context(handler, rutas=[])
        findings = await PathDiscoveryModule().run(ctx)
        self.assertIn("Directory listing enabled: /static/", [f.title for f in findings])


class ManualCommandTests(unittest.TestCase):
    def test_nmap_command_reruns_exact_script_on_its_port(self):
        finding = SimpleNamespace(url="", target="https://app.example.com/", endpoint="6379/tcp", method="",
                                  param="", payload="", title="Redis sin autenticacion on 6379/tcp",
                                  category="External/Nmap", source="nmap:redis-info", evidence="")
        command = build_manual_command(finding)
        self.assertIn('--script "redis-info"', command)
        self.assertIn("-p 6379", command)
        self.assertIn('"app.example.com"', command)

    def test_nuclei_network_template_uses_host_port(self):
        finding = SimpleNamespace(url="", target="app.example.com", endpoint="app.example.com:6379", method="",
                                  param="", payload="", title="Nuclei: Redis", category="External",
                                  source="nuclei:redis-default-logins", evidence="")
        command = build_manual_command(finding)
        self.assertIn('-u "app.example.com:6379"', command)
        self.assertIn("-pt tcp,javascript,ssl", command)

    def test_path_command_includes_nonexistent_control(self):
        finding = SimpleNamespace(url="https://app.example.com/.env", target="t", endpoint="/.env", method="GET",
                                  param="", payload="", title="Exposed or restricted path: /.env",
                                  category="Discovery", source="path_discovery", evidence="")
        command = build_manual_command(finding)
        self.assertIn("scan-titan-404-control", command)
        self.assertIn("https://app.example.com/.env", command)

    def test_replay_prints_proof_instead_of_only_saving_files(self):
        command = replay_command({"baseline_url": "https://a/x", "probe_url": "https://a/x?q=1"}, "xss", "<svg")
        self.assertIn("Select-String -SimpleMatch '<svg'", command)
        self.assertNotIn(".body.txt", command)

    def test_daily_keeps_proof_for_confirmed_injection(self):
        import Dashboard

        base = {"canonical_id": "STV-1", "target": "https://shop.example.com", "category": "XSS", "severity": "Medium",
                "title": "Cross-site scripting reflejado", "param": "q", "method": "GET",
                "last_url": "https://shop.example.com/search?q=%3Csvg%20onload%3Dst1%3E"}
        confirmed = Dashboard._record_from_state(
            {**base, "validation": {"state": "CONFIRMED", "version": "differential-v1", "payload": "<svg onload=st1>"}},
            {}, "2026-11-24")
        self.assertIn("validacion diferencial confirmada", confirmed["manual_command"])
        self.assertIn("Select-String -SimpleMatch '<svg onload=st1>'", confirmed["manual_command"])
        historical = Dashboard._record_from_state(base, {}, "2026-11-24")
        self.assertIn("pendiente de validacion diferencial", historical["manual_command"])
        self.assertNotIn("Select-String -SimpleMatch '<svg", historical["manual_command"])


class LeakGateTests(unittest.TestCase):
    def test_client_hosts_from_private_sources_block_publication(self):
        sys.path.insert(0, str(ROOT / "tools"))
        import leak_gate

        with tempfile.TemporaryDirectory() as tmp:
            workspace = Path(tmp)
            (workspace / "targets").mkdir()
            (workspace / "targets" / "targets.txt").write_text("https://portal.cliente-ficticio.com.gt/app\n",
                                                                 encoding="utf-8")
            (workspace / "audit_reports").mkdir()
            (workspace / "audit_reports" / "coverage_api.otro-ficticio.net_20261120_101010.json").write_text("{}")
            leaked = workspace / "wordlist.txt"
            leaked.write_text("<script src=http://cliente-ficticio.com.gt/x.js>\nkex-strict-s-v00@openssh.com\n",
                              encoding="utf-8")
            clean = workspace / "clean.py"
            clean.write_text("URL = 'https://app.example.com/'\n", encoding="utf-8")
            denylist = leak_gate.build_denylist(workspace)
            self.assertIn("api.otro-ficticio.net", denylist)
            self.assertEqual(len(leak_gate.scan_file(leaked, denylist)), 1)
            self.assertEqual(leak_gate.scan_file(clean, denylist), [])
            self.assertEqual(leak_gate.main(["--workspace", str(workspace), str(leaked)]), 1)


class DailyTemplateTests(unittest.TestCase):
    def test_daily_has_tabs_dialog_and_strict_csp(self):
        page = render_daily('{"meta":{},"rows":[]}')
        for marker in ('role="tablist"', 'data-tab="hallazgos"', 'data-tab="evolucion"', 'data-view="NOT_SEEN"',
                       'data-view="PENDING"', "Registro operativo de hallazgos", "Centro operativo de vulnerabilidades",
                       "<dialog", 'name="color-scheme"', "connect-src 'none'", "Prueba manual"):
            with self.subTest(marker=marker):
                self.assertIn(marker, page)
        self.assertNotIn("<script src=", page)


if __name__ == "__main__":
    unittest.main()


class DailyHistoryTests(unittest.TestCase):
    def write(self, folder, name, target, date, findings, unreachable=False):
        import json
        report = {"schema": "scan_titan_target_report_v1", "target": target, "date": f"{date} 10:00:00",
                  "findings": findings,
                  "coverage": {"http_availability": {"state": "unreachable" if unreachable else "observed"}}}
        (folder / name).write_text(json.dumps(report), encoding="utf-8")

    def test_timeline_carries_state_and_merges_language_variants(self):
        import daily_history

        csp_en = {"title": "CSP missing", "severity": "Medium", "url": "https://a.example.com/"}
        csp_es = {"title": "CSP ausente", "severity": "Medium", "url": "https://a.example.com/login"}
        xss = {"title": "Reflected XSS: q", "severity": "High", "url": "https://a.example.com/s?q=1", "param": "q",
               "category": "XSS", "validation": {"state": "CONFIRMED", "version": "differential-v1"}}
        with tempfile.TemporaryDirectory() as tmp:
            folder = Path(tmp)
            self.write(folder, "a1.json", "a.example.com", "2026-11-01", [csp_en, xss])
            self.write(folder, "b1.json", "b.example.com", "2026-11-01", [csp_en])
            self.write(folder, "a2.json", "a.example.com", "2026-11-02", [csp_es])   # XSS fixed, CSP same
            self.write(folder, "b3.json", "b.example.com", "2026-11-03", [], unreachable=True)
            timeline = daily_history.build_timeline(folder)
        by_date = {s["date"]: s for s in timeline["series"]}
        self.assertEqual(by_date["2026-11-01"]["total"], 3)
        self.assertEqual((by_date["2026-11-02"]["total"], by_date["2026-11-02"]["new"],
                          by_date["2026-11-02"]["resolved"]), (2, 0, 1))
        # b did not answer HTTP on 11-03: its CSP is not counted as resolved.
        self.assertEqual((by_date["2026-11-03"]["total"], by_date["2026-11-03"]["resolved"],
                          by_date["2026-11-03"]["targets_unreachable"]), (2, 0, 1))
        self.assertEqual(len(timeline["snapshots"]["2026-11-03"]), 2)

    def test_daily_has_history_views_and_logo_slot(self):
        page = render_daily('{"meta":{},"rows":[]}')
        for marker in ('data-tab="evolucion"', 'data-tab="comparar"', 'data-tab="vulnerabilidades"', 'id="stackChart"',
                       'id="flowChart"', 'id="heatmap"', 'id="cmpA"', 'id="logo"'):
            with self.subTest(marker=marker):
                self.assertIn(marker, page)
