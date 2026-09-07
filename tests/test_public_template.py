from __future__ import annotations

import importlib.util
import json
import os
import sys
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
ENGINE = ROOT / "src" / "scan_titan"


class PublicTemplateTests(unittest.TestCase):
    def setUp(self) -> None:
        os.environ.setdefault("SCAN_TITAN_BASE_DIR", str(ROOT))
        os.environ.setdefault("SCAN_TITAN_CONFIG_FILE", str(ROOT / "config" / "config.yaml"))
        os.environ.setdefault("SCAN_TITAN_REPORTS_DIR", str(ROOT / "reports"))
        os.environ.setdefault("SCAN_TITAN_TARGETS_FILE", str(ROOT / "targets" / "targets.txt"))
        sys.path.insert(0, str(ENGINE))

    def test_required_layout_exists(self) -> None:
        required = [
            ROOT / "main.py",
            ROOT / "config" / "config.yaml",
            ROOT / "targets" / "targets.txt",
            ROOT / "wordlists",
            ROOT / "reports",
            ENGINE / "Main.py",
            ENGINE / "modules",
        ]
        for path in required:
            with self.subTest(path=path):
                self.assertTrue(path.exists(), str(path))

    def test_full_aliases_are_accepted(self) -> None:
        from Main import build_argparser

        parser = build_argparser()
        for alias in ("--full", "-full", "-Full"):
            with self.subTest(alias=alias):
                args = parser.parse_args([alias])
                self.assertTrue(args.full)

    def test_optional_private_technical_exporter_is_absent(self) -> None:
        self.assertIsNone(importlib.util.find_spec("technical_detail_exporter"))

    def test_whatweb_json_parser_extracts_structured_technologies(self) -> None:
        from recon_manager import parse_whatweb_json

        sample = [
            {
                "target": "http://scanme.nmap.org/",
                "plugins": {
                    "Apache": {"version": ["2.4.7"], "string": ["Ubuntu"]},
                    "HTTPServer": {"string": ["Apache/2.4.7 (Ubuntu)"]},
                    "jQuery": {"version": ["1.12.4"]},
                },
            }
        ]
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "whatweb.json"
            path.write_text(json.dumps(sample), encoding="utf-8")
            technologies = parse_whatweb_json(path)

        labels = {item["name"]: item for item in technologies}
        self.assertEqual(labels["Apache"]["category"], "Web Server")
        self.assertEqual(labels["Apache"]["version"], "2.4.7")
        self.assertEqual(labels["jQuery"]["category"], "JavaScript/UI")

    def test_recon_dashboard_renders_compact_cells(self) -> None:
        from recon_manager import ReconMatrixManager

        with tempfile.TemporaryDirectory() as tmp:
            manager = ReconMatrixManager(Path(tmp) / "Recon_Matrix.xlsx")
            manager.update_target(
                {
                    "Target": "example.test",
                    "Tipo": "URL",
                    "URL Base": "https://example.test/",
                    "WhatWeb Tecnologias": ["Web Server: Apache 2.4.7", "JavaScript/UI: jQuery 3.7.1"],
                    "Tecnologias": ["Web Server: Apache 2.4.7", "JavaScript/UI: jQuery 3.7.1"],
                }
            )
            dashboard = manager.write_dashboard(Path(tmp) / "Recon_Dashboard.html")
            html = dashboard.read_text(encoding="utf-8")

        self.assertIn("WhatWeb Tecnologias", html)
        self.assertIn("class='chip", html)

    def test_default_runtime_uses_10k_wordlist_floor_and_evidence(self) -> None:
        from Main import RuntimeConfig, build_argparser

        args = build_argparser().parse_args([])
        config = RuntimeConfig(args)

        self.assertGreaterEqual(config.max_tests_per_module, 10000)
        self.assertGreaterEqual(config.module_test_budget("path_discovery"), 10000)
        self.assertGreaterEqual(config.module_test_budget("xss"), 10000)
        self.assertGreaterEqual(config.ffuf_max_words, 10000)
        self.assertTrue(config.policy.evidence_cards)
        self.assertTrue(config.policy.browser_evidence)
        self.assertFalse(config.policy.console_screenshots)
        self.assertEqual(config.nmap_timeout, 0)
        self.assertEqual(config.nuclei_timeout, 0)
        self.assertEqual(config.zap_timeout, 0)
        self.assertEqual(config.zap_spider_timeout, 0)
        self.assertEqual(config.zap_passive_timeout, 0)
        self.assertEqual(config.zap_active_timeout, 0)
        self.assertEqual(config.external_profile_timeout("nmap", "network_vulnerability_scan", 0), 0)
        self.assertEqual(config.external_profile_timeout("nuclei", "vulnerability_scan", 0), 0)

    def test_recon_sitemap_filters_artifacts_and_builds_tree(self) -> None:
        from sitemap_manager import ReconSiteMapManager

        with tempfile.TemporaryDirectory() as tmp:
            manager = ReconSiteMapManager(Path(tmp), "Scan Titan Test")
            stats = manager.update_target(
                target="example.test",
                base_url="https://example.test/",
                ip="192.0.2.10",
                timestamp="2026-09-07 08:00:00",
                recon={
                    "site_map": [
                        "https://example.test/#/login",
                        "script-src data:",
                        '"*://*.coin-hive.com/lib/*"',
                    ],
                    "wordlist_path_hits": [
                        {
                            "url": "https://example.test/api/users?id=1",
                            "status": 200,
                            "classification": "public_200",
                            "method": "GET",
                        },
                        {
                            "url": "https://example.test/admin",
                            "status": 403,
                            "classification": "forbidden",
                            "method": "GET",
                        },
                    ],
                },
            )
            payload = json.loads((Path(tmp) / "Recon_Sitemap.json").read_text(encoding="utf-8"))
            html = (Path(tmp) / "Recon_Sitemap.html").read_text(encoding="utf-8")

        target_map = payload["targets"]["example.test"]
        routes = {item["route"] for item in target_map["routes"]}
        self.assertGreaterEqual(stats["routes"], 3)
        self.assertIn("/#/login", routes)
        self.assertIn("/api/users", routes)
        self.assertIn("/admin", routes)
        self.assertNotIn("script-src data:", html)
        self.assertNotIn("coin-hive", html)
        self.assertIn("Site Map del objetivo", html)

    def test_formal_report_is_generated_with_browser_evidence_field(self) -> None:
        from Main import Finding, ReportWriter, Target

        with tempfile.TemporaryDirectory() as tmp:
            report_dir = Path(tmp) / "reports"
            browser_dir = report_dir / "browser_evidence"
            browser_dir.mkdir(parents=True)
            browser_png = browser_dir / "sample_browser.png"
            browser_png.write_bytes(b"png")
            target = Target(
                raw="https://example.test/",
                url="https://example.test/",
                host="example.test",
                ip="192.0.2.10",
                scheme="https",
                port=443,
            )
            finding = Finding(
                target="example.test",
                category="Headers",
                severity="Medium",
                title="CSP missing",
                url="https://example.test/",
                evidence="Content-Security-Policy header not observed.",
                cwe="CWE-693",
                owasp="A02:2025 - Configuración de seguridad incorrecta",
                browser_artifact=str(browser_png),
            )
            writer = ReportWriter(report_dir, report_dir / "history")
            output = writer.write_formal_report(
                [{"target": target, "findings": [finding], "duration": 1.3}],
                "2026-09-01 08:00:00",
            )
            html = output.read_text(encoding="utf-8")

        self.assertIn("Informe Formal de Vulnerabilidades", html)
        self.assertIn("Captura browser del hallazgo", html)
        self.assertIn("CSP missing", html)


if __name__ == "__main__":
    unittest.main()
