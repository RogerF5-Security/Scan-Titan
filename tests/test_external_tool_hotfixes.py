from __future__ import annotations

import os
import json
import sys
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch


ROOT = Path(__file__).resolve().parents[1]
ENGINE = ROOT / "src" / "scan_titan"
os.environ.setdefault("SCAN_TITAN_BASE_DIR", str(ROOT))
os.environ.setdefault("SCAN_TITAN_CONFIG_FILE", str(ROOT / "config" / "config.yaml"))
os.environ.setdefault("SCAN_TITAN_REPORTS_DIR", str(ROOT / "reports"))
sys.path.insert(0, str(ENGINE))

import Main as titan_main  # noqa: E402
from Main import ExternalTools, Target  # noqa: E402
from modules.common import ScanContext, ScanLimits  # noqa: E402
from modules.ssrf import SsrfModule  # noqa: E402


def target() -> Target:
    return Target(
        raw="https://fac.claro.com.gt/",
        url="https://fac.claro.com.gt/",
        host="fac.claro.com.gt",
        ip="192.0.2.10",
        scheme="https",
        port=443,
    )


def external_tools(**overrides) -> ExternalTools:
    values = {
        "nuclei_system_resolvers": True,
        "nuclei_disable_host_error_skip": True,
        "nuclei_max_seed_urls": 60,
        "nuclei_templates_path": "missing-nuclei-templates",
    }
    values.update(overrides)
    return ExternalTools(SimpleNamespace(**values))


class ExternalToolHotfixTests(unittest.TestCase):
    def test_nmap_ports_merge_ranges_and_remove_duplicates(self) -> None:
        tools = external_tools()
        ctx = SimpleNamespace(
            target=target(),
            recon={"open_ports": ["443/tcp", "8080/tcp"], "services": ["8443/tcp https"]},
        )
        ports = tools._nmap_ports_for(ctx, "1-1024,443,8080,8443")
        self.assertEqual(ports, "1-1024,8080,8443")

    def test_subfinder_uses_registrable_domain(self) -> None:
        tools = external_tools()
        self.assertEqual(tools._registrable_domain("fac.claro.com.gt"), "claro.com.gt")
        self.assertEqual(tools._registrable_domain("api.example.com"), "example.com")
        self.assertEqual(tools._registrable_domain("192.0.2.10"), "192.0.2.10")

    def test_nuclei_seeds_are_same_origin_deduplicated_and_bounded(self) -> None:
        tools = external_tools(nuclei_max_seed_urls=4)
        ctx = SimpleNamespace(
            target=target(),
            recon={
                "endpoints": [
                    {"url": "https://fac.claro.com.gt/api/Quantitys", "params": []},
                    {"url": "https://evil.example/api", "params": []},
                ],
                "site_map": ["/login/?next=/", "/login/?next=/"],
                "discovered_paths": ["/static/app.css (200 public_200)"],
            },
        )
        seeds = tools._nuclei_seed_urls(ctx)
        self.assertEqual(len(seeds), 3)
        self.assertIn("https://fac.claro.com.gt/api/Quantitys", seeds)
        self.assertIn("https://fac.claro.com.gt/login/?next=/", seeds)
        self.assertNotIn("https://evil.example/api", seeds)
        self.assertFalse(any(url.endswith(".css") for url in seeds))

    def test_every_nuclei_profile_uses_resolver_guard_target_list_and_jsonl(self) -> None:
        tools = external_tools()
        ctx = SimpleNamespace(target=target(), recon={"endpoints": [{"url": "https://fac.claro.com.gt/login/"}]})
        with tempfile.TemporaryDirectory() as tmp, patch.object(titan_main, "REPORTS_DIR", Path(tmp)):
            profiles = tools._nuclei_profiles("nuclei", ctx)
            for name, command, output in profiles:
                with self.subTest(profile=name):
                    self.assertIn("-sr", command)
                    self.assertIn("-nmhe", command)
                    self.assertIn("-fhr", command)
                    self.assertIn("-l", command)
                    self.assertIn("-jle", command)
                    self.assertEqual(output.suffix, ".jsonl")
            conservative = next(command for name, command, _output in profiles if name == "conservative_scan")
            severity = conservative[conservative.index("-severity") + 1]
            self.assertIn("info", severity.split(","))
            target_list = Path(profiles[0][1][profiles[0][1].index("-l") + 1])
            self.assertIn("https://fac.claro.com.gt/login/", target_list.read_text(encoding="utf-8"))

    def test_nuclei_empty_reasons_are_distinct(self) -> None:
        tools = external_tools()
        missing = Path("missing.jsonl")
        self.assertIn(
            "abandono el host",
            tools._nuclei_empty_reason(0, False, "no address found for host", "", missing, 0, ""),
        )
        self.assertIn(
            "no cargo plantillas",
            tools._nuclei_empty_reason(0, False, "no templates provided", "", missing, 0, ""),
        )
        self.assertIn(
            "Error de parser",
            tools._nuclei_empty_reason(0, False, "", "", missing, 0, "Error de parser Nuclei"),
        )
        self.assertIn(
            "0 hallazgos",
            tools._nuclei_empty_reason(0, False, "", "", missing, 0, ""),
        )

    def test_nuclei_jsonl_parser_reports_valid_and_invalid_lines(self) -> None:
        tools = external_tools()
        ctx = SimpleNamespace(target=target())
        record = (
            '{"template-id":"http-missing-security-headers","matcher-name":"content-security-policy",'
            '"type":"http","host":"https://fac.claro.com.gt",'
            '"matched-at":"https://fac.claro.com.gt/login/",'
            '"info":{"name":"Missing security headers","severity":"info"}}'
        )
        with tempfile.TemporaryDirectory() as tmp:
            output = Path(tmp) / "nuclei.jsonl"
            output.write_text(record + "\nnot-json\n", encoding="utf-8")
            findings, parser_error = tools._parse_nuclei_with_status(ctx, output, "")
        self.assertEqual(len(findings), 1)
        self.assertIn("1 linea(s) JSONL invalidas", parser_error)

    def test_nuclei_valid_empty_array_is_zero_findings_not_parser_error(self) -> None:
        tools = external_tools()
        ctx = SimpleNamespace(target=target())
        with tempfile.TemporaryDirectory() as tmp:
            output = Path(tmp) / "nuclei.json"
            output.write_text("[]", encoding="utf-8")
            findings, parser_error = tools._parse_nuclei_with_status(ctx, output, "")
            reason = tools._nuclei_empty_reason(0, False, "", "", output, len(findings), parser_error)
        self.assertEqual(findings, [])
        self.assertEqual(parser_error, "")
        self.assertIn("0 hallazgos", reason)

    def test_ffuf_soft404_requires_matching_response_shape(self) -> None:
        tools = external_tools()
        signature = {
            "status": 200,
            "size_min": 995,
            "size_max": 1005,
            "size_tolerance": 20,
            "words": 120,
            "lines": 30,
            "redirect_shape": "",
        }
        self.assertTrue(tools._ffuf_matches_soft404({"status": 200, "length": 1000, "words": 120, "lines": 30}, signature))
        self.assertFalse(tools._ffuf_matches_soft404({"status": 200, "length": 5000, "words": 800, "lines": 100}, signature))
        args = tools._ffuf_filter_args(signature)
        self.assertIn("-fs", args)
        self.assertIn("-fw", args)
        self.assertIn("-fmode", args)

    def test_ffuf_parser_excludes_soft404_from_recon_hits(self) -> None:
        tools = external_tools()
        signature = {
            "status": 200,
            "size_min": 995,
            "size_max": 1005,
            "size_tolerance": 20,
            "words": 120,
            "lines": 30,
            "redirect_shape": "",
        }
        ctx = SimpleNamespace(target=target(), recon={})
        payload = {
            "results": [
                {"input": {"FUZZ": "missing"}, "status": 200, "length": 1000, "words": 120, "lines": 30},
                {"input": {"FUZZ": "admin"}, "status": 403, "length": 420, "words": 30, "lines": 10},
            ]
        }
        with tempfile.TemporaryDirectory() as tmp:
            output = Path(tmp) / "ffuf.json"
            output.write_text(json.dumps(payload), encoding="utf-8")
            findings, hit_count = tools._parse_ffuf(ctx, output, "", signature)
        self.assertEqual(findings, [])
        self.assertEqual(hit_count, 1)
        self.assertEqual(ctx.recon["ffuf_soft404_filtered_count"], 1)
        self.assertEqual(len(ctx.recon["wordlist_path_hits"]), 1)
        self.assertEqual(ctx.recon["wordlist_path_hits"][0]["path"], "/admin")


class SsrfObservabilityTests(unittest.IsolatedAsyncioTestCase):
    async def test_ssrf_logs_explicit_skip_without_candidate_parameters(self) -> None:
        progress = []
        ctx = ScanContext(
            target=target(),
            http=SimpleNamespace(),
            wordlists={},
            limits=ScanLimits(),
            recon={"endpoints": []},
            heartbeat=lambda module, detail, tested, hits: progress.append((module, detail, tested, hits)),
        )
        findings = await SsrfModule().run(ctx)
        self.assertEqual(findings, [])
        self.assertEqual(ctx.recon["ssrf_status"], "skipped_no_candidate_parameters")
        self.assertIn("no se observaron parametros candidatos", progress[0][1])


if __name__ == "__main__":
    unittest.main()
