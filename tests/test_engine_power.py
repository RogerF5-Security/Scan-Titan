"""Regression tests for the engine-power upgrade (Nmap/Nuclei/ZAP/SSH).

They exercise command construction and parsers offline; no network traffic.
"""
from __future__ import annotations

import asyncio
import sys
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import AsyncMock, patch

sys.path.insert(0, str(Path(__file__).resolve().parent))
from test_external_tool_hotfixes import external_tools, target, titan_main  # noqa: E402

from service_exposure import classify_script, classify_service  # noqa: E402
from ssh_audit import NmapSSHAuditor  # noqa: E402


def nmap_xml(port: str, service: str, scripts: str = "", proto: str = "tcp", **attrs: str) -> str:
    extra = " ".join(f'{key}="{value}"' for key, value in attrs.items())
    return (f'<nmaprun><host><ports><port protocol="{proto}" portid="{port}"><state state="open"/>'
            f'<service name="{service}" {extra}/>{scripts}</port></ports></host></nmaprun>')


class ServiceExposureTests(unittest.TestCase):
    def test_exact_signatures_classify(self):
        self.assertEqual(classify_script("vnc-info", "\n  Protocol version: 3.8\n  Security types: \n    None (1)\n")["severity"], "Critical")
        self.assertEqual(classify_script("redis-info", "\n  Version: 7.2.4\n  Operating System: Linux\n")["severity"], "High")
        self.assertIsNone(classify_script("redis-info", "ERROR: NOAUTH Authentication required"))
        self.assertIn("NLA", classify_script("rdp-enum-encryption", "Security layer\n  Native RDP: SUCCESS\n")["title"])
        self.assertIsNone(classify_script("ftp-anon", "Anonymous FTP login allowed (FTP code 230)"))
        self.assertEqual(classify_script(
            "ftp-anon", "Anonymous FTP login allowed\ndrwxrwxrwx 2 0 0 4096 incoming [NSE: writeable]")["severity"], "High")
        self.assertEqual(classify_script("http-methods", "\n  Potentially risky methods: PUT DELETE\n")["severity"], "Medium")
        self.assertEqual(classify_script("http-methods", "\n  Potentially risky methods: TRACE\n")["severity"], "Low")
        self.assertIsNone(classify_script("http-methods", "\n  Supported Methods: GET HEAD POST OPTIONS\n"))

    def test_rdp_weak_rc4_requires_low_declared_level(self):
        high = "Native RDP: FAILED\nRDP Encryption level: High\n  40-bit RC4: SUCCESS\n"
        self.assertIsNone(classify_script("rdp-enum-encryption", high))
        low = "Native RDP: FAILED\nRDP Encryption level: Client Compatible\n  40-bit RC4: SUCCESS\n"
        self.assertIn("RC4", classify_script("rdp-enum-encryption", low)["title"])

    def test_snmp_info_is_exposure_only_but_sysdescr_proves_public(self):
        self.assertEqual(classify_script("snmp-info", "enterprise: net-snmp\n engineIDFormat: unknown")["severity"], "Low")
        self.assertIn("public", classify_script("snmp-sysdescr", "Linux router 5.10\n  System uptime: 3 days")["title"])

    def test_service_classification(self):
        self.assertEqual(classify_service("23", "tcp", "telnet")["severity"], "High")
        self.assertIsNone(classify_service("992", "tcp", "telnet", tunnel="ssl"))
        self.assertEqual(classify_service("6379", "tcp", "redis")["severity"], "Low")
        self.assertEqual(classify_service("2375", "tcp", "docker", "Docker")["severity"], "Critical")
        self.assertIsNone(classify_service("21", "tcp", "ftp"))
        self.assertIsNone(classify_service("443", "tcp", "https"))


class NmapPipelineTests(unittest.TestCase):
    def test_parse_nmap_emits_exposure_without_profile_in_title(self):
        tools = external_tools()
        ctx = SimpleNamespace(target=target(), recon={})
        xml = nmap_xml("5900", "vnc", '<script id="vnc-info" output="Security types:&#10;    None (1)"/>')
        findings = tools._parse_nmap(ctx, xml, "network_vulnerability_scan")
        titles = [f.title for f in findings]
        self.assertTrue(any(t.startswith("VNC acepta conexiones sin autenticacion") for t in titles), titles)
        self.assertTrue(all("network_vulnerability_scan" not in t for t in titles))
        self.assertIn("5900/tcp", ctx.recon["open_ports"])

    def test_base_profile_covers_high_value_ports_and_dedicated_vulners(self):
        tools = external_tools(full_power=False, nmap_timeout=60,
                               runtime_control=SimpleNamespace(wait_if_paused=AsyncMock(), finish_requested=False),
                               telemetry=None, ssh_username="scan_titan_probe")
        tools.config.external_profile_enabled = lambda tool, name: name in {"network_vulnerability_scan", "vulners_cvss"}
        tools.config.external_profile_timeout = lambda tool, name, fallback: 1
        tools._resolve_binary = lambda *args: "nmap"
        captured = []

        async def fake_run(cmd, timeout):
            captured.append(cmd)
            return "", "", False, 0, 0.1

        tools._run_command = fake_run
        tools._log_external = lambda *args, **kwargs: None
        ctx = SimpleNamespace(target=target(), recon={})
        with tempfile.TemporaryDirectory() as tmp, patch.object(titan_main.asyncio, "sleep", AsyncMock()):
            tools.external_reports_dir = Path(tmp)
            asyncio.run(tools.run_nmap(ctx))
        base = captured[0]
        ports = base[base.index("-p") + 1]
        expanded: set[int] = set()
        for token in ports.split(","):
            low, _, high = token.partition("-")
            expanded.update(range(int(low), int(high or low) + 1))
        for port in (3306, 3389, 5432, 6379, 9200, 27017, 11211, 2375, 8009, 10250):
            self.assertIn(port, expanded)
        self.assertNotIn("--version-light", base)
        expression = base[base.index("--script") + 1]
        self.assertIn("not vulners", expression)
        self.assertIn("redis-info", expression)


class SshAuditTests(unittest.TestCase):
    def ssh_xml(self, version: str, kex: list[str], enc: list[str], mac: list[str]) -> str:
        def table(key, items):
            return f'<table key="{key}">' + "".join(f"<elem>{item}</elem>" for item in items) + "</table>"
        algos = table("kex_algorithms", kex) + table("encryption_algorithms", enc) + table("mac_algorithms", mac)
        return (f'<nmaprun><host><ports><port protocol="tcp" portid="22"><state state="open"/>'
                f'<service name="ssh" product="OpenSSH" version="{version}"/>'
                f'<script id="ssh2-enum-algos" output="x">{algos}</script>'
                f'<script id="ssh-hostkey" output="x"/><script id="ssh-auth-methods" output="x"/>'
                f'</port></ports></host></nmaprun>')

    def test_terrapin_detected_without_strict_kex(self):
        xml = self.ssh_xml("9.9p2", ["curve25519-sha256"], ["chacha20-poly1305@openssh.com"], ["hmac-sha2-256"])
        findings, records = NmapSSHAuditor.parse("t", xml)
        self.assertTrue(any("CVE-2023-48795" in f.title for f in findings))
        self.assertEqual(records[0]["state"], "observed")  # sshv1 absence is not missing coverage

    def test_terrapin_mitigated_by_strict_kex(self):
        xml = self.ssh_xml("9.9p2", ["curve25519-sha256", "kex-strict-s-v00@openssh.com"],
                           ["chacha20-poly1305@openssh.com"], ["hmac-sha2-256"])
        findings, _ = NmapSSHAuditor.parse("t", xml)
        self.assertFalse(any("CVE-2023-48795" in f.title for f in findings))

    def test_regresshion_respects_distro_backport(self):
        modern = (["kex-strict-s-v00@openssh.com"], ["aes256-gcm@openssh.com"], ["hmac-sha2-256"])
        fixed, _ = NmapSSHAuditor.parse("t", self.ssh_xml("8.9p1 Ubuntu 3ubuntu0.10", *modern))
        self.assertFalse(any("CVE-2024-6387" in f.title for f in fixed))
        old, _ = NmapSSHAuditor.parse("t", self.ssh_xml("8.9p1 Ubuntu 3ubuntu0.6", *modern))
        self.assertTrue(any("CVE-2024-6387" in f.title and f.confidence == "medium" for f in old))
        upstream, _ = NmapSSHAuditor.parse("t", self.ssh_xml("9.6p1", *modern))
        self.assertTrue(any("CVE-2024-6387" in f.title for f in upstream))
        patched, _ = NmapSSHAuditor.parse("t", self.ssh_xml("9.8p1", *modern))
        self.assertFalse(any("CVE-2024-6387" in f.title for f in patched))


class NucleiProfileTests(unittest.TestCase):
    def test_network_and_dast_profiles_from_recon(self):
        ctx = SimpleNamespace(target=target(), recon={
            "open_ports": ["22/tcp", "443/tcp", "6379/tcp", "161/udp"],
            "endpoints": [{"url": "https://app.example.com/item?id=1"},
                          {"url": "https://app.example.com/item?id=2"},
                          {"url": "https://evil.example/x?a=1"}],
        })
        with tempfile.TemporaryDirectory() as tmp, patch.object(titan_main, "REPORTS_DIR", Path(tmp)):
            tools = external_tools(external_reports_dir=Path(tmp) / "external reports",
                                   nuclei_severity="low,medium,high,critical", nuclei_retries=2,
                                   nuclei_request_timeout=9, policy=SimpleNamespace(allow_bruteforce=False))
            profiles = {name: cmd for name, cmd, _ in tools._nuclei_profiles("nuclei", ctx)}
            network = profiles["network_services_scan"]
            services = Path(network[network.index("-l") + 1]).read_text(encoding="utf-8").split()
            self.assertEqual(services, ["app.example.com:22", "app.example.com:443", "app.example.com:6379"])
            self.assertIn("tcp,javascript,ssl", network)
            dast = profiles["dast_scan"]
            urls = Path(dast[dast.index("-l") + 1]).read_text(encoding="utf-8").split()
            self.assertEqual(urls, ["https://app.example.com/item?id=1"])
            self.assertIn("-dast", dast)
            vuln = profiles["vulnerability_scan"]
            self.assertEqual(vuln[vuln.index("-retries") + 1], "2")
            self.assertEqual(vuln[vuln.index("-timeout") + 1], "9")
            self.assertIn("brute", vuln[vuln.index("-exclude-tags") + 1])

    def test_no_network_or_dast_profile_without_inputs(self):
        ctx = SimpleNamespace(target=target(), recon={})
        with tempfile.TemporaryDirectory() as tmp, patch.object(titan_main, "REPORTS_DIR", Path(tmp)):
            tools = external_tools(external_reports_dir=Path(tmp) / "external reports")
            names = [name for name, _cmd, _ in tools._nuclei_profiles("nuclei", ctx)]
        self.assertEqual(names, ["vulnerability_scan", "conservative_scan", "cve_scan"])


class ZapUpgradeTests(unittest.IsolatedAsyncioTestCase):
    async def test_alert_cap_truncates_lowest_risk_first(self):
        with tempfile.TemporaryDirectory() as tmp:
            tool = external_tools(zap_max_alerts=150)
            ctx = SimpleNamespace(target=target(), recon={'_zap_export_path': str(Path(tmp) / 'z.json')})

            async def api(path, params, timeout=None):
                risk = params['riskId']
                total = {'3': 20, '2': 30, '1': 0, '0': 400}[risk]
                start, count = int(params['start']), int(params['count'])
                return {'alerts': [{'id': f'{risk}-{i}', 'risk': risk}
                                   for i in range(start, min(total, start + count))]}

            tool._zap_api = api
            alerts = await tool._zap_checkpoint(ctx, 'running')
        self.assertEqual(len(alerts), 150)
        self.assertEqual(sum(1 for a in alerts if a['risk'] == '3'), 20)
        self.assertEqual(sum(1 for a in alerts if a['risk'] == '2'), 30)
        self.assertTrue(ctx.recon['zap_alerts_capped'])

    async def test_active_scan_targets_whole_context(self):
        tool = external_tools(zap_active_timeout=5)
        calls = []

        async def api(path, params=None, timeout=None):
            calls.append((path, dict(params or {})))
            return {'scan': '7'} if path == 'ascan/action/scan' else {'messagesIds': []}

        tool._zap_api = api
        tool._zap_poll_scan = AsyncMock(return_value=(100, 'completed'))
        ctx = SimpleNamespace(target=target(), recon={'_zap_context_id': '3'})
        await tool._zap_active_scan(ctx, 'https://app.example.com/app/login')
        scan_call = next(params for path, params in calls if path == 'ascan/action/scan')
        self.assertNotIn('url', scan_call)
        self.assertEqual(scan_call['contextId'], '3')
        self.assertEqual(ctx.recon['zap_active_scope'], 'context')


if __name__ == "__main__":
    unittest.main()
