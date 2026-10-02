"""Protocol fixtures and negative controls for the service-access upgrade."""
from __future__ import annotations

import asyncio
import json
import re
import shutil
import socket
import socketserver
import subprocess
import sys
import tempfile
import threading
import time
import unittest
import xml.etree.ElementTree as ET
from pathlib import Path
from types import SimpleNamespace, ModuleType
from unittest.mock import AsyncMock, patch

import aiohttp
from aiohttp import web

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'src/scan_titan'))
from service_audit import audit_ftp, audit_smb, audit_smb_nmap, service_findings, parse_smb_access_xml
from network_audit import NmapNetworkAuditor
from modules.common import HttpResult, ScanContext, ScanLimits, ScanPolicy, Target, AsyncHttpClient
from modules.injection import InjectionModule
from modules.ssrf import SsrfModule, ssrf_response_proven
from modules.role_audit import RoleAuditor
from modules.service_access import ServiceAccessAuditor
from session_manager import SessionManager


class FTPHandler(socketserver.StreamRequestHandler):
    def handle(self):
        data_socket = None

        def reply(text):
            self.wfile.write((text + '\r\n').encode())
            self.wfile.flush()

        reply('220 Test FTP')
        try:
            while line := self.rfile.readline():
                command = line.decode().strip().split(' ', 1)[0]
                self.server.commands.append(command)
                if command == 'AUTH':
                    reply('502 TLS unavailable')
                elif command == 'USER':
                    reply('331 Password required')
                elif command == 'PASS':
                    reply('230 Welcome' if self.server.anonymous else '530 Denied')
                elif command == 'TYPE':
                    reply('200 Type set')
                elif command == 'PASV':
                    data_socket = socket.socket()
                    data_socket.bind(('127.0.0.1', 0))
                    data_socket.listen(1)
                    data_socket.settimeout(3)
                    port = data_socket.getsockname()[1]
                    reply(f'227 Entering Passive Mode (127,0,0,1,{port // 256},{port % 256})')
                elif command == 'LIST':
                    if not self.server.listing:
                        reply('550 Access denied')
                        continue
                    reply('150 Opening data connection')
                    connection, _ = data_socket.accept()
                    with connection:
                        connection.sendall(b'-rw-r--r-- 1 ftp ftp 12 Jan 1 00:00 example.txt\r\n')
                    reply('226 Transfer complete')
                else:
                    reply('221 Bye')
                    break
        finally:
            if data_socket:
                data_socket.close()


class FTPIntegrationTests(unittest.TestCase):
    def test_real_anonymous_ftp_listing_and_denial(self):
        with socketserver.ThreadingTCPServer(('127.0.0.1', 0), FTPHandler) as server:
            server.daemon_threads = True
            server.commands = []
            server.anonymous = server.listing = True
            thread = threading.Thread(target=server.serve_forever, daemon=True)
            thread.start()
            try:
                positive = audit_ftp('127.0.0.1', server.server_address[1], 2)
                self.assertTrue(positive['listing'])
                self.assertEqual(positive['entries_observed'], 1)
                self.assertTrue(service_findings('fixture', positive))
                server.listing = False
                restricted = audit_ftp('127.0.0.1', server.server_address[1], 2)
                self.assertTrue(restricted['anonymous_login'])
                self.assertFalse(restricted['listing'])
                server.anonymous = False
                denied = audit_ftp('127.0.0.1', server.server_address[1], 2)
                self.assertEqual(denied['state'], 'denied')
                self.assertEqual(service_findings('fixture', denied), [])
                self.assertFalse(set(server.commands) & {'STOR', 'RETR', 'DELE', 'MKD'})
            finally:
                server.shutdown()
                thread.join(3)


class SMBEvidenceTests(unittest.TestCase):
    def test_real_smb1_and_smb2_directory_access_when_backend_available(self):
        try:
            from impacket.smbconnection import SMBConnection
        except (ImportError, OSError):
            self.skipTest('Impacket unavailable; native NSE and protocol adapter covered separately')
        code = ("import sys;from impacket.smbserver import SimpleSMBServer;"
                "s=SimpleSMBServer(listenAddress='127.0.0.1',listenPort=int(sys.argv[1]));"
                "s.setSMB2Support(sys.argv[3]=='2');s.addShare('Public',sys.argv[2],readOnly='yes');"
                "s.start()")
        with tempfile.TemporaryDirectory() as folder:
            Path(folder, 'evidence.txt').write_text('test fixture')
            for dialect in ('1', '2'):
                with socket.socket() as probe:
                    probe.bind(('127.0.0.1', 0))
                    port = probe.getsockname()[1]
                process = subprocess.Popen([sys.executable, '-B', '-c', code, str(port), folder, dialect],
                                           stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
                try:
                    ready = False
                    for _ in range(100):
                        try:
                            with socket.create_connection(('127.0.0.1', port), 0.1):
                                ready = True
                                break
                        except OSError:
                            time.sleep(0.05)
                    self.assertTrue(ready, 'SMB fixture did not start')
                    result = audit_smb('127.0.0.1', port, 2, ['Public'], 1)
                    self.assertTrue(any(s.get('list_root') for identity in result['sessions']
                                        for s in identity['shares']), result)
                    if dialect == '1' and shutil.which('nmap'):
                        native = audit_smb_nmap('127.0.0.1', port, ['Public'])
                        self.assertTrue(any(s.get('list_root') for identity in native['sessions']
                                            for s in identity['shares']), native)
                        denied = audit_smb_nmap('127.0.0.1', port, ['MISSING_SHARE'])
                        self.assertFalse(any(s.get('list_root') for identity in denied['sessions']
                                             for s in identity['shares']), denied)
                finally:
                    process.kill()
                    process.wait(timeout=5)

    def record(self, readable=True):
        return {'protocol': 'smb', 'port': 445, 'state': 'observed', 'os': 'Windows XP SP3',
                'server_name': 'LEGACY-LAB', 'dialect': 'NT LM 0.12', 'signing_required': False,
                'sessions': [{'identity': 'null', 'accepted': True, 'guest_mapping': True,
                              'shares': [{'name': 'SharedDocs', 'list_root': readable, 'entries_observed': 1}]}]}

    def test_xp_report_names_server_resource_and_proven_access(self):
        findings = service_findings('127.0.0.1', self.record())
        exposure = next(f for f in findings if 'sin credenciales' in f.title)
        self.assertIn('LEGACY-LAB', exposure.evidence)
        self.assertIn('Windows XP', exposure.evidence)
        self.assertIn('SharedDocs', exposure.title)
        self.assertEqual(exposure.severity, 'High')

    def test_null_session_without_share_access_is_not_file_exposure(self):
        findings = service_findings('fixture', self.record(False))
        self.assertFalse(any('recurso SharedDocs' in f.title for f in findings))
        self.assertTrue(any(f.severity == 'Info' for f in findings))

    def test_native_nse_structured_access_and_denial(self):
        root = ET.fromstring('''<nmaprun><host><hostscript><script id="titan-smb-access">
          <table key="null"><elem key="accepted">true</elem><elem key="os">Windows XP</elem>
            <table key="SharedDocs"><elem key="list_root">true</elem><elem key="entries_observed">2</elem></table>
            <table key="C$"><elem key="list_root">false</elem></table></table>
          <table key="Guest/empty-password"><elem key="accepted">false</elem></table>
          </script></hostscript></host></nmaprun>''')
        result = parse_smb_access_xml(root)
        self.assertTrue(result['sessions'][0]['shares'][0]['list_root'])
        self.assertFalse(result['sessions'][0]['shares'][1]['list_root'])
        self.assertFalse(result['sessions'][1]['accepted'])

    def test_smb_hostscript_ms17_requires_exact_vulnerable_state(self):
        for state, expected in [('VULNERABLE', 1), ('NOT VULNERABLE', 0), ('UNKNOWN', 0)]:
            xml = f'<nmaprun><host><hostscript><script id="smb-vuln-ms17-010"><table><elem key="state">{state}</elem></table></script></hostscript></host></nmaprun>'
            findings, _ = NmapNetworkAuditor.parse('fixture', xml)
            self.assertEqual(len(findings), expected)

    def test_smb_script_error_is_not_clean(self):
        xml = '<nmaprun><host><hostscript><script id="smb-vuln-ms17-010" output="ERROR: failed"/></hostscript></host></nmaprun>'
        findings, records = NmapNetworkAuditor.parse('fixture', xml)
        self.assertEqual(findings, [])
        self.assertEqual(records[0]['state'], 'error')

    def test_smb_signing_required_and_smb2_only_do_not_flag_smb1(self):
        xml = '<nmaprun><host><hostscript><script id="smb2-security-mode" output="Message signing required"/><script id="smb-protocols" output="3.1.1"/></hostscript></host></nmaprun>'
        findings, _ = NmapNetworkAuditor.parse('fixture', xml)
        self.assertEqual(findings, [])

    def test_impacket_calls_only_login_enumeration_and_listing(self):
        calls = []

        class Client:
            def __init__(self, *args, **kwargs): pass
            def login(self, user, password): calls.append(('login', user, password))
            def isGuestSession(self): return True
            def getServerOS(self): return 'Windows XP'
            def getServerName(self): return 'LEGACY'
            def getDialect(self): return 'NT LM 0.12'
            def isSigningRequired(self): return False
            def listShares(self): return [{'shi1_type': 0, 'shi1_netname': 'Docs\x00'}, {'shi1_type': 3, 'shi1_netname': 'IPC$\x00'}]
            def listPath(self, share, pattern):
                calls.append(('list', share, pattern))
                return [SimpleNamespace(get_longname=lambda: 'example.txt')]
            def close(self): pass

        module = ModuleType('impacket.smbconnection')
        module.SMBConnection = Client
        with patch.dict(sys.modules, {'impacket': ModuleType('impacket'), 'impacket.smbconnection': module}):
            result = audit_smb('127.0.0.1', 445)
        self.assertTrue(result['sessions'][0]['shares'][0]['list_root'])
        self.assertEqual([c for c in calls if c[0] == 'login'], [('login', '', ''), ('login', 'Guest', '')])
        self.assertFalse(any(c[1] == 'IPC$' for c in calls))


class WebProofTests(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        self.mode = 'vulnerable'
        self.secret = 'remote-body-only-unique-proof-918472'
        app = web.Application()
        app.router.add_get('/fetch', self.fetch)
        app.router.add_get('/proof', lambda _: web.Response(text=self.secret))
        app.router.add_get('/command', self.command)
        app.router.add_get('/object', self.object)
        self.runner = web.AppRunner(app)
        await self.runner.setup()
        self.site = web.TCPSite(self.runner, '127.0.0.1', 0)
        await self.site.start()
        self.port = self.site._server.sockets[0].getsockname()[1]
        self.base = f'http://127.0.0.1:{self.port}'
        self.client = aiohttp.ClientSession()

    async def asyncTearDown(self):
        await self.client.close()
        await self.runner.cleanup()

    async def fetch(self, request):
        value = request.query.get('url', '')
        if self.mode == 'redirect':
            raise web.HTTPFound(value if value.startswith(self.base) else '/proof')
        if self.mode == 'vulnerable' and value == self.base + '/proof':
            async with self.client.get(value) as response:
                return web.Response(text=await response.text())
        return web.Response(text=value)

    async def command(self, request):
        value = request.query.get('cmd', '')
        match = re.search(r'expr (\d+) \+ (\d+)', value)
        # Fixture emulates a command's output without passing user data to a shell.
        text = str(int(match[1]) + int(match[2])) if match and self.mode == 'vulnerable' else value
        return web.Response(text=text)

    async def object(self, request):
        if self.mode != 'vulnerable' and request.headers.get('Authorization') != 'Bearer owner':
            return web.Response(status=403)
        return web.json_response({'private_record': 'owned-resource-proof'})

    async def request(self, method, url, **kwargs):
        kwargs.pop('timeout', None)
        async with self.client.request(method, url, **kwargs) as response:
            text = await response.text()
            return HttpResult(url, str(response.url), response.status, dict(response.headers), text, len(text), 0.01)

    def context(self, path, stateful=None, sessions=None):
        url = self.base + path
        limits = ScanLimits(max_tests_per_module=12, jitter_min_seconds=0, jitter_max_seconds=0)
        return ScanContext(Target(url, url, '127.0.0.1', '127.0.0.1', 'http', self.port),
            AsyncHttpClient(self.client, asyncio.Semaphore(5), limits), {}, limits,
            {'endpoints': []}, lambda *args: None, ScanPolicy(stateful=stateful or {}), sessions)

    async def test_rce_requires_two_calculated_results_not_reflection(self):
        ctx = self.context('/command')
        found = await InjectionModule()._command(ctx, [(ctx.target.url, ['cmd'])])
        self.assertEqual(len(found), 1)
        self.assertEqual(len(set(ctx.recon['rce_checks'][0]['outputs'])), 2)
        self.mode = 'reflection'
        self.assertEqual(await InjectionModule()._command(ctx, [(ctx.target.url, ['cmd'])]), [])

    async def test_ssrf_real_fetch_positive_reflection_and_redirect_negative(self):
        settings = {'ssrf': {'probes': [{'url': self.base + '/proof', 'expected_body': self.secret}]}}
        ctx = self.context('/fetch?url=test', settings)
        found = await SsrfModule().run(ctx)
        self.assertEqual(len(found), 1)
        for self.mode in ('reflection', 'redirect'):
            self.assertEqual(await SsrfModule().run(ctx), [])
        self.assertFalse(ssrf_response_proven(SimpleNamespace(status=200, text=self.secret), 'url', (self.secret,))[0])

    async def test_idor_owned_objects_and_unauthenticated_access(self):
        profile = {'name': 'Owner', 'headers': {'Authorization': 'Bearer owner'}}
        # Static profiles require an explicit identity rule, evaluated by SessionManager.
        profile['check'] = {'url': '/object', 'json_path': 'private_record', 'equals': 'owned-resource-proof'}
        settings = {'roles': {'objects': [{'url': '/object', 'owner_profile': 'Owner',
                                          'sensitive_json_paths': ['private_record']}]}}
        async with SessionManager(self.base, [profile]) as manager:
            ctx = self.context('/object', settings, manager)
            found = await RoleAuditor().run(ctx)
            self.assertEqual(len(found), 1)
            self.assertIn('IDOR', found[0].title)
            self.mode = 'protected'
            self.assertEqual(await RoleAuditor().run(ctx), [])

    async def test_service_worker_reports_error_instead_of_clean_on_missing_protocol(self):
        result = await ServiceAccessAuditor._worker({'protocol': 'ftp', 'host': '127.0.0.1', 'port': self.port, 'timeout': 0.2})
        self.assertEqual(result['state'], 'error')

    async def test_non_http_target_runs_network_tools_without_web_tools(self):
        from test_external_tool_hotfixes import external_tools
        tool = external_tools(skip_external=False, policy=SimpleNamespace(enable_nmap=True))
        tool.run_nmap = AsyncMock(return_value=[])
        ctx = self.context('/command')
        ctx.recon['http_availability'] = {'state': 'unreachable'}
        self.assertEqual(await tool.run(ctx), [])
        tool.run_nmap.assert_awaited_once_with(ctx)

    async def test_duplicate_query_parameter_is_replaced(self):
        ctx = self.context('/command?cmd=old&other=keep')
        response = await ctx.http.request('GET', ctx.target.url, params={'cmd': ';expr 91234 + 123'})
        self.assertEqual(response.text, '91357')
        self.assertNotIn('cmd=old', response.final_url)
        self.assertIn('other=keep', response.final_url)

    async def test_generic_login_success_text_is_not_confirmed_auth_bypass(self):
        from modules.auth_session import AuthSessionModule
        ctx = self.context('/login')
        ctx.http = SimpleNamespace(request=AsyncMock(return_value=HttpResult(
            self.base, self.base, 200, {}, 'Welcome to the session dashboard demo', 42, 0.01)))
        forms = [{'action': self.base + '/login', 'method': 'POST',
                  'fields': {'username': {'value': ''}, 'password': {'value': ''}}}]
        module = AuthSessionModule()
        findings = await module._login_bypass(ctx, forms)
        findings += await module._controlled_credential_probe(ctx, forms)
        self.assertTrue(findings)
        self.assertTrue(all(f.severity == 'Info' for f in findings))
