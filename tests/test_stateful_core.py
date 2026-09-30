"""Loopback integration tests: real cookies, tokens, persistence and concurrency."""
from __future__ import annotations

import asyncio
import html
import json
import os
import sys
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

from aiohttp import web

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'src' / 'scan_titan'))
from session_manager import RequestSpec, SessionManager
from modules.common import ScanContext, ScanLimits, ScanPolicy, Target
from modules.role_audit import RoleAuditor
from modules.race_conditions import RaceCondition_Tester
from modules.stored_xss import StoredXSS_Auditor
from modules.websocket_analyzer import WebSocket_Analyzer
from modules.session_lifecycle import SessionLifecycleAuditor
from ssh_audit import NmapSSHAuditor


class StatefulCoreTests(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self) -> None:
        self.tokens = {}
        self.logins = 0
        self.writes = 0
        self.persist = True
        self.escape = False
        self.content = ''
        self.access_broken = False
        self.race_broken = True
        self.redemptions = 0
        self.concurrent = 0
        self.peak = 0
        self.burst_ready = asyncio.Event()
        self.ws_private_open = False
        self.revoke_on_logout = True
        app = web.Application()
        app.add_routes([
            web.get('/login', self.login_form), web.post('/login', self.login),
            web.post('/challenge', self.challenge), web.get('/me', self.me),
            web.get('/resource', self.resource), web.get('/cookie', self.cookie),
            web.post('/write', self.write), web.get('/form', self.form),
            web.post('/logout', self.logout),
            web.post('/submit', self.submit), web.get('/board', self.board),
            web.post('/redeem', self.redeem), web.get('/state', self.state),
            web.get('/ws', self.websocket), web.get('/ws-public', self.websocket_public),
            web.get('/ws-redirect', self.websocket_redirect),
        ])
        self.runner = web.AppRunner(app)
        await self.runner.setup()
        self.site = web.TCPSite(self.runner, '127.0.0.1', 0)
        await self.site.start()
        self.port = self.site._server.sockets[0].getsockname()[1]
        self.base = f'http://127.0.0.1:{self.port}'

    async def asyncTearDown(self) -> None:
        await self.runner.cleanup()

    def identity(self, request):
        token = request.headers.get('Authorization', '').removeprefix('Bearer ')
        return self.tokens.get(token or request.cookies.get('sid', ''))

    async def login_form(self, request):
        response = web.Response(text='<form><input name="csrf" value="nonce"></form>', content_type='text/html')
        response.set_cookie('csrf', 'nonce')
        return response

    async def login(self, request):
        data = await request.json() if request.content_type == 'application/json' else dict(await request.post())
        if request.content_type != 'application/json' and (data.get('csrf') != 'nonce' or request.cookies.get('csrf') != 'nonce'):
            return web.Response(status=403)
        role = data.get('username')
        if role not in {'admin', 'user'} or data.get('password') != 'fixture':
            return web.Response(status=401)
        self.logins += 1
        token = f'token-{role}-{self.logins}'
        self.tokens[token] = role
        response = web.json_response({'access_token': token})
        response.set_cookie('sid', token, httponly=True)
        return response

    async def challenge(self, request):
        return web.json_response({'mfa_required': True}, status=202)

    async def me(self, request):
        role = self.identity(request)
        return web.json_response({'role': role}) if role else web.Response(status=401)

    async def resource(self, request):
        if self.identity(request) != 'admin' and not self.access_broken:
            return web.Response(status=403)
        return web.json_response({'id': 42, 'email': 'private@fixture.invalid'})

    async def cookie(self, request):
        response = web.json_response({'incoming': bool(request.cookies)})
        response.set_cookie('contamination', 'value')
        return response

    async def write(self, request):
        self.writes += 1
        return web.Response(status=401)

    async def logout(self, request):
        token = request.headers.get('Authorization', '').removeprefix('Bearer ')
        if self.revoke_on_logout:
            self.tokens.pop(token or request.cookies.get('sid', ''), None)
        response = web.Response(status=204)
        response.del_cookie('sid')
        return response

    async def test_logout_replays_old_credential_without_automatic_relogin(self):
        profiles = self.profiles()
        profiles[0]['logout'] = {'url': '/logout', 'method': 'POST'}
        for revoke in (True, False):
            self.revoke_on_logout = revoke
            async with SessionManager(self.base, profiles) as manager:
                findings = await SessionLifecycleAuditor().run(self.context(manager))
                self.assertEqual(len(findings), 0 if revoke else 1)
                self.assertEqual(manager.profiles['Admin'].state, 'logged_out')
                self.assertIsNone(await manager.request('Admin', RequestSpec('/me')))

    async def form(self, request):
        return web.Response(text='<form method="POST" action="/submit"><textarea name="comment"></textarea></form><a href="/board">Board</a>', content_type='text/html')

    async def submit(self, request):
        data = await request.post()
        if self.persist:
            self.content = data.get('comment', '')
        return web.Response(text=data.get('comment', ''), headers={'Location': '/board'}, content_type='text/html')

    async def board(self, request):
        return web.Response(text=html.escape(self.content) if self.escape else self.content, content_type='text/html')

    async def redeem(self, request):
        self.concurrent += 1
        self.peak = max(self.peak, self.concurrent)
        try:
            if self.redemptions:
                return web.json_response({'accepted': False}, status=409)
            if self.concurrent == 20:
                self.burst_ready.set()
            await asyncio.wait_for(self.burst_ready.wait(), timeout=3)
            await asyncio.sleep(0.01)
            if not self.race_broken and self.redemptions:
                return web.json_response({'accepted': False}, status=409)
            self.redemptions += 1
            return web.json_response({'accepted': True, 'id': self.redemptions})
        finally:
            self.concurrent -= 1

    async def state(self, request):
        return web.json_response({'count': self.redemptions})

    async def websocket(self, request):
        if not self.identity(request) and not self.ws_private_open:
            return web.Response(status=401)
        websocket = web.WebSocketResponse()
        await websocket.prepare(request)
        await websocket.send_str('fixture-private-message')
        async for message in websocket:
            pass
        return websocket

    async def websocket_public(self, request):
        websocket = web.WebSocketResponse()
        await websocket.prepare(request)
        await websocket.send_str('public')
        async for message in websocket:
            pass
        return websocket

    async def websocket_redirect(self, request):
        raise web.HTTPFound(self.base + '/ws')

    def profiles(self):
        return [{'name': role.title(), 'login': {'url': '/login', 'method': 'POST',
                 'json': {'username': role, 'password': 'fixture'}},
                 'token': {'json_path': 'access_token'},
                 'check': {'url': '/me', 'json_path': 'role', 'equals': role}}
                for role in ('admin', 'user')]

    def context(self, manager, settings=None):
        policy = ScanPolicy(allow_state_changing_api_tests=True, stateful=settings or {})
        target = Target(self.base, self.base, '127.0.0.1', '127.0.0.1', 'http', self.port)
        return ScanContext(target, SimpleNamespace(circuit_open=False), {}, ScanLimits(),
                           {'endpoints': []}, lambda *args: None, policy, manager)

    async def test_tokens_cookies_and_anonymous_are_isolated(self):
        async with SessionManager(self.base, self.profiles()) as manager:
            self.assertEqual(manager.authenticated_names(), ['Admin', 'User'])
            for name, expected in [('Admin', 'admin'), ('User', 'user')]:
                response = await manager.request(name, RequestSpec('/me'))
                self.assertEqual(json.loads(response.text)['role'], expected)
            self.assertEqual((await manager.request('Unauth', RequestSpec('/me'))).status, 401)
            await manager.request('Unauth', RequestSpec('/cookie'))
            second = await manager.request('Unauth', RequestSpec('/cookie'))
            self.assertFalse(json.loads(second.text)['incoming'])
            with self.assertRaises(ValueError):
                await manager.request('Admin', RequestSpec('https://outside.invalid'))

    async def test_csrf_form_login_uses_independent_cookie_jar(self):
        profile = {'name': 'Form', 'login': {'url': '/login', 'method': 'POST',
                   'data': {'username': 'user', 'password': 'fixture'},
                   'csrf': {'url': '/login', 'selector': 'input[name=csrf]', 'field': 'csrf'}},
                   'check': {'url': '/me', 'json_path': 'role', 'equals': 'user'}}
        async with SessionManager(self.base, [profile]) as manager:
            self.assertEqual(manager.authenticated_names(), ['Form'])

    async def test_refresh_and_no_automatic_mutation_replay(self):
        async with SessionManager(self.base, self.profiles()) as manager:
            self.tokens.clear()
            result = await manager.request('User', RequestSpec('/me'))
            self.assertEqual(result.status, 200)
            result = await manager.request('User', RequestSpec('/write', 'POST'))
            self.assertEqual(result.status, 401)
            self.assertEqual(self.writes, 1)

    async def test_failed_identity_and_mfa_never_become_authenticated(self):
        profile = {'name': 'Pending', 'login': {'url': '/challenge', 'method': 'POST'},
                   'mfa_challenge': {'statuses': [202], 'json_path': 'mfa_required', 'equals': True},
                   'check': {'url': '/me', 'json_path': 'role', 'equals': 'user'}}
        async with SessionManager(self.base, [profile]) as manager:
            self.assertEqual(manager.profiles['Pending'].state, 'mfa_required')
            self.assertEqual(manager.authenticated_names(), [])
        with patch.dict(os.environ, {}, clear=True):
            async with SessionManager(self.base, [{'name': 'Missing', 'bearer_token': '${UNSET_FIXTURE_SECRET}'}]) as manager:
                self.assertEqual(manager.profiles['Missing'].state, 'failed')

    async def test_roles_require_protected_content_and_explicit_policy(self):
        settings = {'roles': {'requests': [{'url': '/resource', 'allowed_profiles': ['Admin'],
                                            'sensitive_json_paths': ['email']}]}}
        async with SessionManager(self.base, self.profiles()) as manager:
            ctx = self.context(manager, settings)
            self.assertEqual(await RoleAuditor().run(ctx), [])
            self.access_broken = True
            self.assertEqual(len(await RoleAuditor().run(ctx)), 2)
            settings['roles']['requests'][0].pop('allowed_profiles')
            self.assertEqual(await RoleAuditor().run(ctx), [])

    async def test_stored_canary_rejects_reflection_and_escaped_output(self):
        settings = {'stored_xss': {'urls': ['/form'], 'max_forms': 1, 'validate_browser': False}}
        async with SessionManager(self.base, []) as manager:
            ctx = self.context(manager, settings)
            self.persist = False
            self.assertEqual(await StoredXSS_Auditor().run(ctx), [])
            self.assertEqual(ctx.recon['stored_xss_results'][0]['state'], 'no_persistence_observed')
            self.persist = True
            self.escape = True
            self.assertEqual(await StoredXSS_Auditor().run(ctx), [])
            self.assertEqual(ctx.recon['stored_xss_results'][0]['state'], 'persisted_escaped_or_transformed')
            self.escape = False
            self.assertEqual(await StoredXSS_Auditor().run(ctx), [])
            self.assertEqual(ctx.recon['stored_xss_results'][0]['state'], 'persisted_unescaped_candidate')

    async def test_stored_xss_executes_only_after_independent_reload(self):
        try:
            from playwright.async_api import async_playwright
            async with async_playwright() as p:
                if not Path(p.chromium.executable_path).exists():
                    self.skipTest('Chromium not installed')
        except ImportError:
            self.skipTest('Playwright not installed')
        async with SessionManager(self.base, []) as manager:
            ctx = self.context(manager, {'stored_xss': {'urls': ['/form'], 'max_forms': 1}})
            ctx.policy.enable_browser = True
            findings = await StoredXSS_Auditor().run(ctx)
            self.assertEqual(len(findings), 1)
            self.assertIn('independent reload', findings[0].title)

    async def test_twenty_real_concurrent_requests_detect_only_broken_invariant(self):
        settings = {'race': {'cases': [{'request': {'url': '/redeem', 'method': 'POST', 'json': {'coupon': 'fixture'}},
                    'success': {'statuses': [200], 'json_path': 'accepted', 'equals': True},
                    'success_id_path': 'id', 'max_successes': 1,
                    'verify': {'url': '/state', 'value_path': 'count', 'max_delta': 1}}]}}
        async with SessionManager(self.base, []) as manager:
            ctx = self.context(manager, settings)
            self.assertEqual(len(await RaceCondition_Tester().run(ctx)), 1, ctx.recon)
            self.assertEqual(self.peak, 20)
            self.assertEqual(ctx.recon['race_results'][0]['unique_successes'], 20)
            self.redemptions = 0
            self.race_broken = False
            self.burst_ready.clear()
            self.assertEqual(await RaceCondition_Tester().run(ctx), [])
            self.assertEqual(self.redemptions, 1)

    async def test_websocket_auth_private_message_and_public_control(self):
        raw = {'url': self.base.replace('http:', 'ws:') + '/ws', 'requires_auth': True,
               'protected_contains': 'fixture-private-message'}
        async with SessionManager(self.base, self.profiles()) as manager:
            ctx = self.context(manager, {'websockets': {'endpoints': [raw]}})
            self.assertEqual(await WebSocket_Analyzer().run(ctx), [])
            self.assertEqual(ctx.recon['websocket_results'][0]['state'], 'handshake_requires_credentials')
            self.ws_private_open = True
            self.assertEqual(len(await WebSocket_Analyzer().run(ctx)), 1)
            raw['url'] = self.base.replace('http:', 'ws:') + '/ws-public'
            self.assertEqual(await WebSocket_Analyzer().run(ctx), [])
            raw['url'] = self.base.replace('http:', 'ws:') + '/ws-redirect'
            self.assertEqual(await WebSocket_Analyzer().run(ctx), [])


class SSHParserTests(unittest.TestCase):
    def test_xml_algorithms_keys_and_methods_are_evaluated_independently(self):
        xml = '''<nmaprun><host><ports><port portid="22" protocol="tcp"><state state="open"/>
        <script id="ssh2-enum-algos"><table key="kex_algorithms"><elem>diffie-hellman-group1-sha1</elem></table>
        <table key="compression_algorithms"><elem>none</elem></table></script>
        <script id="ssh-hostkey"><table><elem key="type">ssh-rsa</elem><elem key="bits">1024</elem></table></script>
        <script id="ssh-auth-methods"><table><elem>password</elem><elem>publickey</elem></table></script>
        </port></ports></host></nmaprun>'''
        findings, records = NmapSSHAuditor.parse('fixture', xml)
        self.assertEqual(len(findings), 2)
        self.assertEqual(records[0]['auth_methods'], ['password', 'publickey'])
        modern = xml.replace('diffie-hellman-group1-sha1', 'curve25519-sha256').replace('1024', '3072')
        self.assertEqual(NmapSSHAuditor.parse('fixture', modern)[0], [])


if __name__ == '__main__':
    unittest.main()
