"""Compare WebSocket handshakes and optional protected messages by identity."""
from __future__ import annotations

import asyncio
import json
import re
from typing import Any

import aiohttp

from .common import Finding, ScanContext, VulnerabilityModule


class WebSocket_Analyzer(VulnerabilityModule):
    name = 'websocket_analyzer'

    async def run(self, ctx: ScanContext) -> list[Finding]:
        from session_manager import RequestSpec

        manager = ctx.sessions
        if manager is None:
            return []
        config = ctx.policy.stateful.get('websockets', {})
        candidates: dict[str, dict[str, Any]] = {}
        for item in [*ctx.recon.get('websockets', []), *config.get('endpoints', [])]:
            raw = item if isinstance(item, dict) else {'url': str(item)}
            if raw.get('url'):
                candidates[str(raw['url'])] = raw
        page = await manager.request('Unauth', RequestSpec(ctx.target.url))
        if page:
            for url in re.findall(r'wss?://[^\s\"\x27<>]+', page.text):
                candidates.setdefault(url, {'url': url})
        records = []
        ctx.recon['websocket_results'] = records
        findings = []
        for raw in list(candidates.values())[:int(config.get('max_endpoints', 10))]:
            if ctx.should_stop():
                break
            try:
                url = manager.resolve(str(raw['url']))
            except ValueError:
                continue
            if not url.startswith(('ws://', 'wss://')):
                continue
            observations = []
            for name in ['Unauth', *manager.authenticated_names()]:
                if not await manager.ensure_authenticated(name):
                    continue
                observations.append(await self._probe(manager, name, url, raw))
            anonymous = next((item for item in observations if item['profile'] == 'Unauth'), {})
            authorized = [item for item in observations if item['profile'] != 'Unauth' and item['connected']]
            protected = bool(anonymous.get('protected_message'))
            state = ('anonymous_handshake_accepted' if anonymous.get('connected') else
                     'handshake_requires_credentials' if authorized and anonymous.get('status') in {401, 403}
                     else 'inconclusive')
            records.append({'url': url, 'state': state, 'profiles': observations})
            # Public WebSockets commonly allow anonymous upgrades. Report only a
            # configured protected endpoint with the expected private message proof.
            if raw.get('requires_auth') and anonymous.get('connected') and authorized and protected:
                findings.append(Finding(
                    target=ctx.target.display, category='WebSocket', severity='High',
                    title='Protected WebSocket message accessible without credentials',
                    url=url, source=self.name, confidence='high', cwe='CWE-306',
                    evidence='Anonymous upgrade and configured protected-message marker matched; authenticated control connected.',
                    recommendation='Authenticate the handshake and authorize every message and subscription.'))
            ctx.heartbeat(self.name, state, len(records), len(findings))
        return findings

    async def _probe(self, manager: Any, name: str, url: str, raw: dict[str, Any]) -> dict[str, Any]:
        profile = manager.profiles[name]
        record = {'profile': name, 'connected': False, 'status': 0, 'protected_message': False}
        try:
            async with asyncio.timeout(float(raw.get('timeout_seconds', 8))):
                # SessionManager's redirect trace rejects redirects before a second
                # handshake can forward any profile credentials to another origin.
                async with profile.session.ws_connect(
                    url, headers=manager.headers_for(name),
                    origin=str(raw.get('origin') or manager.base_url.split('/', 3)[0] + '//' + manager.base_url.split('/')[2]),
                    ssl=None if manager.verify_tls else False, max_msg_size=65536,
                ) as websocket:
                    record['connected'] = True
                    record['status'] = 101
                    if 'probe' in raw:
                        payload = raw['probe']
                        await websocket.send_str(payload if isinstance(payload, str) else json.dumps(payload))
                    if raw.get('protected_contains'):
                        message = await websocket.receive(timeout=2)
                        record['protected_message'] = bool(
                            message.type == aiohttp.WSMsgType.TEXT
                            and str(raw['protected_contains']) in str(message.data))
        except aiohttp.WSServerHandshakeError as exc:
            record['status'] = exc.status
        except (aiohttp.ClientError, asyncio.TimeoutError, OSError, ValueError):
            pass
        return record
