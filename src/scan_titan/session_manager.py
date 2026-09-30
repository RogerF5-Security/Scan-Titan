"""Isolated, origin-bound authenticated HTTP sessions for stateful auditors."""
from __future__ import annotations

import asyncio
import json
import os
import re
import time
from dataclasses import dataclass, field
from typing import Any
from urllib.parse import urljoin, urlsplit

import aiohttp
from bs4 import BeautifulSoup
from yarl import URL

from modules.common import HttpResult


def json_path(value: Any, path: str) -> Any:
    """Read a dotted path without executing expressions."""
    for part in path.split('.') if path else []:
        if isinstance(value, dict):
            value = value.get(part)
        elif isinstance(value, list) and part.isdigit() and int(part) < len(value):
            value = value[int(part)]
        else:
            return None
    return value


def expand_env(value: Any) -> Any:
    if isinstance(value, dict):
        return {key: expand_env(item) for key, item in value.items()}
    if isinstance(value, list):
        return [expand_env(item) for item in value]
    if isinstance(value, str):
        def replace(match: re.Match[str]) -> str:
            key = match.group(1)
            if key not in os.environ:
                raise ValueError(f"Missing environment variable: {key}")
            return os.environ[key]
        return re.sub(r"\$\{([A-Za-z_][A-Za-z_0-9]*)\}", replace, value)
    return value


def matches(result: HttpResult | None, rule: dict[str, Any]) -> bool:
    """Explicit response predicate; HTTP 200 alone is never an identity proof."""
    if result is None or result.status not in rule.get('statuses', [200]):
        return False
    if rule.get('contains') and str(rule['contains']) not in result.text:
        return False
    if rule.get('json_path'):
        try:
            actual = json_path(json.loads(result.text), str(rule['json_path']))
        except (ValueError, TypeError):
            return False
        if 'equals' in rule:
            return actual == rule['equals']
        return actual is not None and actual is not False
    return bool(rule.get('contains') or rule.get('statuses'))


@dataclass
class RequestSpec:
    url: str
    method: str = 'GET'
    params: dict[str, Any] | None = None
    data: Any = None
    json_body: Any = None
    headers: dict[str, str] = field(default_factory=dict)
    files: dict[str, dict[str, str]] = field(default_factory=dict)

    @classmethod
    def from_dict(cls, raw: dict[str, Any]) -> 'RequestSpec':
        return cls(str(raw['url']), str(raw.get('method', 'GET')).upper(),
                   raw.get('params'), raw.get('data'), raw.get('json'),
                   dict(raw.get('headers') or {}), dict(raw.get('files') or {}))


@dataclass
class ProfileState:
    name: str
    config: dict[str, Any]
    session: aiohttp.ClientSession
    headers: dict[str, str] = field(default_factory=dict)
    token: str = field(default='', repr=False)
    state: str = 'not_authenticated'
    expires_at: float = 0.0
    generation: int = 0
    reason: str = ''
    logout_replay: HttpResult | None = field(default=None, repr=False)
    logout_succeeded: bool = False
    lock: asyncio.Lock = field(default_factory=asyncio.Lock)


class SessionManager:
    """One cookie jar per identity; Unauth never stores cookies or tokens.

    Login/refresh steps support form CSRF and JSON token extraction. Authentication
    is established only by an explicit identity check. Refresh is single-flight;
    only GET/HEAD are retried after a 401, never a submitted business operation.
    """

    def __init__(self, base_url: str, profiles: list[dict[str, Any]], *,
                 timeout: float = 10, verify_tls: bool = False,
                 control: Any = None, max_body_bytes: int = 600_000) -> None:
        self.base_url = base_url
        self.origin = self._origin(base_url)
        self.configs = profiles
        self.timeout = timeout
        self.verify_tls = verify_tls
        self.control = control
        self.max_body_bytes = max_body_bytes
        self.profiles: dict[str, ProfileState] = {}
        self.identity_headers = {'authorization', 'cookie', 'host', 'proxy-authorization'}
        self.identity_headers.update(str(item.get('token', {}).get('header', 'Authorization')).lower()
                                     for item in profiles)

    @staticmethod
    def _origin(url: str) -> tuple[str, str, int]:
        parsed = urlsplit(url)
        scheme = {'ws': 'http', 'wss': 'https'}.get(parsed.scheme, parsed.scheme)
        return scheme, (parsed.hostname or '').lower(), parsed.port or (443 if scheme == 'https' else 80)

    def resolve(self, url: str) -> str:
        resolved = urljoin(self.base_url, url)
        parsed = urlsplit(resolved)
        if (parsed.username or parsed.password or parsed.scheme not in {'http', 'https', 'ws', 'wss'}
                or self._origin(resolved) != self.origin):
            raise ValueError('Session request outside the configured target origin')
        return resolved

    async def __aenter__(self) -> 'SessionManager':
        try:
            configs = [{'name': 'Unauth', 'anonymous': True}, *self.configs]
            for raw in configs:
                name = str(raw.get('name', '')).strip()
                if not name or name in self.profiles:
                    if name == 'Unauth' and raw is not configs[0]:
                        continue
                    raise ValueError('Each authentication profile needs a unique name')
                missing_environment = False
                try:
                    config = expand_env(raw)
                except ValueError:
                    config = {'name': name, '_missing_environment': True}
                    missing_environment = True
                if config.get('origins') and self._origin(self.base_url) not in {
                    self._origin(item) for item in config['origins']
                }:
                    continue
                anonymous = bool(config.get('anonymous'))
                jar = aiohttp.DummyCookieJar() if anonymous else aiohttp.CookieJar(unsafe=True)
                trace = aiohttp.TraceConfig()

                async def reject_redirect(*args: Any) -> None:
                    raise ValueError('Redirects are disabled for identity-bound requests')

                trace.on_request_redirect.append(reject_redirect)
                session = aiohttp.ClientSession(
                    cookie_jar=jar, connector=aiohttp.TCPConnector(limit=64, limit_per_host=64),
                    timeout=aiohttp.ClientTimeout(total=self.timeout), trust_env=False,
                    trace_configs=[trace])
                headers = {} if anonymous else {str(k): str(v) for k, v in config.get('headers', {}).items()}
                state = ProfileState(name, config, session, headers)
                self.profiles[name] = state
                if missing_environment:
                    state.state = 'failed'
                    state.reason = 'Required credential environment variable missing'
                if anonymous:
                    state.state = 'anonymous'
                else:
                    state.token = str(config.get('bearer_token', ''))
                    if config.get('cookies'):
                        jar.update_cookies(config['cookies'], response_url=URL(self.base_url))
            for name, profile in self.profiles.items():
                if not profile.config.get('anonymous'):
                    await self.ensure_authenticated(name)
            return self
        except BaseException:
            await self.close()
            raise

    async def __aexit__(self, *exc: Any) -> None:
        await self.close()

    async def close(self) -> None:
        await asyncio.gather(*(p.session.close() for p in self.profiles.values()))

    def summary(self) -> list[dict[str, str]]:
        return [{'name': p.name, 'state': p.state, 'reason': p.reason} for p in self.profiles.values()]

    def authenticated_names(self) -> list[str]:
        return [p.name for p in self.profiles.values() if p.state == 'authenticated']

    def headers_for(self, name: str) -> dict[str, str]:
        profile = self.profiles[name]
        if profile.config.get('anonymous'):
            return {}
        headers = dict(profile.headers)
        if profile.token:
            token_cfg = profile.config.get('token', {})
            headers[str(token_cfg.get('header', 'Authorization'))] = (
                str(token_cfg.get('prefix', 'Bearer ')) + profile.token)
        return headers

    async def ensure_authenticated(self, name: str, *, force: bool = False) -> bool:
        profile = self.profiles[name]
        if profile.config.get('anonymous'):
            return True
        if profile.config.get('_missing_environment'):
            return False
        async with profile.lock:
            if profile.state in {'failed', 'mfa_required', 'logged_out'} and not force:
                return False
            if profile.state == 'authenticated' and not force and time.monotonic() < profile.expires_at:
                return True
            try:
                config = profile.config
                previous = profile.state == 'authenticated'
                profile.state = 'authenticating'
                steps = config.get('refresh_steps') if previous else None
                steps = steps or config.get('login_steps') or ([config['login']] if config.get('login') else [])
                for step in steps:
                    spec = RequestSpec.from_dict(step)
                    if step.get('csrf'):
                        csrf = step['csrf']
                        page = await self._send(profile, RequestSpec(str(csrf.get('url', spec.url))))
                        soup = BeautifulSoup(page.text if page else '', 'html.parser')
                        field = soup.select_one(str(csrf.get('selector', 'input[name=csrfmiddlewaretoken]')))
                        if field is None or not field.get('value'):
                            raise ValueError('CSRF extraction failed')
                        value = str(field['value'])
                        if csrf.get('header'):
                            spec.headers[str(csrf['header'])] = value
                        else:
                            spec.data = {**(spec.data or {}), str(csrf.get('field', field.get('name'))): value}
                    result = await self._send(profile, spec)
                    if result is None:
                        raise ValueError('Login request failed')
                    if config.get('mfa_challenge') and matches(result, config['mfa_challenge']):
                        profile.state = 'mfa_required'
                        profile.reason = 'Configured MFA challenge observed; identity not established'
                        return False
                    if step.get('expect') and not matches(result, step['expect']):
                        raise ValueError('Login step predicate failed')
                    token_cfg = step.get('token', config.get('token', {}))
                    token = None
                    if token_cfg.get('json_path'):
                        token = json_path(json.loads(result.text), token_cfg['json_path'])
                    elif token_cfg.get('response_header'):
                        token = next((v for k, v in result.headers.items()
                                      if k.lower() == token_cfg['response_header'].lower()), None)
                    if token:
                        profile.token = str(token)
                check = config.get('check')
                if not check or not (check.get('contains') or check.get('json_path')):
                    raise ValueError('An identity check with contains/json_path is required')
                result = await self._send(profile, RequestSpec.from_dict(check))
                if not matches(result, check):
                    raise ValueError('Authenticated identity check failed')
                profile.state = 'authenticated'
                profile.generation += 1
                profile.reason = ''
                profile.expires_at = time.monotonic() + max(1, float(config.get('refresh_after_seconds', 300)))
                return True
            except (ValueError, KeyError, TypeError, aiohttp.ClientError, OSError, asyncio.TimeoutError):
                profile.state = 'failed'
                profile.reason = 'Authentication failed or profile configuration incomplete'
                return False

    async def request(self, name: str, spec: RequestSpec, *, retry: bool = True) -> HttpResult | None:
        self.resolve(spec.url)
        if name not in self.profiles or not await self.ensure_authenticated(name):
            return None
        profile = self.profiles[name]
        generation = profile.generation
        result = await self._send(profile, spec)
        if (retry and result and result.status == 401 and spec.method.upper() in {'GET', 'HEAD'}
                and not profile.config.get('anonymous')):
            # Another concurrent request may already have refreshed this session.
            if profile.generation == generation:
                profile.expires_at = 0
            if await self.ensure_authenticated(name):
                result = await self._send(profile, spec)
        return result

    async def logout(self, name: str) -> bool:
        """Execute a configured logout and test server-side revocation before clearing credentials."""
        profile = self.profiles[name]
        step = profile.config.get('logout')
        if not step or profile.state != 'authenticated':
            return False
        async with profile.lock:
            old_cookies = list(profile.session.cookie_jar)
            result = await self._send(profile, RequestSpec.from_dict(step))
            profile.logout_succeeded = matches(result, step.get('expect', {'statuses': [200, 204, 302, 303]}))
            profile.session.cookie_jar.clear()
            for cookie in old_cookies:
                profile.session.cookie_jar.update_cookies({cookie.key: cookie.value}, response_url=URL(self.base_url))
            probe = await self._send(profile, RequestSpec.from_dict(profile.config['check']))
            profile.logout_replay = probe
            revoked = profile.logout_succeeded and probe is not None and probe.status in {401, 403}
            profile.session.cookie_jar.clear()
            profile.token = ''
            profile.headers.clear()
            profile.state = 'logged_out'
            profile.reason = 'Server revocation observed' if revoked else 'Server revocation unconfirmed'
            return revoked

    async def _send(self, profile: ProfileState, spec: RequestSpec) -> HttpResult | None:
        if self.control:
            await self.control.wait_if_paused()
            if self.control.finish_requested:
                return None
        url = self.resolve(spec.url)
        headers = self.headers_for(profile.name)
        # Replay data cannot override the identity currently under test.
        protected = self.identity_headers
        headers.update({k: v for k, v in spec.headers.items() if k.lower() not in protected})
        started = time.monotonic()
        try:
            data = spec.data
            if spec.files:
                data = aiohttp.FormData()
                for key, value in (spec.data or {}).items():
                    data.add_field(str(key), str(value))
                for key, file in spec.files.items():
                    data.add_field(key, file.get('content', '').encode(),
                                   filename=file.get('filename', 'scan_titan_probe.txt'),
                                   content_type=file.get('content_type', 'text/plain'))
            async with profile.session.request(
                spec.method.upper(), url, params=spec.params, data=data, json=spec.json_body,
                headers=headers, allow_redirects=False, ssl=None if self.verify_tls else False,
            ) as response:
                body = await response.content.read(self.max_body_bytes)
                raw_headers = {k: response.headers.getall(k) for k in response.headers}
                return HttpResult(url, str(response.url), response.status, dict(response.headers),
                                  body.decode(response.charset or 'utf-8', errors='replace'), len(body),
                                  time.monotonic() - started, response.headers.get('Content-Type', ''),
                                  raw_headers, spec.method.upper(), str(response.url), {})
        except (aiohttp.ClientError, asyncio.TimeoutError, OSError):
            return None
