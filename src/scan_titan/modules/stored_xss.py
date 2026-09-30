"""Persist a unique canary, revisit independent routes and validate execution."""
from __future__ import annotations

import asyncio
import re
import uuid
from typing import Any
from urllib.parse import urljoin, urlsplit

from bs4 import BeautifulSoup
from yarl import URL

from .common import Finding, ScanContext, VulnerabilityModule


class StoredXSS_Auditor(VulnerabilityModule):
    name = 'stored_xss'

    async def run(self, ctx: ScanContext) -> list[Finding]:
        from session_manager import RequestSpec

        settings = ctx.policy.stateful.get('stored_xss', {})
        manager = ctx.sessions
        observations: list[dict[str, Any]] = []
        ctx.recon['stored_xss_results'] = observations
        if manager is None or not ctx.policy.allow_state_changing_api_tests:
            observations.append({'state': 'skipped_by_policy'})
            return []
        profile = str(settings.get('profile') or next(iter(manager.authenticated_names()), 'Unauth'))
        if profile not in manager.profiles:
            return []
        seeds = [ctx.target.url, *settings.get('urls', []),
                 *[item.get('url', '') for item in ctx.recon.get('endpoints', []) if isinstance(item, dict)]]
        seeds = list(dict.fromkeys(seeds))[:int(settings.get('max_pages', 20))]
        queue = list(seeds)
        visited: set[str] = set()
        forms_seen: set[tuple[str, str]] = set()
        findings: list[Finding] = []
        submitted = 0
        while queue and len(visited) < int(settings.get('max_pages', 20)) and not ctx.should_stop():
            try:
                url = manager.resolve(queue.pop(0))
            except ValueError:
                continue
            if url in visited:
                continue
            visited.add(url)
            page = await manager.request(profile, RequestSpec(url))
            if page is None or page.status != 200:
                continue
            soup = BeautifulSoup(page.text, 'html.parser')
            queue.extend(urljoin(url, anchor['href']) for anchor in soup.select('a[href]'))
            for form in soup.select('form'):
                if submitted >= int(settings.get('max_forms', 3)) or ctx.should_stop():
                    break
                action = urljoin(url, str(form.get('action') or url))
                method = str(form.get('method', 'GET')).upper()
                if (action, method) in forms_seen or method != 'POST':
                    continue
                if form.select('input[type=password], input[type=file]'):
                    continue
                # Avoid guessing write semantics on account deletion/payment forms.
                if re.search(r'delete|transfer|payment|checkout|logout', action, re.I):
                    continue
                editable = form.select('textarea[name], input[name]:not([type]), input[type=text][name], input[type=search][name]')
                if not editable:
                    continue
                try:
                    manager.resolve(action)
                except ValueError:
                    continue
                forms_seen.add((action, method))
                field = editable[0]['name']
                marker = 'scan_titan_' + uuid.uuid4().hex
                payload = f'<svg onload="alert(\'{marker}\')"></svg>'
                values = {str(item['name']): str(item.get('value', item.text or ''))
                          for item in form.select('input[name], textarea[name]')
                          if item.get('type', '').lower() not in {'submit', 'button', 'file', 'password'}}
                values[field] = payload
                submitted += 1
                response = await manager.request(profile, RequestSpec(action, 'POST', data=values), retry=False)
                if response is None:
                    observations.append({'url': action, 'state': 'submission_failed', 'canary': marker})
                    continue
                revisit = list(dict.fromkeys([url, action, urljoin(action, response.headers.get('Location', '')),
                                             *visited, *queue, *seeds]))
                record: dict[str, Any] = {'submit_url': action, 'field': field, 'canary': marker,
                                          'state': 'no_persistence_observed', 'locations': []}
                observations.append(record)
                # Never count the POST response, URLs carrying the marker, or one cached response as persistence.
                for candidate in revisit[:int(settings.get('max_pages', 20))]:
                    if ctx.should_stop():
                        break
                    try:
                        candidate = manager.resolve(candidate)
                    except ValueError:
                        continue
                    if marker in candidate:
                        continue
                    probe = RequestSpec(candidate, headers={'Cache-Control': 'no-cache', 'Pragma': 'no-cache'})
                    first = await manager.request(profile, probe)
                    second = await manager.request(profile, probe) if first and marker in first.text else None
                    if not (first and second and first.status == second.status == 200
                            and marker in first.text and marker in second.text):
                        continue
                    record['locations'].append(candidate)
                    record['state'] = 'persisted_canary'
                    if payload not in second.text:
                        record['state'] = 'persisted_escaped_or_transformed'
                        continue
                    executed = False
                    if ctx.policy.enable_browser and settings.get('validate_browser', True):
                        executed = await self._browser_proof(ctx, profile, candidate, marker)
                    record['state'] = 'stored_xss_confirmed' if executed else 'persisted_unescaped_candidate'
                    if executed:
                        findings.append(Finding(
                            target=ctx.target.display, category='XSS', severity='High',
                            title='Stored XSS execution after independent reload', url=candidate,
                            method='GET', param=str(field), source=self.name, confidence='high',
                            payload=payload, evidence=f'Canary={marker}; two independent GETs; exact browser dialog matched; submitted={action}',
                            cwe='CWE-79', recommendation='Encode persisted content for its output context and sanitize allowed HTML.'))
                        break
                ctx.heartbeat(self.name, record['state'], submitted, len(findings))
        return findings

    async def _browser_proof(self, ctx: ScanContext, profile: str, url: str, marker: str) -> bool:
        try:
            from playwright.async_api import async_playwright
        except ImportError:
            return False
        manager = ctx.sessions
        dialogs: list[str] = []
        try:
            async with async_playwright() as engine:
                browser = await engine.chromium.launch(headless=True)
                try:
                    context = await browser.new_context(ignore_https_errors=not manager.verify_tls,
                                                        service_workers='block')
                    headers = manager.headers_for(profile)
                    jar = manager.profiles[profile].session.cookie_jar.filter_cookies(URL(url))
                    if jar:
                        headers['Cookie'] = '; '.join(f'{name}={cookie.value}' for name, cookie in jar.items())

                    async def scoped_route(route: Any) -> None:
                        try:
                            manager.resolve(route.request.url)
                        except ValueError:
                            await route.abort()
                            return
                        response = await route.fetch(headers={**route.request.headers, **headers}, max_redirects=0)
                        if 300 <= response.status < 400:
                            await route.abort()
                        else:
                            await route.fulfill(response=response)

                    await context.route('**/*', scoped_route)
                    page = await context.new_page()

                    async def dialog_handler(dialog: Any) -> None:
                        dialogs.append(dialog.message)
                        await dialog.dismiss()

                    page.on('dialog', dialog_handler)
                    await page.goto(url, wait_until='domcontentloaded', timeout=ctx.policy.browser_timeout_seconds * 1000)
                    await page.wait_for_timeout(500)
                    return marker in dialogs
                finally:
                    await browser.close()
        except (Exception, asyncio.TimeoutError):
            return False
