"""Synchronized business-operation bursts with explicit state invariants."""
from __future__ import annotations

import asyncio
import json
import time
from typing import Any

from .common import Finding, ScanContext, VulnerabilityModule


class RaceCondition_Tester(VulnerabilityModule):
    name = 'race_conditions'

    async def run(self, ctx: ScanContext) -> list[Finding]:
        from session_manager import RequestSpec, json_path, matches

        manager = ctx.sessions
        if manager is None:
            return []
        settings = ctx.policy.stateful.get('race', {})
        cases = settings.get('cases', [])
        # Discovery is useful even when the operation's success invariant is unknown.
        ctx.recon['race_candidates'] = [{'url': item.get('url'), 'method': item.get('method', 'GET')}
                                       for item in ctx.recon.get('endpoints', []) if isinstance(item, dict)
                                       if any(word in str(item).lower() for word in
                                              ('coupon', 'redeem', 'transfer', 'upload', 'checkout'))][:40]
        records: list[dict[str, Any]] = []
        ctx.recon['race_results'] = records
        findings: list[Finding] = []
        if not cases:
            records.append({'state': 'cases_not_configured'})
            return findings
        if not ctx.policy.allow_state_changing_api_tests:
            records.append({'state': 'skipped_by_policy'})
            return findings
        for case in cases[:int(settings.get('max_cases', 3))]:
            if ctx.should_stop():
                break
            profile = str(case.get('profile', 'Unauth'))
            if profile not in manager.profiles or not await manager.ensure_authenticated(profile):
                records.append({'state': 'profile_unavailable', 'profile': profile})
                continue
            if not case.get('success') or not (case.get('success_id_path') or case.get('verify')):
                records.append({'state': 'missing_success_or_state_oracle'})
                continue
            request = RequestSpec.from_dict(case['request'])
            verify = case.get('verify')
            before = None
            if verify:
                baseline = await manager.request(profile, RequestSpec.from_dict(verify))
                try:
                    before = float(json_path(json.loads(baseline.text), verify['value_path']))
                except (AttributeError, ValueError, TypeError, KeyError):
                    records.append({'state': 'state_baseline_unavailable'})
                    continue
            count = max(20, min(64, int(case.get('concurrency', 20))))
            ready = asyncio.Event()
            starts: list[float] = []

            async def worker() -> Any:
                await ready.wait()
                starts.append(time.perf_counter())
                return await manager.request(profile, request, retry=False)

            tasks = [asyncio.create_task(worker()) for _ in range(count)]
            # All workers await the same barrier. No normal payload jitter applies.
            await asyncio.sleep(0)
            ready.set()
            try:
                responses = await asyncio.wait_for(asyncio.gather(*tasks),
                                                  timeout=float(case.get('timeout_seconds', 30)))
            except asyncio.TimeoutError:
                responses = [task.result() if task.done() and not task.cancelled()
                             and task.exception() is None else None for task in tasks]
            finally:
                for task in tasks:
                    if not task.done():
                        task.cancel()
                await asyncio.gather(*tasks, return_exceptions=True)
            successes = [response for response in responses if matches(response, case['success'])]
            ids: set[str] = set()
            for response in successes:
                if case.get('success_id_path'):
                    try:
                        value = json_path(json.loads(response.text), case['success_id_path'])
                        if value is not None:
                            ids.add(json.dumps(value, sort_keys=True))
                    except (ValueError, TypeError):
                        pass
            allowed = max(0, int(case.get('max_successes', 1)))
            delta = None
            if verify and not ctx.should_stop():
                after_response = await manager.request(profile, RequestSpec.from_dict(verify))
                try:
                    after = float(json_path(json.loads(after_response.text), verify['value_path']))
                    delta = after - before
                except (AttributeError, ValueError, TypeError):
                    pass
            violated = len(ids) > allowed
            if delta is not None:
                violated |= delta > float(verify.get('max_delta', allowed))
            record = {'url': manager.resolve(request.url), 'requests': count,
                      'successes': len(successes), 'unique_successes': len(ids),
                      'state_delta': delta, 'dispatch_window_ms': round((max(starts) - min(starts)) * 1000, 3),
                      'state': 'invariant_violated' if violated else 'no_violation_observed',
                      'responses': sum(response is not None for response in responses)}
            if record['responses'] < count and not violated:
                record['state'] = 'incomplete'
            records.append(record)
            if violated:
                findings.append(Finding(
                    target=ctx.target.display, category='Business Logic', severity='High',
                    title='Concurrent operation violated configured success invariant',
                    url=record['url'], method=request.method, source=self.name,
                    confidence='high', cwe='CWE-362', evidence=json.dumps(record),
                    recommendation='Enforce atomic transactions, uniqueness and idempotency server-side.'))
            ctx.heartbeat(self.name, f'burst={count} successes={len(successes)}', len(records), len(findings))
        return findings
