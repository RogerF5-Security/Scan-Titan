"""Replay identical requests under isolated identities and explicit access rules."""
from __future__ import annotations

import hashlib
import json
from difflib import SequenceMatcher
from typing import Any

from .common import Finding, ScanContext, VulnerabilityModule


class RoleAuditor(VulnerabilityModule):
    name = 'role_audit'

    async def run(self, ctx: ScanContext) -> list[Finding]:
        from session_manager import RequestSpec, json_path

        manager = ctx.sessions
        if manager is None:
            return []
        config = ctx.policy.stateful.get('roles', {})
        configured = config.get('requests', [])
        discovered = [item for item in ctx.recon.get('endpoints', []) if isinstance(item, dict)]
        requests = [*configured, *discovered][:int(config.get('max_requests', 40))]
        identities = ['Unauth', *manager.authenticated_names()]
        records: list[dict[str, Any]] = []
        findings: list[Finding] = []
        seen: set[tuple[str, str, str]] = set()
        for raw in requests:
            if ctx.should_stop():
                break
            if not raw.get('url'):
                continue
            try:
                spec = RequestSpec.from_dict(raw)
                spec.url = manager.resolve(spec.url)
            except (ValueError, KeyError):
                continue
            if spec.method not in {'GET', 'HEAD'} and not (
                raw.get('replay_state_changing') and ctx.policy.allow_state_changing_api_tests
            ):
                continue
            key = spec.method, spec.url, json.dumps([spec.params, spec.data, spec.json_body], sort_keys=True)
            if key in seen:
                continue
            seen.add(key)
            # Each identity gets the exact URL, parameters and body; no guessed IDs.
            results = {name: await manager.request(name, spec) for name in identities}
            allowed = raw.get('allowed_profiles', [])
            references = [(name, result) for name, result in results.items()
                          if name in allowed and result and 200 <= result.status < 300]
            for name, response in results.items():
                if response is None:
                    records.append({'url': spec.url, 'profile': name, 'state': 'unavailable'})
                    continue
                record: dict[str, Any] = {
                    'url': spec.url, 'method': spec.method, 'profile': name,
                    'status': response.status, 'length': response.body_len,
                    'sha256': hashlib.sha256(response.text.encode()).hexdigest(),
                    'state': 'comparison_only' if not allowed else 'evaluated',
                }
                for owner, reference in references:
                    if name in allowed or not 200 <= response.status < 300:
                        continue
                    similarity = SequenceMatcher(None, reference.text[:8192], response.text[:8192]).ratio()
                    record['reference_profile'] = owner
                    record['similarity'] = round(similarity, 4)
                    record['length_delta'] = response.body_len - reference.body_len
                    protected = False
                    for path in raw.get('sensitive_json_paths', []):
                        try:
                            before = json_path(json.loads(reference.text), path)
                            after = json_path(json.loads(response.text), path)
                            protected |= before not in (None, '', False) and after == before
                        except (ValueError, TypeError):
                            pass
                    for marker in raw.get('sensitive_contains', []):
                        protected |= bool(marker and marker in reference.text and marker in response.text)
                    # Body length/status differences alone do not prove an IDOR.
                    if protected:
                        findings.append(Finding(
                            target=ctx.target.display, category='Authorization', severity='High',
                            title=f'Protected resource accessible to disallowed profile: {name}',
                            url=spec.url, method=spec.method, source=self.name, confidence='high',
                            evidence=(f'Allowed={owner}; disallowed={name}; protected content matched; '
                                      f'status={response.status}; similarity={similarity:.4f}; '
                                      f'lengths={reference.body_len}/{response.body_len}'),
                            cwe='CWE-639', recommendation='Enforce object ownership and role authorization server-side.'))
                        record['state'] = 'access_violation'
                        break
                records.append(record)
            ctx.heartbeat(self.name, f'{spec.method} role comparison', len(seen), len(findings))
        ctx.recon['role_audit'] = records
        ctx.recon['session_profiles'] = manager.summary()
        return findings
