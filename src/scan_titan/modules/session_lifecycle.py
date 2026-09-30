"""Optional final lifecycle checks after other authenticated modules finish."""
from __future__ import annotations

from .common import Finding, ScanContext, VulnerabilityModule


class SessionLifecycleAuditor(VulnerabilityModule):
    name = 'session_lifecycle'

    async def run(self, ctx: ScanContext) -> list[Finding]:
        from session_manager import matches

        manager = ctx.sessions
        records = []
        ctx.recon['session_lifecycle'] = records
        findings = []
        if manager is None or not ctx.policy.allow_state_changing_api_tests:
            return findings
        for name in list(manager.authenticated_names()):
            profile = manager.profiles[name]
            if ctx.should_stop():
                break
            if not profile.config.get('logout'):
                records.append({'profile': name, 'state': 'logout_not_configured'})
                continue
            revoked = await manager.logout(name)
            replay = getattr(profile, 'logout_replay', None)
            retained = profile.logout_succeeded and matches(replay, profile.config['check'])
            records.append({'profile': name, 'state': 'revoked' if revoked else
                            'credential_still_valid' if retained else 'inconclusive'})
            if retained:
                findings.append(Finding(
                    target=ctx.target.display, category='Session', severity='Medium',
                    title='Authenticated credential remains valid after logout',
                    url=manager.resolve(profile.config['check']['url']), source=self.name,
                    confidence='high', cwe='CWE-613',
                    evidence=f'Profile={name}; old credential replay still matches the identity check after configured logout.',
                    recommendation='Invalidate the server-side session and apply the required token revocation policy.'))
        ctx.recon['session_profiles'] = manager.summary()
        return findings
