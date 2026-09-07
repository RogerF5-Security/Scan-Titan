from __future__ import annotations

import asyncio
import urllib.parse

from .common import Finding, ScanContext, VulnerabilityModule


class AdvancedLogicModule(VulnerabilityModule):
    name = "advanced_logic"

    LOG_PATHS = ["/logs", "/log", "/debug.log", "/error.log", "/access.log", "/var/log", "/storage/logs/laravel.log"]

    async def run(self, ctx: ScanContext) -> list[Finding]:
        findings: list[Finding] = []
        findings.extend(await self._websockets(ctx))
        findings.extend(await self._race_conditions(ctx))
        findings.extend(await self._logs(ctx))
        return findings

    async def _websockets(self, ctx: ScanContext) -> list[Finding]:
        sockets = ctx.recon.get("websockets", [])
        findings = []
        for idx, ws_url in enumerate(sockets[:10], start=1):
            ctx.heartbeat(self.name, f"websocket {ws_url}", idx, len(findings))
            findings.append(
                Finding(
                    target=ctx.target.display,
                    category="Advanced",
                    severity="Info",
                    title="WebSocket endpoint discovered",
                    url=ws_url,
                    evidence="WebSocket security requires origin/authentication validation.",
                    source=self.name,
                    confidence="medium",
                )
            )
        return findings

    async def _race_conditions(self, ctx: ScanContext) -> list[Finding]:
        candidates = [ctx.target.url]
        for endpoint in ctx.recon.get("endpoints", [])[:10]:
            if endpoint.get("url"):
                candidates.append(endpoint["url"])
        findings = []
        for idx, url in enumerate(list(dict.fromkeys(candidates))[:5], start=1):
            ctx.heartbeat(self.name, f"race {url}", idx, len(findings))
            results = await asyncio.gather(
                *(ctx.http.request("GET", url, params={"scan_titan_race": str(i)}) for i in range(6))
            )
            valid = [r for r in results if r]
            if len(valid) < 4:
                continue
            statuses = {r.status for r in valid}
            sizes = {r.body_len for r in valid}
            if len(statuses) > 2 or (len(sizes) > 3 and max(sizes) - min(sizes) > 500):
                findings.append(
                    Finding(
                        target=ctx.target.display,
                        category="Advanced",
                        severity="Low",
                        title="Race/concurrency response variance",
                        url=url,
                        evidence=f"Statuses={sorted(statuses)} Sizes={sorted(sizes)[:8]}",
                        source=self.name,
                        confidence="low",
                    )
                )
        return findings

    async def _logs(self, ctx: ScanContext) -> list[Finding]:
        findings = []
        for idx, path in enumerate(self.LOG_PATHS, start=1):
            ctx.heartbeat(self.name, f"logs {path}", idx, len(findings))
            url = urllib.parse.urljoin(ctx.target.url, path)
            result = await ctx.http.request("GET", url, allow_redirects=False)
            if not result:
                continue
            body = result.text.lower()
            if result.status == 200 and any(marker in body for marker in ["exception", "traceback", " stack trace", "error", "warning"]):
                findings.append(
                    Finding(
                        target=ctx.target.display,
                        category="Advanced",
                        severity="High",
                        title=f"Exposed log/debug content: {path}",
                        url=url,
                        endpoint=path,
                        status=str(result.status),
                        evidence="Log/debug markers observed in response.",
                        source=self.name,
                        confidence="medium",
                    )
                )
        return findings
