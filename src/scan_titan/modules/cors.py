from __future__ import annotations

from .common import Finding, ScanContext, VulnerabilityModule


class CorsModule(VulnerabilityModule):
    name = "cors"

    ORIGINS = [
        "https://example.com",
        "https://attacker.invalid",
        "null",
    ]

    async def run(self, ctx: ScanContext) -> list[Finding]:
        findings: list[Finding] = []
        for index, origin in enumerate(self.ORIGINS, start=1):
            ctx.heartbeat(self.name, f"Origin={origin}", index, len(findings))
            result = await ctx.http.request(
                "GET",
                ctx.target.url,
                headers={"Origin": origin},
                allow_redirects=False,
            )
            if not result:
                continue
            acao = result.headers.get("Access-Control-Allow-Origin", "")
            acac = result.headers.get("Access-Control-Allow-Credentials", "")
            if acao == "*" and acac.lower() == "true":
                findings.append(
                    Finding(
                        target=ctx.target.display,
                        category="CORS",
                        severity="High",
                        title="CORS wildcard with credentials",
                        url=ctx.target.url,
                        evidence=f"ACAO={acao} | ACAC={acac} | Origin={origin}",
                        source=self.name,
                        confidence="high",
                    )
                )
            elif acao == origin and not origin.endswith(ctx.target.host):
                severity = "High" if acac.lower() == "true" else "Medium"
                findings.append(
                    Finding(
                        target=ctx.target.display,
                        category="CORS",
                        severity=severity,
                        title="CORS reflects arbitrary origin",
                        url=ctx.target.url,
                        evidence=f"ACAO={acao} | ACAC={acac or '-'} | Origin={origin}",
                        source=self.name,
                        confidence="high",
                    )
                )
        return findings
