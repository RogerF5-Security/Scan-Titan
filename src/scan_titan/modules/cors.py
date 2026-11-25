from __future__ import annotations

import secrets
import urllib.parse

from .common import Finding, ScanContext, VulnerabilityModule


class CorsModule(VulnerabilityModule):
    """CORS policy checks on the origin page and on discovered API endpoints.

    Credentialed APIs (JSON, /api/, /graphql) are where a permissive policy is
    exploitable, so they are tested too, not only the landing page. A finding
    requires the exact attacker origin (unique per run) reflected back.
    """

    name = "cors"
    MAX_URLS = 15

    def _origins(self) -> list[str]:
        return [f"https://st-cors-{secrets.token_hex(4)}.example", "null"]

    def _urls(self, ctx: ScanContext) -> list[str]:
        origin = urllib.parse.urlsplit(ctx.target.url)
        urls = [ctx.target.url]
        candidates = [item.get("url", "") for item in ctx.recon.get("endpoints", []) if isinstance(item, dict)]
        candidates += [item.get("url", "") for item in (ctx.recon.get("javascript_recon") or {}).get("endpoints", [])
                       if isinstance(item, dict) and item.get("in_scope")]
        for url in candidates:
            parsed = urllib.parse.urlsplit(str(url))
            if (parsed.scheme, parsed.netloc) != (origin.scheme, origin.netloc):
                continue
            path = parsed.path.lower()
            if "/api" in path or "graphql" in path or path.endswith(".json") or "/rest/" in path or "/v1/" in path:
                urls.append(urllib.parse.urlunsplit((parsed.scheme, parsed.netloc, parsed.path, "", "")))
        return list(dict.fromkeys(urls))[: self.MAX_URLS]

    async def run(self, ctx: ScanContext) -> list[Finding]:
        findings: list[Finding] = []
        tested = 0
        for url in self._urls(ctx):
            for origin in self._origins():
                tested += 1
                ctx.heartbeat(self.name, f"Origin={origin} {urllib.parse.urlsplit(url).path}", tested, len(findings))
                result = await ctx.http.request("GET", url, headers={"Origin": origin}, allow_redirects=False)
                if not result:
                    continue
                headers = {str(k).lower(): str(v) for k, v in result.headers.items()}
                acao = headers.get("access-control-allow-origin", "")
                acac = headers.get("access-control-allow-credentials", "").lower() == "true"
                if acao == origin:
                    findings.append(Finding(
                        target=ctx.target.display, category="CORS", severity="High" if acac else "Medium",
                        title="CORS reflects arbitrary origin", url=url,
                        endpoint=urllib.parse.urlsplit(url).path or "/",
                        evidence=(f"Origin={origin} -> Access-Control-Allow-Origin={acao} | "
                                  f"Access-Control-Allow-Credentials={'true' if acac else '-'} | HTTP {result.status}"),
                        source=self.name, confidence="high", evidence_strength="strong", false_positive_risk="low",
                        cwe="CWE-942",
                        impact=("Un sitio de un atacante puede leer respuestas autenticadas del usuario."
                                if acac else "Un sitio externo puede leer las respuestas no autenticadas."),
                    ))
                    break
                if acao == "*" and acac:
                    # Browsers refuse credentialed requests with a wildcard origin,
                    # so this is a misconfiguration rather than an exploitable leak.
                    findings.append(Finding(
                        target=ctx.target.display, category="CORS", severity="Low",
                        title="CORS wildcard with credentials", url=url,
                        endpoint=urllib.parse.urlsplit(url).path or "/",
                        evidence=f"Access-Control-Allow-Origin=* con Access-Control-Allow-Credentials=true | HTTP {result.status}",
                        source=self.name, confidence="high", cwe="CWE-942",
                    ))
                    break
        return findings
