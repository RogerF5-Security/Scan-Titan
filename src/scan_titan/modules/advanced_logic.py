from __future__ import annotations

import asyncio
import re
import urllib.parse

from .common import Finding, ScanContext, VulnerabilityModule
from .soft_not_found import SoftNotFoundOracle

# Line shapes of real log files. Generic words such as "error" or "warning"
# appear in almost any HTML page (SPA bundles, login forms, framework 404s),
# so they are never accepted as proof on their own.
LOG_LINE_PATTERNS = (
    # Apache/Nginx combined access log
    re.compile(r'^\S+ \S+ \S+ \[\d{2}/\w{3}/\d{4}:\d{2}:\d{2}:\d{2} [+-]\d{4}\] "(?:GET|POST|HEAD|PUT|DELETE|OPTIONS|PATCH) ', re.M),
    # Laravel / Monolog
    re.compile(r'^\[\d{4}-\d{2}-\d{2}[ T]\d{2}:\d{2}:\d{2}[^\]]*\] \w+\.(?:ERROR|WARNING|INFO|DEBUG|CRITICAL|NOTICE)', re.M),
    # Apache error log
    re.compile(r'^\[\w{3} \w{3} \d{1,2} \d{2}:\d{2}:\d{2}(?:\.\d+)? \d{4}\] \[[\w:]+\]', re.M),
    # Generic ISO timestamp + level (log4j, logback, Python logging)
    re.compile(r'^\d{4}-\d{2}-\d{2}[ T]\d{2}:\d{2}:\d{2}(?:[.,]\d+)?\s*(?:\[[^\]]*\]\s*)?(?:ERROR|WARN(?:ING)?|INFO|DEBUG|FATAL|CRITICAL|TRACE)\b', re.M),
    # Nginx error log
    re.compile(r'^\d{4}/\d{2}/\d{2} \d{2}:\d{2}:\d{2} \[(?:error|warn|notice|crit|alert|emerg)\]', re.M),
)
TRACEBACK = re.compile(r'Traceback \(most recent call last\):\s*\n\s+File "', re.M)
LOG_LISTING = re.compile(r'href="[^"]+\.log(?:\.\d+)?(?:\.gz)?"', re.I)


class AdvancedLogicModule(VulnerabilityModule):
    name = "advanced_logic"

    LOG_PATHS = ["/logs", "/log", "/debug.log", "/error.log", "/access.log", "/var/log", "/storage/logs/laravel.log"]

    async def run(self, ctx: ScanContext) -> list[Finding]:
        findings: list[Finding] = []
        if ctx.sessions is None:
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
        oracle = SoftNotFoundOracle.for_context(ctx)
        for idx, path in enumerate(self.LOG_PATHS, start=1):
            ctx.heartbeat(self.name, f"logs {path}", idx, len(findings))
            url = urllib.parse.urljoin(ctx.target.url, path)
            result = await ctx.http.request("GET", url, allow_redirects=False)
            if not result or result.status != 200:
                continue
            proof = self.log_proof(result.text, getattr(result, "content_type", ""))
            if not proof:
                continue
            # A framework debug page served for every unknown path also carries
            # tracebacks; it must not be reported once per guessed log path.
            if await oracle.verdict(url, result, path):
                continue
            findings.append(
                Finding(
                    target=ctx.target.display,
                    category="Advanced",
                    severity="Medium" if proof["kind"] == "directory_listing" else "High",
                    title=f"Exposed log/debug content: {path}",
                    url=url,
                    endpoint=path,
                    status=str(result.status),
                    evidence=(f"{proof['detail']} | Content-Type={getattr(result, 'content_type', '') or '-'} | "
                              f"Muestra: {proof['sample']}"),
                    source=self.name,
                    confidence="high",
                    evidence_strength="strong",
                    false_positive_risk="low",
                )
            )
        return findings

    @staticmethod
    def log_proof(body: str, content_type: str = "") -> dict[str, str]:
        """Return proof that ``body`` is a log file or a log directory listing, else {}."""
        text = str(body or "")[:200000]
        head = text[:800].lower()
        if "index of /" in head and LOG_LISTING.search(text):
            return {"kind": "directory_listing", "detail": "Listado de directorio con archivos .log",
                    "sample": re.sub(r"\s+", " ", text[:160])}
        match = TRACEBACK.search(text)
        if match:
            return {"kind": "traceback", "detail": "Traceback de Python completo en la respuesta",
                    "sample": re.sub(r"\s+", " ", text[match.start():match.start() + 160])}
        if "html" in str(content_type or "").lower() or "<html" in head or "<!doctype" in head:
            return {}
        for pattern in LOG_LINE_PATTERNS:
            lines = pattern.findall(text)
            if len(lines) >= 3:
                first = pattern.search(text)
                end = text.find("\n", first.start())
                sample = text[first.start():end if end > 0 else first.start() + 160]
                return {"kind": "log_lines", "detail": f"{len(lines)} lineas con formato de log",
                        "sample": sample[:160]}
        return {}
