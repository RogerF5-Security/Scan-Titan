from __future__ import annotations

import asyncio
import urllib.parse

from .common import Finding, ScanContext, VulnerabilityModule, run_bounded, url_with_params
from .payload_utils import xss_payloads


class XssModule(VulnerabilityModule):
    name = "xss"

    DEFAULT_PARAMS = [
        "q",
        "search",
        "query",
        "keyword",
        "name",
        "msg",
        "message",
        "text",
        "comment",
        "title",
        "redirect",
        "next",
    ]

    DEFAULT_PAYLOADS = [
        "titan-xss\"><svg/onload=alert(1)>",
        "\"><img src=x onerror=alert(1)>",
        "'><details open ontoggle=alert(1)>",
        "<ScRiPt>alert(1)</ScRiPt>",
        "\"><svg><animate onbegin=alert(1) attributeName=x>",
    ]

    async def run(self, ctx: ScanContext) -> list[Finding]:
        budget = max(ctx.limits.max_tests_per_module, 40)
        payloads = xss_payloads(ctx.wordlists, self.DEFAULT_PAYLOADS, limit=budget)
        candidates = self._candidate_urls(ctx)
        findings: list[Finding] = []
        tested = 0
        local_lock = asyncio.Lock()

        async def probe(url: str, param: str, payload: str) -> None:
            nonlocal tested
            result = await ctx.http.request("GET", url, params={param: payload})
            async with local_lock:
                tested += 1
                if tested == 1 or tested % 20 == 0 or tested == len(specs):
                    ctx.heartbeat(self.name, f"{param}={payload[:28]}", tested, len(findings))
            if not result:
                return
            content_type = result.content_type.lower()
            if "html" not in content_type and "text" not in content_type:
                return
            escaped = payload.replace("<", "&lt;").replace(">", "&gt;")
            if payload in result.text and escaped not in result.text:
                findings.append(
                    Finding(
                        target=ctx.target.display,
                        category="XSS",
                        severity="High",
                        title=f"Reflected XSS candidate: {param}",
                        url=url_with_params(url, {param: payload}),
                        endpoint=urllib.parse.urlparse(url).path or "/",
                        param=param,
                        method="GET",
                        payload=payload,
                        status=str(result.status),
                        size=f"{result.body_len}b",
                        elapsed=f"{result.elapsed:.2f}s",
                        evidence="Payload reflected without HTML escaping.",
                        source=self.name,
                        confidence="high",
                    )
                )

        specs = []
        for url, params in candidates:
            for param in params[:10]:
                for payload in payloads:
                    if len(specs) >= ctx.limits.max_tests_per_module:
                        break
                    specs.append((url, param, payload))

        async def run_probe(spec: tuple[str, str, str]) -> None:
            await probe(*spec)

        await run_bounded(specs, run_probe, should_stop=ctx.should_stop)
        return findings

    def _candidate_urls(self, ctx: ScanContext) -> list[tuple[str, list[str]]]:
        candidates = [(ctx.target.url, self.DEFAULT_PARAMS)]
        for endpoint in ctx.recon.get("endpoints", [])[:40]:
            url = endpoint.get("url")
            params = endpoint.get("params") or []
            if url:
                candidates.append((url, params or self.DEFAULT_PARAMS[:6]))
        seen = set()
        unique = []
        for url, params in candidates:
            key = (url, ",".join(sorted(params)))
            if key in seen:
                continue
            seen.add(key)
            unique.append((url, params))
        return unique
