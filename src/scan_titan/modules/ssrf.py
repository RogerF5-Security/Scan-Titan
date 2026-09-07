from __future__ import annotations

import asyncio
import urllib.parse

from .common import Finding, ScanContext, VulnerabilityModule, clean_text, url_with_params


def ssrf_response_proven(
    result: object,
    payload: str,
    proof_markers: tuple[str, ...],
    baseline: object | None = None,
) -> tuple[bool, str]:
    """Accept only concrete internal-service output, never a reflected URL/payload."""
    if result is None or int(getattr(result, "status", 0) or 0) != 200 or not proof_markers:
        return False, ""
    body = str(getattr(result, "text", "") or "")[:12000]
    lower = body.lower()
    reflected_values = {
        str(payload or "").lower(),
        urllib.parse.quote(str(payload or ""), safe="").lower(),
        urllib.parse.quote_plus(str(payload or "")).lower(),
    }
    scrubbed = lower
    for reflected in reflected_values:
        if reflected:
            scrubbed = scrubbed.replace(reflected, "")
    baseline_text = str(getattr(baseline, "text", "") or "").lower()
    marker = next(
        (
            item
            for item in proof_markers
            if item.lower() in scrubbed and item.lower() not in baseline_text
        ),
        "",
    )
    return bool(marker), marker


class SsrfModule(VulnerabilityModule):
    name = "ssrf"

    PARAMS = [
        "url",
        "src",
        "source",
        "dest",
        "destination",
        "target",
        "href",
        "link",
        "path",
        "redirect",
        "load",
        "fetch",
        "proxy",
        "image",
        "img",
        "callback",
        "api",
        "endpoint",
        "host",
        "server",
        "uri",
        "resource",
    ]

    SAFE_PAYLOADS = [
        ("http://127.0.0.1:9/scan-titan", ()),
        ("http://localhost:9/scan-titan", ()),
        ("http://[::1]:9/scan-titan", ()),
    ]

    CLOUD_PAYLOADS = [
        (
            "http://169.254.169.254/latest/meta-data/",
            ("ami-id", "instance-id", "iam/security-credentials", "local-hostname", "public-keys"),
        ),
        (
            "http://metadata.google.internal/computeMetadata/v1/",
            ("service-accounts/", "project-id", "numeric-project-id", "instance/"),
        ),
        (
            "http://169.254.169.254/metadata/instance?api-version=2021-02-01",
            ("azEnvironment", "subscriptionId", "resourceGroupName", "vmId"),
        ),
    ]

    async def run(self, ctx: ScanContext) -> list[Finding]:
        payloads = list(self.SAFE_PAYLOADS)
        if ctx.limits.allow_cloud_ssrf:
            payloads.extend(self.CLOUD_PAYLOADS)
        targets = self._candidate_params(ctx)
        if not targets:
            deferred = set(ctx.recon.get("policy_deferred_tests", []))
            deferred.add("ssrf_no_observed_candidate_parameter")
            ctx.recon["policy_deferred_tests"] = sorted(deferred)
            return []
        findings: list[Finding] = []
        tested = 0
        lock = asyncio.Lock()
        baselines: dict[tuple[str, str], object | None] = {}
        for url, param in targets:
            baselines[(url, param)] = await ctx.http.request(
                "GET",
                url,
                params={param: "scan_titan_control"},
                allow_redirects=True,
                timeout=max(ctx.limits.timeout, 8),
            )

        async def probe(
            url: str,
            param: str,
            payload: str,
            proof_markers: tuple[str, ...],
            baseline: object | None,
        ) -> None:
            nonlocal tested
            async with lock:
                tested += 1
                if tested == 1 or tested % 20 == 0:
                    ctx.heartbeat(self.name, f"{param}->{payload[:34]}", tested, len(findings))
            result = await ctx.http.request(
                "GET",
                url,
                params={param: payload},
                allow_redirects=True,
                timeout=max(ctx.limits.timeout, 8),
            )
            if not result:
                return
            proven, marker = ssrf_response_proven(result, payload, proof_markers, baseline)
            if not proven:
                return
            findings.append(
                Finding(
                    target=ctx.target.display,
                    category="SSRF",
                    severity="Critical",
                    title=f"Confirmed SSRF internal metadata response: {param}",
                    url=url_with_params(url, {param: payload}),
                    endpoint=urllib.parse.urlparse(url).path or "/",
                    param=param,
                    method="GET",
                    payload=payload,
                    status=str(result.status),
                    size=f"{result.body_len}b",
                    elapsed=f"{result.elapsed:.2f}s",
                    evidence=clean_text(
                        f"Internal metadata marker observed after reflection stripping: {marker} | {result.text}",
                        600,
                    ),
                    source=self.name,
                    confidence="high",
                    evidence_strength="strong",
                    false_positive_risk="low",
                )
            )

        tasks = []
        for url, param in targets:
            for payload, proof_markers in payloads:
                if len(tasks) >= ctx.limits.max_tests_per_module:
                    break
                tasks.append(probe(url, param, payload, tuple(proof_markers), baselines.get((url, param))))
        await asyncio.gather(*tasks)
        return findings

    def _candidate_params(self, ctx: ScanContext) -> list[tuple[str, str]]:
        out: list[tuple[str, str]] = []
        for endpoint in ctx.recon.get("endpoints", [])[:60]:
            url = endpoint.get("url")
            params = endpoint.get("params") or []
            if not url:
                continue
            for param in params:
                if any(token in param.lower() for token in self.PARAMS):
                    out.append((url, param))
        return list(dict.fromkeys(out))
