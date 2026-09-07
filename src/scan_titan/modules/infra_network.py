from __future__ import annotations

import asyncio

from .common import Finding, ScanContext, VulnerabilityModule


class InfraNetworkModule(VulnerabilityModule):
    name = "infra_network"

    COMMON_PORTS = [21, 22, 23, 25, 53, 80, 110, 143, 443, 445, 1433, 1521, 3306, 3389, 5432, 6379, 8000, 8080, 8443, 9200, 27017]
    VERSION_RISKS = {
        "apache/2.2": "Apache 2.2 is end-of-life.",
        "apache/2.0": "Apache 2.0 is obsolete.",
        "php/5.": "PHP 5.x is end-of-life.",
        "php/7.0": "PHP 7.0 is end-of-life.",
        "php/7.1": "Old PHP 7.1 branch detected.",
        "php/7.2": "Old PHP 7.2 branch detected.",
        "php/7.3": "Old PHP 7.3 branch detected.",
        "php/7.4": "Old PHP 7.4 branch detected.",
        "openssl/1.0": "OpenSSL 1.0.x is end-of-life.",
        "openssl/1.1.0": "Old OpenSSL branch detected.",
        "nginx/1.10": "Old nginx branch detected.",
        "nginx/1.12": "Old nginx branch detected.",
        "nginx/1.14": "Old nginx branch detected.",
        "nginx/1.16": "Old nginx branch detected.",
        "iis/6.0": "IIS 6.0 is obsolete.",
        "iis/7.0": "Old IIS branch detected.",
        "openssh_7.": "Older OpenSSH branch detected.",
        "tomcat/7": "Old Apache Tomcat branch detected.",
        "tomcat/8.0": "Old Apache Tomcat branch detected.",
        "jboss": "JBoss/WildFly exposure requires version validation.",
    }
    WAF_HEADERS = {
        "cf-ray": "Cloudflare",
        "cf-cache-status": "Cloudflare",
        "server: cloudflare": "Cloudflare",
        "x-sucuri-id": "Sucuri",
        "x-sucuri-cache": "Sucuri",
        "x-akamai": "Akamai",
        "akamai": "Akamai",
        "x-waf": "Generic WAF",
        "x-cdn": "CDN/WAF",
        "x-cache": "Proxy/CDN",
    }

    async def run(self, ctx: ScanContext) -> list[Finding]:
        findings: list[Finding] = []
        findings.extend(await self._tcp_surface(ctx))
        findings.extend(await self._server_config(ctx))
        findings.extend(await self._http_methods(ctx))
        findings.extend(await self._ip_blocking(ctx))
        if ctx.policy.allow_rate_limit_probes:
            findings.extend(await self._rate_limit(ctx))
        else:
            ctx.recon["policy_deferred_tests"] = sorted(
                set(ctx.recon.get("policy_deferred_tests", []) + ["rate_limit_probe"])
            )
        return findings

    async def _tcp_surface(self, ctx: ScanContext) -> list[Finding]:
        if ctx.recon.get("open_ports"):
            return []
        open_ports: list[str] = []
        semaphore = asyncio.Semaphore(6)

        async def probe(port: int) -> None:
            async with semaphore:
                try:
                    reader, writer = await asyncio.wait_for(asyncio.open_connection(ctx.target.ip, port), timeout=1.5)
                    writer.close()
                    await writer.wait_closed()
                    open_ports.append(f"{port}/tcp")
                    await asyncio.sleep(0.25)
                except Exception:
                    return

        await asyncio.gather(*(probe(port) for port in self.COMMON_PORTS))
        ctx.recon["open_ports"] = sorted(open_ports)
        return []

    async def _server_config(self, ctx: ScanContext) -> list[Finding]:
        findings: list[Finding] = []
        result = await ctx.http.request("GET", ctx.target.url, allow_redirects=False)
        if not result:
            return findings
        server = result.headers.get("Server", "")
        powered = result.headers.get("X-Powered-By", "")
        exposed = [item for item in [f"Server: {server}" if server else "", f"X-Powered-By: {powered}" if powered else ""] if item]
        waf = self._waf_signal(result.headers)
        if waf:
            ctx.recon["waf_cdn"] = waf
            findings.append(
                Finding(
                    target=ctx.target.display,
                    category="Infra",
                    severity="Info",
                    title="WAF/CDN signal detected",
                    url=ctx.target.url,
                    evidence=", ".join(waf),
                    source=self.name,
                    confidence="medium",
                )
            )
        if exposed:
            findings.append(
                Finding(
                    target=ctx.target.display,
                    category="Infra",
                    severity="Info",
                    title="Server configuration headers exposed",
                    url=ctx.target.url,
                    evidence=" | ".join(exposed),
                    source=self.name,
                    confidence="high",
                )
            )
        banner = " ".join([server, powered]).lower()
        for marker, evidence in self.VERSION_RISKS.items():
            if marker in banner:
                findings.append(
                    Finding(
                        target=ctx.target.display,
                        category="Infra",
                        severity="Medium",
                        title=f"Potential vulnerable/obsolete version: {marker}",
                        url=ctx.target.url,
                        evidence=evidence,
                        source=self.name,
                        confidence="medium",
                    )
                )
        return findings

    async def _http_methods(self, ctx: ScanContext) -> list[Finding]:
        findings: list[Finding] = []
        options = await ctx.http.request("OPTIONS", ctx.target.url, allow_redirects=False)
        if options:
            allow = options.headers.get("Allow", "")
            public = [method.strip().upper() for method in allow.split(",") if method.strip()]
            dangerous = [method for method in public if method in {"PUT", "DELETE", "TRACE", "CONNECT", "PATCH"}]
            ctx.recon["http_methods"] = public
            if dangerous:
                findings.append(
                    Finding(
                        target=ctx.target.display,
                        category="Infra",
                        severity="Medium",
                        title="Potentially dangerous HTTP methods advertised",
                        url=ctx.target.url,
                        method="OPTIONS",
                        status=str(options.status),
                        evidence=f"Allow={allow}",
                        source=self.name,
                        confidence="medium",
                    )
                )
        trace = await ctx.http.request(
            "TRACE",
            ctx.target.url,
            headers={"X-Scan-Titan-Trace": "scan_titan_trace_marker"},
            allow_redirects=False,
        )
        if trace and trace.status == 200 and "scan_titan_trace_marker" in trace.text:
            findings.append(
                Finding(
                    target=ctx.target.display,
                    category="Infra",
                    severity="High",
                    title="HTTP TRACE method enabled",
                    url=ctx.target.url,
                    method="TRACE",
                    status=str(trace.status),
                    evidence="TRACE reflected the request marker.",
                    source=self.name,
                    confidence="high",
                )
            )
        return findings

    async def _ip_blocking(self, ctx: ScanContext) -> list[Finding]:
        baseline = await ctx.http.request("GET", ctx.target.url, allow_redirects=False)
        if not baseline:
            return []
        findings: list[Finding] = []
        bypass_headers = [
            {"X-Forwarded-For": "127.0.0.1"},
            {"X-Real-IP": "127.0.0.1"},
            {"X-Originating-IP": "127.0.0.1"},
            {"X-Client-IP": "127.0.0.1"},
        ]
        for idx, headers in enumerate(bypass_headers, start=1):
            ctx.heartbeat(self.name, f"ip-block {headers}", idx, len(findings))
            result = await ctx.http.request("GET", ctx.target.url, headers=headers, allow_redirects=False)
            if not result:
                continue
            if baseline.status in {401, 403} and result.status == 200:
                findings.append(
                    Finding(
                        target=ctx.target.display,
                        category="Infra",
                        severity="High",
                        title="IP restriction bypass via forwarding header",
                        url=ctx.target.url,
                        method="GET",
                        payload=str(headers),
                        status=str(result.status),
                        evidence=f"Baseline={baseline.status} HeaderProbe={result.status}",
                        source=self.name,
                        confidence="medium",
                    )
                )
        return findings

    async def _rate_limit(self, ctx: ScanContext) -> list[Finding]:
        statuses = []
        total = max(1, min(int(ctx.policy.rate_limit_probe_requests or 8), 25))
        for idx in range(1, total + 1):
            ctx.heartbeat(self.name, "rate-limit probe", idx, 0)
            result = await ctx.http.request("GET", ctx.target.url, headers={"X-Scan-Titan-Probe": str(idx)}, allow_redirects=False)
            if result:
                statuses.append(result.status)
        if len(statuses) >= 6 and not any(code in {401, 403, 409, 429, 503} for code in statuses):
            return [
                Finding(
                    target=ctx.target.display,
                    category="Infra",
                    severity="Low",
                    title="No rate-limit / anti-automation signal observed",
                    url=ctx.target.url,
                    evidence=f"Repeated probe statuses: {statuses}",
                    source=self.name,
                    confidence="low",
                )
            ]
        return []

    def _waf_signal(self, headers: dict[str, str]) -> list[str]:
        combined = " ".join(f"{key}: {value}" for key, value in headers.items()).lower()
        return sorted({name for marker, name in self.WAF_HEADERS.items() if marker in combined})
