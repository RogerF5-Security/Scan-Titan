from __future__ import annotations

import re
import urllib.parse
from typing import Any

from bs4 import BeautifulSoup

from .common import Finding, ScanContext, VulnerabilityModule, clean_text, url_with_params
from .payload_utils import xss_payloads


class ClientSideModule(VulnerabilityModule):
    name = "client_side"

    XSS_PAYLOADS = [
        "scan-titan\"><svg/onload=alert(1)>",
        "\"><img src=x onerror=alert(1)>",
        "<svg><animate onbegin=alert(1) attributeName=x>",
        "javascript:alert(1)",
    ]
    PARAMS = ["q", "search", "query", "name", "msg", "message", "text", "comment", "redirect", "next", "url"]
    TOKEN_PATTERNS = {
        "JWT": r"eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}",
        "AWS Access Key": r"AKIA[0-9A-Z]{16}",
        "Google API Key": r"AIza[0-9A-Za-z_-]{35}",
        "GitHub Token": r"ghp_[A-Za-z0-9_]{36}",
        "Slack Token": r"xox[baprs]-[0-9a-zA-Z-]+",
        "SendGrid API Key": r"SG\.[A-Za-z0-9_-]{22}\.[A-Za-z0-9_-]{43}",
        "OpenAI API Key": r"sk-[A-Za-z0-9]{48}",
        "Stripe Live Secret": r"sk_live_[0-9a-zA-Z]{24}",
        "Generic API Key": r"(?:api_key|apikey|api-key)[\"'\s:=]+[A-Za-z0-9_\-]{20,80}",
        "Bearer Token": r"[Bb]earer\s+[A-Za-z0-9\-._~+/]{20,}",
        "Private Key": r"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----",
    }
    DOM_SOURCES = ["location", "location.hash", "location.search", "document.URL", "document.referrer", "postMessage"]
    DOM_SINKS = ["innerHTML", "outerHTML", "document.write", "eval(", "setTimeout(", "setInterval(", "insertAdjacentHTML"]

    async def run(self, ctx: ScanContext) -> list[Finding]:
        findings: list[Finding] = []
        result = await ctx.http.request("GET", ctx.target.url, allow_redirects=True)
        if not result:
            return findings
        soup = BeautifulSoup(result.text, "html.parser")
        # El modulo XSS dedicado ya ejecuta deteccion adaptativa de reflexion.
        # No repetir aqui hasta 10k payloads sobre la misma superficie.
        if not ctx.recon.get("xss_active_completed"):
            findings.extend(await self._reflected_xss(ctx))
        if ctx.policy.allow_state_changing_api_tests:
            findings.extend(await self._stored_candidate(ctx, result.final_url, soup))
        else:
            ctx.recon["policy_deferred_tests"] = sorted(
                set(ctx.recon.get("policy_deferred_tests", []) + ["stored_xss_form_probe"])
            )
        findings.extend(self._dom_xss(ctx, result, [("html", result.text)]))
        findings.extend(await self._front_end_tokens(ctx, result, soup))
        findings.extend(await self._cors(ctx))
        findings.extend(self._headers(ctx, result))
        findings.extend(await self._waf_evasion(ctx))
        return findings

    async def _reflected_xss(self, ctx: ScanContext) -> list[Finding]:
        findings = []
        tested = 0
        fallback_budget = min(max(1, ctx.limits.max_tests_per_module), 120)
        payloads = xss_payloads(ctx.wordlists, self.XSS_PAYLOADS, limit=min(12, fallback_budget))
        candidates = [(ctx.target.url, self.PARAMS)]
        for endpoint in ctx.recon.get("endpoints", []):
            if endpoint.get("url"):
                candidates.append((endpoint["url"], endpoint.get("params") or self.PARAMS[:6]))
        for url, params in candidates:
            for param in params[:12]:
                for payload in payloads:
                    if tested >= fallback_budget:
                        return findings
                    tested += 1
                    ctx.heartbeat("xss_reflected", f"{param}={payload[:24]}", tested, len(findings))
                    result = await ctx.http.request("GET", url, params={param: payload})
                    if not result:
                        continue
                    escaped = payload.replace("<", "&lt;").replace(">", "&gt;")
                    if payload in result.text and escaped not in result.text:
                        findings.append(
                            Finding(
                                target=ctx.target.display,
                                category="Client-Side",
                                severity="High",
                                title=f"Reflected XSS candidate: {param}",
                                url=url_with_params(url, {param: payload}),
                                param=param,
                                method="GET",
                                payload=payload,
                                status=str(result.status),
                                evidence="Payload reflected without HTML escaping.",
                                source=self.name,
                                confidence="high",
                            )
                        )
                        break
        return findings

    async def _stored_candidate(self, ctx: ScanContext, base_url: str, soup: Any) -> list[Finding]:
        findings = []
        marker = f"scan_titan_stored_{ctx.target.host.replace('.', '_')}"
        forms = [f for f in soup.find_all("form") if not f.find("input", {"type": "password"})]
        for idx, form in enumerate(forms[:5], start=1):
            action = urllib.parse.urljoin(base_url, form.get("action") or base_url)
            method = (form.get("method") or "GET").upper()
            fields = {}
            for field in form.find_all(["input", "textarea"]):
                name = field.get("name")
                if name:
                    fields[name] = marker
            if not fields:
                continue
            ctx.heartbeat("xss_stored_probe", action, idx, len(findings))
            result = await ctx.http.request(method, action, data=fields, allow_redirects=True)
            if result and marker in result.text:
                findings.append(
                    Finding(
                        target=ctx.target.display,
                        category="Client-Side",
                        severity="Medium",
                        title="Stored/reflected form input candidate",
                        url=action,
                        method=method,
                        payload=marker,
                        status=str(result.status),
                        evidence="Benign marker was reflected after form submission.",
                        source=self.name,
                        confidence="low",
                    )
                )
        return findings

    def _dom_xss(self, ctx: ScanContext, result: Any, sources: list[tuple[str, str]]) -> list[Finding]:
        # Merely having a source and sink somewhere in a bundle proves no flow.
        from .javascript_recon import analyze_javascript
        for source, text in sources:
            info = analyze_javascript(result.final_url if source == "html" else source, text, ctx.target.url)
            ctx.recon.setdefault("dom_static_candidates", []).extend(info["dom_flows"])
        return []

    async def _front_end_tokens(self, ctx: ScanContext, result: Any, soup: Any) -> list[Finding]:
        from .javascript_recon import javascript_recon
        if "javascript_recon" not in ctx.recon:
            await javascript_recon(ctx, result)
        # Candidate keys, public identifiers and storage access are recon. Never
        # claim a usable credential without verifying its security implications.
        return []

    def _storage_and_cookie_hits(self, text: str) -> str:
        patterns = {
            "document.cookie": r"document\.cookie",
            "localStorage token": r"localStorage\.(?:getItem|setItem)\(['\"][^'\"]*(?:token|auth|jwt|session|role)",
            "sessionStorage token": r"sessionStorage\.(?:getItem|setItem)\(['\"][^'\"]*(?:token|auth|jwt|session|role)",
        }
        hits = [name for name, pattern in patterns.items() if re.search(pattern, text, re.IGNORECASE)]
        return ", ".join(hits)

    async def _cors(self, ctx: ScanContext) -> list[Finding]:
        findings = []
        for idx, origin in enumerate(["https://example.com", "null"], start=1):
            ctx.heartbeat("cors", origin, idx, len(findings))
            result = await ctx.http.request("GET", ctx.target.url, headers={"Origin": origin}, allow_redirects=False)
            if not result:
                continue
            acao = result.headers.get("Access-Control-Allow-Origin", "")
            acac = result.headers.get("Access-Control-Allow-Credentials", "")
            if acao == "*" and acac.lower() == "true":
                findings.append(Finding(ctx.target.display, "Client-Side", "High", "CORS wildcard with credentials", ctx.target.url, evidence=f"ACAO={acao} ACAC={acac}", source=self.name))
            elif acao == origin:
                findings.append(Finding(ctx.target.display, "Client-Side", "Medium", "CORS reflects arbitrary origin", ctx.target.url, evidence=f"ACAO={acao} ACAC={acac or '-'}", source=self.name))
        return findings

    def _headers(self, ctx: ScanContext, result: Any) -> list[Finding]:
        findings = []
        headers = result.headers
        csp = headers.get("Content-Security-Policy", "")
        if not csp:
            findings.append(Finding(ctx.target.display, "Client-Side", "Medium", "CSP missing", result.final_url, evidence="Content-Security-Policy not observed.", source=self.name))
        else:
            weak = [x for x in ["'unsafe-inline'", "'unsafe-eval'", "*", "data:"] if x in csp]
            if weak:
                findings.append(Finding(ctx.target.display, "Client-Side", "Medium", "CSP bypass/evasion primitives present", result.final_url, evidence=", ".join(weak), source=self.name))
        if not headers.get("X-Frame-Options") and "frame-ancestors" not in csp.lower():
            findings.append(Finding(ctx.target.display, "Client-Side", "Low", "Clickjacking protection missing", result.final_url, evidence="No X-Frame-Options or CSP frame-ancestors.", source=self.name))
        if not headers.get("X-Content-Type-Options"):
            findings.append(Finding(ctx.target.display, "Client-Side", "Low", "X-Content-Type-Options missing", result.final_url, evidence="nosniff not observed.", source=self.name))
        cache = headers.get("Cache-Control", "")
        if "no-store" not in cache.lower() and "private" not in cache.lower():
            findings.append(Finding(ctx.target.display, "Client-Side", "Low", "Cache-Control not restrictive", result.final_url, evidence=f"Cache-Control={cache or '-'}", source=self.name))
        return findings

    async def _waf_evasion(self, ctx: ScanContext) -> list[Finding]:
        probes = ["%27%20OR%201%3D1--", "%3Csvg/onload=alert(1)%3E", "/..;/admin"]
        statuses = []
        for idx, payload in enumerate(probes, start=1):
            ctx.heartbeat("waf_evasion", payload, idx, 0)
            result = await ctx.http.request("GET", ctx.target.url, params={"scan_titan_probe": payload}, allow_redirects=False)
            if result:
                statuses.append(result.status)
        if statuses and not any(s in {403, 406, 419, 429, 503} for s in statuses):
            return [Finding(ctx.target.display, "Client-Side", "Info", "No WAF/filtering signal on encoded probes", ctx.target.url, evidence=f"Statuses={statuses}", source=self.name, confidence="low")]
        return []
