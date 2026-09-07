from __future__ import annotations

import re
from http.cookies import SimpleCookie
from typing import Any

from .common import Finding, ScanContext, VulnerabilityModule, clean_text


class HeadersModule(VulnerabilityModule):
    name = "headers"

    SECURITY_HEADERS = {
        "Strict-Transport-Security": (
            "Medium",
            "HSTS missing",
            "HTTPS is not explicitly enforced by HSTS.",
        ),
        "Content-Security-Policy": (
            "Medium",
            "CSP missing",
            "XSS mitigation is weakened by a missing CSP.",
        ),
        "X-Frame-Options": (
            "Low",
            "X-Frame-Options missing",
            "Clickjacking protection is not declared.",
        ),
        "X-Content-Type-Options": (
            "Low",
            "X-Content-Type-Options missing",
            "Browser MIME sniffing is not explicitly disabled.",
        ),
        "Referrer-Policy": (
            "Low",
            "Referrer-Policy missing",
            "Sensitive URLs may leak through the Referer header.",
        ),
        "Permissions-Policy": (
            "Low",
            "Permissions-Policy missing",
            "Browser feature access is not explicitly constrained.",
        ),
    }

    INFO_HEADERS = {
        "Server",
        "X-Powered-By",
        "X-AspNet-Version",
        "X-AspNetMvc-Version",
        "X-Generator",
    }

    async def run(self, ctx: ScanContext) -> list[Finding]:
        result = await ctx.http.request("GET", ctx.target.url, allow_redirects=True)
        if not result:
            return [
                Finding(
                    target=ctx.target.display,
                    category="Availability",
                    severity="Info",
                    title="Initial HTTP request failed",
                    url=ctx.target.url,
                    evidence="The target did not answer the initial HTTP probe.",
                    source=self.name,
                    confidence="low",
                )
            ]

        headers_lower = {key.lower(): key for key in result.headers}
        ctx.recon["security_headers"] = self._security_header_summary(result.headers)
        ctx.recon["cookies_status"] = self._cookie_summary(result)
        findings: list[Finding] = []

        for header, (severity, title, evidence) in self.SECURITY_HEADERS.items():
            if header.lower() not in headers_lower:
                findings.append(
                    Finding(
                        target=ctx.target.display,
                        category="Headers",
                        severity=severity,
                        title=title,
                        url=result.final_url,
                        evidence=evidence,
                        source=self.name,
                        confidence="high",
                    )
                )

        for header in self.INFO_HEADERS:
            if header in result.headers:
                findings.append(
                    Finding(
                        target=ctx.target.display,
                        category="Headers",
                        severity="Info",
                        title=f"Information disclosure header: {header}",
                        url=result.final_url,
                        evidence=f"{header}: {result.headers.get(header)}",
                        source=self.name,
                        confidence="high",
                    )
                )

        csp = result.headers.get("Content-Security-Policy", "")
        if csp:
            findings.extend(self._csp_findings(ctx, result.final_url, csp))
        findings.extend(self._hsts_findings(ctx, result))
        findings.extend(self._cache_findings(ctx, result))
        findings.extend(self._referrer_findings(ctx, result))

        return findings

    def _csp_findings(self, ctx: ScanContext, url: str, csp: str) -> list[Finding]:
        findings: list[Finding] = []
        lowered = csp.lower()
        directives = self._parse_csp(csp)
        weak_tokens = [
            token
            for token in ["'unsafe-inline'", "'unsafe-eval'", "*", "data:", "http:"]
            if token in lowered
        ]
        if weak_tokens:
            findings.append(
                Finding(
                    target=ctx.target.display,
                    category="Headers",
                    severity="Medium",
                    title="CSP contains bypass/evasion primitives",
                    url=url,
                    evidence=f"WeakTokens={weak_tokens} CSP={clean_text(csp, 700)}",
                    source=self.name,
                    confidence="high",
                )
            )
        missing = [
            directive
            for directive in ["default-src", "object-src", "base-uri", "frame-ancestors", "form-action"]
            if directive not in directives
        ]
        if missing:
            findings.append(
                Finding(
                    target=ctx.target.display,
                    category="Headers",
                    severity="Low",
                    title="CSP missing hardening directives",
                    url=url,
                    evidence=f"Missing={','.join(missing)}",
                    source=self.name,
                    confidence="medium",
                )
            )
        object_src = " ".join(directives.get("object-src", []))
        if object_src and "'none'" not in object_src and "none" not in object_src:
            findings.append(
                Finding(
                    target=ctx.target.display,
                    category="Headers",
                    severity="Low",
                    title="CSP object-src is not locked down",
                    url=url,
                    evidence=f"object-src={object_src}",
                    source=self.name,
                    confidence="medium",
                )
            )
        return findings

    def _hsts_findings(self, ctx: ScanContext, result: Any) -> list[Finding]:
        hsts = result.headers.get("Strict-Transport-Security", "")
        if not hsts or not result.final_url.lower().startswith("https://"):
            return []
        findings: list[Finding] = []
        match = re.search(r"max-age\s*=\s*(\d+)", hsts, re.IGNORECASE)
        max_age = int(match.group(1)) if match else 0
        if max_age < 15552000:
            findings.append(
                Finding(
                    target=ctx.target.display,
                    category="Headers",
                    severity="Low",
                    title="HSTS max-age is weak",
                    url=result.final_url,
                    evidence=f"Strict-Transport-Security={hsts}",
                    source=self.name,
                    confidence="high",
                )
            )
        lowered = hsts.lower()
        if "includesubdomains" not in lowered:
            findings.append(
                Finding(
                    target=ctx.target.display,
                    category="Headers",
                    severity="Info",
                    title="HSTS does not include subdomains",
                    url=result.final_url,
                    evidence=f"Strict-Transport-Security={hsts}",
                    source=self.name,
                    confidence="medium",
                )
            )
        return findings

    def _cache_findings(self, ctx: ScanContext, result: Any) -> list[Finding]:
        cache = result.headers.get("Cache-Control", "")
        pragma = result.headers.get("Pragma", "")
        has_cookie = bool(self._cookie_values(result))
        sensitive_url = any(token in result.final_url.lower() for token in ["login", "account", "profile", "admin", "dashboard"])
        if (has_cookie or sensitive_url) and "no-store" not in cache.lower():
            return [
                Finding(
                    target=ctx.target.display,
                    category="Headers",
                    severity="Low",
                    title="Cache-Control may allow sensitive response caching",
                    url=result.final_url,
                    evidence=f"Cache-Control={cache or '-'} Pragma={pragma or '-'} Set-Cookie={has_cookie}",
                    source=self.name,
                    confidence="medium",
                )
            ]
        return []

    def _referrer_findings(self, ctx: ScanContext, result: Any) -> list[Finding]:
        policy = result.headers.get("Referrer-Policy", "")
        if policy.lower() in {"unsafe-url", "origin-when-cross-origin"}:
            return [
                Finding(
                    target=ctx.target.display,
                    category="Headers",
                    severity="Low",
                    title="Weak Referrer-Policy",
                    url=result.final_url,
                    evidence=f"Referrer-Policy={policy}",
                    source=self.name,
                    confidence="high",
                )
            ]
        return []

    def _parse_csp(self, csp: str) -> dict[str, list[str]]:
        directives: dict[str, list[str]] = {}
        for part in csp.split(";"):
            tokens = part.strip().split()
            if not tokens:
                continue
            directives[tokens[0].lower()] = tokens[1:]
        return directives

    def _security_header_summary(self, headers: dict[str, str]) -> str:
        present = []
        missing = []
        lowered = {key.lower() for key in headers}
        for header in self.SECURITY_HEADERS:
            if header.lower() in lowered:
                present.append(header)
            else:
                missing.append(header)
        return f"Present: {', '.join(present) or '-'} | Missing: {', '.join(missing) or '-'}"

    def _cookie_summary(self, result: Any) -> str:
        raw_cookies = self._cookie_values(result)
        if not raw_cookies:
            return "No Set-Cookie observed"
        rows = []
        for raw in raw_cookies:
            cookie = SimpleCookie()
            try:
                cookie.load(raw)
            except Exception:
                rows.append("Unparseable Set-Cookie")
                continue
            for name, morsel in cookie.items():
                flags: dict[str, Any] = {
                    "Secure": bool(morsel["secure"]),
                    "HttpOnly": bool(morsel["httponly"]),
                    "SameSite": bool(morsel["samesite"]),
                }
                missing = [key for key, enabled in flags.items() if not enabled]
                rows.append(f"{name}: missing {','.join(missing) if missing else 'none'}")
        return " | ".join(rows)

    def _cookie_values(self, result: Any) -> list[str]:
        raw_headers = getattr(result, "raw_headers", {}) or {}
        values: list[str] = []
        for key, raw_values in raw_headers.items():
            if str(key).lower() == "set-cookie":
                values.extend([str(item) for item in raw_values if str(item).strip()])
        if not values:
            values = [value for key, value in result.headers.items() if key.lower() == "set-cookie"]
        return values
