from __future__ import annotations

import asyncio
import re
import urllib.parse
from collections import deque
from typing import Any

from bs4 import BeautifulSoup

from .common import Finding, ScanContext, VulnerabilityModule, clean_text


class SiteMapModule(VulnerabilityModule):
    name = "site_map"

    FUNCTION_KEYWORDS = {
        "authentication": ["login", "signin", "logout", "register", "signup", "password", "reset"],
        "account": ["account", "profile", "settings", "user", "member"],
        "admin": ["admin", "manage", "manager", "dashboard", "console"],
        "commerce": ["cart", "basket", "checkout", "order", "invoice", "payment"],
        "api": ["api", "graphql", "swagger", "openapi", "rest"],
        "upload": ["upload", "file", "attachment", "import"],
        "search": ["search", "query", "filter"],
        "debug": ["debug", "log", "trace", "status", "metrics", "actuator"],
    }

    async def run(self, ctx: ScanContext) -> list[Finding]:
        findings: list[Finding] = []
        routes, forms, scripts = await self._crawl(ctx)
        robots_routes = await self._robots(ctx)
        sitemap_routes = await self._sitemap(ctx)

        all_routes = sorted(set(routes + robots_routes + sitemap_routes))[:1000]
        functions = self._classify_functions(all_routes, forms)
        ctx.recon["site_map"] = all_routes
        ctx.recon["site_functions"] = functions
        ctx.recon["forms"] = forms[:200]
        ctx.recon["js_libraries"] = sorted(set(ctx.recon.get("js_libraries", []) + scripts))[:300]
        ctx.recon["discovered_paths"] = sorted(
            set(ctx.recon.get("discovered_paths", []) + [urllib.parse.urlparse(url).path for url in all_routes])
        )[:1000]
        self._merge_endpoints(ctx, all_routes)

        if all_routes:
            findings.append(
                Finding(
                    target=ctx.target.display,
                    category="Recon/SiteMap",
                    severity="Info",
                    title="Functional site map generated",
                    url=ctx.target.url,
                    evidence=clean_text(
                        f"Routes={len(all_routes)} Forms={len(forms)} Functions={functions or '-'}",
                        700,
                    ),
                    source=self.name,
                    confidence="high",
                )
            )
        sensitive_public = [
            route
            for route in all_routes
            if any(token in route.lower() for token in ["admin", "debug", "actuator", "metrics", "swagger", "openapi"])
        ][:20]
        if sensitive_public:
            findings.append(
                Finding(
                    target=ctx.target.display,
                    category="Recon/SiteMap",
                    severity="Low",
                    title="Sensitive-looking functionality exposed in site map",
                    url=ctx.target.url,
                    evidence=clean_text(sensitive_public, 900),
                    source=self.name,
                    confidence="medium",
                )
            )
        return findings

    async def _crawl(self, ctx: ScanContext) -> tuple[list[str], list[str], list[str]]:
        visited: set[str] = set()
        routes: list[str] = []
        forms: list[str] = []
        scripts: list[str] = []
        queue: deque[str] = deque([ctx.target.url])
        max_pages = min(ctx.limits.max_tests_per_module, max(1, int(ctx.policy.browser_max_pages or 50)))

        while queue and len(visited) < max_pages:
            url = queue.popleft()
            stable = self._stable_url(url)
            if stable in visited:
                continue
            visited.add(stable)
            ctx.heartbeat(self.name, urllib.parse.urlparse(url).path or "/", len(visited), len(routes))
            result = await ctx.http.request("GET", url, allow_redirects=True)
            if not result or result.status not in {200, 301, 302, 401, 403}:
                continue
            final_url = self._stable_url(result.final_url)
            if final_url not in routes:
                routes.append(final_url)
            if "html" not in result.content_type.lower() and "<html" not in result.text[:300].lower():
                continue
            soup = BeautifulSoup(result.text, "html.parser")
            for script in soup.find_all("script", src=True)[:80]:
                src = urllib.parse.urljoin(result.final_url, script.get("src"))
                if self._same_host(src, ctx.target.host):
                    scripts.append(src)
            for form in soup.find_all("form")[:40]:
                method = (form.get("method") or "GET").upper()
                action = urllib.parse.urljoin(result.final_url, form.get("action") or result.final_url)
                fields = [
                    str(field.get("name") or "")
                    for field in form.find_all(["input", "textarea", "select"])
                    if field.get("name")
                ]
                forms.append(f"{method} {action} fields={','.join(fields[:12])}")
            for next_url in self._links(result.final_url, soup, ctx.target.host):
                if self._stable_url(next_url) not in visited and len(visited) + len(queue) < max_pages:
                    queue.append(next_url)
            await asyncio.sleep(0.05)
        return routes, sorted(set(forms)), sorted(set(scripts))

    async def _robots(self, ctx: ScanContext) -> list[str]:
        url = urllib.parse.urljoin(ctx.target.url, "/robots.txt")
        result = await ctx.http.request("GET", url, allow_redirects=False, timeout=min(ctx.limits.timeout, 6))
        if not result or result.status != 200:
            return []
        routes = []
        for line in result.text.splitlines():
            match = re.match(r"\s*(?:allow|disallow|sitemap)\s*:\s*(.+)$", line, re.IGNORECASE)
            if not match:
                continue
            value = match.group(1).strip()
            if value and value != "/":
                routes.append(urllib.parse.urljoin(ctx.target.url, value))
        ctx.recon["robots_entries"] = routes[:200]
        return routes[:200]

    async def _sitemap(self, ctx: ScanContext) -> list[str]:
        routes: list[str] = []
        for path in ["/sitemap.xml", "/sitemap_index.xml"]:
            result = await ctx.http.request(
                "GET",
                urllib.parse.urljoin(ctx.target.url, path),
                allow_redirects=False,
                timeout=min(ctx.limits.timeout, 6),
            )
            if not result or result.status != 200:
                continue
            for loc in re.findall(r"<loc>\s*([^<]+)\s*</loc>", result.text, flags=re.IGNORECASE):
                if self._same_host(loc, ctx.target.host):
                    routes.append(self._stable_url(loc))
        ctx.recon["sitemap_entries"] = sorted(set(routes))[:500]
        return sorted(set(routes))[:500]

    def _links(self, base_url: str, soup: Any, host: str) -> list[str]:
        links = []
        for tag in soup.find_all(["a", "area"], href=True)[:250]:
            url = urllib.parse.urljoin(base_url, tag.get("href"))
            if self._same_host(url, host):
                links.append(self._stable_url(url))
        return list(dict.fromkeys(links))

    def _same_host(self, url: str, host: str) -> bool:
        parsed = urllib.parse.urlparse(url)
        return parsed.scheme in {"http", "https"} and parsed.hostname == host

    def _stable_url(self, url: str) -> str:
        parsed = urllib.parse.urlparse(url)
        query = urllib.parse.urlencode(sorted(urllib.parse.parse_qsl(parsed.query, keep_blank_values=True)))
        return parsed._replace(fragment="", query=query).geturl()

    def _classify_functions(self, routes: list[str], forms: list[str]) -> list[str]:
        text = " ".join(routes + forms).lower()
        return sorted(name for name, values in self.FUNCTION_KEYWORDS.items() if any(item in text for item in values))

    def _merge_endpoints(self, ctx: ScanContext, routes: list[str]) -> None:
        current = list(ctx.recon.get("endpoints", []))
        seen = {item.get("url") for item in current if isinstance(item, dict)}
        for url in routes[:500]:
            if url in seen:
                continue
            params = list(urllib.parse.parse_qs(urllib.parse.urlparse(url).query).keys())
            current.append({"url": url, "params": params, "method": "GET", "source": self.name})
            seen.add(url)
        ctx.recon["endpoints"] = current[:1000]
