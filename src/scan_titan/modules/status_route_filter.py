from __future__ import annotations

import urllib.parse
from typing import Any

from bs4 import BeautifulSoup

from .common import (
    Finding,
    ScanContext,
    VulnerabilityModule,
    record_probe_timeout,
    run_bounded,
)


class StatusRouteFilterModule(VulnerabilityModule):
    """Collect same-origin routes that answer strictly with HTTP 200 or 403."""

    name = "status_route_filter"
    ALLOWED_STATUSES = {200, 403}
    MAX_WORKERS = 12
    DEFAULT_PATHS = (
        "/",
        "/robots.txt",
        "/admin",
        "/login",
        "/api",
        "/swagger.json",
        "/openapi.json",
        "/graphql",
        "/.well-known/security.txt",
    )

    async def run(self, ctx: ScanContext) -> list[Finding]:
        routes = await self.collect(ctx)
        ctx.recon["raw_routes"] = routes
        ctx.recon["discovered_paths"] = sorted(
            set(ctx.recon.get("discovered_paths", [])) | set(routes)
        )[:1000]
        self._merge_endpoints(ctx, routes)
        return []

    async def collect(self, ctx: ScanContext) -> list[str]:
        """Return a raw path list; no findings, status labels, or metadata."""
        budget = max(1, min(int(ctx.limits.max_tests_per_module or 1), 1000))
        visited: set[str] = set()
        accepted: set[str] = set()
        frontier = self._seed_urls(ctx, budget)
        tested = 0

        while frontier and tested < budget and not ctx.should_stop():
            batch: list[str] = []
            for candidate in frontier:
                stable = self._stable_url(candidate)
                if not stable or stable in visited or not self._same_origin(ctx.target.url, stable):
                    continue
                visited.add(stable)
                batch.append(stable)
                if tested + len(batch) >= budget:
                    break
            frontier = []
            if not batch:
                break

            discovered: list[str] = []

            async def probe(url: str) -> None:
                nonlocal tested
                result = await ctx.http.request(
                    "GET",
                    url,
                    allow_redirects=False,
                    timeout=min(max(1.0, float(ctx.limits.timeout)), 12.0),
                )
                tested += 1
                if result is None:
                    ctx.heartbeat(self.name, f"sin respuesta {self._raw_path(url)}", tested, len(accepted))
                    return
                if int(result.status or 0) in self.ALLOWED_STATUSES:
                    route = self._raw_path(result.url or url)
                    if route:
                        accepted.add(route)
                if int(result.status or 0) == 200 and self._is_html(result):
                    discovered.extend(self._html_links(result.final_url or url, result.text, ctx.target.url))
                ctx.heartbeat(
                    self.name,
                    f"HTTP {int(result.status or 0)} {self._raw_path(url)}",
                    tested,
                    len(accepted),
                )

            await run_bounded(
                batch,
                probe,
                limit=self.MAX_WORKERS,
                should_stop=ctx.should_stop,
                item_timeout=max(5.0, min(20.0, float(ctx.limits.timeout) + 3.0)),
                on_timeout=lambda item, seconds: record_probe_timeout(ctx, self.name, item, seconds),
            )
            frontier = list(dict.fromkeys(discovered))

        return sorted(accepted)

    def _seed_urls(self, ctx: ScanContext, budget: int) -> list[str]:
        values: list[Any] = [ctx.target.url]
        values.extend(urllib.parse.urljoin(ctx.target.url, path) for path in self.DEFAULT_PATHS)
        for item in ctx.recon.get("endpoints", []) or []:
            values.append(item.get("url") if isinstance(item, dict) else item)
        values.extend(ctx.recon.get("discovered_paths", []) or [])
        values.extend(ctx.recon.get("unauthenticated_routes", []) or [])
        values.extend((ctx.wordlists.get("rutas", []) or [])[: max(0, min(80, budget // 2))])

        urls: list[str] = []
        seen: set[str] = set()
        for value in values:
            text = str(value or "").strip().split()[0] if str(value or "").strip() else ""
            if not text:
                continue
            url = text if text.startswith(("http://", "https://")) else urllib.parse.urljoin(ctx.target.url, text)
            stable = self._stable_url(url)
            if stable and self._same_origin(ctx.target.url, stable) and stable not in seen:
                seen.add(stable)
                urls.append(stable)
            if len(urls) >= budget:
                break
        return urls

    def _html_links(self, base_url: str, body: str, target_url: str) -> list[str]:
        try:
            soup = BeautifulSoup(body or "", "html.parser")
        except Exception:
            return []
        links: list[str] = []
        for tag in soup.find_all(["a", "area"], href=True)[:300]:
            url = self._stable_url(urllib.parse.urljoin(base_url, str(tag.get("href") or "")))
            if url and self._same_origin(target_url, url):
                links.append(url)
        return links

    def _is_html(self, result: Any) -> bool:
        return "html" in str(result.content_type or "").lower() or "<html" in str(result.text or "")[:500].lower()

    def _same_origin(self, base: str, candidate: str) -> bool:
        left = urllib.parse.urlsplit(base)
        right = urllib.parse.urlsplit(candidate)
        left_port = left.port or (443 if left.scheme == "https" else 80)
        right_port = right.port or (443 if right.scheme == "https" else 80)
        return (
            right.scheme in {"http", "https"}
            and left.scheme == right.scheme
            and left.hostname == right.hostname
            and left_port == right_port
        )

    def _stable_url(self, value: str) -> str:
        parsed = urllib.parse.urlsplit(str(value or "").strip())
        if parsed.scheme not in {"http", "https"} or not parsed.hostname:
            return ""
        query = urllib.parse.urlencode(sorted(urllib.parse.parse_qsl(parsed.query, keep_blank_values=True)))
        return urllib.parse.urlunsplit((parsed.scheme, parsed.netloc, parsed.path or "/", query, ""))

    def _raw_path(self, value: str) -> str:
        parsed = urllib.parse.urlsplit(str(value or ""))
        path = parsed.path or "/"
        return f"{path}?{parsed.query}" if parsed.query else path

    def _merge_endpoints(self, ctx: ScanContext, routes: list[str]) -> None:
        current = list(ctx.recon.get("endpoints", []))
        seen = {
            str(item.get("url") or "")
            for item in current
            if isinstance(item, dict)
        }
        for route in routes:
            url = urllib.parse.urljoin(ctx.target.url, route)
            if url in seen:
                continue
            params = list(urllib.parse.parse_qs(urllib.parse.urlsplit(url).query).keys())
            current.append({"url": url, "params": params, "method": "GET", "source": self.name})
            seen.add(url)
        ctx.recon["endpoints"] = current[:1000]
