from __future__ import annotations

import asyncio
import random
import re
import socket
import urllib.parse
from typing import Any

from bs4 import BeautifulSoup

from .common import (
    Finding,
    ScanContext,
    VulnerabilityModule,
    is_soft_auth_redirect,
    soft_auth_redirect_reason,
)


class ReconSurfaceModule(VulnerabilityModule):
    name = "recon_surface"
    WORDLIST_HIT_STATUSES = {200, 301, 302, 403, 500}

    DEFAULT_PATHS = [
        "/admin",
        "/login",
        "/dashboard",
        "/manager",
        "/portal",
        "/api",
        "/api/v1",
        "/swagger",
        "/swagger.json",
        "/openapi.json",
        "/graphql",
        "/robots.txt",
        "/sitemap.xml",
        "/.env",
        "/.git/config",
        "/.git/HEAD",
        "/backup.zip",
        "/backup.tar.gz",
        "/web.config",
        "/appsettings.json",
        "/composer.json",
        "/package.json",
        "/phpinfo.php",
        "/server-status",
        "/actuator/env",
        "/debug",
        "/logs",
    ]
    SENSITIVE = [".env", ".git", "backup", "config", "phpinfo", "server-status", "actuator", "debug", "logs"]
    SENSITIVE_CONTENT = [
        "[core]",
        "APP_KEY=",
        "DB_PASSWORD",
        "BEGIN RSA PRIVATE KEY",
        "phpinfo()",
        "SERVER_SOFTWARE",
        "actuator",
        "root:x:",
        "Index of /",
    ]

    async def run(self, ctx: ScanContext) -> list[Finding]:
        findings: list[Finding] = []
        base = await ctx.http.request("GET", ctx.target.url, allow_redirects=True)
        if not base:
            return findings

        ctx.recon["base_status"] = base.status
        ctx.recon["headers_exposed"] = [f"{k}: {v}" for k, v in base.headers.items()]
        ctx.recon["technologies"] = self._detect_technologies(base.text, base.headers)
        soup = BeautifulSoup(base.text, "html.parser")
        ctx.recon["js_libraries"] = self._extract_js(base.final_url, soup)
        ctx.recon["login_forms"] = self._extract_login_forms(base.final_url, soup)
        ctx.recon["endpoints"] = self._extract_endpoints(base.final_url, soup, ctx.target.host)
        ctx.recon["websockets"] = self._extract_websockets(base.text)

        subdomains = await self._subdomains(ctx)
        ctx.recon["subdomains"] = subdomains
        path_findings = await self._fuzz_paths(ctx)
        findings.extend(path_findings)
        return findings

    async def _fuzz_paths(self, ctx: ScanContext) -> list[Finding]:
        raw_paths = ctx.wordlists.get("rutas") or self.DEFAULT_PATHS
        path_budget = min(ctx.limits.max_tests_per_module, max(len(raw_paths), len(self.DEFAULT_PATHS)))
        paths = list(dict.fromkeys([self._path(p) for p in raw_paths[:path_budget]] + self.DEFAULT_PATHS))
        findings: list[Finding] = []
        discovered: list[str] = []
        exposed_files: list[str] = []
        wordlist_hits: list[dict[str, Any]] = []
        tested = 0
        lock = asyncio.Lock()
        soft_404 = await self._soft_404_baseline(ctx)

        async def probe(path: str) -> None:
            nonlocal tested
            async with lock:
                tested += 1
                if tested == 1 or tested % 25 == 0:
                    ctx.heartbeat(self.name, path, tested, len(findings))
            url = urllib.parse.urljoin(ctx.target.url, path)
            result = await ctx.http.request("GET", url, allow_redirects=False)
            if not result:
                return
            lower = path.lower()
            sensitive = any(marker in lower for marker in self.SENSITIVE)
            if result.status in self.WORDLIST_HIT_STATUSES:
                soft404_filtered = self._looks_like_soft_404(result, soft_404, path)
                wordlist_hits.append(
                    self._wordlist_hit_record(
                        ctx=ctx,
                        path=path,
                        url=url,
                        result=result,
                        soft404_filtered=soft404_filtered,
                        sensitive=sensitive,
                    )
                )
            if result.status not in {200, 301, 302, 401, 403, 500}:
                return
            if self._looks_like_soft_404(result, soft_404, path):
                return
            item = f"{path} ({result.status})"
            discovered.append(item)
            if sensitive:
                exposed_files.append(item)
                confirmed_content = self._has_sensitive_content(result.text)
                severity = "High" if result.status == 200 and confirmed_content else "Medium"
                findings.append(
                    Finding(
                        target=ctx.target.display,
                        category="Recon/Sensitive Exposure",
                        severity=severity,
                        title=f"Sensitive path discovered: {path}",
                        url=url,
                        endpoint=path,
                        method="GET",
                        status=str(result.status),
                        size=f"{result.body_len}b",
                        elapsed=f"{result.elapsed:.2f}s",
                        evidence=(
                            f"Sensitive marker matched in path. ConfirmedContent={confirmed_content} | "
                            f"Content-Type={result.content_type or '-'}"
                        ),
                        source=self.name,
                        confidence="high" if confirmed_content else "medium",
                    )
                )

        await asyncio.gather(*(probe(path) for path in paths[:path_budget]))
        ctx.recon["wordlist_path_hits"] = list(
            ctx.recon.get("wordlist_path_hits", []) + sorted(wordlist_hits, key=lambda item: (item["status"], item["path"]))
        )
        ctx.recon["discovered_paths"] = sorted(set(discovered))[:500]
        ctx.recon["exposed_files"] = sorted(set(exposed_files))[:200]
        return findings

    def _wordlist_hit_record(
        self,
        *,
        ctx: ScanContext,
        path: str,
        url: str,
        result: Any,
        soft404_filtered: bool,
        sensitive: bool,
    ) -> dict[str, Any]:
        location = result.headers.get("Location") or result.headers.get("location") or ""
        soft_auth_reason = soft_auth_redirect_reason(result, None, path)
        return {
            "target": ctx.target.display,
            "ip": ctx.target.ip,
            "module": self.name,
            "wordlist": "rutas.txt",
            "method": "GET",
            "status": result.status,
            "url": url,
            "path": path,
            "redirect_location": location,
            "content_type": result.content_type or "",
            "size_bytes": result.body_len,
            "time_seconds": f"{result.elapsed:.2f}",
            "title": self._title(result.text),
            "soft404_filtered": soft404_filtered,
            "sensitive_marker": sensitive,
            "notes": soft_auth_reason or ("soft404-like response" if soft404_filtered else "wordlist HTTP hit"),
        }

    async def _soft_404_baseline(self, ctx: ScanContext) -> Any:
        token = f"/scan-titan-soft404-{random.randint(100000, 999999)}"
        return await ctx.http.request("GET", urllib.parse.urljoin(ctx.target.url, token), allow_redirects=False)

    def _looks_like_soft_404(self, result: Any, baseline: Any, request_path: str | None = None) -> bool:
        if result and is_soft_auth_redirect(result, baseline, request_path):
            return True
        if not baseline or result.status != baseline.status:
            return False
        size_delta = abs(result.body_len - baseline.body_len)
        tolerance = max(100, int(max(result.body_len, baseline.body_len) * 0.08))
        if size_delta > tolerance:
            return False
        result_title = self._title(result.text)
        baseline_title = self._title(baseline.text)
        return bool(result_title and baseline_title and result_title == baseline_title)

    def _has_sensitive_content(self, body: str) -> bool:
        lower = body.lower()
        return any(marker.lower() in lower for marker in self.SENSITIVE_CONTENT)

    def _title(self, body: str) -> str:
        match = re.search(r"<title[^>]*>(.*?)</title>", body or "", re.IGNORECASE | re.DOTALL)
        return re.sub(r"\s+", " ", match.group(1)).strip().lower() if match else ""

    async def _subdomains(self, ctx: ScanContext) -> list[str]:
        if ctx.target.is_ip:
            return []
        words = ctx.wordlists.get("subdomains") or ["www", "api", "portal", "admin", "dev", "test", "vpn"]
        words = list(dict.fromkeys(words[: ctx.limits.max_tests_per_module]))
        semaphore = asyncio.Semaphore(10)

        async def resolve(word: str) -> str | None:
            async with semaphore:
                await asyncio.sleep(random.uniform(0.05, 0.2))
                fqdn = word if word.endswith(f".{ctx.target.host}") else f"{word}.{ctx.target.host}"
                try:
                    ip = await asyncio.to_thread(socket.gethostbyname, fqdn)
                    return f"{fqdn}={ip}"
                except OSError:
                    return None

        out = []
        for idx, result in enumerate(await asyncio.gather(*(resolve(w) for w in words)), start=1):
            if idx == 1 or idx % 50 == 0:
                ctx.heartbeat("subdomain_bruteforce", ctx.target.host, idx, len(out))
            if result:
                out.append(result)
        return sorted(set(out))

    def _detect_technologies(self, body: str, headers: dict[str, str]) -> list[str]:
        tech = set()
        if headers.get("Server"):
            tech.add(f"Server:{headers['Server']}")
        if headers.get("X-Powered-By"):
            tech.add(f"Backend:{headers['X-Powered-By']}")
        lower = body.lower()
        markers = {
            "WordPress": ["wp-content", "wp-includes"],
            "Drupal": ["drupal", "sites/default"],
            "Joomla": ["joomla", "/media/jui/"],
            "React": ["react", "__react"],
            "Next.js": ["__next_data__"],
            "Vue.js": ["vue", "v-cloak"],
            "Angular": ["ng-version", "ng-app"],
            "jQuery": ["jquery"],
            "Bootstrap": ["bootstrap"],
            "Laravel": ["laravel"],
            "Django": ["django"],
            "Spring": ["spring"],
            "Express": ["express"],
        }
        for name, values in markers.items():
            if any(v in lower for v in values):
                tech.add(name)
        return sorted(tech)

    def _extract_js(self, base_url: str, soup: Any) -> list[str]:
        libs = set()
        for script in soup.find_all("script"):
            src = script.get("src")
            text = script.get_text() or ""
            if src:
                full = urllib.parse.urljoin(base_url, src)
                libs.add(full)
                lower = full.lower()
            else:
                lower = text.lower()
            for name in ["jquery", "bootstrap", "react", "vue", "angular", "axios", "lodash", "moment"]:
                if name in lower:
                    libs.add(name)
        return sorted(libs)[:200]

    def _extract_login_forms(self, base_url: str, soup: Any) -> list[str]:
        forms = []
        for form in soup.find_all("form"):
            action = urllib.parse.urljoin(base_url, form.get("action") or base_url)
            has_password = bool(form.find("input", {"type": "password"}))
            if has_password or "login" in action.lower():
                forms.append(action)
        return sorted(set(forms))[:100]

    def _extract_endpoints(self, base_url: str, soup: Any, host: str) -> list[dict[str, Any]]:
        endpoints = []
        tags = list(soup.find_all(["a", "area"], href=True)) + list(soup.find_all("form", action=True))
        for tag in tags:
            raw = tag.get("href") or tag.get("action")
            url = urllib.parse.urljoin(base_url, raw)
            parsed = urllib.parse.urlparse(url)
            if parsed.hostname != host:
                continue
            params = list(urllib.parse.parse_qs(parsed.query).keys())
            endpoints.append({"url": url, "params": params})
        return endpoints[:300]

    def _extract_websockets(self, body: str) -> list[str]:
        return sorted(set(re.findall(r"wss?://[^\s'\"<>]+", body)))[:100]

    def _path(self, value: str) -> str:
        clean = "/" + str(value or "").strip().lstrip("/")
        return clean if clean != "/" else "/"
