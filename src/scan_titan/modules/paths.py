from __future__ import annotations

import asyncio
import random
import re
import urllib.parse
from pathlib import PurePosixPath
from typing import Any

from .common import (
    Finding,
    ScanContext,
    VulnerabilityModule,
    is_soft_auth_redirect,
    record_probe_timeout,
    run_bounded,
    soft_auth_redirect_reason,
)
from .soft_not_found import SoftNotFoundOracle


class PathDiscoveryModule(VulnerabilityModule):
    name = "path_discovery"
    WORDLIST_HIT_STATUSES = {200, 301, 302, 403, 500}

    DEFAULT_PATHS = [
        "/admin",
        "/administrator",
        "/login",
        "/dashboard",
        "/manager",
        "/portal",
        "/api",
        "/api/v1",
        "/api/v2",
        "/swagger",
        "/swagger.json",
        "/openapi.json",
        "/graphql",
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
        "/actuator",
        "/actuator/env",
        "/metrics",
    ]

    # Always tested first. The route wordlist has 1.6M alphabetical lines and is
    # truncated to the module budget, which used to drop every high-value path.
    HIGH_VALUE_PATHS = [
        "/.env", "/.env.local", "/.env.production", "/.env.backup", "/.env.bak", "/.env.old", "/.env.example",
        "/.git/HEAD", "/.git/config", "/.git/index", "/.gitignore", "/.svn/entries", "/.svn/wc.db", "/.hg/hgrc",
        "/.DS_Store", "/.htaccess", "/.htpasswd", "/.npmrc", "/.dockercfg", "/.docker/config.json",
        "/.aws/credentials", "/.ssh/id_rsa", "/id_rsa", "/.bash_history",
        "/config.php.bak", "/wp-config.php.bak", "/wp-config.php~", "/wp-config.old", "/configuration.php.bak",
        "/config.json", "/config.yml", "/config.yaml", "/settings.py", "/application.properties",
        "/application.yml", "/appsettings.Development.json", "/web.config.bak", "/database.yml",
        "/backup.sql", "/dump.sql", "/database.sql", "/db.sql", "/backup.tar", "/site.zip", "/www.zip",
        "/phpinfo.php", "/info.php", "/test.php", "/server-info", "/server-status",
        "/actuator/env", "/actuator/heapdump", "/actuator/configprops", "/actuator/mappings", "/actuator/health",
        "/env", "/trace", "/heapdump", "/jolokia", "/metrics", "/debug/vars", "/debug/pprof/",
        "/elmah.axd", "/trace.axd", "/_profiler/phpinfo", "/telescope", "/horizon", "/__debug__/",
        "/swagger-ui.html", "/swagger/index.html", "/v2/api-docs", "/v3/api-docs", "/api-docs",
        "/graphiql", "/console", "/h2-console", "/adminer.php", "/phpmyadmin/", "/storage/logs/laravel.log",
        "/crossdomain.xml", "/clientaccesspolicy.xml", "/sitemap.xml", "/robots.txt", "/security.txt",
        "/.well-known/security.txt",
    ]

    SENSITIVE_MARKERS = {
        ".env",
        ".git",
        "backup",
        "config",
        "secret",
        "private",
        "debug",
        "actuator",
        "server-status",
        "phpinfo",
    }
    SENSITIVE_CONTENT = [
        "[core]",
        "APP_KEY=",
        "DB_PASSWORD",
        "BEGIN RSA PRIVATE KEY",
        "phpinfo()",
        "SERVER_SOFTWARE",
        "root:x:",
        "Index of /",
        "ref: refs/heads/",
        "[remote \"",
        "DB_HOST=",
        "AWS_SECRET_ACCESS_KEY",
        "-----BEGIN OPENSSH PRIVATE KEY",
        '"propertySources"',
        '"activeProfiles"',
        "<connectionStrings",
        "<machineKey",
    ]
    # Real but lower-impact content: dependency manifests and API descriptions.
    LOW_CONTENT = ['"dependencies"', '"require"', '"openapi"', '"swagger"', '"paths"']

    async def run(self, ctx: ScanContext) -> list[Finding]:
        raw_paths = ctx.wordlists.get("rutas") or self.DEFAULT_PATHS
        paths = self._prioritized_paths(raw_paths, ctx.limits.max_tests_per_module)
        findings: list[Finding] = []
        discovered: list[str] = []
        login_forms: list[str] = []
        wordlist_hits: list[dict[str, Any]] = []
        tested = 0
        soft_404 = await self._soft_404_baseline(ctx)
        oracle = SoftNotFoundOracle.for_context(ctx)
        filtered_soft: list[dict[str, str]] = []

        async def probe(path: str) -> None:
            nonlocal tested
            url = urllib.parse.urljoin(ctx.target.url, path)
            result = await ctx.http.request_route(url)
            tested += 1
            if tested == 1 or tested % 25 == 0:
                ctx.heartbeat(self.name, path, tested, len(findings))
            if not result:
                return
            soft_reason = ""
            if result.status in self.WORDLIST_HIT_STATUSES or result.status == 401:
                soft_reason = await oracle.verdict(url, result, path)
            if result.status in self.WORDLIST_HIT_STATUSES:
                soft404_filtered = bool(soft_reason)
                lower_path = path.lower()
                sensitive = any(marker in lower_path for marker in self.SENSITIVE_MARKERS)
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
            if soft_reason:
                if len(filtered_soft) < 200:
                    filtered_soft.append({"path": path, "status": str(result.status), "reason": soft_reason})
                return
            item = f"{path} ({result.status})"
            discovered.append(item)
            lower_path = path.lower()
            lower_body = result.text.lower()
            if "login" in lower_path or "password" in lower_body:
                login_forms.append(item)
            sensitive = any(marker in lower_path for marker in self.SENSITIVE_MARKERS)
            # A finding needs proof in the body. A 401/403 only shows the control
            # works, and a sensitive-looking name without content proves nothing:
            # both stay in recon (discovered_paths / Recon Matrix).
            confirmed_content = result.status == 200 and self._has_sensitive_content(result.text)
            low_content = result.status == 200 and not confirmed_content and self._has_low_content(result.text)
            if confirmed_content or low_content:
                listing_only = confirmed_content and self._content_markers(result.text) == ["Index of /"]
                severity = "Medium" if listing_only else ("High" if confirmed_content else "Low")
                findings.append(
                    Finding(
                        target=ctx.target.display,
                        category="Discovery",
                        severity=severity,
                        title=f"Exposed or restricted path: {path}",
                        url=url,
                        endpoint=path,
                        method="GET",
                        status=str(result.status),
                        size=f"{result.body_len}b",
                        elapsed=f"{result.elapsed:.2f}s",
                        evidence=(
                            f"Sensitive={sensitive} | ConfirmedContent={confirmed_content} | "
                            f"Marcadores={','.join(self._content_markers(result.text)) or 'manifiesto/API'} | "
                            f"Content-Type={result.content_type or '-'} | "
                            "Respuesta distinta de la de una ruta inexistente con la misma extension"
                        ),
                        source=self.name,
                        confidence="high" if confirmed_content else "medium",
                    )
                )
            if result.status in {401, 403}:
                bypass = await self._try_403_bypass(ctx, path, result, soft_404)
                if bypass:
                    findings.append(bypass)

        await run_bounded(
            paths,  # already prioritized and bounded by _prioritized_paths
            probe,
            limit=12,
            should_stop=ctx.should_stop,
            item_timeout=max(30.0, float(ctx.limits.timeout) * 6.0),
            on_timeout=lambda item, seconds: record_probe_timeout(ctx, self.name, item, seconds),
        )
        ctx.recon["wordlist_path_hits"] = list(
            ctx.recon.get("wordlist_path_hits", []) + sorted(wordlist_hits, key=lambda item: (item["status"], item["path"]))
        )
        findings.extend(await self._directory_listings(ctx, oracle))
        ctx.recon["soft404_filtered_paths"] = list(ctx.recon.get("soft404_filtered_paths", []) + filtered_soft)[:400]
        ctx.recon["discovered_paths"] = sorted(set(ctx.recon.get("discovered_paths", []) + discovered))[:500]
        ctx.recon["login_forms"] = sorted(set(ctx.recon.get("login_forms", []) + login_forms))[:50]
        return findings

    LISTING_DIRS = ["/static/", "/uploads/", "/upload/", "/files/", "/images/", "/img/", "/assets/", "/media/",
                    "/backup/", "/backups/", "/logs/", "/log/", "/tmp/", "/temp/", "/public/", "/download/",
                    "/downloads/", "/data/", "/docs/", "/export/", "/reports/", "/storage/"]
    LISTING_SIGNATURES = re.compile(
        r"<title>\s*index of /|<h1>\s*index of /|directory listing for /|\[to parent directory\]|"
        r"<a href=\"\?C=N;O=D\">|>parent directory</a>", re.IGNORECASE)

    async def _directory_listings(self, ctx: ScanContext, oracle: SoftNotFoundOracle) -> list[Finding]:
        """Directories that answer with a real index page (Apache, Nginx, IIS, Python, Tomcat)."""
        origin = urllib.parse.urlsplit(ctx.target.url)
        dirs: list[str] = []
        urls = [item.get("url", "") for item in ctx.recon.get("endpoints", []) if isinstance(item, dict)]
        urls += [str(item) for item in ctx.recon.get("urls", []) or [] if isinstance(item, str)]
        for url in urls:
            parsed = urllib.parse.urlsplit(url)
            if (parsed.scheme, parsed.netloc) != (origin.scheme, origin.netloc):
                continue
            path = parsed.path or "/"
            dirs.append(path if path.endswith("/") else path.rsplit("/", 1)[0] + "/")
        candidates = [d for d in dict.fromkeys(dirs + self.LISTING_DIRS) if d != "/"][:40]
        findings: list[Finding] = []
        for directory in candidates:
            if ctx.should_stop():
                break
            url = urllib.parse.urljoin(ctx.target.url, directory)
            result = await ctx.http.request("GET", url, allow_redirects=False)
            if not result or result.status != 200 or not self.LISTING_SIGNATURES.search(result.text[:20000]):
                continue
            if await oracle.verdict(url, result, directory):
                continue
            entries = re.findall(r'href="([^"?#/][^"?#]*)"', result.text[:20000])[:8]
            findings.append(Finding(
                target=ctx.target.display, category="Discovery", severity="Medium",
                title=f"Directory listing enabled: {directory}", url=url, endpoint=directory, method="GET",
                status=str(result.status), size=f"{result.body_len}b",
                evidence=f"Indice del servidor con entradas: {', '.join(entries) or '-'}",
                source=self.name, confidence="high", evidence_strength="strong", false_positive_risk="low",
                cwe="CWE-548",
            ))
        return findings

    def _prioritized_paths(self, raw_paths: list[str], budget: int) -> list[str]:
        """High-value paths first, then wordlist entries with sensitive markers, then the rest."""
        budget = max(1, int(budget or 1))
        curated = [self._normalize_path(p) for p in self.HIGH_VALUE_PATHS + self.DEFAULT_PATHS]
        sensitive, ordinary = [], []
        for raw in raw_paths:
            value = str(raw or "").strip()
            if not value or value.startswith("#") or any(ch in value for ch in "\"<>{}|^`$!*'"):
                continue  # junk lines of public lists ("! Game title", "$100_laptop", quoted JSON...)
            path = self._normalize_path(value)
            (sensitive if any(marker in path.lower() for marker in self.SENSITIVE_MARKERS) else ordinary).append(path)
            if len(sensitive) + len(ordinary) >= budget * 3:
                break
        return list(dict.fromkeys(curated + sensitive + ordinary))[:max(budget, len(curated))]

    def _normalize_path(self, value: str) -> str:
        path = "/" + str(value or "").strip().lstrip("/")
        parsed = urllib.parse.urlparse(path)
        clean = parsed.path or "/"
        if clean != "/" and clean.endswith("//"):
            clean = clean.rstrip("/")
        return str(PurePosixPath(clean)) if clean != "/" else clean

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

    async def _soft_404_baseline(self, ctx: ScanContext):
        token = f"/scan-titan-soft404-{random.randint(100000, 999999)}"
        return await ctx.http.request("GET", urllib.parse.urljoin(ctx.target.url, token), allow_redirects=False)

    async def _try_403_bypass(
        self,
        ctx: ScanContext,
        path: str,
        original: Any,
        soft_404: Any,
    ) -> Finding | None:
        url = urllib.parse.urljoin(ctx.target.url, path)
        for label, headers in self._bypass_headers(path):
            result = await ctx.http.request("GET", url, headers=headers, allow_redirects=False)
            if self._bypass_success(result, original, soft_404) and not await self._soft(ctx, url, result, path):
                return Finding(
                    target=ctx.target.display,
                    category="Discovery",
                    severity="High",
                    title=f"Authorization bypass signal: {path}",
                    url=url,
                    endpoint=path,
                    method="GET",
                    status=f"{original.status}->{result.status}",
                    size=f"{original.body_len}b->{result.body_len}b",
                    elapsed=f"{result.elapsed:.2f}s",
                    evidence=f"403 bypass header accepted: {label}",
                    source=self.name,
                    confidence="medium",
                )
        for bypass_path in self._bypass_path_variants(path, ctx.wordlists.get("403bypass", [])):
            bypass_url = urllib.parse.urljoin(ctx.target.url, bypass_path)
            result = await ctx.http.request("GET", bypass_url, allow_redirects=False)
            if self._bypass_success(result, original, soft_404) and not await self._soft(ctx, bypass_url, result, bypass_path):
                return Finding(
                    target=ctx.target.display,
                    category="Discovery",
                    severity="High",
                    title=f"Authorization bypass signal: {path}",
                    url=urllib.parse.urljoin(ctx.target.url, bypass_path),
                    endpoint=bypass_path,
                    method="GET",
                    status=f"{original.status}->{result.status}",
                    size=f"{original.body_len}b->{result.body_len}b",
                    elapsed=f"{result.elapsed:.2f}s",
                    evidence=f"403 bypass path variant accepted for original path {path}",
                    source=self.name,
                    confidence="medium",
                )
        return None

    async def _soft(self, ctx: ScanContext, url: str, result: Any, path: str) -> str:
        return await SoftNotFoundOracle.for_context(ctx).verdict(url, result, path)

    def _bypass_success(self, result: Any, original: Any, soft_404: Any) -> bool:
        if not result or result.status != 200:
            return False
        if self._looks_like_soft_404(result, soft_404):
            return False
        lower = result.text.lower()
        if "password" in lower and any(token in lower for token in ["login", "sign in", "username", "email"]):
            return False
        return result.body_len > 80 and abs(result.body_len - original.body_len) > 40

    def _bypass_headers(self, path: str) -> list[tuple[str, dict[str, str]]]:
        clean_path = "/" + str(path or "").lstrip("/")
        return [
            ("X-Original-URL", {"X-Original-URL": clean_path}),
            ("X-Rewrite-URL", {"X-Rewrite-URL": clean_path}),
            ("X-Custom-IP-Authorization", {"X-Custom-IP-Authorization": "127.0.0.1"}),
            ("X-Forwarded-For", {"X-Forwarded-For": "127.0.0.1"}),
            ("X-Real-IP", {"X-Real-IP": "127.0.0.1"}),
            ("X-Originating-IP", {"X-Originating-IP": "127.0.0.1"}),
        ]

    def _bypass_path_variants(self, path: str, values: list[str]) -> list[str]:
        target_name = str(path or "").strip("/").split("/")[-1] or "admin"
        variants = []
        for raw in values[:120]:
            value = str(raw or "").strip()
            if not value or value.startswith("-H"):
                continue
            if "admin" in value.lower():
                candidate = re.sub("admin", target_name, value, flags=re.IGNORECASE)
            elif ".env" in value.lower() and target_name != ".env":
                candidate = re.sub(r"\.env", target_name, value, flags=re.IGNORECASE)
            else:
                candidate = value
            if target_name.lower() not in candidate.lower() and ".env" not in candidate.lower():
                continue
            variants.append(self._normalize_path(candidate))
            if len(variants) >= 14:
                break
        return list(dict.fromkeys(variants))

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

    def _content_markers(self, body: str) -> list[str]:
        lower = (body or "").lower()
        return [marker for marker in self.SENSITIVE_CONTENT if marker.lower() in lower]

    def _has_sensitive_content(self, body: str) -> bool:
        return bool(self._content_markers(body))

    def _has_low_content(self, body: str) -> bool:
        lower = (body or "")[:20000].lower()
        if "<html" in lower[:500]:
            return False
        return any(marker.lower() in lower for marker in self.LOW_CONTENT)

    def _title(self, body: str) -> str:
        match = re.search(r"<title[^>]*>(.*?)</title>", body or "", re.IGNORECASE | re.DOTALL)
        return re.sub(r"\s+", " ", match.group(1)).strip().lower() if match else ""
