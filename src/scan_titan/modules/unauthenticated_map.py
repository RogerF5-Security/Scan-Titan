from __future__ import annotations

import asyncio
import re
import urllib.parse
import xml.etree.ElementTree as ET
from collections import deque
from typing import Any

from bs4 import BeautifulSoup

from .common import (
    Finding,
    ScanContext,
    VulnerabilityModule,
    clean_text,
    is_soft_auth_redirect,
    soft_auth_redirect_reason,
)


class UnauthenticatedMapModule(VulnerabilityModule):
    name = "unauthenticated_map"

    HIT_STATUSES = {200, 204, 301, 302, 307, 308, 401, 403, 405, 500}
    MAX_WORDLIST_CANDIDATES = 10000
    MAX_DIRECTORY_INDEX_ITEMS = 350
    MAX_WORKERS = 8

    DEFAULT_PATHS = [
        "/",
        "/login/",
        "/login",
        "/login_post/",
        "/login_post",
        "/procesarlogin/",
        "/procesarlogin",
        "/dashboard/",
        "/dashboard",
        "/home/",
        "/inicio/",
        "/logout/",
        "/logout",
        "/admin/",
        "/admin",
        "/accounts/login/",
        "/accounts/logout/",
        "/password_reset/",
        "/reset/",
        "/profile/",
        "/perfil/",
        "/tickets/",
        "/tickets",
        "/ticket/",
        "/ticket",
        "/incidentes/",
        "/incidencias/",
        "/casos/",
        "/caso/",
        "/reportes/",
        "/reports/",
        "/usuarios/",
        "/users/",
        "/clientes/",
        "/client/",
        "/api/",
        "/api/v1/",
        "/docs/",
        "/swagger/",
        "/swagger-ui/",
        "/swagger.json",
        "/openapi.json",
        "/redoc/",
        "/graphql",
        "/health",
        "/healthz",
        "/status",
        "/metrics",
        "/debug/",
        "/server-status",
        "/server-status/",
        "/javascript",
        "/javascript/",
        "/static",
        "/static/",
        "/static/CSS/",
        "/static/js/",
        "/static/image/",
        "/static/admin/",
        "/robots.txt",
        "/sitemap.xml",
        "/.well-known/security.txt",
        "/.well-known/openid-configuration",
        "/.git/config",
        "/.env",
        "/favicon.ico",
        "/saml/login/",
        "/saml/login",
        "/saml/metadata/",
        "/saml/metadata",
        "/saml/acs/",
        "/saml/acs",
        "/saml/logout/",
        "/cerrarsesion/",
    ]

    RESIDUE_EXTENSIONS = (".save", ".bak", ".backup", ".old", ".orig", ".tmp", "~", ".swp")
    DIRECTORY_INDEX_MARKERS = ("index of /", "parent directory")

    async def run(self, ctx: ScanContext) -> list[Finding]:
        findings: list[Finding] = []
        soft_404 = await self._soft_404_baseline(ctx)
        candidates = self._candidate_paths(ctx)
        tested = 0
        records: list[dict[str, Any]] = []
        records_by_path: dict[str, dict[str, Any]] = {}

        async def probe(path: str) -> None:
            nonlocal tested
            tested += 1
            if tested == 1 or tested % 50 == 0:
                ctx.heartbeat(self.name, path, tested, len(records))
            result = await ctx.http.request(
                "GET",
                urllib.parse.urljoin(ctx.target.url, path),
                allow_redirects=False,
                timeout=min(ctx.limits.timeout, 8),
            )
            if not result or result.status not in self.HIT_STATUSES:
                return
            record = self._route_record(ctx, path, result, soft_404, source="route_probe")
            if record["classification"] == "soft404_like":
                return
            records.append(record)
            records_by_path[path] = record

        await self._run_bounded(candidates, probe)

        directory_records = await self._crawl_directory_indexes(ctx, records_by_path)
        records.extend(directory_records)

        saml_findings = await self._analyze_saml_metadata(ctx, records_by_path)
        findings.extend(saml_findings)

        records = self._dedupe_records(records)
        self._merge_recon(ctx, records)
        findings.extend(self._findings_from_records(ctx, records))
        return findings

    def _candidate_paths(self, ctx: ScanContext) -> list[str]:
        budget = max(len(self.DEFAULT_PATHS), min(ctx.limits.max_tests_per_module, self.MAX_WORDLIST_CANDIDATES))
        raw_paths = ctx.wordlists.get("rutas") or []
        candidates = [self._path(value) for value in self.DEFAULT_PATHS]
        candidates.extend(self._path(value) for value in raw_paths[:budget])
        return list(dict.fromkeys(path for path in candidates if path))[: budget + len(self.DEFAULT_PATHS)]

    async def _run_bounded(self, items: list[str], worker: Any) -> None:
        semaphore = asyncio.Semaphore(self.MAX_WORKERS)

        async def guarded(item: str) -> None:
            async with semaphore:
                await worker(item)

        await asyncio.gather(*(guarded(item) for item in items))

    async def _crawl_directory_indexes(
        self,
        ctx: ScanContext,
        records_by_path: dict[str, dict[str, Any]],
    ) -> list[dict[str, Any]]:
        out: list[dict[str, Any]] = []
        queue: deque[str] = deque(
            path
            for path, record in records_by_path.items()
            if record.get("classification") == "directory_listing"
        )
        seen = set(queue)
        processed = 0
        while queue and len(seen) < self.MAX_DIRECTORY_INDEX_ITEMS:
            path = queue.popleft()
            record = records_by_path.get(path)
            if not record:
                continue
            for child in self._directory_links(ctx.target.url, path, record.get("body_sample", "")):
                if child in seen or len(seen) >= self.MAX_DIRECTORY_INDEX_ITEMS:
                    continue
                seen.add(child)
                processed += 1
                if processed == 1 or processed % 50 == 0:
                    ctx.heartbeat(self.name, child, processed, len(out))
                method = "GET" if child.endswith("/") else "HEAD"
                result = await ctx.http.request(
                    method,
                    urllib.parse.urljoin(ctx.target.url, child),
                    allow_redirects=False,
                    timeout=min(ctx.limits.timeout, 8),
                )
                if result and result.status == 405 and method == "HEAD":
                    result = await ctx.http.request(
                        "GET",
                        urllib.parse.urljoin(ctx.target.url, child),
                        allow_redirects=False,
                        timeout=min(ctx.limits.timeout, 8),
                    )
                    method = "GET"
                if not result or result.status not in self.HIT_STATUSES:
                    continue
                child_record = self._route_record(
                    ctx,
                    child,
                    result,
                    baseline=None,
                    source="directory_index_crawl",
                    method=method,
                )
                records_by_path[child] = child_record
                out.append(child_record)
                if child.endswith("/") and child_record.get("classification") == "directory_listing":
                    queue.append(child)
        return out

    def _directory_links(self, base_url: str, current_path: str, body: str) -> list[str]:
        soup = BeautifulSoup(body or "", "html.parser")
        links: list[str] = []
        base = urllib.parse.urljoin(base_url, current_path)
        base_host = urllib.parse.urlparse(base_url).netloc
        current_prefix = current_path if current_path.endswith("/") else f"{current_path}/"
        for tag in soup.find_all("a", href=True)[:300]:
            href = str(tag.get("href") or "")
            if not href or href.startswith("?") or href.startswith("/icons/"):
                continue
            url = urllib.parse.urljoin(base, href)
            parsed = urllib.parse.urlparse(url)
            if parsed.netloc != base_host:
                continue
            path = parsed.path or "/"
            if path == current_path or path == "/":
                continue
            if not path.startswith(current_prefix) and not path.startswith("/static/"):
                continue
            links.append(path)
        return list(dict.fromkeys(links))

    async def _analyze_saml_metadata(
        self,
        ctx: ScanContext,
        records_by_path: dict[str, dict[str, Any]],
    ) -> list[Finding]:
        record = records_by_path.get("/saml/metadata/") or records_by_path.get("/saml/metadata")
        if not record or record.get("status") != 200:
            return []
        body = str(record.get("body_sample") or "")
        metadata = self._parse_saml_metadata(body)
        if metadata:
            ctx.recon["saml_metadata"] = metadata
            record["notes"] = self._saml_notes(ctx, metadata)
        mismatches = self._saml_mismatches(ctx, metadata)
        if not mismatches:
            return [
                Finding(
                    target=ctx.target.display,
                    category="Recon/SAML",
                    severity="Info",
                    title="SAML metadata endpoint is publicly reachable",
                    url=record.get("url", ""),
                    endpoint=record.get("path", ""),
                    method="GET",
                    status=str(record.get("status", "")),
                    evidence=clean_text(record.get("notes") or "Metadata endpoint returned XML", 900),
                    source=self.name,
                    confidence="high",
                )
            ]
        return [
            Finding(
                target=ctx.target.display,
                category="Recon/SAML",
                severity="Medium",
                title="SAML metadata appears inconsistent with scanned target",
                url=record.get("url", ""),
                endpoint=record.get("path", ""),
                method="GET",
                status=str(record.get("status", "")),
                evidence=clean_text(" | ".join(mismatches), 1000),
                source=self.name,
                confidence="medium",
                cwe="CWE-346",
                owasp="A02:2025 - Configuración de seguridad incorrecta",
                remediation=(
                    "Publish SAML metadata whose entityID, ACS and SLO URLs match the QA host, scheme and port "
                    "used by the service provider."
                ),
            )
        ]

    def _parse_saml_metadata(self, body: str) -> dict[str, Any]:
        if not body.strip():
            return {}
        try:
            root = ET.fromstring(body.encode("utf-8", errors="ignore"))
        except ET.ParseError:
            return {}
        ns = {
            "md": "urn:oasis:names:tc:SAML:2.0:metadata",
            "ds": "http://www.w3.org/2000/09/xmldsig#",
        }
        acs = [
            {
                "binding": node.attrib.get("Binding", ""),
                "location": node.attrib.get("Location", ""),
                "index": node.attrib.get("index", ""),
            }
            for node in root.findall(".//md:AssertionConsumerService", ns)
        ]
        slo = [
            {
                "binding": node.attrib.get("Binding", ""),
                "location": node.attrib.get("Location", ""),
            }
            for node in root.findall(".//md:SingleLogoutService", ns)
        ]
        certs = root.findall(".//ds:X509Certificate", ns)
        return {
            "entity_id": root.attrib.get("entityID", ""),
            "valid_until": root.attrib.get("validUntil", ""),
            "cache_duration": root.attrib.get("cacheDuration", ""),
            "acs": acs,
            "slo": slo,
            "x509_cert_count": len(certs),
        }

    def _saml_notes(self, ctx: ScanContext, metadata: dict[str, Any]) -> str:
        acs = ", ".join(item.get("location", "") for item in metadata.get("acs", []) if item.get("location"))
        slo = ", ".join(item.get("location", "") for item in metadata.get("slo", []) if item.get("location"))
        return (
            f"entityID={metadata.get('entity_id') or '-'} | ACS={acs or '-'} | SLO={slo or '-'} | "
            f"x509_cert_count={metadata.get('x509_cert_count', 0)}"
        )

    def _saml_mismatches(self, ctx: ScanContext, metadata: dict[str, Any]) -> list[str]:
        if not metadata:
            return ["SAML metadata is not valid XML metadata"]
        expected = urllib.parse.urlparse(ctx.target.url)
        expected_netloc = expected.netloc.lower()
        expected_scheme = expected.scheme.lower()
        mismatches: list[str] = []
        entity_id = metadata.get("entity_id") or ""
        if entity_id:
            parsed_entity = urllib.parse.urlparse(entity_id)
            if parsed_entity.scheme and parsed_entity.scheme.lower() != expected_scheme:
                mismatches.append(f"entityID scheme {parsed_entity.scheme} differs from target {expected_scheme}")
            if parsed_entity.netloc and parsed_entity.netloc.lower() != expected_netloc:
                mismatches.append(f"entityID netloc {parsed_entity.netloc} differs from target {expected_netloc}")
        for label, urls in [
            ("ACS", [item.get("location", "") for item in metadata.get("acs", [])]),
            ("SLO", [item.get("location", "") for item in metadata.get("slo", [])]),
        ]:
            for url in urls:
                parsed = urllib.parse.urlparse(url)
                if parsed.scheme and parsed.scheme.lower() != expected_scheme:
                    mismatches.append(f"{label} scheme {parsed.scheme} differs from target {expected_scheme}")
                if parsed.netloc and parsed.netloc.lower() != expected_netloc:
                    mismatches.append(f"{label} netloc {parsed.netloc} differs from target {expected_netloc}")
        return mismatches

    def _route_record(
        self,
        ctx: ScanContext,
        path: str,
        result: Any,
        baseline: Any,
        *,
        source: str,
        method: str = "GET",
    ) -> dict[str, Any]:
        location = result.headers.get("Location") or result.headers.get("location") or ""
        classification = self._classification(path, result, baseline, location)
        title = self._title(result.text)
        notes = self._notes(path, result, classification, location)
        return {
            "target": ctx.target.display,
            "ip": ctx.target.ip,
            "module": self.name,
            "wordlist": "rutas.txt+smart_seeds",
            "method": method,
            "status": result.status,
            "url": urllib.parse.urljoin(ctx.target.url, path),
            "path": path,
            "redirect_location": location,
            "content_type": result.content_type or "",
            "size_bytes": result.body_len,
            "time_seconds": f"{result.elapsed:.2f}",
            "title": title,
            "soft404_filtered": classification == "soft404_like",
            "sensitive_marker": self._sensitive_path(path, classification),
            "classification": classification,
            "evidence_summary": notes,
            "notes": notes,
            "source": source,
            "body_sample": result.text[:120000] if classification in {"directory_listing", "saml_metadata"} else result.text[:2000],
        }

    def _classification(self, path: str, result: Any, baseline: Any, location: str) -> str:
        if baseline and self._looks_like_soft_404(result, baseline, path):
            return "soft404_like"
        lower_path = path.lower()
        lower_body = (result.text or "").lower()
        lower_type = (result.content_type or "").lower()
        if result.status == 403:
            return "forbidden"
        if result.status == 405:
            return "method_not_allowed"
        if result.status in {301, 302, 307, 308}:
            if "samlrequest=" in location.lower():
                return "saml_login_redirect"
            if location in {"/", "./"} or "/login" in location.lower():
                return "redirect_to_login"
            return "redirect"
        if result.status == 401:
            return "auth_required"
        if result.status != 200:
            return "http_hit"
        if "saml/metadata" in lower_path or ("xml" in lower_type and "entitydescriptor" in lower_body):
            return "saml_metadata"
        if self._is_directory_index(lower_body):
            return "directory_listing"
        if "csrfmiddlewaretoken" in lower_body and any(token in lower_body for token in ["password", "contraseña", "login"]):
            return "login_page"
        if lower_path.endswith(self.RESIDUE_EXTENSIONS):
            return "static_residue"
        if lower_path.startswith("/static/") or self._looks_like_static_asset(lower_path, lower_type):
            return "static_asset"
        return "public_200"

    def _notes(self, path: str, result: Any, classification: str, location: str) -> str:
        values = [
            f"classification={classification}",
            f"content_type={result.content_type or '-'}",
            f"size={result.body_len}b",
        ]
        if location:
            values.append(f"redirect={location}")
        soft_auth_reason = soft_auth_redirect_reason(result, None, path)
        if soft_auth_reason:
            values.append(soft_auth_reason)
        if classification == "directory_listing":
            values.append("Apache-style directory index is enabled")
        if classification == "static_residue":
            values.append("backup/editor residue extension exposed")
        if path.lower().startswith("/server-status"):
            values.append("server-status endpoint present")
        return " | ".join(values)

    def _findings_from_records(self, ctx: ScanContext, records: list[dict[str, Any]]) -> list[Finding]:
        findings: list[Finding] = []
        directory_listings = [record for record in records if record.get("classification") == "directory_listing"]
        residues = [record for record in records if record.get("classification") == "static_residue"]
        protected = [
            record
            for record in records
            if record.get("classification") in {"forbidden", "auth_required", "method_not_allowed", "redirect_to_login"}
        ]
        dynamic = [
            record
            for record in records
            if not str(record.get("path", "")).startswith("/static/")
            and record.get("classification") not in {"static_asset", "soft404_like"}
        ]
        if dynamic:
            findings.append(
                Finding(
                    target=ctx.target.display,
                    category="Recon/Unauthenticated Sitemap",
                    severity="Info",
                    title="Unauthenticated route audit generated",
                    url=ctx.target.url,
                    evidence=clean_text(
                        f"Routes={len(dynamic)} | ProtectedOrGated={len(protected)} | "
                        f"Sample={self._route_sample(dynamic, 12)}",
                        1000,
                    ),
                    source=self.name,
                    confidence="high",
                )
            )
        if directory_listings:
            findings.append(
                Finding(
                    target=ctx.target.display,
                    category="Recon/Exposure",
                    severity="Medium",
                    title="Directory listing enabled on unauthenticated paths",
                    url=directory_listings[0].get("url", ctx.target.url),
                    endpoint=directory_listings[0].get("path", ""),
                    method="GET",
                    status=",".join(sorted({str(item.get("status", "")) for item in directory_listings})),
                    evidence=clean_text(self._route_sample(directory_listings, 20), 1000),
                    source=self.name,
                    confidence="high",
                    cwe="CWE-548",
                    owasp="A02:2025 - Configuración de seguridad incorrecta",
                    remediation="Disable Apache autoindex/Options Indexes and publish only required static artifacts.",
                )
            )
        if residues:
            findings.append(
                Finding(
                    target=ctx.target.display,
                    category="Recon/Exposure",
                    severity="Low",
                    title="Backup or editor residue files exposed in static tree",
                    url=residues[0].get("url", ctx.target.url),
                    endpoint=residues[0].get("path", ""),
                    method=residues[0].get("method", "GET"),
                    status=",".join(sorted({str(item.get("status", "")) for item in residues})),
                    evidence=clean_text(self._route_sample(residues, 20), 1000),
                    source=self.name,
                    confidence="medium",
                    cwe="CWE-530",
                    owasp="A02:2025 - Configuración de seguridad incorrecta",
                    remediation="Remove backup/editor files from web roots and block risky extensions at the web server.",
                )
            )
        return findings

    def _merge_recon(self, ctx: ScanContext, records: list[dict[str, Any]]) -> None:
        public_routes = [
            self._route_label(record)
            for record in records
            if not str(record.get("path", "")).startswith("/static/")
            and record.get("classification") not in {"static_asset", "soft404_like"}
        ]
        directory_listings = [
            self._route_label(record)
            for record in records
            if record.get("classification") == "directory_listing"
        ]
        residues = [
            self._route_label(record)
            for record in records
            if record.get("classification") == "static_residue"
        ]
        ctx.recon["unauthenticated_routes"] = sorted(set(ctx.recon.get("unauthenticated_routes", []) + public_routes))[:500]
        ctx.recon["directory_listings"] = sorted(set(ctx.recon.get("directory_listings", []) + directory_listings))[:300]
        ctx.recon["static_residue_files"] = sorted(set(ctx.recon.get("static_residue_files", []) + residues))[:200]
        ctx.recon["discovered_paths"] = sorted(
            set(ctx.recon.get("discovered_paths", []) + [self._route_label(record) for record in records])
        )[:1000]
        ctx.recon["exposed_files"] = sorted(
            set(ctx.recon.get("exposed_files", []) + directory_listings + residues)
        )[:300]
        existing = list(ctx.recon.get("wordlist_path_hits", []))
        stripped = [{key: value for key, value in record.items() if key != "body_sample"} for record in records]
        ctx.recon["wordlist_path_hits"] = existing + stripped

    def _route_label(self, record: dict[str, Any]) -> str:
        location = record.get("redirect_location") or ""
        suffix = f" -> {location}" if location else ""
        return f"{record.get('path')} ({record.get('status')} {record.get('classification')}){suffix}"

    def _route_sample(self, records: list[dict[str, Any]], limit: int) -> str:
        return " | ".join(self._route_label(record) for record in records[:limit])

    def _dedupe_records(self, records: list[dict[str, Any]]) -> list[dict[str, Any]]:
        out: list[dict[str, Any]] = []
        seen: set[tuple[str, str, int]] = set()
        for record in records:
            key = (str(record.get("method", "")), str(record.get("path", "")), int(record.get("status") or 0))
            if key in seen:
                continue
            seen.add(key)
            out.append(record)
        return sorted(out, key=lambda item: (str(item.get("status", "")), str(item.get("path", ""))))

    async def _soft_404_baseline(self, ctx: ScanContext) -> Any:
        token = "/scan-titan-route-audit-soft404-987654321"
        return await ctx.http.request(
            "GET",
            urllib.parse.urljoin(ctx.target.url, token),
            allow_redirects=False,
            timeout=min(ctx.limits.timeout, 8),
        )

    def _looks_like_soft_404(self, result: Any, baseline: Any, request_path: str | None = None) -> bool:
        if result and is_soft_auth_redirect(result, baseline, request_path):
            return True
        if not baseline or result.status != baseline.status:
            return False
        size_delta = abs(result.body_len - baseline.body_len)
        tolerance = max(100, int(max(result.body_len, baseline.body_len) * 0.08))
        if size_delta > tolerance:
            return False
        return self._title(result.text) == self._title(baseline.text)

    def _path(self, value: str) -> str:
        raw = str(value or "").strip()
        if not raw:
            return ""
        if raw.startswith(("http://", "https://")):
            parsed = urllib.parse.urlparse(raw)
            raw = parsed.path or "/"
        raw = "/" + raw.lstrip("/")
        parsed = urllib.parse.urlparse(raw)
        path = parsed.path or "/"
        if path != "/" and path.endswith("//"):
            path = path.rstrip("/")
        return path

    def _title(self, body: str) -> str:
        match = re.search(r"<title[^>]*>(.*?)</title>", body or "", re.IGNORECASE | re.DOTALL)
        return re.sub(r"\s+", " ", match.group(1)).strip() if match else ""

    def _is_directory_index(self, lower_body: str) -> bool:
        return all(marker in lower_body for marker in self.DIRECTORY_INDEX_MARKERS)

    def _looks_like_static_asset(self, lower_path: str, lower_type: str) -> bool:
        return any(
            token in lower_type
            for token in ["javascript", "text/css", "image/", "font/", "application/octet-stream"]
        ) or lower_path.endswith((".js", ".css", ".png", ".jpg", ".jpeg", ".gif", ".svg", ".ico", ".woff", ".woff2"))

    def _sensitive_path(self, path: str, classification: str) -> bool:
        lower = path.lower()
        return classification in {"directory_listing", "static_residue", "saml_metadata"} or any(
            token in lower
            for token in [".git", ".env", "server-status", "debug", "metrics", "swagger", "openapi", "admin"]
        )
