from __future__ import annotations

import hashlib
import re
import urllib.parse
from typing import Any

import aiohttp
from bs4 import BeautifulSoup

from .common import Finding, ScanContext, VulnerabilityModule, url_with_params
from .payload_utils import (
    lfi_payloads,
    sqli_payloads,
)


def _standalone_token(text: str, token: str) -> bool:
    """Match generated numeric proof without accepting a longer reflected number."""
    if not text or not token:
        return False
    return re.search(rf"(?<!\d){re.escape(token)}(?!\d)", text) is not None


def differential_output_proven(result: Any, baseline: Any, expected: str) -> bool:
    """Require a successful response with new transformed output absent from control."""
    if result is None or baseline is None:
        return False
    if int(getattr(result, "status", 0) or 0) >= 400:
        return False
    result_text = str(getattr(result, "text", "") or "")
    baseline_text = str(getattr(baseline, "text", "") or "")
    return _standalone_token(result_text, expected) and not _standalone_token(baseline_text, expected)


class InjectionModule(VulnerabilityModule):
    name = "injection"

    PARAMS = [
        "id",
        "q",
        "search",
        "query",
        "name",
        "user",
        "username",
        "email",
        "page",
        "file",
        "path",
        "template",
        "cmd",
        "host",
    ]
    SQL_PAYLOADS = [
        "'",
        "\"",
        "' OR '1'='1",
        "'/**/OR/**/'1'='1",
        "1' OR '1'='1'--",
        "' UNION SELECT NULL--",
    ]
    SQL_ERRORS = [
        "sql syntax",
        "mysql",
        "postgresql",
        "sqlite",
        "ora-",
        "odbc",
        "sqlstate",
        "unclosed quotation",
        "syntax error",
    ]
    LDAP_PAYLOADS = ["*", "*)(&", "*)(uid=*))(|(uid=*", "admin*"]
    LDAP_ERRORS = ["ldap", "invalid dn", "bad search filter", "operations error", "protocol error"]
    TRAVERSAL = [
        ("../../../etc/passwd", "root:x:"),
        ("..%2F..%2F..%2Fetc%2Fpasswd", "root:x:"),
        ("../../../windows/win.ini", "[extensions]"),
    ]
    async def run(self, ctx: ScanContext) -> list[Finding]:
        findings: list[Finding] = []
        candidates = self._candidates(ctx)
        findings.extend(await self._ldap(ctx, candidates))
        findings.extend(await self._command(ctx, candidates))
        findings.extend(await self._ssti(ctx, candidates))
        findings.extend(await self._file_upload(ctx))
        return findings

    async def _sqli(self, ctx: ScanContext, candidates: list[tuple[str, list[str]]]) -> list[Finding]:
        findings = []
        tested = 0
        budget = max(ctx.limits.max_tests_per_module, 36)
        payloads = sqli_payloads(ctx.wordlists, self.SQL_PAYLOADS, limit=budget)
        for url, params in candidates:
            for param in params[:12]:
                baseline = await ctx.http.request("GET", url, params={param: "scan_titan_control"})
                baseline_body = str(getattr(baseline, "text", "") or "").lower()
                for payload in payloads:
                    if tested >= ctx.limits.max_tests_per_module:
                        return findings
                    tested += 1
                    ctx.heartbeat("sqli", f"{param}={payload[:20]}", tested, len(findings))
                    result = await ctx.http.request("GET", url, params={param: payload})
                    result_body = str(getattr(result, "text", "") or "").lower() if result else ""
                    signatures = [
                        error for error in self.SQL_ERRORS if error in result_body and error not in baseline_body
                    ]
                    if result and signatures:
                        findings.append(
                            self._finding(
                                ctx,
                                "SQL Injection",
                                "Critical",
                                url,
                                param,
                                payload,
                                result,
                                f"Differential database error signature observed: {', '.join(signatures[:3])}.",
                            )
                        )
                        break
        return findings

    async def _ldap(self, ctx: ScanContext, candidates: list[tuple[str, list[str]]]) -> list[Finding]:
        findings = []
        tested = 0
        for url, params in candidates:
            for param in params[:12]:
                if not any(x in param.lower() for x in ["user", "uid", "login", "name", "filter", "search", "mail"]):
                    continue
                baseline = await ctx.http.request("GET", url, params={param: "scan_titan_control"})
                baseline_body = str(getattr(baseline, "text", "") or "").lower()
                for payload in self.LDAP_PAYLOADS:
                    if tested >= ctx.limits.max_tests_per_module:
                        return findings
                    tested += 1
                    ctx.heartbeat("ldap_injection", f"{param}={payload}", tested, len(findings))
                    result = await ctx.http.request("GET", url, params={param: payload})
                    result_body = str(getattr(result, "text", "") or "").lower() if result else ""
                    signatures = [
                        error for error in self.LDAP_ERRORS if error in result_body and error not in baseline_body
                    ]
                    if result and signatures:
                        findings.append(
                            self._finding(
                                ctx,
                                "LDAP Injection",
                                "High",
                                url,
                                param,
                                payload,
                                result,
                                f"Differential LDAP error signature observed: {', '.join(signatures[:3])}.",
                            )
                        )
                        break
        return findings

    async def _command(self, ctx: ScanContext, candidates: list[tuple[str, list[str]]]) -> list[Finding]:
        findings = []
        tested = 0
        for url, params in candidates:
            for param in params[:12]:
                if not any(x in param.lower() for x in ["cmd", "exec", "host", "ip", "domain", "url", "ping", "query"]):
                    continue
                baseline = await ctx.http.request("GET", url, params={param: "scan_titan_control"})
                for payload, expected, engine in self._command_probes(url, param):
                    if tested >= ctx.limits.max_tests_per_module:
                        return findings
                    tested += 1
                    ctx.heartbeat("command_injection", f"{param}={payload}", tested, len(findings))
                    result = await ctx.http.request("GET", url, params={param: payload})
                    if differential_output_proven(result, baseline, expected):
                        findings.append(
                            self._finding(
                                ctx,
                                "Command Injection",
                                "Critical",
                                url,
                                param,
                                payload,
                                result,
                                (
                                    f"Differential arithmetic command proof ({engine}): output {expected} "
                                    "appeared only after the active payload and the control response did not contain it."
                                ),
                            )
                        )
                        break
        return findings

    async def _traversal(self, ctx: ScanContext, candidates: list[tuple[str, list[str]]]) -> list[Finding]:
        findings = []
        tested = 0
        payloads = lfi_payloads(ctx.wordlists, self.TRAVERSAL, limit=max(ctx.limits.max_tests_per_module, 80))
        for url, params in candidates:
            for param in params[:12]:
                if not any(x in param.lower() for x in ["file", "path", "page", "include", "doc", "template", "view"]):
                    continue
                baseline = await ctx.http.request("GET", url, params={param: "scan_titan_control"})
                baseline_body = str(getattr(baseline, "text", "") or "")
                for payload, marker in payloads:
                    if tested >= ctx.limits.max_tests_per_module:
                        return findings
                    tested += 1
                    ctx.heartbeat("path_traversal", f"{param}={payload[:22]}", tested, len(findings))
                    result = await ctx.http.request("GET", url, params={param: payload})
                    if result and marker in result.text and marker not in baseline_body:
                        findings.append(
                            self._finding(
                                ctx,
                                "Path Traversal / LFI",
                                "Critical",
                                url,
                                param,
                                payload,
                                result,
                                f"Marker observed: {marker}",
                            )
                        )
                        break
        return findings

    async def _ssti(self, ctx: ScanContext, candidates: list[tuple[str, list[str]]]) -> list[Finding]:
        findings = []
        tested = 0
        for url, params in candidates:
            for param in params[:12]:
                if not any(x in param.lower() for x in ["name", "template", "msg", "text", "view", "email", "title"]):
                    continue
                baseline = await ctx.http.request("GET", url, params={param: "scan_titan_control"})
                for payload, expected, engine in self._ssti_probes(url, param):
                    if tested >= ctx.limits.max_tests_per_module:
                        return findings
                    tested += 1
                    ctx.heartbeat("ssti", f"{param}={payload}", tested, len(findings))
                    result = await ctx.http.request("GET", url, params={param: payload})
                    if differential_output_proven(result, baseline, expected):
                        findings.append(
                            self._finding(
                                ctx,
                                "Server-Side Template Injection",
                                "Critical",
                                url,
                                param,
                                payload,
                                result,
                                (
                                    f"Differential SSTI proof ({engine}): expression evaluated to {expected}; "
                                    "the generated result was absent from the control response."
                                ),
                            )
                        )
                        break
        return findings

    @staticmethod
    def _probe_numbers(url: str, param: str) -> tuple[int, int]:
        digest = hashlib.sha256(f"{url}|{param}".encode("utf-8", errors="ignore")).digest()
        left = 71000 + int.from_bytes(digest[:2], "big") % 7000
        right = 3100 + int.from_bytes(digest[2:4], "big") % 1900
        return left, right

    @classmethod
    def _command_probes(cls, url: str, param: str) -> list[tuple[str, str, str]]:
        left, right = cls._probe_numbers(url, param)
        expected = str(left + right)
        return [
            (f";expr {left} + {right}", expected, "POSIX expr"),
            (f"&& expr {left} + {right}", expected, "POSIX expr"),
            (f"| expr {left} + {right}", expected, "POSIX expr"),
            (f"& set /a {left}+{right}", expected, "Windows set /a"),
        ]

    @classmethod
    def _ssti_probes(cls, url: str, param: str) -> list[tuple[str, str, str]]:
        left_seed, right_seed = cls._probe_numbers(url, param)
        left = 700 + left_seed % 200
        right = 900 + right_seed % 200
        expected = str(left * right)
        return [
            (f"{{{{{left}*{right}}}}}", expected, "Jinja/Twig"),
            (f"${{{left}*{right}}}", expected, "EL/Freemarker"),
            (f"#{{{left}*{right}}}", expected, "Spring/Thymeleaf"),
            (f"<%= {left}*{right} %>", expected, "ERB/EJS"),
        ]

    async def _file_upload(self, ctx: ScanContext) -> list[Finding]:
        result = await ctx.http.request("GET", ctx.target.url, allow_redirects=True)
        if not result:
            return []
        soup = BeautifulSoup(result.text, "html.parser")
        findings = []
        for form in soup.find_all("form"):
            file_input = form.find("input", {"type": "file"})
            if not file_input:
                continue
            action = urllib.parse.urljoin(result.final_url, form.get("action") or result.final_url)
            method = (form.get("method") or "POST").upper()
            findings.append(
                Finding(
                    target=ctx.target.display,
                    category="File Upload",
                    severity="Medium",
                    title="File upload surface discovered",
                    url=action,
                    method=method,
                    evidence="File input exists. Verify extension/MIME/content validation.",
                    source=self.name,
                    confidence="medium",
                )
            )
            if not ctx.policy.perform_upload_attempts:
                ctx.recon["policy_deferred_tests"] = sorted(
                    set(ctx.recon.get("policy_deferred_tests", []) + ["safe_file_upload_probe"])
                )
                continue
            upload_result = await self._safe_upload_probe(ctx, form, action, method)
            if upload_result:
                findings.append(upload_result)
        return findings

    async def _safe_upload_probe(self, ctx: ScanContext, form: Any, action: str, method: str) -> Finding | None:
        marker = f"scan_titan_upload_marker_{ctx.target.host.replace('.', '_')}"
        data = aiohttp.FormData()
        file_added = False
        for field in form.find_all(["input", "textarea", "select"]):
            name = field.get("name")
            if not name:
                continue
            field_type = (field.get("type") or "text").lower()
            if field_type == "file":
                data.add_field(
                    name,
                    marker.encode("utf-8"),
                    filename="scan_titan_probe.txt",
                    content_type="text/plain",
                )
                file_added = True
            elif field_type not in {"submit", "button", "image", "reset"}:
                data.add_field(name, field.get("value") or marker)
        if not file_added:
            return None
        result = await ctx.http.request(method if method in {"POST", "PUT", "PATCH"} else "POST", action, data=data)
        if not result:
            return None
        accepted = result.status in {200, 201, 202, 204, 302, 303}
        reflected = marker in result.text
        if not accepted and not reflected:
            return None
        return Finding(
            target=ctx.target.display,
            category="File Upload",
            severity="High" if reflected else "Medium",
            title="Benign file upload probe accepted",
            url=action,
            method=method,
            payload="scan_titan_probe.txt",
            status=str(result.status),
            size=f"{result.body_len}b",
            elapsed=f"{result.elapsed:.2f}s",
            evidence=(
                "Uploaded text marker was reflected in response."
                if reflected
                else "Upload endpoint returned an acceptance status for a benign text file."
            ),
            source=self.name,
            confidence="medium" if reflected else "low",
        )

    def _candidates(self, ctx: ScanContext) -> list[tuple[str, list[str]]]:
        out = [(ctx.target.url, self.PARAMS)]
        for endpoint in ctx.recon.get("endpoints", [])[:80]:
            url = endpoint.get("url")
            params = endpoint.get("params") or []
            if url:
                out.append((url, params or self.PARAMS[:6]))
        return out

    def _finding(
        self,
        ctx: ScanContext,
        title: str,
        severity: str,
        url: str,
        param: str,
        payload: str,
        result: Any,
        evidence: str,
    ) -> Finding:
        return Finding(
            target=ctx.target.display,
            category="Injection",
            severity=severity,
            title=f"{title}: {param}",
            url=url_with_params(url, {param: payload}),
            endpoint=urllib.parse.urlparse(url).path or "/",
            param=param,
            method="GET",
            payload=payload,
            status=str(result.status),
            size=f"{result.body_len}b",
            elapsed=f"{result.elapsed:.2f}s",
            evidence=evidence,
            source=self.name,
            confidence="high",
        )
