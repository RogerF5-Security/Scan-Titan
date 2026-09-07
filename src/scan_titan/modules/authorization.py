from __future__ import annotations

import urllib.parse

from .common import Finding, ScanContext, VulnerabilityModule, url_with_params


class AuthorizationModule(VulnerabilityModule):
    name = "authorization"

    SENSITIVE_ENDPOINTS = [
        "/api/users",
        "/api/admin",
        "/admin",
        "/account",
        "/profile",
        "/settings",
        "/orders",
        "/invoices",
    ]
    ROLE_PARAMS = ["role", "is_admin", "admin", "permission", "access", "scope", "debug"]
    BYPASS_HEADERS = [
        {"Authorization": ""},
        {"Authorization": "Bearer null"},
        {"Authorization": "Bearer undefined"},
        {"X-Custom-IP-Authorization": "127.0.0.1"},
        {"X-Forwarded-For": "127.0.0.1"},
        {"X-Real-IP": "127.0.0.1"},
        {"X-Originating-IP": "127.0.0.1"},
    ]

    async def run(self, ctx: ScanContext) -> list[Finding]:
        findings: list[Finding] = []
        findings.extend(await self._sensitive_routes(ctx))
        findings.extend(await self._header_bypass(ctx))
        findings.extend(await self._idor_and_tampering(ctx))
        findings.extend(await self._auth_profile_matrix(ctx))
        return findings

    async def _sensitive_routes(self, ctx: ScanContext) -> list[Finding]:
        findings = []
        for idx, path in enumerate(self.SENSITIVE_ENDPOINTS, start=1):
            ctx.heartbeat(self.name, f"sensitive {path}", idx, len(findings))
            url = urllib.parse.urljoin(ctx.target.url, path)
            result = await ctx.http.request("GET", url, allow_redirects=False)
            if result and result.status == 200 and "password" not in result.text.lower():
                findings.append(
                    Finding(
                        target=ctx.target.display,
                        category="Authorization",
                        severity="Medium",
                        title=f"Sensitive route returned 200: {path}",
                        url=url,
                        endpoint=path,
                        status=str(result.status),
                        evidence="Route may require authorization review.",
                        source=self.name,
                        confidence="low",
                    )
                )
        return findings

    async def _header_bypass(self, ctx: ScanContext) -> list[Finding]:
        findings = []
        endpoints = list(
            dict.fromkeys(
                self.SENSITIVE_ENDPOINTS
                + [
                    urllib.parse.urlparse(item.get("url", "")).path
                    for item in ctx.recon.get("endpoints", [])[:50]
                    if isinstance(item, dict) and item.get("url")
                ]
            )
        )[:40]
        tested = 0
        for path in endpoints:
            url = urllib.parse.urljoin(ctx.target.url, path or "/")
            baseline = await ctx.http.request("GET", url, allow_redirects=False)
            if not baseline or baseline.status not in {401, 403, 404}:
                continue
            dynamic_headers = [
                {"X-Original-URL": path or "/"},
                {"X-Rewrite-URL": path or "/"},
                *self.BYPASS_HEADERS,
            ]
            for headers in dynamic_headers:
                tested += 1
                header_name = next(iter(headers.keys()))
                ctx.heartbeat(self.name, f"header-bypass {header_name}", tested, len(findings))
                result = await ctx.http.request("GET", url, headers=headers, allow_redirects=False)
                if not result or result.status != 200:
                    continue
                lower = result.text.lower()
                if "password" in lower and any(token in lower for token in ["login", "sign in", "username", "email"]):
                    continue
                if result.body_len <= 80 or abs(result.body_len - baseline.body_len) < 40:
                    continue
                findings.append(
                    Finding(
                        target=ctx.target.display,
                        category="Authorization",
                        severity="High",
                        title=f"Header-based authorization bypass signal: {path}",
                        url=url,
                        endpoint=path,
                        status=f"{baseline.status}->{result.status}",
                        size=f"{baseline.body_len}b->{result.body_len}b",
                        evidence=f"Header accepted: {headers}",
                        source=self.name,
                        confidence="medium",
                    )
                )
                break
        return findings

    async def _idor_and_tampering(self, ctx: ScanContext) -> list[Finding]:
        candidates = self._candidates(ctx)
        findings = []
        tested = 0
        for url, params in candidates[:40]:
            baseline = await ctx.http.request("GET", url)
            if not baseline:
                continue
            parsed_params = dict(urllib.parse.parse_qsl(urllib.parse.urlparse(url).query))
            for param in params[:8]:
                tests = self._payloads_for_param(param, parsed_params.get(param))
                for payload in tests:
                    tested += 1
                    ctx.heartbeat(self.name, f"{param}={payload}", tested, len(findings))
                    result = await ctx.http.request("GET", url, params={param: payload})
                    if not result:
                        continue
                    diff = abs(result.body_len - baseline.body_len)
                    if result.status == 200 and baseline.status == 200 and diff > 150:
                        findings.append(
                            Finding(
                                target=ctx.target.display,
                                category="Authorization",
                                severity="Medium",
                                title=f"Parameter tampering differential: {param}",
                                url=url_with_params(url, {param: payload}),
                                endpoint=urllib.parse.urlparse(url).path or "/",
                                param=param,
                                method="GET",
                                payload=str(payload),
                                status=str(result.status),
                                size=f"base={baseline.body_len}b new={result.body_len}b",
                                evidence="Response body changed significantly after parameter manipulation.",
                                source=self.name,
                                confidence="low",
                            )
                        )
                        break
        return findings

    def _candidates(self, ctx: ScanContext) -> list[tuple[str, list[str]]]:
        out = []
        for endpoint in ctx.recon.get("endpoints", [])[:80]:
            url = endpoint.get("url")
            params = endpoint.get("params") or []
            if url and params:
                out.append((url, params))
        if not out:
            out = [(ctx.target.url, ["id", "user_id", "account_id", "role", "admin"])]
        return out

    async def _auth_profile_matrix(self, ctx: ScanContext) -> list[Finding]:
        profiles = ctx.policy.auth_profiles
        if not profiles:
            return []
        findings: list[Finding] = []
        candidates = list(dict.fromkeys(self.SENSITIVE_ENDPOINTS + [
            urllib.parse.urlparse(item.get("url", "")).path
            for item in ctx.recon.get("endpoints", [])[:40]
            if isinstance(item, dict) and item.get("url")
        ]))[:60]
        for idx, path in enumerate(candidates, start=1):
            url = urllib.parse.urljoin(ctx.target.url, path or "/")
            ctx.heartbeat(self.name, f"auth-matrix {path}", idx, len(findings))
            anonymous = await ctx.http.request("GET", url, allow_redirects=False)
            if not anonymous:
                continue
            profile_results = []
            for profile in profiles[:4]:
                result = await ctx.http.request("GET", url, headers=self._profile_headers(profile), allow_redirects=False)
                if result:
                    profile_results.append((profile.get("name", "profile"), result))
            if not profile_results:
                continue
            for name, result in profile_results:
                if anonymous.status == 200 and result.status == 200 and self._similar(anonymous.text, result.text) > 0.92:
                    findings.append(
                        Finding(
                            target=ctx.target.display,
                            category="Authorization",
                            severity="Medium",
                            title=f"Anonymous access resembles authenticated profile: {path}",
                            url=url,
                            endpoint=path,
                            status=f"anon={anonymous.status} profile={name}:{result.status}",
                            evidence="Anonymous response closely matches authenticated profile response.",
                            source=self.name,
                            confidence="medium",
                            cwe="CWE-862",
                            owasp="A01:2025 - Falla de control de acceso",
                            recommendation="Require authentication and object-level authorization before serving protected resources.",
                        )
                    )
                    break
        return findings

    def _profile_headers(self, profile: dict) -> dict[str, str]:
        headers = {str(k): str(v) for k, v in (profile.get("headers") or {}).items() if str(v).strip()}
        bearer = str(profile.get("bearer_token") or "").strip()
        if bearer and "Authorization" not in headers:
            headers["Authorization"] = f"Bearer {bearer}"
        cookies = profile.get("cookies") or {}
        if isinstance(cookies, dict) and cookies and "Cookie" not in headers:
            headers["Cookie"] = "; ".join(f"{key}={value}" for key, value in cookies.items())
        return headers

    def _similar(self, left: str, right: str) -> float:
        left_set = set(left[:8000].split())
        right_set = set(right[:8000].split())
        if not left_set or not right_set:
            return 0.0
        return len(left_set & right_set) / max(1, len(left_set | right_set))

    def _payloads_for_param(self, param: str, current: str | None) -> list[str]:
        lower = param.lower()
        if current and current.isdigit():
            value = int(current)
            return [str(max(0, value - 1)), str(value + 1), "1", "2"]
        if lower in self.ROLE_PARAMS or any(x in lower for x in self.ROLE_PARAMS):
            return ["admin", "true", "1", "superuser"]
        if any(x in lower for x in ["id", "uid", "account", "user"]):
            return ["1", "2", "999999"]
        return ["admin", "true", "1"]
