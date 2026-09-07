from __future__ import annotations

import base64
import json
import re
import urllib.parse
from http.cookies import SimpleCookie
from typing import Any

from bs4 import BeautifulSoup

from .common import Finding, ScanContext, VulnerabilityModule, clean_text
from .payload_utils import jwt_decode, jwt_temporal_claims, jwt_weak_secret


class AuthSessionModule(VulnerabilityModule):
    name = "auth_session"

    AUTH_PATHS = ["/admin", "/dashboard", "/manager", "/portal", "/account", "/profile", "/settings", "/wp-admin"]
    RECOVERY_PATHS = ["/forgot-password", "/password/reset", "/reset-password", "/recover", "/account/recovery"]
    DEFAULT_CREDS = [
        ("admin", "admin"),
        ("admin", "password"),
        ("administrator", "administrator"),
        ("test", "test"),
        ("user", "password"),
    ]
    LOGIN_BYPASS_PAYLOADS = [
        {"username": "' OR '1'='1", "password": "' OR '1'='1"},
        {"username": "admin'--", "password": "invalid"},
        {"username": "admin", "password": "' OR '1'='1"},
    ]

    async def run(self, ctx: ScanContext) -> list[Finding]:
        findings: list[Finding] = []
        base = await ctx.http.request("GET", ctx.target.url, allow_redirects=True)
        if not base:
            return findings
        soup = BeautifulSoup(base.text, "html.parser")
        login_forms = self._login_forms(base.final_url, soup)
        if login_forms:
            ctx.recon["login_forms"] = sorted(set(ctx.recon.get("login_forms", []) + [f["action"] for f in login_forms]))
        findings.extend(await self._unauthenticated_routes(ctx))
        if ctx.policy.allow_state_changing_api_tests:
            findings.extend(await self._login_bypass(ctx, login_forms))
        elif login_forms:
            ctx.recon["policy_deferred_tests"] = sorted(
                set(ctx.recon.get("policy_deferred_tests", []) + ["form_login_bypass"])
            )
        if ctx.policy.allow_bruteforce:
            findings.extend(await self._controlled_credential_probe(ctx, login_forms))
        findings.extend(await self._password_recovery(ctx))
        findings.extend(self._cookie_findings(ctx, base))
        findings.extend(await self._session_regeneration_profiles(ctx))
        findings.extend(self._jwt_findings(ctx, base.text, base.headers))
        findings.extend(self._csrf_findings(ctx, base.final_url, soup))
        findings.extend(self._mfa_findings(ctx, login_forms))
        return findings

    async def _controlled_credential_probe(self, ctx: ScanContext, forms: list[dict[str, Any]]) -> list[Finding]:
        findings = []
        users = ctx.wordlists.get("users", [])[:64]
        passwords = ctx.wordlists.get("passwords", [])[:64]
        wordlist_pairs = [(username, password) for username in users for password in passwords]
        pairs = list(dict.fromkeys(self.DEFAULT_CREDS + wordlist_pairs))
        max_attempts = min(ctx.limits.max_tests_per_module, 1000)
        tested = 0
        for form in forms[:3]:
            fields = form["fields"]
            user_field = self._find_field(fields, ["user", "email", "login"])
            pass_field = self._find_field(fields, ["pass", "pwd"])
            if not user_field or not pass_field:
                continue
            for username, password in pairs[:max_attempts]:
                tested += 1
                ctx.heartbeat(self.name, f"credential-probe {form['action']}", tested, len(findings))
                data = {name: meta.get("value", "scan_titan") for name, meta in fields.items()}
                data[user_field] = username
                data[pass_field] = password
                result = await ctx.http.request(form["method"], form["action"], data=data, allow_redirects=False)
                if not result:
                    continue
                location = result.headers.get("Location", "")
                body = result.text.lower()
                success_signal = result.status in {200, 302, 303} and (
                    "logout" in body or "dashboard" in body or "session" in body or "dashboard" in location.lower()
                )
                failure_signal = any(token in body for token in ["invalid", "incorrect", "error", "denied", "captcha"])
                if success_signal and not failure_signal:
                    findings.append(
                        Finding(
                            target=ctx.target.display,
                            category="Auth",
                            severity="Critical",
                            title="Weak credential accepted",
                            url=form["action"],
                            method=form["method"],
                            payload=f"{username}:{password}",
                            status=str(result.status),
                            evidence=f"Location={location or '-'}",
                            source=self.name,
                            confidence="medium",
                        )
                    )
                    break
        return findings

    async def _unauthenticated_routes(self, ctx: ScanContext) -> list[Finding]:
        findings = []
        for idx, path in enumerate(self.AUTH_PATHS, start=1):
            ctx.heartbeat(self.name, f"unauth {path}", idx, len(findings))
            url = urllib.parse.urljoin(ctx.target.url, path)
            result = await ctx.http.request("GET", url, allow_redirects=False)
            if not result:
                continue
            if result.status == 200 and not self._looks_like_login(result.text):
                findings.append(
                    Finding(
                        target=ctx.target.display,
                        category="Auth",
                        severity="High",
                        title=f"Potential unauthenticated protected route: {path}",
                        url=url,
                        endpoint=path,
                        method="GET",
                        status=str(result.status),
                        evidence="Protected-looking route returned 200 without login challenge.",
                        source=self.name,
                        confidence="medium",
                    )
                )
        return findings

    async def _login_bypass(self, ctx: ScanContext, forms: list[dict[str, Any]]) -> list[Finding]:
        findings = []
        for form in forms[:5]:
            fields = form["fields"]
            user_field = self._find_field(fields, ["user", "email", "login"])
            pass_field = self._find_field(fields, ["pass", "pwd"])
            if not user_field or not pass_field:
                continue
            for idx, payload in enumerate(self.LOGIN_BYPASS_PAYLOADS, start=1):
                data = {name: meta.get("value", "scan_titan") for name, meta in fields.items()}
                data[user_field] = payload["username"]
                data[pass_field] = payload["password"]
                ctx.heartbeat(self.name, f"login-bypass {form['action']}", idx, len(findings))
                result = await ctx.http.request(form["method"], form["action"], data=data, allow_redirects=False)
                if not result:
                    continue
                location = result.headers.get("Location", "")
                body = result.text.lower()
                success_signal = result.status in {200, 302, 303} and (
                    "logout" in body or "dashboard" in body or "session" in body or "dashboard" in location.lower()
                )
                failure_signal = any(x in body for x in ["invalid", "incorrect", "error", "denied", "captcha"])
                if success_signal and not failure_signal:
                    findings.append(
                        Finding(
                            target=ctx.target.display,
                            category="Auth",
                            severity="Critical",
                            title="Login bypass signal with injection payload",
                            url=form["action"],
                            method=form["method"],
                            payload=json.dumps(payload),
                            status=str(result.status),
                            evidence=f"Location={location or '-'}",
                            source=self.name,
                            confidence="medium",
                        )
                    )
        return findings

    async def _password_recovery(self, ctx: ScanContext) -> list[Finding]:
        findings = []
        for idx, path in enumerate(self.RECOVERY_PATHS, start=1):
            ctx.heartbeat(self.name, f"recovery {path}", idx, len(findings))
            url = urllib.parse.urljoin(ctx.target.url, path)
            result = await ctx.http.request("GET", url, allow_redirects=False)
            if result and result.status == 200:
                findings.append(
                    Finding(
                        target=ctx.target.display,
                        category="Auth",
                        severity="Info",
                        title=f"Password recovery endpoint discovered: {path}",
                        url=url,
                        endpoint=path,
                        status=str(result.status),
                        evidence="Recovery surface identified for manual workflow review.",
                        source=self.name,
                        confidence="high",
                    )
                )
        return findings

    def _cookie_findings(self, ctx: ScanContext, result: Any) -> list[Finding]:
        findings = []
        raw_headers = getattr(result, "raw_headers", {}) or {}
        raw = []
        for key, values in raw_headers.items():
            if str(key).lower() == "set-cookie":
                raw.extend([str(value) for value in values if str(value).strip()])
        if not raw:
            raw = [value for key, value in result.headers.items() if key.lower() == "set-cookie"]
        statuses = []
        for cookie_header in raw:
            cookie = SimpleCookie()
            try:
                cookie.load(cookie_header)
            except Exception:
                continue
            for name, morsel in cookie.items():
                missing = []
                if not morsel["secure"]:
                    missing.append("Secure")
                if not morsel["httponly"]:
                    missing.append("HttpOnly")
                if not morsel["samesite"]:
                    missing.append("SameSite")
                if missing:
                    findings.append(
                        Finding(
                            target=ctx.target.display,
                            category="Session",
                            severity="Low",
                            title=f"Cookie missing security flags: {name}",
                            url=result.final_url,
                            evidence=f"Missing={','.join(missing)}",
                            source=self.name,
                            confidence="high",
                        )
                    )
                same_site = str(morsel["samesite"] or "").lower()
                if same_site == "none" and not morsel["secure"]:
                    findings.append(
                        Finding(
                            target=ctx.target.display,
                            category="Session",
                            severity="Medium",
                            title=f"Cookie SameSite=None without Secure: {name}",
                            url=result.final_url,
                            evidence="Browsers require Secure for SameSite=None; session transport guarantees are weakened.",
                            source=self.name,
                            confidence="high",
                        )
                    )
                if self._session_like(name) and len(morsel.value or "") < 16:
                    findings.append(
                        Finding(
                            target=ctx.target.display,
                            category="Session",
                            severity="Low",
                            title=f"Session cookie value appears short: {name}",
                            url=result.final_url,
                            evidence=f"Length={len(morsel.value or '')}",
                            source=self.name,
                            confidence="medium",
                        )
                    )
                if morsel.value and len(morsel.value) > 12 and morsel.value in result.text:
                    findings.append(
                        Finding(
                            target=ctx.target.display,
                            category="Session",
                            severity="Medium",
                            title=f"Cookie value reflected in response body: {name}",
                            url=result.final_url,
                            evidence=f"Cookie name={name} value length={len(morsel.value)}",
                            source=self.name,
                            confidence="medium",
                        )
                    )
                if not morsel["expires"] and not morsel["max-age"]:
                    findings.append(
                        Finding(
                            target=ctx.target.display,
                            category="Session",
                            severity="Info",
                            title=f"Session cookie without explicit expiration: {name}",
                            url=result.final_url,
                            evidence="No Expires/Max-Age observed.",
                            source=self.name,
                            confidence="medium",
                        )
                    )
                max_age = self._int_cookie_attr(morsel["max-age"])
                if max_age and max_age > 60 * 60 * 24 * 30 and self._session_like(name):
                    findings.append(
                        Finding(
                            target=ctx.target.display,
                            category="Session",
                            severity="Low",
                            title=f"Long-lived session cookie: {name}",
                            url=result.final_url,
                            evidence=f"Max-Age={max_age} seconds",
                            source=self.name,
                            confidence="medium",
                        )
                    )
                statuses.append(f"{name}: missing {','.join(missing) if missing else 'none'}")
        if statuses:
            ctx.recon["cookies_status"] = statuses
        if "document.cookie" in result.text:
            findings.append(
                Finding(
                    target=ctx.target.display,
                    category="Session",
                    severity="Medium",
                    title="JavaScript references document.cookie",
                    url=result.final_url,
                    evidence="document.cookie found in page source; verify cookie exposure and HttpOnly coverage.",
                    source=self.name,
                    confidence="medium",
                )
            )
        return findings

    async def _session_regeneration_profiles(self, ctx: ScanContext) -> list[Finding]:
        findings: list[Finding] = []
        for idx, profile in enumerate(ctx.policy.auth_profiles[:4], start=1):
            headers = self._profile_headers(profile)
            sent_cookies = self._parse_cookie_header(headers.get("Cookie", ""))
            if not sent_cookies:
                continue
            ctx.heartbeat(self.name, f"session-regeneration {profile.get('name', idx)}", idx, len(findings))
            result = await ctx.http.request("GET", ctx.target.url, headers=headers, allow_redirects=False)
            if not result:
                continue
            returned = self._set_cookie_values(result)
            reused = [
                name
                for name, value in sent_cookies.items()
                if value and returned.get(name) == value and self._session_like(name)
            ]
            if reused:
                findings.append(
                    Finding(
                        target=ctx.target.display,
                        category="Session",
                        severity="Low",
                        title="Session regeneration not observed for auth profile",
                        url=ctx.target.url,
                        evidence=f"Profile={profile.get('name', idx)} ReusedCookies={reused}",
                        source=self.name,
                        confidence="low",
                    )
                )
        return findings

    def _profile_headers(self, profile: dict[str, Any]) -> dict[str, str]:
        headers = {str(key): str(value) for key, value in (profile.get("headers") or {}).items() if str(value).strip()}
        bearer = str(profile.get("bearer_token") or "").strip()
        if bearer and "Authorization" not in headers:
            headers["Authorization"] = f"Bearer {bearer}"
        cookies = profile.get("cookies") or {}
        if isinstance(cookies, dict) and cookies and "Cookie" not in headers:
            headers["Cookie"] = "; ".join(f"{key}={value}" for key, value in cookies.items())
        return headers

    def _parse_cookie_header(self, value: str) -> dict[str, str]:
        out: dict[str, str] = {}
        for part in str(value or "").split(";"):
            if "=" not in part:
                continue
            name, cookie_value = part.split("=", 1)
            out[name.strip()] = cookie_value.strip()
        return out

    def _set_cookie_values(self, result: Any) -> dict[str, str]:
        values: dict[str, str] = {}
        for raw in self._raw_cookie_headers(result):
            cookie = SimpleCookie()
            try:
                cookie.load(raw)
            except Exception:
                continue
            for name, morsel in cookie.items():
                values[name] = morsel.value
        return values

    def _raw_cookie_headers(self, result: Any) -> list[str]:
        raw_headers = getattr(result, "raw_headers", {}) or {}
        raw = []
        for key, values in raw_headers.items():
            if str(key).lower() == "set-cookie":
                raw.extend([str(value) for value in values if str(value).strip()])
        if not raw:
            raw = [value for key, value in result.headers.items() if key.lower() == "set-cookie"]
        return raw

    def _session_like(self, name: str) -> bool:
        lowered = str(name or "").lower()
        return any(token in lowered for token in ["session", "sess", "sid", "jwt", "auth", "token", "jwt"])

    def _int_cookie_attr(self, value: str) -> int:
        try:
            return int(value or 0)
        except Exception:
            return 0

    def _jwt_findings(self, ctx: ScanContext, body: str, headers: dict[str, str]) -> list[Finding]:
        tokens = set(re.findall(r"eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}", body))
        for value in headers.values():
            tokens.update(re.findall(r"eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}", value))
        findings = []
        for token in list(tokens)[:20]:
            header, payload, _signature, _parts = jwt_decode(token)
            alg = str(header.get("alg", "")).lower()
            if alg in {"none", "null", ""}:
                findings.append(
                    Finding(
                        target=ctx.target.display,
                        category="JWT",
                        severity="Critical",
                        title="JWT uses unsigned/null algorithm",
                        url=ctx.target.url,
                        evidence=f"Header={header}",
                        source=self.name,
                        confidence="high",
                    )
                )
            for key, severity, title in [
                ("jku", "High", "JWT JKU header allows remote key reference"),
                ("jwk", "High", "JWT embeds JWK header"),
                ("x5u", "High", "JWT X5U header allows remote certificate reference"),
                ("x5c", "Medium", "JWT embeds certificate chain"),
                ("kid", "Medium", "JWT KID header present; test key confusion/injection"),
            ]:
                if key in header:
                    findings.append(
                        Finding(
                            target=ctx.target.display,
                            category="JWT",
                            severity=severity,
                            title=title,
                            url=ctx.target.url,
                            evidence=f"{key}={clean_text(header.get(key), 260)}",
                            source=self.name,
                            confidence="medium",
                        )
                    )
            temporal_issues = jwt_temporal_claims(payload)
            if temporal_issues:
                findings.append(
                    Finding(
                        target=ctx.target.display,
                        category="JWT",
                        severity="Low",
                        title="JWT temporal claim weakness",
                        url=ctx.target.url,
                        evidence="; ".join(temporal_issues),
                        source=self.name,
                        confidence="medium",
                    )
                )
            sensitive = [
                key
                for key in payload
                if any(
                    token_key in key.lower()
                    for token_key in ["password", "secret", "token", "key", "ssn", "credit"]
                )
            ]
            if sensitive:
                findings.append(
                    Finding(
                        target=ctx.target.display,
                        category="JWT",
                        severity="Medium",
                        title="JWT contains sensitive-looking claims",
                        url=ctx.target.url,
                        evidence=f"Keys={sensitive}",
                        source=self.name,
                        confidence="medium",
                    )
                )
            if payload.get("admin") is True or payload.get("is_admin") is True or payload.get("isAdmin") is True:
                findings.append(
                    Finding(
                        target=ctx.target.display,
                        category="JWT",
                        severity="Info",
                        title="JWT contains privileged boolean claim",
                        url=ctx.target.url,
                        evidence=clean_text(payload, 300),
                        source=self.name,
                        confidence="low",
                    )
                )
            if str(payload.get("role", "")).lower() in {"admin", "root", "superuser"}:
                findings.append(
                    Finding(
                        target=ctx.target.display,
                        category="JWT",
                        severity="Info",
                        title="JWT contains privileged role claim",
                        url=ctx.target.url,
                        evidence=f"role={payload.get('role')}",
                        source=self.name,
                        confidence="low",
                    )
                )
            if ctx.policy.allow_bruteforce and alg.upper() in {"HS256", "HS384", "HS512"}:
                secret = jwt_weak_secret(
                    token,
                    ctx.wordlists.get("passwords", []),
                    limit=ctx.limits.max_tests_per_module,
                )
                if secret:
                    findings.append(
                        Finding(
                            target=ctx.target.display,
                            category="JWT",
                            severity="Critical",
                            title="JWT signed with weak HMAC secret",
                            url=ctx.target.url,
                            evidence=f"Weak secret recovered from controlled dictionary: {secret}",
                            source=self.name,
                            confidence="high",
                        )
                    )
        return findings

    def _csrf_findings(self, ctx: ScanContext, base_url: str, soup: Any) -> list[Finding]:
        findings = []
        token_names = ["csrf", "_token", "xsrf", "authenticity_token", "csrfmiddlewaretoken"]
        for form in soup.find_all("form")[:25]:
            method = (form.get("method") or "GET").upper()
            if method not in {"POST", "PUT", "PATCH", "DELETE"}:
                continue
            fields = [
                str(field.get("name") or "").lower()
                for field in form.find_all(["input", "textarea", "select"])
                if field.get("name")
            ]
            has_token = any(any(token in name for token in token_names) for name in fields)
            if has_token:
                continue
            action = urllib.parse.urljoin(base_url, form.get("action") or base_url)
            findings.append(
                Finding(
                    target=ctx.target.display,
                    category="Auth",
                    severity="Low",
                    title="State-changing form without visible CSRF token",
                    url=action,
                    method=method,
                    evidence=f"Fields={','.join(fields[:12]) or '-'}",
                    source=self.name,
                    confidence="medium",
                )
            )
        return findings

    def _mfa_findings(self, ctx: ScanContext, forms: list[dict[str, Any]]) -> list[Finding]:
        findings = []
        for form in forms:
            names = " ".join(form["fields"].keys()).lower()
            if not any(x in names for x in ["otp", "mfa", "totp", "2fa", "code"]):
                findings.append(
                    Finding(
                        target=ctx.target.display,
                        category="Auth",
                        severity="Info",
                        title="Login form without visible MFA field",
                        url=form["action"],
                        evidence="No OTP/MFA/TOTP/2FA field identified in login form markup.",
                        source=self.name,
                        confidence="low",
                    )
                )
        return findings

    def _login_forms(self, base_url: str, soup: Any) -> list[dict[str, Any]]:
        forms = []
        for form in soup.find_all("form"):
            action = urllib.parse.urljoin(base_url, form.get("action") or base_url)
            method = (form.get("method") or "GET").upper()
            fields = {}
            for field in form.find_all(["input", "textarea", "select"]):
                name = field.get("name")
                if name:
                    fields[name] = {"type": (field.get("type") or "text").lower(), "value": field.get("value") or "scan_titan"}
            has_password = any(meta["type"] == "password" for meta in fields.values())
            if has_password or "login" in action.lower():
                forms.append({"action": action, "method": method, "fields": fields})
        return forms

    def _find_field(self, fields: dict[str, Any], needles: list[str]) -> str | None:
        for name in fields:
            if any(needle in name.lower() for needle in needles):
                return name
        return None

    def _looks_like_login(self, body: str) -> bool:
        lower = body.lower()
        return "password" in lower and any(x in lower for x in ["login", "sign in", "username", "email"])

    def _decode_jwt(self, token: str) -> tuple[dict[str, Any], dict[str, Any]]:
        try:
            head, body, _sig = token.split(".", 2)
            return self._b64_json(head), self._b64_json(body)
        except Exception:
            return {}, {}

    def _b64_json(self, value: str) -> dict[str, Any]:
        try:
            padded = value + "=" * (-len(value) % 4)
            return json.loads(base64.urlsafe_b64decode(padded))
        except Exception:
            return {}
