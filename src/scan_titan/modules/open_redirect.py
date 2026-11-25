"""Open redirect detection with a differential proof.

A parameter is reported only when:
  1. a same-site control value does NOT produce an external redirect, and
  2. a unique external host produces a redirect (3xx Location, Refresh header or
     <meta http-equiv=refresh>) whose parsed host is exactly that unique host, and
  3. the result repeats on a second request.
A reflected URL in the body, a redirect to login or a host that merely contains
the marker as a substring is never accepted.
"""
from __future__ import annotations

import re
import secrets
import urllib.parse
from typing import Any

from .common import Finding, ScanContext, VulnerabilityModule, record_probe_timeout, run_bounded, url_with_params

REDIRECT_PARAMS = {
    "next", "url", "redirect", "redirect_url", "redirect_uri", "redirecturl", "redirect_to", "return", "returnurl",
    "return_url", "return_to", "returnto", "continue", "dest", "destination", "goto", "go", "target", "r", "u",
    "forward", "callback", "out", "view", "to", "link", "redir", "location", "success_url", "back", "backurl",
}
META_REFRESH = re.compile(r"""<meta[^>]+http-equiv=["']?refresh["']?[^>]*content=["'][^"']*url=([^"'>\s]+)""", re.I)


def redirect_target(response: Any) -> tuple[str, str]:
    """Return (mechanism, absolute target) of a redirect in ``response``."""
    if response is None:
        return "", ""
    headers = {str(k).lower(): str(v) for k, v in (getattr(response, "headers", {}) or {}).items()}
    status = int(getattr(response, "status", 0) or 0)
    base = getattr(response, "url", "") or ""
    if 300 <= status < 400 and headers.get("location"):
        return f"HTTP {status} Location", urllib.parse.urljoin(base, headers["location"].strip())
    refresh = headers.get("refresh", "")
    match = re.search(r"url\s*=\s*(\S+)", refresh, re.I)
    if match:
        return "Refresh header", urllib.parse.urljoin(base, match.group(1).strip("'\""))
    meta = META_REFRESH.search(str(getattr(response, "text", "") or "")[:20000])
    if meta:
        return "meta refresh", urllib.parse.urljoin(base, meta.group(1))
    return "", ""


def redirects_to_host(response: Any, host: str) -> tuple[bool, str, str]:
    mechanism, target = redirect_target(response)
    if not target:
        return False, "", ""
    parsed = urllib.parse.urlsplit(target)
    return (parsed.hostname or "").lower() == host.lower(), mechanism, target


class OpenRedirectModule(VulnerabilityModule):
    name = "open_redirect"

    def _candidates(self, ctx: ScanContext) -> list[tuple[str, str]]:
        origin = urllib.parse.urlsplit(ctx.target.url)
        seen: dict[tuple[str, str], tuple[str, str]] = {}
        urls = [item.get("url", "") for item in ctx.recon.get("endpoints", []) if isinstance(item, dict)]
        urls += [str(item) for item in ctx.recon.get("urls", []) or [] if isinstance(item, str)]
        for url in urls:
            parsed = urllib.parse.urlsplit(url)
            if (parsed.scheme, parsed.netloc) != (origin.scheme, origin.netloc):
                continue
            for name, value in urllib.parse.parse_qsl(parsed.query, keep_blank_values=True):
                looks_url = value.startswith(("/", "http://", "https://", "//")) or "%2f" in value.lower()
                if name.lower() in REDIRECT_PARAMS or looks_url:
                    seen.setdefault((parsed.path, name), (url, name))
        return list(seen.values())[:40]

    async def run(self, ctx: ScanContext) -> list[Finding]:
        findings: list[Finding] = []
        candidates = self._candidates(ctx)
        tested = 0

        async def probe(item: tuple[str, str]) -> None:
            nonlocal tested
            url, param = item
            tested += 1
            ctx.heartbeat(self.name, f"{param} @ {urllib.parse.urlsplit(url).path}", tested, len(findings))
            host = f"st-redirect-{secrets.token_hex(4)}.example"
            control_url = url_with_params(url, {param: "/scan-titan-control"})
            control = await ctx.http.request("GET", control_url, allow_redirects=False)
            if control is None or redirects_to_host(control, host)[0]:
                return
            _, control_target = redirect_target(control)
            if control_target and urllib.parse.urlsplit(control_target).hostname not in (
                    None, urllib.parse.urlsplit(url).hostname):
                return  # the endpoint redirects off-site regardless of input
            for payload in (f"https://{host}/", f"//{host}/", f"/\\{host}/", f"https:{host}/"):
                probe_url = url_with_params(url, {param: payload})
                first = await ctx.http.request("GET", probe_url, allow_redirects=False)
                ok, mechanism, target = redirects_to_host(first, host)
                if not ok:
                    continue
                second = await ctx.http.request("GET", probe_url, allow_redirects=False)
                if not redirects_to_host(second, host)[0]:
                    continue
                findings.append(Finding(
                    target=ctx.target.display, category="Redirect", severity="Medium",
                    title=f"Open redirect: {param}", url=probe_url,
                    endpoint=urllib.parse.urlsplit(url).path or "/", param=param, method="GET", payload=payload,
                    status=str(first.status),
                    evidence=(f"{mechanism} -> {target} (host controlado {host}); control "
                              f"{control_url} -> {control_target or 'sin redireccion externa'}; repetido 2/2"),
                    source=self.name, confidence="high", evidence_strength="strong", false_positive_risk="low",
                    cwe="CWE-601", owasp="A01:2025 - Control de acceso roto",
                    impact="Permite usar el dominio legitimo para redirigir a un sitio controlado por un atacante "
                           "(phishing, robo de tokens en flujos OAuth).",
                    remediation="Aceptar solo rutas relativas o una allowlist de destinos; nunca URLs absolutas "
                                "proporcionadas por el usuario.",
                ))
                return

        await run_bounded(candidates, probe, limit=4, should_stop=ctx.should_stop,
                          item_timeout=max(20.0, float(ctx.limits.timeout) * 4),
                          on_timeout=lambda item, seconds: record_probe_timeout(ctx, self.name, item, seconds))
        return findings
