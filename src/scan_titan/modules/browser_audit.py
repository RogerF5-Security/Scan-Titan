from __future__ import annotations

import asyncio
import importlib.util
import os
import re
import urllib.parse
from pathlib import Path
from typing import Any

from .common import Finding, ScanContext, VulnerabilityModule, clean_text


class BrowserAuditModule(VulnerabilityModule):
    name = "browser_audit"

    async def run(self, ctx: ScanContext) -> list[Finding]:
        if not ctx.policy.enable_browser:
            return []
        if importlib.util.find_spec("playwright") is None:
            return [
                Finding(
                    target=ctx.target.display,
                    category="Browser",
                    severity="Info",
                    title="Browser audit skipped: Playwright not installed",
                    url=ctx.target.url,
                    evidence="Install with: pip install playwright && python -m playwright install chromium",
                    source=self.name,
                    confidence="high",
                )
            ]
        try:
            from playwright.async_api import async_playwright
        except Exception as exc:
            return [
                Finding(
                    target=ctx.target.display,
                    category="Browser",
                    severity="Info",
                    title="Browser audit skipped: Playwright import failed",
                    url=ctx.target.url,
                    evidence=str(exc),
                    source=self.name,
                    confidence="high",
                )
            ]

        findings: list[Finding] = []
        evidence_dir = Path(os.environ.get("SCAN_TITAN_REPORTS_DIR", "reports")) / "browser_evidence"
        if ctx.policy.evidence_cards:
            evidence_dir.mkdir(parents=True, exist_ok=True)
        try:
            async with async_playwright() as p:
                browser = await p.chromium.launch(headless=True)
                context = await browser.new_context(ignore_https_errors=not ctx.http.verify_tls)
                page = await context.new_page()
                dialogs: list[str] = []
                page.on("dialog", lambda dialog: asyncio.create_task(self._dismiss_dialog(dialog, dialogs)))
                await page.goto(ctx.target.url, wait_until="networkidle", timeout=ctx.policy.browser_timeout_seconds * 1000)
                await self._collect_browser_recon(ctx, page, context, evidence_dir)
                findings.extend(await self._validated_dom_xss(ctx, page, dialogs, evidence_dir))
                findings.extend(await self._crawl_routes(ctx, page, evidence_dir))
                await browser.close()
        except Exception as exc:
            findings.append(
                Finding(
                    target=ctx.target.display,
                    category="Browser",
                    severity="Info",
                    title="Browser audit skipped or failed",
                    url=ctx.target.url,
                    evidence=clean_text(str(exc), 500),
                    source=self.name,
                    confidence="medium",
                )
            )
        return findings

    async def _collect_browser_recon(self, ctx: ScanContext, page: Any, context: Any, evidence_dir: Path) -> None:
        title = await page.title()
        ctx.recon["browser_title"] = title
        links = await page.eval_on_selector_all("a[href]", "els => els.map(a => a.href).slice(0, 200)")
        same_host = []
        for link in links:
            parsed = urllib.parse.urlparse(link)
            if parsed.hostname == ctx.target.host:
                same_host.append(parsed.geturl())
        ctx.recon["browser_routes"] = sorted(set(ctx.recon.get("browser_routes", []) + same_host))[:300]
        storage = await page.evaluate(
            """() => ({
                localStorage: Object.keys(window.localStorage || {}),
                sessionStorage: Object.keys(window.sessionStorage || {})
            })"""
        )
        ctx.recon["browser_storage_keys"] = storage
        cookies = await context.cookies()
        ctx.recon["browser_cookies"] = [
            f"{item.get('name')}: HttpOnly={item.get('httpOnly')} Secure={item.get('secure')} SameSite={item.get('sameSite')}"
            for item in cookies[:50]
        ]
        if ctx.policy.evidence_cards:
            screenshot_path = evidence_dir / f"{self._slug(ctx.target.display)}_landing.png"
            await page.screenshot(path=str(screenshot_path), full_page=True)
            ctx.recon["browser_screenshots"] = sorted(
                set(ctx.recon.get("browser_screenshots", []) + [str(screenshot_path)])
            )

    async def _validated_dom_xss(
        self,
        ctx: ScanContext,
        page: Any,
        dialogs: list[str],
        evidence_dir: Path,
    ) -> list[Finding]:
        findings: list[Finding] = []
        payload = "<img src=x onerror=alert('scan_titan_dom')>"
        test_urls = [
            ctx.target.url + ("&" if "?" in ctx.target.url else "?") + "scan_titan_dom=" + urllib.parse.quote(payload),
            urllib.parse.urljoin(ctx.target.url, "/#/" + urllib.parse.quote(payload)),
        ]
        for idx, url in enumerate(test_urls, start=1):
            before = len(dialogs)
            ctx.heartbeat(self.name, f"dom-xss {idx}", idx, len(findings))
            try:
                await page.goto(url, wait_until="networkidle", timeout=ctx.policy.browser_timeout_seconds * 1000)
                await page.wait_for_timeout(1000)
            except Exception:
                continue
            if len(dialogs) <= before:
                continue
            screenshot_path = Path("")
            if ctx.policy.evidence_cards:
                screenshot_path = evidence_dir / f"{self._slug(ctx.target.display)}_dom_xss_{idx}.png"
                try:
                    await page.screenshot(path=str(screenshot_path), full_page=True)
                except Exception:
                    screenshot_path = Path("")
            findings.append(
                Finding(
                    target=ctx.target.display,
                    category="Browser/DOM XSS",
                    severity="High",
                    title="Validated DOM XSS dialog execution",
                    url=url,
                    payload=payload,
                    evidence=f"Browser dialog observed: {dialogs[-1]}",
                    source=self.name,
                    confidence="high",
                    cwe="CWE-79",
                    owasp="A05:2025 - Inyección",
                    recommendation="Ensure URL, query, and hash-derived values are contextually encoded before DOM insertion.",
                    evidence_artifact=str(screenshot_path) if str(screenshot_path) else "",
                )
            )
            break
        return findings

    async def _crawl_routes(self, ctx: ScanContext, page: Any, evidence_dir: Path) -> list[Finding]:
        findings: list[Finding] = []
        routes = ctx.recon.get("browser_routes", [])[: ctx.policy.browser_max_pages]
        login_like: list[str] = []
        for idx, route in enumerate(routes, start=1):
            ctx.heartbeat(self.name, f"crawl {urllib.parse.urlparse(route).path or '/'}", idx, len(findings))
            try:
                await page.goto(route, wait_until="networkidle", timeout=ctx.policy.browser_timeout_seconds * 1000)
                body_text = (await page.locator("body").inner_text(timeout=3000))[:4000]
            except Exception:
                continue
            if re.search(r"\b(password|sign in|login|otp|mfa|2fa)\b", body_text, flags=re.IGNORECASE):
                login_like.append(route)
        if login_like:
            ctx.recon["browser_login_routes"] = sorted(set(ctx.recon.get("browser_login_routes", []) + login_like))[:80]
            findings.append(
                Finding(
                    target=ctx.target.display,
                    category="Browser/Recon",
                    severity="Info",
                    title="Browser crawl identified login/auth routes",
                    url=ctx.target.url,
                    evidence=clean_text(login_like, 500),
                    source=self.name,
                    confidence="medium",
                )
            )
        return findings

    async def _dismiss_dialog(self, dialog: Any, dialogs: list[str]) -> None:
        try:
            dialogs.append(dialog.message)
            await dialog.dismiss()
        except Exception:
            pass

    def _slug(self, value: str) -> str:
        return re.sub(r"[^A-Za-z0-9._-]+", "_", value).strip("_")[:90] or "target"
