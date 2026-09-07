from __future__ import annotations

import json
import re
from datetime import datetime
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

from modules.common import Finding, clean_text

try:
    from PIL import Image, ImageDraw, ImageFont, ImageGrab

    PIL_AVAILABLE = True
except ImportError:
    Image = ImageDraw = ImageFont = ImageGrab = None  # type: ignore[assignment]
    PIL_AVAILABLE = False


class EvidenceManager:
    """Creates stable visual artifacts for new findings.

    Evidence cards are generated from the finding data, so they work even when
    the PowerShell window is minimized. Console screenshots are best-effort and
    depend on an interactive Windows desktop session.
    """

    CARD_VERSION = "3"
    BROWSER_VERSION = "1"

    def __init__(
        self,
        reports_dir: Path,
        *,
        enable_cards: bool = True,
        enable_console_screenshots: bool = False,
        enable_browser_evidence: bool = True,
        browser_timeout_seconds: int = 15,
        browser_full_page: bool = True,
        browser_max_per_target: int = 150,
    ) -> None:
        self.root = reports_dir / "evidence_screenshots"
        self.browser_root = reports_dir / "browser_evidence"
        self.index_path = self.root / "evidence_index.json"
        self.enable_cards = enable_cards
        self.enable_console_screenshots = enable_console_screenshots
        self.enable_browser_evidence = enable_browser_evidence
        self.browser_timeout_seconds = max(3, int(browser_timeout_seconds or 15))
        self.browser_full_page = browser_full_page
        self.browser_max_per_target = max(1, int(browser_max_per_target or 150))
        self.index = self._load_index()

    def attach_artifacts(
        self,
        findings: list[Finding],
        timestamp: str,
        *,
        capture_browser: bool = False,
    ) -> None:
        if not any(
            [
                self.enable_cards,
                self.enable_console_screenshots,
                capture_browser and self.enable_browser_evidence,
            ]
        ):
            return
        changed = False
        browser_counts: dict[str, int] = {}
        for finding in findings:
            if finding.severity == "Info":
                continue
            target_key = str(finding.target or finding.asset or "target")
            existing = self.index.get(finding.fingerprint)
            has_existing_browser = (
                isinstance(existing, dict)
                and bool(existing.get("browser_screenshot"))
                and Path(str(existing.get("browser_screenshot"))).exists()
            )
            should_capture_browser = capture_browser and (
                browser_counts.get(target_key, 0) < self.browser_max_per_target
                or has_existing_browser
            )
            item = self._ensure_artifact(
                finding,
                timestamp,
                capture_browser=should_capture_browser,
            )
            if item:
                finding.evidence_artifact = item.get("evidence_card", "")
                finding.console_artifact = item.get("console_screenshot", "")
                finding.browser_artifact = item.get("browser_screenshot", "")
                if should_capture_browser and item.get("browser_screenshot"):
                    browser_counts[target_key] = browser_counts.get(target_key, 0) + 1
                changed = True
        if changed:
            self._save_index()

    def _ensure_artifact(
        self,
        finding: Finding,
        timestamp: str,
        *,
        capture_browser: bool = False,
    ) -> dict[str, str]:
        key = finding.fingerprint
        existing = self.index.get(key) if isinstance(self.index.get(key), dict) else {}
        slug = self._slug(f"{finding.severity}_{finding.target}_{key[:12]}")
        item = {
            "id": key[:16],
            "target": finding.target,
            "title": finding.title,
            "severity": finding.severity,
            "first_created": existing.get("first_created", timestamp) if isinstance(existing, dict) else timestamp,
            "card_version": self.CARD_VERSION,
            "browser_version": self.BROWSER_VERSION,
            "evidence_card": "",
            "console_screenshot": "",
            "browser_screenshot": "",
        }
        if isinstance(existing, dict):
            item.update(
                {
                    "evidence_card": existing.get("evidence_card", ""),
                    "console_screenshot": existing.get("console_screenshot", ""),
                    "browser_screenshot": existing.get("browser_screenshot", ""),
                }
            )
        needs_card = (
            self.enable_cards
            and (
                not item.get("evidence_card")
                or (isinstance(existing, dict) and existing.get("card_version") != self.CARD_VERSION)
                or not Path(str(item.get("evidence_card") or "")).exists()
            )
        )
        if needs_card:
            self.root.mkdir(parents=True, exist_ok=True)
            card_path = self.root / f"{slug}.png"
            if self._create_card(finding, timestamp, card_path):
                item["evidence_card"] = str(card_path)
            else:
                text_path = self.root / f"{slug}.txt"
                self._create_text_fallback(finding, timestamp, text_path)
                item["evidence_card"] = str(text_path)
        if self.enable_console_screenshots and not item.get("console_screenshot"):
            self.root.mkdir(parents=True, exist_ok=True)
            screenshot_path = self.root / f"{slug}_console.png"
            if self._capture_console(screenshot_path):
                item["console_screenshot"] = str(screenshot_path)
        if capture_browser and self.enable_browser_evidence:
            browser_path = Path(str(item.get("browser_screenshot") or ""))
            if not item.get("browser_screenshot") or not browser_path.exists():
                self.browser_root.mkdir(parents=True, exist_ok=True)
                screenshot_path = self.browser_root / f"{slug}_browser.png"
                if self._capture_browser(finding, screenshot_path):
                    item["browser_screenshot"] = str(screenshot_path)
        self.index[key] = item
        return item

    def _create_card(self, finding: Finding, timestamp: str, path: Path) -> bool:
        if not PIL_AVAILABLE:
            return False
        try:
            width, height = 1600, 980
            image = Image.new("RGB", (width, height), color=(10, 15, 25))
            draw = ImageDraw.Draw(image)
            title_font = self._font(42, bold=True)
            head_font = self._font(25, bold=True)
            body_font = self._font(21)
            mono_font = self._font(19)
            colors = {
                "Critical": (239, 68, 68),
                "High": (248, 113, 113),
                "Medium": (245, 158, 11),
                "Low": (34, 211, 238),
            }
            accent = colors.get(finding.severity, (229, 231, 235))
            draw.rectangle((0, 0, width, 92), fill=(15, 23, 42))
            draw.rectangle((0, 92, width, 102), fill=accent)
            draw.text((36, 24), "SCAN TITAN - EVIDENCE CARD", fill=(255, 255, 255), font=title_font)

            y = 122
            title_lines = self._wrap(f"{finding.severity.upper()} | {finding.title}", 112)
            for line in title_lines[:3]:
                draw.text((36, y), line, fill=accent, font=head_font)
                y += 32
            y += 12

            fields = [
                ("Evidence ID", finding.fingerprint[:16], 1, 520),
                ("Target", finding.target, 1, 520),
                ("Timestamp", timestamp, 1, 520),
                ("Category", finding.category, 1, 520),
                ("Confidence", finding.confidence or "-", 1, 520),
                ("CWE", finding.cwe or "-", 1, 520),
                ("OWASP", finding.owasp or "-", 1, 520),
                ("CVSS", finding.cvss or "-", 1, 520),
                ("URL", finding.url or finding.endpoint or "-", 2, 700),
                ("Payload", finding.payload or "-", 2, 700),
                ("Evidence", finding.evidence or "-", 8, 1400),
                ("Recommendation", finding.recommendation or finding.remediation or "-", 4, 900),
            ]
            for label, value, max_lines, text_limit in fields:
                draw.text((44, y), f"{label}:", fill=(148, 163, 184), font=body_font)
                wrapped = self._wrap(clean_text(value, text_limit), 126 if label in {"Evidence", "Recommendation"} else 118)
                x_value = 230
                visible = wrapped[:max_lines]
                for idx, line in enumerate(visible):
                    draw.text((x_value, y + idx * 25), line, fill=(226, 232, 240), font=mono_font)
                if len(wrapped) > max_lines and y + len(visible) * 25 < height - 96:
                    draw.text((x_value, y + len(visible) * 25), "...ver reporte JSON/TXT para evidencia completa", fill=(251, 191, 36), font=mono_font)
                    visible = visible + ["..."]
                y += max(34, 25 * len(visible) + 10)
                if y > height - 72:
                    break
            draw.text(
                (44, height - 48),
                "Generated once per unique finding fingerprint. First Seen / Last Seen managed by scan_titan_state.json.",
                fill=(100, 116, 139),
                font=mono_font,
            )
            image.save(path)
            return True
        except Exception:
            return False

    def _capture_console(self, path: Path) -> bool:
        if not PIL_AVAILABLE:
            return False
        try:
            shot = ImageGrab.grab()
            shot.save(path)
            return True
        except Exception:
            return False

    def _capture_browser(self, finding: Finding, path: Path) -> bool:
        url = str(finding.url or finding.endpoint or "").strip()
        parsed = urlparse(url)
        if parsed.scheme not in {"http", "https"} or not parsed.netloc:
            return False
        try:
            from playwright.sync_api import sync_playwright
        except Exception:
            return False
        browser = context = page = None
        try:
            with sync_playwright() as playwright:
                browser = playwright.chromium.launch(headless=True)
                context = browser.new_context(
                    ignore_https_errors=True,
                    viewport={"width": 1440, "height": 1000},
                    user_agent=(
                        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
                        "AppleWebKit/537.36 Chrome/124 Safari/537.36 ScanTitanEvidence"
                    ),
                )
                page = context.new_page()
                page.goto(
                    url,
                    wait_until="domcontentloaded",
                    timeout=self.browser_timeout_seconds * 1000,
                )
                try:
                    page.wait_for_load_state("networkidle", timeout=5000)
                except Exception:
                    pass
                page.screenshot(
                    path=str(path),
                    full_page=self.browser_full_page,
                    timeout=max(3000, self.browser_timeout_seconds * 1000),
                )
            return path.exists() and path.stat().st_size > 0
        except Exception:
            return False
        finally:
            for item in (page, context, browser):
                try:
                    if item is not None:
                        item.close()
                except Exception:
                    pass

    def _create_text_fallback(self, finding: Finding, timestamp: str, path: Path) -> None:
        lines = [
            "SCAN TITAN - EVIDENCE CARD FALLBACK",
            f"ID: {finding.fingerprint[:16]}",
            f"Timestamp: {timestamp}",
            f"Severity: {finding.severity}",
            f"Target: {finding.target}",
            f"Title: {finding.title}",
            f"URL: {finding.url}",
            f"Payload: {finding.payload}",
            f"Evidence: {finding.evidence}",
            f"Recommendation: {finding.recommendation}",
            f"Manual Test: {finding.manual_command}",
        ]
        path.write_text("\n".join(lines), encoding="utf-8")

    def _font(self, size: int, *, bold: bool = False) -> Any:
        if not PIL_AVAILABLE:
            return None
        candidates = [
            "C:/Windows/Fonts/consolab.ttf" if bold else "C:/Windows/Fonts/consola.ttf",
            "C:/Windows/Fonts/arialbd.ttf" if bold else "C:/Windows/Fonts/arial.ttf",
        ]
        for candidate in candidates:
            try:
                if Path(candidate).exists():
                    return ImageFont.truetype(candidate, size=size)
            except Exception:
                continue
        return ImageFont.load_default()

    def _load_index(self) -> dict[str, Any]:
        if not self.index_path.exists():
            return {}
        try:
            data = json.loads(self.index_path.read_text(encoding="utf-8"))
            return data if isinstance(data, dict) else {}
        except Exception:
            return {}

    def _save_index(self) -> None:
        self.root.mkdir(parents=True, exist_ok=True)
        tmp = self.index_path.with_suffix(".tmp")
        payload = dict(sorted(self.index.items(), key=lambda item: item[0]))
        tmp.write_text(json.dumps(payload, indent=2, ensure_ascii=False), encoding="utf-8")
        tmp.replace(self.index_path)

    def _wrap(self, text: str, width: int) -> list[str]:
        words = str(text or "").split()
        lines: list[str] = []
        current = ""
        for word in words:
            if len(word) > width:
                if current:
                    lines.append(current)
                    current = ""
                for index in range(0, len(word), width):
                    chunk = word[index : index + width]
                    if len(chunk) == width:
                        lines.append(chunk)
                    else:
                        current = chunk
                continue
            if len(current) + len(word) + 1 > width:
                if current:
                    lines.append(current)
                current = word
            else:
                current = f"{current} {word}".strip()
        if current:
            lines.append(current)
        return lines or [""]

    def _slug(self, value: str) -> str:
        clean = re.sub(r"[^A-Za-z0-9._-]+", "_", value).strip("_")
        return clean[:130] or f"finding_{datetime.now().strftime('%H%M%S')}"
