"""Per-origin soft-404 / catch-all oracle shared by path-based checks.

A route only counts as existing when its response differs from what the server
returns for a random path with the same parent directory and extension. Many
applications answer every unknown path with HTTP 200 (SPA shells, CMS routers),
a redirect to login, a framework debug 404 page or a WAF 403. A single root
baseline without extension misses most of these cases, which is how
non-existent routes became findings.
"""

from __future__ import annotations

import asyncio
import difflib
import html
import re
import secrets
import urllib.parse
from typing import Any

from .common import html_title, is_soft_auth_redirect

_DYNAMIC = re.compile(
    r"\b[0-9a-f]{8,}\b|\b\d+\b|[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}",
    re.IGNORECASE,
)
_SPACES = re.compile(r"\s+")


def _split(url: str) -> tuple[str, str, str]:
    """Return (origin, parent directory, extension) for a URL path."""
    parsed = urllib.parse.urlsplit(url)
    origin = f"{parsed.scheme}://{parsed.netloc}".lower()
    path = parsed.path or "/"
    if path.endswith("/") and path != "/":
        parent = path.rstrip("/").rsplit("/", 1)[0] + "/"
        return origin, parent or "/", "/"
    parent, _, leaf = path.rpartition("/")
    parent = (parent or "") + "/"
    ext = ""
    if "." in leaf.strip("."):
        ext = "." + leaf.rsplit(".", 1)[1].lower()[:12]
    return origin, parent, ext


def _variants(value: str) -> list[str]:
    raw = str(value or "")
    if not raw:
        return []
    items = {raw, urllib.parse.quote(raw), urllib.parse.unquote(raw), html.escape(raw),
             html.escape(urllib.parse.unquote(raw))}
    leaf = raw.rstrip("/").rsplit("/", 1)[-1]
    if len(leaf) >= 3:
        items.update({leaf, urllib.parse.quote(leaf), urllib.parse.unquote(leaf)})
    return sorted((item for item in items if item), key=len, reverse=True)


def normalize_body(text: str, reflections: list[str]) -> str:
    """Lowercased body without reflected path values and volatile tokens."""
    body = str(text or "")[:20000]
    for value in reflections:
        for variant in _variants(value):
            body = body.replace(variant, "\x00")
    body = _DYNAMIC.sub("#", body.lower())
    return _SPACES.sub(" ", body).strip()


def _location(result: Any) -> str:
    headers = getattr(result, "headers", {}) or {}
    for key, value in headers.items():
        if str(key).lower() == "location":
            return str(value)
    return ""


class SoftNotFoundOracle:
    SIMILARITY = 0.90
    TEMPLATE_SIMILARITY = 0.75
    MAX_KEYS = 256

    def __init__(self, http: Any) -> None:
        self.http = http
        self._cache: dict[tuple[str, str, str], list[tuple[Any, str]]] = {}
        self._locks: dict[tuple[str, str, str], asyncio.Lock] = {}
        self.probes = 0

    @classmethod
    def for_context(cls, ctx: Any) -> "SoftNotFoundOracle":
        oracle = getattr(ctx, "soft404_oracle", None)
        if oracle is None or getattr(oracle, "http", None) is not getattr(ctx, "http", None):
            oracle = cls(getattr(ctx, "http", None))
            try:
                setattr(ctx, "soft404_oracle", oracle)
            except (AttributeError, TypeError):
                pass
        return oracle

    async def baselines(self, url: str) -> list[tuple[Any, str]]:
        key = _split(url)
        if key in self._cache:
            return self._cache[key]
        lock = self._locks.setdefault(key, asyncio.Lock())
        async with lock:
            if key in self._cache:
                return self._cache[key]
            origin, parent, ext = key
            plans = [(parent, ext)]
            if ext:
                plans.append((parent, ""))
            if parent != "/":
                plans.append(("/", ext))
            results: list[tuple[Any, str]] = []
            for probe_parent, probe_ext in dict.fromkeys(plans):
                token = f"st404{secrets.token_hex(6)}"
                suffix = "/" if probe_ext == "/" else probe_ext
                probe_url = f"{origin}{probe_parent}{token}{suffix}"
                request = getattr(self.http, "request", None)
                if request is None:
                    break
                self.probes += 1
                try:
                    result = await request("GET", probe_url, allow_redirects=False)
                except Exception:  # network errors must not turn a route into a finding
                    result = None
                if result is not None:
                    results.append((result, token))
            if len(self._cache) >= self.MAX_KEYS:
                self._cache.pop(next(iter(self._cache)))
            self._cache[key] = results
            return results

    async def verdict(self, url: str, result: Any, request_path: str | None = None) -> str:
        """Return why ``result`` is indistinguishable from a non-existent route ('' = distinct)."""
        if result is None:
            return "no response"
        for baseline, token in await self.baselines(url):
            reason = self.compare(result, baseline, request_path or urllib.parse.urlsplit(url).path, token)
            if reason:
                return reason
        return ""

    @classmethod
    def compare(cls, result: Any, baseline: Any, request_path: str = "", token: str = "") -> str:
        if result is None or baseline is None:
            return ""
        if is_soft_auth_redirect(result, baseline, request_path):
            return "redirect/login comun a rutas inexistentes"
        status = getattr(result, "status", None)
        if status != getattr(baseline, "status", None):
            return ""
        reflections = [request_path, token, getattr(result, "url", ""), getattr(baseline, "url", "")]
        if 300 <= int(status or 0) < 400:
            loc_a = normalize_body(_location(result), reflections)
            loc_b = normalize_body(_location(baseline), reflections)
            return f"redireccion {status} identica a ruta inexistente" if loc_a == loc_b else ""
        body_a = normalize_body(getattr(result, "text", ""), reflections)
        body_b = normalize_body(getattr(baseline, "text", ""), reflections)
        if not body_a and not body_b:
            return f"HTTP {status} vacio igual que ruta inexistente"
        ratio = 0.0
        if body_a and body_b:
            matcher = difflib.SequenceMatcher(None, body_a[:6000], body_b[:6000], autojunk=False)
            if matcher.real_quick_ratio() >= cls.TEMPLATE_SIMILARITY and matcher.quick_ratio() >= cls.TEMPLATE_SIMILARITY:
                ratio = matcher.ratio()
        if ratio >= cls.SIMILARITY:
            return f"HTTP {status} con cuerpo {ratio:.0%} similar a ruta inexistente"
        # Same template (title + size) only counts when the bodies are also
        # largely alike; a real page rendered in the same layout must survive.
        size_a = int(getattr(result, "body_len", 0) or 0)
        size_b = int(getattr(baseline, "body_len", 0) or 0)
        title = html_title(getattr(result, "text", ""))
        if (ratio >= cls.TEMPLATE_SIMILARITY and title and title == html_title(getattr(baseline, "text", ""))
                and abs(size_a - size_b) <= max(100, int(max(size_a, size_b) * 0.08))):
            return f"HTTP {status} con mismo titulo, tamano y plantilla que ruta inexistente"
        return ""
