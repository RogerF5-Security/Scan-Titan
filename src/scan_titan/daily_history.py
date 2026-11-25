"""Vulnerability timeline for the Daily report.

Builds a day-by-day view of the vulnerabilities considered present, suitable
for comparing dates:

* Carry-forward: on each date every target contributes the findings of its most
  recent scan on or before that date. A target that was not scanned that day
  keeps its previous state instead of looking "resolved".
* Identity is recomputed with the current canonical families, so ES/EN titles
  and older IDs of the same vulnerability count once across the whole history.
* Quality rules are applied to historical reports as well, so the series does
  not drop artificially when a noisy class was later moved to "Por validar".
"""
from __future__ import annotations

import base64
import io
import json
from collections import Counter, defaultdict
from pathlib import Path
from typing import Any

from quality_rules import finding_quality_exclusion

try:
    from modules.common import canonical_vulnerability_family, canonical_vulnerability_id, normalize_severity
except Exception:  # pragma: no cover - standalone fallback
    canonical_vulnerability_family = None  # type: ignore[assignment]
    canonical_vulnerability_id = None  # type: ignore[assignment]

    def normalize_severity(value: Any) -> str:  # type: ignore[no-redef]
        return str(value or "Info").title()

SEVERITIES = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]


def _severity(value: Any) -> str:
    return normalize_severity(value or "Info").upper()


def _identity(finding: dict[str, Any]) -> tuple[str, str]:
    if canonical_vulnerability_id is None:
        key = str(finding.get("canonical_id") or finding.get("title") or "")
        return key, ""
    return canonical_vulnerability_id(finding), canonical_vulnerability_family(finding)


def load_scans(reports_dir: Path) -> list[dict[str, Any]]:
    """One entry per (target, date): the last report of that day, empty scans included."""
    latest: dict[tuple[str, str], dict[str, Any]] = {}
    for path in sorted(reports_dir.glob("*.json")):
        if path.name.startswith(("coverage_", "recon_", "ffuf_", "whatweb_", "scan_titan_", "tool_")):
            continue
        try:
            data = json.loads(path.read_text(encoding="utf-8", errors="ignore"))
        except (OSError, ValueError):
            continue
        if not isinstance(data, dict) or data.get("schema") != "scan_titan_target_report_v1":
            continue
        timestamp = str(data.get("date") or "")
        target = str(data.get("target") or data.get("url") or "")
        if len(timestamp) < 10 or not target:
            continue
        items: dict[str, dict[str, str]] = {}
        for finding in data.get("findings") or []:
            if not isinstance(finding, dict) or finding_quality_exclusion(finding):
                continue
            severity = _severity(finding.get("severity"))
            if severity == "INFO":
                continue
            key, family = _identity(finding)
            previous = items.get(key)
            if previous and SEVERITIES.index(previous["severity"]) <= SEVERITIES.index(severity):
                continue
            items[key] = {"severity": severity, "title": str(finding.get("title") or ""),
                          "category": str(finding.get("category") or ""), "family": family}
        coverage = data.get("coverage") if isinstance(data.get("coverage"), dict) else {}
        unreachable = str((coverage.get("http_availability") or {}).get("state", "")).lower() == "unreachable"
        scan = {"target": target, "date": timestamp[:10], "timestamp": timestamp, "items": items,
                "unreachable": unreachable}
        current = latest.get((target, scan["date"]))
        if current is None or current["timestamp"] <= timestamp:
            latest[(target, scan["date"])] = scan
    return sorted(latest.values(), key=lambda scan: scan["timestamp"])


def build_timeline(reports_dir: Path, max_dates: int = 120) -> dict[str, Any]:
    scans = load_scans(Path(reports_dir))
    if not scans:
        return {"dates": [], "series": [], "targets": {}, "items": [], "snapshots": {}, "scanned": {}}
    by_target: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for scan in scans:
        by_target[scan["target"]].append(scan)
    dates = sorted({scan["date"] for scan in scans})[-max_dates:]
    catalog: dict[str, int] = {}
    items: list[list[str]] = []
    series, snapshots, target_series = [], {}, defaultdict(list)
    scanned = {date: sorted({s["target"] for s in scans if s["date"] == date}) for date in dates}
    previous: set[str] = set()
    for date in dates:
        unreachable_today: set[str] = set()
        present: set[str] = set()
        counts = Counter()
        for target, history in by_target.items():
            state, observed = None, None
            for scan in history:
                if scan["date"] > date:
                    break
                state = scan
                if not scan["unreachable"]:
                    observed = scan
            if state is None:
                continue
            # A target that did not answer HTTP is not "fixed": keep its last
            # observed web state and add whatever this scan did see.
            current = dict(observed["items"]) if (state["unreachable"] and observed) else {}
            current.update(state["items"])
            if state["unreachable"] and state["date"] == date:
                unreachable_today.add(target)
            target_counts = Counter()
            for key, item in current.items():
                composite = f"{target}|{key}"
                if composite not in catalog:
                    catalog[composite] = len(items)
                    items.append([target, item["severity"], item["title"], item["category"], item["family"], key])
                else:  # keep the most recent wording and severity (titles became Spanish over time)
                    entry = items[catalog[composite]]
                    entry[1], entry[2], entry[3] = item["severity"], item["title"], item["category"]
                present.add(composite)
                counts[item["severity"]] += 1
                target_counts[item["severity"]] += 1
            target_series[target].append({"date": date, "total": sum(target_counts.values()),
                                          "last_scan": state["date"],
                                          **{s: target_counts.get(s, 0) for s in SEVERITIES[:4]}})
        new, resolved = present - previous, previous - present
        series.append({"date": date, "total": sum(counts.values()), **{s: counts.get(s, 0) for s in SEVERITIES[:4]},
                       "new": len(new) if previous else 0, "resolved": len(resolved),
                       "new_ids": sorted(catalog[k] for k in new) if previous else [],
                       "resolved_ids": sorted(catalog[k] for k in resolved),
                       "targets_scanned": len(scanned[date]), "targets_unreachable": len(unreachable_today)})
        snapshots[date] = sorted(catalog[key] for key in present)
        previous = present
    return {"dates": dates, "series": series, "targets": dict(target_series), "items": items,
            "snapshots": snapshots, "scanned": scanned}


_LOGO_CACHE: dict[str, str] = {}


def logo_data_uri(base_dir: Path, size: int = 160) -> str:
    """Small embedded PNG of the project logo (keeps the Daily a single offline file)."""
    candidates = [base_dir / "assets" / "scan-titan-logo.png", base_dir / "ScanTitanlogo.png",
                  Path(__file__).resolve().parents[2] / "assets" / "scan-titan-logo.png"]
    source = next((path for path in candidates if path.is_file()), None)
    if source is None:
        return ""
    key = f"{source}|{source.stat().st_mtime}|{size}"
    if key in _LOGO_CACHE:
        return _LOGO_CACHE[key]
    try:
        from PIL import Image

        with Image.open(source) as image:
            image = image.convert("RGBA")
            image.thumbnail((size, size))
            buffer = io.BytesIO()
            image.save(buffer, format="PNG", optimize=True)
        data = buffer.getvalue()
    except Exception:
        data = source.read_bytes() if source.stat().st_size < 300_000 else b""
    uri = "data:image/png;base64," + base64.b64encode(data).decode("ascii") if data else ""
    _LOGO_CACHE[key] = uri
    return uri
