"""Data helpers for the standalone Daily (rendering lives in daily_report.py)."""
from __future__ import annotations

import json
from pathlib import Path


def intelligence_model(reports: Path):
    """JavaScript reconnaissance and differential-validation records per target."""
    items = []
    for path in sorted(reports.glob("recon_intelligence_*.json")):
        try:
            item = json.loads(path.read_text(encoding="utf-8"))
            if isinstance(item, dict):
                items.append(item)
        except (OSError, ValueError):
            continue
    return items
