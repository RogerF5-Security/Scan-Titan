"""Verify the actual generated Daily in a browser without making network requests."""
from __future__ import annotations

import argparse
import json
from pathlib import Path

from playwright.sync_api import sync_playwright


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument('report', type=Path)
    parser.add_argument('--screenshot', type=Path)
    args = parser.parse_args()
    report = args.report.resolve()
    state = json.loads(report.with_name('scan_titan_state.json').read_text(encoding='utf-8'))
    expected = sum(item.get('state') == 'ACTIVE' for item in state['findings'].values())
    errors = []
    with sync_playwright() as browser_runtime:
        browser = browser_runtime.chromium.launch(headless=True)
        page = browser.new_page(viewport={'width': 1440, 'height': 1080})
        page.route('http://**', lambda route: route.abort())
        page.route('https://**', lambda route: route.abort())
        page.on('pageerror', lambda error: errors.append(str(error)))
        page.goto(report.as_uri())
        page.wait_for_selector('#history .bar-total')
        model = page.locator('#dashboardData').evaluate('(n) => JSON.parse(n.textContent)')
        visible = int(page.locator('#history .bar-total').inner_text())
        assert model['meta']['active'] == visible == expected, (expected, visible)
        page.select_option('#historyMetric', 'observed')
        last_observed = int(page.locator('#history .bar-total').last.inner_text())
        assert last_observed == model['history'][-1]['total']
        page.select_option('#historyMetric', 'active')
        if args.screenshot:
            args.screenshot.parent.mkdir(parents=True, exist_ok=True)
            page.screenshot(path=str(args.screenshot), full_page=True)
        page.set_viewport_size({'width': 390, 'height': 844})
        assert page.evaluate('document.documentElement.scrollWidth <= window.innerWidth')
        assert not errors, errors
        browser.close()
    print(json.dumps(dict(active=expected, chart=visible, last_observed=last_observed, browser_errors=errors)))
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
