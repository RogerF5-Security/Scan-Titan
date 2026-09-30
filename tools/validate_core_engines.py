"""Bounded integration smoke using installed engines against a loopback fixture only."""
from __future__ import annotations

import asyncio
import json
import os
import socket
import sys
import tempfile
from pathlib import Path
from types import SimpleNamespace

from aiohttp import web

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
import main as launcher
launcher.configure_environment()
launcher.engine_path_ready()
from Main import ExternalTools, RuntimeConfig, build_argparser
from modules.common import Target


async def validate() -> dict:
    app = web.Application()
    async def fixture(request):
        response = web.Response(text='<html><head><title>Titan fixture</title></head><body><a href="/page">page</a>SCAN_TITAN_LOCAL_FIXTURE<form method="POST" action="/login"><input name="password" type="password"></form></body></html>',
                                content_type='text/html', headers={'X-Powered-By': 'PHP/5.3.0'})
        response.set_cookie('sessionid', 'fixture-insecure-cookie')
        return response
    app.router.add_get('/', fixture)
    app.router.add_get('/page', fixture)
    runner = web.AppRunner(app)
    await runner.setup()
    site = web.TCPSite(runner, '127.0.0.1', 0)
    await site.start()
    port = site._server.sockets[0].getsockname()[1]
    url = f'http://127.0.0.1:{port}/'
    evidence = ROOT / 'version_backups' / 'core_upgrade_20260929' / 'engine_smoke'
    evidence.mkdir(parents=True, exist_ok=True)
    results = {}
    try:
        cfg = RuntimeConfig(build_argparser().parse_args([]))
        cfg.telemetry = None
        cfg.external_reports_dir = evidence
        tools = ExternalTools(cfg)
        ctx = SimpleNamespace(target=Target(url, url, '127.0.0.1', '127.0.0.1', 'http', port),
                              recon={}, heartbeat=lambda *args: None,
                              http=SimpleNamespace(request=None))
        binary = tools._resolve_binary('nuclei', 'nuclei')
        if binary:
            template = evidence / 'fixture.yaml'
            template.write_text('''id: scan-titan-loopback-fixture
info:
  name: Scan Titan loopback fixture
  author: scan-titan
  severity: info
http:
  - method: GET
    path:
      - "{{BaseURL}}/page"
    matchers:
      - type: word
        words:
          - "SCAN_TITAN_LOCAL_FIXTURE"
''', encoding='utf-8')
            output = evidence / 'nuclei.jsonl'
            command = [binary, '-u', url, '-t', str(template), '-duc', '-ni', '-jsonl',
                       '-jle', str(output), '-timeout', '2', '-retries', '0', '-stats-json']
            out, err, timed_out, rc, duration = await tools._run_command(command, 30)
            findings, parse_error = tools._parse_nuclei_with_status(ctx, output, out)
            results['nuclei'] = {'rc': rc, 'timed_out': timed_out, 'duration': duration,
                                'findings': len(findings), 'parser_error': parse_error,
                                'passed': rc == 0 and not timed_out and len(findings) == 1 and not parse_error}
        else:
            results['nuclei'] = {'passed': False, 'reason': 'binary unavailable'}
        if tools._resolve_zap_binary():
            with socket.socket() as sock:
                sock.bind(('127.0.0.1', 0))
                cfg.zap_port = sock.getsockname()[1]
            cfg.zap_host = '127.0.0.1'
            cfg.zap_api_url = f'http://127.0.0.1:{cfg.zap_port}'
            cfg.zap_api_key = ''
            cfg.zap_mode = 'active'
            cfg.zap_start_daemon = True
            cfg.zap_shutdown_after_scan = True
            cfg.zap_startup_timeout = 60
            cfg.zap_spider_timeout = 15
            cfg.zap_active_timeout = 15
            cfg.zap_passive_timeout = 15
            cfg.zap_progress_timeout = 10
            cfg.zap_max_seed_urls = 2
            cfg.zap_max_alerts = 100
            async def keep_alerts(ctx, alerts):
                return alerts, []
            tools._filter_zap_soft_auth_redirect_alerts = keep_alerts
            # Smoke evidence belongs here, not in the user's scan history.
            tools._log_external = lambda *args, **kwargs: None
            shutdown = tools._zap_shutdown
            async def diagnostic_shutdown(process):
                try:
                    diag = {}
                    for path in ['core/view/numberOfAlerts', 'core/view/alerts', 'pscan/view/scanners', 'core/view/sites']:
                        diag[path] = await tools._zap_api(path)
                    (evidence / 'zap_diagnostics.json').write_text(json.dumps(diag, indent=2), encoding='utf-8')
                finally:
                    await shutdown(process)
            tools._zap_shutdown = diagnostic_shutdown
            findings = await tools.run_zap(ctx)
            coverage = ctx.recon.get('external_coverage', [])
            results['zap'] = {'findings': len(findings), 'coverage': coverage,
                              'passed': bool(findings and coverage and coverage[-1]['state'] in {'completed', 'partial'})}
        else:
            results['zap'] = {'passed': False, 'reason': 'binary unavailable'}
        result_path = evidence / 'result.json'
        result_path.write_text(json.dumps(results, indent=2), encoding='utf-8')
        print(json.dumps(results, indent=2))
        return results
    finally:
        await runner.cleanup()


if __name__ == '__main__':
    result = asyncio.run(validate())
    raise SystemExit(0 if all(item['passed'] for item in result.values()) else 1)
