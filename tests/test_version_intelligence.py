from __future__ import annotations

import datetime as dt
import sys
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import AsyncMock, patch

import pandas as pd
import aiohttp

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'src' / 'scan_titan'))
import Dashboard
from version_intelligence import VersionAuditor, VersionCatalog, extract_components


class VersionCatalogTests(unittest.IsolatedAsyncioTestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.db = VersionCatalog(Path(self.tmp.name) / 'db.json')
        self.db.data['sources'] = {
            'retirejs': {'data': {'jquery': {'vulnerabilities': [
                {'atOrAbove': '1.0.0', 'below': '3.5.0', 'severity': 'medium',
                 'identifiers': {'CVE': ['CVE-2020-11022']}, 'info': ['https://jquery.com/']}
            ]}}},
            'php_advisories': {'data': [{'cve_id': 'CVE-fixture', 'severity': 'critical',
                'vulnerabilities': [
                    {'patched_versions': '8.2.35', 'vulnerable_version_range': '< 8.2.35'},
                    {'patched_versions': '8.3.36', 'vulnerable_version_range': '< 8.3.36'},
                    {'patched_versions': '8.5.12', 'vulnerable_version_range': '< 8.5.12'},
                ]}]},
            'eol:php': {'data': {'result': {'releases': [
                {'name': '8.1', 'eolFrom': '2025-12-31'},
                {'name': '8.2', 'eolFrom': '2026-12-31'},
            ]}}},
        }

    def tearDown(self):
        self.tmp.cleanup()

    def test_library_range_boundaries(self):
        self.assertTrue(self.db.issues('jquery', '3.4.1'))
        self.assertFalse(self.db.issues('jquery', '3.5.0'))
        self.assertFalse(self.db.issues('jquery', '3.10.0'))

    async def test_failed_update_keeps_offline_catalog(self):
        original = self.db.data
        with patch('version_intelligence.download_json', new=AsyncMock(side_effect=aiohttp.ClientError('offline'))):
            result = await self.db.refresh(force=True)
        self.assertEqual(result['updated'], 0)
        self.assertGreater(result['errors'], 0)
        self.assertIs(self.db.data, original)
        self.assertTrue(self.db.issues('jquery', '3.4.1'))

    async def test_real_http_header_is_collected_without_extra_request(self):
        import asyncio
        from aiohttp import web
        from modules.common import AsyncHttpClient, ScanLimits

        async def handler(request):
            return web.Response(text='OK', headers={'X-Powered-By': 'PHP/8.2.34'})

        app = web.Application()
        app.router.add_get('/', handler)
        runner = web.AppRunner(app)
        await runner.setup()
        site = web.TCPSite(runner, '127.0.0.1', 0)
        await site.start()
        port = site._server.sockets[0].getsockname()[1]
        try:
            async with aiohttp.ClientSession() as session:
                limits = ScanLimits(jitter_min_seconds=0, jitter_max_seconds=0)
                client = AsyncHttpClient(session, asyncio.Semaphore(2), limits)
                await client.request('GET', f'http://127.0.0.1:{port}/')
                self.assertEqual(client.requests_started, 1)
                self.assertEqual(client.version_observations[0]['version'], '8.2.34')
        finally:
            await runner.cleanup()

    def test_php_upper_bound_is_scoped_to_branch(self):
        self.assertTrue(self.db.issues('php', '8.2.34', dt.date(2026, 11, 5)))
        self.assertFalse(self.db.issues('php', '8.3.36', dt.date(2026, 11, 5)))
        self.assertFalse(self.db.issues('php', '8.5.12'))

    def test_eol_is_distinct_from_cve_and_partial_version(self):
        self.assertEqual(self.db.issues('php', '8.1', dt.date(2026, 11, 5))[0]['kind'], 'eol')
        self.assertFalse(self.db.issues('php', '8.2', dt.date(2026, 11, 5)))
        self.assertFalse(self.db.issues('php', '8.1.31-ubuntu1'))

    def test_extract_explicit_versions_from_header_and_js_url(self):
        records = extract_components('Apache/2.4.55 PHP/8.2.34 jquery-3.4.1.min.js', 'https://example.test/', 'header')
        self.assertEqual([(r['product'], r['version']) for r in records],
                         [('apache-http-server', '2.4.55'), ('php', '8.2.34'), ('jquery', '3.4.1')])
        self.assertEqual(extract_components('PHP jQuery React', '', ''), [])

    def test_apache_v5_range_and_v4_exact(self):
        self.db.data['sources']['apache_advisories'] = {'data': [
            {'cveMetadata': {'cveId': 'CVE-range'}, 'containers': {'cna': {'affected': [
                {'product': 'Apache HTTP Server', 'versions': [
                    {'version': '2.4.0', 'lessThanOrEqual': '2.4.59', 'status': 'affected'}]}]}}},
            {'CVE_data_meta': {'ID': 'CVE-exact'}, 'affects': {'vendor': {'vendor_data': [
                {'product': {'product_data': [{'product_name': 'Apache HTTP Server',
                    'version': {'version_data': [{'version_value': '2.4.49', 'version_affected': '='}]}}]}}]}}},
        ]}
        self.assertEqual(len(self.db.issues('apache-http-server', '2.4.49')), 2)
        self.assertFalse(self.db.issues('apache-http-server', '2.4.60'))

    async def test_auditor_emits_vulnerability_and_does_not_fetch_third_party(self):
        http = SimpleNamespace(version_observations=extract_components('PHP/8.2.34', 'https://example.test/', 'header'),
                               request=AsyncMock(return_value=SimpleNamespace(status=200, text='jQuery v3.4.1')))
        ctx = SimpleNamespace(http=http, target=SimpleNamespace(url='https://example.test/', display='example.test'),
                              recon={'js_libraries': ['https://example.test/app.js', 'https://cdn.example/app.js']},
                              limits=SimpleNamespace(timeout=8), should_stop=lambda: False, heartbeat=lambda *a: None)
        findings = await VersionAuditor(self.db).run(ctx)
        self.assertGreaterEqual(len(findings), 2)
        self.assertTrue(all(f.category == 'Componentes/Versiones' and f.manual_command for f in findings))
        http.request.assert_awaited_once()
        self.assertEqual(http.request.await_args.args[1], 'https://example.test/app.js')


class DashboardCountTests(unittest.TestCase):
    def test_version_match_is_not_displayed_as_functionally_validated(self):
        row = Dashboard._record_from_state(
            {'source': 'version_intelligence', 'severity': 'High'}, {}, '2026-11-05')
        self.assertEqual(row['quality'], 'CANDIDATE')

    def test_active_snapshot_does_not_use_daily_observation_count(self):
        records = {str(n): {'canonical_id': str(n), 'target': 'example.test', 'asset': 'example.test',
                           'state': 'ACTIVE', 'severity': 'Medium', 'title': f'Finding {n}',
                           'first_seen': '2026-10-01', 'last_seen': '2026-11-04'} for n in range(82)}
        df = pd.DataFrame([{'Asset': 'example.test', 'Vuln_ID': str(n), 'Target': 'example.test',
                            'Timestamp': pd.Timestamp('2026-11-04'), 'Fecha': pd.Timestamp('2026-11-04'),
                            'Severidad': 'MEDIUM'} for n in range(12)])
        with patch.object(Dashboard, 'cargar_estado_hallazgos', return_value=records):
            model = Dashboard.construir_modelo(df)
        self.assertEqual(model['meta']['active'], 82)
        self.assertEqual(model['active_snapshot'][0]['total'], 82)
        self.assertEqual(model['history'][0]['total'], 12)
        self.assertEqual(sum(model['meta']['severity'].values()), 82)


if __name__ == '__main__':
    unittest.main()
