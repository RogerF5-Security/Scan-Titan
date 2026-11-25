from __future__ import annotations

import asyncio
import html
import json
import os
import sys
import tempfile
import threading
import unittest
import urllib.error
import urllib.request
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import AsyncMock, patch
from urllib.parse import parse_qs, urlsplit

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'src' / 'scan_titan'))
from finding_triage import is_discarded, load_decisions, triage_key
from daily_server import create_server
from modules.common import Finding, HttpResult
from modules.injection_validation import InjectionValidator, comparable, file_signature, replay_command, unsafe_reflection
from modules.javascript_recon import analyze_javascript, javascript_recon
from quality_rules import finding_quality_exclusion


def response(text='<html><body>Login</body></html>', status=200, elapsed=.1, content_type='text/html'):
    return HttpResult(url='https://app.test/login/', final_url='https://app.test/login/', status=status,
                      text=text, headers={}, body_len=len(text), elapsed=elapsed, content_type=content_type)


def finding(family='SQLi', payload="'", **kwargs):
    defaults = dict(target='app.test', category=family, severity='High', title=family + ' candidate',
                    url='https://app.test/login/?js=' + __import__('urllib.parse', fromlist=['quote']).quote(payload),
                    param='js', payload=payload, method='GET', source='zap:40018')
    defaults.update(kwargs)
    return Finding(**defaults)


def context(callback):
    return SimpleNamespace(target=SimpleNamespace(url='https://app.test/'),
                           http=SimpleNamespace(request=AsyncMock(side_effect=callback)), recon={},
                           should_stop=lambda: False, heartbeat=lambda *_: None)


class MockCoroutineCase(unittest.TestCase):
    """Drive immediate mock awaits without opening an asyncio self-pipe socket."""
    def _callTestMethod(self, method):
        result = method()
        if hasattr(result, 'send'):
            try:
                result.send(None)
            except StopIteration:
                return
            finally:
                result.close()
            self.fail('A mocked coroutine unexpectedly required a real event loop')


class ReplayTests(MockCoroutineCase):
    async def validate(self, f, callback):
        ctx = context(callback)
        await InjectionValidator().validate_all(ctx, [f])
        return f.validation, ctx

    async def test_ghost_parameter_and_bare_odbc_are_not_sqli(self):
        f = finding(payload='"%0a#')
        result, ctx = await self.validate(f, lambda *_args, **_kw: response('<html>ODBC documentation</html>'))
        self.assertEqual(result['state'], 'FALSE_POSITIVE')
        self.assertEqual(result['reason'], 'route_tolerance_no_injection_evidence')
        self.assertEqual(result['similarity'], 1)
        self.assertTrue(finding_quality_exclusion(f))
        self.assertEqual(len(ctx.recon['injection_triage']), 1)

    async def test_generic_500_is_not_sql_proof(self):
        result, _ = await self.validate(finding(), lambda _m, url, **kw: response('syntax error ODBC', 500) if '?' in url else response())
        self.assertEqual(result['state'], 'INCONCLUSIVE')

    async def test_new_database_error_requires_repeat(self):
        f = finding()
        result, ctx = await self.validate(f, lambda _m, url, **kw: response('SQLSTATE[42000] invalid query', 500) if '?' in url else response())
        self.assertEqual(result['state'], 'CONFIRMED')
        self.assertEqual(ctx.http.request.await_count, 3)
        # The replay prints both responses and the proof, not files to diff by hand.
        self.assertIn("Write-Host '[baseline]'", f.manual_command)
        self.assertIn("Write-Host '[probe]'", f.manual_command)
        self.assertIn("Select-String -SimpleMatch 'SQLSTATE[42000]'", f.manual_command)

    async def test_preexisting_database_error_does_not_confirm(self):
        result, _ = await self.validate(finding(), lambda *a, **kw: response('SQLSTATE[42000] invalid query', 500))
        self.assertNotEqual(result['state'], 'CONFIRMED')

    async def test_echoed_error_text_does_not_confirm(self):
        payload = 'SQLSTATE[42000]'
        result, _ = await self.validate(finding(payload=payload), lambda _m, url, **kw: response(payload) if '?' in url else response())
        self.assertNotEqual(result['state'], 'CONFIRMED')

    async def test_waf_is_inconclusive(self):
        result, _ = await self.validate(finding(), lambda *_a, **_kw: response('Access denied', 403))
        self.assertEqual(result['reason'], 'waf_or_access_block')

    async def test_absent_baseline_is_inconclusive(self):
        result, _ = await self.validate(finding(), lambda _m, url, **kw: response() if '?' in url else None)
        self.assertEqual(result['reason'], 'missing_baseline_or_probe')

    async def test_real_small_xss_overrides_similarity(self):
        payload = '"><img src=x onerror=alert(1)>'
        base = '<html><body>' + 'A' * 10000 + '</body></html>'
        result, _ = await self.validate(finding('XSS', payload), lambda _m, url, **kw: response(base.replace('</body>', payload + '</body>')) if '?' in url else response(base))
        self.assertGreater(result['similarity'], .98)
        self.assertEqual(result['state'], 'CONFIRMED')

    async def test_escaped_and_textarea_reflection_do_not_confirm(self):
        payload = '<img src=x onerror=alert(1)>'
        for text in (html.escape(payload), '<textarea>' + payload + '</textarea>', '<!--' + payload + '-->'):
            with self.subTest(text=text):
                result, _ = await self.validate(finding('XSS', payload), lambda _m, url, **kw: response(text) if '?' in url else response())
                self.assertNotEqual(result['state'], 'CONFIRMED')

    async def test_plaintext_reflection_does_not_confirm(self):
        payload = '<svg onload=alert(1)>'
        result, _ = await self.validate(finding('XSS', payload), lambda _m, url, **kw: response(payload, content_type='text/plain') if '?' in url else response())
        self.assertNotEqual(result['state'], 'CONFIRMED')

    def test_json_script_and_unknown_event_are_inert(self):
        for payload in ('<script type="application/json">alert(1)</script>', '<img oninvalidfake=alert(1)>'):
            self.assertEqual(unsafe_reflection(response(payload), payload), '')

    def test_unrelated_preexisting_handler_does_not_validate_comment_reflection(self):
        payload = '<img src=x onerror=alert(1)>'
        text = '<img onerror="alert(1)" src="x"><!--' + payload + '-->'
        self.assertEqual(unsafe_reflection(response(text), payload), '')

    async def test_traversal_needs_structured_file_content(self):
        for text, expected in [('localhost', False), ('root:x:', False), ('root:x:0:0:root:/root:/bin/bash\n', True)]:
            result, _ = await self.validate(finding('LFI', '../../../etc/passwd'), lambda _m, url, **kw: response(text, content_type='text/plain') if '?' in url else response())
            self.assertEqual(result['state'] == 'CONFIRMED', expected)

    async def test_boolean_echo_size_difference_is_not_sql(self):
        f = finding(payload='1 AND 1=1 / 1 AND 1=2', title='SQL Injection boolean differential')
        def callback(_m, url, **kwargs):
            return response('<html>' + html.escape(parse_qs(urlsplit(url).query).get('js', [''])[0]) + '</html>')
        result, _ = await self.validate(f, callback)
        self.assertNotEqual(result['state'], 'CONFIRMED')

    async def test_repeatable_boolean_dom_change(self):
        base = '<main>' + ''.join('<article>Product %d</article>' % i for i in range(40)) + '</main>'
        f = finding(payload='1 AND 1=1', title='SQL Injection boolean differential')
        def callback(_m, url, **kwargs):
            param = parse_qs(urlsplit(url).query).get('js', [''])[0]
            return response('<main>No products</main>' if '1=2' in param else base)
        result, _ = await self.validate(f, callback)
        self.assertEqual(result['reason'], 'repeatable_boolean_dom_change')
        self.assertIn('false_url', result['requests'])

    async def test_time_based_is_paired_and_repeated(self):
        f = finding(payload="1; SELECT SLEEP(5)", title='SQL Injection time-based')
        result, _ = await self.validate(f, lambda _m, url, **kw: response(elapsed=5.2 if 'SLEEP%285%29' in url else .1))
        self.assertEqual(result['reason'], 'repeatable_paired_delay')
        self.assertEqual(len(result['timing_deltas']), 3)

    async def test_single_slow_response_and_static_body_are_not_confirmed(self):
        count = 0
        def callback(_m, url, **kwargs):
            nonlocal count
            count += 1
            return response(elapsed=6 if count == 2 else .1)
        result, _ = await self.validate(finding(payload='SLEEP(5)', title='SQL Injection time-based'), callback)
        self.assertEqual(result['state'], 'INCONCLUSIVE')

    async def test_static_missing_path_is_not_injection(self):
        f = finding('XSS', '<svg>', param='', url='https://app.test/login/missing')
        result, _ = await self.validate(f, lambda _m, url, **kw: response('not found', 404) if not url.endswith('/') else response('login'))
        self.assertEqual(result['reason'], 'static_rewrite_catch_all')

    async def test_out_of_scope_and_post_are_not_replayed(self):
        for kwargs in ({'url': 'https://other.test/?js=1'}, {'method': 'POST'}):
            result, ctx = await self.validate(finding(**kwargs), lambda *_a, **_kw: response())
            self.assertEqual(ctx.http.request.await_count, 0)
            self.assertEqual(result['state'], 'INCONCLUSIVE')

    async def test_exact_encoded_url_is_preserved(self):
        f = finding(url='https://app.test/login/?js=%22%250a%23')
        result, ctx = await self.validate(f, lambda *_a, **_kw: response())
        self.assertEqual(ctx.http.request.await_args_list[1].args[1], f.url)

    async def test_header_alert_is_not_replayed_as_an_invented_query(self):
        result, ctx = await self.validate(finding(param='Host', url='https://app.test/login/'), lambda *_a, **_kw: response())
        self.assertEqual(result['state'], 'INCONCLUSIVE')
        self.assertEqual(result['reason'], 'non_query_input_requires_original_request')
        self.assertEqual(ctx.http.request.await_count, 0)


class TriageTests(unittest.TestCase):
    def test_engine_and_state_respect_persisted_decisions(self):
        from Main import ScanTitan, StateStore
        f = finding()
        f.validation = {'state': 'CONFIRMED', 'version': 'differential-v1'}
        f.confidence = 'high'
        scanner = object.__new__(ScanTitan)
        scanner.config = SimpleNamespace(report_min_severity='Low', include_pipeline_findings=False,
                                         include_recon_info_findings=False)
        with tempfile.TemporaryDirectory() as tmp:
            decisions_file = Path(tmp) / 'finding_triage.json'
            with patch.dict(os.environ, {'SCAN_TITAN_TRIAGE_FILE': str(decisions_file)}):
                self.assertEqual(scanner._reportable_findings([f]), [f])
                store = StateStore(Path(tmp) / 'state.json')
                store.enrich([f], f.target, '2026-11-09')
                self.assertEqual(len(store.active_records()), 1)
                decisions_file.write_text(json.dumps({'schema': 'scan_titan_triage_v1', 'decisions': {triage_key(f): {'decision': 'discarded'}}}))
                self.assertEqual(scanner._reportable_findings([f]), [])
                self.assertEqual(store.active_records(), [])
                decisions_file.write_text(json.dumps({'schema': 'scan_titan_triage_v1', 'decisions': {triage_key(f): {'decision': 'restored'}}}))
                self.assertEqual(scanner._reportable_findings([f]), [f])

    def test_daily_legacy_injection_requires_revalidation(self):
        import Dashboard
        import pandas as pd
        f = finding()
        record = {'target': f.target, 'canonical_id': f.canonical_id, 'last_url': f.url,
                  'title': f.title, 'category': f.category, 'severity': 'High', 'state': 'ACTIVE'}
        with patch.object(Dashboard, 'cargar_estado_hallazgos', return_value={'fixture': record}), \
             patch.object(Dashboard, 'cargar_runtime', return_value={}), \
             patch.object(Dashboard, 'cargar_recon_modelo', return_value={}), \
             patch.object(Dashboard, 'load_decisions', return_value={}):
            model = Dashboard.construir_modelo(pd.DataFrame(columns=Dashboard.REPORT_COLUMNS))
        self.assertEqual(model['meta']['active'], 0)
        self.assertEqual(model['rows'][0]['state'], 'PENDING')
        self.assertIn("Write-Host '[probe]'", model['rows'][0]['manual_command'])

    def test_scope_is_stable_but_does_not_hide_other_inputs(self):
        f = finding()
        key = triage_key(f)
        decisions = {key: {'decision': 'discarded'}}
        self.assertTrue(is_discarded(f, decisions))
        self.assertEqual(key, triage_key(finding(payload='other')))
        for kw in ({'method': 'POST'}, {'param': 'name'}, {'url': 'https://other.test/login/?js=1'}, {'url': 'https://app.test/other/?js=1'}):
            self.assertFalse(is_discarded(finding(**kw), decisions))
        decisions[key]['decision'] = 'restored'
        self.assertFalse(is_discarded(f, decisions))

    def test_legacy_state_key_matches_new_finding(self):
        f = finding()
        state = dict(title=f.title, last_url=f.url, canonical_id=f.canonical_id)
        self.assertEqual(triage_key(f), triage_key(state))

    def test_live_handler_persists_and_rejects_cross_origin_writes(self):
        import io
        class OfflineServer:
            def __init__(self, address, handler):
                self.server_port = 43210
                self.handler = handler
        with tempfile.TemporaryDirectory() as tmp:
            report = Path(tmp) / 'Daily_vulns_report.html'
            report.write_text('<html><head></head><body>Daily</body></html>')
            decisions_file = Path(tmp) / 'finding_triage.json'
            with patch('http.server.HTTPServer', OfflineServer):
                server = create_server(report, decisions_file)
            handler = object.__new__(server.handler)
            handler.server = server
            handler.headers = {'Host': '127.0.0.1:43210'}
            handler.path = '/'
            results = []
            handler.respond = lambda status, body, ctype=None: results.append((status, body))
            handler.do_GET()
            token = results[-1][1].split('window.SCAN_TITAN_TRIAGE_TOKEN=')[1].split(';')[0].strip('"')
            f = finding()
            body = json.dumps({'schema': 'scan_titan_triage_v1', 'decisions': {triage_key(f): {'decision': 'discarded', 'updated_at': '2026-11-09', 'reason': 'fixture'}}}).encode()
            headers = {'Host': '127.0.0.1:43210', 'Origin': 'http://127.0.0.1:43210', 'X-ScanTitan-Token': token, 'Content-Length': str(len(body))}
            handler.headers = headers
            handler.path = '/api/triage'
            handler.rfile = io.BytesIO(body)
            handler.do_POST()
            self.assertEqual(results[-1][0], 200)
            self.assertTrue(is_discarded(f, load_decisions(decisions_file)))
            for origin in ('https://evil.test', ''):
                handler.headers = {**headers, 'Origin': origin}
                handler.rfile = io.BytesIO(body)
                handler.do_POST()
                self.assertEqual(results[-1][0], 403)
            handler.headers = {**headers, 'Host': 'evil.test:43210'}
            handler.do_GET()
            self.assertEqual(results[-1][0], 403)


class JavascriptReconTests(MockCoroutineCase):
    def test_extracts_routes_and_redacts_candidate_secret(self):
        code = "fetch('/api/users?id=1'); axios.post('/auth/token'); document.querySelector('#x').innerHTML=location.search; const k='ghp_" + 'A' * 36 + "'; //# sourceMappingURL=app.js.map"
        result = analyze_javascript('https://app.test/app.js', code, 'https://app.test/')
        self.assertEqual(result['endpoints'][0]['params'], ['id'])
        self.assertEqual(len(result['dom_flows']), 1)
        self.assertNotIn('A' * 36, json.dumps(result))
        self.assertEqual(result['source_maps'], ['app.js.map'])

    def test_source_sink_cooccurrence_does_not_prove_flow(self):
        result = analyze_javascript('https://app.test/app.js', "const a=location.search; unrelated.innerHTML='Hello';", 'https://app.test/')
        self.assertEqual(result['dom_flows'], [])

    async def test_third_party_not_fetched_and_map_validated(self):
        def callback(_m, url, **kw):
            if url.endswith('.map'):
                return response(json.dumps({'version': 3, 'sources': ['src/main.js'], 'sourcesContent': ["fetch('/api/hidden')"]}), content_type='application/json')
            return response("fetch('/api/public'); //# sourceMappingURL=app.js.map", content_type='application/javascript')
        ctx = context(callback)
        result = await javascript_recon(ctx, response('<script src="https://external.test/vendor.js"></script><script src="/app.js"></script>'))
        self.assertEqual(ctx.http.request.await_count, 2)
        self.assertEqual(result['source_maps'][0]['state'], 'valid_source_map')
        self.assertTrue(any(x['url'].endswith('/api/hidden') for x in result['endpoints']))
        self.assertTrue(any(x['state'] == 'external_not_fetched' for x in result['coverage']))


if __name__ == '__main__':
    unittest.main()
