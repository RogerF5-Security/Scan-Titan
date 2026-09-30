"""Regression gates for incomplete external scans and durable evidence."""
from __future__ import annotations

import asyncio
import json
import sys
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import AsyncMock, patch

from test_external_tool_hotfixes import external_tools, target
from Main import ExternalTools, RuntimeConfig, RuntimeControl, StateStore
from modules.common import Finding


class ExternalUpgradeTests(unittest.IsolatedAsyncioTestCase):
    def context(self):
        return SimpleNamespace(target=target(), recon={}, heartbeat=lambda *args: None)

    async def test_zap_paginates_and_writes_checkpoint_before_completion(self):
        with tempfile.TemporaryDirectory() as tmp:
            tool = external_tools(zap_max_alerts=250)
            ctx = self.context()
            ctx.recon['_zap_export_path'] = str(Path(tmp) / 'zap.json')
            pages = [{'alerts': [{'id': str(i)} for i in range(100)]},
                     {'alerts': [{'id': str(i)} for i in range(100, 103)]}]
            tool._zap_api = AsyncMock(side_effect=pages)
            result = await tool._zap_checkpoint(ctx, 'running')
            saved = json.loads(Path(ctx.recon['_zap_export_path']).read_text())
            self.assertEqual(len(result), 103)
            self.assertEqual(len(saved['alerts']), 103)
            self.assertEqual(saved['state'], 'running')
            self.assertEqual(tool._zap_api.call_args_list[1].args[1]['start'], '100')
            self.assertFalse(ctx.recon['zap_alerts_capped'])

    async def test_zap_stalled_scan_stops_only_owned_id_and_keeps_alerts(self):
        tool = external_tools(zap_progress_timeout=0, runtime_control=RuntimeControl())
        tool._zap_api = AsyncMock(return_value={'status': '12'})
        tool._zap_checkpoint = AsyncMock(return_value=[{'alert': 'retained'}])
        ctx = self.context()
        progress, reason = await tool._zap_poll_scan(ctx, 'ascan', '47', 2)
        self.assertEqual((progress, reason), (12, 'stalled'))
        tool._zap_api.assert_any_await('ascan/action/stop', {'scanId': '47'}, timeout=5)
        self.assertEqual(ctx.recon['zap_stages']['ascan']['state'], 'stalled')

    async def test_zap_rejects_missing_scan_id(self):
        tool = external_tools(zap_active_timeout=2)
        tool._zap_api = AsyncMock(return_value={})
        with self.assertRaisesRegex(RuntimeError, 'valid scan ID'):
            await tool._zap_active_scan(self.context(), 'https://example.invalid')

    async def test_zap_failed_stage_recovers_alerts(self):
        with tempfile.TemporaryDirectory() as tmp:
            tool = external_tools(zap_mode='active', zap_api_url='http://127.0.0.1:1',
                                  policy=SimpleNamespace(allow_state_changing_api_tests=True),
                                  zap_shutdown_after_scan=True, zap_start_daemon=False, zap_startup_timeout=1, telemetry=None,
                                  runtime_control=RuntimeControl(), external_reports_dir=Path(tmp))
            tool._zap_wait_ready = AsyncMock(return_value=True)
            async def api(path, *args, **kwargs):
                if path == 'core/view/version':
                    return {'version': 'fixture'}
                if path == 'context/action/newContext':
                    return {'contextId': '1'}
                return {}
            tool._zap_api = AsyncMock(side_effect=api)
            tool._zap_rule_inventory = AsyncMock()
            tool._zap_seed_urls = lambda ctx: [ctx.target.url]
            tool._zap_access_urls = AsyncMock(return_value=1)
            tool._zap_spider = AsyncMock(side_effect=RuntimeError('fixture failure'))
            tool._zap_checkpoint = AsyncMock(return_value=[{
                'alert': 'fixture alert', 'risk': 'High', 'url': target().url, 'pluginId': '99999'}])
            tool._log_external = lambda *args, **kwargs: None
            ctx = self.context()
            findings = await tool.run_zap(ctx)
            self.assertEqual(len(findings), 1)
            self.assertEqual(ctx.recon['external_coverage'][0]['state'], 'failed_partial')

    async def test_stream_retains_head_tail_and_complete_raw_file(self):
        with tempfile.TemporaryDirectory() as tmp:
            tool = external_tools()
            tool.MAX_EXTERNAL_OUTPUT_BYTES = 100
            stream = asyncio.StreamReader()
            payload = b'HEAD' + b'x' * 300 + b'FINAL_ERROR'
            stream.feed_data(payload)
            stream.feed_eof()
            raw = Path(tmp) / 'stderr.log'
            result = await tool._read_stream_limited(stream, raw_path=raw)
            self.assertIn(b'HEAD', result)
            self.assertIn(b'FINAL_ERROR', result)
            self.assertEqual(raw.read_bytes(), payload)

    async def test_real_child_timeout_keeps_partial_stdout_and_error_tail(self):
        with tempfile.TemporaryDirectory() as tmp:
            tool = external_tools(external_reports_dir=Path(tmp), runtime_control=RuntimeControl(), telemetry=None)
            code = "import time,sys; print('partial result',flush=True); print('diagnostic tail',file=sys.stderr,flush=True); time.sleep(20)"
            out, err, timed_out, rc, duration = await tool._run_command([sys.executable, '-c', code], 1)
            self.assertTrue(timed_out)
            self.assertIn('partial result', out)
            self.assertIn('diagnostic tail', err)
            self.assertLess(duration, 8)
            self.assertEqual(len(list(Path(tmp).glob('*.log'))), 2)

    def test_nuclei_statistics_and_failed_matchers_are_not_findings(self):
        with tempfile.TemporaryDirectory() as tmp:
            tool = external_tools()
            output = Path(tmp) / 'out.jsonl'
            record = {'template-id': 'fixture', 'info': {'name': 'Fixture', 'severity': 'low'},
                      'matched-at': target().url}
            output.write_text('\n'.join(map(json.dumps, [
                {'requests': 15, 'matched': 0}, {**record, 'matcher-status': False}, record])) + '\n{"partial":', encoding='utf-8')
            findings, error = tool._parse_nuclei_with_status(self.context(), output, '')
            self.assertEqual(len(findings), 1)
            self.assertTrue(error)
            self.assertIn('timeout', tool._nuclei_empty_reason(-1, True, '', '', output, 1, error))

    def test_zero_timeout_uses_finite_default_and_zero_override_is_ignored(self):
        cfg = object.__new__(RuntimeConfig)
        self.assertEqual(cfg._timeout_value(0, 900), 900)
        self.assertEqual(cfg._int_map({'lfi': 0, 'xss': 45}), {'xss': 45})

    async def test_zap_inventory_detects_missing_or_disabled_core_rules(self):
        tool = external_tools()
        tool._zap_api = AsyncMock(return_value={'scanners': [
            {'id': '10010', 'enabled': 'true'}, {'id': '10020', 'enabled': 'false'}]})
        ctx = self.context()
        await tool._zap_rule_inventory(ctx)
        self.assertEqual(ctx.recon['zap_rule_inventory']['missing_baseline_rules'], ['10020', '10021'])

    def test_incomplete_scan_does_not_mark_prior_finding_not_seen(self):
        with tempfile.TemporaryDirectory() as tmp:
            store = StateStore(Path(tmp) / 'state.json')
            finding = Finding(target='fixture', category='XSS', severity='High', title='Stored XSS')
            store.enrich([finding], 'fixture', '2026-01-01')
            store.enrich([], 'fixture', '2026-01-02', complete=False)
            self.assertEqual(next(iter(store.data['findings'].values()))['state'], 'ACTIVE')
            store.enrich([], 'fixture', '2026-01-03', complete=True)
            self.assertEqual(next(iter(store.data['findings'].values()))['state'], 'NOT_SEEN')


if __name__ == '__main__':
    unittest.main()
