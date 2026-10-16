"""Regressions for chart correctness; no scanner or desktop session required."""
from __future__ import annotations

import copy
import sys
import unittest
from datetime import datetime, timedelta
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src" / "scan_titan"))
from monitor_model import TelemetryHistory, monitor_base_dir, number


class MonitorLocationTests(unittest.TestCase):
    def test_structured_copy_uses_project_root(self):
        root = (Path.cwd() / "sample_scan").resolve()
        self.assertEqual(monitor_base_dir(root / "src/scan_titan/ScanTitan_Monitor.py"), root)

    def test_standalone_legacy_copy_uses_its_own_folder(self):
        root = (Path.cwd() / "legacy_scan").resolve()
        self.assertEqual(monitor_base_dir(root / "ScanTitan_Monitor.py"), root)


class TelemetryHistoryTests(unittest.TestCase):
    def setUp(self) -> None:
        self.history = TelemetryHistory(limit=5)
        self.start = datetime(2026, 10, 16, 12, 0, 0)

    def sample(self, seconds: int = 0, completed: int = 100, **changes):
        stamp = (self.start + timedelta(seconds=seconds)).isoformat()
        data = {
            "pid": 10, "started_at": self.start.isoformat(), "updated_at": stamp,
            "status": "running", "current_target": "example.test", "current_module": "headers",
            "global_percent": 45, "http_activity": {"completed": completed},
            "resources": {"available": True, "sampled_at": stamp, "cpu_percent": 240, "ram_mb": 128},
        }
        data.update(changes)
        return data

    def test_rate_uses_producer_elapsed_time_and_ignores_duplicate_refreshes(self):
        first = self.sample()
        self.history.ingest(first, "a")
        self.assertIsNone(self.history.rate)
        self.history.ingest(first, "a")
        self.assertEqual(len(self.history.series["cpu"]), 1)
        self.history.ingest(self.sample(10, 150), "a")
        self.assertEqual(self.history.rate, 5)
        self.history.ingest(self.sample(10, 150), "a")
        self.assertEqual(self.history.rate, 5)
        self.assertEqual(len(self.history.series["requests"]), 2)

    def test_http_context_changes_and_counter_resets_start_new_baseline(self):
        self.history.ingest(self.sample(), "a")
        self.history.ingest(self.sample(10, 150, current_module="xss"), "a")
        self.assertIsNone(self.history.rate)
        self.history.ingest(self.sample(20, 10, current_module="xss"), "a")
        self.assertIsNone(self.history.rate)
        self.history.ingest(self.sample(30, 30, current_module="xss"), "a")
        self.assertEqual(self.history.rate, 2)
        self.history.ingest(self.sample(40, 80, current_target="other.test", current_module="xss"), "a")
        self.assertIsNone(self.history.rate)

    def test_different_scan_folder_or_run_clears_old_series(self):
        for changes, source in (({}, "b"), ({"pid": 99}, "a"), ({"started_at": "2026-10-16T11:00:00"}, "a")):
            with self.subTest(changes=changes, source=source):
                self.history.clear()
                self.history.ingest(self.sample(), "a")
                self.history.ingest(self.sample(10, 150, **changes), source)
                self.assertEqual(len(self.history.series["cpu"]), 1)
                self.assertIsNone(self.history.rate)

    def test_stale_data_does_not_fabricate_activity_or_samples(self):
        self.history.ingest(self.sample(), "a")
        self.history.ingest(self.sample(10, 150), "a")
        self.history.ingest(self.sample(20, 200), "a", stale=True)
        self.assertIsNone(self.history.rate)
        self.assertEqual(len(self.history.series["cpu"]), 2)
        self.history.ingest(self.sample(30, 250), "a")
        self.assertIsNone(self.history.rate)

    def test_gap_and_out_of_order_samples_do_not_create_rate_spikes(self):
        self.history.ingest(self.sample(), "a")
        self.history.ingest(self.sample(90, 300), "a")
        self.assertIsNone(self.history.rate)
        self.history.ingest(self.sample(80, 400), "a")
        self.assertIsNone(self.history.rate)
        self.assertEqual(len(self.history.series["cpu"]), 2)

    def test_missing_http_is_a_gap_and_not_zero_requests(self):
        self.history.ingest(self.sample(), "a")
        self.history.ingest(self.sample(10, http_activity={}), "a")
        self.assertIsNone(self.history.rate)
        self.assertIsNone(self.history.series["requests"][-1][1])
        self.history.ingest(self.sample(20, 150), "a")
        self.assertIsNone(self.history.rate)

    def test_resource_sample_timestamps_are_deduplicated_independently(self):
        first = self.sample()
        self.history.ingest(first, "a")
        self.history.ingest(self.sample(10, resources=first["resources"]), "a")
        self.assertEqual(len(self.history.series["cpu"]), 1)
        self.assertEqual(self.history.series["cpu"][0][1], 240)

    def test_unavailable_resources_make_a_gap(self):
        self.history.ingest(self.sample(), "a")
        self.history.ingest(self.sample(10, resources={"available": False}), "a")
        self.assertIsNone(self.history.series["cpu"][-1][1])

    def test_finished_status_freezes_http_rate(self):
        self.history.ingest(self.sample(), "a")
        self.history.ingest(self.sample(10, 200, status="finished"), "a")
        self.assertIsNone(self.history.rate)

    def test_history_is_bounded_and_never_mutates_runtime(self):
        sample = self.sample()
        before = copy.deepcopy(sample)
        self.history.ingest(sample, "a")
        self.assertEqual(sample, before)
        for index in range(1, 30):
            self.history.ingest(self.sample(index * 5, 100 + index), "a")
        self.assertTrue(all(len(points) == 5 for points in self.history.series.values()))
        self.history.clear()
        self.assertTrue(all(not points for points in self.history.series.values()))

    def test_invalid_numbers_are_safe_for_canvas_coordinates(self):
        for value in (None, "bad", float("inf"), float("nan"), -4):
            self.assertEqual(number(value), 0)
        self.assertEqual(number("240.5"), 240.5)


if __name__ == "__main__":
    unittest.main()
