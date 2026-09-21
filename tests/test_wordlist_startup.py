from __future__ import annotations

import os
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch


ROOT = Path(__file__).resolve().parents[1]
ENGINE = ROOT / "src" / "scan_titan"
os.environ.setdefault("SCAN_TITAN_BASE_DIR", str(ROOT))
sys.path.insert(0, str(ENGINE))

from Main import Console, WordlistLoader, build_argparser  # noqa: E402
from modules.payload_utils import xss_payloads  # noqa: E402


class WordlistStartupTests(unittest.TestCase):
    def test_count_is_real_and_cap_applies_after_deduplication(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "xss.txt").write_text(
                "# comentario\n<script>alert(1)</script>\n<script>alert(1)</script>\n"
                "<img src=x onerror=alert(1)>\n<svg onload=alert(1)>\n",
                encoding="utf-8",
            )
            (root / "xss_payloads.txt").write_text("legacy-duplicate\n", encoding="utf-8")
            loader = WordlistLoader(root, max_entries=2)
            with patch.object(Console, "step") as log:
                data = loader.load()
            self.assertEqual(data["xss"], ["<script>alert(1)</script>", "<img src=x onerror=alert(1)>"])
            self.assertNotIn("xss_payloads", data)
            log.assert_not_called()

            with patch.object(Console, "step") as log:
                loader.load(verbose=True)
            self.assertTrue(any("xss" in call.args[0] and "2 entradas reales" in call.args[0] for call in log.call_args_list))

    def test_short_wordlist_is_not_filled_with_generated_entries(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "users.txt").write_text("admin\noperator\nADMIN\n", encoding="utf-8")
            data = WordlistLoader(root, max_entries=50_000).load()
            self.assertEqual(data["users"], ["admin", "operator"])

    def test_xss_probes_use_single_canonical_wordlist(self) -> None:
        probes = xss_payloads(
            {"xss": ["noise", "<svg onload=alert(1)>"]},
            ["<script>alert(1)</script>"],
            limit=2,
        )
        self.assertIn("<svg onload=alert(1)>", probes)

    def test_verbose_startup_is_opt_in(self) -> None:
        parser = build_argparser()
        self.assertFalse(parser.parse_args([]).verbose_startup)
        self.assertTrue(parser.parse_args(["--verbose-startup"]).verbose_startup)


if __name__ == "__main__":
    unittest.main()
