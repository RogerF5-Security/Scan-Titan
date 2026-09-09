"""Keep every public Scan Titan version marker aligned."""

from pathlib import Path
import re
import unittest


ROOT = Path(__file__).resolve().parents[1]


class VersionConsistencyTests(unittest.TestCase):
    def test_public_version_markers_match_version_file(self):
        version = (ROOT / "VERSION").read_text(encoding="utf-8").strip()
        self.assertRegex(version, r"^\d+\.\d+\.\d+$")

        expected = {
            "README.md": (rf"Version del motor:\*\* {re.escape(version)}\.",),
            "src/scan_titan/__init__.py": (rf'__version__ = "{re.escape(version)}-community"',),
            "src/scan_titan/Main.py": (
                rf'SCAN_VERSION = "TITAN v{re.escape(version)} COMMUNITY ZERO-TOUCH"',
                rf'SCAN TITAN COMMUNITY \| TATAKAE \| .* v{re.escape(version)} ',
            ),
            "src/scan_titan/Dashboard.py": (
                rf'DASHBOARD_VERSION = "{re.escape(version)}-community"',
                rf'SCANNER_FALLBACK = "TITAN v{re.escape(version)} COMMUNITY ZERO-TOUCH"',
            ),
        }
        for relative, patterns in expected.items():
            with self.subTest(path=relative):
                content = (ROOT / relative).read_text(encoding="utf-8")
                for pattern in patterns:
                    self.assertRegex(content, pattern)


if __name__ == "__main__":
    unittest.main()
