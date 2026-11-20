"""Development entrypoint for the existing Scan Titan workspace."""
from __future__ import annotations

import argparse
import importlib.util
import os
import sys
from pathlib import Path


def workspace_root(explicit: str | None = None) -> Path:
    candidates = [explicit or os.environ.get("SCAN_TITAN_BASE_DIR")]
    if not candidates[0]:
        candidates.extend([str(Path.cwd()), str(Path(__file__).resolve().parents[2])])
    for candidate in candidates:
        if not candidate:
            continue
        root = Path(candidate).expanduser().resolve()
        if (root / "main.py").is_file() and (root / "src/scan_titan/Main.py").is_file():
            return root
    raise ValueError("Scan Titan workspace not found. Use --workspace PATH or SCAN_TITAN_BASE_DIR.")


def main(argv: list[str] | None = None) -> int:
    args = list(sys.argv[1:] if argv is None else argv)
    parser = argparse.ArgumentParser(add_help=False, allow_abbrev=False)
    parser.add_argument("--workspace")
    options, rest = parser.parse_known_args(args)
    try:
        root = workspace_root(options.workspace)
    except ValueError as exc:
        if rest in (["--help"], ["-h"]):
            print("Scan Titan development launcher\nUsage: scan-titan --workspace PATH [engine options]\n"
                  "A source workspace supplies configuration, wordlists, and optional exporters.")
            return 0
        if rest == ["--version"]:
            from importlib.metadata import version
            print(version("scan-titan"))
            return 0
        print(str(exc), file=sys.stderr)
        return 2
    os.environ["SCAN_TITAN_BASE_DIR"] = str(root)
    # Root exporters and the existing launcher remain compatible during ST-next-01.
    if str(root) not in sys.path:
        sys.path.insert(0, str(root))
    spec = importlib.util.spec_from_file_location("_scan_titan_workspace_launcher", root / "main.py")
    if spec is None or spec.loader is None:
        raise RuntimeError("Cannot load Scan Titan workspace launcher")
    launcher = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(launcher)
    return int(launcher.main(rest))


if __name__ == "__main__":
    raise SystemExit(main())
