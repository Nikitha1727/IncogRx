#!/usr/bin/env python3
"""IncogRx: offline, CPU-only, LLM-free privacy firewall for Indian hospital records.

Usage: RAKSHA_SECRET=<secret> python main.py --input <input dir> --output <empty output dir>
Only counts are printed: stdout and stderr never carry personal data or the secret."""
from __future__ import annotations

import argparse
import sys
from pathlib import Path

from incog.pipeline import run


def main() -> int:
    ap = argparse.ArgumentParser(description="IncogRx privacy firewall")
    ap.add_argument("--input", required=True)
    ap.add_argument("--output", required=True)
    a = ap.parse_args()
    try:
        rep = run(Path(a.input), Path(a.output))
    except Exception as exc:  # noqa: BLE001  a traceback could print file names, which may hold PII
        print(f"incogrx: failed ({type(exc).__name__})", file=sys.stderr)
        return 1
    c = rep["counts"]
    print(f"files {c['files_total']} sanitized {c['files_sanitized']} quarantined {c['files_quarantined']} "
          f"records {c['records_processed']}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
