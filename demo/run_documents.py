#!/usr/bin/env python3
"""IncogRx document mode, from the terminal (optional, not part of the graded run).

Same flow as the demo website: every file is security-scanned first, PDFs and images are read
page by page (OCR for scanned or handwritten pages), every page goes through the same main.py
engine as its own record, and redacted copies of the documents are written.

Usage: RAKSHA_SECRET=<secret> python demo/run_documents.py --input <dir> --output <new dir>
Prints counts, verdicts and timings only; never file content, never the secret."""
from __future__ import annotations

import argparse
import os
import shutil
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

import app  # noqa: E402
import pdf_support  # noqa: E402


def main() -> int:
    ap = argparse.ArgumentParser(description="IncogRx document mode")
    ap.add_argument("--input", required=True)
    ap.add_argument("--output", required=True)
    a = ap.parse_args()
    src, dst = Path(a.input), Path(a.output)
    if dst.exists() and any(dst.iterdir()):
        print("incogrx-docs: output folder must be new or empty", file=sys.stderr)
        return 2
    files, links = [], []
    for p in sorted(src.rglob("*")):
        if not p.is_file():
            continue
        rel = p.relative_to(src).as_posix()
        if p.is_symlink() or any((src / d).is_symlink() for d in p.relative_to(src).parents if str(d) != "."):
            links.append(app.security._result(rel, "blocked", "symbolic link: never followed outside the input"))
            continue
        files.append((rel, p.read_bytes()))
    t0 = time.time()
    res = app.run_job(files, os.environ.get("RAKSHA_SECRET", ""), scans=links)
    work = app.JOBS.pop(res["job"])
    shutil.copytree(work / "output", dst, dirs_exist_ok=True)
    shutil.rmtree(work, ignore_errors=True)
    total = time.time() - t0

    sec = res["security"]
    print(f"IncogRx document mode | OCR {'on (' + pdf_support.ocr_langs() + ')' if pdf_support.OCR_AVAILABLE else 'off'}")
    print(f"security scan: {sec['scanned']} files | blocked {len(sec['blocked'])} | "
          f"neutralized {len(sec['neutralized'])} | clean {sec['clean']}")
    for x in sec["blocked"]:
        print(f"  BLOCKED      {x['name']}: {x['reason']}")
    for x in sec["neutralized"]:
        print(f"  NEUTRALIZED  {x['name']}: {x['reason']}")
    for d in res["documents"]:
        kind = f"{d['typed_pages']} typed" + (f", {d['ocr_pages']} OCR (mean conf {d['ocr_conf']})" if d["ocr_pages"] else "")
        review = f" | review pages {d['review_pages']}" if d["review_pages"] else ""
        print(f"  DOCUMENT     {d['name']}: {d['pages']} pages ({kind}) | {d['boxes']} redaction boxes | "
              f"read {d['read_seconds']}s, redact {d['redact_seconds']}s{review}")
        for c in d.get("clinical_checks", []):
            print(f"    CHECK page {c['page']}: {c['issue']} (released text not changed)")
    eng = [f for f in res["files"] if f["status"] != "sanitized"]
    for f in eng:
        name = f.get("input", "?")
        print(f"  QUARANTINED  {name}: {f.get('reason')}")
    v, s = res["view"], res["speed"]
    print(f"files {v['files_total']} sanitized {v['files_sanitized']} quarantined {v['files_quarantined']} "
          f"blocked {v['files_blocked']} records {v['records_processed']} pages {s['pages']}")
    print(f"time {total:.2f}s (read {s['read_seconds']}s, engine {s['engine_seconds']}s, redact {s['redact_seconds']}s)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
