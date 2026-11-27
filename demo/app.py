#!/usr/bin/env python3
"""IncogRx demo UI: a local, offline web page to try the firewall on your own files or text.

    python demo/app.py            then open http://127.0.0.1:8765
    (on Render / Railway the platform's PORT is used and the page is served publicly; see Dockerfile)

Standard library only. Every run calls the same `main.py` the evaluator runs (in a separate
process), so the demo shows exactly what the scored pipeline does. The server listens on
127.0.0.1 only; uploads and results live in a temporary folder that is deleted on exit."""
from __future__ import annotations

import atexit
import base64
import csv
import hashlib
import io
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
import threading
import time
import uuid
import webbrowser
import zipfile
from collections import Counter, defaultdict
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path, PurePosixPath

DEMO = Path(__file__).resolve().parent
ROOT = DEMO.parent
MAIN = ROOT / "main.py"
CLOUD = "PORT" in os.environ          # set by hosting platforms (Render, Railway): serve publicly there
HOST = os.environ.get("INCOGRX_DEMO_HOST", "0.0.0.0" if CLOUD else "127.0.0.1")
PORT = int(os.environ.get("PORT") or os.environ.get("INCOGRX_DEMO_PORT", "8765"))
MAX_UPLOAD = 80 * 1024 * 1024          # bytes of decoded upload per run
PREVIEW = 30000                         # characters shown per file
KEEP_JOBS = 5

sys.path.insert(0, str(ROOT))
from incog.readers import decode  # noqa: E402  (same decoder as the pipeline, for the "before" view)
sys.path.insert(0, str(DEMO))
import pdf_support  # noqa: E402  (demo-only: PDFs, scans and images -> redacted PDF)
import security  # noqa: E402  (demo-only: intake security scan before anything is processed)

TAG_RX = re.compile(r"\[(NAME|RELATIVE|PHONE|AADHAAR|ABHA|PAN|EMAIL|MRN|ID|INSURANCE_ID|DOB|PIN|ADDRESS|HOUSE|"
                    r"LOCALITY|LANDMARK|VILLAGE|TEHSIL)\]")
PSN_RX = re.compile(r"PSN-[0-9A-Z]{6}")
JOBS: dict = {}
LOCK = threading.Lock()


def _cleanup_all() -> None:
    for work in list(JOBS.values()):
        shutil.rmtree(work, ignore_errors=True)


atexit.register(_cleanup_all)


def safe_rel(path: str) -> Path:
    """Keep an uploaded relative path inside the job folder (no '..', no absolute paths)."""
    parts = [p for p in PurePosixPath(path.replace("\\", "/")).parts if p not in ("", ".", "..", "/")]
    if not parts:
        raise ValueError("empty path")
    return Path(*parts)


def expand_zip(path: str, data: bytes, blocked: list):
    """Demo convenience: a dropped .zip is unpacked in memory so its files are processed (the
    evaluator never sends archives). Encrypted members, zip-slip paths, bombs and nested archives
    are refused and listed in `blocked`; nothing from an archive is written before it is scanned."""
    if not path.lower().endswith(".zip") or not zipfile.is_zipfile(io.BytesIO(data)):
        yield path, data
        return
    stem = path.rsplit("/", 1)[-1][:-4] or "archive"
    total = 0
    with zipfile.ZipFile(io.BytesIO(data)) as z:
        for info in z.infolist():
            name = info.filename
            parts = PurePosixPath(name.replace("\\", "/")).parts
            if info.is_dir() or not parts or parts[0] == "__MACOSX" or parts[-1].startswith("."):
                continue
            why = security.scan_zip_entry(info)
            if why:
                blocked.append(security._result(f"{stem}/{parts[-1]}", "blocked", why))
                continue
            total += info.file_size
            if total > MAX_UPLOAD:                  # zip-bomb guard
                raise ValueError("The zip expands to more than 80 MB.")
            yield f"{stem}/{name}", z.read(info)


DOC_EXT = (".pdf",) + tuple("." + e for e in pdf_support.IMAGE_TYPES)
PAGES = ".pages"                       # folder of per-page records for one document
PAGE_RX = re.compile(r"^(.*)\.pages/p(\d{4})\.txt$")


def shown_name(path: str) -> str:
    """How a released record is named on the page: a document page shows as 'file.pdf, page 3'."""
    m = PAGE_RX.match(path)
    return f"{m.group(1)}, page {int(m.group(2))}" if m else path


def run_job(files: list, secret: str, scans: list | None = None) -> dict:
    """Scan every file, read PDFs and images page by page (OCR where needed), run the engine
    (the same main.py the evaluator runs) with every page as its own record, then write redacted
    copies of the documents."""
    t_start = time.time()
    work = Path(tempfile.mkdtemp(prefix="incogrx_demo_"))
    inp, out = work / "input", work / "output"
    inp.mkdir()
    scans = list(scans or [])
    docs, notes = {}, {}
    for rel, data in files:
        rel = safe_rel(rel).as_posix()
        verdict = security.scan(rel, data)
        scans.append(verdict)
        if verdict["verdict"] == "blocked":     # never written to disk, never processed
            continue
        if rel.lower().endswith(DOC_EXT) or data[:5] == b"%PDF-":
            prep = pdf_support.prepare(rel, data)
            if prep is not None:                # every page is its own record for the engine
                folder = rel + PAGES
                for n, page in enumerate(prep["pages"]):
                    if page.get("text", "").strip():
                        dst = inp / folder / f"p{n + 1:04d}.txt"
                        dst.parent.mkdir(parents=True, exist_ok=True)
                        dst.write_text(page["text"], encoding="utf-8")
                docs[rel] = (folder, prep)
                continue
            elif not pdf_support.AVAILABLE:
                notes[rel] = "Document support needs PyMuPDF: run  pip install pymupdf  and restart the demo."
            elif not pdf_support.OCR_AVAILABLE:
                notes[rel] = "Scanned or handwritten pages need OCR: install Tesseract (see README), so it stays quarantined."
            else:
                notes[rel] = "No readable text on any page, so it stays quarantined."
        dst = inp / rel
        dst.parent.mkdir(parents=True, exist_ok=True)
        dst.write_bytes(data)
    if not any(inp.rglob("*")):
        shutil.rmtree(work, ignore_errors=True)
        raise ValueError("Every file was blocked by the security scan: " +
                         "; ".join(f"{x['name']}: {x['reason']}" for x in scans if x["verdict"] == "blocked")[:600])
    read_s = round(time.time() - t_start, 2)
    env = dict(os.environ, RAKSHA_SECRET=secret or "demo-secret")
    t0 = time.time()
    proc = subprocess.run([sys.executable, str(MAIN), "--input", str(inp), "--output", str(out)],
                          env=env, capture_output=True, text=True, timeout=900)
    wall = time.time() - t0
    if proc.returncode != 0 or not (out / "report.json").exists():
        shutil.rmtree(work, ignore_errors=True)
        raise RuntimeError("The pipeline could not process this input.")
    t1 = time.time()
    pdf_out, doc_stats = {}, []
    if docs:
        report = json.loads((out / "report.json").read_text(encoding="utf-8"))
        by_sha = {f["input_sha256"]: f for f in report["files"]}
        for src_rel, (folder, prep) in docs.items():
            outs, out_dir = [], None
            for n, page in enumerate(prep["pages"]):
                pin = inp / folder / f"p{n + 1:04d}.txt"
                o = out / "sanitized" / folder / f"p{n + 1:04d}.txt"      # the engine mirrors input paths
                if pin.exists() and not o.is_file():                       # renamed (a name in the path)
                    f = by_sha.get(hashlib.sha256(pin.read_bytes()).hexdigest())
                    o = out / f["output"] if f and f.get("output") else None
                elif not pin.exists():
                    o = None
                outs.append(o)
                if o is not None and out_dir is None:
                    out_dir = o.parent
            if out_dir is None:
                continue
            released = ("\n\n" + pdf_support.PAGE_MARK + "\n\n").join(
                o.read_text(encoding="utf-8") if o else "" for o in outs)
            name = out_dir.name[:-len(PAGES)] if out_dir.name.endswith(PAGES) else out_dir.name
            out_pdf = out_dir.parent / (name if name.lower().endswith(".pdf") else name + ".pdf")
            try:
                t_doc = time.time()
                pdf_bytes, text, pages = pdf_support.redact(prep, released)
                out_pdf.write_bytes(pdf_bytes)
                for o, page_text in zip(outs, text.split(pdf_support.PAGE_MARK)):
                    if o is not None:                     # unsure OCR words are hidden in the text too
                        o.write_text(page_text.strip("\n"), encoding="utf-8")
                rel_pdf = out_pdf.relative_to(out).as_posix()
                pdf_out[out_dir.relative_to(out / "sanitized").as_posix()] = (src_rel, rel_pdf)
                ocr = [p for p in pages if p["kind"] == "ocr"]
                doc_stats.append({
                    "name": src_rel, "output": rel_pdf, "pages": len(pages),
                    "typed_pages": sum(p["kind"] == "text" for p in pages), "ocr_pages": len(ocr),
                    "ocr_conf": round(sum(p["conf"] for p in ocr) / len(ocr), 1) if ocr else None,
                    "review_pages": [p["page"] for p in ocr if p.get("review")],
                    "clinical_checks": [{"page": p["page"], "issue": c} for p in ocr for c in p.get("clinical_checks", [])],
                    "unsure_hidden": sum(p.get("unsure_hidden", 0) for p in ocr),
                    "boxes": sum(p["boxes"] for p in pages), "langs": prep["langs"],
                    "read_seconds": prep["read_seconds"], "redact_seconds": round(time.time() - t_doc, 2)})
            except Exception:  # noqa: BLE001  keep the text release even if redaction fails
                notes[src_rel] = "The text was cleaned, but the redacted copy could not be produced."
    redact_s = round(time.time() - t1, 2)
    job = uuid.uuid4().hex[:12]
    with LOCK:
        JOBS[job] = work
        while len(JOBS) > KEEP_JOBS:
            old = next(iter(JOBS))
            shutil.rmtree(JOBS.pop(old), ignore_errors=True)
    res = summarize(job, inp, out, wall, pdf_out, notes)
    total_s = round(time.time() - t_start, 2)
    pages = sum(d["pages"] for d in doc_stats)
    res["documents"] = doc_stats
    res["security"] = {"scanned": len(scans), "blocked": [x for x in scans if x["verdict"] == "blocked"],
                       "neutralized": [x for x in scans if x["verdict"] == "neutralized"],
                       "clean": sum(x["verdict"] == "clean" for x in scans)}
    released = sum(1 for f in res["files"] if f["status"] == "sanitized" and f.get("output"))
    res["view"] = {**res["counts"], "files_total": len(scans), "files_sanitized": released,
                   "files_quarantined": len(scans) - released, "files_blocked": len(res["security"]["blocked"])}
    res["speed"] = {"total_seconds": total_s, "read_seconds": read_s, "engine_seconds": round(wall, 2),
                    "redact_seconds": redact_s, "pages": pages,
                    "pages_per_second": round(pages / total_s, 2) if pages and total_s else None,
                    "ocr_available": pdf_support.OCR_AVAILABLE, "ocr_langs": pdf_support.ocr_langs()}
    return res


def _read_text(p: Path) -> str:
    try:
        return decode(p.read_bytes())
    except Exception:  # noqa: BLE001
        return "(binary or unreadable file)"


def summarize(job: str, inp: Path, out: Path, wall: float, pdf_out: dict | None = None,
              notes: dict | None = None) -> dict:
    pdf_out, notes = pdf_out or {}, notes or {}
    report = json.loads((out / "report.json").read_text(encoding="utf-8"))
    records = [json.loads(x) for x in (out / "records.jsonl").read_text(encoding="utf-8").splitlines() if x.strip()]
    sha2in = {hashlib.sha256(p.read_bytes()).hexdigest(): p for p in inp.rglob("*") if p.is_file()}
    tags: Counter = Counter()
    files, pages = [], {}
    for f in report["files"]:
        src = sha2in.get(f["input_sha256"])
        entry = {"input": src.relative_to(inp).as_posix() if src else "?", "status": f["status"],
                 "reason": f.get("reason"), "output": f.get("output")}
        if src is not None:
            before = _read_text(src)
            entry["before"] = before[:PREVIEW]
        if f.get("output"):
            after = (out / f["output"]).read_text(encoding="utf-8", errors="replace")
            found = TAG_RX.findall(after)
            tags.update(found)
            entry["after"] = after[:PREVIEW]
            entry["truncated"] = len(after) > PREVIEW
            entry["removed"] = len(found)
            entry["pseudonyms"] = sorted(set(PSN_RX.findall(after)))
        m = PAGE_RX.match((f.get("output") or "").removeprefix("sanitized/"))
        if m and m.group(1) + PAGES in pdf_out:    # pages of one document: shown as that document
            pages.setdefault(m.group(1) + PAGES, []).append((int(m.group(2)), entry))
            continue
        if entry["input"] in notes:
            entry["note"] = notes[entry["input"]]
        files.append(entry)
    for folder, items in pages.items():
        src_rel, out_pdf = pdf_out[folder]
        items.sort(key=lambda x: x[0])
        after = "\n\n".join(f"--- page {n} ---\n{e.get('after', '')}" for n, e in items)
        files.append({"input": src_rel, "status": "sanitized", "reason": None, "output": out_pdf, "pdf": out_pdf,
                      "after": after[:PREVIEW], "truncated": len(after) > PREVIEW,
                      "removed": sum(e.get("removed", 0) for _, e in items),
                      "pseudonyms": sorted({p for _, e in items for p in e.get("pseudonyms", [])}),
                      "note": "Every page was read (typed text directly, scanned or handwritten pages by OCR), "
                              "cleaned by IncogRx as its own record, and written back as a redacted, scrubbed copy."})
    files.sort(key=lambda e: (e["status"] != "sanitized", e["input"]))
    pats = defaultdict(lambda: {"records": 0, "files": set()})
    for r in records:
        if r.get("patient"):
            pats[r["patient"]]["records"] += 1
            shown = r["file"].removeprefix("sanitized/")
            pats[r["patient"]]["files"].add(shown_name(shown))
    patients = sorted(({"pseudonym": k, "records": v["records"], "files": sorted(v["files"])} for k, v in pats.items()),
                      key=lambda x: (-len(x["files"]), -x["records"], x["pseudonym"]))
    try:
        people, unlinked_people = build_people(out, records)
    except Exception:  # noqa: BLE001  the list is a view; never fail the run over it
        people, unlinked_people = [], []
    return {"job": job, "counts": report["counts"], "timing": report.get("timing", {}),
            "resources": report.get("resources", {}), "wall_seconds": round(wall, 2),
            "tags": dict(tags.most_common()), "files": files, "patients": patients,
            "unlinked": sum(1 for r in records if not r.get("patient")),
            "people": people, "unlinked_records": unlinked_people,
            "pdfs": [{"name": f["input"], "path": f["pdf"]} for f in files if f.get("pdf")]}


# ---------- people list (released values only; nothing here is read from the input) ----------
AGE_KEY = re.compile(r"(?i)^(?:patient[_ ]?)?age(?:[_ ]?(?:in[_ ]?)?(?:years?|yrs|band|group))?$|^age[_ ]?/?[_ ]?sex$|^आयु$|^उम्र$")
BAND_RX = re.compile(r"([0-9]{1,3}\s*-\s*[0-9]{1,3}|[0-9]{2}\+)")
SEX_KEY = re.compile(r"(?i)gender|\bsex\b|^sex|लिंग")
DIST_KEY = re.compile(r"(?i)district|distt|जिला|जनपद")
DX_KEY = re.compile(r"(?i)diagnos|icd|condition|disease|निदान")
ICD_RX = re.compile(r"\b([A-TV-Z][0-9]{2}(?:\.[0-9A-Z]{1,4})?)\b")
TXT_AGE = re.compile(r"(?i)(?:\bage(?:\s*/\s*sex)?|आयु|उम्र)\s*[:\-]\s*([0-9]{1,3}\s*-\s*[0-9]{1,3}|[0-9]{2}\+)")
TXT_SEX = re.compile(r"(?i)(?:\bsex\b|\bgender\b|लिंग)\s*[:\-]\s*(male|female|m|f|पुरुष|महिला)\b|"
                     r"[0-9]\s*(?:yrs?|years?|वर्ष)?\s*/\s*(male|female|m|f|पुरुष|महिला)\b|\b(पुरुष|महिला)\b")
TXT_DIST = re.compile(r"(?i)(?:\bdistt?\.?|\bdistrict|जिला|जनपद)\s*[:\-.]?\s*([A-Za-z][A-Za-z ]{2,24}?|[ऀ-ॿ]{2,20})(?=\s*(?:[-,|\n(]|$|[0-9]))")
TXT_DX = re.compile(r"(?i)(?:final\s+|provisional\s+)?diagnosis\s*[:\-]\s*([^\n]{3,160})|निदान\s*[:\-]\s*([^\n]{3,160})")
SEX_NORM = {"m": "M", "male": "M", "पुरुष": "M", "f": "F", "female": "F", "महिला": "F"}


def _flatten(node, prefix=""):
    if isinstance(node, dict):
        for k, v in node.items():
            yield from _flatten(v, f"{prefix}.{k}" if prefix else str(k))
    elif isinstance(node, list):
        for v in node:
            yield from _flatten(v, prefix)
    elif node not in (None, ""):
        yield prefix, str(node)


def _pointer(doc, ptr: str):
    node = doc
    for part in ptr.strip("/").split("/") if ptr.strip("/") else []:
        part = part.replace("~1", "/").replace("~0", "~")
        node = node[int(part)] if isinstance(node, list) else node[part]
    return node


class _Released:
    """Reads released (sanitized) files once and returns one record's released content."""
    def __init__(self, out: Path):
        self.out, self.cache = out, {}

    def _load(self, rel: str):
        if rel not in self.cache:
            p = self.out / rel
            text = p.read_text(encoding="utf-8", errors="replace")
            kind, data = "text", text
            low = rel.lower()
            try:
                if low.endswith((".csv", ".tsv")):
                    delim = "\t" if low.endswith(".tsv") else ","
                    first = text.split("\n", 1)[0]
                    if first.count("\t") > first.count(delim):
                        delim = "\t"
                    elif first.count(";") > first.count(delim) and delim == ",":
                        delim = ";"
                    kind, data = "csv", list(csv.reader(io.StringIO(text, newline=""), delimiter=delim))
                elif low.endswith(".jsonl") or low.endswith(".ndjson"):
                    kind, data = "json", [json.loads(x) for x in text.splitlines() if x.strip()]
                elif low.endswith(".json"):
                    kind, data = "json", json.loads(text)
            except Exception:  # noqa: BLE001
                kind, data = "text", text
            self.cache[rel] = (kind, data)
        return self.cache[rel]

    def get(self, rec: dict):
        """Return (pairs, text): key/value pairs for structured records, plain text for documents."""
        kind, data = self._load(rec["file"])
        loc = rec.get("out") or rec["loc"]
        try:
            if kind == "csv" and loc.startswith("row:"):
                header, row = data[0], data[int(loc[4:]) + 1]
                return [(h, v) for h, v in zip(header, row) if v.strip()], None
            if kind == "json":
                node = data if loc == "doc" else _pointer(data, loc)
                return list(_flatten(node)), None
        except Exception:  # noqa: BLE001
            pass
        if kind == "json":
            return list(_flatten(data)), None
        return None, data if isinstance(data, str) else ""


def _facts(pairs, text) -> dict:
    f = {"age": set(), "sex": set(), "district": set(), "diagnosis": set()}
    if pairs is not None:
        for k, v in pairs:
            leaf = k.rsplit(".", 1)[-1]
            if AGE_KEY.search(leaf.strip()):
                b = BAND_RX.search(v)
                if b:
                    f["age"].add(re.sub(r"\s+", "", b.group(1)))
                g = re.search(r"/\s*(m|f|male|female)\b", v, re.I)
                if g:
                    f["sex"].add(SEX_NORM[g.group(1).lower()])
            elif SEX_KEY.search(leaf) and v.strip().lower() in SEX_NORM:
                f["sex"].add(SEX_NORM[v.strip().lower()])
            elif DIST_KEY.search(k) and len(v) <= 30 and "[" not in v:
                f["district"].add(v.strip())
            elif DX_KEY.search(k) or leaf.lower() in ("display",) and "condition" in k.lower():
                if 2 < len(v) <= 160 and not v.startswith("http"):
                    f["diagnosis"].add(v.strip())
    else:
        for m in TXT_AGE.finditer(text):
            f["age"].add(re.sub(r"\s+", "", m.group(1)))
        for m in TXT_SEX.finditer(text):
            g = (m.group(1) or m.group(2) or m.group(3) or "").lower()
            if g in SEX_NORM:
                f["sex"].add(SEX_NORM[g])
        for m in TXT_DIST.finditer(text):
            d = m.group(1).strip()
            if d and "[" not in d:
                f["district"].add(d)
        for m in TXT_DX.finditer(text):
            d = (m.group(1) or m.group(2) or "").strip(" .;")
            if d and "[" not in d[:3]:
                f["diagnosis"].add(d)
    return f


def _tidy_dx(values) -> list:
    """Readable condition names: split lists, drop bare codes when a name exists, de-duplicate."""
    names, codes = {}, set()
    for v in values:
        for part in re.split(r"[;|]", v):
            part = part.strip(" .,")
            if not part:
                continue
            if re.fullmatch(r"[A-Z][0-9]{2}(?:\.[0-9A-Z]{1,4})?(?:\s*-\s*[A-Z][0-9]{2})?", part):
                codes.add(part)
                continue
            key = re.sub(r"\s*\([^)]*\)?\s*$", "", part).lower()
            if len(part) > 70:
                part = part[:67].rstrip() + "..."
            names.setdefault(key, part)
    keys = sorted(names, key=len, reverse=True)
    keep = [k for i, k in enumerate(keys) if not any(o.startswith(k) for o in keys[:i])]
    out = sorted((names[k] for k in keep), key=str.lower)
    return (out or sorted(codes))[:6]


def _preview(pairs, text) -> str:
    if pairs is not None:
        return "  ·  ".join(f"{k.rsplit('.', 1)[-1]}: {v}" for k, v in pairs)[:600]
    return (text or "").strip()[:4000]


def build_people(out: Path, records: list) -> tuple:
    rd = _Released(out)
    groups: dict = defaultdict(list)
    for r in records:
        groups[r.get("patient")].append(r)

    def block(recs: list, pseudonym):
        facts = {"age": set(), "sex": set(), "district": set(), "diagnosis": set()}
        removed: Counter = Counter()
        items = []
        for r in recs:
            pairs, text = rd.get(r)
            for k, v in _facts(pairs, text).items():
                facts[k] |= v
            content = " ".join(v for _, v in pairs) if pairs is not None else (text or "")
            removed.update(TAG_RX.findall(content))
            shown = shown_name(r["file"].removeprefix("sanitized/"))
            items.append({"file": shown, "loc": r.get("out") or r["loc"],
                          "preview": _preview(pairs, text)})
        return {"pseudonym": pseudonym, "records": len(recs), "files": sorted({i["file"] for i in items}),
                "age": sorted(facts["age"]), "sex": sorted(facts["sex"]), "district": sorted(facts["district"]),
                "diagnosis": _tidy_dx(facts["diagnosis"]), "removed": dict(removed.most_common()),
                "items": items[:15], "more": max(0, len(items) - 15)}

    people = [block(v, k) for k, v in groups.items() if k]
    people.sort(key=lambda x: (-len(x["files"]), -x["records"], x["pseudonym"]))
    by_file: dict = defaultdict(list)
    for r in groups.get(None, []):
        by_file[r["file"]].append(r)
    unlinked = [block(v, None) for _, v in sorted(by_file.items())][:40]
    return people, unlinked


def job_file(job: str, rel: str) -> bytes | None:
    from urllib.parse import unquote
    with LOCK:
        work = JOBS.get(job)
    if work is None:
        return None
    root = (work / "output").resolve()
    p = (root / unquote(rel)).resolve()
    if root not in p.parents or not p.is_file():   # stay inside this job's output folder
        return None
    return p.read_bytes()


def zip_job(job: str) -> bytes | None:
    with LOCK:
        work = JOBS.get(job)
    if work is None or not (work / "output").exists():
        return None
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as z:
        for p in sorted((work / "output").rglob("*")):
            if p.is_file():
                z.write(p, p.relative_to(work / "output").as_posix())
    return buf.getvalue()


class Handler(BaseHTTPRequestHandler):
    server_version = "IncogRxDemo/1.0"

    def log_message(self, *args) -> None:   # no request logs: paths and payloads may hold personal data
        return

    def _send(self, code: int, body: bytes, ctype: str, extra: dict | None = None) -> None:
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.send_header("Access-Control-Allow-Origin", "*")      # the static page on Vercel calls this API
        for k, v in (extra or {}).items():
            self.send_header(k, v)
        self.end_headers()
        self.wfile.write(body)

    def _json(self, code: int, obj) -> None:
        self._send(code, json.dumps(obj, ensure_ascii=False).encode("utf-8"), "application/json; charset=utf-8")

    def do_OPTIONS(self) -> None:  # noqa: N802  CORS preflight from the static page
        self.send_response(204)
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
        self.send_header("Access-Control-Allow-Headers", "Content-Type")
        self.send_header("Access-Control-Max-Age", "86400")
        self.end_headers()

    def do_GET(self) -> None:  # noqa: N802
        if self.path.split("?")[0] == "/health":       # tiny keep-alive target for an uptime pinger
            self._send(200, b"ok", "text/plain; charset=utf-8")
        elif self.path in ("/", "/index.html"):
            page = (DEMO / "index.html").read_bytes().replace(b"__INCOGRX_API__", b"")   # same-server API
            self._send(200, page, "text/html; charset=utf-8")
        elif self.path.startswith("/assets/"):    # page images only: a bare file name, no paths
            name = self.path[len("/assets/"):].split("?")[0]
            p = DEMO / "assets" / name
            types = {".jpg": "image/jpeg", ".jpeg": "image/jpeg", ".png": "image/png", ".webp": "image/webp"}
            if "/" in name or "\\" in name or name.startswith(".") or p.suffix.lower() not in types or not p.is_file():
                self._json(404, {"error": "not found"})
            else:
                self._send(200, p.read_bytes(), types[p.suffix.lower()], {"Cache-Control": "max-age=3600"})
        elif self.path.startswith("/api/file/"):
            job, _, rel = self.path[len("/api/file/"):].partition("/")
            data = job_file(job, rel)
            if data is None:
                self._json(404, {"error": "File not found or expired."})
            else:
                name = rel.rsplit("/", 1)[-1]
                low = name.lower()
                ctype = ("application/pdf" if low.endswith(".pdf") else
                         "text/plain; charset=utf-8" if low.endswith((".txt", ".csv", ".tsv", ".json", ".jsonl", ".ndjson", ".md"))
                         else "application/octet-stream")
                self._send(200, data, ctype,
                           {"Content-Disposition": f'inline; filename="{name}"'})
        elif self.path.startswith("/api/download/"):
            data = zip_job(self.path.rsplit("/", 1)[-1])
            if data is None:
                self._json(404, {"error": "Result expired. Run again."})
            else:
                self._send(200, data, "application/zip",
                           {"Content-Disposition": 'attachment; filename="incogrx_output.zip"'})
        else:
            self._json(404, {"error": "not found"})

    def do_POST(self) -> None:  # noqa: N802
        if self.path != "/api/run":
            self._json(404, {"error": "not found"})
            return
        try:
            length = int(self.headers.get("Content-Length", "0"))
            if length <= 0 or length > MAX_UPLOAD * 2:
                raise ValueError("Upload is empty or too large.")
            req = json.loads(self.rfile.read(length).decode("utf-8"))
            mode, secret = req.get("mode"), str(req.get("secret") or "")
            if mode == "text":
                text = str(req.get("text") or "")
                if not text.strip():
                    raise ValueError("Paste some text first.")
                files = [("pasted_note.txt", text.encode("utf-8"))]
            elif mode == "files":
                files, total, scans = [], 0, []
                for f in req.get("files") or []:
                    data = base64.b64decode(f["b64"])
                    for rel, member in expand_zip(str(f["path"]), data, scans):
                        total += len(member)
                        if total > MAX_UPLOAD:
                            raise ValueError("Upload is larger than 80 MB.")
                        files.append((rel, member))
                if not files and scans:
                    raise ValueError("Every file was blocked by the security scan: " +
                                     "; ".join(f"{x['name']}: {x['reason']}" for x in scans)[:600])
                if not files:
                    raise ValueError("Choose at least one file.")
                if total > MAX_UPLOAD:
                    raise ValueError("Upload is larger than 80 MB.")
            else:
                raise ValueError("Unknown mode.")
            result = run_job(files, secret, scans if mode == "files" else None)
            if mode == "files":           # uploaded originals are never sent back to the page
                for f in result["files"]:
                    f.pop("before", None)
            self._json(200, result)
        except (ValueError, KeyError, json.JSONDecodeError) as exc:
            self._json(400, {"error": str(exc) or "Bad request."})
        except Exception:  # noqa: BLE001  never echo internals: they may contain file names
            self._json(500, {"error": "The pipeline could not process this input."})


def main() -> int:
    httpd = ThreadingHTTPServer((HOST, PORT), Handler)
    url = f"http://{HOST}:{PORT}"
    print(f"IncogRx demo running at {url}  (Ctrl+C to stop)")
    if "--no-browser" not in sys.argv and not CLOUD:
        threading.Timer(0.8, lambda: webbrowser.open(url)).start()
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        httpd.server_close()
        _cleanup_all()
    return 0


if __name__ == "__main__":
    sys.exit(main())
