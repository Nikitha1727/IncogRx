"""Two-pass pipeline.

Pass 1 (learn): parse every file and learn identifiers from structured fields
            (MRNs, phones, IDs, PINs, names) into a Knowledge base.
Pass 2 (sanitise): clean every field, free-text value, key, header and file name using
            field categories + patterns + the learned identifiers, then write outputs.
Linking (phase 3) and the privacy layer (phase 4) plug in between the two passes."""
from __future__ import annotations

import base64
import binascii
import csv
import hashlib
import io
import json
import re
import sys
import time
from pathlib import Path

from . import readers
from .detect import Knowledge, find_spans, redact, norm_digits, RX
from .fields import classify_key, classify_path, norm_key
from .sanitize import Stats, clean_text, sanitize

ID_CATS = ("PHONE", "AADHAAR", "ABHA", "PAN", "EMAIL", "INSURANCE")


# ----------------------------------------------------------------------------- column sniffing
def sniff_column(values: list) -> str | None:
    """Classify an unrecognised column from the shape of its values."""
    vals = [v.strip() for v in values if v and v.strip()][:200]
    if len(vals) < 2:
        return None
    for cat, kind in (("ABHA", "ABHA"), ("AADHAAR", "AADHAAR"), ("PAN", "PAN"), ("EMAIL", "EMAIL"),
                      ("INSURANCE", "INSURANCE"), ("PHONE", "PHONE")):
        hits = sum(1 for v in vals if RX[kind].fullmatch(norm_digits(v)))
        if hits / len(vals) >= 0.6:
            return cat
    return None


def csv_categories(header: list, body: list) -> list:
    cats = []
    for j, h in enumerate(header):
        cat = classify_key(h)
        if cat is None:
            cat = sniff_column([r[j] for r in body if j < len(r)])
        cats.append(cat)
    return cats


def row_ctx(header: list, row: list) -> dict:
    ctx = {}
    for h, v in zip(header, row):
        k = norm_key(h)
        if not v:
            continue
        if any(w in k.split() for w in ("tehsil", "taluka", "तहसील")):
            ctx["tehsil"] = v.strip()
        elif any(w in k.split() for w in ("district", "jila", "zila", "distt", "जिला")):
            ctx["district"] = v.strip()
    return ctx


# ----------------------------------------------------------------------------- pass 1: learning
def learn_value(cat: str | None, value, kb: Knowledge) -> None:
    if value is None or isinstance(value, bool) or not str(value).strip():
        return
    s = str(value)
    if cat == "MRN":
        kb.add_mrn(s)
    elif cat in ("PHONE", "AADHAAR", "ABHA"):
        kb.add_digits(s)
    elif cat == "PIN":
        d = re.sub(r"\D", "", norm_digits(s))
        if len(d) == 6:
            kb.pins.add(d)
    elif cat in ("EMAIL", "PAN", "INSURANCE"):
        if len(s.strip()) >= 6 and "[" not in s:
            kb.exact[s.strip().lower()] = cat
    elif cat == "NAME":
        kb.add_name(s, "NAME")
    elif cat == "RELATIVE":
        kb.add_name(s, "RELATIVE")


def ext_key(node: dict, k: str) -> str:
    """FHIR extensions carry their meaning in `url`: {"url": ".../mothers-name", "valueString": ...}."""
    if k.startswith("value") and isinstance(node.get("url"), str):
        tail = node["url"].rstrip("/").rsplit("/", 1)[-1]
        if classify_key(tail) is not None:
            return tail
    return k


def learn_json(node, path: tuple, rt, kb: Knowledge) -> None:
    if isinstance(node, dict):
        rt = node.get("resourceType", rt) if isinstance(node.get("resourceType"), str) else rt
        for k, v in node.items():
            learn_json(v, path + (ext_key(node, k),), rt, kb)
    elif isinstance(node, list):
        for v in node:
            learn_json(v, path, rt, kb)
    else:
        learn_value(classify_path(path, rt), node, kb)


def learn(doc: readers.Doc, kb: Knowledge) -> None:
    if doc.kind == "csv":
        header, body = doc.rows[0], doc.rows[1:]
        cats = csv_categories(header, body)
        for row in body:
            for j, v in enumerate(row):
                if j < len(cats):
                    learn_value(cats[j], v, kb)
    elif doc.kind == "json":
        learn_json(doc.data, (), None, kb)
    elif doc.kind == "jsonl":
        for obj in doc.lines:
            learn_json(obj, (), None, kb)
    if doc.kind == "text":
        for s, e, kind in find_spans(doc.text, None):
            if kind == "MRN":
                kb.add_mrn(doc.text[s:e])


# ----------------------------------------------------------------------------- pass 2: sanitising
def clean_key(key: str, kb: Knowledge) -> str:
    if classify_key(key) is not None:
        return key
    return clean_text(key, kb)


def clean_b64(value: str, kb: Knowledge) -> str:
    try:
        raw = base64.b64decode(value, validate=True)
        text = raw.decode("utf-8")
    except (binascii.Error, ValueError, UnicodeDecodeError):
        return value
    cleaned = clean_text(text, kb)
    if cleaned == text:
        return value
    return base64.b64encode(cleaned.encode("utf-8")).decode("ascii")


def sanitize_json(node, path: tuple, rt, ctx: dict, kb: Knowledge):
    if isinstance(node, dict):
        if isinstance(node.get("resourceType"), str):
            rt = node["resourceType"]
        local = dict(ctx)
        for k, v in node.items():
            nk = norm_key(k)
            if isinstance(v, str) and v.strip():
                if nk in ("tehsil", "taluka"):
                    local["tehsil"] = v.strip()
                elif nk in ("district", "jila", "distt"):
                    local["district"] = v.strip()
        out, used = {}, set()
        for k, v in node.items():
            nk_out = clean_key(k, kb)
            base, i = nk_out, 2
            while nk_out in used:
                nk_out = f"{base}#{i}"
                i += 1
            used.add(nk_out)
            out[nk_out] = sanitize_json(v, path + (ext_key(node, k),), rt, local, kb)
        return out
    if isinstance(node, list):
        return [sanitize_json(v, path, rt, ctx, kb) for v in node]
    if isinstance(node, str) and len(path) >= 2 and norm_key(path[-1]) == "data" and norm_key(path[-2]) == "attachment":
        return clean_b64(node, kb)
    cat = classify_path(path, rt)
    if cat is None and isinstance(node, str) and path and norm_key(path[-1]) == "name":
        if kb.name_rx() is not None and kb.name_rx().fullmatch(node.strip()):
            cat = "NAME"
    return sanitize(cat, node, ctx, kb)


def json_records(data, out_rel: str) -> list:
    recs = []
    if isinstance(data, dict) and data.get("resourceType") != "Bundle":
        for k, v in data.items():
            if isinstance(v, list) and v and all(isinstance(x, dict) for x in v):
                key = k.replace("~", "~0").replace("/", "~1")
                recs += [{"file": out_rel, "loc": f"/{key}/{i}", "patient": None} for i in range(len(v))]
    return recs or [{"file": out_rel, "loc": "doc", "patient": None}]


def write_csv(doc: readers.Doc, kb: Knowledge, out_rel: str, records: list) -> str:
    header, body = doc.rows[0], doc.rows[1:]
    cats = csv_categories(header, body)
    new_header = [h if cats[j] is not None else clean_text(h, kb) for j, h in enumerate(header)]
    buf = io.StringIO()
    w = csv.writer(buf, delimiter=doc.delimiter, lineterminator=doc.newline)
    w.writerow(new_header)
    for i, row in enumerate(body):
        ctx = row_ctx(header, row)
        w.writerow([sanitize(cats[j] if j < len(cats) else None, v, ctx, kb) for j, v in enumerate(row)])
        records.append({"file": out_rel, "loc": f"row:{i}", "patient": None})
    return buf.getvalue()


def write_doc(doc: readers.Doc, kb: Knowledge, out_rel: str, records: list) -> str:
    if doc.kind == "csv":
        return write_csv(doc, kb, out_rel, records)
    if doc.kind == "json":
        cleaned = sanitize_json(doc.data, (), None, {}, kb)
        records += json_records(cleaned, out_rel)
        return json.dumps(cleaned, ensure_ascii=False, indent=2) + "\n"
    if doc.kind == "jsonl":
        records.append({"file": out_rel, "loc": "doc", "patient": None})
        return doc.newline.join(json.dumps(sanitize_json(o, (), None, {}, kb), ensure_ascii=False)
                                for o in doc.lines) + doc.newline
    records.append({"file": out_rel, "loc": "doc", "patient": None})
    return clean_text(doc.text, kb)


def safe_name(rel: str, kb: Knowledge) -> str:
    parts = rel.split("/")
    out = []
    for p in parts:
        stem, dot, ext = p.rpartition(".") if "." in p else (p, "", "")
        spaced = stem.replace("_", " ")
        cleaned = clean_text(spaced, kb)
        if cleaned != spaced:
            stem = re.sub(r"\[([A-Z_]+)\]", r"\1", cleaned).replace(" ", "_")
        out.append(stem + (dot + ext if dot else ""))
    return "/".join(out)


# ----------------------------------------------------------------------------- driver
def peak_rss_mb() -> float:
    try:
        import resource
        r = resource.getrusage(resource.RUSAGE_SELF).ru_maxrss
        return round(r / 1024 if sys.platform != "darwin" else r / 1048576, 1)
    except Exception:  # noqa: BLE001
        return 0.0


def run(inp: Path, out: Path) -> dict:
    t0 = time.monotonic()
    sys.setrecursionlimit(10000)
    san = out / "sanitized"
    san.mkdir(parents=True, exist_ok=True)
    kb = Knowledge()
    items = []
    for path in sorted((p for p in inp.rglob("*") if p.is_file()), key=lambda p: p.relative_to(inp).as_posix()):
        rel = path.relative_to(inp).as_posix()
        raw = path.read_bytes()
        item = {"rel": rel, "sha": hashlib.sha256(raw).hexdigest(), "doc": None, "reason": None}
        try:
            item["doc"] = readers.load(path, rel, raw)
        except readers.Quarantine as q:
            item["reason"] = str(q)
        except Exception as exc:  # noqa: BLE001  fail safe, reason holds no content
            item["reason"] = type(exc).__name__
        items.append(item)

    for it in items:  # pass 1
        if it["doc"] is not None:
            try:
                learn(it["doc"], kb)
            except Exception:  # noqa: BLE001
                pass

    files, records, used_names = [], [], set()
    for it in items:  # pass 2
        entry = {"input_sha256": it["sha"]}
        doc = it["doc"]
        if doc is None:
            entry.update(output=None, status="quarantined", reason=it["reason"])
            files.append(entry)
            continue
        try:
            out_rel = safe_name(it["rel"], kb)
            base, n = out_rel, 2
            while out_rel in used_names:
                stem, dot, ext = base.rpartition(".")
                out_rel = f"{stem}_{n}.{ext}" if dot else f"{base}_{n}"
                n += 1
            used_names.add(out_rel)
            file_records: list = []
            result = write_doc(doc, kb, f"sanitized/{out_rel}", file_records)
            dest = san / out_rel
            dest.parent.mkdir(parents=True, exist_ok=True)
            dest.write_text(result, encoding="utf-8", newline="")
            records += file_records
            entry.update(output=f"sanitized/{out_rel}", status="sanitized")
            if out_rel != it["rel"]:
                entry["renamed"] = True
        except Exception as exc:  # noqa: BLE001
            entry.update(output=None, status="quarantined", reason=type(exc).__name__)
        files.append(entry)

    with open(out / "records.jsonl", "w", encoding="utf-8") as f:
        for r in records:
            f.write(json.dumps(r, ensure_ascii=False, sort_keys=True) + "\n")
    n_san = sum(e["status"] == "sanitized" for e in files)
    report = {
        "schema": "raksha-report/1",
        "files": files,
        "counts": {
            "files_total": len(files), "files_sanitized": n_san, "files_quarantined": len(files) - n_san,
            "records_processed": len(records), "identifiers_detected": Stats.identifiers,
            "records_linked": sum(r["patient"] is not None for r in records),
            "records_generalized": Stats.generalized, "records_suppressed": 0, "records_quarantined": 0,
        },
        "timing": {"seconds": round(time.monotonic() - t0, 2)},
        "resources": {"peak_rss_mb": peak_rss_mb()},
    }
    (out / "report.json").write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    return report
