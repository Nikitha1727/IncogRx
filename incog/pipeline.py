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

from . import dates, link, privacy, readers, sniff, textner
from .config import POLICY
from .detect import REL_PREFIX, Knowledge, find_spans, redact, norm_digits, RX
from .fields import classify_key, classify_path, norm_key
from .sanitize import DOB_MODE, Stats, clean_text, sanitize

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


def csv_categories(header: list, body: list, kb: Knowledge | None = None) -> list:
    return sniff.csv_categories(header, body, kb)


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
    elif cat == "VILLAGE":
        if len(s) <= 40 and not re.search(r"\d", s):
            for t in s.split():
                kb.add_token(t, "VILLAGE")
    elif cat == "NAME":
        kb.add_name(s, "NAME")
        if len(s.split()) == 1:
            kb.add_token(s, "NAME")
    elif cat == "RELATIVE":
        kb.add_name(s, "RELATIVE")
        rest = REL_PREFIX.sub("", s).strip()
        if len(rest.split()) == 1:
            kb.add_token(rest, "RELATIVE")
    elif cat in (None, "TEXT", "KEEP", "ADDRESS") and isinstance(value, str) and len(s) > 3:
        learn_text(s, kb)
        if "(" in s:
            kb.rare.learn_text(s)


def learn_admin(key: str, value, kb: Knowledge) -> None:
    nk = norm_key(key)
    if isinstance(value, str) and any(w in nk.split() for w in ("tehsil", "taluka", "district", "distt", "jila", "zila",
                                                                "जिला", "तहसील", "state")):
        if len(value) <= 40:
            for t in value.split():
                kb.admin.add(t.strip(".,").lower())


def learn_text(s: str, kb: Knowledge) -> None:
    """Learn person and village names from free text using the Phase 2 context detectors."""
    short = len(s) <= 200                   # short values repeat a lot; long notes are unique, so not cached
    for t in (textner.admin_names_cached(s) if short else textner.admin_names(s)):
        kb.admin.add(t.lower())
    for surf, kind in (textner.detect_found(s) if short else textner.detect(s).found):
        if kind in ("NAME", "RELATIVE"):
            if len(surf.split()) >= 2:
                kb.add_name(surf, kind)
            else:
                kb.add_token(surf, kind)
        elif kind == "VILLAGE":
            for t in surf.split():
                kb.add_token(t, "VILLAGE")


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
        if "code" in node and "display" in node:
            kb.rare.learn_pair(node.get("code"), node.get("display"))
        for k, v in node.items():
            if not isinstance(v, (dict, list)):
                learn_admin("district" if (resource_type_is_place(rt) and k == "city") else k, v, kb)
            learn_json(v, path + (ext_key(node, k),), rt, kb)
    elif isinstance(node, list):
        for v in node:
            learn_json(v, path, rt, kb)
    else:
        learn_value(sniff.path_cat(path, rt), node, kb)


def resource_type_is_place(rt) -> bool:
    return rt in ("Organization", "Location")


def learn(doc: readers.Doc, kb: Knowledge) -> None:
    if doc.kind == "csv":
        header, body = doc.rows[0], doc.rows[1:]
        cats = csv_categories(header, body, kb)
        for row in body:
            for j, v in enumerate(row):
                if j < len(cats):
                    learn_value(cats[j], v, kb)
                    if isinstance(v, str) and "(" in v:
                        kb.rare.learn_text(v)
                    if cats[j] in ("KEEP", None) and j < len(header):
                        learn_admin(header[j], v, kb)
    elif doc.kind == "json":
        sniff.CURRENT = sniff.json_map(doc.data, kb)
        learn_json(doc.data, (), None, kb)
        sniff.CURRENT = {}
    elif doc.kind == "jsonl":
        sniff.CURRENT = sniff.json_map(doc.lines, kb)
        for obj in doc.lines:
            learn_json(obj, (), None, kb)
        sniff.CURRENT = {}
    if doc.kind == "text":
        kb.rare.learn_text(doc.text)
        learn_text(doc.text, kb)
        for s, e, kind in find_spans(doc.text, None):
            if kind == "MRN":
                kb.add_mrn(doc.text[s:e])


# ----------------------------------------------------------------------------- linking units
def _ptr(k: str) -> str:
    return k.replace("~", "~0").replace("/", "~1")


def units(doc: readers.Doc, kb: Knowledge) -> list:
    """Return [(loc, Evidence)] for the records of one document, plus the list keys used."""
    if doc.kind == "csv":
        header, body = doc.rows[0], doc.rows[1:]
        cats = csv_categories(header, body, kb)
        out = []
        for i, row in enumerate(body):
            ev = link.Ev()
            for j, v in enumerate(row):
                if j < len(cats):
                    h = header[j] if j < len(header) else ""
                    cat = cats[j]
                    if cat is None and norm_key(h) in ("patient ref", "patient id"):
                        cat = "MRN"
                    link.add_value(ev, cat, v, link._rel_context([h]), h)
                    if cat in (None, "TEXT", "KEEP") and isinstance(v, str) and len(v) > 12:
                        link.text_evidence(v, ev, light=True)
            out.append((f"row:{i}", ev))
        return out
    if doc.kind == "json":
        sniff.CURRENT = sniff.json_map(doc.data, kb)
        try:
            return json_units(doc.data)
        finally:
            sniff.CURRENT = {}
    if doc.kind == "jsonl":
        sniff.CURRENT = sniff.json_map(doc.lines, kb)
        ev = link.Ev()
        for o in doc.lines:
            link.json_evidence(o, (), None, ev)
        sniff.CURRENT = {}
        return [("doc", link.single_person(ev))]
    ev = link.Ev()
    link.text_evidence(doc.text, ev, kb)
    return [("doc", ev)]


def _record_like(v: list) -> bool:
    """A list of similar dicts (rows of an export), not a list of sub-structures like lab panels."""
    if len(v) < 2:
        return False
    keysets = [frozenset(x) for x in v]
    common = max(set(keysets), key=keysets.count)
    return keysets.count(common) / len(keysets) >= 0.5 and len(common) >= 3


def json_units(data) -> list:
    if isinstance(data, dict) and data.get("resourceType") != "Bundle":
        top = link.Ev()
        for k, v in data.items():
            if not (isinstance(v, list) and v and all(isinstance(x, dict) for x in v)):
                link.json_evidence(v, (k,), None, top)
        out = []
        for k, v in data.items():
            if isinstance(v, list) and v and all(isinstance(x, dict) for x in v):
                evs = []
                for x in v:
                    ev = link.Ev()
                    link.json_evidence(x, (k,), None, ev)
                    evs.append(ev)
                person_rows = any(e.ids or e.names for e in evs)
                if person_rows or (_record_like(v) and not (top.ids or top.names)):
                    out += [(f"/{_ptr(k)}/{i}", e) for i, e in enumerate(evs)]
        if out:
            return out
    ev = link.Ev()
    link.json_evidence(data, (), None, ev)
    return [("doc", link.single_person(ev))]


def measure_privacy(lk) -> dict:
    """Residual re-identification risk measured on what the release still shows per patient:
    the (age band, gender, district) combination. Counts only, never values."""
    from collections import Counter
    from .sanitize import age_band
    k = int(POLICY.get("min_group_size", 5))
    keys, missing = [], 0
    for r, ev in getattr(lk, "clusters", {}).items():
        if not ev.person():
            continue
        band = age_band(sorted(ev.ages)[len(ev.ages) // 2]) if ev.ages else None
        g = next(iter(ev.genders)) if len(ev.genders) == 1 else None
        d = sorted(ev.districts)[0] if ev.districts else None
        if band and g and d:
            keys.append((band, g, d))
        else:
            missing += 1
    groups = Counter(keys)
    sizes = [groups[x] for x in keys]
    n = len(keys)
    return {
        "patients": n + missing,
        "quasi_identifiers": ["age_band", "gender", "district"],
        "patients_with_all_quasi_identifiers": n,
        "groups": len(groups),
        "smallest_group": min(groups.values()) if groups else 0,
        "median_group": sorted(sizes)[n // 2] if n else 0,
        "k": k,
        "patients_unique": sum(1 for s in sizes if s == 1),
        "patients_below_k": sum(1 for s in sizes if s < k),
        "share_below_k": round(sum(1 for s in sizes if s < k) / n, 3) if n else 0.0,
        "note": "measured inside this release on the quasi-identifiers that survive; an attacker with a "
                "population register faces larger groups",
    }


def link_all(items: list, kb: Knowledge) -> None:
    lk = link.Linker()
    for it in items:
        it["units"] = []
        if it["doc"] is None:
            continue
        try:
            for loc, ev in units(it["doc"], kb):
                it["units"].append((loc, lk.add(it["rel"], loc, ev)))
        except Exception:  # noqa: BLE001
            it["units"] = []
    ps = lk.solve()
    for it in items:
        it["ps"] = {loc: ps[i] for loc, i in it["units"]}
    kb.privacy = measure_privacy(lk)
    for i, ev in enumerate(lk.ev):                     # rare conditions counted per patient cluster
        if not ev.person():
            continue
        for c in ev.codes:
            kb.rare.count(c, str(lk.roots[i]))
    kb.rare.finalize()


PS_LABEL = re.compile(r"(?i:Patient\s*Name|Pt\.?\s*Name|Name|Naam|मरीज़?\s*का\s*नाम|नाम)\s*[:\-]\s*\[NAME\]")


def put_pseudonym(text: str, ps: str | None) -> str:
    """Write the record's pseudonym into the exported text (consistency check reads it there)."""
    if not ps:
        return text
    if "[MRN]" in text:
        return text.replace("[MRN]", ps)
    m = PS_LABEL.search(text)
    if m:
        return text[:m.end() - 6] + ps + text[m.end():]
    if "[NAME]" in text:
        return text.replace("[NAME]", ps, 1)
    nl = "\r\n" if "\r\n" in text else "\n"
    return f"Patient: {ps}{nl}" + text


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
            if rt and norm_key(k) == "birth date" and isinstance(v, str) and DOB_MODE != "year":
                continue   # FHIR birthDate is optional; a placeholder would not be a valid FHIR date
            nk_out = clean_key(k, kb)
            base, i = nk_out, 2
            while nk_out in used:
                nk_out = f"{base}#{i}"
                i += 1
            used.add(nk_out)
            rec = ctx.get("_rec") if not path else None
            if rec and k in rec and isinstance(v, list):
                sub = {kk: vv for kk, vv in local.items() if kk != "_rec"}
                out[nk_out] = [sanitize_json(x, (k,), rt, {**sub, "pseudonym": rec[k].get(i),
                                                          "shift": shift_for(rec[k].get(i), ctx.get("_rel", ""),
                                                                             f"/{_ptr(k)}/{i}")}, kb)
                               for i, x in enumerate(v)]
                continue
            out[nk_out] = sanitize_json(v, path + (ext_key(node, k),), rt, local, kb)
        return out
    if isinstance(node, list):
        return [sanitize_json(v, path, rt, ctx, kb) for v in node]
    if isinstance(node, str) and len(path) >= 2 and norm_key(path[-1]) == "data" and norm_key(path[-2]) == "attachment":
        return clean_b64(node, kb)
    cat = sniff.path_cat(path, rt)
    if cat is None and isinstance(node, str) and path and norm_key(path[-1]) == "name":
        if kb.name_rx() is not None and kb.name_rx().fullmatch(node.strip()):
            cat = "NAME"
    return sanitize(cat, node, ctx, kb)


def _unptr(k: str) -> str:
    return k.replace("~1", "/").replace("~0", "~")


def shift_for(ps: str | None, rel: str, loc: str) -> int:
    """One secret offset per patient (pseudonym); unlinked records get their own offset."""
    return dates.days_for(ps or f"rec:{rel}#{loc}")


def write_csv(doc: readers.Doc, kb: Knowledge, out_rel: str, records: list, ps: dict,
              order: str = "dmy", rel: str = "") -> str:
    header, body = doc.rows[0], doc.rows[1:]
    cats = csv_categories(header, body, kb)
    new_header = [h if cats[j] is not None else clean_text(h, kb) for j, h in enumerate(header)]
    buf = io.StringIO()
    w = csv.writer(buf, delimiter=doc.delimiter, lineterminator=doc.newline)
    w.writerow(new_header)
    for i, row in enumerate(body):
        ctx = row_ctx(header, row)
        p = ps.get(f"row:{i}")
        ctx["pseudonym"] = p
        ctx["shift"] = shift_for(p, rel, f"row:{i}")
        ctx["order"] = order
        out_row = []
        for j, v in enumerate(row):
            cat = cats[j] if j < len(cats) else None
            if cat is None and j < len(header) and norm_key(header[j]) in ("patient ref", "patient id") and v.strip():
                cat = "MRN"
            out_row.append(sanitize(cat, v, ctx, kb))
        w.writerow(out_row)
        records.append({"file": out_rel, "loc": f"row:{i}", "patient": p})
    return buf.getvalue()


def write_doc(doc: readers.Doc, kb: Knowledge, out_rel: str, records: list, ps: dict,
              order: str = "dmy", rel: str = "") -> str:
    if doc.kind == "csv":
        return write_csv(doc, kb, out_rel, records, ps, order, rel)
    if doc.kind == "json":
        rec: dict = {}
        for loc, p in ps.items():
            if loc != "doc":
                k, i = loc[1:].rsplit("/", 1)
                rec.setdefault(_unptr(k), {})[int(i)] = p
        if rec:
            ctx = {"_rec": rec, "_rel": rel, "shift": shift_for(None, rel, "doc"), "order": order}
        else:
            ctx = {"pseudonym": ps.get("doc"), "shift": shift_for(ps.get("doc"), rel, "doc"), "order": order}
        sniff.CURRENT = sniff.json_map(doc.data, kb)
        try:
            cleaned = sanitize_json(doc.data, (), None, ctx, kb)
        finally:
            sniff.CURRENT = {}
        locs = sorted(ps, key=lambda x: (x.rsplit("/", 1)[0], int(x.rsplit("/", 1)[1]) if x != "doc" else 0))
        records += [{"file": out_rel, "loc": loc, "patient": ps[loc]} for loc in locs] or \
            [{"file": out_rel, "loc": "doc", "patient": None}]
        return json.dumps(cleaned, ensure_ascii=False, indent=2) + ("\n" if doc.text.endswith("\n") else "")
    if doc.kind == "jsonl":
        p = ps.get("doc")
        records.append({"file": out_rel, "loc": "doc", "patient": p})
        jctx = {"pseudonym": p, "shift": shift_for(p, rel, "doc"), "order": order}
        sniff.CURRENT = sniff.json_map(doc.lines, kb)
        return doc.newline.join(json.dumps(sanitize_json(o, (), None, jctx, kb), ensure_ascii=False)
                                for o in doc.lines) + doc.newline
    p = ps.get("doc")
    records.append({"file": out_rel, "loc": "doc", "patient": p})
    text = clean_text(doc.text, kb)
    if p:                                       # rare-condition and age handling only for patient records
        text = privacy.band_ages(kb.rare.apply(text))
    text = dates.shift_text(text, shift_for(p, rel, "doc"), order)[0]
    return put_pseudonym(text, p)


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
    kb.rare = privacy.RareConditions()
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

    for _round in range(2):  # pass 1 (twice: the 2nd round sniffs unfamiliar columns with what round 1 learned)
        for it in items:
            if it["doc"] is not None:
                try:
                    learn(it["doc"], kb)
                except Exception:  # noqa: BLE001
                    pass
        kb.finalize()
    votes = dates.OrderVotes()
    for it in items:
        if it["doc"] is not None:
            it["toks"] = dates.source_tokens(it["rel"], it["doc"].text or "")
            it["hint"] = dates.order_hint(it["doc"].text or "")
            votes.add(it["toks"], it["hint"])
    for it in items:
        if it["doc"] is not None:
            it["order"] = votes.decide(it["toks"], it["hint"])
    try:
        link_all(items, kb)
    except Exception:  # noqa: BLE001  fail safe: release without links rather than crash
        for it in items:
            it["ps"] = {}

    kb.frozen, kb.clean_cache = True, {}       # learning is over: cleaning results can be reused
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
            result = write_doc(doc, kb, f"sanitized/{out_rel}", file_records, it.get("ps", {}),
                               it.get("order", "dmy"), it["rel"])
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
        "entities": dict(sorted(Stats.entities.items())),
        "privacy": {
            "policy": {
                "pseudonyms": "HMAC-SHA256 keyed with RAKSHA_SECRET; one per patient across files and scripts",
                "date_shift": f"one secret offset per patient within +/-{POLICY.get('date_shift_max_days', 180)} days; "
                              "intervals and lengths of stay preserved",
                "age_band_years": POLICY.get("age_band_years", 10),
                "age_top_code": POLICY.get("age_top_code", 80),
                "location_kept": "district" if str(POLICY.get("keep_tehsil", "false")).lower() != "true" else "tehsil",
                "pin_digits_kept": 3,
                "dob": POLICY.get("dob", "suppress"),
                "rare_condition_max_patients": POLICY.get("rare_condition_max_patients", 3),
            },
            "applied": {
                "dates_shifted": dates.SHIFTED[0],
                "rare_conditions_generalised": len(getattr(kb.rare, "rare_codes", {}) or {}),
            },
            "measured_risk": getattr(kb, "privacy", {}),
        },
        "timing": {"seconds": round(time.monotonic() - t0, 2)},
        "resources": {"peak_rss_mb": peak_rss_mb()},
    }
    (out / "report.json").write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    return report
