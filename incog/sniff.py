"""Phase 5: classify unfamiliar CSV columns and JSON keys from their VALUES.

Unseen exports rename columns ("Hosp Regn ID", "beneficiary", "basti"). A column is
classified by the shape of its values and by overlap with identifiers, names and villages
learned elsewhere in the release, so new vocabulary does not silently leak PII or break
linking."""
from __future__ import annotations

import re
import statistics

from .detect import RX, Knowledge, norm_digits
from .fields import classify_path, norm_key

CURRENT: dict = {}        # path -> category for the JSON document being processed

ORG = re.compile(r"(?i)\b(?:hospital|clinic|patholog\w*|lab|labs|diagnostic\w*|centre|center|medical|trust|sadan|"
                 r"pharma\w*|nursing|institute|college|ltd|pvt|dept|department|ward|govt|district)\b")
REL_START = re.compile(r"(?i)^\s*(?:[SDWC]\s?/\s?O\b|son\s+of|wife\s+of|daughter\s+of|husband\s+of|care\s+of|"
                       r"पुत्र|पुत्री|पत्नी|पति)")
NAME_SHAPE = re.compile(r"^(?:(?:[A-Z][a-z]+|[A-Z]{2,}|[A-Z]\.|Md\.|Mohd\.?)(?:\s+|$)){1,4}$|^(?:[ऀ-ॿ]+(?:\s+|$)){1,4}$")
ID_SHAPE = re.compile(r"^(?=.*\d{3})[A-Za-z0-9][A-Za-z0-9/\-_. ]{3,24}$")
DATE_RX = re.compile(r"(\d{4})-\d{1,2}-\d{1,2}|\d{1,2}[/.\-]\d{1,2}[/.\-](\d{4})")
ADDR_WORDS = re.compile(r"(?i)\b(?:house|h\.?\s?no|makan|ward|mohalla|vill\.?|village|gram|tehsil|distt?\.?|near|opp\.?|"
                        r"gali|lane|road|colony|nagar)\b|मकान|ग्राम|मोहल्ला|तहसील|जिला")
NOT_ID_KEY = {"bill", "visit", "sample", "trip", "package", "policy", "claim", "order", "invoice", "test", "loinc",
              "code", "txn", "receipt", "batch", "lot", "ticket", "amount", "room", "bed", "ward", "version", "schema"}
ID_KEY = {"reg", "regn", "registration", "id", "no", "num", "number", "uhid", "mrn", "hosp", "pt", "patient", "ptno",
          "cr", "ip", "ipd", "opd", "adm", "admission", "record", "file", "ref", "reference", "hospital",
          "क्रमांक", "पंजीकरण", "अस्पताल"}
REL_KEY = {"guardian", "relative", "attendant", "father", "husband", "mother", "spouse", "caretaker", "care", "taker",
           "abhibhavak", "kin", "escort", "pita", "pati"}
AGE_KEY = {"yrs", "years", "yr", "age", "aayu", "umar", "umr", "vay", "आयु", "उम्र"}


def sniff(values: list, key: str, kb: Knowledge | None) -> str | None:
    vals = [str(v).strip() for v in values if v is not None and not isinstance(v, (bool, dict, list)) and str(v).strip()]
    vals = vals[:300]
    if len(vals) < 1:
        return None
    n = len(vals)
    ktoks = set(norm_key(key).split()) if key else set()

    def share(pred) -> float:
        return sum(1 for v in vals if pred(v)) / n

    for cat, kind in (("ABHA", "ABHA"), ("AADHAAR", "AADHAAR"), ("PAN", "PAN"), ("EMAIL", "EMAIL"),
                      ("INSURANCE", "INSURANCE"), ("PHONE", "PHONE")):
        if share(lambda v: RX[kind].fullmatch(norm_digits(v)) is not None) >= 0.6:
            return cat
    if share(lambda v: re.fullmatch(r"[1-9]\d{5}", norm_digits(v)) is not None) >= 0.8 and not ktoks & {
            "amount", "bill", "sample", "visit", "claim", "invoice", "receipt", "order", "loinc", "test"}:
        return "PIN"
    # hospital IDs: values match a learned MRN shape / digit core, or an ID-ish key with ID-shaped values
    if kb is not None and not ktoks & NOT_ID_KEY:
        rx = kb.mrn_regex()

        def known_id(v: str) -> bool:
            t = norm_digits(v)
            if rx is not None and rx.fullmatch(t):
                return True
            return any(c in kb.digit_ids for c in re.findall(r"\d{5,}", t))
        learned = share(known_id)
        if learned >= 0.5:
            return "MRN"
        if ktoks & ID_KEY and share(lambda v: ID_SHAPE.fullmatch(v) is not None and re.search(r"[A-Za-z]", v)) >= 0.8:
            return "MRN"
    if share(lambda v: REL_START.match(v) is not None) >= 0.6:
        return "RELATIVE"
    if share(lambda v: ADDR_WORDS.search(v) is not None and ("," in v or len(v.split()) >= 4)) >= 0.5:
        return "ADDRESS"
    # dates: birth dates sit decades in the past
    years = []
    for v in vals:
        m = DATE_RX.search(norm_digits(v))
        if m:
            years.append(int(m.group(1) or m.group(2)))
    if len(years) >= 0.6 * n and years and statistics.median(years) <= 2012:
        return "DOB"
    if ktoks & AGE_KEY and share(lambda v: re.fullmatch(r"-?\d{1,3}(?:\s*(?:y|yrs?|years?|वर्ष|साल))?", norm_digits(v).lower()) is not None) >= 0.8:
        return "AGE"
    # person names / villages, using what was learned from labelled fields
    shaped = share(lambda v: NAME_SHAPE.match(v) is not None and not ORG.search(v) and not v.lower().startswith("dr"))
    if shaped >= 0.6 and kb is not None:
        toks = [t.lower() for v in vals for t in re.findall(r"[A-Za-zऀ-ॿ]+", v)]
        if toks:
            name_hits = sum(1 for t in toks if kb.tokens.get(t) in ("NAME", "RELATIVE")) / len(toks)
            vil_hits = sum(1 for t in toks if kb.tokens.get(t) == "VILLAGE") / len(toks)
            admin_hits = sum(1 for t in toks if t in kb.admin) / len(toks)
            distinct = len(set(vals)) / n
            multi = share(lambda v: len(v.split()) >= 2)
            if admin_hits >= 0.3:
                return None
            if vil_hits >= 0.4 and vil_hits > name_hits:
                return "VILLAGE"
            if name_hits >= 0.3 or (distinct >= 0.6 and multi >= 0.5 and n >= 5):
                return "RELATIVE" if ktoks & REL_KEY else "NAME"
    return None


def csv_categories(header: list, body: list, kb: Knowledge | None) -> list:
    from .fields import classify_key
    cats = []
    for j, h in enumerate(header):
        cat = classify_key(h)
        if cat is None:
            cat = sniff([r[j] for r in body if j < len(r)], h, kb)
        cats.append(cat)
    return cats


def _ext(node: dict, k: str) -> str:
    from .fields import classify_key
    if k.startswith("value") and isinstance(node.get("url"), str):
        tail = node["url"].rstrip("/").rsplit("/", 1)[-1]
        if classify_key(tail) is not None:
            return tail
    return k


def json_map(data, kb: Knowledge | None) -> dict:
    """path (keys only) -> sniffed category, for leaves the vocabulary does not recognise."""
    groups: dict = {}

    def walk(node, path, rt):
        if isinstance(node, dict):
            if isinstance(node.get("resourceType"), str):
                rt = node["resourceType"]
            for k, v in node.items():
                walk(v, path + (_ext(node, k),), rt)
        elif isinstance(node, list):
            for v in node:
                walk(v, path, rt)
        elif node is not None and path and classify_path(path, rt) is None:
            groups.setdefault((path, rt), []).append(node)

    walk(data, (), None)
    out = {}
    for (path, rt), vals in groups.items():
        if rt is not None:            # FHIR resources: structure is standard, keep the vocabulary rules
            continue
        cat = sniff(vals, str(path[-1]), kb)
        if cat:
            out[path] = cat
    return out


def path_cat(path: tuple, rt=None) -> str | None:
    c = classify_path(path, rt)
    if c is None and CURRENT:
        c = CURRENT.get(path)
    return c
