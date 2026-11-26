"""Value-level sanitisers, one per privacy category."""
from __future__ import annotations

import base64
import binascii
import re
from collections import Counter

from .config import POLICY
from . import dates, privacy, textner
from .detect import TAG, Knowledge, find_spans, norm_digits, redact

REL_MARKER = re.compile(r"^\s*((?:[SDWCH]\s?/\s?[Oo]|[SDW]/O|C/O|पुत्र|पुत्री|पत्नी|पति)\.?\s*(?:of)?)\s*", re.I)
_KEEP_TEHSIL = str(POLICY.get("keep_tehsil", "false")).lower() == "true"
ADDR_KEEP = re.compile(r"(?i)^\s*(?:" + (r"Tehsil|Teh\.?|Tahsil|तहसील|" if _KEEP_TEHSIL else "") +
                       r"Distt?\.?|District|Dist\.?|जिला|जि\.)\s")
DOB_MODE = str(POLICY.get("dob", "suppress")).lower()
PERSON_TITLE = re.compile(r"^\s*(?:Dr|Prof)\.?\s", re.I)


class Stats:
    identifiers = 0
    generalized = 0
    entities: Counter = Counter()   # removed identifiers by type (report.json "entities")


ENTITY = {"NAME": "PATIENT_NAME", "INSURANCE": "INSURANCE_ID"}
_TAG_RX = re.compile(r"\[(NAME|RELATIVE|PHONE|AADHAAR|ABHA|PAN|EMAIL|MRN|ID|INSURANCE_ID|DOB|PIN|ADDRESS|HOUSE|"
                     r"LOCALITY|LANDMARK|VILLAGE|TEHSIL)\]")


# ----------------------------------------------------------------------------- hardening helpers
# Invisible characters and full-width digits are a cheap way to slip an identifier past a pattern.
# Zero-width joiner/non-joiner are left alone: Devanagari spelling needs them.
_INVISIBLE = "\u200b\u2060\ufeff"
_NORM_TABLE = {ord(c): None for c in _INVISIBLE}
_NORM_TABLE.update({0xFF10 + i: ord("0") + i for i in range(10)})
_NORM_ANY = re.compile("[" + _INVISIBLE + "\uff10-\uff19]")


def normalize_text(value: str) -> str:
    return value.translate(_NORM_TABLE) if _NORM_ANY.search(value) else value


# A whole value that is base64 or hex of readable text (an encoded attachment) is decoded, cleaned and
# re-encoded. Hashes and binary payloads do not decode to readable text, so they are left unchanged.
_B64_RX = re.compile(r"[A-Za-z0-9+/]{24,}={0,2}")
_HEX_RX = re.compile(r"(?:[0-9a-fA-F]{2}){12,}")
_READABLE = re.compile(r"[A-Za-z\u0900-\u097F]{2,}")


def _readable(t: str) -> bool:
    return bool(t) and sum(ch.isprintable() or ch in "\n\r\t" for ch in t) >= 0.97 * len(t) \
        and _READABLE.search(t) is not None and (" " in t or ":" in t)


def _decode_blob(value: str):
    if len(value) < 24 or value.strip() != value:
        return None
    if _HEX_RX.fullmatch(value):
        try:
            t = bytes.fromhex(value).decode("utf-8")
        except ValueError:
            t = None
        if t and _readable(t):
            up = value.isupper()
            return t, (lambda c: c.encode("utf-8").hex().upper() if up else c.encode("utf-8").hex())
    if len(value) % 4 == 0 and _B64_RX.fullmatch(value):
        try:
            t = base64.b64decode(value, validate=True).decode("utf-8")
        except (binascii.Error, ValueError, UnicodeDecodeError):
            return None
        if _readable(t):
            return t, (lambda c: base64.b64encode(c.encode("utf-8")).decode("ascii"))
    return None


# Code-shaped identifiers in file names, column headers, JSON keys and path strings
# ("TEST-HDR-91", "REG-483719"). Two-part clinical codes such as ICD-10 or COVID-19 do not match.
META_ID_RX = re.compile(r"(?<![A-Za-z0-9])(?=[A-Z0-9\-]*\d)[A-Z][A-Z0-9]*(?:-[A-Z0-9]+){2,}(?![A-Za-z0-9])"
                        r"|(?<![A-Za-z0-9])[A-Z]{2,}[A-Z0-9]*-\d{4,}(?![A-Za-z0-9])")


def clean_meta(value: str, kb: Knowledge | None) -> str:
    """Clean a file name part, column header, JSON key or path segment. Underscores are read as spaces so
    "Patient_Tavishi_Menon" is seen as words; the original separator is restored afterwards."""
    if not isinstance(value, str) or not value:
        return value
    spaced = value.replace("_", " ")
    cleaned = clean_text(spaced, kb)
    cleaned, n = META_ID_RX.subn("[ID]", cleaned)
    if n:
        Stats.identifiers += n
        _ent("ID", n)
    if cleaned == spaced:
        return value
    return cleaned.replace(" ", "_") if "_" in value and " " not in value else cleaned


_PATH_RX = re.compile(r"^[^\s/\\]*(?:[/\\][^/\\\n]+)+\.[A-Za-z][A-Za-z0-9]{0,4}$")


def clean_path_value(value: str, kb: Knowledge | None) -> str | None:
    """A string value that is a file path: clean each segment. Returns None when the value is not a path."""
    if not isinstance(value, str) or "\n" in value or len(value) > 300 or not _PATH_RX.match(value.strip()):
        return None
    parts = re.split(r"([/\\])", value)
    out = []
    for p in parts:
        if p in ("/", "\\") or not p:
            out.append(p)
            continue
        stem, dot, ext = p.rpartition(".") if "." in p else (p, "", "")
        out.append(clean_meta(stem, kb) + (dot + ext if dot else ""))
    return "".join(out)


def _ent(kind: str, n: int = 1) -> None:
    Stats.entities[ENTITY.get(kind, kind)] += n


def _count_new_tags(before: str, after: str) -> None:
    """Count placeholders that this step wrote (tags already in the input are not counted again)."""
    old = Counter(_TAG_RX.findall(before))
    for k, v in Counter(_TAG_RX.findall(after)).items():
        if v > old.get(k, 0):
            _ent(k, v - old.get(k, 0))


def age_band(age: int) -> str:
    top = int(POLICY.get("age_top_code", 80))
    if age >= top:
        return f"{top}+"            # very old patients are rare: one open band hides them
    w = int(POLICY.get("age_band_years", 5))
    lo = (age // w) * w
    return f"{lo}-{lo + w - 1}"


def generalize_age(value):
    if isinstance(value, bool):
        return value
    if isinstance(value, (int, float)):
        Stats.generalized += 1
        return age_band(int(value))
    if isinstance(value, str):
        v = norm_digits(value)
        m = re.search(r"\d{1,3}", v)
        if m and 0 <= int(m.group()) <= 125:
            Stats.generalized += 1
            return value[:m.start()] + age_band(int(m.group())) + value[m.end():]
    return value


def generalize_dob(value):
    if DOB_MODE != "year":                 # a birth year pins the age to ~1 year and defeats age bands
        Stats.generalized += 1
        return "[DOB]" if value is not None else value
    if not isinstance(value, str):
        return "[DOB]" if value is not None else value
    v = norm_digits(value)
    m = re.search(r"\b(1[89]\d{2}|20\d{2})\b", v)
    Stats.generalized += 1
    return m.group(1) if m else "[DOB]"


def generalize_pin(value):
    if value is None:
        return value
    d = re.sub(r"\D", "", norm_digits(str(value)))
    Stats.generalized += 1
    return d[:3] + "***" if len(d) == 6 else "[PIN]"


def generalize_address(value: str, kb: Knowledge | None) -> str:
    """Keep only coarse administrative parts (tehsil, district); drop house, locality,
    landmark, village and PIN."""
    if not isinstance(value, str) or not value.strip():
        return value
    parts = re.split(r"[,;\n]", value)
    kept = []
    for p in parts:
        p2 = re.sub(r"\s*[-–]\s*\d{6}\s*$", "", p).strip()
        if ADDR_KEEP.match(p2 + " "):
            kept.append(p2)
    Stats.identifiers += 1
    return ", ".join(["[ADDRESS]"] + kept)


def relative_value(value):
    if not isinstance(value, str) or not value.strip():
        return value
    m = REL_MARKER.match(value)
    Stats.identifiers += 1
    return (m.group(1).strip() + " " if m else "") + TAG["RELATIVE"]


CACHE_MAX_LEN = 200     # short values repeat a lot (labels, codes, names); long notes are unique


def clean_text(value, kb: Knowledge | None):
    """Generic free-text cleaner (identifier patterns + learned identifiers + learned names).

    Once learning is finished (kb.frozen), the result for a short value depends only on the value, so it
    is computed once and reused; the report counters are replayed exactly as the first call changed them."""
    if not isinstance(value, str) or not value:
        return value
    cache = getattr(kb, "clean_cache", None) if kb is not None and getattr(kb, "frozen", False) else None
    if cache is None or len(value) > CACHE_MAX_LEN:
        return _clean_text(value, kb)
    hit = cache.get(value)
    if hit is not None:
        text, d_ids, d_gen, d_ent = hit
        Stats.identifiers += d_ids
        Stats.generalized += d_gen
        Stats.entities.update(d_ent)
        return text
    ids0, gen0, ent0 = Stats.identifiers, Stats.generalized, Counter(Stats.entities)
    text = _clean_text(value, kb)
    d_ent = Counter(Stats.entities)
    d_ent.subtract(ent0)
    cache[value] = (text, Stats.identifiers - ids0, Stats.generalized - gen0, +d_ent)
    return text


def _clean_text(value, kb: Knowledge | None):
    blob = _decode_blob(value)
    if blob is not None:
        inner, encode = blob
        cleaned = _clean_text(inner, kb)
        return value if cleaned == inner else encode(cleaned)
    value = normalize_text(value)
    text, n = textner.apply(value, lambda v: generalize_address(v, kb))
    text, m = redact(text, find_spans(text, kb))
    n += m
    if kb is not None and kb.name_rx() is not None:
        text, m = kb.redact_names(text)
        n += m
    if kb is not None and kb.token_rx() is not None:
        text, m = kb.redact_tokens(text, textner.protected_spans(text))
        n += m
    Stats.identifiers += n
    _count_new_tags(value, text)
    return text


def sanitize(cat: str | None, value, ctx: dict, kb: Knowledge | None):
    out = _sanitize(cat, value, ctx, kb)
    if isinstance(out, str) and cat in (None, "KEEP", "TEXT"):
        if ctx.get("pseudonym"):              # patient records only; reference documents stay intact
            if kb is not None and kb.rare is not None:
                out = kb.rare.apply(out)
            out = privacy.band_ages(out)
        if ctx.get("shift"):
            out = dates.shift_text(out, ctx["shift"], ctx.get("order", "dmy"))[0]
    return out


def _sanitize(cat: str | None, value, ctx: dict, kb: Knowledge | None):
    if value is None or isinstance(value, bool) or value == "":
        return value
    if cat in ("KEEP",):
        return clean_text(value, kb) if isinstance(value, str) else value
    if cat == "NAME":
        if isinstance(value, str) and PERSON_TITLE.match(value):
            return value
        Stats.identifiers += 1
        _ent("NAME")
        return ctx.get("pseudonym") or TAG["NAME"]
    if cat == "RELATIVE":
        out = relative_value(value)
        if out != value:
            _ent("RELATIVE")
        return out
    if cat in ("MRN",):
        Stats.identifiers += 1
        _ent("MRN")
        return ctx.get("pseudonym") or TAG["MRN"]
    if cat in ("PHONE", "AADHAAR", "ABHA", "PAN", "EMAIL", "INSURANCE"):
        Stats.identifiers += 1
        _ent(cat)
        return TAG.get(cat, "[ID]") if not (cat == "AADHAAR" and False) else value
    if cat in ("HOUSE", "LANDMARK"):
        Stats.identifiers += 1
        _ent(cat)
        return f"[{cat}]"
    if cat == "ADDRESS":
        out = generalize_address(value, kb)
        if out != value:
            _ent("ADDRESS")
        return out
    if cat == "VILLAGE":
        Stats.generalized += 1
        return (ctx.get("tehsil") if _KEEP_TEHSIL else None) or ctx.get("district") or "[VILLAGE]"
    if cat == "TEHSIL":
        if _KEEP_TEHSIL:
            return value
        Stats.generalized += 1
        return ctx.get("district") or "[TEHSIL]"
    if cat == "PIN":
        return generalize_pin(value)
    if cat == "DOB":
        return generalize_dob(value)
    if cat == "AGE":
        return generalize_age(value)
    return clean_text(value, kb) if isinstance(value, str) else value
