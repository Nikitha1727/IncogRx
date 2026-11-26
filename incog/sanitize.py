"""Value-level sanitisers, one per privacy category."""
from __future__ import annotations

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


def clean_text(value, kb: Knowledge | None):
    """Generic free-text cleaner (identifier patterns + learned identifiers + learned names)."""
    if not isinstance(value, str) or not value:
        return value
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
