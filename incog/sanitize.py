"""Value-level sanitisers, one per privacy category."""
from __future__ import annotations

import re

from .config import POLICY
from . import textner
from .detect import TAG, Knowledge, find_spans, norm_digits, redact

REL_MARKER = re.compile(r"^\s*((?:[SDWCH]\s?/\s?[Oo]|[SDW]/O|C/O|पुत्र|पुत्री|पत्नी|पति)\.?\s*(?:of)?)\s*", re.I)
ADDR_KEEP = re.compile(r"(?i)^\s*(?:Tehsil|Teh\.?|Tahsil|Distt?\.?|District|Dist\.?|तहसील|जिला|जि\.)\s")
PERSON_TITLE = re.compile(r"^\s*(?:Dr|Prof)\.?\s", re.I)


class Stats:
    identifiers = 0
    generalized = 0


def age_band(age: int) -> str:
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
    return text


def sanitize(cat: str | None, value, ctx: dict, kb: Knowledge | None):
    if value is None or isinstance(value, bool) or value == "":
        return value
    if cat in ("KEEP",):
        return clean_text(value, kb) if isinstance(value, str) else value
    if cat == "NAME":
        if isinstance(value, str) and PERSON_TITLE.match(value):
            return value
        Stats.identifiers += 1
        return ctx.get("pseudonym") or TAG["NAME"]
    if cat == "RELATIVE":
        return relative_value(value)
    if cat in ("MRN",):
        Stats.identifiers += 1
        return ctx.get("pseudonym") or TAG["MRN"]
    if cat in ("PHONE", "AADHAAR", "ABHA", "PAN", "EMAIL", "INSURANCE"):
        Stats.identifiers += 1
        return TAG.get(cat, "[ID]") if not (cat == "AADHAAR" and False) else value
    if cat in ("HOUSE", "LANDMARK"):
        Stats.identifiers += 1
        return f"[{cat}]"
    if cat == "ADDRESS":
        return generalize_address(value, kb)
    if cat == "VILLAGE":
        Stats.generalized += 1
        return ctx.get("tehsil") or ctx.get("district") or "[VILLAGE]"
    if cat == "PIN":
        return generalize_pin(value)
    if cat == "DOB":
        return generalize_dob(value)
    if cat == "AGE":
        return generalize_age(value)
    return clean_text(value, kb) if isinstance(value, str) else value
