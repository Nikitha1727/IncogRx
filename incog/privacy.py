"""Phase 4: quasi-identifier handling beyond direct identifiers.

* Rare diagnoses (held by <= rare_condition_max_patients patients in this release) are
  generalised to their ICD-10 chapter, in codes and in the matching description text,
  because a rare condition next to an age band and a district can single a person out.
* Exact ages written in free text ("46 Yrs/M", "Age: 52", "आयु: 65 वर्ष") become the
  same 5-year bands used for structured age fields."""
from __future__ import annotations

import re

from .config import POLICY
from .detect import norm_digits

ICD_RX = re.compile(r"(?<![A-Za-z0-9\-/])([A-TV-Z]\d{2}(?:\.\d{1,2})?)(?![A-Za-z0-9\-/])")
DISPLAY_CODE_RX = re.compile(r"([A-Za-z\u0900-\u097F][^;:()\n\[\]]{2,80}?)\s*\(([A-TV-Z]\d{2}(?:\.\d{1,2})?)\)")

CHAPTERS = [
    ("A00", "B99", "Certain infectious and parasitic diseases"), ("C00", "D48", "Neoplasms"),
    ("D50", "D89", "Diseases of the blood and immune mechanism"),
    ("E00", "E90", "Endocrine, nutritional and metabolic diseases"), ("F00", "F99", "Mental and behavioural disorders"),
    ("G00", "G99", "Diseases of the nervous system"), ("H00", "H59", "Diseases of the eye and adnexa"),
    ("H60", "H95", "Diseases of the ear and mastoid process"), ("I00", "I99", "Diseases of the circulatory system"),
    ("J00", "J99", "Diseases of the respiratory system"), ("K00", "K93", "Diseases of the digestive system"),
    ("L00", "L99", "Diseases of the skin and subcutaneous tissue"),
    ("M00", "M99", "Diseases of the musculoskeletal system"), ("N00", "N99", "Diseases of the genitourinary system"),
    ("O00", "O99", "Pregnancy, childbirth and the puerperium"), ("P00", "P96", "Perinatal conditions"),
    ("Q00", "Q99", "Congenital malformations"), ("R00", "R99", "Symptoms and abnormal findings"),
    ("S00", "T98", "Injury and poisoning"), ("V01", "Y98", "External causes"), ("Z00", "Z99", "Health service factors"),
]


def chapter(code: str) -> tuple:
    c3 = code[:3]
    for lo, hi, name in CHAPTERS:
        if lo <= c3 <= hi:
            return f"{lo}-{hi}", name
    return "ICD-10", "Other condition"


def codes_in(value) -> set:
    if isinstance(value, str):
        return set(ICD_RX.findall(value))
    return set()


class RareConditions:
    def __init__(self):
        self.displays: dict = {}        # code -> set of description strings seen with it
        self.patients: dict = {}        # code -> set of patient keys
        self.rare_codes: dict = {}
        self.rare_text: list = []
        self._rx = None

    def learn_text(self, s: str) -> None:
        for m in DISPLAY_CODE_RX.finditer(s):
            disp = m.group(1).strip(" ,.-")
            disp = re.split(r"(?i)\b(?:for|with|of|on|treated|diagnosis|dx|निदान)\s*[:\-]?\s+", disp)[-1].strip()
            if 3 <= len(disp) <= 80:
                self.displays.setdefault(m.group(2), set()).add(disp)

    def learn_pair(self, code, display) -> None:
        if isinstance(code, str) and ICD_RX.fullmatch(code.strip()) and isinstance(display, str) and 3 <= len(display) <= 80:
            self.displays.setdefault(code.strip(), set()).add(display.strip())

    def count(self, code: str, patient_key: str) -> None:
        self.patients.setdefault(code, set()).add(patient_key)

    def finalize(self) -> None:
        k = int(POLICY.get("rare_condition_max_patients", 3))
        self.rare_codes = {c: chapter(c) for c, ps in self.patients.items() if len(ps) <= k}
        pairs = []
        for c, (rng, name) in self.rare_codes.items():
            for d in self.displays.get(c, ()):
                pairs.append((d, name))
        pairs.sort(key=lambda x: -len(x[0]))
        self.rare_text = pairs
        alts = [re.escape(d) for d, _ in pairs] + [re.escape(c) for c in sorted(self.rare_codes, key=len, reverse=True)]
        if alts:
            self._rx = re.compile(r"(?<![A-Za-z0-9\u0900-\u097F])(?:" + "|".join(alts) + r")(?![A-Za-z0-9\u0900-\u097F])",
                                  re.I)
        self._map = {d.lower(): n for d, n in pairs}
        self._map.update({c.lower(): r for c, (r, _) in self.rare_codes.items()})

    def apply(self, text: str) -> str:
        if self._rx is None or not isinstance(text, str):
            return text
        return self._rx.sub(lambda m: self._map.get(m.group().lower(), m.group()), text)


# ----------------------------------------------------------------------------- ages in free text
def _band(n: int) -> str:
    top = int(POLICY.get("age_top_code", 80))
    if n >= top:
        return f"{top}+"
    w = int(POLICY.get("age_band_years", 5))
    lo = (n // w) * w
    return f"{lo}-{lo + w - 1}"


AGE_LABEL = re.compile(r"((?i:\bAge(?:\s*/\s*(?:Sex|Gender))?|आयु|उम्र|\bUmar|\bUmr)\s*[:\-]?\s*)([0-9]{1,3})(?![0-9\-])")
AGE_SEX = re.compile(r"(?<![0-9/.\-])([0-9]{1,3})(\s*(?:[Yy](?:rs?|ears?|RS)?\.?|वर्ष|साल)\s*[/,]\s*(?:M|F|(?i:male|female|fem\w*)|महिला|पुरुष)(?![A-Za-z]))")
AGE_SLASH = re.compile(r"(?<![0-9/.\-:])([0-9]{1,3})(\s*/\s*(?:M|F)(?![A-Za-z]))")
AGE_YRS_ONLY = re.compile(r"(?<![0-9/.\-x×])(?<!x )(?<!X )([0-9]{1,3})(\s*(?:वर्ष|साल)(?:\s|$|[,।]))")


def band_ages(text: str) -> str:
    if not isinstance(text, str) or not text:
        return text
    t = norm_digits(text)
    edits = []
    for rx in (AGE_LABEL, AGE_SEX, AGE_SLASH, AGE_YRS_ONLY):
        for m in rx.finditer(t):
            g = 2 if rx is AGE_LABEL else 1
            n = int(m.group(g))
            if 0 <= n <= 120:
                edits.append((m.start(g), m.end(g), _band(n)))
    if not edits:
        return text
    edits.sort()
    out, last = [], 0
    for s, e, rep in edits:
        if s < last:
            continue
        out.append(text[last:s])
        out.append(rep)
        last = e
    out.append(text[last:])
    return "".join(out)
