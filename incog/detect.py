"""Pattern detectors for identifiers in free text, keys, headers and file names.

All matching runs on a digit-normalised copy (Devanagari/other Indic digits -> ASCII,
same length), so spans map 1:1 back to the original string."""
from __future__ import annotations

import re
from dataclasses import dataclass, field

_INDIC_DIGITS = {}
for base in (0x0966, 0x09E6, 0x0A66, 0x0AE6, 0x0B66, 0x0BE6, 0x0C66, 0x0CE6, 0x0D66):
    for i in range(10):
        _INDIC_DIGITS[base + i] = ord("0") + i
_INDIC_DIGITS[0xFF10] = ord("0")  # fullwidth zero (rest handled by NFKC elsewhere)


def norm_digits(s: str) -> str:
    return s.translate(_INDIC_DIGITS)


def digits_only(s: str) -> str:
    return re.sub(r"\D", "", norm_digits(s))


SEP = r"[ \t \-./_]?"
NOT_DIGIT_BEFORE = r"(?<!\d)(?<!\d[ \t \-./_])"
NOT_DIGIT_AFTER = r"(?![ \t \-./_]?\d)"

RX = {
    "EMAIL": re.compile(r"[\w.+-]+@[A-Za-z0-9-]+(?:\.[A-Za-z0-9.-]+)?", re.UNICODE),
    "ABHA": re.compile(NOT_DIGIT_BEFORE + r"\d{2}[ \t-]?\d{4}[ \t-]?\d{4}[ \t-]?\d{4}" + NOT_DIGIT_AFTER),
    "AADHAAR": re.compile(NOT_DIGIT_BEFORE + r"[2-9]\d{3}[ \t-]?\d{4}[ \t-]?\d{4}" + NOT_DIGIT_AFTER),
    "AADHAAR_MASKED": re.compile(r"(?i)(?<![\w])[x*•]{4}[ \t-]?[x*•]{4}[ \t-]?\d{4}(?!\d)"),
    "PHONE": re.compile(NOT_DIGIT_BEFORE + r"(?:\+\s?91[ \t-]?|91[ \t-]|0)?[6-9](?:[ \t-]?\d){9}" + NOT_DIGIT_AFTER),
    "PHONE_MASKED": re.compile(r"(?<!\w)[6-9]\d[xX*]{6}\d{2}(?!\w)"),
    "PAN": re.compile(r"(?<![A-Za-z0-9])[A-Z]{5}\d{4}[A-Z](?![A-Za-z0-9])"),
    "INSURANCE": re.compile(r"(?i)(?<![A-Za-z0-9])(?:PMJAY|PM-JAY|AB-?PMJAY)[ \t-]?[A-Z]{2}[ \t-]?\d{6,14}(?!\d)"
                            r"|(?<![A-Za-z0-9])POL[\s/-]?\d{1,4}[\s/-]\d{5,12}(?!\d)"),
}
# label-anchored detectors: (label regex, value regex, kind)
LABELLED = [
    (r"(?i)(?:D\.?\s?O\.?\s?B\.?|Date\s+of\s+Birth|Birth\s*Date|Janm\s*Tithi|जन्म\s*तिथि|जन्मतिथि)\s*[:\-]?\s*",
     r"\d{1,4}[/\-.]\d{1,2}[/\-.]\d{1,4}", "DOB"),
    (r"(?i)(?:\bPIN(?:\s*Code)?|Pincode|Zip|पिन(?:\s*कोड)?)\s*[:\-.]?\s*", r"\d{6}(?!\d)", "PIN"),
    (r"(?i)(?:\bUHID|\bIPD\s*No|\bIP\s*No|\bMRN|\bReg(?:istration)?\.?\s*No|\bAdm(?:ission)?\.?\s*No|"
     r"\bPatient\s*ID|\bCR\s*No|\bOPD\s*No|पंजीकरण\s*(?:सं|संख्या)|आईपीडी\s*(?:सं|संख्या|नं)|ओपीडी\s*(?:सं|संख्या|नं))\.?\s*[:#\-]?\s*",
     r"(?=[A-Z0-9/\-]*\d{4})[A-Z]{0,6}[/\-]?[A-Z0-9][A-Z0-9/\-]{3,}", "MRN"),
    (r"(?i)(?:Policy\s*(?:No\.?|Number|#)|Member\s*ID|Card\s*No\.?)\s*[:\-]?\s*", r"[A-Z0-9][A-Z0-9/\-]{4,}", "INSURANCE"),
]
LABELLED_RX = [(re.compile(lab + "(" + val + ")"), kind) for lab, val, kind in LABELLED]
# "Distt. Rae Bareli - 229678": a PIN at the end of an address
PIN_TAIL = re.compile(r"(?<=[A-Za-z\u0900-\u097F\.]\s[-–]\s)\d{6}(?!\d)|(?<=[A-Za-z\u0900-\u097F],\s)\d{6}(?!\d)")


# generic name parts: never identifying on their own, so never redacted as a single token
GENERIC_TOKENS = {"kumar", "kumari", "devi", "singh", "kaur", "bano", "begum", "khatoon", "khatun", "bai", "lal", "ram",
                  "prasad", "chand", "nath", "md", "mohd", "mohammad", "mohammed", "sri", "shri", "smt", "ji", "das"}
REL_PREFIX = re.compile(r"^\s*(?:[SDWC]\s?/\s?[Oo]|पुत्र|पुत्री|पत्नी)\.?\s*", re.I)


@dataclass
class Knowledge:
    """Identifiers learned from structured fields in pass 1, reused everywhere in pass 2."""
    digit_ids: set = field(default_factory=set)      # digit cores of phones, IDs, MRNs (>= 5 digits)
    pins: set = field(default_factory=set)
    exact: dict = field(default_factory=dict)         # lowercase surface -> kind (emails, PAN, ...)
    mrn_shapes: set = field(default_factory=set)      # learned MRN shape regex sources
    names: dict = field(default_factory=dict)         # lowercase full name -> "NAME"/"RELATIVE"
    tokens: dict = field(default_factory=dict)        # single name tokens -> "NAME"/"RELATIVE"/"VILLAGE"
    admin: set = field(default_factory=set)           # tehsil/district names (kept, never redacted)
    rare: object = None                               # privacy.RareConditions, set by the pipeline
    privacy: dict = field(default_factory=dict)       # measured residual risk (counts only)
    _mrn_rx: object = None
    _tok_rx: object = None

    _name_rx: object = None

    def add_name(self, value: str, kind: str = "NAME") -> None:
        v = re.sub(r"\s+", " ", str(value)).strip()
        v = REL_PREFIX.sub("", v).strip()
        if len(v) < 3 or len(v) > 60 or re.search(r"\d|\[", v) or len(v.split()) < 2:
            return
        for t in v.split(" "):
            self.add_token(t, kind)
        key = v.lower()
        if self.names.get(key) == "NAME":
            return
        self.names[key] = kind
        self._name_rx = None

    def add_token(self, tok: str, kind: str = "NAME") -> None:
        from .textner import NOT_NAME, DEV_STOP
        t = tok.strip(" .,:;'\"()").lower()
        if len(t) < 3 or len(t) > 25 or re.search(r"[^a-z\u0900-\u097F]", t) or t in NOT_NAME or t in DEV_STOP \
                or t in GENERIC_TOKENS:
            return
        old = self.tokens.get(t)
        if old == kind or old == "NAME" or (old == "RELATIVE" and kind == "VILLAGE"):
            return
        self.tokens[t] = kind
        self._tok_rx = None

    def finalize(self) -> None:
        """After pass 1: tehsil and district names are kept for utility, so drop them as tokens."""
        for a in self.admin:
            self.tokens.pop(a, None)
        self._tok_rx = None

    def token_rx(self):
        if self._tok_rx is None and self.tokens:
            body = "|".join(re.escape(a) for a in sorted(self.tokens, key=len, reverse=True))
            self._tok_rx = re.compile(r"(?<![A-Za-z\u0900-\u097F])(?:" + body + r")(?![A-Za-z\u0900-\u097F])", re.I)
        return self._tok_rx

    def redact_tokens(self, text: str, protected: list) -> tuple:
        rx = self.token_rx()
        if rx is None:
            return text, 0
        out, last, n = [], 0, 0
        for m in rx.finditer(text):
            s, e = m.span()
            w = m.group()
            if any(a <= s < b for a, b in protected):
                continue
            if w.isascii() and w.isupper() and len(w) > 1:      # ASHA, ward codes: not a person mention
                continue
            if s > 0 and text[s - 1] == "[":
                continue
            kind = self.tokens.get(w.lower(), "NAME")
            out.append(text[last:s])
            out.append({"RELATIVE": "[RELATIVE]", "VILLAGE": "[VILLAGE]"}.get(kind, "[NAME]"))
            last = e
            n += 1
        out.append(text[last:])
        return "".join(out), n

    def name_rx(self):
        if self._name_rx is None and self.names:
            alts = sorted(self.names, key=len, reverse=True)
            body = "|".join(re.escape(a).replace("\\ ", r"[\s_]+") for a in alts)
            self._name_rx = re.compile(r"(?<![A-Za-z\u0900-\u097F])(?:" + body + r")(?![A-Za-z\u0900-\u097F])", re.I)
        return self._name_rx

    def redact_names(self, text: str) -> tuple:
        rx = self.name_rx()
        if rx is None:
            return text, 0
        n = 0

        def rep(m):
            nonlocal n
            n += 1
            kind = self.names.get(re.sub(r"[\s_]+", " ", m.group()).lower(), "NAME")
            return "[RELATIVE]" if kind == "RELATIVE" else "[NAME]"
        return rx.sub(rep, text), n

    def add_digits(self, value: str, minimum: int = 5) -> None:
        d = digits_only(value)
        if len(d) >= minimum:
            self.digit_ids.add(d)
            if len(d) > 10 and d.startswith("91") and len(d) == 12:
                self.digit_ids.add(d[2:])

    def add_mrn(self, value: str) -> None:
        value = value.strip()
        if not value or len(value) > 40:
            return
        core = re.findall(r"\d{5,}", norm_digits(value))
        for c in core:
            self.digit_ids.add(c)
        shape = mrn_shape(value)
        if shape:
            self.mrn_shapes.add(shape)
            self._mrn_rx = None

    def mrn_regex(self):
        if self._mrn_rx is None and self.mrn_shapes:
            self._mrn_rx = re.compile("|".join(f"(?:{s})" for s in sorted(self.mrn_shapes)), re.I)
        return self._mrn_rx


def mrn_shape(value: str) -> str | None:
    """'SNJ/26/064127' -> 'SNJ[\\s\\-./_]?\\d{2}[\\s\\-./_]?\\d{6}' (letters literal, digits by count,
    any separator), so the same ID is found in text and in file names like SNJ-26-064127."""
    v = norm_digits(value.strip())
    if not re.search(r"\d{4,}", v) or not re.fullmatch(r"[A-Za-z0-9/\-_. ]+", v):
        return None
    parts = re.findall(r"[A-Za-z]+|\d+|[/\-_. ]+", v)
    out = []
    for p in parts:
        if p.isdigit():
            out.append(r"\d{%d}" % len(p))
        elif p.isalpha():
            out.append(re.escape(p))
        else:
            out.append(r"[ \t \-./_]?")
    src = "".join(out)
    return r"(?<![A-Za-z0-9])" + src + r"(?!\d)"


def find_spans(text: str, kb: Knowledge | None = None) -> list:
    """Return non-overlapping (start, end, kind) spans of identifiers in text."""
    if not text:
        return []
    t = norm_digits(text)
    found = []
    for kind in ("EMAIL", "INSURANCE", "ABHA", "AADHAAR_MASKED", "AADHAAR", "PAN", "PHONE_MASKED", "PHONE"):
        for m in RX[kind].finditer(t):
            found.append((m.start(), m.end(), kind if kind != "PHONE_MASKED" else "PHONE"))
    for rx, kind in LABELLED_RX:
        for m in rx.finditer(t):
            found.append((m.start(1), m.end(1), kind))
    for m in PIN_TAIL.finditer(t):
        found.append((m.start(), m.end(), "PIN"))
    if kb is not None:
        rx = kb.mrn_regex()
        if rx is not None:
            for m in rx.finditer(t):
                found.append((m.start(), m.end(), "MRN"))
        if kb.digit_ids or kb.pins:
            # any digit run (with separators) whose digits equal or end with a learned identifier
            for m in re.finditer(r"\d(?:[ \t \-./_]?\d){4,}", t):
                d = re.sub(r"\D", "", m.group())
                if d in kb.digit_ids or d in kb.pins or any(len(c) >= 6 and d.endswith(c) for c in kb.digit_ids):
                    found.append((m.start(), m.end(), "ID"))
                else:
                    for c in kb.digit_ids:
                        if len(c) >= 6 and c in d:
                            i = t.find(c, m.start(), m.end())
                            if i >= 0:
                                found.append((i, i + len(c), "ID"))
                            break
        for surf, kind in kb.exact.items():
            if surf and surf in t.lower():
                start = 0
                low = t.lower()
                while True:
                    i = low.find(surf, start)
                    if i < 0:
                        break
                    found.append((i, i + len(surf), kind))
                    start = i + len(surf)
    return _merge(found)


def _merge(spans: list) -> list:
    spans.sort(key=lambda s: (s[0], -(s[1] - s[0])))
    out = []
    for s in spans:
        if out and s[0] < out[-1][1]:
            if s[1] > out[-1][1]:
                out[-1] = (out[-1][0], s[1], out[-1][2])
            continue
        out.append(s)
    return out


TAG = {"MRN": "[MRN]", "ID": "[ID]", "PHONE": "[PHONE]", "AADHAAR": "[AADHAAR]", "AADHAAR_MASKED": "[AADHAAR]",
       "ABHA": "[ABHA]", "PAN": "[PAN]", "EMAIL": "[EMAIL]", "INSURANCE": "[INSURANCE_ID]", "DOB": "[DOB]",
       "PIN": "[PIN]", "NAME": "[NAME]", "RELATIVE": "[RELATIVE]", "ADDRESS": "[ADDRESS]"}


def redact(text: str, spans: list) -> tuple:
    if not spans:
        return text, 0
    out, last = [], 0
    for s, e, kind in spans:
        out.append(text[last:s])
        out.append(TAG.get(kind, "[REDACTED]"))
        last = e
    out.append(text[last:])
    return "".join(out), len(spans)
