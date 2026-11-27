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
# a phone after a word that merely ends in a digit ("SpO2 98...", "base64 98...") is still a phone
PHONE_BEFORE = (r"(?<!\d)(?<!\d[\-./_])(?<![^A-Za-z0-9]\d[ \t\xa0])(?<!^\d[ \t\xa0])"
                r"(?<![^A-Za-z]\d\d[ \t\xa0])(?<!^\d\d[ \t\xa0])")
NOT_DIGIT_AFTER = r"(?![ \t \-./_]?\d)"

RX = {
    "EMAIL": re.compile(r"(?<![\w.+-])[\w.+-]+@[A-Za-z0-9-]+(?:\.[A-Za-z0-9.-]+)?", re.UNICODE),  # start of a token only: linear on long runs
    "ABHA": re.compile(NOT_DIGIT_BEFORE + r"\d{2}[ \t-]?\d{4}[ \t-]?\d{4}[ \t-]?\d{4}" + NOT_DIGIT_AFTER),
    "AADHAAR": re.compile(NOT_DIGIT_BEFORE + r"[2-9]\d{3}[ \t-]?\d{4}[ \t-]?\d{4}" + NOT_DIGIT_AFTER),
    "AADHAAR_MASKED": re.compile(r"(?i)(?<![\w])[x*•]{4}[ \t-]?[x*•]{4}[ \t-]?\d{4}(?!\d)"),
    # a mobile (6-9 first) with or without +91 / 0; any 10 digits after an explicit "+91" (landlines,
    # placeholder or test numbers written in international form are still phone numbers)
    "PHONE": re.compile(PHONE_BEFORE + r"(?:(?:\+\s?91[ \t-]?|91[ \t-]|0)?[6-9](?:[ \t-]?\d){9}"
                        r"|\+\s?91[ \t-]?\d(?:[ \t-]?\d){9})" + NOT_DIGIT_AFTER),
    "PHONE_MASKED": re.compile(r"(?<!\w)[6-9]\d[xX*]{6}\d{2}(?!\w)"),
    "PAN": re.compile(r"(?<![A-Za-z0-9])[A-Z]{5}\d{4}[A-Z](?![A-Za-z0-9])"),
    "INSURANCE": re.compile(r"(?i)(?<![A-Za-z0-9])(?:PMJAY|PM-JAY|AB-?PMJAY)[ \t-]?[A-Z]{2}[ \t-]?\d{6,14}(?!\d)"
                            r"|(?<![A-Za-z0-9])POL[\s/-]?\d{1,4}[\s/-]\d{5,12}(?!\d)"),
    # planted canary tokens and well-known credential shapes: never released, whatever the field
    "SECRET": re.compile(r"(?i)(?<![A-Za-z0-9])CANARY[-_][A-Z0-9][A-Z0-9_-]{3,}"
                         r"|(?<![A-Za-z0-9])(?:sk|pk|rk)[-_](?:live|test|prod)[-_][A-Za-z0-9]{12,}"
                         r"|(?<![A-Za-z0-9])(?:AKIA|ASIA)[0-9A-Z]{16}(?![A-Za-z0-9])"
                         r"|(?<![A-Za-z0-9])gh[pousr]_[A-Za-z0-9]{30,}"
                         r"|(?<![A-Za-z0-9])xox[abprs]-[A-Za-z0-9-]{10,}"
                         r"|(?<![A-Za-z0-9_-])eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}"),
}
# label-anchored detectors: (label regex, value regex, kind)
LABELLED = [
    (r"(?i)(?:D\.?\s?O\.?\s?B\.?|Date\s+of\s+Birth|Birth\s*Date|Janm\s*Tithi|जन्म\s*तिथि|जन्मतिथि)\s*[:\-]?\s*",
     r"\d{1,4}[/\-.]\d{1,2}[/\-.]\d{1,4}", "DOB"),
    (r"(?i)(?:\bPIN(?:\s*Code)?|Pincode|Zip|पिन(?:\s*कोड)?)\s*[:\-.]?\s*", r"\d{6}(?!\d)", "PIN"),
    (r"(?i)(?:\bUHID|\bIPD\s*No|\bIP\s*No|\bMRN|\bReg(?:istration)?\.?\s*No|\bAdm(?:ission)?\.?\s*No|"
     r"\bPatient\s*ID|\bCR\s*No|\bOPD\s*No|पंजीकरण\s*(?:सं|संख्या)|आईपीडी\s*(?:सं|संख्या|नं)|ओपीडी\s*(?:सं|संख्या|नं))\.?\s*[:#\-]?\s*",
     r"(?=[A-Z0-9/\-]*\d{4})[A-Z]{0,6}[/\-]?[A-Z0-9][A-Z0-9/\-]{3,}|(?=[A-Z0-9\-]*\d)[A-Z][A-Z0-9]*(?:-[A-Z0-9]+){2,}", "MRN"),
    (r"(?i)(?<![A-Za-z])(?:password|passwd|pwd|passcode|passphrase|otp|api[_ -]?key|access[_ -]?token|"
     r"auth[_ -]?token|refresh[_ -]?token|client[_ -]?secret|secret[_ -]?key|bearer)\s*[:=]\s*[\"']?",
     r"[^\s\"',;]{3,}", "SECRET"),
    (r"(?i)(?:Policy\s*(?:No\.?|Number|#)|Member\s*ID|Card\s*No\.?|Insurance\s*(?:ID|No\.?|Number|#))\s*[:\-]?\s*", r"[A-Z0-9][A-Z0-9/\-]{4,}", "INSURANCE"),
]
LABELLED_RX = [(re.compile(lab + "(" + val + ")"), kind) for lab, val, kind in LABELLED]
# "Distt. Rae Bareli - 229678": a PIN at the end of an address
PIN_TAIL = re.compile(r"(?<=[A-Za-z\u0900-\u097F\.]\s[-–]\s)\d{6}(?!\d)|(?<=[A-Za-z\u0900-\u097F],\s)\d{6}(?!\d)")


_RATIO = re.compile(r"\d{1,3}(?:/\d{1,3})+")
_LETTER = re.compile(r"[A-Za-z\u0900-\u097F]")

# generic name parts: never identifying on their own, so never redacted as a single token
GENERIC_TOKENS = {"kumar", "kumari", "devi", "singh", "kaur", "bano", "begum", "khatoon", "khatun", "bai", "lal", "ram",
                  "prasad", "chand", "nath", "md", "mohd", "mohammad", "mohammed", "sri", "shri", "smt", "ji", "das"}
REL_PREFIX = re.compile(r"^\s*(?:[SDWC]\s?/\s?[Oo]|पुत्र|पुत्री|पत्नी)\.?\s*", re.I)


WORD_RUN = re.compile(r"[A-Za-z\u0900-\u097F]+")
DIGIT_RUN = re.compile(r"\d(?:[ \t \-./_]?\d){4,}")   # same digit-run pattern as before, compiled once


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
        if "-" in t:                                   # hyphenated names: "Kenzie-Leigh" -> kenzie, leigh
            for part in t.split("-"):
                if part:
                    self.add_token(part, kind)
            return
        if len(t) < 3 or len(t) > 25 or re.search(r"[^a-z\u0900-\u097F]", t) or t in NOT_NAME or t in DEV_STOP \
                or t in GENERIC_TOKENS:
            return
        old = self.tokens.get(t)
        if old == kind or old == "NAME" or (old == "RELATIVE" and kind == "VILLAGE"):
            return
        self.tokens[t] = kind
        self._tok_rx = None

    def exact_candidates(self, low: str) -> list:
        """The learned exact surfaces (emails, PAN, policy numbers) that occur in `low`, in insertion order.
        Same result as testing every surface, via an index on each surface's first 12 characters (emails
        share long prefixes such as "patient", so short keys would not narrow anything down)."""
        if getattr(self, "_ex_n", -1) != len(self.exact):
            idx: dict = {}
            for n, surf in enumerate(self.exact):
                if surf:
                    idx.setdefault(surf[:12], []).append((n, surf))
            self._ex_idx, self._ex_n = idx, len(self.exact)
            self._ex_lens = sorted({len(k) for k in idx})
        idx, lens, hits = self._ex_idx, self._ex_lens, {}
        for i in range(len(low) - lens[0] + 1 if lens else 0):
            for k in lens:
                for n, surf in idx.get(low[i:i + k], ()):
                    if n not in hits and low.startswith(surf, i):
                        hits[n] = surf
        return [(hits[n], self.exact[hits[n]]) for n in sorted(hits)]

    def finalize(self) -> None:
        """After pass 1: tehsil and district names are kept for utility, so drop them as tokens."""
        for a in self.admin:
            self.tokens.pop(a, None)
        self._tok_rx = None

    def token_rx(self):
        # Tokens hold letters only, and a match must not touch another letter on either side, so a token
        # can only ever match a whole run of letters. Scanning runs and looking each up in the token set
        # finds exactly the same matches as one giant alternation, in linear time.
        return WORD_RUN if self.tokens else None

    def redact_tokens(self, text: str, protected: list) -> tuple:
        if not self.tokens:
            return text, 0
        out, last, n = [], 0, 0
        runs = list(WORD_RUN.finditer(text))
        for idx, m in enumerate(runs):
            w = m.group()
            if w.lower() not in self.tokens:
                continue
            s, e = m.span()
            if w.isascii() and w.isupper() and len(w) > 1 and self._caps_name(text, runs, idx):
                w = w.title()          # "OKKES REILLY": a run of learned name words, not an acronym like "ASHA"
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

    def redact_ocr_variants(self, text: str) -> tuple:
        """OCR misreads one letter of a first name ("Ira Kaur" read as "fra Kaur"). The surname is then a
        common one (Kaur, Singh, Devi) that is never redacted on its own, so the name would survive. A word
        one letter away from a learned first name, followed by the surname learned with it, is that name."""
        if getattr(self, "_ocr_n", -1) != len(self.names):
            idx: dict = {}
            for name in self.names:
                toks = name.lower().split()
                if len(toks) == 2 and toks[1] in GENERIC_TOKENS and len(toks[0]) >= 3 and toks[0].isalpha():
                    idx.setdefault(toks[1], set()).add(toks[0])
            self._ocr_idx, self._ocr_n = idx, len(self.names)
        idx = self._ocr_idx
        if not idx:
            return text, 0
        out, last, n = [], 0, 0
        runs = list(WORD_RUN.finditer(text))
        for j in range(1, len(runs)):
            a, b = runs[j - 1], runs[j]
            firsts = idx.get(b.group().lower())
            if not firsts or a.start() < last or not re.fullmatch(r"[ \t]{1,2}", text[a.end():b.start()]):
                continue
            w = a.group().lower()
            if not w.isascii() or w in firsts or not any(_one_edit(w, f) for f in firsts):
                continue
            if a.start() > 0 and text[a.start() - 1] == "[":
                continue
            if _is_doctor(text, a.start()):
                continue
            out.append(text[last:a.start()])
            out.append("[NAME]")
            last = b.end()
            n += 1
        out.append(text[last:])
        return "".join(out), n

    def _caps_name(self, text: str, runs: list, idx: int) -> bool:
        """True when an ALL-CAPS word touches another learned name word (spaces or a hyphen between)."""
        for j in (idx - 1, idx + 1):
            if 0 <= j < len(runs):
                a, b = (runs[j].end(), runs[idx].start()) if j < idx else (runs[idx].end(), runs[j].start())
                if re.fullmatch(r" {1,2}|-", text[a:b]) and runs[j].group().lower() in self.tokens:
                    return True
        return False

    def name_rx(self):
        if self._name_rx is None and self.names:
            alts = sorted(self.names, key=len, reverse=True)
            body = "|".join(re.escape(a).replace("\\ ", r"[\s_]+") for a in alts)
            self._name_rx = re.compile(r"(?<![A-Za-z\u0900-\u097F])(?:" + body + r")(?![A-Za-z\u0900-\u097F])", re.I)
        return self._name_rx

    def _name_index(self):
        """Learned full names grouped by first character, in the same order the alternation tried them."""
        if getattr(self, "_nidx_n", -1) != len(self.names):
            idx: dict = {}
            for name in sorted(self.names, key=len, reverse=True):
                toks = name.split(" ")
                if name and all(toks):
                    idx.setdefault(name[0], []).append((name, toks))
            self._nidx, self._nidx_n = idx, len(self.names)
            first = "".join(sorted(idx))
            self._nstart = re.compile(r"(?<![A-Za-z\u0900-\u097F])[" + re.escape(first) + "]") if first else None
        return self._nidx, self._nstart

    def redact_names(self, text: str) -> tuple:
        """Every learned full name as a whole word sequence (case-insensitive, spaces or underscores between
        words). Same matches as the single alternation of all names (longest first), found by trying only
        the names that start with the letter at each word start: fast with thousands of patients."""
        if not self.names:
            return text, 0
        low = text.lower()
        if len(low) != len(text):                  # rare characters change length when lowered
            return self._redact_names_rx(text)
        idx, start = self._name_index()
        if start is None:
            return text, 0
        out, last, n, pos = [], 0, 0, 0
        L = len(low)
        while True:
            m = start.search(low, pos)
            if m is None:
                break
            i = m.start()
            end = -1
            for name, toks in idx.get(low[i], ()):
                j = i
                ok = True
                for k, tok in enumerate(toks):
                    if not low.startswith(tok, j):
                        ok = False
                        break
                    j += len(tok)
                    if k < len(toks) - 1:
                        g = j
                        while j < L and (low[j] == "_" or low[j].isspace()):
                            j += 1
                        if j == g:
                            ok = False
                            break
                if ok and (j == L or not _LETTER.match(low[j])):
                    end = j
                    break
            if end < 0:
                pos = i + 1
                continue
            if _is_doctor(text, i):
                pos = end
                continue
            kind = self.names.get(re.sub(r"[\s_]+", " ", text[i:end]).lower(), "NAME")
            out.append(text[last:i])
            out.append("[RELATIVE]" if kind == "RELATIVE" else "[NAME]")
            last = pos = end
            n += 1
        out.append(text[last:])
        return "".join(out), n

    def _redact_names_rx(self, text: str) -> tuple:
        rx = self.name_rx()
        if rx is None:
            return text, 0
        n = 0

        def rep(m):
            nonlocal n
            if _is_doctor(text, m.start()):
                return m.group()
            n += 1
            kind = self.names.get(re.sub(r"[\s_]+", " ", m.group()).lower(), "NAME")
            return "[RELATIVE]" if kind == "RELATIVE" else "[NAME]"
        return rx.sub(rep, text), n

    def long_ids(self) -> tuple:
        """Learned identifiers of 6+ digits as a set, plus their distinct lengths (cached until the set grows)."""
        if getattr(self, "_ids6_n", -1) != len(self.digit_ids):
            ids6 = {c for c in self.digit_ids if len(c) >= 6}
            self._ids6, self._lens6, self._ids6_n = ids6, sorted({len(c) for c in ids6}), len(self.digit_ids)
        return self._ids6, self._lens6

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
    for kind in ("SECRET", "EMAIL", "INSURANCE", "ABHA", "AADHAAR_MASKED", "AADHAAR", "PAN", "PHONE_MASKED", "PHONE"):
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
            ids6, lens6 = kb.long_ids()
            for m in DIGIT_RUN.finditer(t):
                if _RATIO.fullmatch(m.group()):      # "130/75" (BP), "1/2": a reading, not an identifier
                    continue
                d = re.sub(r"\D", "", m.group())
                if d in kb.digit_ids or d in kb.pins or any(d[-k:] in ids6 for k in lens6 if k <= len(d)):
                    found.append((m.start(), m.end(), "ID"))
                else:
                    hit = next((d[a:a + k] for k in reversed(lens6) for a in range(len(d) - k + 1)
                                if d[a:a + k] in ids6), None)
                    if hit is not None:
                        i = t.find(hit, m.start(), m.end())
                        if i >= 0:
                            found.append((i, i + len(hit), "ID"))
        if kb.exact:
            low = t.lower()
            for surf, kind in kb.exact_candidates(low):
                start = 0
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
       "PIN": "[PIN]", "NAME": "[NAME]", "RELATIVE": "[RELATIVE]", "ADDRESS": "[ADDRESS]", "SECRET": "[SECRET]"}


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


_DR_PREFIX = re.compile(r"(?:\bDr\.?|\bDoctor|डॉ\.?|डा\.|டாக்டர்)\s*$", re.I)


def _is_doctor(text: str, start: int) -> bool:
    """A name right after a doctor title is the treating doctor, a clinical fact, even when the same
    name was also learned as a patient alias ("Dr. A. Mehta" next to a patient called "A. Mehta")."""
    return bool(_DR_PREFIX.search(text[max(0, start - 12):start]))


def _one_edit(a: str, b: str) -> bool:
    """True when a and b differ by exactly one substitution, insertion or deletion."""
    if abs(len(a) - len(b)) > 1 or a == b:
        return False
    if len(a) == len(b):
        return sum(x != y for x, y in zip(a, b)) == 1
    if len(a) > len(b):
        a, b = b, a
    i = 0
    while i < len(a) and a[i] == b[i]:
        i += 1
    return a[i:] == b[i + 1:]
