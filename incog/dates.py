"""Phase 4: per-patient secret date shifting that keeps every date's own format.

All dates of one patient move by the same keyed offset, so intervals and lengths of stay
are exact, while a global offset cannot be recovered from a few known visit dates.
Day-first vs month-first is decided per file (a value > 12, a "(MM/DD/YYYY)" label, or
a vote from other files of the same source)."""
from __future__ import annotations

import datetime as dt
import re

from .crypto import date_shift_days
from .detect import norm_digits

MONTHS = ["january", "february", "march", "april", "may", "june", "july", "august", "september", "october",
          "november", "december"]
_MON = {m: i + 1 for i, m in enumerate(MONTHS)}
_MON.update({m[:3]: i + 1 for i, m in enumerate(MONTHS)})
_MON["sept"] = 9
MON_RX = "|".join(sorted(_MON, key=len, reverse=True))

ISO = re.compile(r"(?<![\d/.\-])(\d{4})-(\d{2})-(\d{2})(?![\d])")
NUM = re.compile(r"(?<![\d/.\-:])(\d{1,2})([/.\-])(\d{1,2})\2(\d{4}|\d{2})(?![\d/.\-])")
WORD = re.compile(rf"(?<![\d])(\d{{1,2}})(?:st|nd|rd|th)?[ \-]((?i:{MON_RX}))\.?(?:,?[ \-](\d{{4}}))?(?![A-Za-z])")
WORD2 = re.compile(rf"(?<![A-Za-z])((?i:{MON_RX}))\.?[ ](\d{{1,2}})(?:st|nd|rd|th)?,?[ ](\d{{4}})(?![\d])")
MDY_LABEL = re.compile(r"(?i)MM\s*/\s*DD|month\s*/\s*day")


def order_hint(text: str) -> str | None:
    """'dmy' / 'mdy' when the file itself decides it, else None."""
    if MDY_LABEL.search(text):
        return "mdy"
    t = norm_digits(text)
    d = m = 0
    for x in NUM.finditer(t):
        a, b = int(x.group(1)), int(x.group(3))
        if a > 12 and b <= 12:
            d += 1
        elif b > 12 and a <= 12:
            m += 1
    if d > m:
        return "dmy"
    if m > d:
        return "mdy"
    return None


STOP = {"discharge", "summary", "rx", "nursing", "notes", "note", "report", "results", "opd", "registration",
        "claims", "export", "csv", "json", "txt", "tsv", "bundle", "lab", "ds", "patients", "the", "and", "of",
        "hospital", "uhid", "mrn", "ipd", "adm", "doc", "file", "data", "name", "mrn"}


def source_tokens(rel: str, text: str) -> set:
    stem = rel.rsplit("/", 1)[-1].rsplit(".", 1)[0]
    toks = {t.lower() for t in re.findall(r"[A-Za-z]{3,}", stem)}
    first = next((ln for ln in text.splitlines() if ln.strip()), "")[:80]
    toks |= {t.lower() for t in re.findall(r"[A-Za-z]{4,}", first)}
    return {t for t in toks if t not in STOP}


class OrderVotes:
    def __init__(self):
        self.votes: dict = {}

    def add(self, toks: set, hint: str | None) -> None:
        if hint:
            for t in toks:
                v = self.votes.setdefault(t, [0, 0])
                v[0 if hint == "dmy" else 1] += 1

    def decide(self, toks: set, hint: str | None) -> str:
        if hint:
            return hint
        d = m = 0
        for t in toks:
            v = self.votes.get(t)
            if v:
                d += v[0]
                m += v[1]
        return "mdy" if m > d else "dmy"


def _fmt_num(n: int, like: str) -> str:
    return str(n).zfill(len(like)) if len(like) > 1 and like.startswith("0") else (
        str(n).zfill(2) if len(like) == 2 else str(n))


SHIFTED = [0]       # dates shifted in this run (for the privacy report)


def shift_text(text: str, days: int | None, order: str = "dmy") -> tuple:
    """Shift every recognisable calendar date in text by `days`. Returns (text, count)."""
    if not days or not isinstance(text, str) or not text:
        return text, 0
    t = norm_digits(text)
    edits = []
    delta = dt.timedelta(days=days)

    for m in ISO.finditer(t):
        try:
            d = dt.date(int(m.group(1)), int(m.group(2)), int(m.group(3))) + delta
        except ValueError:
            continue
        edits.append((m.start(), m.end(), f"{d.year:04d}-{d.month:02d}-{d.day:02d}"))
    for m in NUM.finditer(t):
        a, sep, b, y = m.group(1), m.group(2), m.group(3), m.group(4)
        dd, mm = (a, b) if order == "dmy" else (b, a)
        try:
            year = int(y) + (2000 if len(y) == 2 else 0)
            d = dt.date(year, int(mm), int(dd)) + delta
        except ValueError:
            continue
        nd, nm = _fmt_num(d.day, dd), _fmt_num(d.month, mm)
        ny = str(d.year)[-2:] if len(y) == 2 else str(d.year)
        out = f"{nd}{sep}{nm}{sep}{ny}" if order == "dmy" else f"{nm}{sep}{nd}{sep}{ny}"
        edits.append((m.start(), m.end(), out))
    for m in WORD.finditer(t):
        mon_s = m.group(2)
        try:
            year = int(m.group(3)) if m.group(3) else 2026
            d = dt.date(year, _MON[mon_s.lower().rstrip(".")], int(m.group(1))) + delta
        except (ValueError, KeyError):
            continue
        mon_out = _month_like(d.month, mon_s)
        out = f"{d.day} {mon_out}" + (f" {d.year}" if m.group(3) else "")
        sep_txt = t[m.start():m.end()]
        if "-" in sep_txt and " " not in sep_txt:
            out = out.replace(" ", "-")
        edits.append((m.start(), m.end(), out))
    for m in WORD2.finditer(t):
        try:
            d = dt.date(int(m.group(3)), _MON[m.group(1).lower().rstrip(".")], int(m.group(2))) + delta
        except (ValueError, KeyError):
            continue
        edits.append((m.start(), m.end(), f"{_month_like(d.month, m.group(1))} {d.day}, {d.year}"))
    if not edits:
        return text, 0
    edits.sort()
    out, last, n = [], 0, 0
    for s, e, rep in edits:
        if s < last:
            continue
        out.append(text[last:s])
        out.append(rep)
        last = e
        n += 1
    out.append(text[last:])
    SHIFTED[0] += n
    return "".join(out), n


def _month_like(month: int, like: str) -> str:
    full = MONTHS[month - 1]
    name = full if len(like.rstrip(".")) > 3 else full[:3]
    if like.isupper():
        return name.upper()
    if like[:1].isupper():
        return name.capitalize()
    return name


def days_for(key: str | None) -> int | None:
    return date_shift_days(key) if key else None
