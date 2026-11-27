"""Phase 3: evidence-based patient linking and keyed pseudonyms.

Two records are linked only when the data connects them:
  * a shared strong identifier (UHID/MRN, Aadhaar, ABHA, patient phone, email), or
  * the same name (phonetic, cross-script) plus a second clue: DOB, relative's name,
    or village + age within 1 year.
Merges are vetoed when the two clusters carry different Aadhaar/ABHA numbers or
clearly different names. A "first name, W/o husband" fragment is linked only when exactly
one cluster matches. Anything else stays unlinked: a missed link costs less than a false merge."""
from __future__ import annotations

import re
from dataclasses import dataclass, field

from . import textner
from .crypto import pseudonym
from .detect import LABELLED_RX, RX, Knowledge, digits_only, find_spans, norm_digits
from .fields import classify_key, classify_path, norm_key
from .privacy import codes_in
from . import sniff

_MRN_PREFIX = re.compile(r"^\s*([A-Za-z]{2,})")
_GENERIC_PREFIX = {"MRN", "UHID", "ID", "PID", "NO", "NUM", "REG", "REGNO", "CR", "CRNO", "IP", "IPD", "OP", "OPD",
                   "PATIENT", "PT", "UID", "RECORD", "REC"}


def mrn_key(s: str) -> str | None:
    """Record numbers from different numbering systems must not collide: INC-00057 and HOSP-00057 belong
    to different patients. A distinctive letter prefix is kept; a generic label (MRN, UHID) is dropped so
    'MRN 123456' still matches a bare '123456'."""
    d = digits_only(s)
    if len(d) < 4:
        return None
    m = _MRN_PREFIX.match(norm_digits(s))
    if m:
        pre = m.group(1).upper()
        if pre not in _GENERIC_PREFIX:
            return "M:" + pre + d
    return "M:" + d

# ----------------------------------------------------------------------------- phonetic keys
_V = {"अ": "a", "आ": "a", "इ": "i", "ई": "i", "उ": "u", "ऊ": "u", "ए": "e", "ऐ": "ai", "ओ": "o", "औ": "au", "ऋ": "ri"}
_M = {"ा": "a", "ि": "i", "ी": "i", "ु": "u", "ू": "u", "े": "e", "ै": "ai", "ो": "o", "ौ": "au", "ृ": "ri",
      "ं": "n", "ँ": "n", "ः": "h", "ॅ": "e", "ॉ": "o"}
_C = {"क": "k", "ख": "kh", "ग": "g", "घ": "gh", "ङ": "n", "च": "ch", "छ": "chh", "ज": "j", "झ": "jh", "ञ": "n",
      "ट": "t", "ठ": "th", "ड": "d", "ढ": "dh", "ण": "n", "त": "t", "थ": "th", "द": "d", "ध": "dh", "न": "n",
      "प": "p", "फ": "ph", "ब": "b", "भ": "bh", "म": "m", "य": "y", "र": "r", "ल": "l", "व": "v", "श": "sh",
      "ष": "sh", "स": "s", "ह": "h", "ळ": "l"}
_NUKTA = {"क": "q", "ख": "kh", "ग": "g", "ज": "z", "ड": "r", "ढ": "rh", "फ": "f"}
_PRE = {"क़": "q", "ख़": "kh", "ग़": "g", "ज़": "z", "ड़": "r", "ढ़": "rh", "फ़": "f"}


def translit(s: str) -> str:
    """Devanagari -> rough Latin (enough for phonetic comparison)."""
    for k, v in _PRE.items():
        s = s.replace(k, v + "a")
    out, i = [], 0
    while i < len(s):
        ch = s[i]
        if ch in _C:
            base = _C[ch]
            if i + 1 < len(s) and s[i + 1] == "\u093c":
                base = _NUKTA.get(ch, base)
                i += 1
            out.append(base)
            nxt = s[i + 1] if i + 1 < len(s) else ""
            if nxt not in _M and nxt != "\u094d":
                out.append("a")
        elif ch in _V:
            out.append(_V[ch])
        elif ch in _M:
            out.append(_M[ch])
        elif ch == "\u094d":
            pass
        else:
            out.append(ch)
        i += 1
    return "".join(out)


GENERIC = {"devi", "kumar", "kumari", "md", "mohd", "ji", "smt", "shri", "sri", "km", "mr", "mrs", "ms", "bibi",
           "begum", "bai", "kunwar", "late", "baby", "master"}
_DIG = [("chh", "c"), ("ch", "c"), ("ph", "f"), ("kh", "k"), ("gh", "g"), ("sh", "s"), ("th", "t"), ("dh", "d"),
        ("bh", "b"), ("jh", "j"), ("qu", "k"), ("q", "k"), ("w", "v"), ("z", "j"), ("x", "ks"), ("ck", "k")]


def skel(token: str) -> str:
    t = translit(token).lower()
    t = re.sub(r"[^a-z]", "", t)
    if not t:
        return ""
    for a, b in _DIG:
        t = t.replace(a, b)
    head, rest = t[0], t[1:]
    rest = rest.replace("h", "")
    rest = re.sub(r"[aeiouy]", "", rest)
    s = head + rest
    return re.sub(r"(.)\1+", r"\1", s)


def name_tokens(name: str) -> list:
    name = re.sub(r"(?i)\b(?:S|D|W|C)\s?/\s?O\b\.?", " ", str(name))
    toks = re.findall(r"[A-Za-z\u0900-\u097F]+", name)
    out = []
    for t in toks:
        lt = translit(t).lower()
        if lt in GENERIC or t in textner.DEV_STOP or len(lt) < 2:
            continue
        out.append(skel(t))
    return [t for t in out if t]


def name_key(name: str) -> str | None:
    toks = name_tokens(name)
    if not toks:
        return None
    return "|".join(sorted(set(toks)))


def first_key(name: str) -> str | None:
    toks = name_tokens(name)
    return toks[0] if toks else None


def dob_key(v: str) -> str | None:
    parts = re.findall(r"\d+", norm_digits(str(v)))
    if len(parts) != 3:
        return None
    return "-".join(sorted(str(int(p)) for p in parts))


def _births(keys) -> set:
    """Only well-formed birth dates (a 1900-2026 year plus day and month) are trusted for a veto."""
    out = set()
    for k in keys:
        p = [int(x) for x in k.split("-")]
        years = [x for x in p if 1900 <= x <= 2026]
        rest = [x for x in p if not 1900 <= x <= 2026]
        if len(years) == 1 and len(rest) == 2 and all(1 <= x <= 31 for x in rest) and min(rest) <= 12:
            out.add(k)
    return out


def age_val(v) -> int | None:
    m = re.search(r"\d{1,3}", norm_digits(str(v)))
    if m and 0 < int(m.group()) < 120:
        return int(m.group())
    return None


# ----------------------------------------------------------------------------- evidence
@dataclass
class Ev:
    ids: set = field(default_factory=set)     # "M:...", "P:...", "A:...", "H:...", "E:..."
    unk: set = field(default_factory=set)     # digit strings of unknown type, resolved later
    names: set = field(default_factory=set)
    firsts: set = field(default_factory=set)
    rels: set = field(default_factory=set)
    relfirsts: set = field(default_factory=set)
    dobs: set = field(default_factory=set)
    villages: set = field(default_factory=set)
    ages: set = field(default_factory=set)
    codes: set = field(default_factory=set)   # ICD-10 codes in the record (for rare-condition counts)
    genders: set = field(default_factory=set)  # quasi-identifiers, for the measured privacy report
    districts: set = field(default_factory=set)

    def person(self) -> bool:
        return bool(self.ids or self.names or self.firsts or self.unk)

    def merge(self, o: "Ev") -> None:
        for k in self.__dataclass_fields__:
            getattr(self, k).update(getattr(o, k))


REL_WORDS = {"relative", "attendant", "guardian", "contact", "father", "husband", "mother", "wife", "kin", "nok",
             "emergency", "informant", "payer", "pita", "pati", "spouse", "son", "daughter", "caller"}


def _rel_context(keys) -> bool:
    for k in keys:
        if isinstance(k, str) and set(norm_key(k).split()) & REL_WORDS:
            return True
    return False


GENDER_KEYS = {"gender", "sex", "ling", "लिंग"}
DISTRICT_KEYS = {"district", "distt", "dist", "jila", "zila", "zilla", "जिला"}
_GENDER_VAL = {"m": "M", "male": "M", "purush": "M", "पुरुष": "M", "f": "F", "female": "F", "mahila": "F", "महिला": "F"}


def _quasi(ev: Ev, cat, s: str, key: str) -> None:
    """Gender and district, kept only to measure residual risk (counts, never written out)."""
    words = set(norm_key(key).split()) if key else set()
    if words & GENDER_KEYS or cat == "AGE":
        g = _GENDER_VAL.get(s.lower())
        if g is None:
            m = re.search(r"(?i)(?:/|\b)\s*(M|F|male|female|पुरुष|महिला)\s*$", s)
            g = _GENDER_VAL.get((m.group(1) or "").lower()) if m else None
        if g:
            ev.genders.add(g)
    if words & DISTRICT_KEYS and cat in (None, "KEEP"):
        k = name_key(s)
        if k:
            ev.districts.add(k)


def add_value(ev: Ev, cat, value, rel_ctx: bool = False, key: str = "") -> None:
    if value is None or isinstance(value, bool):
        return
    s = str(value).strip()
    if s and not rel_ctx:
        try:  # risk measurement only; must never affect linking
            _quasi(ev, cat, s, key)
        except Exception:
            pass
    if not s:
        return
    if cat == "MRN":
        mk = mrn_key(s)
        if mk:
            ev.ids.add(mk)
    elif cat == "PHONE" and not rel_ctx:
        d = digits_only(s)
        if len(d) >= 10:
            ev.ids.add("P:" + d[-10:])
    elif cat == "AADHAAR" and not rel_ctx:
        d = digits_only(s)
        if len(d) == 12:
            ev.ids.add("A:" + d)
    elif cat == "ABHA" and not rel_ctx:
        d = digits_only(s)
        if len(d) == 14:
            ev.ids.add("H:" + d)
    elif cat == "EMAIL" and not rel_ctx:
        ev.ids.add("E:" + s.lower())
    elif cat == "NAME":
        if s.lower().startswith(("dr.", "dr ")):
            return
        k = name_key(s)
        if k:
            if len(name_tokens(s)) >= 2:
                ev.names.add(k)
            ev.firsts.add(first_key(s))
    elif cat == "RELATIVE":
        k = name_key(s)
        if k:
            ev.rels.add(k)
            ev.relfirsts.add(first_key(s))
    elif cat == "DOB":
        k = dob_key(s)
        if k:
            ev.dobs.add(k)
    elif cat == "VILLAGE":
        k = name_key(s)
        if k:
            ev.villages.add(k)
    elif cat == "AGE":
        a = age_val(s)
        if a:
            ev.ages.add(a)


def json_evidence(node, path: tuple, rt, ev: Ev) -> None:
    if isinstance(node, dict):
        if isinstance(node.get("resourceType"), str):
            rt = node["resourceType"]
        if rt in ("Practitioner", "Organization", "Location", "PractitionerRole", "Device"):
            return
        for k, v in node.items():
            kk = k
            if k.startswith("value") and isinstance(node.get("url"), str):
                tail = node["url"].rstrip("/").rsplit("/", 1)[-1]
                if classify_key(tail) is not None:
                    kk = tail
            json_evidence(v, path + (kk,), rt, ev)
    elif isinstance(node, list):
        for v in node:
            json_evidence(v, path, rt, ev)
    elif node is not None:
        if isinstance(node, str):
            ev.codes |= codes_in(node)
        cat = sniff.path_cat(path, rt)
        if cat is None and isinstance(node, str) and path and norm_key(path[-1]) in ("patient ref", "patient id"):
            cat = "MRN"
        add_value(ev, cat, node, _rel_context(path[:-1]) or _rel_context(path[-1:]), str(path[-1]) if path else "")
        if cat in (None, "TEXT", "KEEP") and isinstance(node, str) and len(node) > 12:
            text_evidence(node, ev, light=True)


AGE_RX = re.compile(r"(?i:\bAge(?:\s*/\s*Sex)?|आयु|उम्र|\bUmar|\bUmr)\s*[:\-]?\s*([0-9०-९]{1,3})"
                    r"|(?<![\d/])([0-9]{1,3})\s*(?i:Y(?:rs?|ears?)?\b|वर्ष|साल)")
GENDER_TXT_RX = re.compile(r"(?i)\b(?:\d{1,3}\s*(?:Y|Yrs?|Years?)?\.?\s*/\s*|Sex\s*[:\-]\s*|Gender\s*[:\-]\s*)(M|F|Male|Female)\b"
                           r"|(पुरुष|महिला)")
DISTRICT_TXT_RX = re.compile(r"(?i:\b(?:Distt?\.?|District))\s*[:\-]?\s*([A-Z][a-z]+(?:[ ][A-Z][a-z]+)?)|जिला\s*[:\-]?\s*([\u0900-\u097F]+)")
ATT_LINE = re.compile(r"(?i)attendant|relative|guardian|caller|called by|परिजन|husband|father|pita|pati|bhaiya|papa|mama|chachu")


def text_evidence(text: str, ev: Ev, kb: Knowledge | None = None, light: bool = False) -> None:
    ev.codes |= codes_in(text)
    t = norm_digits(text)
    if not light:
        for line in t.split("\n"):
            rel_line = bool(ATT_LINE.search(line))
            for s, e, kind in find_spans(line, kb):
                d = digits_only(line[s:e])
                if kind == "MRN" and len(d) >= 4:
                    ev.ids.add(mrn_key(line[s:e]))
                elif kind == "PHONE" and not rel_line and len(d) >= 10:
                    ev.ids.add("P:" + d[-10:])
                elif kind == "AADHAAR" and not rel_line:
                    ev.ids.add("A:" + d)
                elif kind == "ABHA" and not rel_line:
                    ev.ids.add("H:" + d)
                elif kind == "EMAIL" and not rel_line:
                    ev.ids.add("E:" + line[s:e].lower())
                elif kind == "ID" and len(d) >= 5 and not rel_line:
                    ev.unk.add(d)
        for m in AGE_RX.finditer(t):
            a = age_val(m.group(1) or m.group(2))
            if a:
                ev.ages.add(a)
                break
        try:  # risk measurement only; must never affect linking
            m = GENDER_TXT_RX.search(t)
            if m:
                g = _GENDER_VAL.get((m.group(1) or m.group(2) or "").lower())
                if g:
                    ev.genders.add(g)
            m = DISTRICT_TXT_RX.search(text)
            if m:
                k = name_key(m.group(1) or m.group(2) or "")
                if k:
                    ev.districts.add(k)
        except Exception:
            pass
        for rx, kind in LABELLED_RX:
            if kind == "DOB":
                for m in rx.finditer(t):
                    k = dob_key(m.group(1))
                    if k:
                        ev.dobs.add(k)
    for m in textner.NAME_LBL_RX.finditer(text):
        nm = textner._trim_name(m.group(1))
        if textner._valid(nm):
            add_value(ev, "NAME", nm)
    for m in textner.HING_NAME_RX.finditer(text):
        nm = textner._trim_name(m.group(1))
        if textner._valid(nm):
            add_value(ev, "NAME", nm)
    for m in textner.REL_LBL_RX.finditer(text):
        add_value(ev, "RELATIVE", textner._trim_name(m.group(1)))
    for m in textner.REL_MARK_RX.finditer(text):
        add_value(ev, "RELATIVE", textner._trim_name(m.group(2)))
    for m in textner.LEAD_REL_RX.finditer(text):
        nm = textner._trim_name(m.group(1))
        if textner._valid(nm):
            ev.firsts.add(first_key(nm))
            if len(name_tokens(nm)) >= 2:
                ev.names.add(name_key(nm))
    if not light:
        for rx in (textner.HONOR_RX, textner.DEV_HONOR_RX, textner.POSS_RX, textner.TITLE_RX):
            for m in rx.finditer(text):
                nm = textner._trim_name(m.group(1))
                if textner._valid(nm) and nm.lower() not in ("dr",):
                    fk = first_key(nm)
                    if fk:
                        ev.firsts.add(fk)
                    if len(name_tokens(nm)) >= 2:
                        ev.names.add(name_key(nm))
        for m in textner.VILLAGE_RX.finditer(text):
            v = m.group(1) or m.group(2)
            if v:
                add_value(ev, "VILLAGE", textner._trim_name(v))
                break


def single_person(ev: Ev) -> Ev:
    """A whole document that mentions several patients (two different IDs of one kind, or
    several full names) must not be linked as one person: keep it unlinked."""
    for p in ("M:", "P:", "A:", "H:"):
        if len({i for i in ev.ids if i.startswith(p)}) > (4 if p == "M:" else 1):
            return Ev()
    if len(ev.names) > 3:
        return Ev()
    return ev


# ----------------------------------------------------------------------------- clustering
class Linker:
    def __init__(self):
        self.nodes: list = []            # (file_rel, loc)
        self.ev: list = []
        self.parent: list = []

    def add(self, rel: str, loc: str, ev: Ev) -> int:
        self.nodes.append((rel, loc))
        self.ev.append(ev)
        self.parent.append(len(self.parent))
        return len(self.nodes) - 1

    def find(self, i: int) -> int:
        while self.parent[i] != i:
            self.parent[i] = self.parent[self.parent[i]]
            i = self.parent[i]
        return i

    def _conflict(self, a: Ev, b: Ev, by_name: bool, phone: bool = False, national: bool = False) -> bool:
        # a phone is often shared by a family: a phone link never joins two different birth dates
        if phone:
            da, db = _births(a.dobs), _births(b.dobs)
            if da and db and not da & db:
                return True
        for p in ("A:", "H:"):
            x = {i for i in a.ids if i.startswith(p)}
            y = {i for i in b.ids if i.startswith(p)}
            if x and y and not x & y:
                return True
        if by_name:
            da, db = _births(a.dobs), _births(b.dobs)
            if da and db and not da & db:
                return True
            mx = {i for i in a.ids if i.startswith("M:")}
            my = {i for i in b.ids if i.startswith("M:")}
            if mx and my and not mx & my and a.villages and b.villages and not a.villages & b.villages:
                return True
            # a shared name (even with the same relative's name) does not outweigh a different
            # record number AND a different phone, unless the birth date agrees: homonyms are common
            px = {i for i in a.ids if i.startswith("P:")}
            py = {i for i in b.ids if i.startswith("P:")}
            if mx and my and not mx & my and px and py and not px & py and not (da and db and da & db):
                return True
        if national:
            # one Aadhaar number belongs to one person: a name that does not transliterate cleanly
            # (or a typo) does not split the record, unless the birth dates disagree
            da, db = _births(a.dobs), _births(b.dobs)
            return bool(da and db and not da & db)
        if a.names and b.names and not a.names & b.names:
            fa = {n.split("|")[0] for n in a.names} | a.firsts
            fb = {n.split("|")[0] for n in b.names} | b.firsts
            ta = {t for n in a.names for t in n.split("|")}
            tb = {t for n in b.names for t in n.split("|")}
            if not (ta & tb) or (by_name and not fa & fb):
                return True
        return False

    def union(self, i: int, j: int, cev: dict, by_name: bool = False, phone: bool = False,
              national: bool = False) -> bool:
        ri, rj = self.find(i), self.find(j)
        if ri == rj:
            return True
        if self._conflict(cev[ri], cev[rj], by_name, phone, national):
            return False
        if rj < ri:
            ri, rj = rj, ri
        self.parent[rj] = ri
        cev[ri].merge(cev.pop(rj))
        return True

    def solve(self) -> list:
        n = len(self.nodes)
        known = set()
        for e in self.ev:
            known |= e.ids
        for e in self.ev:                                 # resolve digit runs of unknown type
            for d in sorted(e.unk):
                for cand in ("M:" + d, "P:" + d[-10:], "A:" + d, "H:" + d):
                    if cand in known:
                        e.ids.add(cand)
                        break
        cev = {i: Ev() for i in range(n)}
        for i in range(n):
            cev[i].merge(self.ev[i])
        # 1) strong identifiers (an identifier seen with 2+ different names is not trusted)
        idx: dict = {}
        for i, e in enumerate(self.ev):
            for k in e.ids:
                idx.setdefault(k, []).append(i)
        for k in sorted(idx):
            members = idx[k]
            for j in members[1:]:
                self.union(members[0], j, cev, phone=k.startswith("P:"), national=k.startswith("A:"))
        # 2) same name + second clue
        for _round in range(2):
            keys: dict = {}
            for r in sorted(cev):
                e = cev[r]
                for nm in e.names:
                    for d in e.dobs:
                        keys.setdefault(("dob", nm, d), []).append(r)
                    for rl in e.rels:
                        keys.setdefault(("rel", nm, rl), []).append(r)
                    for rf in e.relfirsts:
                        keys.setdefault(("relf", nm, rf), []).append(r)
                    for v in e.villages:
                        for a in e.ages:
                            keys.setdefault(("va", nm, v), []).append((r, a))
            for k in sorted(keys, key=str):
                rs = keys[k]
                if k[0] == "va":
                    rs = sorted(set(rs))
                    for x in range(len(rs)):
                        for y in range(x + 1, len(rs)):
                            if abs(rs[x][1] - rs[y][1]) <= 1:
                                self.union(rs[x][0], rs[y][0], cev, by_name=True)
                else:
                    for j in rs[1:]:
                        self.union(rs[0], j, cev, by_name=True)
        # 3) fragments: first name + relative's first name, matched to exactly one cluster
        frag_index: dict = {}
        for r in sorted(cev):
            e = cev[r]
            fs = e.firsts | {nm.split("|")[0] for nm in e.names} | {t for nm in e.names for t in nm.split("|")}
            for f in fs:
                for rf in e.relfirsts:
                    frag_index.setdefault((f, rf), set()).add(r)
        for i in range(n):
            e = self.ev[i]
            if e.ids or e.names or not e.firsts or not e.relfirsts:
                continue
            cands = set()
            for f in e.firsts:
                for rf in e.relfirsts:
                    cands |= {self.find(r) for r in frag_index.get((f, rf), ()) if r in cev}
            cands.discard(self.find(i))
            strong = [c for c in cands if cev[c].ids or cev[c].names]
            if len(strong) == 1:
                self.union(strong[0], i, cev, by_name=False)
        # pseudonyms
        out = []
        for i in range(n):
            r = self.find(i)
            e = cev[r]
            if not self.ev[i].person():
                out.append(None)
                continue
            # one key per cluster: its anchor record (smallest index), so two clusters never share
            # a pseudonym even when they carry the same name or a vetoed identifier
            key = "rec:" + self.nodes[r][0] + "#" + self.nodes[r][1]
            out.append(pseudonym(key))
        self.roots = [self.find(i) for i in range(n)]
        self.clusters = cev
        return out
