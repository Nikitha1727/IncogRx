"""Phase 2: context-aware detection in free text (English, Hindi, Hinglish).

Finds names, relatives, addresses, houses, localities, landmarks and villages that are not
in any structured field, using labels ("Patient Name:", "पता:"), relation markers (S/o, W/o),
honorifics (ji, bhaiya, amma), cue phrases ("called by X") and a gazetteer of name tokens
learned in pass 1. Doctors ("Dr. X"), organisations ("X Hospital") and the ASHA worker role
are protected."""
from __future__ import annotations

import functools
import re

DEV = "\u0900-\u097F"
L = "A-Za-z" + DEV                      # letters for word boundaries
NB = rf"(?<![{L}])"
NA = rf"(?![{L}])"

# one Latin name token: Capitalised word, or an initial "K."
LAT_TOK = r"(?:Mohd\.|Md\.|Mohd|[A-Z][a-z]+|[A-Z]\.)"
LAT_NAME = LAT_TOK + r"(?:[ ](?:" + LAT_TOK + r")){0,3}"
DEV_NAME = rf"[{DEV}]+(?:[ ][{DEV}]+){{0,3}}"
ANY_NAME = rf"(?:{LAT_NAME}|{DEV_NAME})"

# words that look like names (capitalised) but are not
NOT_NAME = {
    "caregiver", "caregivers", "carer", "healthcare", "other", "others", "organization", "organisation",
    "provider", "staff", "clinician", "practitioner", "unknown", "contact", "subtype", "category", "label",
    "name", "patient", "admitted", "discharged", "attendant", "mob", "mobile", "address", "age", "sex",
    "male", "female", "ward", "bed", "date", "the", "and", "with", "for", "from", "report", "sample",
    "test", "tab", "cap", "inj", "syp", "dr", "doctor", "hospital", "clinic", "pathology", "lab",
    "sister", "nurse", "staff", "visitor", "relative", "guardian", "husband", "wife", "father", "mother",
    "son", "daughter", "brother", "self", "none", "nil", "na", "unknown", "ji", "sahab", "bhai",
    "fever", "pain", "cough", "vomiting", "weakness", "breathlessness", "complaints", "history",
    "advice", "review", "diagnosis", "medicine", "surgery", "opd", "ipd", "icu", "emergency",
    "village", "gram", "vill", "tehsil", "district", "distt", "house", "mohalla", "near", "opp",
    "behind", "anm", "aww", "worker", "forwarded", "attachment", "mr", "mrs", "smt", "shri",
    "km", "kumari", "master", "baby", "of", "on", "at", "in", "to", "by", "is", "was", "bp", "rbs",
}
DEV_STOP = {"को", "का", "की", "के", "है", "ने", "से", "में", "और", "आयु", "उम्र", "ग्राम", "पता", "मोबाइल",
            "वर्ष", "साल", "पुत्र", "पुत्री", "पत्नी", "पति", "पिता", "माता", "निवासी", "जी", "मरीज़", "मरीज",
            "डॉक्टर", "डॉ", "अस्पताल", "बुखार", "दिन", "तहसील", "जिला", "रात", "सुबह", "शाम", "आज", "कल", "था",
            "थी", "हैं", "भी", "ही", "तो", "पर", "लिए", "साथ", "नाम", "का", "की", "के"}


def _trim_name(v: str) -> str:
    toks = v.split(" ")
    while toks and (toks[-1].lower().strip(".") in NOT_NAME or toks[-1] in DEV_STOP):
        toks.pop()
    while toks and (toks[0].lower().strip(".") in NOT_NAME or toks[0] in DEV_STOP):
        toks.pop(0)
    return " ".join(toks)


# ----------------------------------------------------------------------------- label patterns
LBL_END = r"\s*[:\-–]\s*"
NAME_LABELS = (r"(?:Patient(?:'s)?\s*Name|Pt\.?\s*Name|Name\s+of\s+(?:the\s+)?Patient|Mareez\s+ka\s+Naam|"
               r"Patient\s+ka\s+Naam|Rogi(?:\s+ka\s+Naam)?|Beneficiary(?:\s+Name)?|मरीज़?\s*का\s*नाम|रोगी(?:\s*का\s*नाम)?|"
               r"(?m:^\s*)(?:Name|Naam|नाम|मरीज़?))")
REL_LABELS = (r"(?:Father(?:'s)?\s*Name|Husband(?:'s)?\s*Name|Mother(?:'s)?\s*Name|Guardian(?:'s)?\s*(?:Name)?|"
              r"Attendant(?:'s)?\s*(?:Name)?|Next\s+of\s+Kin|NOK|Informant|Pita\s*(?:ka|/Pati\s*ka)?\s*Naam|"
              r"Pati\s*ka\s*Naam|Accompanied\s+by|Escort(?:ed\s+by)?|Care\s*taker|Abhibhavak|"
              r"पिता(?:\s*का\s*नाम)?|पति(?:\s*का\s*नाम)?|माता(?:\s*का\s*नाम)?|पिता/पति(?:\s*का\s*नाम)?|परिजन(?:\s*का\s*नाम)?|अभिभावक)")
NAME_LBL_RX = re.compile(rf"(?i:{NAME_LABELS}){LBL_END}({ANY_NAME})")
# Hinglish label without a colon: "Patient ka naam Kavya Mehta"
HING_NAME_RX = re.compile(rf"(?i:\b(?:patient|mareez|mariz|marij|rogi)\s+ka\s+naam)(?:\s+(?i:hai|he))?\s+({LAT_NAME})")
REL_LBL_RX = re.compile(rf"(?i:{REL_LABELS}){LBL_END}({ANY_NAME})")
ADDR_LBL_RX = re.compile(r"(?:(?i:\b(?:Address|Addr\.?|Pata|Niwas|Residence))|(?<![\u0900-\u097F])(?:पता|निवासी|निवास)(?![\u0900-\u097F]))"
                         r"\s*(?:\([^()\n]{1,30}\))?\s*[:\-–]\s*([^\n]+)"
                         r"|(?i:\b(?:Resident\s+of|R/o))\.?\s+([^\n]+)")

ADDR_CONT_RX = re.compile(r"(?i:\b(?:Distt?\.?|District|Tehsil|Teh\.|Pin(?:\s*code)?)\b)|जिला|तहसील|(?<!\d)\d{6}(?!\d)")
NEW_LABEL_RX = re.compile(r"\s*[A-Za-z\u0900-\u097F][\w\u0900-\u097F ./()]{0,30}:")
HOUSE_RX = re.compile(r"(?i:\b(?:House|H\.?\s?No|Makan|Ghar)\.?\s*(?:No\.?|Number|#)?\s*[:\-]?\s*)\d+[A-Za-z]?(?:[/\-]\d+[A-Za-z]?)?"
                      r"|मकान\s*(?:नं|न|संख्या|नंबर)\.?\s*[:\-]?\s*[0-9०-९]+")
# municipal ward inside an address line ("C/O Ramesh, H.No. 364, Ward 20"); a hospital ward elsewhere stays
WARD_ADDR_RX = re.compile(r"(?i:,\s*(Ward\s*(?:No\.?\s*)?[:\-]?\s*\d{1,3}))(?![\d/])")
MOHALLA_RX = re.compile(rf"(?i:\bMohalla|\bMohalla|\bMuhalla|\bColony\s+No)\s+{LAT_NAME}|मोहल्ला\s+{DEV_NAME}")
LANDMARK_RX = re.compile(rf"(?i:\b(?:near|opp\.?|opposite|behind|beside|next\s+to|in\s+front\s+of))\s+(?:the\s+)?{LAT_NAME}"
                         rf"|(?<![{DEV}])(?:[{DEV}]+\s+){{1,3}}के\s+(?:पास|सामने|पीछे|बगल\s+में)")  # word start only: linear on long runs
VILLAGE_RX = re.compile(rf"(?i:\b(?:Village|Vill\.?|Gram|Gaon|Gaanv|Mauza))\s*[:\-]?\s*({LAT_NAME})"
                        rf"|(?<![{DEV}])(?:ग्राम|गांव|गाँव|मौजा)(?![{DEV}])\s*[:\-]?\s*({DEV_NAME})")

# ----------------------------------------------------------------------------- context patterns
REL_MARK_RX = re.compile(rf"(?<![A-Za-z])((?:[SDW]\s?/\s?[Oo]|[SDW]/O)\.?|(?i:son|wife|daughter|husband)\s+of|"
                         rf"पुत्र|पुत्री|पत्नी)(?:\s*[:\-–]\s*|\s+)({LAT_NAME}|{DEV_NAME})")
CO_RX = re.compile(rf"(?<![A-Za-z])(C/[Oo]\.?)(?:\s*[:\-–]\s*|\s+)({LAT_NAME})")
HONOR = (r"ji|jee|sahab|saheb|sahib|didi|bhaiya|bhaiyya|bhai|behenji|behen|bahenji|amma|ammi|chacha|chachu|chachi|"
         r"mama|mami|mamaji|papa|uncle|aunty|aunti|bhabhi|dada|dadi|nana|nani|babu|kaka|kaki|tau|tai|bua")
HONOR_RX = re.compile(rf"(?<![A-Za-z.])({LAT_TOK}(?:[ ]{LAT_TOK})?)[ ](?i:({HONOR}))(?![A-Za-z])")
DEV_HONOR_RX = re.compile(rf"(?<![{DEV}])([{DEV}]+(?:[ ][{DEV}]+)?)\s+(जी|साहब|दीदी|भैया|भाई|अम्मा|बहनजी|चाचा|मामा)(?![{DEV}])")
POSS_RX = re.compile(rf"(?<![A-Za-z.])({LAT_NAME})'s\s+(?i:(?=attendant|husband|wife|son|daughter|father|mother|brother|"
                     r"sister|family|relative|sample|report|bed|file))")
CUE_RX = re.compile(rf"(?i:\b(?:called|visited|brought|accompanied|escorted|informed|received|collected|signed|"
                    rf"consented|witnessed|attended|sent)\s+by|\bcaller|\bvisitor|\bcontact\s+person)\s*[:\-]?\s+({LAT_NAME}|{DEV_NAME})")
REL_NOUN_RX = re.compile(rf"(?<![A-Za-z])(?i:son|daughter|wife|husband|father|mother|nephew|niece|grandson|"
                         rf"granddaughter|beta|beti|bahu|pati|patni|bhai|behen|bahen|saas|sasur|devar|nanad|damad|jija)"
                         rf"(?:\s+(?i:of\s+patient|named|is|was))?\s+({LAT_NAME})"
                         rf"|(?<![{DEV}])(?:बेटा|बेटी|बहू|पति|पत्नी|भाई|बहन|सास|ससुर|दामाद)(?!\s*(?:का|की|के|ने|को|से|[:\-]))\s+([{DEV}]+(?:[ ][{DEV}]+)?)")
LOG_RX = re.compile(rf"(?m)^\s*\d{{1,2}}[:.]\d{{2}}\s*[-–]\s*({LAT_NAME})(?=\s*[(,])")
LEAD_REL_RX = re.compile(rf"(?m)^\s*({LAT_NAME}|{DEV_NAME}),?\s*(?=[SDW]\s?/\s?[Oo]|(?i:son|wife|daughter)\s+of\b)")
TITLE_RX = re.compile(rf"(?<![A-Za-z])(?:Mr|Mrs|Ms|Smt|Shri|Sri|Kumari|Km|Master|Report\s+of|Patient|Pt)\.?\s*:?\s+({LAT_NAME})")
WA_RX = re.compile(rf"(?m)^\[[^\]]+\]\s*({LAT_NAME}(?:[ ](?i:{HONOR}))?)\s*:")

# protected spans: doctors, organisations, ASHA worker role
PROTECT_RX = re.compile(
    rf"(?:\bDr\.?|\bDoctor|\bProf\.?|डॉ\.?|डॉक्टर)\s+(?:{LAT_TOK}[ ]?){{1,4}}"
    rf"|(?:\bDr\.?|डॉ\.?)\s+(?:[{DEV}]+[ ]?){{1,3}}"
    rf"|(?:{LAT_TOK}[ ]){{1,5}}(?:Hospital|Clinic|Pathology|Diagnostics|Labs?|Nursing\s+Home|Medical|Trust|Sadan|"
    rf"Charitable|Multispeciality|Institute|Centre|Center|Pharmacy|Dispensary)"
    r"|\bASHA\b|\bAsha\s+(?:worker|didi\s+\(ASHA\)|karyakarta|sahyogini)")


def _valid(name: str) -> bool:
    toks = name.split(" ")
    if not toks or not name.strip():
        return False
    if all(t.lower().strip(".") in NOT_NAME or t in DEV_STOP for t in toks):
        return False
    return len(name.replace(".", "").replace(" ", "")) >= 3


class Finder:
    """Collects (start, end, replacement) edits on one string; later edits never overlap earlier ones."""

    def __init__(self, text: str):
        self.text = text
        self.edits: list = []
        self.found: list = []          # (surface, kind) for learning

    def free(self, s: int, e: int) -> bool:
        return all(e <= a or s >= b for a, b, _ in self.edits)

    def add(self, s: int, e: int, rep: str, kind: str | None = None) -> None:
        if s < e and self.free(s, e):
            self.edits.append((s, e, rep))
            if kind:
                self.found.append((self.text[s:e], kind))

    def apply(self) -> str:
        out, last = [], 0
        for s, e, rep in sorted(self.edits):
            out.append(self.text[last:s])
            out.append(rep)
            last = e
        out.append(self.text[last:])
        return "".join(out)


def _name_group(f: Finder, m, g: int, tag: str, kind: str) -> None:
    raw = m.group(g)
    if raw is None:
        return
    name = _trim_name(raw)
    if not _valid(name):
        return
    s = m.start(g) + raw.find(name)
    f.add(s, s + len(name), tag, kind)


def detect(text: str, address_fn=None) -> Finder:
    f = Finder(text)
    protected = [(m.start(), m.end(), None) for m in PROTECT_RX.finditer(text)]
    f.edits.extend(protected)                       # placeholders: block edits inside protected spans
    # addresses first (whole value), then parts that appear outside an address line
    for m in ADDR_LBL_RX.finditer(text):
        g = 1 if m.group(1) is not None else 2
        start, end = m.start(g), m.end(g)
        # a wrapped address continues on the next line when that line carries address markers
        # (district, tehsil, PIN) and does not start a new "Label:"
        nl = text.find("\n", end)
        if nl == end:
            nxt_end = text.find("\n", nl + 1)
            nxt = text[nl + 1:nxt_end if nxt_end >= 0 else len(text)]
            if ADDR_CONT_RX.search(nxt) and not NEW_LABEL_RX.match(nxt):
                end = nl + 1 + len(nxt)
        val = text[start:end]
        if address_fn and re.search(r"\d|,|[A-Z][a-z]|[" + DEV + "]", val):
            f.add(start, end, address_fn(val.replace("\n", ", ")), "ADDRESS")
    for m in HOUSE_RX.finditer(text):
        f.add(m.start(), m.end(), "[HOUSE]", "HOUSE")
    for m in WARD_ADDR_RX.finditer(text):
        line = text[text.rfind("\n", 0, m.start()) + 1:m.start()]
        if HOUSE_RX.search(line) or CO_RX.search(line):
            f.add(m.start(1), m.end(1), "[LOCALITY]")
    for m in MOHALLA_RX.finditer(text):
        f.add(m.start(), m.end(), "[LOCALITY]", "LOCALITY")
    for m in LANDMARK_RX.finditer(text):
        f.add(m.start(), m.end(), "[LANDMARK]", "LANDMARK")
    for m in VILLAGE_RX.finditer(text):
        g = 1 if m.group(1) else 2
        _name_group(f, m, g, "[VILLAGE]", "VILLAGE")
    for m in NAME_LBL_RX.finditer(text):
        _name_group(f, m, 1, "[NAME]", "NAME")
    for m in HING_NAME_RX.finditer(text):
        _name_group(f, m, 1, "[NAME]", "NAME")
    for m in REL_LBL_RX.finditer(text):
        _name_group(f, m, 1, "[RELATIVE]", "RELATIVE")
    for m in REL_MARK_RX.finditer(text):
        _name_group(f, m, 2, "[RELATIVE]", "RELATIVE")
    for m in CO_RX.finditer(text):
        _name_group(f, m, 2, "[RELATIVE]", "RELATIVE")
    for m in LEAD_REL_RX.finditer(text):
        _name_group(f, m, 1, "[NAME]", "NAME")
    for m in WA_RX.finditer(text):
        _name_group(f, m, 1, "[RELATIVE]", "RELATIVE")
    for m in REL_NOUN_RX.finditer(text):
        _name_group(f, m, 1 if m.group(1) else 2, "[RELATIVE]", "RELATIVE")
    for rx in (HONOR_RX, DEV_HONOR_RX, POSS_RX, CUE_RX, LOG_RX, TITLE_RX):
        for m in rx.finditer(text):
            _name_group(f, m, 1, "[NAME]", "NAME")
    f.edits = [e for e in f.edits if e[2] is not None] + [(s, e, None) for s, e, _ in protected]
    return f


def apply(text: str, address_fn=None) -> tuple:
    f = detect(text, address_fn)
    f.edits = [e for e in f.edits if e[2] is not None]
    return f.apply(), len(f.edits)


ADMIN_RX = re.compile(rf"(?i:\b(?:Tehsil|Teh\.?|Tahsil|Distt?\.?|District|Dist\.?|Jila|Zila))\s*[:\-]?\s*({LAT_NAME})"
                      rf"|(?:तहसील|जिला|ज़िला)\s*[:\-]?\s*({DEV_NAME})")


@functools.lru_cache(maxsize=65536)
def detect_found(text: str) -> tuple:
    """(surface, kind) findings for learning. Pure function of the text, so repeated values reuse it."""
    return tuple(detect(text).found)


@functools.lru_cache(maxsize=65536)
def admin_names_cached(text: str) -> tuple:
    return tuple(admin_names(text))


def admin_names(text: str) -> list:
    """Tehsil and district names: kept for utility, so never learned as person or village tokens."""
    out = []
    for m in ADMIN_RX.finditer(text):
        v = m.group(1) or m.group(2)
        out += [t for t in _trim_name(v).split(" ") if t]
    return out


def protected_spans(text: str) -> list:
    return [(m.start(), m.end()) for m in PROTECT_RX.finditer(text)]
