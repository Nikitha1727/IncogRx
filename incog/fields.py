"""Classify a CSV header or JSON key path into a privacy category.

Headers on hidden data are renamed ("Patient's Name", "Gram/Mohalla", "Naam"), so matching
works on normalised word sets in English, Hindi (Devanagari) and Hinglish transliteration,
and JSON keys also use their parent context (guardian/name is a relative, facility/name
is not a person)."""
from __future__ import annotations

import functools
import re
import unicodedata

# category -> phrases (normalised: lowercase, alnum words). A header matches a category when
# one of its phrases appears as a word sequence inside the header.
_RULES = [
    ("SECRET", ["password", "passwd", "pwd", "passcode", "passphrase", "api key", "apikey", "access token",
                "auth token", "refresh token", "client secret", "secret", "secret key", "private key"]),
    ("ABHA", ["abha", "health id", "healthid", "आभा"]),
    ("AADHAAR", ["aadhaar", "aadhar", "adhar", "uid", "uidai", "आधार"]),
    ("PAN", ["pan", "pan no", "pan number", "payer pan", "पैन"]),
    ("INSURANCE", ["pmjay", "pm jay", "ayushman", "policy", "insurance", "insurer id", "member id", "beneficiary id",
                   "card no", "bima", "बीमा"]),
    ("EMAIL", ["email", "e mail", "mail id", "mail", "email id", "ईमेल"]),
    ("PHONE", ["mobile", "phone", "mob", "contact no", "contact number", "telephone", "tel", "callback",
               "whatsapp", "cell", "ph", "ph no", "contact", "call back", "mobile no", "मोबाइल", "फोन", "फ़ोन", "दूरभाष"]),
    ("PIN", ["pin", "pincode", "pin code", "zip", "zipcode", "postal", "postal code", "postcode", "po code", "post code", "पिन", "पिनकोड"]),
    ("DOB", ["dob", "d o b", "birth", "birthdate", "date of birth", "janm", "janm tithi", "janamtithi", "born", "born on", "paidaish", "janam", "जन्म"]),
    ("AGE", ["age", "umar", "umra", "umr", "aayu", "ayu", "vay", "yrs", "years", "age sex", "age gender", "उम्र", "आयु"]),
    ("MRN", ["uhid", "mrn", "patient id", "patientid", "pid", "reg no", "registration no", "registration number",
             "reg number", "patient ref", "hospital uhid", "cr no", "opd no", "patient no", "pateint id",
             "record no", "medical record", "regn", "regn no", "regn number", "hosp id", "hospital id", "hosp regn", "pt no", "ptno", "pt id", "ip no", "ipd no", "adm no", "पंजीकरण संख्या", "रजि"]),
    ("TEHSIL", ["tehsil", "taluka", "tahsil", "तहसील"]),
    ("KEEP", ["doctor", "ref doctor", "referred by", "consultant", "reviewed by", "physician", "surgeon",
              "hospital", "facility", "department", "dept", "ward", "bed", "block",
              "district", "jila", "zila", "zilla", "distt", "state", "country", "gender", "sex", "ling", "relation",
              "rishta", "test", "loinc", "unit", "range", "result", "drug", "strength", "dose", "frequency",
              "duration", "diagnosis", "icd", "procedure", "package", "amount", "status", "category",
              "रिश्ता", "लिंग", "जिला", "जिले", "राज्य", "विभाग", "डॉक्टर", "चिकित्सक"]),
    ("RELATIVE", ["guardian", "relative", "relative name", "father", "father name", "husband", "spouse",
                  "mother", "pita", "pati", "pita pati", "attendant", "next of kin", "kin", "care of", "c o name",
                  "caretaker", "care taker", "abhibhavak", "escort", "accompanied by", "पिता", "पति", "अभिभावक", "परिजन"]),
    ("HOUSE", ["house", "house no", "h no", "makan", "flat", "मकान"]),
    ("LANDMARK", ["landmark", "near"]),
    ("VILLAGE", ["village", "gaon", "gram", "basti", "mauza", "majra", "city", "town", "mohalla", "locality", "area", "ग्राम", "गांव", "गाँव",
                 "मोहल्ला"]),
    ("ADDRESS", ["address", "addr", "street", "pata", "line", "address line", "residence", "niwas", "gali", "पता", "निवास"]),
    ("NAME", ["name", "naam", "patient name", "patient", "full name", "first", "last", "firstname", "lastname",
              "first name", "last name", "surname", "given", "family", "middle name", "beneficiary", "rogi", "pt name", "नाम", "मरीज", "रोगी"]),
    ("TEXT", ["notes", "note", "remarks", "remark", "comment", "comments", "complaints", "complaint", "history",
              "narrative", "text", "div", "description", "summary", "advice", "address note", "source path",
              "path", "message", "data", "content", "valuestring", "टिप्पणी"]),
]


@functools.lru_cache(maxsize=65536)
def norm_key(key: str) -> str:
    k = unicodedata.normalize("NFKC", str(key))
    k = re.sub(r"([a-z])([A-Z])", r"\1 \2", k)            # camelCase -> camel Case
    k = re.sub(r"\(.*?\)", " ", k)                       # "DOB (MM/DD/YYYY)" -> "DOB"
    k = re.sub(r"[^\wऀ-ॿ]+", " ", k.lower().replace("_", " "))
    return re.sub(r"\s+", " ", k).strip()


def _has_phrase(words: list, phrase: str) -> bool:
    p = phrase.split()
    n = len(p)
    return any(words[i:i + n] == p for i in range(len(words) - n + 1))


@functools.lru_cache(maxsize=65536)
def classify_key(key: str) -> str | None:
    words = norm_key(key).split()
    if not words:
        return None
    joined = " ".join(words)
    # strong compound headers first
    if re.search(r"\b(pita|pati|father|husband|guardian|relative)\b.*\b(naam|name)\b", joined):
        return "RELATIVE"
    if "age" in words and ("sex" in words or "gender" in words):
        return "AGE"
    for cat, phrases in _RULES:
        for ph in phrases:
            if _has_phrase(words, ph):
                # "Village/Mohalla" -> VILLAGE, "Address" -> ADDRESS, "Patient Name" -> NAME
                return cat
    return None


_PERSON_PARENTS = {"patient", "patients", "person", "raised by", "subject", "beneficiary", "member", "insured",
                   "claimant", "caller", "informant", "contact person", "name"}
_RELATIVE_PARENTS = {"guardian", "relative", "contact", "kin", "next of kin", "father", "husband", "attendant",
                     "emergency contact", "spouse", "mother"}
_NOT_PERSON_PARENTS = {"facility", "hospital", "lab", "laboratory", "organization", "organisation", "panels",
                       "panel", "drug", "medication", "test", "ward", "department", "practitioner", "doctor",
                       "location", "service provider", "author", "performer", "export meta", "meta", "system",
                       "coding", "code", "class", "type", "category", "qualification", "section", "insurer",
                       "payer", "diagnosis", "rx", "results", "result", "package", "procedure"}
_NOT_PERSON_RESOURCES = {"Practitioner", "Organization", "Location", "PractitionerRole", "HealthcareService",
                         "Device", "Medication", "Substance"}


@functools.lru_cache(maxsize=65536)
def classify_path(path: tuple, resource_type: str | None = None) -> str | None:
    """path: tuple of JSON keys from the root (list indices removed)."""
    keys = [k for k in path if isinstance(k, str)]
    if not keys:
        return None
    leaf = norm_key(keys[-1])
    parents = [norm_key(k) for k in keys[:-1]]
    parent = parents[-1] if parents else ""
    ancestors = set(parents)
    if resource_type in _NOT_PERSON_RESOURCES and not ancestors & {"contact", "telecom", "address"}:
        if leaf in {"family", "given", "text", "name", "prefix", "suffix"}:
            return "KEEP"
    if ancestors & {"relationship", "relation", "coding"} or leaf in {"relationship", "relation"}:
        return "KEEP"  # "Husband", "Next-of-Kin": a role, not a person
    if resource_type in _NOT_PERSON_RESOURCES and "address" in ancestors and "contact" not in ancestors:
        return "KEEP"  # an organisation's or location's own address
    # FHIR / generic structures where the parent decides
    if parent in {"telecom"} and leaf == "value":
        return "PHONE"
    if parent in {"identifier"} and leaf == "value":
        return "KEEP" if resource_type in _NOT_PERSON_RESOURCES else "MRN"
    if leaf in {"display"} and parent in {"subject", "patient", "beneficiary"}:
        return "NAME"
    if leaf in {"display"} and parent in {"author", "performer", "requester", "practitioner", "location",
                                          "service provider", "organization", "recorder", "asserter"}:
        return "KEEP"
    if ancestors & _NOT_PERSON_PARENTS and leaf in {"name", "text", "display", "first", "last", "family", "given"}:
        if not ancestors & (_PERSON_PARENTS | _RELATIVE_PARENTS) or parent in _NOT_PERSON_PARENTS:
            return "KEEP"
    if leaf in {"name", "first", "last", "given", "family", "local", "text", "full", "full name", "middle"} and (
            ancestors & _RELATIVE_PARENTS):
        return "RELATIVE"
    if leaf in {"family", "given", "local", "first", "last", "middle", "full", "prefix"} and parent == "name":
        return "NAME" if "prefix" != leaf else "KEEP"
    if leaf == "text" and parent == "name":
        return "NAME"
    if leaf == "name" and (parent in _PERSON_PARENTS or not parent or resource_type in ("Patient",)):
        return "NAME"
    if leaf == "name" and parent and parent not in _PERSON_PARENTS:
        return None  # decided by value (person-like or not)
    if parent == "address" or (parent and classify_key(keys[-2]) == "ADDRESS" and leaf not in {"address"}):
        if leaf in {"city", "village"}:
            return "VILLAGE"
        if leaf in {"tehsil", "taluka"}:
            return "TEHSIL"
        if leaf in {"district", "state", "country", "use", "type"}:
            return "KEEP"
        if leaf in {"line", "text"}:
            return "ADDRESS"
        if leaf in {"postal code", "pin", "zip"}:
            return "PIN"
        sub = classify_key(keys[-1])
        if sub in ("PIN", "TEHSIL", "VILLAGE", "HOUSE", "LANDMARK", "ADDRESS"):
            return sub
        if sub == "KEEP":
            return "KEEP"
        return "ADDRESS"
    if leaf == "patient" and parent in {"", "visits", "results", "records"}:
        return "NAME"
    cat = classify_key(keys[-1])
    if cat == "NAME" and leaf not in {"name", "naam", "patient name", "patient", "full name", "first", "last",
                                       "first name", "last name", "firstname", "lastname", "surname", "given",
                                       "family", "नाम", "patient s name", "patients name", "pt name",
                                       "patient full name", "मरीज का नाम", "मरीज"} and "name" not in leaf.split():
        return None
    return cat
