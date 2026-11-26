"""Safe ingestion: decoding, format sniffing and parsing. Never raises on bad input;
returns a Doc or a quarantine reason (a short identifier that holds no file content)."""
from __future__ import annotations

import csv
import io
import json
import re
from dataclasses import dataclass, field
from pathlib import Path

TEXT_EXT = {".txt", ".text", ".md", ".log", ".note", ".notes"}
CSV_EXT = {".csv"}
TSV_EXT = {".tsv", ".tab"}
JSON_EXT = {".json", ".fhir"}
JSONL_EXT = {".jsonl", ".ndjson"}
MAX_JSON_DEPTH = 120
csv.field_size_limit(10_000_000)


# Files that must never be released, whatever their extension: the antivirus test
# signature (and anything carrying it), and cryptographic key material. Matching is
# on bytes, so the check holds before any decoding and never echoes the content.
_AV_SIGNATURE = re.compile(rb"X5O!P%@AP\[4\\PZX54\(P\^\)7CC\)7\}\$EICAR|EICAR-STANDARD-ANTIVIRUS-TEST-FILE")
_KEY_MATERIAL = re.compile(
    rb"-----BEGIN (?:[A-Z]+ )?PRIVATE KEY-----"
    rb"|(?i:\b(?:aes|enc|encryption|private|secret|master|session|data)?[_ -]?"
    rb"(?:key|nonce|iv|secret)(?:[_ -]?(?:hex|b64|base64))?\b)\s*[=:]\s*[\"']?"
    rb"(?:[0-9A-Fa-f]{24,}|[A-Za-z0-9+/]{32,}={0,2})(?![0-9A-Za-z])")


def security_gate(raw: bytes) -> None:
    if _AV_SIGNATURE.search(raw):
        raise Quarantine("malware_signature")
    if _KEY_MATERIAL.search(raw):
        raise Quarantine("key_material")


class Quarantine(Exception):
    """Raised with a reason identifier, for example Quarantine("truncated_json")."""


@dataclass
class Doc:
    rel: str
    kind: str                      # csv | json | jsonl | text
    text: str = ""
    delimiter: str = ","
    newline: str = "\n"
    rows: list = field(default_factory=list)   # csv rows incl. header
    data: object = None                        # parsed json
    lines: list = field(default_factory=list)  # jsonl objects


def sniff_delimiter(text: str, default: str) -> str:
    """Pick the delimiter that splits the header and the first rows into the same number of fields."""
    lines = [ln for ln in text.splitlines()[:20] if ln.strip()]
    if not lines:
        return default
    best, score = default, 0
    for d in (default, ",", "\t", ";", "|"):
        counts = [ln.count(d) for ln in lines]
        if counts[0] == 0:
            continue
        sc = sum(1 for c in counts if c == counts[0]) * 10 + counts[0]
        if sc > score:
            best, score = d, sc
    return best


def decode(raw: bytes) -> str:
    if raw.startswith(b"\xef\xbb\xbf"):
        return raw[3:].decode("utf-8")
    if raw.startswith((b"\xff\xfe", b"\xfe\xff")):
        return raw.decode("utf-16")
    try:
        return raw.decode("utf-8")
    except UnicodeDecodeError:
        pass
    # Legacy single-byte exports (cp1252) are accepted, but a file whose bytes contain a
    # stray UTF-16 byte-order mark or NULs in the middle is corrupt, not legacy text.
    if b"\xff\xfe" in raw or b"\xfe\xff" in raw or b"\x00" in raw:
        raise Quarantine("corrupt_encoding")
    try:
        return raw.decode("cp1252")
    except UnicodeDecodeError:
        raise Quarantine("undecodable_text") from None


def json_depth_ok(text: str, limit: int = MAX_JSON_DEPTH) -> bool:
    depth = 0
    in_str = esc = False
    for ch in text:
        if in_str:
            if esc:
                esc = False
            elif ch == "\\":
                esc = True
            elif ch == '"':
                in_str = False
        elif ch == '"':
            in_str = True
        elif ch in "[{":
            depth += 1
            if depth > limit:
                return False
        elif ch in "]}":
            depth -= 1
    return True


def parse_json(text: str):
    if not json_depth_ok(text):
        raise Quarantine("excessive_nesting")
    try:
        return json.loads(text)
    except json.JSONDecodeError:
        raise Quarantine("malformed_json") from None


def load(path: Path, rel: str, raw: bytes) -> Doc:
    ext = path.suffix.lower()
    if not raw.strip():
        raise Quarantine("empty_file")
    security_gate(raw)
    known = TEXT_EXT | CSV_EXT | TSV_EXT | JSON_EXT | JSONL_EXT
    if ext not in known:
        raise Quarantine("unsupported_format")
    text = decode(raw)
    stripped = text.lstrip()
    nl = "\r\n" if "\r\n" in text else "\n"
    if ext in CSV_EXT | TSV_EXT:
        if stripped[:1] in "{[":
            raise Quarantine("format_mismatch")
        delim = sniff_delimiter(text, "\t" if ext in TSV_EXT else ",")
        rows = list(csv.reader(io.StringIO(text, newline=""), delimiter=delim))
        if not rows:
            raise Quarantine("empty_file")
        return Doc(rel, "csv", text=text, delimiter=delim, newline=nl, rows=rows)
    if ext in JSON_EXT:
        return Doc(rel, "json", text=text, data=parse_json(text))
    if ext in JSONL_EXT:
        objs = [parse_json(line) for line in text.splitlines() if line.strip()]
        return Doc(rel, "jsonl", text=text, newline=nl, lines=objs)
    return Doc(rel, "text", text=text, newline=nl)
