"""Demo-only PDF support: a text PDF goes through the same IncogRx engine and comes back as a
redacted copy of the original PDF (same pages and layout, personal data covered by its tag).

The scored pipeline (main.py) is not changed: there, a PDF is quarantined, which the track allows.
Needs PyMuPDF (`pip install pymupdf`); without it, PDFs stay quarantined in the demo too.
Scanned PDFs (images, no text layer) need OCR and are quarantined."""
from __future__ import annotations

import difflib
import re

try:
    import pymupdf  # PyMuPDF >= 1.24
except ImportError:  # pragma: no cover
    try:
        import fitz as pymupdf  # older PyMuPDF
    except ImportError:
        pymupdf = None

AVAILABLE = pymupdf is not None
MIN_TEXT = 20                      # fewer extracted characters than this = scanned / image-only PDF
FILL = (0.90, 0.93, 0.97)          # light box behind the replacement text
INK = (0.06, 0.16, 0.27)


def extract_text(data: bytes) -> str | None:
    """Text of every page, or None when the PDF has no usable text layer (or cannot be opened)."""
    if not AVAILABLE:
        return None
    try:
        with pymupdf.open(stream=data, filetype="pdf") as doc:
            if doc.needs_pass:
                return None
            text = "\n".join(page.get_text("text") for page in doc)
    except Exception:  # noqa: BLE001  damaged PDF: let the pipeline quarantine it
        return None
    return text if len(text.strip()) >= MIN_TEXT else None


_TOK = re.compile(r"\S+")


def _changes(original: str, released: str) -> list:
    """(original phrase, replacement) for every span the engine changed, one pair per text line."""
    a = [(m.group(), m.start(), m.end()) for m in _TOK.finditer(original)]
    b = [m.group() for m in _TOK.finditer(released)]
    pairs = []
    sm = difflib.SequenceMatcher(None, [t for t, _, _ in a], b, autojunk=False)
    for op, i1, i2, j1, j2 in sm.get_opcodes():
        if op not in ("replace", "delete") or i1 == i2:
            continue
        rep = " ".join(b[j1:j2]) if op == "replace" else "[REDACTED]"
        # widen very short changes (an age "34", a "Dr" fragment) with the next word on the line,
        # so the search does not hit the same digits elsewhere on the page
        if a[i2 - 1][2] - a[i1][1] < 4 and i2 < len(a) and "\n" not in original[a[i2 - 1][2]:a[i2][1]]:
            nxt = a[i2][0]
            if j2 < len(b) and b[j2] == nxt:
                rep = f"{rep} {nxt}"
                i2 += 1
            else:
                continue
        chunk = original[a[i1][1]:a[i2 - 1][2]]
        lines = [ln.strip() for ln in chunk.split("\n") if ln.strip()]
        for k, ln in enumerate(lines):
            if re.search(r"\w", ln):
                pairs.append((ln, rep if k == 0 else ""))
    # longest phrases first, so a full name is redacted before any part of it
    seen, out = set(), []
    for o, r in sorted(pairs, key=lambda p: -len(p[0])):
        if o not in seen:
            seen.add(o)
            out.append((o, r))
    return out


def redact(data: bytes, original_text: str, released_text: str) -> bytes:
    """Return a copy of the PDF with every changed phrase covered by its replacement."""
    pairs = _changes(original_text, released_text)
    with pymupdf.open(stream=data, filetype="pdf") as doc:
        for page in doc:
            for orig, rep in pairs:
                for rect in page.search_for(orig):
                    size = max(4.0, min(11.0, rect.height * 0.72))
                    page.add_redact_annot(rect, text=rep, fontname="helv", fontsize=size,
                                          fill=FILL, text_color=INK, align=0)
            page.apply_redactions()            # removes the underlying text, not just covers it
        doc.set_metadata({})                   # title / author / subject can hold names
        try:
            doc.del_xml_metadata()
        except Exception:  # noqa: BLE001
            pass
        return doc.tobytes(garbage=4, deflate=True)
