"""Demo-only document support: PDFs (typed or scanned) and page images go through the same
IncogRx engine and come back as a redacted copy of the original (same pages and layout).

  * typed pages: the text layer is extracted, cleaned by the engine, and every changed phrase is
    removed from that page (the underlying text is deleted, not just covered);
  * scanned or handwritten pages and images: read with Tesseract OCR (English + Hindi, bundled
    tessdata_fast models, well under the 50M-parameter limit). Words the engine removes are
    blacked out in the image itself. Words the OCR is unsure of are also blacked out, and pages
    with low OCR confidence are flagged for human review: when unsure, we hide rather than leak;
  * every released PDF is scrubbed: JavaScript, auto-actions, embedded files, links, form data,
    hidden text and metadata are removed.

The scored pipeline (main.py) is not changed: there, a PDF or image is quarantined, as the track
defines. Needs PyMuPDF; OCR also needs the `tesseract` program and `pytesseract`."""
from __future__ import annotations

import difflib
import io
import os
import re
import shutil
import time
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

try:
    import pymupdf  # PyMuPDF >= 1.24
except ImportError:  # pragma: no cover
    try:
        import fitz as pymupdf  # older PyMuPDF
    except ImportError:
        pymupdf = None

try:
    import pytesseract
    from PIL import Image
except ImportError:  # pragma: no cover
    pytesseract = None

AVAILABLE = pymupdf is not None
TESSDATA = Path(__file__).resolve().parent / "tessdata"
if (TESSDATA / "eng.traineddata").exists() and not os.environ.get("TESSDATA_PREFIX"):
    os.environ["TESSDATA_PREFIX"] = str(TESSDATA)
os.environ.setdefault("OMP_THREAD_LIMIT", "1")       # one core per OCR process; pages run in parallel
OCR_AVAILABLE = AVAILABLE and pytesseract is not None and shutil.which("tesseract") is not None
MIN_TEXT = 20                      # fewer characters than this on a page = scanned / handwritten page
OCR_DPI = 220
LOW_PAGE_CONF = 70                 # mean word confidence below this: page flagged for human review
UNSURE_WORD_CONF = 45              # words read with less confidence are blacked out
REVIEW_WORD_CONF = 60              # stricter on pages flagged for review (messy handwriting)
PAGE_MARK = "=== IncogRx page break ==="
IMAGE_TYPES = {"jpg": "jpeg", "jpeg": "jpeg", "png": "png", "tif": "tiff", "tiff": "tiff", "bmp": "bmp",
               "webp": "webp", "gif": "gif"}
FILL = (0.90, 0.93, 0.97)          # light box behind replacement text on typed pages
INK = (0.06, 0.16, 0.27)
_TOK = re.compile(r"\S+")
_WORDY = re.compile(r"[A-Za-z0-9ऀ-ॿ]")
_CAPWORD = re.compile(r"^[A-Z][a-z]+[.,;:]?$|^[A-Z]{2,}[.,;:]?$|^[ऀ-ॿ]+$")
# characters a PDF draws without saying which letters they are (font with no Unicode map):
# nobody can check them, so they are hidden in the image and marked in the text
_UNMAPPED = re.compile(r"[\x00\ufffd]+(?:[ ]+[\x00\ufffd]+)*")
UNREADABLE = "[UNREADABLE]"
_TAGGED = ("[NAME", "[RELATIVE", "PSN-")


def ocr_langs() -> str:
    if not OCR_AVAILABLE:
        return ""
    try:
        have = set(pytesseract.get_languages(config=""))
    except Exception:  # noqa: BLE001
        have = {"eng"}
    return "+".join(x for x in ("eng", "hin") if x in have) or "eng"


def extract_text(data: bytes) -> str | None:
    """Kept for compatibility: text of every page, or None without a usable text layer."""
    prep = prepare("file.pdf", data)
    return prep["text"] if prep else None


def _to_pdf(name: str, data: bytes) -> bytes | None:
    ext = name.rsplit(".", 1)[-1].lower() if "." in name else ""
    if data[:5] == b"%PDF-" or ext == "pdf":
        return data
    if ext in IMAGE_TYPES:
        with pymupdf.open(stream=data, filetype=IMAGE_TYPES[ext]) as img:
            return img.convert_to_pdf()
    return None


def _ocr_page(png: bytes, langs: str) -> dict:
    img = Image.open(io.BytesIO(png))
    d = pytesseract.image_to_data(img, lang=langs, output_type=pytesseract.Output.DICT, config="--psm 3")
    words, lines, cur_key, cur = [], [], None, []
    for i, w in enumerate(d["text"]):
        w = (w or "").strip()
        if not w:
            continue
        key = (d["block_num"][i], d["par_num"][i], d["line_num"][i])
        if key != cur_key and cur:
            lines.append(" ".join(cur))
            cur = []
        cur_key = key
        cur.append(w)
        try:
            conf = float(d["conf"][i])
        except (TypeError, ValueError):
            conf = -1.0
        words.append((d["left"][i], d["top"][i], d["left"][i] + d["width"][i], d["top"][i] + d["height"][i],
                      w, conf, key))
    if cur:
        lines.append(" ".join(cur))
    confs = [w[5] for w in words if w[5] >= 0]
    return {"text": "\n".join(lines), "words": words, "conf": round(sum(confs) / len(confs), 1) if confs else 0.0}


def prepare(name: str, data: bytes) -> dict | None:
    """Read every page: the text layer where there is one, OCR where there is not.
    Returns None when the file cannot be read (it then stays quarantined)."""
    if not AVAILABLE:
        return None
    t0 = time.time()
    try:
        pdf = _to_pdf(name, data)
        if pdf is None:
            return None
        doc = pymupdf.open(stream=pdf, filetype="pdf")
    except Exception:  # noqa: BLE001
        return None
    with doc:
        if doc.needs_pass:
            return None
        pages, todo = [], []
        langs = ocr_langs()
        for page in doc:
            text = _UNMAPPED.sub(UNREADABLE, page.get_text("text"))
            if len(text.strip()) >= MIN_TEXT:
                pages.append({"kind": "text", "text": text.strip("\n")})
            elif OCR_AVAILABLE:
                pix = page.get_pixmap(dpi=OCR_DPI, colorspace=pymupdf.csGRAY)
                pages.append({"kind": "ocr", "scale": 72.0 / OCR_DPI})
                todo.append((len(pages) - 1, pix.tobytes("png")))
            else:
                pages.append({"kind": "unread", "text": ""})
    if todo:
        with ThreadPoolExecutor(max_workers=max(1, min(4, os.cpu_count() or 2))) as ex:
            for (i, _), res in zip(todo, ex.map(lambda t: _ocr_page(t[1], langs), todo)):
                pages[i].update(res)
    if not any(p.get("text", "").strip() for p in pages):
        return None
    text = ("\n\n" + PAGE_MARK + "\n\n").join(p.get("text", "") for p in pages)
    return {"pdf": pdf, "pages": pages, "text": text, "langs": langs, "read_seconds": round(time.time() - t0, 2)}


def _pairs(original: str, released: str) -> list:
    """(original phrase, replacement) for every span the engine changed, one pair per text line."""
    a = [(m.group(), m.start(), m.end()) for m in _TOK.finditer(original)]
    b = [m.group() for m in _TOK.finditer(released)]
    pairs = []
    sm = difflib.SequenceMatcher(None, [t for t, _, _ in a], b, autojunk=False)
    for op, i1, i2, j1, j2 in sm.get_opcodes():
        if op not in ("replace", "delete") or i1 == i2:
            continue
        rep = " ".join(b[j1:j2]) if op == "replace" else "[REDACTED]"
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
    seen, out = set(), []
    for o, r in sorted(pairs, key=lambda p: -len(p[0])):
        if o not in seen:
            seen.add(o)
            out.append((o, r))
    return out


def _ocr_masks(page: dict, released: str) -> tuple:
    """Word boxes to black out on an OCR page, and the released text with unsure words hidden."""
    words = page["words"]
    a = [w[4] for w in words]
    b_spans = [(m.start(), m.end(), m.group()) for m in _TOK.finditer(released)]
    b = [t for _, _, t in b_spans]
    hide, unsure_b = set(), set()
    limit = REVIEW_WORD_CONF if page["conf"] < LOW_PAGE_CONF else UNSURE_WORD_CONF
    sm = difflib.SequenceMatcher(None, a, b, autojunk=False)
    for op, i1, i2, j1, j2 in sm.get_opcodes():
        if op in ("replace", "delete"):
            hide.update(range(i1, i2))
            # handwriting is read word by word: when a name was removed, the capitalised words that
            # follow it on the same line ("W/o Mohan | Bisht") are hidden too
            if op == "delete" or any(t.startswith(_TAGGED) for t in b[j1:j2]):
                k = i2
                while k < len(words) and words[k][6] == words[i2 - 1][6] and _CAPWORD.match(words[k][4]):
                    hide.add(k)
                    k += 1
        elif op == "equal":
            for k in range(i2 - i1):
                i = i1 + k
                w = words[i]
                prev = words[i - 1] if i > 0 else None
                follows_name = (prev is not None and (i - 1) in hide and prev[6] == w[6]
                                and _CAPWORD.match(prev[4]) is not None and _CAPWORD.match(w[4]) is not None)
                if i in hide or follows_name or (0 <= w[5] < limit and len(w[4]) >= 3 and _WORDY.search(w[4])):
                    hide.add(i)
                    unsure_b.add(j1 + k)
    out, last = [], 0
    for j, (s, e, _) in enumerate(b_spans):
        if j in unsure_b:
            out.append(released[last:s])
            out.append("[UNSURE]")
            last = e
    out.append(released[last:])
    return hide, "".join(out), len(unsure_b)


def _unmapped_rects(page) -> list:
    """Boxes around runs of glyphs that carry no Unicode (cannot be read, so cannot be cleared)."""
    rects = []
    for block in page.get_text("rawdict").get("blocks", []):
        for line in block.get("lines", []):
            for span in line.get("spans", []):
                run = None
                for ch in span.get("chars", []):
                    c = ch.get("c", "")
                    if c in ("\x00", "\ufffd") or (c == " " and run is not None):
                        r = pymupdf.Rect(ch["bbox"])
                        run = r if run is None else run | r
                    elif run is not None:
                        rects.append(run)
                        run = None
                if run is not None:
                    rects.append(run)
    return [r for r in rects if not r.is_empty]


def redact(prep: dict, released_text: str) -> tuple:
    """Redacted, scrubbed PDF bytes; the released text (with unsure OCR words hidden); and per-page stats."""
    parts = released_text.split(PAGE_MARK)
    per_page = len(parts) == len(prep["pages"])
    if per_page:
        parts = [p.strip("\n") for p in parts]
    stats, out_texts = [], []
    with pymupdf.open(stream=prep["pdf"], filetype="pdf") as doc:
        whole_pairs = None if per_page else _pairs(prep["text"], released_text)
        for n, (page, info) in enumerate(zip(doc, prep["pages"])):
            rel = parts[n] if per_page else ""
            st = {"page": n + 1, "kind": info["kind"], "boxes": 0}
            if info["kind"] == "ocr":
                st["conf"] = info["conf"]
                st["review"] = info["conf"] < LOW_PAGE_CONF
                if per_page:
                    hide, rel_masked, unsure = _ocr_masks(info, rel)
                else:                              # cannot align: hide every word on the page
                    hide, rel_masked, unsure = set(range(len(info["words"]))), "", len(info["words"])
                st["unsure_hidden"] = unsure
                sc = info["scale"]
                for k in sorted(hide):
                    x0, y0, x1, y1 = info["words"][k][:4]
                    page.add_redact_annot(pymupdf.Rect(x0 * sc - 1, y0 * sc - 1, x1 * sc + 1, y1 * sc + 1),
                                          fill=(0, 0, 0))
                    st["boxes"] += 1
                page.apply_redactions(images=pymupdf.PDF_REDACT_IMAGE_PIXELS)   # pixels removed, not covered
                out_texts.append(rel_masked)
            else:
                pairs = _pairs(info.get("text", ""), rel) if per_page else whole_pairs
                for orig, rep in pairs:
                    for rect in page.search_for(orig):
                        size = max(4.0, min(11.0, rect.height * 0.72))
                        page.add_redact_annot(rect, text=rep, fontname="helv", fontsize=size,
                                              fill=FILL, text_color=INK, align=0)
                        st["boxes"] += 1
                for rect in _unmapped_rects(page):
                    page.add_redact_annot(rect, fill=(0, 0, 0))
                    st["boxes"] += 1
                page.apply_redactions()            # removes the underlying text, not just covers it
                out_texts.append(rel)
            stats.append(st)
        # Release a NEW document that receives only the page contents: the original catalog (auto-run
        # actions, document JavaScript, embedded files, forms, outlines, metadata) is left behind.
        clean = pymupdf.open()
        try:
            clean.insert_pdf(doc, links=False, annots=False, widgets=False)
        except TypeError:                          # older PyMuPDF without the widgets option
            clean.insert_pdf(doc, links=False, annots=False)
        try:  # belt and braces: remove anything that could still ride along on the pages
            clean.scrub(attached_files=True, clean_pages=True, embedded_files=True, hidden_text=True,
                        javascript=True, metadata=True, redactions=True, remove_links=True, reset_fields=True,
                        reset_responses=True, thumbnails=True, xml_metadata=True)
        except Exception:  # noqa: BLE001
            pass
        clean.set_metadata({})
        try:
            clean.del_xml_metadata()
        except Exception:  # noqa: BLE001
            pass
        data = clean.tobytes(garbage=4, deflate=True)
        clean.close()
    text = ("\n\n" + PAGE_MARK + "\n\n").join(out_texts) if per_page else released_text
    return data, text, stats
