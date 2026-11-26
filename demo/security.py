"""Demo-only intake security scan.

Every uploaded file is checked BEFORE it reaches the engine. Nothing is ever executed or opened by
another program: files are read as bytes, and PDFs and images are parsed only by PyMuPDF / Pillow in
this process. A file can be:

  clean        passed to the engine unchanged
  neutralized  passed on, but its active content (PDF JavaScript, auto-actions, embedded files,
               links, forms) is removed from the released copy
  blocked      never written to disk, never processed, listed with the reason

The scored pipeline (main.py) is not changed by this module."""
from __future__ import annotations

import io
import re
import zipfile

MAX_FILE = 60 * 1024 * 1024        # bytes per file
MAX_PAGES = 600                    # a PDF with more pages is treated as a denial-of-service attempt
MAX_PIXELS = 60_000_000            # image decompression-bomb guard

EICAR = b"X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*"
EXEC_EXT = {"exe", "dll", "com", "scr", "msi", "bat", "cmd", "ps1", "psm1", "vbs", "vbe", "js", "jse", "wsf",
            "hta", "jar", "apk", "app", "dmg", "pkg", "deb", "rpm", "sh", "bash", "zsh", "py", "pyc", "pl", "rb",
            "php", "lnk", "reg", "iso", "img", "cpl", "msc", "gadget", "docm", "xlsm", "pptm", "dotm", "xlam"}
MAGIC = [(b"MZ", "Windows executable (MZ header)"),
         (b"\x7fELF", "Linux executable (ELF header)"),
         (b"\xfe\xed\xfa\xce", "macOS executable (Mach-O)"), (b"\xfe\xed\xfa\xcf", "macOS executable (Mach-O)"),
         (b"\xce\xfa\xed\xfe", "macOS executable (Mach-O)"), (b"\xcf\xfa\xed\xfe", "macOS executable (Mach-O)"),
         (b"\xca\xfe\xba\xbe", "Java class or macOS universal binary"),
         (b"#!", "script with an interpreter line"),
         (b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1", "legacy Office container (can carry macros)")]
PDF_ACTIVE = [(rb"/JavaScript|/JS\b", "JavaScript"), (rb"/OpenAction", "auto-run action on open"),
              (rb"/AA\b", "automatic actions"), (rb"/Launch", "launch-a-program action"),
              (rb"/EmbeddedFile", "embedded file"), (rb"/RichMedia", "rich media"), (rb"/XFA", "XFA form"),
              (rb"/SubmitForm", "form that sends data out"), (rb"/URI\b", "external link")]
SCRIPT_TEXT = re.compile(rb"(?i)<script\b|javascript:|vbscript:|onload\s*=|<iframe\b")
IMAGE_EXT = {"jpg", "jpeg", "png", "tif", "tiff", "bmp", "webp", "gif"}


def _ext(name: str) -> str:
    base = name.rsplit("/", 1)[-1].lower()
    return base.rsplit(".", 1)[-1] if "." in base else ""


def _result(name, verdict, reason, findings=None) -> dict:
    return {"name": name, "verdict": verdict, "reason": reason, "findings": findings or []}


def scan(name: str, data: bytes) -> dict:
    """Classify one uploaded file. Pure inspection of bytes; never executes anything."""
    ext = _ext(name)
    if len(data) > MAX_FILE:
        return _result(name, "blocked", f"file larger than {MAX_FILE // (1024 * 1024)} MB")
    if EICAR in data:
        return _result(name, "blocked", "matches the EICAR anti-virus test signature (treated as malware)")
    if ext in EXEC_EXT:
        return _result(name, "blocked", f"executable, script or macro file type (.{ext})")
    for sig, what in MAGIC:
        if data.startswith(sig):
            if sig == b"MZ" and b"PE\x00\x00" not in data[:4096] and b"This program" not in data[:1024]:
                continue                       # a text file that merely starts with "MZ"
            return _result(name, "blocked", what)
    if data[:4] == b"PK\x03\x04" and ext not in ("zip",):
        try:
            with zipfile.ZipFile(io.BytesIO(data)) as z:
                if any(n.lower().endswith("vbaproject.bin") for n in z.namelist()):
                    return _result(name, "blocked", "Office document with macros (vbaProject.bin)")
        except zipfile.BadZipFile:
            pass
    if ext in ("html", "htm", "svg", "xhtml", "xml") and SCRIPT_TEXT.search(data[:2_000_000]):
        return _result(name, "blocked", "markup with active script content")
    if data[:5] == b"%PDF-" or ext == "pdf":
        return _scan_pdf(name, data)
    if ext in IMAGE_EXT:
        return _scan_image(name, data)
    return _result(name, "clean", "no executable or active content found")


def _scan_pdf(name: str, data: bytes) -> dict:
    try:
        import pymupdf
    except ImportError:  # pragma: no cover
        try:
            import fitz as pymupdf
        except ImportError:
            return _result(name, "clean", "PDF reader not installed; the engine will quarantine it")
    try:
        with pymupdf.open(stream=data, filetype="pdf") as doc:
            if doc.needs_pass or doc.is_encrypted:
                return _result(name, "blocked", "password-protected or encrypted PDF: it cannot be inspected, "
                                                "so it is not released")
            if doc.page_count > MAX_PAGES:
                return _result(name, "blocked", f"more than {MAX_PAGES} pages (denial-of-service guard)")
            if doc.page_count == 0:
                return _result(name, "blocked", "empty or damaged PDF")
    except Exception:  # noqa: BLE001
        return _result(name, "blocked", "damaged PDF that cannot be parsed safely")
    found = sorted({what for rx, what in PDF_ACTIVE if re.search(rx, data)})
    if found:
        return _result(name, "neutralized", "active content removed from the released copy", found)
    return _result(name, "clean", "no active content found")


def _scan_image(name: str, data: bytes) -> dict:
    try:
        from PIL import Image
        Image.MAX_IMAGE_PIXELS = MAX_PIXELS
        with Image.open(io.BytesIO(data)) as im:
            w, h = im.size
            if w * h > MAX_PIXELS:
                return _result(name, "blocked", "image too large to decode safely (decompression-bomb guard)")
            im.verify()
    except Exception as exc:  # noqa: BLE001
        if "decompression bomb" in str(exc).lower():
            return _result(name, "blocked", "image too large to decode safely (decompression-bomb guard)")
        return _result(name, "blocked", "damaged or disguised image file")
    return _result(name, "clean", "image header and size checked")


def scan_zip_entry(info: zipfile.ZipInfo) -> str | None:
    """Reason to refuse one archive member, or None when it may be extracted (in memory only)."""
    name = info.filename.replace("\\", "/")
    if info.flag_bits & 0x1:
        return "encrypted archive entry: cannot be inspected"
    if name.startswith("/") or re.match(r"^[A-Za-z]:", name) or ".." in name.split("/"):
        return "path escapes the archive folder (zip-slip attack)"
    if info.file_size > MAX_FILE:
        return "archive entry too large"
    if info.compress_size and info.file_size / max(1, info.compress_size) > 200 and info.file_size > 5 * 1024 * 1024:
        return "compression ratio above 200:1 (zip bomb)"
    if name.lower().endswith((".zip", ".rar", ".7z", ".tar", ".gz")):
        return "nested archive (not unpacked)"
    return None
