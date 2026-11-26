"""Vercel function for the hosted demo website (POST /api/run). Not part of the graded run.

The same work as demo/app.py: security scan, the main.py engine in a subprocess, the release.
Vercel keeps nothing between requests, so everything the page needs (summary, previews, released
files and the zip) comes back in this one response, within Vercel's 4.5 MB response limit.
Vercel has no Tesseract and no PyMuPDF: PDFs and images are quarantined here, and the local demo
(python demo/app.py) reads them."""
from __future__ import annotations

import base64
import io
import json
import shutil
import sys
import zipfile
from email.parser import BytesParser
from email.policy import default as email_policy
from http.server import BaseHTTPRequestHandler
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "demo"))

import app as demo  # noqa: E402
import security  # noqa: E402

MAX_BODY = 4_400_000            # Vercel rejects request bodies over 4.5 MB
MAX_RESPONSE = 4_000_000        # stay under Vercel's 4.5 MB response limit
NOTE = ("PDFs, scans and photos are read by the local demo (python demo/app.py), which has OCR. "
        "The hosted site quarantines them, so nothing from them is released.")

try:                              # no Pillow on Vercel: images are never decoded here, so the
    import PIL  # noqa: F401      # decompression-bomb check is not needed; the engine quarantines them
except ImportError:
    security._scan_image = lambda name, data: security._result(
        name, "clean", "image not opened on the hosted site; quarantined by the engine")


def parse_form(ctype: str, body: bytes) -> tuple:
    msg = BytesParser(policy=email_policy).parsebytes(
        b"Content-Type: " + ctype.encode("latin-1") + b"\r\nMIME-Version: 1.0\r\n\r\n" + body)
    fields, files = {}, []
    for part in msg.iter_parts():
        name = part.get_param("name", header="content-disposition")
        data = part.get_payload(decode=True) or b""
        if part.get_filename() is not None:
            files.append((part.get_filename(), data))
        elif name:
            fields[name] = data.decode("utf-8", "replace")
    return fields, files


def build(fields: dict, uploads: list) -> dict:
    mode, secret = fields.get("mode"), fields.get("secret", "")
    scans = []
    if mode == "text":
        text = fields.get("text", "")
        if not text.strip():
            raise ValueError("Paste some text first.")
        files = [("pasted_note.txt", text.encode("utf-8"))]
    elif mode == "files":
        files, total = [], 0
        for path, data in uploads:
            for rel, member in demo.expand_zip(path, data, scans):
                total += len(member)
                if total > demo.MAX_UPLOAD:
                    raise ValueError("Upload is larger than 80 MB.")
                files.append((rel, member))
        if not files and scans:
            raise ValueError("Every file was blocked by the security scan: " +
                             "; ".join(f"{x['name']}: {x['reason']}" for x in scans)[:600])
        if not files:
            raise ValueError("Choose at least one file.")
    else:
        raise ValueError("Unknown mode.")
    result = demo.run_job(files, secret, scans if mode == "files" else None)
    work = demo.JOBS.pop(result["job"], None)
    try:
        out = work / "output" if work else None
        for f in result["files"]:
            if mode == "files":
                f.pop("before", None)          # uploaded originals are never sent back
            note = f.get("note") or ""
            if "PyMuPDF" in note or note.startswith("Scanned"):
                f["note"] = NOTE
        result["hosted"] = True
        attach(result, out)
    finally:
        if work:
            shutil.rmtree(work, ignore_errors=True)
    return result


def attach(result: dict, out: Path | None) -> None:
    """Released files and the zip, as base64, as far as the response budget allows."""
    if out is None or not out.exists():
        return
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as z:
        for p in sorted(out.rglob("*")):
            if p.is_file():
                z.write(p, p.relative_to(out).as_posix())
    budget = MAX_RESPONSE - len(json.dumps(result, ensure_ascii=False).encode("utf-8")) - 20000
    zb = base64.b64encode(buf.getvalue()).decode("ascii")
    if len(zb) < budget:
        result["zip_b64"] = zb
        budget -= len(zb)
    else:
        result["zip_note"] = "The release is too large to download from the hosted site; run the local demo."
    inline = {}
    for p in sorted(out.rglob("*"), key=lambda q: q.stat().st_size if q.is_file() else 0):
        if not p.is_file():
            continue
        b = base64.b64encode(p.read_bytes()).decode("ascii")
        if len(b) + 200 > budget:
            break
        inline[p.relative_to(out).as_posix()] = b
        budget -= len(b) + 200
    result["inline"] = inline


def shrink(result: dict) -> bytes:
    """Keep the response under Vercel's limit even for very large batches."""
    body = json.dumps(result, ensure_ascii=False).encode("utf-8")
    for step in ("inline", "zip_b64", "previews", "files"):
        if len(body) <= MAX_RESPONSE:
            break
        if step in ("inline", "zip_b64"):
            result.pop(step, None)
        elif step == "previews":
            for f in result.get("files", []):
                for k in ("after", "before"):
                    if isinstance(f.get(k), str) and len(f[k]) > 1500:
                        f[k] = f[k][:1500]
                        f["truncated"] = True
        else:
            n = len(result.get("files", []))
            result["files"] = result.get("files", [])[:300]
            result["files_note"] = f"Showing 300 of {n} files; the counts cover all of them."
        body = json.dumps(result, ensure_ascii=False).encode("utf-8")
    return body


class handler(BaseHTTPRequestHandler):  # noqa: N801  (name required by Vercel)
    def _send(self, code: int, body: bytes, ctype: str = "application/json; charset=utf-8") -> None:
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.end_headers()
        self.wfile.write(body)

    def _error(self, code: int, msg: str) -> None:
        self._send(code, json.dumps({"error": msg}).encode("utf-8"))

    def do_GET(self) -> None:  # noqa: N802
        self._send(200, json.dumps({"ok": True, "engine": "IncogRx", "hosted": True}).encode("utf-8"))

    def do_POST(self) -> None:  # noqa: N802
        try:
            length = int(self.headers.get("Content-Length", "0"))
            if length <= 0:
                raise ValueError("Upload is empty.")
            if length > MAX_BODY:
                raise ValueError("The hosted site accepts up to about 4 MB per run. Split the batch, "
                                 "or run the local demo (python demo/app.py) for larger ones.")
            body = self.rfile.read(length)
            ctype = self.headers.get("Content-Type", "")
            if ctype.startswith("multipart/form-data"):
                fields, uploads = parse_form(ctype, body)
            else:
                req = json.loads(body.decode("utf-8"))
                fields = {k: str(v) for k, v in req.items() if k in ("mode", "secret", "text")}
                uploads = [(str(f["path"]), base64.b64decode(f["b64"])) for f in req.get("files") or []]
            self._send(200, shrink(build(fields, uploads)))
        except (ValueError, KeyError, json.JSONDecodeError) as exc:
            self._error(400, str(exc) or "Bad request.")
        except Exception:  # noqa: BLE001  never echo internals: they may contain file names
            self._error(500, "The pipeline could not process this input.")
