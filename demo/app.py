#!/usr/bin/env python3
"""IncogRx demo UI: a local, offline web page to try the firewall on your own files or text.

    python demo/app.py            then open http://127.0.0.1:8765

Standard library only. Every run calls the same `main.py` the evaluator runs (in a separate
process), so the demo shows exactly what the scored pipeline does. The server listens on
127.0.0.1 only; uploads and results live in a temporary folder that is deleted on exit."""
from __future__ import annotations

import atexit
import base64
import hashlib
import io
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
import threading
import time
import uuid
import webbrowser
import zipfile
from collections import Counter, defaultdict
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path, PurePosixPath

DEMO = Path(__file__).resolve().parent
ROOT = DEMO.parent
MAIN = ROOT / "main.py"
HOST = "127.0.0.1"
PORT = int(os.environ.get("INCOGRX_DEMO_PORT", "8765"))
MAX_UPLOAD = 80 * 1024 * 1024          # bytes of decoded upload per run
PREVIEW = 30000                         # characters shown per file
KEEP_JOBS = 5

sys.path.insert(0, str(ROOT))
from incog.readers import decode  # noqa: E402  (same decoder as the pipeline, for the "before" view)

TAG_RX = re.compile(r"\[(NAME|RELATIVE|PHONE|AADHAAR|ABHA|PAN|EMAIL|MRN|ID|INSURANCE_ID|DOB|PIN|ADDRESS|HOUSE|"
                    r"LOCALITY|LANDMARK|VILLAGE|TEHSIL)\]")
PSN_RX = re.compile(r"PSN-[0-9A-Z]{6}")
JOBS: dict = {}
LOCK = threading.Lock()


def _cleanup_all() -> None:
    for work in list(JOBS.values()):
        shutil.rmtree(work, ignore_errors=True)


atexit.register(_cleanup_all)


def safe_rel(path: str) -> Path:
    """Keep an uploaded relative path inside the job folder (no '..', no absolute paths)."""
    parts = [p for p in PurePosixPath(path.replace("\\", "/")).parts if p not in ("", ".", "..", "/")]
    if not parts:
        raise ValueError("empty path")
    return Path(*parts)


def run_job(files: list, secret: str) -> dict:
    work = Path(tempfile.mkdtemp(prefix="incogrx_demo_"))
    inp, out = work / "input", work / "output"
    inp.mkdir()
    for rel, data in files:
        dst = inp / safe_rel(rel)
        dst.parent.mkdir(parents=True, exist_ok=True)
        dst.write_bytes(data)
    env = dict(os.environ, RAKSHA_SECRET=secret or "demo-secret")
    t0 = time.time()
    proc = subprocess.run([sys.executable, str(MAIN), "--input", str(inp), "--output", str(out)],
                          env=env, capture_output=True, text=True, timeout=900)
    wall = time.time() - t0
    if proc.returncode != 0 or not (out / "report.json").exists():
        shutil.rmtree(work, ignore_errors=True)
        raise RuntimeError("The pipeline could not process this input.")
    job = uuid.uuid4().hex[:12]
    with LOCK:
        JOBS[job] = work
        while len(JOBS) > KEEP_JOBS:
            old = next(iter(JOBS))
            shutil.rmtree(JOBS.pop(old), ignore_errors=True)
    return summarize(job, inp, out, wall)


def _read_text(p: Path) -> str:
    try:
        return decode(p.read_bytes())
    except Exception:  # noqa: BLE001
        return "(binary or unreadable file)"


def summarize(job: str, inp: Path, out: Path, wall: float) -> dict:
    report = json.loads((out / "report.json").read_text(encoding="utf-8"))
    records = [json.loads(x) for x in (out / "records.jsonl").read_text(encoding="utf-8").splitlines() if x.strip()]
    sha2in = {hashlib.sha256(p.read_bytes()).hexdigest(): p for p in inp.rglob("*") if p.is_file()}
    tags: Counter = Counter()
    files = []
    for f in report["files"]:
        src = sha2in.get(f["input_sha256"])
        entry = {"input": src.relative_to(inp).as_posix() if src else "?", "status": f["status"],
                 "reason": f.get("reason"), "output": f.get("output")}
        if src is not None:
            before = _read_text(src)
            entry["before"] = before[:PREVIEW]
        if f.get("output"):
            after = (out / f["output"]).read_text(encoding="utf-8", errors="replace")
            found = TAG_RX.findall(after)
            tags.update(found)
            entry["after"] = after[:PREVIEW]
            entry["truncated"] = len(after) > PREVIEW
            entry["removed"] = len(found)
            entry["pseudonyms"] = sorted(set(PSN_RX.findall(after)))
        files.append(entry)
    files.sort(key=lambda e: (e["status"] != "sanitized", e["input"]))
    pats = defaultdict(lambda: {"records": 0, "files": set()})
    for r in records:
        if r.get("patient"):
            pats[r["patient"]]["records"] += 1
            pats[r["patient"]]["files"].add(r["file"].removeprefix("sanitized/"))
    patients = sorted(({"pseudonym": k, "records": v["records"], "files": sorted(v["files"])} for k, v in pats.items()),
                      key=lambda x: (-len(x["files"]), -x["records"], x["pseudonym"]))
    return {"job": job, "counts": report["counts"], "timing": report.get("timing", {}),
            "resources": report.get("resources", {}), "wall_seconds": round(wall, 2),
            "tags": dict(tags.most_common()), "files": files, "patients": patients,
            "unlinked": sum(1 for r in records if not r.get("patient"))}


def zip_job(job: str) -> bytes | None:
    with LOCK:
        work = JOBS.get(job)
    if work is None or not (work / "output").exists():
        return None
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as z:
        for p in sorted((work / "output").rglob("*")):
            if p.is_file():
                z.write(p, p.relative_to(work / "output").as_posix())
    return buf.getvalue()


class Handler(BaseHTTPRequestHandler):
    server_version = "IncogRxDemo/1.0"

    def log_message(self, *args) -> None:   # no request logs: paths and payloads may hold personal data
        return

    def _send(self, code: int, body: bytes, ctype: str, extra: dict | None = None) -> None:
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        for k, v in (extra or {}).items():
            self.send_header(k, v)
        self.end_headers()
        self.wfile.write(body)

    def _json(self, code: int, obj) -> None:
        self._send(code, json.dumps(obj, ensure_ascii=False).encode("utf-8"), "application/json; charset=utf-8")

    def do_GET(self) -> None:  # noqa: N802
        if self.path in ("/", "/index.html"):
            self._send(200, (DEMO / "index.html").read_bytes(), "text/html; charset=utf-8")
        elif self.path.startswith("/api/download/"):
            data = zip_job(self.path.rsplit("/", 1)[-1])
            if data is None:
                self._json(404, {"error": "Result expired. Run again."})
            else:
                self._send(200, data, "application/zip",
                           {"Content-Disposition": 'attachment; filename="incogrx_output.zip"'})
        else:
            self._json(404, {"error": "not found"})

    def do_POST(self) -> None:  # noqa: N802
        if self.path != "/api/run":
            self._json(404, {"error": "not found"})
            return
        try:
            length = int(self.headers.get("Content-Length", "0"))
            if length <= 0 or length > MAX_UPLOAD * 2:
                raise ValueError("Upload is empty or too large.")
            req = json.loads(self.rfile.read(length).decode("utf-8"))
            mode, secret = req.get("mode"), str(req.get("secret") or "")
            if mode == "text":
                text = str(req.get("text") or "")
                if not text.strip():
                    raise ValueError("Paste some text first.")
                files = [("pasted_note.txt", text.encode("utf-8"))]
            elif mode == "files":
                files, total = [], 0
                for f in req.get("files") or []:
                    data = base64.b64decode(f["b64"])
                    total += len(data)
                    files.append((str(f["path"]), data))
                if not files:
                    raise ValueError("Choose at least one file.")
                if total > MAX_UPLOAD:
                    raise ValueError("Upload is larger than 80 MB.")
            else:
                raise ValueError("Unknown mode.")
            self._json(200, run_job(files, secret))
        except (ValueError, KeyError, json.JSONDecodeError) as exc:
            self._json(400, {"error": str(exc) or "Bad request."})
        except Exception:  # noqa: BLE001  never echo internals: they may contain file names
            self._json(500, {"error": "The pipeline could not process this input."})


def main() -> int:
    httpd = ThreadingHTTPServer((HOST, PORT), Handler)
    url = f"http://{HOST}:{PORT}"
    print(f"IncogRx demo running at {url}  (Ctrl+C to stop)")
    if "--no-browser" not in sys.argv:
        threading.Timer(0.8, lambda: webbrowser.open(url)).start()
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        httpd.server_close()
        _cleanup_all()
    return 0


if __name__ == "__main__":
    sys.exit(main())
