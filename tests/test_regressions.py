"""Regression tests for fixes made after testing on unseen data. Each case runs main.py on a tiny
synthetic input and checks the release. Usage: python tests/test_regressions.py"""
from __future__ import annotations

import json
import os
import subprocess
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def run(files: dict) -> Path:
    tmp = Path(tempfile.mkdtemp(prefix="incogrx_reg_"))
    for rel, text in files.items():
        p = tmp / "in" / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(text, encoding="utf-8")
    subprocess.run([sys.executable, str(ROOT / "main.py"), "--input", str(tmp / "in"), "--output", str(tmp / "out")],
                   check=True, capture_output=True, env=dict(os.environ, RAKSHA_SECRET="regression"))
    return tmp / "out"


def released(out: Path) -> str:
    return "\n".join(p.read_text(encoding="utf-8") for p in sorted((out / "sanitized").rglob("*")) if p.is_file())


def records(out: Path) -> list:
    return [json.loads(x) for x in (out / "records.jsonl").read_text(encoding="utf-8").splitlines() if x.strip()]


def main() -> int:
    fails = 0

    def check(name: str, ok: bool, detail: str = "") -> None:
        nonlocal fails
        fails += not ok
        print(f"{'PASS' if ok else 'FAIL'} {name}{(': ' + detail) if detail and not ok else ''}")

    # 1. a person's name used as a JSON key; clinical and field keys stay
    out = run({"misc/index.json": json.dumps({"Vihana_Bisht": {"test": "TSH 3.2 mIU/L"},
                                              "Blood_Pressure": {"value": "120/80 mmHg"},
                                              "Lab_Results": {"Haemoglobin": "11.2 g/dL"}})})
    txt = released(out)
    check("name used as a JSON key is removed", "Vihana" not in txt and "Bisht" not in txt)
    check("clinical JSON keys and values kept", all(k in txt for k in ("Blood_Pressure", "Lab_Results",
                                                                       "TSH 3.2 mIU/L", "120/80 mmHg")))

    # 2. JSONL: one record per line, the pseudonym inside each record
    lines = [{"patient_name": "Aarav Menon", "hospital_id": "H1-UHID-100400", "phone": "+91 9003167600",
              "diagnosis": "dengue fever"},
             {"patient_name": "Ishita Rao", "hospital_id": "H2-UHID-100401", "phone": "+91 9003175519",
              "diagnosis": "asthma"}]
    out = run({"visits.jsonl": "\n".join(json.dumps(x) for x in lines) + "\n"})
    rec = records(out)
    rel = [json.loads(x) for x in (out / "sanitized/visits.jsonl").read_text().splitlines()]
    check("JSONL gives one record per line", [r["loc"] for r in rec] == ["/0", "/1"])
    check("JSONL pseudonym appears inside its line",
          all(r["patient"] and r["patient"] in json.dumps(o) for r, o in zip(rec, rel)))

    # 3. same name, different hospital ID and phone: two people, never merged
    same = [{"patient_name": "Aarav Menon", "hospital_id": "H1-UHID-100400", "phone": "+91 9003167600",
             "relative": "S/o Mohan Menon", "diagnosis": "dengue fever"},
            {"patient_name": "Aarav Menon", "hospital_id": "H1-UHID-100420", "phone": "+91 9003325980",
             "relative": "S/o Mohan Menon", "diagnosis": "asthma"}]
    out = run({"a.json": json.dumps({"records": same})})
    ps = [r["patient"] for r in records(out)]
    check("homonyms with different IDs and phones stay apart", len(ps) == 2 and ps[0] != ps[1], str(ps))

    # 4. the same Aadhaar with a name that does not transliterate: one person
    out = run({"reg.csv": "Name,Aadhaar,DOB\nRamesh Yadav,2345 6789 0123,12/04/1977\n",
               "lab.csv": "Patient Name,Aadhaar,Test\nRamesh Yadava,2345 6789 0123,TSH 3.2\n"})
    ps = [r["patient"] for r in records(out)]
    check("one Aadhaar links despite a spelling change", len(set(ps)) == 1 and ps[0] is not None, str(ps))

    # 5. a register of many patients in one text file is not given one patient's pseudonym
    names = ["Ramesh Yadav", "Sita Devi", "Aman Gupta", "Kavya Rao", "Imran Khan", "Neha Bansal"]
    reg = "".join(f"Patient Name: {n}, Mobile +91 98{i:08d}\n" for i, n in enumerate(names))
    out = run({"register.txt": reg})
    check("multi-patient text file stays unlinked", records(out)[0]["patient"] is None)

    # 6. ages become 20-year bands that contain the true age
    out = run({"p.csv": "Patient Name,Age,Diagnosis\nRamesh Yadav,47,asthma\nSita Devi,63,TB\nAman Gupta,8,fever\n"})
    rel = (out / "sanitized/p.csv").read_text()
    check("age bands are 20 years wide and contain the age", all(b in rel for b in ("40-59", "60-79", "0-19")), rel)

    print(f"\n8 checks, {fails} failure(s)")
    return 1 if fails else 0


if __name__ == "__main__":
    sys.exit(main())
