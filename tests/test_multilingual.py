"""False-negative and false-positive checks for English, Hindi (Devanagari) and Hinglish free text.

Each case: a sentence, the strings that must NOT survive (personal data) and the strings that MUST
survive (clinical meaning, doctors, roles). Runs the real text cleaner with no learned names, so
detection comes from context alone. Usage: python tests/test_multilingual.py"""
from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from incog.sanitize import clean_text  # noqa: E402

CASES = [
    # ---- English
    ("en", "Patient Name: Rohit Saxena, Mobile +91 9123456780", ["Rohit", "Saxena", "9123456780"], ["Patient Name"]),
    ("en", "Mr. Anil Kapoor admitted with dengue fever. Dolo 650 mg BD x 5 days.", ["Anil", "Kapoor"],
     ["dengue fever", "Dolo 650 mg BD x 5 days"]),
    ("en", "Seen by Dr. Ramesh Iyer. C/O fever and cough since 3 days.", [], ["Dr. Ramesh Iyer", "C/O fever", "3 days"]),
    ("en", "Relative: Sunil Verma S/o Mahesh Verma, contact 9876543210", ["Sunil", "Mahesh", "9876543210"], ["Relative"]),
    ("en", "Aadhaar 4821 7736 1290, PAN ABCPK1234F, UHID: SJH-2024-88412", ["4821 7736 1290", "ABCPK1234F", "88412"], []),
    ("en", "Rx Ramipril 5 mg OD; Metformin 500 mg 1-0-1; BP 120/80 mmHg; Hb 11.2 g/dL", [],
     ["Ramipril 5 mg OD", "Metformin 500 mg 1-0-1", "BP 120/80 mmHg", "Hb 11.2 g/dL"]),
    ("en", "Diagnosis: Parkinson's disease. Platelets 1.45 lakh/µL, creatinine 0.9 mg/dL.", [],
     ["Parkinson's disease", "1.45 lakh/µL", "0.9 mg/dL"]),
    ("en", "Lab report reviewed by ASHA worker; Ward 9 (Medicine), Bed 12.", [], ["ASHA worker", "Ward 9 (Medicine)"]),
    ("en", "email: rohit.saxena@example.in", ["rohit.saxena@example.in"], ["email"]),
    ("en", "Ref CANARY-SECRET-WARDS-DO-NOT-LEAK-7F3A91; password: Tr0ub4dor&3", ["CANARY-SECRET", "Tr0ub4dor"], []),
    # ---- Hindi (Devanagari)
    ("hi", "मरीज़ का नाम: इमरान कुरैशी", ["इमरान", "कुरैशी"], ["मरीज़ का नाम"]),
    ("hi", "नाम: मीरा नायर, मोबाइल: 9811122233", ["मीरा", "नायर", "9811122233"], []),
    ("hi", "नामः विक्रम जोशी", ["विक्रम", "जोशी"], []),
    ("hi", "पिता का नाम: सलीम कुरैशी", ["सलीम"], ["पिता का नाम"]),
    ("hi", "कविता रेड्डी पत्नी राजेश रेड्डी", ["कविता", "राजेश"], ["पत्नी"]),
    ("hi", "रोगी: फ़राह ख़ान, पता: मकान नं. 398, ग्राम रामपुर", ["फ़राह", "398", "रामपुर"], []),
    ("hi", "डॉ. रमेश शर्मा द्वारा देखा गया। बुखार 3 दिन से।", [], ["डॉ. रमेश शर्मा", "बुखार 3 दिन"]),
    ("hi", "मोबाइल: ९८१११२२२३३", ["९८१११२२२३३"], []),
    ("hi", "निदान: मधुमेह; दवा: Metformin 500 mg 1-0-1", [], ["मधुमेह", "Metformin 500 mg 1-0-1"]),
    # ---- Hinglish and mixed script
    ("hinglish", "Mareez ka naam: Farah Khan, Pati ka naam: Imtiaz Khan", ["Farah", "Imtiaz"], ["Mareez ka naam"]),
    ("hinglish", "Ramesh bhai ka BP 150/90 hai, Sunita didi saath aayi", ["Ramesh", "Sunita"], ["BP 150/90"]),
    ("hinglish", "Arif sahab ko Dolo 650 mg BD x 5 days diya", ["Arif"], ["Dolo 650 mg BD x 5 days"]),
    ("hinglish", "Patient ka naam hai Pooja Yadav, umar 34", ["Pooja", "Yadav"], []),
    ("mixed", "Aarav Menon (आरव मेनन) admitted. C/O fever.", ["Aarav", "Menon", "आरव", "मेनन"], ["C/O fever"]),
    ("mixed", "Patient Name: Aarav Menon / आरव मेनन, phone +91 9004751400", ["आरव", "मेनन", "9004751400"], []),
    ("mixed", "Mr. Imran Qureshi ji (इमरान कुरैशी) admitted", ["Imran", "इमरान", "कुरैशी"], ["admitted"]),
    ("mixed", "C/O Ramesh Kumar, village Rampur", ["Ramesh"], ["C/O"]),
    ("mixed", "Dolo Tablet (डोलो) given; Paracetamol Syrup (पैरासिटामोल सिरप)", [], ["Dolo Tablet", "डोलो", "पैरासिटामोल सिरप"]),
    ("mixed", "Viral Fever (वायरल बुखार) at Sanjeevani Hospital (संजीवनी अस्पताल)", [], ["Viral Fever", "वायरल बुखार", "Sanjeevani Hospital"]),
    ("mixed", "Kal OPD mein aaye; café naïve — हिन्दी", [], ["Kal OPD mein aaye", "हिन्दी"]),
]


def main() -> int:
    fn = fp = 0
    for lang, text, gone, kept in CASES:
        out = clean_text(text, None)
        miss = [g for g in gone if g in out]
        lost = [k for k in kept if k not in out]
        fn += len(miss)
        fp += len(lost)
        mark = "PASS" if not miss and not lost else "FAIL"
        print(f"{mark} [{lang}] {out}")
        if miss:
            print(f"     still visible: {miss}")
        if lost:
            print(f"     clinical/role text lost: {lost}")
    n_gone = sum(len(c[2]) for c in CASES)
    n_kept = sum(len(c[3]) for c in CASES)
    print(f"\n{len(CASES)} cases | personal items {n_gone}, missed {fn} | kept items {n_kept}, lost {fp}")
    return 1 if fn or fp else 0


if __name__ == "__main__":
    sys.exit(main())
