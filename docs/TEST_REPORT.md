# IncogRx test report (27 Nov 2026)

Every figure below comes from a run of the current code on the stated inputs. Nothing was estimated.
The official validators were run unmodified.

## Results

| # | Test | Inputs | Expected | Actual | Result |
|---|------|--------|----------|--------|--------|
| 1 | Official practice data, `main.py` + `validate_output.py` | 200 files (dev/input) | CONTRACT OK | CONTRACT OK; 192 sanitized, 8 quarantined; 821 records; 1.9 s; 29.5 MB | PASS |
| 2 | `check_dev.py --show 10` | same | no leaks, no canaries, linking without false merges | 0 of 3,230 identifiers leaked (all 16 types, Latin, Devanagari, Hinglish, all hiding places); 0 of 4 canaries; medical values 4,682 of 4,855 (96.4%); linking precision 1.00, recall 1.00; 0 raw copies | PASS |
| 3 | `check_submission.py --repo . --run` | repository | READY TO SUBMIT | READY TO SUBMIT | PASS |
| 4 | Determinism and secret separation | practice, 2 secrets | same secret gives the same bytes; different secrets share no pseudonym | identical output; 0 of 49 pseudonyms shared | PASS |
| 5 | Detection traps (phase 2) | 58 traps | 58 | 58 | PASS |
| 6 | Linkage edge cases (phase 3) | 16 cases | 16 | 15 (bare first name with no other clue gets its own pseudonym, never merged) | 15/16 |
| 7 | Privacy engine (phase 4) | unit tests | OK | OK | PASS |
| 8 | Hardening (phase 5) | 20 attacks | 20 | 20 | PASS |
| 9 | Organizer test set, graded run | 18 files | text files released clean; EICAR and key file never released | 4 sanitized; EICAR `malware_signature`, key file `key_material`, `.aesgcm`, PDFs and PNGs `unsupported_format`; CONTRACT OK | PASS |
| 10 | Leak scan of that output (text, file names, base64 and hex decoded) | 32 names incl. Devanagari aliases, 120 IDs, 90 phones, 60 addresses, EICAR, key values, secret | 0 found | 0 found | PASS |
| 11 | Clinical fields in JSON and JSONL records | 120 records x 8 fields | unchanged | 960 of 960 unchanged | PASS |
| 12 | records.jsonl mapping | mixed_records.json / .jsonl | one entry per record, pseudonym inside the record, same record same pseudonym across files | 60 + 60 entries (`/records/N`, `/N`); pseudonym present in 60 of 60 JSONL lines; 60 of 60 cross-file pairs share a pseudonym; 0 false merges | PASS |
| 13 | Document mode, typed PDFs (25, 50, 80 pages) | 155 pages, 542 identifiers, 775 clinical values | 0 identifiers in released text, all clinical kept | 0 found; 775 of 775 kept; 39 unreadable name glyph runs blacked out | PASS |
| 14 | Visual check of every released PDF page (rendered at 200 dpi, OCR eng+hin) | 163 pages, 771 identifiers | 0 visible | 0 visible. Positive control on the unredacted 25-page PDF: 118 of 120 found | PASS |
| 15 | Handwritten notes (ground_truth.json) | 8 notes | names, UHIDs, phones removed; clinical kept | 0 identifiers left; clinical exact text 24 of 40 (see limitations); every suspect value flagged `CHECK` | PASS with limits |
| 16 | Hindi and Hinglish OCR (typed Devanagari images) | 6 images, 22 identifiers, 20 clinical values | names removed, clinical kept | 0 identifiers in text, 0 visible; 20 of 20 clinical values kept | PASS |
| 17 | Security pack (`tests/test_security_pack.py`) | 12 files: prompt injection, canaries, fake credentials, private key, key_hex file, EICAR in a CSV, symlink to /etc/passwd, base64 attachment, zip with `../`, opaque binary, truncated JSON | each file released clean or quarantined with the right reason; nothing forbidden in the output | 12 of 12 outcomes as expected; 0 of 29 forbidden strings; 6 of 6 clinical values kept | PASS |
| 18 | Multilingual false negatives and false positives (`tests/test_multilingual.py`) | 30 sentences: English, Devanagari, Hinglish, mixed | 46 personal items removed, 38 clinical or role items kept | 0 missed, 0 lost | PASS |
| 19 | Unseen-format, broken-and-odd and chaos sets (team laptop) | 3 sets + practice copy | output unchanged by this round, contract valid | byte-identical sanitized/, records.jsonl and report.json to the previous release on all 5 sets; broken-and-odd CONTRACT OK; unseen-format 0 of 3,230 leaked, medical 97.2%, linking precision 1.00, recall 0.87, 0 false merges | PASS |
| 20 | Re-identification, our replica of the published A2/A3/A4 attack (`devtools/attack.py`, 240-person registry) | practice release | as few patients identifiable as possible without losing medical values | 8 of 48 patients at confidence 0.5 or more (14 with 10-year age bands, 47 on the raw data); mean record risk 0.051; medical values unchanged at 96.4% | PASS |
| 21 | Regression tests (`tests/test_regressions.py`) | 8 checks | all pass | name used as a JSON key removed; clinical keys kept; JSONL per line; homonyms apart; one Aadhaar links a spelling change; register unlinked; 20-year bands | PASS |

## Count reconciliation (organizer test set, graded run)

* `records_processed` 122 = 60 JSONL lines + 60 JSON records + 2 text files.
* `records_linked` 120 = records that carry a pseudonym. The 2 text files are `null` on purpose: one lists about 30 different patients, the other is a set of malformed samples.
* 60 JSON/JSONL pairs are the same record and share a pseudonym. The 60 records within one file are 60 different people (same names, different UHID, phone, age and address), so none of them are merged.
* Clinical values tested: 960 = 120 records x 8 fields.
* Document mode reports 285 records = 163 page records (155 PDF pages, 8 notes) + the same 122.

## Changes in the third round (27 Nov, morning)

Measured on the 7,200-patient senior security test pack (46 files, graded `main.py`, `RAKSHA_SECRET=regress-key`):

| Measure | Before | After |
|---|---|---|
| Personal values leaked (name, Hindi name, phone, email, DOB, address, hospital ID, MRN) | 0 of 57,600 | 0 of 57,600 |
| Different patients sharing one pseudonym | 67 | 0 |
| One patient split across pseudonyms | 0 | 0 |
| Records with no pseudonym | 1,000 | 0 |
| Run time | 86.8 s | 61.2 s |

* Record numbers kept their letters only as digits, so `INC-00057` and `HOSP-00057` collided and chained four patients together. A distinctive prefix is now part of the key; generic labels (`MRN`, `UHID`) are still dropped so `MRN 123456` matches `123456`.
* A JSON file that is a top-level list of patients was one record with no pseudonym. It now gives one record per patient (`/0`, `/1`, ...).
* Name redaction scans word starts instead of one giant alternation, which is most of the speed gain.
* Blood pressure such as `130/75` is no longer redacted as an ID.

Document mode (`demo/run_documents.py`) on the organizer PDFs, handwriting and security files:

| Input | Personal values leaked | Clinical values kept | Time |
|---|---|---|---|
| 25, 50 and 80 page PDFs (155 pages) | 0 of 695 | doses, vitals, diagnoses, length of stay all present | 5 s |
| 20 handwriting samples (ground truth file) | 0 of 80 | 80 of 80 | about 0.5 s each |
| EICAR signature, key file, AES-GCM payload | all 3 blocked, never released | not applicable | under 1 s |

Two leaks were found by these runs and fixed: an initial-style name (`R. Das`) after a `Patient / <Hindi label>:` label whose Hindi word extracts as blanks, and a name that OCR misread by one letter (`Ira Kaur` read as `fra Kaur`) next to a common surname that is never removed on its own.

Red-team PDFs built for this round, all in document mode: patient name, phone and MRN in PDF metadata (wiped, 0 leaks); name and phone in the file name (renamed `NAME_PHONE.pdf`); encrypted PDF (blocked, reported as not inspectable); damaged PDF (blocked); JavaScript `OpenAction` (output is rebuilt without it, but the scan does not flag it as suspicious); a PDF named `.csv` (detected by content); one PDF holding three patients with a rotated page (three separate pseudonyms); an "ignore all previous rules" instruction inside the text (treated as data, the name and Aadhaar on that page removed).

The practice output is byte-identical before and after this round (report timing aside), and all checks above still pass.

## Changes in the second round

* Ages are now 20-year bands (`config/policy.yaml`). Measured against our attacker replica: 14 of 48 re-identified patients became 8, with no change to any medical-value or leak figure. 30-year bands gave 3 of 48 but would put children and adults in one band.
* A JSON key shaped like a person's name (`Vihana_Bisht`) is removed, unless its words are field, clinical or admin words or a district or tehsil seen in the data (phase 5 now 20 of 20).
* A matching Aadhaar number links two records even when the names do not transliterate cleanly, unless the birth dates disagree (unseen-format recall 0.86 to 0.87, still 0 false merges).
* Medical values lost on the practice data (3.6%) are all diagnoses held by 3 or fewer patients, shown as their ICD-10 chapter on purpose: the published attack weights a condition shared by at most three profiles by 8, so keeping them would hand the attacker its strongest signal.

## Defects found by these tests and fixed in the first round

1. JSONL was one document-level record with no pseudonym. It now has one record per line.
2. Same-name records with different UHID and phone were merged (14 false clusters). A shared name no longer outweighs both identifiers disagreeing.
3. A text file listing many patients received one patient's pseudonym. It now stays unlinked.
4. Canary tokens and credential values were released. They now become `[SECRET]`.
5. A base64 attachment inside a longer text line was released decoded-readable. It is now decoded, cleaned and re-encoded.
6. A symlink to `/etc/passwd` was followed. It is now quarantined (`symlink`) in the graded run and blocked in document mode.
7. OCR reads `नाम:` as `नामः`. The label now matches.
8. `कविता रेड्डी पत्नी राजेश रेड्डी` left the first name. It is now removed.
9. `Aarav Menon (आरव मेनन)` with no other context leaked. It is now removed.
10. `Relative:` was not a label. It now is.

## Remaining limitations

* OCR loses the micro sign (`µL` becomes `uL`) and sometimes a decimal point. These are flagged for review, never corrected by guessing. That accounts for 8 of the 16 handwritten misses.
* The other 8 misses are vitals: the note images show only `BP x/y mmHg`, while the ground truth also lists pulse and SpO2.
* The Devanagari names in the test PDFs are drawn with a font that has no Unicode map, and they render as empty boxes in the source itself. No OCR can recover them, so they are blacked out and marked `[UNREADABLE]`.
* Real handwritten Devanagari was not available. Only typed Devanagari images were tested, and low-confidence OCR words are hidden.
* JSONL is not an official input format, and its locator (`/N`) is our choice.
* Not built: AES-GCM key management (the pipeline never decrypts anything; key files are quarantined), trained ML or CRF models, and a module restructure. These were left out to avoid destabilising a passing system hours before the deadline.
