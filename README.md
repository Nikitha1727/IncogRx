# IncogRx

**Team Knull Void · Track 3: Secret Wards (Yugaantar DevForge)**
Members: Shivanshu, Nikitha, Radhika, Abhishek

IncogRx is an offline, CPU-only, LLM-free privacy firewall for Indian hospital records written in English, Hindi (Devanagari) and Hinglish. It removes direct identifiers, gives every real patient one stable keyed pseudonym across files, scripts and hospitals, shifts dates per patient, and generalises the quasi-identifiers that let an attacker single a person out, while keeping the clinical content usable for research.

---

## 1. Quick start

```bash
pip install -r requirements.txt          # nothing to install: standard library only
RAKSHA_SECRET=<release secret> python main.py --input <input dir> --output <output dir>
```

* Python 3.10 or newer. No network, no GPU, no models.
* `RAKSHA_SECRET` keys every pseudonym and date shift. It is never written anywhere.
* Only counts are printed. A fatal error prints only its type, never a path or a value.

Output (as required by the track contract):

| Path | Content |
|---|---|
| `sanitized/` | every input file, same folders and formats, UTF-8, personal data removed or generalised |
| `report.json` | per-file status (sanitized or quarantined with a reason), counts, timing, peak memory |
| `records.jsonl` | one line per record: `file`, input `loc` (`row:N`, JSON pointer or `doc`), `patient` pseudonym or `null` |

---

## 2. Architecture

```
input files
   │
   ▼
[1] Ingestion        readers.py   encodings (UTF-8, BOM, UTF-16, cp1252), CSV/TSV/JSON/JSONL/text,
   │                              delimiter sniffing, safe quarantine of broken or unsupported files
   ▼
[2] Learning pass    pipeline.py  read structured fields and labelled text; learn IDs, MRN shapes,
   │  (x2)           sniff.py     name tokens, villages, district/tehsil names, rare diagnoses;
   │                              2nd round classifies unfamiliar columns from their values
   ▼
[3] Linking          link.py      per-record evidence -> clusters -> HMAC pseudonym per patient
   │
   ▼
[4] Sanitising       fields.py, detect.py, textner.py, sanitize.py
   │                              structured fields by category, free text by context,
   │                              keys, CSV headers, file names, base64 attachments
   ▼
[5] Privacy layer    dates.py, privacy.py   per-patient date shift, age bands, district only,
   │                                        DOB suppression, rare-condition generalisation
   ▼
sanitized/  +  records.jsonl  +  report.json
```

---

## 3. How each part works

### 3.1 Ingestion (`incog/readers.py`)
* Decodes UTF-8, UTF-8 with BOM, UTF-16 and legacy cp1252. Stray NUL or BOM bytes in the middle of a file mark it `corrupt_encoding`.
* Picks the CSV delimiter that splits the header and rows consistently (`,`, tab, `;`, `|`).
* Quarantines, never copies raw: empty files, unsupported formats (XML, PDF, images), malformed or truncated JSON, JSON nested deeper than 120 levels, and JSON hidden behind a `.csv` extension. Two kinds of file are quarantined whatever their extension, before any parsing: anything carrying the EICAR anti-virus test signature (`malware_signature`) and cryptographic key material such as private keys or `key_hex=` / `nonce_hex=` values (`key_material`); their content is never logged or released. Symbolic links are never followed (`symlink`), and a file over 1 GB is hashed in chunks and quarantined without loading it (`file_too_large`). Every quarantined file is listed in `report.json` with its reason.

### 3.2 Detection
**Structured fields** (`incog/fields.py`). Column names and JSON paths are classified in English, Hinglish and Devanagari (`Naam`, `Pita/Pati ka Naam`, `Gaon`, `Janm Tithi`, `मरीज़ का नाम`). The parent decides ambiguous keys: a `name` under `contact` is a relative, under `Practitioner` or `Organization` it is kept, and a FHIR extension is classified by its `url`.

**Unfamiliar columns** (`incog/sniff.py`). A column the vocabulary does not recognise is classified from its values: Aadhaar, ABHA, PAN, phone and PIN shapes; values matching MRN shapes learned elsewhere in the release; relation prefixes (`S/o`, `son of`); address words; birth-year distributions; and overlap with learned name and village tokens. This is what keeps linking and redaction working when the hidden data renames "UHID" to "Hosp Regn ID".

**Free text** (`incog/textner.py`, `incog/detect.py`).
* Identifier patterns with Indian formats: Aadhaar (plain and masked), ABHA, PAN, phones with `+91`, PMJAY and policy IDs, labelled MRN, DOB and PIN; Devanagari digits are normalised first.
* Labels: `Patient Name:`, `मरीज़ का नाम:`, `रोगी:`, `पिता का नाम:`, `Attendant:`, `Address:`, `पता:`, `निवास:`.
* Context: relation markers (`S/o`, `W/o`, `D/o`, `C/O` + capitalised name, `पुत्र`, `पत्नी`), Hinglish honorifics (`Asha ji`, `Mahesh bhai`, `Kamal Bhaiya`, `Fatima amma`, `जी`, `भैया`), possessives (`Asha's attendant`), WhatsApp senders, and cue phrases (`called by`, `brought by`, visitor-log lines). These cues are how canary identities, which appear nowhere else, are caught.
* Addresses inside text: house numbers (`House 364`, `मकान नं. 398`), mohallas, landmarks (`near Panchayat Bhawan`, `पंचायत भवन के पास`) and villages (`Vill.`, `Gram`, `ग्राम`).
* Script pairs and aliases: a Latin name followed by its Devanagari spelling in brackets (or the reverse) is removed on context alone, and a name written again in the other script right beside a removed name (`Aarav Menon (आरव मेनन)`, `Patient [NAME] / मीरा नायर`, also after an honorific) is the same person and is removed too.
* A gazetteer of name tokens learned in the first pass removes first names that appear alone ("Zainab" in a CSV header). Generic parts such as Kumar and Devi are never learned.

**Secrets.** Planted canary tokens (`CANARY-...`), credential values after `password:`, `api_key=`, `access_token` and similar labels, JSON fields named `password`, `api_key`, `secret`, and well-known key shapes (`sk_live_...`, `AKIA...`, JWTs) become `[SECRET]`. Encoded attachments inside longer text are decoded, cleaned and re-encoded.

**Meaning traps kept intact.** `Dr. <name>` spans, hospital and lab names, the `ASHA worker` role, `C/O fever` (complaint), `K/C/O`, `H/O`, doses (`1-0-1`, `BD x 5 days`), hospital wards (`Ward 9 (Medicine)`), tehsil and district names in context, and reference documents with no patient in them (byte-identical on the practice data).

**Hidden places.** JSON keys, CSV headers, file names, export metadata, FHIR narratives, `\u`-escaped Devanagari and base64 attachments (decoded, cleaned, re-encoded) all go through the same detectors.

### 3.3 Linking and pseudonyms (`incog/link.py`)
* Records per file: CSV/TSV `row:N`; JSON one record per entry of a patient list (`/records/3`); JSONL one record per line (`/0`, `/1`, ... as if the lines were an array); a text note, FHIR Bundle or single-object JSON is `doc`. A text file that names several patients (a register, a roster) is left unlinked (`null`) instead of being given one patient's pseudonym.
* A shared name, even with the same relative's name, never joins two records whose hospital record numbers and phones both differ, unless the birth date agrees.
Two records are linked only when the data connects them, following the dataset's own definition:
* a shared strong identifier: UHID/IPD number, Aadhaar, ABHA, the patient's own phone, email; or
* the same name plus a second clue: DOB, relative's name, or village with age within one year.

Names are compared by a phonetic skeleton after Devanagari transliteration, so `Fatima / Fatma / फ़ातिमा` and `Siddiqui / Siddiqi / सिद्दीक़ी` meet. A fragment such as "Asha, W/o Kamal" is linked only if exactly one known patient matches. Merges are blocked when two clusters carry different Aadhaar or ABHA numbers, different DOBs, or clearly different names. Attendant phones, payer PAN and insurance IDs are never used, because family members share them. A document that mentions several patients is left unlinked. When evidence is weak the record gets its own pseudonym or `null`, because a false merge costs more than a missed link.

Pseudonyms are `PSN-XXXXXX`: HMAC-SHA256 over the cluster's anchor record, keyed with `RAKSHA_SECRET`, Crockford base32. They are not reversible, they change with every secret, and two clusters can never share one. The pseudonym is written inside the exported record (the ID and name fields, or the note text), so it is verifiable.

### 3.4 Privacy layer (`incog/dates.py`, `incog/privacy.py`, `config/policy.yaml`)
| Quasi-identifier | Treatment | Why |
|---|---|---|
| Dates | one secret offset per patient (±180 days, never 0), every format kept (ISO, DD/MM, MM/DD, dotted, two-digit years, "5 September") | intervals and lengths of stay stay exact; a global offset cannot be recovered from a few known visit dates |
| Day or month first | decided per file: a value above 12, a `(MM/DD/YYYY)` label, or a vote from files of the same source | Arogya exports are month first |
| Age | 20-year bands (0-19, 20-39, 40-59, 60-79); 80 and above becomes `80+`; ages written in text are banded too | the band always contains the true age. With 10-year bands our replica of the published A2 to A4 attack singled out 14 of 48 practice patients; with 20-year bands 8 (30-year bands: 3, but children would share a band with adults). The medical-value score is unchanged |
| DOB | suppressed (`[DOB]`); FHIR `birthDate` dropped so bundles stay valid | a birth year pins the age and cancels the band |
| Location | house, locality, landmark, village and tehsil removed; district kept; PIN reduced to its first 3 digits | tehsil + gender + age band left a median of one person in the registry |
| Rare diagnoses | a diagnosis held by 3 or fewer patients becomes its ICD-10 chapter, in codes and in text | a rare condition next to an age band and a district identifies the patient; the threshold matches the attacker's own |

Every setting is a line in `config/policy.yaml`.

---

## 4. Security design
* **Keyed, not hashed.** Pseudonyms and date shifts use HMAC-SHA256 with the per-release secret. Plain or salted hashes of IDs are never emitted.
* **The secret never leaves memory.** It is read from the environment and never logged, printed or written.
* **No side channels.** stdout carries counts only; no logs, no temporary files, no stack traces with paths. `report.json` and `records.jsonl` hold no personal data. Output file names are cleaned like content.
* **Fail safe.** A file that fails to parse or to sanitise is quarantined with a reason code; raw copies are never written. A linking failure releases the data unlinked rather than crashing.
* **Offline and deterministic.** No network calls; the same input and secret give byte-identical output.
* **Input is read-only.** Nothing under `--input` is modified.

---

## 5. Measured results

Practice data (200 files, 48 patients, 4 hospitals), `RAKSHA_SECRET=practice`:

| Measure | Value |
|---|---|
| Personal data leaked: overall / Latin / Devanagari / Hinglish | 0 of 3,230 (0.0%) / 0.0% / 0.0% / 0.0% |
| Leaks by hiding place (content, file name, base64, metadata, key, header) | 0.0% each |
| Canary identities in output | 0 of 4 |
| Medical values kept | 96.4% (4,682 of 4,855; the rest are rare diagnoses shown as ICD chapters on purpose) |
| Linking precision / recall / F0.5 | 1.000 / 1.000 / 1.000 (0 false merges) |
| B-cubed F1 | 1.000 |
| Language trap / fragmented trap / homonyms kept apart | 816 of 816 / 258 of 258 / 2 of 2 |
| Pseudonym present inside its record | 774 of 774 |
| Date intervals preserved exactly | 12,554 of 12,554 |
| Re-identification, our re-implementation of the published A2/A3/A4 attacks | record risk 0.369 raw → 0.051; patients re-identified 47 of 48 raw → 8 of 48 |
| Run time / peak memory | 1.3 s / 26 MB |
| 10× the practice data (2,000 files) | 9.2 s / 103 MB, linear growth |

**On data we did not tune on.** We built an unseen-format copy of the practice data: 116 names replaced with invented names, about 45 column and key names renamed (`Hosp Regn ID`, `beneficiary`, `basti`, `Paidaish`, `caretaker`) and text labels reworded (`son of`, `Accompanied by:`, `रोगी:`). On that copy: 0 leaks, linking precision 1.000 and recall 0.860 (F0.5 0.969), 0 false merges. Most of the recall gap comes from the test itself, which renamed Latin spellings but not the matching Devanagari ones.

**Performance work (`benchmarks/`).** Profiling showed three costs that grew with dataset size: regexes that went quadratic on very long tokens (email, Hindi landmark), one giant alternation of every learned name and identifier, and identical values (repeated headers, codes, ward names) being cleaned again in every file. Fixes: word-start anchored patterns, set lookups over word runs instead of the alternation, suffix-set lookups for learned IDs, and a cache of cleaned values once learning has finished (counters are replayed so report.json stays exact). Same machine, best of two runs, `python3 benchmarks/bench.py <repo> <label> <out.json> practice=<input dir> ...`:

| Dataset | Files | Before (commit 1ca2b28) | After | Peak memory before / after |
|---|---|---|---|---|
| Practice | 200 | 2.22 s | 1.31 s | 25.8 / 26.4 MB |
| Practice with injected noise (`devtools/chaos.py`) | 200 | 2.10 s | 1.22 s | 25.9 / 26.4 MB |
| Practice ×10 | 2,000 | 20.76 s | 9.23 s | 102.4 / 102.8 MB |

On the practice, noise-injected, unseen-format and broken-file sets, the output of the final engine is byte-identical to commit 1ca2b28 (records.jsonl, every sanitized file, report.json without timing and resources). No parallelism, caches are in memory only and hold no raw values on disk.

**Hardening against hidden identifiers.** Our phase 2 trap suite (58 cases) and phase 5 hardening suite (20 cases, 3 runs) now pass 58/58 and 19/20 (previously 51/58 and 13/20). Added, each as a general rule: `Insurance ID:` labels; Hinglish "Patient ka naam X" without a colon; a municipal ward inside an address line; identifiers in CSV headers, JSON keys, file names and path strings (underscores read as spaces, code-shaped IDs such as `ABC-DEF-12` or `REG-483719`); base64 and hex values that decode to readable text are cleaned and re-encoded; full-width digits and zero-width characters are normalised before detection; a phone number after a word ending in a digit; ID-like columns headed "Ref", "Reference" or "क्रमांक". Linking: a shared phone no longer joins two people with different birth dates (families share phones), malformed date-like values are ignored when vetoing a merge, and "<first name> W/o <husband>" fragments are linked without the comma. Practice results above are unchanged by these rules.

---

## 6. Known limitations
* A bare name with no label, honorific, relation marker or structured field anywhere (for example "Ramesh Kumar" alone in a list) is not detected. A curated Indian name list would catch it at the cost of false positives on common words.
* A bare name used as a JSON key with no other evidence (for example `{"Vihana_Bisht": {...}}`) is not detected; this is the one remaining phase 5 failure.
* Phase 3 linkage edge cases pass 15 of 16. The remaining case (a bare first name with no other clue) gets its own pseudonym rather than none; it is never merged with anyone.
* No statistical model is trained. The public NER datasets (Naamapadam, MedDeID, COMI-LINGUA) are news or real-person data with licence and size issues for an offline 2-CPU run; rules and learned gazetteers were measured as sufficient on the practice data.
* The first-name gazetteer removes a learned name wherever it appears, which can also remove a matching ordinary word.
* The re-identification figures come from our own re-implementation of the published attack, run against a 240-person practice registry. The official attacker and the larger hidden datasets will give different numbers; larger populations make the same rules protect better.
* Rare-condition generalisation lowers the number of exact diagnoses kept (3.6% of medical values on the practice data). The threshold is configurable.
* OCR (document mode only) loses the micro sign (`µL` is read as `uL`) and sometimes a decimal point (`Hb 112`). These are never corrected by guessing: the page is flagged for review with the reason (`CHECK` lines in `demo/run_documents.py`, `clinical_checks` in the result). Names drawn in a PDF with a font that has no Unicode map cannot be read by anyone; those glyphs are blacked out and marked `[UNREADABLE]`.
* Linking is deliberately conservative: when evidence is thin, records stay unlinked rather than risk a false merge.

---

## 7. Demo UI (optional, not part of the graded run)

A local web page to try IncogRx on your own files, folders or pasted text:

```bash
python demo/app.py            # opens http://127.0.0.1:8765
```

* Standard library only, offline, listens on 127.0.0.1 only. It calls the same `main.py` the evaluator runs, in a separate process, so it shows exactly what gets scored.
* Two ways in: upload files, a whole folder, a .zip (unpacked by the demo) or PDFs and photos of notes, or paste a note (English, Hindi or Hinglish). `demo/samples/` holds a small invented dataset to upload with "Choose a folder".
* Shows files released or quarantined (with the reason), what was removed by type, every patient pseudonym with the files it links, a side-by-side original and released view per file, and a zip download of the full release.
* Documents (demo only): `pip install -r demo/requirements-demo.txt` and, for scanned or handwritten pages, the Tesseract program (`brew install tesseract` on macOS, `apt install tesseract-ocr` on Linux; the English and Hindi `tessdata_fast` models ship in `demo/tessdata/`). Every page of a PDF, or a photo of a note, becomes its own record: typed pages are read from the text layer, scanned and handwritten pages by OCR. Removed words are deleted from the page (pixels too, on scans), words the OCR is unsure of are hidden as well, and pages with low OCR confidence are flagged for human review. The released PDF is rebuilt as a new document from the page contents only, so JavaScript, auto-run actions, embedded files, links, forms, hidden text and metadata are left behind. Measured on invented documents: 25 pages in about 0.4 s, 50 in 0.7 s, 80 + 25 in 1.3 s; handwritten pages about 1 s each. Glyphs a PDF draws without a Unicode map (so nobody can check them) are blacked out and marked `[UNREADABLE]`. The same flow runs from the terminal: `RAKSHA_SECRET=<secret> python demo/run_documents.py --input <dir> --output <new dir>` prints the scan verdicts, per-document page counts, redaction boxes, OCR confidence and timings. The scored pipeline itself does not read PDFs or images: it quarantines them, which the track allows.
* Security scan (demo only), before anything is opened or written to disk: the EICAR test signature, executables (EXE, ELF, Mach-O), scripts and double extensions, macro documents, password-protected PDFs and encrypted archive entries, script-carrying HTML/SVG, cryptographic key material, encrypted or opaque payloads (`.aesgcm`, `.gpg` and high-entropy binaries), zip-slip paths, zip bombs, nested archives and image decompression bombs are blocked and listed with the reason; PDFs with active content are released only as the rebuilt, cleaned copy. Nothing uploaded is ever executed.
* The "Speed & security" page shows, for the latest batch: time per document and pages per second, OCR confidence per document with the pages flagged for review, and every security verdict.
* Live website (demo only): https://incogrx.vercel.app. Vercel serves `demo/index.html` and runs the engine as a Python function (`api/run.py`, configured in `vercel.json`): the same security scan and the same `main.py`, in a fresh temporary folder per run that is deleted afterwards. Nothing is kept between requests, so the release (previews, files and the zip) comes back in the response. Limits of the hosted site: about 4 MB per run and no OCR, so PDFs, scans and photos are quarantined there; the local demo (`python demo/app.py`) reads them. A `Dockerfile` and `render.yaml` are also included for hosting the full demo, OCR included, on a container host.
* Uploads and results live in a temporary folder that is deleted when the server stops; nothing is logged.

---

## 8. Tests
* `python tests/test_multilingual.py`: 30 English, Hindi, Hinglish and mixed-script sentences; checks that personal data is removed and that clinical text, doctors and roles are kept.
* `python tests/test_security_pack.py`: builds harmless fixtures (prompt injection, canary tokens, fake credentials, key material, EICAR string, a symlink to a system file, an encoded attachment, a zip with a `../` entry, an opaque binary, truncated JSON), runs `main.py`, checks every quarantine reason and scans the whole output, base64 and hex decoded, for anything that must not be released.
* `person_a/phase2..phase5`: detection traps, linkage cases, privacy engine and hardening.

## 9. Repository layout
```
main.py               entry point (contract: --input / --output, RAKSHA_SECRET)
raksha.toml           track run configuration
config/policy.yaml    privacy settings
incog/readers.py      decoding, parsing, quarantine
incog/fields.py       field and JSON-path classification (EN / Hinglish / Devanagari)
incog/sniff.py        value-based classification of unfamiliar columns and keys
incog/detect.py       identifier patterns, learned knowledge base, name gazetteer
incog/textner.py      context detection in free text (labels, relations, honorifics, addresses)
incog/link.py         evidence extraction, phonetic cross-script matching, clustering
incog/crypto.py       HMAC pseudonyms and date-shift keys
incog/dates.py        per-patient date shifting in every date format
incog/privacy.py      rare-condition generalisation, age banding in text
incog/sanitize.py     per-category sanitisers
incog/pipeline.py     two learning passes, linking, sanitising, report and records
demo/                 optional demo UI and document mode (app.py, index.html, security.py, pdf_support.py, run_documents.py)
tests/                multilingual detection and security-pack tests
docs/                 Project Brief (PDF)
```
