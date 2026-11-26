# Secret Wards — Person A, Phase 1

Copy `phase1/` into the team repository. All JSON is UTF-8. These resources are candidate dictionaries, not a sanitizer or a trained model. General name seeds are manually curated; no patient records, truth labels or attacker data are copied into these dictionaries. Clinical vocabulary is supplemented from the toolkit's clean drug formulary and lab reference ranges; field aliases are informed by registration schemas. Do not tune to individual practice patients.

## Integration order
1. Decode strictly and parse each file. Keep original spans and data types.
2. Normalize a detection-only view (NFKC, casefold, Indic digits, separators and zero-width characters); map spans back to the original. Use script-aware tokenization, not ASCII-only word boundaries.
3. Classify structured fields by full path and resource type; aliases are candidates, not universal rules. Extract identity evidence in protected memory before redaction.
4. Detect PII and clinical spans together. Strong identity field context overrides coincidental clinical patterns; explicit doctor/clinical context protects only the relevant span. C/O person vs C/O symptom; H/O history; K/C/O diagnosis. Distinguish hospital wards from residential wards. Generic names and honorifics do not identify a patient alone.
5. Use name variants only for candidate generation, never as proof of identity. Avoid stripping meaningful initials or combining independent patients with matching names.
6. Inspect JSON keys, CSV headers, filenames, nested metadata and safely decoded attachments. Quarantine unprocessable files. Do not emit raw exception messages.
7. Apply privacy transformations after linking. Preserve original clinical strings, units and intervals. Do not treat age or encounter dates as ordinary clinical keep values; DOB is direct PII.

## Checks
Run `python check_resources.py` from this folder. This checks JSON parsing, regex compilation and basic pattern examples; it does not measure PII recall or clinical preservation in Person B's pipeline.
After integration, from the team repository run (adjust toolkit path):
```
RAKSHA_SECRET=practice python3 main.py --input ../Secret-Wards-ToolKit-main/dev/input --output out
python3 ../Secret-Wards-ToolKit-main/validate_output.py --input ../Secret-Wards-ToolKit-main/dev/input --output out
python3 ../Secret-Wards-ToolKit-main/check_dev.py --output out --show 10
```
Keep outputs and truth files out of public git. Use aggregate statistics in shared reports. Compare to Phase 0: 2718/3230 PII mentions leaked, 4855/4855 clinical probes kept, 4/4 canaries leaked (previous baseline run). The official detection metric is F2; identity precision is favored by F0.5. Do not claim improvement until evaluated. Phase 2 trap testing is separate and not included in this phase.

## Source and limitations
Toolkit: START_HERE.md, docs/SCORING.md, registration headers and clean clinical CSVs. Names and additional vocabulary are manually curated candidates, not exhaustive; variants may be distinct identities. No runtime dependency or model is introduced. FHIR validation and context/overlap logic must be implemented by Person B. Resources do not establish anonymity or clinical correctness on their own.
