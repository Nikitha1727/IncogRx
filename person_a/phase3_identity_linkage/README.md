# Phase 3 — Person A handoff (internal testing only)

Source: uploaded official toolkit, docs/SCORING.md, docs/SPEC.md, dev/truth/truth.json; Person A task sheet. No practice names or answers are embedded in synthetic fixtures. Never use ground truth or these fixture identities in production detection/linkage.

## Run
From this directory:
```
python3 run_linkage_tests.py --entry /absolute/path/to/main.py --results results.json
python3 audit_linkage.py --toolkit /absolute/path/to/toolkit --output /absolute/path/to/practice_output --results private_audit.json
```
Also run official `validate_output.py` and `check_dev.py` on the same output. Audit results contain synthetic practice filenames: keep locally, not in the public submission. The synthetic runner checks pseudonyms in sanitized text and records.jsonl, including renamed files via report hashes. It is not a complete privacy scanner. Negative fixtures require both patients assigned to avoid vacuous passes; abstain fixture requires the anchor linked and the ambiguous note null. A bridge record tests whether two conflicting anchors become merged; assignment of the bridge itself is not scored. All fixtures are plain text, not a substitute for cross-format practice testing. No dependencies outside Python standard library.

## Baseline
771 required units, 0 assigned, 6892 missed true pairs, F0.5=0. Language 0/816 pairs; fragmented 0/258. 2 ambiguous units, neither assigned. No false merges because no linkage. 0/16 independent fixture tests passed. See baseline_summary.json and baseline_synthetic.json. Baseline audit uses previously generated official starter output. Synthetic fixtures were freshly executed on starter/main.py. Audit computes required-unit pair metrics, not full official score; ambiguous assignments tracked separately, B-cubed not implemented here. Person B's code has not been supplied.

## Acceptance
Aim for precision >= .99, F0.5 >= .95, high recall, zero homonym merges and zero unsafe ambiguous assignments; 16/16 synthetic fixtures as regression goal. These are targets, not measured results. Re-run PII and clinical checks from Phase 2 after every linkage change. Never expose raw identities in logs or reports. Keep the same patient secret-derived ID and date offset throughout all linked records.
