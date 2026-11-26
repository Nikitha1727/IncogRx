# Secret Wards — Person A, Phase 2 (development QA)

This is a QA handoff, NOT the competition sanitization engine. Baseline is the official unmodified starter, not Person B's current code. All inputs are synthetic. Do not copy practice-derived leak surfaces, truth, reports, or this development audit into the production pipeline, public submission, or release. Do not use exact practice identities as rules. Keep the audit local to team QA.

## Run
From the extracted package directory, with Python 3.10+:

```bash
python run_traps.py --entry /path/to/team/main.py --results results.json
python audit_practice.py --toolkit /path/to/Secret-Wards-ToolKit-main --output /path/to/practice_output --audit local_audit
```

The first command generates 58 independent synthetic fixtures in a temporary input tree, executes the target CLI, and checks the resulting report, sanitized files, clinical strings, identifiers, selected side channels and input hashes. Exit 1 means at least one test failed. Exit 0 means these targeted checks passed, not that the system is fully safe. This runner assumes Python CLI entrypoint; adapt invocation if needed. The second command mirrors the official practice checker's normalized substring probes and produces full lists of leaked mentions, missing medical values and medical probes in unexported files. It requires the toolkit, including its truth, only for evaluation. Never import it from the sanitizer.

Also run the official checker after each change:

```bash
cd /path/to/Secret-Wards-ToolKit-main
RAKSHA_SECRET=practice python /path/to/team/main.py --input dev/input --output /path/to/new_empty_output
python validate_output.py --input dev/input --output /path/to/new_empty_output
python check_dev.py --output /path/to/new_empty_output --show 10
```

## Contents
- `trap_tests.json`: 58 cases with input, required removal, exact clinical strings, format, and quarantine expectation; first 8 match the task sheet.
- `run_traps.py`: executable end-to-end regression runner.
- `make_tests.py`: generator for the synthetic fixtures.
- `baseline_traps.json`: real results of running the official starter against the new suite.
- `audit_practice.py`: development-only full practice audit.
- `dev_only_audit/leaks.csv`: all 2,718 baseline missed mentions with source path, locator, type, script, channel, exact synthetic surface.
- `dev_only_audit/lost_clinical.csv`: missing clinical probes (none in baseline).
- `dev_only_audit/unexported_clinical.csv`: clinical probes in unexported files (none in baseline).
- `dev_only_audit/summary.json`: aggregate baseline.
- `BUG_REPORT.md`: prioritized corrective actions and acceptance gates.

## Limitations
The official self-check uses whole-file normalized substring probes; it does not establish exact field-level preservation or full hidden attack resistance. Our trap runner tests exact clinical substrings in each file, checks selected unique TEST- identifiers in report/logs/temp/home, and detects some base64 text. It does not exhaust all possible side channels, all encodings, changed identifier formatting, FHIR semantics, or adversarial privacy. False positives and false negatives remain possible. The full evaluator is hidden. Quarantine must not become a shortcut to achieving low leak scores; the runner requires sanitization for supported fixtures. No Person B implementation has been supplied, so no integration or improvement has been measured. This is Phase 2 only.
