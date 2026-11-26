# Phase 5 — Hardening (Person A)

Independent synthetic fixtures modeled on the registration and note structures and unusual encodings described in the official toolkit SPEC.md. These are new synthetic files, not copies of patient records. Do not put fixtures or expected answers into the detection engine or submitted runtime. Keep this pack in a separate local QA directory.

## Run

```bash
python3 run_hardening.py --entry /absolute/path/to/main.py --validator /absolute/path/to/toolkit/validate_output.py --results results.json
```

Python 3.10+; standard library only. Executes the supplied Python entrypoint three times, twice with one synthetic test secret and once with another. Each run has a 900-second timeout, separate output, HOME and TMPDIR. Checks input hashes, output contract, exact clinical probes, known synthetic identifiers in released paths/content/reports/logs and private HOME/TMPDIR, and byte-identical sanitized files/records.jsonl across repeat runs. It excludes quarantine from release scanning as the official contract specifies. Quarantined material must nevertheless be protected in real deployments. Different-secret check requires nonempty disjoint pseudonym sets; it does not prove all links are correct.

## Acceptance

20/20 cases, CONTRACT OK on all runs, no secret leaks, unchanged input, identical release under same key, nonempty disjoint pseudonyms under changed key. Then rerun official practice check plus Phase 2, 3 and 4 tests. Check date intervals and key-dependent date shifts using actual linked outputs; this harness only checks literal date probes and the textual stay value. Do not claim privacy success merely from contract validity.

## Limits

Not the hidden evaluator. Probe scanner covers NFKC, case folding, Devanagari digits, one zero-width character, and selected base64/hex/percent encodings; not every obfuscation, file type or PII variant. Literal matching cannot prove semantic date removal or clinical integrity across all formats. Some quarantine expectations (e.g. unsupported PDF) are deliberately conservative. The .jpg fixture is a mislabeled text file, not a valid image. CPU environment hints are not hard resource limits; no enforced network namespace. RSS is pipeline-reported, not independently sampled process-tree memory. The starter is the only pipeline tested; Person B's updated code is not supplied. No official score or hidden attack result is claimed. Run in a disposable offline sandbox for final verification.
