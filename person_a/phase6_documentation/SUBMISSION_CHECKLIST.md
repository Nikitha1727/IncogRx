# Final release checklist — not yet executed on team code

## Inputs needed
- Confirm team name, member names and public GitHub URL.
- Person B's full integrated repository and clean environment.
- Fresh practice output, self-check log, regression reports and measured privacy proxies.

## Run from the official toolkit root (set TEAM to absolute team repo path)
```bash
TEAM=/absolute/path/to/team-repo
OUT=$(mktemp -d)
RAKSHA_SECRET=practice python3 "$TEAM/main.py" --input dev/input --output "$OUT"
python3 validate_output.py --input dev/input --output "$OUT"
python3 check_dev.py --output "$OUT" --show 10
python3 check_submission.py --repo "$TEAM" --run
```
Use the team's declared setup command and a disposable offline sandbox for runtime testing. Keep any private audit logs outside the public repository. Verify the validator reports CONTRACT OK and the submission checker reports READY TO SUBMIT.

Run Phase 2 detection (58), Phase 3 linkage (16), Phase 4 privacy (12) and Phase 5 hardening (20) tests using their READMEs. Do not sum overlapping suites as an official score. Re-run after fixes. Validate FHIR R4, all input hashes accounted for, no raw exports, no secret/canary leaks in output or side channels, no input modifications. Check exact clinical probes and intervals, precision/recall/F0.5 and homonym separation, age bands and patient-level risk (age band, district, admission week, diagnosis). Check same-key reproducibility and different-key pseudonyms and shifts. Verify 2 CPU, 4 GB RAM and 900 s runtime limits in isolated environment.

## Before committing
- [ ] Update two-page brief with team identity and repo URL.
- [ ] Replace starter baseline results with actual integrated metrics; retain baseline as comparison if space permits.
- [ ] Confirm every claimed module exists and is integrated. Mark unsupported features as limitations.
- [ ] Include README, raksha.toml, pinned dependencies, code and brief PDF; exclude practice truth, leak audit, secrets, raw outputs and QA expected answers.
- [ ] Confirm setup works cleanly; no network at inference; synthetic data only.
- [ ] Verify Git status, public link, last commit before deadline; submit both link and PDF.

No final readiness or official score is claimed until these gates pass.
