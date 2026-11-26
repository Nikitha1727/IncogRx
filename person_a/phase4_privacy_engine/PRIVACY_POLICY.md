# Phase 4 — proposed release policy for Person B

Basis: official toolkit docs/SCORING.md, docs/ATTACKS.md, docs/SPEC.md and Person A task sheet. The thresholds here are proposed, not official. Implement during the event; do not ship practice truth, registry or attacker facts in the production pipeline.

## Policy decisions

| Field | Default | Escalation / rationale |
|---|---|---|
| Names, relatives, IDs, contacts | redact or replace with keyed pseudonyms as appropriate | scan all channels; never retain masked fragments |
| Age | truthful five-year band | widen to 10 then 20 years, then suppress if necessary; no fabricated age |
| DOB | suppress | birth year is also identifying; retain only if a measured alternative improves utility safely |
| Address, village, tehsil, PIN | suppress | district retained only at lowest-risk tier; do not invent district if unknown |
| Gender | retain in low tiers | suppress at high risk |
| Encounter dates | HMAC-derived nonzero offset per patient, +/-365 days | apply to every patient event, including nested data; maintain intervals and date syntax |
| Diagnoses, ICD codes, procedures | retain exactly by default | flag rare cases (<=3 distinct patients); generalize demographics first. No blanket rare-disease deletion. If risk persists, review narrowly scoped suppression only with measured clinical-utility trade-off and schema checks. |
| Medicines, doses, vitals, labs, stay durations | preserve exactly | never independently shift paired dates or alter values |
| Uncertain identities | abstain from linkage | use a verified encounter grouping for dates if available, otherwise suppress identifying dates where schema allows; quarantine if safe valid output is impossible |
| Raw/intermediate data | memory only when feasible | authenticated encryption for persisted intermediates; separate purpose-specific keys, no secret or raw PII in logs |

## Risk model and limits

Count distinct verified patient clusters, not visits. Aggregate all released evidence across records before deciding privacy policy. The reference helper accepts one normalized demographic summary per cluster and normalized condition codes. It escalates rare-condition profiles and groups with fewer than five patients; after each escalation it recalculates exact released demographic signatures. It can still end with fewer than five patients. It does not implement l-diversity, registry matching, the hidden attacker, multi-visit age trajectories or rare-diagnosis suppression. Its inverse-group-size metric is a proxy, not the attack success probability. Missing demographics and multiple inconsistent ages need careful treatment; use a consistent truthful policy across all records, recompute actual released profile risk and avoid publishing narrower bands elsewhere. The suppression pattern can itself reveal information. No guarantee of anonymity.

For full integration, measure profile uniqueness using combined retained demographics, diagnosis/procedure, stay length, hospital, temporal intervals and missingness. Compare privacy and utility on held-out synthetic cases. For l-diversity, count distinct sensitive values within demographic classes, report homogeneous classes; do not change diagnoses to manufacture diversity. If a rare condition remains identifying, flag for review and quantify any narrowly scoped suppression. Exact stay durations remain identifying in some cases; preserving them is mandatory. Do not try to evade the scorer with contradictory evidence.

## Attack defenses

- A1: structured/free-text detection and final scan of content, filenames, metadata, headers, keys, attachments, stdout/stderr and reports.
- A2/A3: generalize coherent profile demographics; eliminate direct and partial IDs.
- A4: apply one policy across each verified patient cluster; scan the union of retained facts.
- A5: secret-dependent dates; rare-case escalation; assess hospital, diagnosis and stay evidence jointly. Date shifting alone does not defeat known-fact attacks.
- A6: HMAC-SHA256 with secret and purpose-separated inputs for pseudonyms (Phase 3); no plain hashes or encoded original IDs.
- A7: change secret between releases, keep stable within one release; test pseudonyms and dates. Finite date offsets can collide by chance; do not promise every date changes for every key.

## Integration gates

1. Link before sanitizing; use deterministic canonical cluster key, never a name alone. Keep internal mappings private.
2. Run policy on normalized profiles; enforce decisions across all output locations, including narrative, structured fields and FHIR references. Preserve actual format; FHIR typed ages/dates cannot blindly receive string bands or placeholders. Use valid FHIR representation or omit where permitted; validate or quarantine otherwise.
3. Shift full encounter dates and dateTimes preserving time/offset semantics; reference helper supports ISO date only. Parse source format with explicit locale, preserve interval semantics, reject ambiguous or overflowing dates safely. Never shift durations, doses, IDs or non-patient document dates.
4. Run official validator and check_dev plus Phase 2/3 tests. Test same secret twice and different secret once; compare sanitized bytes and records.jsonl (runtime metrics may differ).
5. Record clinical utility, demographic group sizes, rare-condition residual risk, output coverage and all leaks. Official privacy score = 25 * (1 - attack risk) * min(1, utility / 0.40); no actual official privacy score can be inferred from this proxy.
6. Never publish raw data, practice identities, private cluster maps or secret. Report only aggregate statistics. Do not modify input.

## Brief-ready rationale

We propose adaptive, patient-level quasi-identifier generalization that starts from informative demographics and escalates small groups and rare conditions, combined with purpose-separated keyed date offsets. We preserve clinical values and temporal intervals rather than blanket redaction. The local risk proxy is explicitly not a guarantee of anonymity; residual rare-condition and longitudinal linkability must be measured. Replace this proposed-design wording with implemented behavior and actual measured results after Person B integration.
