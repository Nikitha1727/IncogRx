# Person B — proposed linkage policy

1. Extract evidence before redaction: patient names, scoped hospital IDs, verified national identifiers, phone, DOB, relatives and location. Keep roles distinct; never treat doctors or relatives as patient names. Preserve original text offsets for clinical protection.
2. Normalize comparison copies only: Unicode normalization, Hindi digits, phone country/leading-zero handling, transliteration, spelling variants, surname-first ordering, initials and honorifics. Do not treat transliteration or fuzzy matching as proof of identity. Parse ambiguous dates using source context; missing evidence is not a contradiction.
3. Block on multiple keys: exact verified ID, hospital+MRN, phone, DOB+phonetic surname, relative+name features. Avoid quadratic comparisons. Cap huge common-name blocks without silently dropping reliable ID candidates.
4. Compare independent evidence. A valid same-hospital ID or reliable national identifier is strong evidence, subject to conflicts. Shared phones are common in families. Name similarity alone is insufficient. Name+DOB+phone or name+relative+DOB/location can support a link. Tune thresholds against practice data and independent fixtures, not hidden answers.
5. Conflict-aware clustering: process strong candidate edges first with deterministic tie-breaks. Before union, compare cluster-level reliable IDs and DOB evidence; reject incompatible merges or ambiguous bridge edges. Do not consider different hospital-local IDs across different hospitals a contradiction. A changed phone alone need not veto an otherwise strong link. Avoid unconditional DSU transitivity.
6. Abstain: if a fragment has several plausible matches or no adequate independent evidence, use null; remove direct PII regardless. A distinct well-supported identity can receive its own ID.
7. Produce deterministic cluster keys using a stable canonical representation, then HMAC-SHA256 under RAKSHA_SECRET with domain separation from date offsets. Use the allowed pseudonym syntax per SPEC. Never publish the canonical key or secret. Ensure unique pseudonyms and same patient ID inside sanitized records and records.jsonl. Never use Python hash() or random IDs.
8. Evaluate required-unit precision/recall/F0.5, false merges, language/fragmented traps and homonym separation. Official score additionally measures B-cubed and ambiguous false merges. Check deterministic output under same key and changed IDs under different key; clinical preservation and leakage must not regress.

## Priority bugs
- Critical: starter assigns no patient IDs; integrate evidence extraction and scoped strong-ID linking first.
- Critical: same-name and shared-phone collisions; enforce cluster conflict checks before fuzzy linking.
- High: Hindi/Hinglish spelling, initials, and honorifics; integrate Phase 1 normalization dictionaries.
- High: fragmented records; compare relative and DOB evidence; abstain if uncertain.
- High: output mapping; ensure sanitized paths and locators match report and IDs appear inside records.
