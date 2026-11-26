# Phase 2 — bug report for Person B

Baseline: 2,718/3,230 leaked mentions; 4/4 canaries exposed; 4,855/4,855 official clinical probes preserved; CONTRACT OK; 25/58 new regression tests passed. The practice checker is not the official 100-point score.

| Priority | Defect | Evidence | Recommended fix |
|---|---|---|---|
| P0 | Patient name and MRN leaks | 911 + 817 misses | Field-aware rules first, extract identity evidence before redaction, match labels and context across scripts. Do not use truth as a dictionary. |
| P0 | Canary and hidden channel leaks | 4 canaries; 48 filename, 40 metadata, 12 key, 10 base64, 8 header mentions | Sanitize path components and metadata recursively; safe collision-free key/header mapping; decode supported attachments and resanitize or quarantine when uncertain. Scan reports/logs too. |
| P0 | Hindi/Hinglish | 143 + 111 misses, 100% both | Normalize Unicode and Hindi digits in detection-only copy, map spans back to original, use label and honorific rules plus bilingual dictionaries. |
| P0 | Relatives and context | 232 misses | Relationship markers with context; distinguish C/O fever, H/O, K/C/O and Dr. from patient/relative names. |
| P1 | Addresses and DOB | 150 village + 136 house + 136 PIN + 103 locality + 64 landmark + 111 DOB | Use field context, detect fine-grained locations and DOB; coordinate with privacy layer; retain clinical ward information. |
| P1 | Remaining identifiers | 25 phone, 16 masked Aadhaar, 15 insurance, 2 Aadhaar | Normalize spacing/digits; use labeled identifier patterns; avoid broad numeric deletion. |
| P0 regression gate | Clinical damage | 16/16 clinical-only tests pass now | Preserve these exact strings. Test every change; never sacrifice medicine doses to improve recall. |
| P1 regression gate | Quarantine/contract | 3/3 quarantine tests pass now | Retain proper quarantine; preserve CSV/TSV structure, JSON types, FHIR references. |

Suggested patch order: structured field handling and path/header/key cleanup; multilingual text spans; contextual disambiguation; remaining ID patterns; repeat tests. These are recommendations, not implemented fixes.

Acceptance targets: all 58 traps pass, 0 canaries, no raw copies, CONTRACT OK, 100% measured clinical preservation where possible, reduce practice leakage below 2% as a stretch target. Track record retention as well. These are goals, not observed results. Assess re-identification and linkage later in their designated phases.
