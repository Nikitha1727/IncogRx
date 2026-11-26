# RAKSHA — live desk review (proposed five-minute demo)

Use only synthetic fixtures; run the actual integrated CLI before claiming any outcome. Keep a saved sanitized output and actual metrics as backup. Never show practice truth or the secret in the demo.

| Time | Show | Say |
|---|---|---|
| 0:00–0:35 | Problem and architecture | Four hospital systems, three language styles, many formats. Redaction alone leaves indirect identifiers. |
| 0:35–1:20 | Synthetic Hindi/Hinglish note | Demonstrate names and phone removal alongside unchanged BP 117/82 and Dolo 650 1-0-1 x 5 days. Contrast C/O fever and C/O a relative. |
| 1:20–2:05 | Identity fixtures | Show same-person cross-script linkage with independent evidence and two same-name patients kept apart. Explain abstention and cluster conflicts. |
| 2:05–3:00 | Privacy policy | Show age band, location generalization and per-patient date shift retaining a 9-day stay. Explain the 30-profile helper experiment and residual risk. |
| 3:00–4:10 | Actual run + outputs | Run CLI, show sanitized/, report.json, records.jsonl, quarantine, official validator and measured practice metrics. |
| 4:10–5:00 | Security and limits | Same secret repeat, changed-secret release, no raw logs, remaining failures. Show final checklist and state what is not yet validated. |

## Judge questions and defensible answers

1. **Why no LLM?** Track rules prohibit LLMs; rules, script normalization and classical matching run offline with modest resources.
2. **Why not remove every name dictionary hit?** Names overlap diagnoses and clinician names; protected clinical spans and context resolve conflicts. Dictionary hits are candidates.
3. **What if two patients share a name?** Require corroboration, scope hospital identifiers by hospital and reject reliable contradictions at cluster level. Abstain on ambiguous evidence. Verify the actual linkage code does this.
4. **Why HMAC rather than SHA-256?** A secret key resists offline guessing of low-entropy identifiers; use deterministic canonical cluster IDs and separate purposes. HMAC is not encryption or proof of anonymity.
5. **How do you preserve stay lengths?** Shift all relevant dates for a patient by the same secret-derived offset. For unresolved records use a consistent encounter key or suppress unsafe dates, checking utility impacts.
6. **Why adaptive age bands?** Broad bands everywhere waste precision. Start at five years and widen or suppress in risky groups. Measure groups by distinct patients, not visits.
7. **What about rare diagnoses?** Preserve by default because clinical utility matters. Escalate demographic protections and quantify residual uniqueness; do not claim that k-anonymity prevents every attack.
8. **What did you actually measure?** Starter leaked 84.1% of practice probes and retained 100% of tested clinical probes; the privacy helper independently reduced demographic uniqueness from 46.7% to 0% on 30 synthetic profiles. Neither is a final integrated score. Replace with verified final measurements when available.
9. **How do you protect hidden identifiers?** Inspect paths, headers, JSON keys and metadata; bounded decoding of attachments; quarantine on unsupported or unsafe content. Verify against test suite.
10. **What if server storage is breached?** Planned design minimizes persistence and encrypts necessary sensitive intermediates with authenticated encryption and separated keys. It cannot protect plaintext in a compromised running process; encryption implementation needs verification.
11. **Why is contract validation insufficient?** It verifies output structure, not clinical meaning or privacy. Run self-check, linkage and regression tests too.
12. **What changes with a new secret?** Pseudonyms and date offsets are derived from the new key; accidental individual date-offset collisions are possible. Clinical information and intervals should remain intact. Validate across releases.
13. **Can you guarantee privacy?** No. Rare conditions, longitudinal profiles and auxiliary data remain risks. Hidden evaluator unavailable.
14. **How do you avoid memorization?** Keep truth, audit leaks, fixtures and expected answers outside runtime and public submission. Use general language resources and unseen independent cases.
15. **How fast is it?** Quote actual integrated runtime and process-tree memory only after measurement. Starter measurements are not final performance.
