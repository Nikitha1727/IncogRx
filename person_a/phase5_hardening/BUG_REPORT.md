# Phase 5 baseline bug report

Tested: original toolkit starter only.

| Case | Fixture | Result |
|---|---|---|
| 1 | `registration/renamed.csv` | PII leaked |
| 2 | `registration/alternate.tsv` | PII leaked |
| 3 | `notes/legacy.txt` | PII leaked |
| 4 | `notes/hindi.txt` | PII leaked |
| 5 | `notes/hinglish.txt` | PII leaked |
| 6 | `notes/dates.txt` | PII leaked |
| 7 | `lab/Report_Tanvika_Korde_9000012348.txt` | PII leaked |
| 8 | `misc/key.json` | PII leaked |
| 9 | `misc/header.csv` | PII leaked |
| 10 | `misc/metadata.json` | PII leaked |
| 11 | `notes/zero_width.txt` | PII leaked |
| 12 | `clean/protocol.txt` | PASS |
| 13 | `misc/broken.json` | PASS |
| 14 | `misc/unknown.pdf` | PASS |
| 15 | `misc/empty.txt` | PASS |
| 16 | `misc/base64.json` | PII leaked |
| 17 | `misc/hex.json` | PII leaked |
| 18 | `misc/percent.json` | PASS |
| 19 | `misc/deep.json` | not safely quarantined, PII leaked |
| 20 | `misc/binary.jpg` | PASS |

## Fix order
1. Fail closed on excessive JSON nesting and never publish a raw fallback.
2. Detect identities in unfamiliar schema labels, Hindi/Hinglish, and non-UTF8 input.
3. Scan filenames, headers, keys, metadata, decoded payloads and side channels.
4. Integrate patient-level date shifting and HMAC identity generation.
5. Preserve clinical probes and repeat all regression tests.

Priority follows official privacy (25), detection (20), clinical utility (20), identity consistency (15), integrity (10), reliability (10).
