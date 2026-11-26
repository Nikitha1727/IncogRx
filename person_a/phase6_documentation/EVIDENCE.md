# Evidence ledger

| Metric | Local source | Scope |
|---|---|---|
| 2,718/3,230 leaks; 4,855/4,855 clinical probes; four canaries | Phase2_Secret_Wards/dev_only_audit/summary.json | Starter practice audit |
| Hindi and Hinglish leakage 100% | Phase 0 practice self-check; Phase 2 audit | Starter practice dataset |
| 0.19 s; 104.9 MB reported RSS | phase0_work/baseline/report.json | Starter report |
| 25/58 trap cases | Phase2_Secret_Wards/baseline_traps.json | Independent starter fixture suite |
| 0/771 assigned; 6,892 missed true pairs; F0.5=0 | Phase3_Secret_Wards/baseline_summary.json | Starter practice output; no predicted pairs, precision undefined |
| 0/16 linkage scenarios | Phase3_Secret_Wards/baseline_synthetic.json | Independent starter fixture suite |
| 12 tests passed | Phase4_Secret_Wards/test_results.txt | Standalone helper |
| 46.7% to 0% demographic uniqueness; inverse group size .733 to .133; min group 1 to 3; 3 below k=5 | Phase4_Secret_Wards/synthetic_demo.json | Independent 30-profile proxy experiment, not official attacker |
| 6/20 hardening cases; 3 successful contract validations | Phase5_Secret_Wards/baseline_hardening.json | Starter only |

Official requirements: uploaded Secret-Wards-ToolKit-main.zip, docs/PROJECT_BRIEF.md, SPEC.md, SCORING.md, ATTACKS.md, SANDBOX.md and brief/PROJECT_BRIEF_TEMPLATE.md. No full hidden score calculated. The original results were read from saved artifacts, not newly measured in Phase 6.
