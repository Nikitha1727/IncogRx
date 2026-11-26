# Secret Wards Phase 4 handoff

Files: policy.json (config), privacy_reference.py (standard-library reference helper), test_privacy.py (12 unit tests), test_results.txt (actual test run), PRIVACY_POLICY.md (decisions, attack mapping, integration gates and brief rationale), synthetic_demo.py and synthetic_demo.json (illustrative measured proxy).

Run `python3 -m unittest -v test_privacy` and `python3 synthetic_demo.py`. No external dependencies. Reference helper handles normalized patient summaries and ISO dates only; it is not a complete sanitizer, encryption module, HMAC pseudonym implementation, or official evaluator. It returns internal decisions with cluster keys: never export those. Use RAKSHA_SECRET from environment in the actual pipeline, never test secrets. Integrate with Person B's code and validate formats before release. All fixtures synthetic and independent of practice identities.
