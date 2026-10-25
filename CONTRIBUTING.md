# Contributing

Docket's rule: **a check must be able to say no, and "I don't know" must never become a pass.**

```bash
git clone <your fork> && cd docket
bash scripts/quickstart.sh
```

Adding a verifier: put it in `verifiers.py` (assumptions), `proof.py` (evidence) or `codeverify.py` (code), return
`(status, reason)` with `pass | fail | unverified`, and add tests with one passing case, one failing case, and
malformed input (see `tests/test_robustness.py`). Prefer deterministic evidence over another model's opinion.

Good first contributions: verifiers for new vulnerability classes, call-graph/taint support for other languages,
more AWS/Azure/GCP facts verifiers, and judge adapters for other model providers.

Before opening a PR: `python -m pytest -q` and `docket selftest` must pass. If you change a check, run
`bash benchmarks/run_public.sh` and compare the numbers; a change that kills a real bug in a vulnerable app is a regression.
New importers go in `importers.py` (add a sniff rule and a test with a real sample). Plugin verifiers need no change to Docket at all (see docs/reference.md).
