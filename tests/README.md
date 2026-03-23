# Tests

Run the full audit harness with:

```sh
./tests/run_all.sh
```

Stable contract snapshots live under `tests/golden/`. The harness normalizes fixture-local paths and timestamps before comparing outputs so the contract stays strict without depending on volatile values.

Read `codexaudit.md` for the audited commit, exact commands, pass/fail counts, and findings.
