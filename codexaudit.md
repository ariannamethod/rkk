# Adaptive Knowledge Kernel Audit — Step 7

## Audit metadata
- Audit date/time: 2026-03-23 19:54:07 UTC
- Commit hash tested: `0ef8467d2d1df9d4ba8924bfd7e76351816c2d4b`
- Branch tested: `work`

## Exact commands used
```sh
cc -std=c11 -Wall -Wextra -O2 -o kk kk.c -lsqlite3 -lm
bash -n tests/lib.sh tests/run_all.sh
python3 -m py_compile tests/json_assert.py
./tests/run_all.sh
KEEP_TEST_ARTIFACTS=1 ./tests/run_all.sh
```

## Environment assumptions
- Linux shell environment with `bash`, `cc`, and `python3` available.
- SQLite is linked via `-lsqlite3`; no extra kernel runtime dependencies were introduced.
- Tests rely on temporary directories under `/tmp` and Python's standard-library `sqlite3` module for deterministic integrity-damage orchestration.
- The kernel binary remains the single `kk.c`-derived executable; this step adds harness/audit files only.

## Summary counts
- Passed: 9
- Failed: 3
- Skipped: 0

## Overall verdict
The kernel did **not** pass cleanly. The new harness exercised boot, lineage, namespace discipline, model lifecycle, ask contracts, profile budgeting, integrity checking, and regression edges. Most behaviors held, but three contract-level weaknesses surfaced during audit and were intentionally **not** hidden or silently fixed in this step.

## Findings by severity

### Critical
- None observed in this audit pass.

### Major
1. **`attach-model` accepts a missing namespace manifest.**
   - Impact: a model can be registered against a namespace that does not exist in the manifest, deferring the failure to later `kk ask` or integrity checks instead of rejecting the invalid attachment up front.
2. **`attach-model` accepts a scope/namespace contract mismatch.**
   - Impact: a model can be attached with `private:model` scope while pointing at a namespace whose declared scope is `public`, creating an invalid live configuration.
3. **Public fallback for `kk ask` is currently not practically configurable for one namespace.**
   - Impact: the packet contract advertises fallback-to-public traceability for non-public models, but the namespace uniqueness rule blocks creation of both `shared:*`/`private:*` and `public` manifests for the same namespace name, preventing the happy-path fallback scenario from being set up.

### Minor
- None recorded beyond the major findings above.

### Nice-to-have
- Consider exporting machine-readable per-test results from the harness in a more durable location if long-term CI/report archiving becomes important. The current harness is intentionally minimal and local-first.

## Failed tests

### 1) `attach_model_missing_namespace_rejected`
- Reproduction command:
  ```sh
  ./kk init /tmp/kk-audit-missing.db
  ./kk attach-model /tmp/kk-audit-missing.db ghost public missing
  ```
- Observed behavior:
  - Command exited successfully and printed an attached-model confirmation for namespace `missing`.
- Expected behavior:
  - The command should reject the attachment because no namespace manifest exists for `missing` in scope `public`.
- Likely cause:
  - `attach-model` validates the model name and scope syntax, but does not verify that the target namespace manifest exists before inserting/updating `model_registry`.

### 2) `attach_model_scope_contract_rejected`
- Reproduction command:
  ```sh
  ./kk init /tmp/kk-audit-scope.db
  ./kk namespace-set /tmp/kk-audit-scope.db alpha public "Alpha public"
  ./kk attach-model /tmp/kk-audit-scope.db model-a private:model-a alpha
  ```
- Observed behavior:
  - Command exited successfully and attached `model-a` to namespace `alpha` despite the namespace being declared as `public`.
- Expected behavior:
  - The command should reject the attachment because the model scope (`private:model-a`) and namespace manifest scope (`public`) do not match.
- Likely cause:
  - `attach-model` enforces private-scope naming syntax but does not compare `scope_default` against the target namespace manifest scope.

### 3) `public_fallback_traceability`
- Reproduction command:
  ```sh
  ./kk init /tmp/kk-audit-fallback.db
  ./kk namespace-set /tmp/kk-audit-fallback.db alpha shared:team "Alpha shared"
  ./kk namespace-set /tmp/kk-audit-fallback.db alpha public "Alpha public"
  ```
- Observed behavior:
  - The second `namespace-set` failed with:
    - `namespace scope mismatch: namespace=alpha existing=shared:team requested=public`
- Expected behavior:
  - To exercise the documented fallback path, the kernel would need to allow a non-public model namespace to have an eligible public fallback manifest for the same namespace name, and later `kk ask` should emit `resolution_trace.fallback_to_public=true` when that fallback is used.
- Likely cause:
  - The canonical `namespaces` table enforces a unique namespace name with one scope, while `kk ask` still advertises a multi-stage same-namespace fallback search order that assumes a public variant can coexist.

## What I did NOT fix in this step
- I did **not** change `kk.c` to reject invalid model attachments.
- I did **not** redesign namespace identity or fallback semantics.
- I did **not** alter packet schemas, lineage logic, or retrieval scoring.
- I did **not** refactor the one-file kernel architecture.
- I only added the harness/audit surface needed to expose current behavior more rigorously.

## Follow-up fix note — Step 8
- Fixed the invalid registration findings from this audit: `attach-model` now rejects missing namespace manifests and exact scope mismatches, and `update-model` enforces the same validation before any write.
- Contract decision: namespace identity remains strict and manifest-bound to one scope. `kk ask` now resolves only along the attached model's exact legal namespace/scope binding, so the earlier same-namespace public fallback implication is no longer part of the operational contract.
- `resolution_trace` remains deterministic and now reports only the legal search path that was actually queried; when no legal fallback exists, `fallback_to_public` remains `false` and zero-hit packets stay explicit.
- Harness updates now assert rejection of invalid attach/update operations, assert no attachment/update history is written for rejected operations, and treat the old public-fallback expectation as an invalid contract assumption.
- Known issues remaining after this fix pass: none from the three Step 7 audit failures remain open in the current contract surface.
