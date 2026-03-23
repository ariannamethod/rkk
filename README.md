# rkk

`rkk` is a one-file C knowledge kernel backed by SQLite. It stays deliberately narrow: local files in, lineage-preserving chunks and links inside SQLite, deterministic retrieval packets out.

## What the kernel is
- A brutalist CLI around a single `kk.c` binary.
- A SQLite-only archival and retrieval core.
- A disciplined kernel for documents, namespaces, scopes, lineage, and model-facing packets.
- Not a daemon, not a vector platform, not a plugin host.

## Core commands
- `kk init <db>`
- `kk ingest <db> <dir> <namespace> [scope]`
- `kk watch <db> <dir> <namespace> [scope] [interval_sec] [cycles]`
- `kk query <db> <query> <access_scope> <top_k> [raw|citation|compressed] [namespace_filter]`
- `kk namespace-set <db> <namespace> <scope> "<description>"`
- `kk namespace-list <db>`
- `kk inspect-document <db> <document_path>`
- `kk document-history <db> <document_path>`
- `kk namespace-stats <db> <namespace> <scope>`
- `kk check-integrity <db>`
- `kk rebuild-fts <db>`
- `kk stats <db>`

## Model contract commands
- `kk attach-model <db> <model_name> <scope_default> <namespace_default>`
- `kk update-model <db> <model_name> <scope_default> <namespace_default>`
- `kk model-set-profile <db> <model_name> <tiny|balanced|deep>`
- `kk list-models <db>`
- `kk profiles`
- `kk inspect-model <db> <model_name>`
- `kk model-history <db> <model_name>`
- `kk detach-model <db> <model_name>`
- `kk ask <db> <model_name> "<query>" [k]`

Attached models currently keep:
- `retrieval_mode_default=compressed`
- `packet_mode_default=deterministic-json-v1`
- `query_profile_default=balanced`

`attach-model` and `update-model` are strict manifest-bound operations:
- the target namespace manifest must already exist
- the manifest scope must exactly match `scope_default`
- namespace identity does not float across scopes
- scope/namespace mismatch is a hard error and records no attachment/update event

## Query profiles
`kk ask` now applies an explicit built-in query profile after retrieval resolution succeeds. Profiles are hardcoded, inspectable, and deterministic.

- `tiny`
  - `result_cap=2`
  - `excerpt_chars=160`
  - `lineage_chars=96`
  - `provenance_chars=96`
  - no structural link payload
  - no adjacent/topology context
  - no detailed score breakdown
- `balanced`
  - `result_cap=4`
  - `excerpt_chars=240`
  - `lineage_chars=160`
  - `provenance_chars=160`
  - includes structural link counts
  - excludes adjacent/topology neighbor text
  - includes core score breakdown fields
- `deep`
  - `result_cap=6`
  - `excerpt_chars=420`
  - `lineage_chars=256`
  - `provenance_chars=256`
  - includes structural link counts
  - includes adjacent chunk context
  - includes full score breakdown fields

Use `kk profiles` to inspect the exact built-in budget rules. Use `kk model-set-profile` to update a model’s default profile. Existing attached models migrate to `balanced`.

## Data model
- `namespaces`: strict namespace identity and scope.
- `namespace_manifest`: namespace declarations that make ask-time scope/namespace contracts explicit.
- `documents`: canonical file identity per namespace/path.
- `document_versions`: immutable version lineage with seen timestamps and diff metrics.
- `sections` / `chunks`: structural segmentation.
- `links`: structural and related chunk links.
- `chunk_fts`: SQLite FTS substrate for lexical retrieval.
- `model_registry`: current attached model defaults and lifecycle state.
- `model_attachment_events`: append-only attachment/update/detach history.
- `retrieval_log`: query audit trail.

## Maintenance and observability
Observability is part of kernel discipline, not an afterthought. The kernel should stay inspectable with deterministic commands that expose the exact state already present in SQLite, without introducing background services or hidden repair logic.

- `kk inspect-document <db> <document_path>`
  - deterministic human-readable summary for one canonical document path
  - includes namespace, scope, latest version, total versions, seen timestamps, latest SHA, size/token-ish summary, latest chunk count, FTS presence, and latest lineage/diff summary
- `kk document-history <db> <document_path>`
  - deterministic ordered history of every known version for a document
  - includes version number, SHA, latest flag, ingest/seen timestamps, delta fields, change ratio, diff summary, and whether an older version was later reactivated
- `kk namespace-stats <db> <namespace> <scope>`
  - validates the namespace/scope contract against the manifest before reporting
  - includes manifest metadata, document/version/chunk counts, latest ingest timestamp, attached model count, and latest-chunk FTS coverage
- `kk check-integrity <db>`
  - lightweight inspection-only sanity checks
  - runs SQLite integrity check plus kernel-specific checks for orphaned versions, chunks without versions, missing latest-chunk FTS rows, namespace/manifest mismatches, manifest owner mismatches, missing model manifests, and invalid scope rows
  - returns deterministic `PASS`/`FAIL` output with explicit counts
- `kk rebuild-fts <db>`
  - optional lightweight repair
  - rebuilds `chunk_fts` from canonical chunk/document/namespace/section rows when drift is detected
  - no daemon, no background repair loop, no semantic mutation of canonical lineage data

## `kk ask` packet contract
`kk ask` now emits:
- `packet_schema_version`
- `ask_schema_version`
- deterministic top-level field ordering
- `query_profile`
- `context_budget`
- `budgeting`
- `resolution_trace` with the exact legal searched scopes, searched namespace, per-stage hit counts, whether a public fallback stage was actually queried, and whether all queried stages were zero-hit
- explicit machine-friendly `error` packets when the model is missing, the namespace manifest is missing, the namespace/scope contract mismatches, or all stages return zero hits

### Deterministic context budgeting
- Validation and exact manifest-bound scope/namespace resolution happen first.
- Budgeting happens only after a valid retrieval stage resolves hits.
- Budgeting is deterministic, not heuristic.
- The active profile controls:
  - maximum returned results
  - excerpt character cap
  - lineage summary character cap and verbosity
  - provenance summary character cap and verbosity
  - score breakdown detail level
  - structural link inclusion
  - adjacent/topology context inclusion
- Truncation is explicit via stable boolean fields such as `text_truncated`, `lineage_summary_truncated`, `trust_provenance.summary_truncated`, and top-level `budgeting.any_truncation`.

### `resolution_trace`
- `searched_scopes`: only the legal scopes considered in order for the attached model registration.
- `searched_namespace`: namespace bound to the attached model.
- `hit_stage_index` / `hit_scope`: which stage produced hits, or `null`.
- `fallback_to_public`: `true` only when the current architecture legally queried a public stage.
- `zero_hit_all_stages`: `true` only when every queried stage returned zero hits.
- `stages`: deterministic per-stage objects with `stage_index`, `scope`, `queried`, `hit_count`, and `zero_hit`.

Under the current architecture, namespace identity is strict and one manifest is bound to one scope. In practice this means `kk ask` resolves only against the attached model's exact registered namespace/scope binding; it does not pretend that the same namespace can transparently fall across scopes.

## Stable Contract Surface
- Stable CLI contract surfaces: `kk ask`, `kk inspect-model`, `kk inspect-document`, `kk check-integrity`, `kk profiles`, and machine-friendly failure packets/errors for manifest-bound model and namespace validation.
- Packet schema versions such as `kk.packet.v2` and `kk.ask.v2` are part of the contract and must appear exactly where documented.
- Deterministic field ordering and deterministic result ordering are part of the contract; repeated execution against the same fixture is expected to produce the same normalized output.
- Manifest-bound namespace/scope rules are part of the contract: namespace identity is strict, scope does not float, and manifest mismatches are hard failures.
- Golden tests in `tests/golden/` exist specifically to detect silent contract drift.

### Success packet example
```json
{
  "packet_schema_version": "kk.packet.v2",
  "ask_schema_version": "kk.ask.v2",
  "packet_mode": "deterministic-json-v1",
  "query": "lineage kernel",
  "model_name": "model-public",
  "scope": "public",
  "registered_scope": "public",
  "namespace": "alpha",
  "retrieval_mode": "compressed",
  "query_profile": "balanced",
  "context_budget": {
    "profile": "balanced",
    "result_cap": 4
  },
  "score_policy": {
    "lexical": 0.36,
    "recency": 0.12,
    "trust": 0.10,
    "linkage": 0.16,
    "scope": 0.10,
    "namespace": 0.08,
    "freshness": 0.08
  },
  "resolution_trace": {
    "searched_scopes": ["public"],
    "searched_namespace": "alpha",
    "hit_stage_index": 0,
    "hit_scope": "public",
    "fallback_to_public": false,
    "zero_hit_all_stages": false,
    "stages": [
      {
        "stage_index": 0,
        "scope": "public",
        "queried": true,
        "hit_count": 1,
        "zero_hit": false
      }
    ]
  },
  "results": [
    {
      "document_path": "/tmp/rkk-step4/docs/alpha.md",
      "title": "Alpha Kernel"
    }
  ],
  "budgeting": {
    "applied": true,
    "requested_top_k": 5,
    "profile_result_cap": 4,
    "effective_result_cap": 4,
    "retrieved_result_count": 4,
    "returned_result_count": 4,
    "result_truncated": false,
    "any_truncation": false
  }
}
```

### Zero-hit packet example
```json
{
  "packet_schema_version": "kk.packet.v2",
  "ask_schema_version": "kk.ask.v2",
  "packet_mode": "deterministic-json-v1",
  "query": "nonesuchtoken",
  "model_name": "model-public",
  "scope": "",
  "registered_scope": "public",
  "namespace": "alpha",
  "retrieval_mode": "compressed",
  "query_profile": "balanced",
  "context_budget": {
    "profile": "balanced",
    "result_cap": 4
  },
  "score_policy": {
    "lexical": 0.36,
    "recency": 0.12,
    "trust": 0.10,
    "linkage": 0.16,
    "scope": 0.10,
    "namespace": 0.08,
    "freshness": 0.08
  },
  "resolution_trace": {
    "searched_scopes": ["public"],
    "searched_namespace": "alpha",
    "hit_stage_index": null,
    "hit_scope": null,
    "fallback_to_public": false,
    "zero_hit_all_stages": true,
    "stages": [
      {
        "stage_index": 0,
        "scope": "public",
        "queried": true,
        "hit_count": 0,
        "zero_hit": true
      }
    ]
  },
  "results": [],
  "budgeting": {
    "applied": false,
    "requested_top_k": 5,
    "profile_result_cap": 4,
    "effective_result_cap": 4,
    "retrieved_result_count": 0,
    "returned_result_count": 0,
    "result_truncated": false,
    "any_truncation": false
  },
  "error": {
    "code": "no_matches",
    "model_name": "model-public",
    "namespace": "alpha",
    "searched_scopes": ["public"],
    "reason": "zero_hits_all_stages"
  }
}
```

## Scope and namespace rules
Supported scopes stay strict:
- `public`
- `shared:<group>`
- `private:<model_name>`

Rules:
- namespace matching is exact
- scope matching is exact
- attached model asks are namespace-bound by default
- attach/update require an existing manifest-bound namespace before any write occurs
- namespace manifests are required for attached-model asks
- namespace identity is strict; the same namespace does not float across scopes
- `private:<model_name>` must exactly match the attached model name
- namespace/scope mismatches are hard attach/update errors and explicit machine-friendly ask errors for stale invalid rows
- fallback behavior, if ever legal in the current architecture, is explicit in `resolution_trace`; it is never fuzzy or implied
- query profile budgeting never replaces validation or resolution; it only shapes the final packet after valid retrieval hits exist

## Invariants that must not break
- One C file only.
- SQLite only.
- No external dependencies beyond libc, sqlite3, and libm.
- No background daemon framework.
- No embeddings, vectors, sockets, daemons, plugins, ACLs, or UI layers.
- Namespace/scope mismatch is an error.
- Packet field order is deterministic.
- Context budgeting is deterministic and inspectable.
- Maintenance and observability stay explicit, deterministic, and inspection-first.
- Lineage must remain queryable.
- Attached model queries are namespace-bound by default.
