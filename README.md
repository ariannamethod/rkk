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
- `kk stats <db>`

## Model contract commands
- `kk attach-model <db> <model_name> <scope_default> <namespace_default>`
- `kk update-model <db> <model_name> <scope_default> <namespace_default>`
- `kk list-models <db>`
- `kk inspect-model <db> <model_name>`
- `kk model-history <db> <model_name>`
- `kk detach-model <db> <model_name>`
- `kk ask <db> <model_name> "<query>" [k]`

Attached models currently keep:
- `retrieval_mode_default=compressed`
- `packet_mode_default=deterministic-json-v1`

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

## `kk ask` packet contract
`kk ask` now emits:
- `packet_schema_version`
- `ask_schema_version`
- deterministic top-level field ordering
- `resolution_trace` with searched scopes, searched namespace, per-stage hit counts, whether a public fallback stage was actually queried, and whether all queried stages were zero-hit
- explicit machine-friendly `error` packets when the model is missing, the namespace manifest is missing, the namespace/scope contract mismatches, or all stages return zero hits

### `resolution_trace`
- `searched_scopes`: scopes considered in order.
- `searched_namespace`: namespace bound to the attached model.
- `hit_stage_index` / `hit_scope`: which stage produced hits, or `null`.
- `fallback_to_public`: `true` only when the public stage was actually queried.
- `zero_hit_all_stages`: `true` only when every queried stage returned zero hits.
- `stages`: deterministic per-stage objects with `stage_index`, `scope`, `queried`, `hit_count`, and `zero_hit`.

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
  ]
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
- namespace manifests are required for attached-model asks
- `private:<model_name>` must exactly match the attached model name
- public fallback, when allowed, is explicit in `resolution_trace`; it is never fuzzy

## Invariants that must not break
- One C file only.
- SQLite only.
- No external dependencies beyond libc, sqlite3, and libm.
- No background daemon framework.
- No embeddings, vectors, sockets, daemons, plugins, ACLs, or UI layers.
- Namespace/scope mismatch is an error.
- Packet field order is deterministic.
- Lineage must remain queryable.
- Attached model queries are namespace-bound by default.
