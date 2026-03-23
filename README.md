# rkk

## Purpose
A one-file C knowledge kernel backed by SQLite. It ingests local document trees, preserves lineage, builds structural and related links, and emits retrieval packets for attached models.

## Commands
- `kk init <db>`
- `kk ingest <db> <dir> <namespace> [scope]`
- `kk watch <db> <dir> <namespace> [scope] [interval_sec] [cycles]`
- `kk query <db> <query> <access_scope> <top_k> [raw|citation|compressed] [namespace_filter]`
- `kk stats <db>`

## Data model
- `namespaces`: namespace name + visibility scope.
- `documents`: canonical file identity by namespace/path.
- `document_versions`: SHA256-based versions, latest pointer, seen timestamps, diff metrics.
- `sections` / `chunks`: structural segmentation.
- `links`: structural adjacency/topology and related affinity links.
- `chunk_fts`: SQLite FTS substrate for lexical recall.

## Namespaces and scopes
- `public`
- `shared:<group>`
- `private:<model_name>`

Scope checks stay strict: public is globally readable, shared/private require exact scope match.

## Retrieval modes
- `raw`: full retrieval details + chunk text.
- `citation`: raw plus explicit provenance lines.
- `compressed`: model-facing packet with citation, provenance, lineage, and score breakdown.

## Future extension points
- richer diff-aware lineage at chunk-to-chunk granularity
- stronger trust policies per source family
- attachment-aware packet shaping for downstream models
- minimal ACL overlays without breaking current scope discipline
