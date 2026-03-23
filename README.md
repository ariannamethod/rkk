# rkk

`rkk` is a one-file C knowledge kernel backed by SQLite. It is deliberately small: local files in, lineage-preserving chunks and links inside SQLite, deterministic retrieval packets out.

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
- `kk stats <db>`

## Model attachment
`attach-model` makes model defaults explicit instead of implicit.

- `kk attach-model <db> <model_name> <scope_default> <namespace_default>`
- `kk list-models <db>`
- `kk detach-model <db> <model_name>`
- `kk ask <db> <model_name> "<query>" [k]`

Attached models currently receive these defaults:
- `retrieval_mode_default=compressed`
- `packet_mode_default=deterministic-json-v1`

`kk ask` resolves the model from `model_registry`, applies its registered scope and namespace, and returns a deterministic JSON packet with:
- packet schema version
- query and model identity
- resolved scope and namespace
- retrieval mode and score policy
- explicit resolution order
- result packets with path, title, version info, anchor, excerpt, locator, score breakdown, lineage summary, and trust/provenance metadata

## Scopes and namespaces
Supported scopes stay strict:
- `public`
- `shared:<group>`
- `private:<model_name>`

Rules:
- namespace matching is exact
- scope matching is exact except that `public` may be read from broader queries
- `kk ask` resolves in order, never fuzzily:
  - `private:<model_name>` first when that is the model default
  - `shared:<group>` first when that is the model default
  - `public` fallback last

Namespace manifests make namespaces intentional:
- `kk namespace-set <db> <namespace> <scope> "<description>"`
- `kk namespace-list <db>`

## Data model
- `namespaces`: strict namespace identity and scope.
- `namespace_manifest`: lightweight namespace descriptions and ownership hints.
- `documents`: canonical file identity per namespace/path.
- `document_versions`: immutable version lineage with seen timestamps and diff metrics.
- `sections` / `chunks`: structural segmentation.
- `links`: structural and related chunk links.
- `chunk_fts`: SQLite FTS substrate for lexical retrieval.
- `model_registry`: attached model defaults and lifecycle state.
- `retrieval_log`: query audit trail.

## Invariants that must not break
- One C file only.
- SQLite only.
- No background daemon framework.
- No external dependencies beyond libc, sqlite3, and libm.
- Namespace filtering remains strict and explicit.
- Scope resolution remains explicit and deterministic.
- Lineage/history semantics remain preserved; new versions extend history instead of replacing it.
- Model-facing packets must keep deterministic field order and an explicit schema version.
