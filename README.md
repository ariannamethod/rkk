# rkk

Internal engineering note / draft README skeleton.

## Purpose

`rkk` is a one-file C knowledge kernel: SQLite-backed ingest, versioned lineage, structural linking, and retrieval packets for attached models.
It is not a demo wrapper around storage; it is the early substrate for a living knowledge field.

## Core commands

```sh
cc -O2 -std=c11 -Wall -Wextra -pedantic kk.c -lsqlite3 -lm -o kk
./kk init kernel.db
./kk ingest kernel.db ./docs field public
./kk query kernel.db "resonance scoring" public 5 citation
./kk policy kernel.db lexical=0.34 linkage=0.16 freshness=0.05
./kk watch kernel.db ./docs field public 5 3
./kk stats kernel.db
```

## Data model

- `namespaces`: namespace name + scope/visibility metadata.
- `documents`: canonical file path within a namespace.
- `document_versions`: immutable SHA256-addressed content versions, latest pointer, delta metadata.
- `sections`: section topology derived from normalized source text.
- `chunks`: model-facing retrieval atoms.
- `links`: structural and related local field edges.
- `chunk_fts`: SQLite FTS5 search surface.
- `retrieval_log`: query audit trail.
- `resonance_policy`: configurable weighting policy for resonance scoring.

## Namespaces and scopes

- `public`: globally readable.
- `private:model_name`: strict per-model private field.
- `shared:group_name`: explicit shared scope.

Scope matching is exact except that `public` is readable from any access scope.

## Retrieval modes

- `raw`: direct chunk output with full score audit.
- `citation`: raw output plus provenance-oriented citation line.
- `compressed`: compact model packet with provenance, lineage, resonance audit, and compressed payload text.

## Future extension points

- richer lineage-aware diff summaries and packet compaction
- tighter structural field heuristics and cross-version bridges
- selective ACL overlays without weakening scope discipline
- model attachment protocols built on kernel packets rather than ad hoc prompts
