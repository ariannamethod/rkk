# rkk / Knowledge Kernel

`kk.c` is a single-file C prototype of a **Knowledge Kernel**: a persistent knowledge substrate that ingests text documents, versions them by SHA256, chunks them structurally, indexes them in SQLite/FTS5, and retrieves context through a resonance-style ranking function.

## What it does

- scans directories recursively and ingests `.md`, `.txt`, `.json`, `.html`, `.csv`
- computes SHA256 for each file and skips unchanged documents
- versions changed documents while preserving lineage
- splits documents into `document -> section -> chunk`
- persists everything into SQLite
- maintains lexical search through FTS5
- stores structural links between adjacent and semantically overlapping chunks
- enforces namespace/scope visibility (`public`, `private:*`, `shared:*`)
- exposes model-agnostic query output modes:
  - `raw`
  - `citation`
  - `compressed`

## Build

```bash
cc -O2 -Wall -Wextra -std=c11 kk.c -lsqlite3 -lm -o kk
```

## CLI

```bash
./kk init kernel.db
./kk ingest kernel.db ./docs public
./kk ingest kernel.db ./private_docs private:model_janus
./kk query kernel.db "prophecy debt architecture" public 5
./kk query kernel.db "root transformer hebrew" private:model_pitomadom 8 citation
./kk query kernel.db "root transformer hebrew" private:model_pitomadom 8 compressed
./kk stats kernel.db
```

## Query semantics

A request scoped to namespace `X` can see:

- all chunks in `public`
- all chunks in `X`

Each result carries an explainable score built from:

- lexical relevance
- recency
- trust
- linkage density
- namespace/scope match
- version freshness

## Notes

This MVP deliberately optimizes for a hard foundation:

- one C file
- SQLite persistence
- no Python
- no external indexing service
- explainable retrieval instead of opaque ranking

It is a **proto-OS for knowledge**, not a generic RAG wrapper.
