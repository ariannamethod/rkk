#define _POSIX_C_SOURCE 200809L
#include <ctype.h>
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <inttypes.h>
#include <limits.h>
#include <math.h>
#include <sqlite3.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <time.h>
#include <stdarg.h>
#include <unistd.h>

#ifndef PATH_MAX
#define PATH_MAX 4096
#endif

#define KK_MAX_CHUNK_CHARS 900
#define KK_MIN_CHUNK_CHARS 220
#define KK_MAX_QUERY_TOKENS 16
#define KK_LINK_KIND_STRUCTURAL 1
#define KK_LINK_KIND_RELATED 2

typedef struct {
    uint8_t data[64];
    uint32_t datalen;
    uint64_t bitlen;
    uint32_t state[8];
} SHA256_CTX;

typedef struct {
    char *data;
    size_t len;
    size_t cap;
} StrBuf;

typedef struct {
    char *text;
    size_t start;
    size_t end;
    int level;
    int ordinal;
} SectionInfo;

typedef struct {
    char *text;
    size_t start;
    size_t end;
    int ordinal;
} ChunkInfo;

typedef struct {
    int chunk_id;
    int doc_id;
    int version_id;
    int version_num;
    int previous_version_id;
    int structural_links;
    int related_links;
    int token_estimate;
    double lexical;
    double lexical_norm;
    double recency;
    double trust;
    double linkage;
    double scope_score;
    double namespace_score;
    double freshness;
    double delta_ratio;
    int delta_chars;
    double resonance;
    const char *path;
    const char *filename;
    const char *namespace_name;
    const char *scope_name;
    const char *raw_text;
    const char *sha256;
    const char *ingest_ts;
    const char *section_title;
    const char *change_summary;
} QueryResult;

typedef struct {
    double lexical;
    double recency;
    double trust;
    double linkage;
    double scope;
    double namespace_score;
    double freshness;
} ResonancePolicy;

typedef struct {
    int chunk_id;
    int section_id;
    int section_ordinal;
    int chunk_ordinal;
    char *section_title;
    char *raw_text;
} IngestChunkRef;

static void die(const char *msg) {
    fprintf(stderr, "fatal: %s\n", msg);
    exit(1);
}

static void die_sqlite(sqlite3 *db, const char *msg) {
    fprintf(stderr, "sqlite error: %s: %s\n", msg, sqlite3_errmsg(db));
    exit(1);
}

static void *xmalloc(size_t n) {
    void *p = malloc(n ? n : 1);
    if (!p) die("out of memory");
    return p;
}

static void *xrealloc(void *ptr, size_t n) {
    void *p = realloc(ptr, n ? n : 1);
    if (!p) die("out of memory");
    return p;
}

static char *xstrdup(const char *s) {
    size_t n = strlen(s);
    char *r = xmalloc(n + 1);
    memcpy(r, s, n + 1);
    return r;
}

static char *xstrndup(const char *s, size_t n) {
    char *r = xmalloc(n + 1);
    memcpy(r, s, n);
    r[n] = '\0';
    return r;
}

static void sb_init(StrBuf *sb) {
    sb->data = xmalloc(1);
    sb->data[0] = '\0';
    sb->len = 0;
    sb->cap = 1;
}

static void sb_reserve(StrBuf *sb, size_t extra) {
    size_t need = sb->len + extra + 1;
    if (need <= sb->cap) return;
    size_t cap = sb->cap;
    while (cap < need) cap *= 2;
    sb->data = xrealloc(sb->data, cap);
    sb->cap = cap;
}

static void sb_append_n(StrBuf *sb, const char *s, size_t n) {
    sb_reserve(sb, n);
    memcpy(sb->data + sb->len, s, n);
    sb->len += n;
    sb->data[sb->len] = '\0';
}

static void sb_appendf(StrBuf *sb, const char *fmt, ...) {
    va_list ap;
    va_start(ap, fmt);
    va_list ap2;
    va_copy(ap2, ap);
    int need = vsnprintf(NULL, 0, fmt, ap);
    va_end(ap);
    if (need < 0) die("vsnprintf failed");
    sb_reserve(sb, (size_t)need);
    vsnprintf(sb->data + sb->len, sb->cap - sb->len, fmt, ap2);
    va_end(ap2);
    sb->len += (size_t)need;
}







static uint32_t rotr(uint32_t x, uint32_t n) { return (x >> n) | (x << (32 - n)); }

static const uint32_t k256[64] = {
    0x428a2f98,0x71374491,0xb5c0fbcf,0xe9b5dba5,0x3956c25b,0x59f111f1,0x923f82a4,0xab1c5ed5,
    0xd807aa98,0x12835b01,0x243185be,0x550c7dc3,0x72be5d74,0x80deb1fe,0x9bdc06a7,0xc19bf174,
    0xe49b69c1,0xefbe4786,0x0fc19dc6,0x240ca1cc,0x2de92c6f,0x4a7484aa,0x5cb0a9dc,0x76f988da,
    0x983e5152,0xa831c66d,0xb00327c8,0xbf597fc7,0xc6e00bf3,0xd5a79147,0x06ca6351,0x14292967,
    0x27b70a85,0x2e1b2138,0x4d2c6dfc,0x53380d13,0x650a7354,0x766a0abb,0x81c2c92e,0x92722c85,
    0xa2bfe8a1,0xa81a664b,0xc24b8b70,0xc76c51a3,0xd192e819,0xd6990624,0xf40e3585,0x106aa070,
    0x19a4c116,0x1e376c08,0x2748774c,0x34b0bcb5,0x391c0cb3,0x4ed8aa4a,0x5b9cca4f,0x682e6ff3,
    0x748f82ee,0x78a5636f,0x84c87814,0x8cc70208,0x90befffa,0xa4506ceb,0xbef9a3f7,0xc67178f2
};

static void sha256_transform(SHA256_CTX *ctx, const uint8_t data[]) {
    uint32_t m[64];
    for (int i = 0, j = 0; i < 16; i++, j += 4) {
        m[i] = ((uint32_t)data[j] << 24) | ((uint32_t)data[j + 1] << 16) |
               ((uint32_t)data[j + 2] << 8) | (uint32_t)data[j + 3];
    }
    for (int i = 16; i < 64; i++) {
        uint32_t s0 = rotr(m[i - 15], 7) ^ rotr(m[i - 15], 18) ^ (m[i - 15] >> 3);
        uint32_t s1 = rotr(m[i - 2], 17) ^ rotr(m[i - 2], 19) ^ (m[i - 2] >> 10);
        m[i] = m[i - 16] + s0 + m[i - 7] + s1;
    }

    uint32_t a = ctx->state[0], b = ctx->state[1], c = ctx->state[2], d = ctx->state[3];
    uint32_t e = ctx->state[4], f = ctx->state[5], g = ctx->state[6], h = ctx->state[7];

    for (int i = 0; i < 64; i++) {
        uint32_t S1 = rotr(e, 6) ^ rotr(e, 11) ^ rotr(e, 25);
        uint32_t ch = (e & f) ^ (~e & g);
        uint32_t temp1 = h + S1 + ch + k256[i] + m[i];
        uint32_t S0 = rotr(a, 2) ^ rotr(a, 13) ^ rotr(a, 22);
        uint32_t maj = (a & b) ^ (a & c) ^ (b & c);
        uint32_t temp2 = S0 + maj;

        h = g;
        g = f;
        f = e;
        e = d + temp1;
        d = c;
        c = b;
        b = a;
        a = temp1 + temp2;
    }

    ctx->state[0] += a; ctx->state[1] += b; ctx->state[2] += c; ctx->state[3] += d;
    ctx->state[4] += e; ctx->state[5] += f; ctx->state[6] += g; ctx->state[7] += h;
}

static void sha256_init(SHA256_CTX *ctx) {
    ctx->datalen = 0;
    ctx->bitlen = 0;
    ctx->state[0] = 0x6a09e667;
    ctx->state[1] = 0xbb67ae85;
    ctx->state[2] = 0x3c6ef372;
    ctx->state[3] = 0xa54ff53a;
    ctx->state[4] = 0x510e527f;
    ctx->state[5] = 0x9b05688c;
    ctx->state[6] = 0x1f83d9ab;
    ctx->state[7] = 0x5be0cd19;
}

static void sha256_update(SHA256_CTX *ctx, const uint8_t *data, size_t len) {
    for (size_t i = 0; i < len; i++) {
        ctx->data[ctx->datalen++] = data[i];
        if (ctx->datalen == 64) {
            sha256_transform(ctx, ctx->data);
            ctx->bitlen += 512;
            ctx->datalen = 0;
        }
    }
}

static void sha256_final(SHA256_CTX *ctx, uint8_t hash[]) {
    uint32_t i = ctx->datalen;
    if (ctx->datalen < 56) {
        ctx->data[i++] = 0x80;
        while (i < 56) ctx->data[i++] = 0x00;
    } else {
        ctx->data[i++] = 0x80;
        while (i < 64) ctx->data[i++] = 0x00;
        sha256_transform(ctx, ctx->data);
        memset(ctx->data, 0, 56);
    }
    ctx->bitlen += (uint64_t)ctx->datalen * 8;
    ctx->data[63] = (uint8_t)(ctx->bitlen);
    ctx->data[62] = (uint8_t)(ctx->bitlen >> 8);
    ctx->data[61] = (uint8_t)(ctx->bitlen >> 16);
    ctx->data[60] = (uint8_t)(ctx->bitlen >> 24);
    ctx->data[59] = (uint8_t)(ctx->bitlen >> 32);
    ctx->data[58] = (uint8_t)(ctx->bitlen >> 40);
    ctx->data[57] = (uint8_t)(ctx->bitlen >> 48);
    ctx->data[56] = (uint8_t)(ctx->bitlen >> 56);
    sha256_transform(ctx, ctx->data);
    for (i = 0; i < 4; i++) {
        hash[i]      = (ctx->state[0] >> (24 - i * 8)) & 0xff;
        hash[i + 4]  = (ctx->state[1] >> (24 - i * 8)) & 0xff;
        hash[i + 8]  = (ctx->state[2] >> (24 - i * 8)) & 0xff;
        hash[i + 12] = (ctx->state[3] >> (24 - i * 8)) & 0xff;
        hash[i + 16] = (ctx->state[4] >> (24 - i * 8)) & 0xff;
        hash[i + 20] = (ctx->state[5] >> (24 - i * 8)) & 0xff;
        hash[i + 24] = (ctx->state[6] >> (24 - i * 8)) & 0xff;
        hash[i + 28] = (ctx->state[7] >> (24 - i * 8)) & 0xff;
    }
}

static int is_supported_ext(const char *path) {
    const char *dot = strrchr(path, '.');
    if (!dot) return 0;
    return !strcasecmp(dot, ".md") || !strcasecmp(dot, ".txt") ||
           !strcasecmp(dot, ".json") || !strcasecmp(dot, ".html") ||
           !strcasecmp(dot, ".csv");
}

static const char *detect_source_type(const char *path) {
    const char *dot = strrchr(path, '.');
    return dot ? dot + 1 : "bin";
}

static int is_markdown_heading(const char *line, int *level_out) {
    int level = 0;
    while (*line == '#') {
        level++;
        line++;
    }
    if (level > 0 && level <= 6 && (*line == ' ' || *line == '\t')) {
        if (level_out) *level_out = level;
        return 1;
    }
    return 0;
}

static char *trim_inplace(char *s) {
    while (isspace((unsigned char)*s)) s++;
    char *end = s + strlen(s);
    while (end > s && isspace((unsigned char)end[-1])) end--;
    *end = '\0';
    return s;
}

static char *read_file_all(const char *path, size_t *out_len, char sha_hex[65], off_t *out_size) {
    int fd = open(path, O_RDONLY);
    if (fd < 0) {
        fprintf(stderr, "warn: cannot open %s: %s\n", path, strerror(errno));
        return NULL;
    }
    struct stat st;
    if (fstat(fd, &st) != 0) {
        close(fd);
        fprintf(stderr, "warn: cannot stat %s: %s\n", path, strerror(errno));
        return NULL;
    }
    char *buf = xmalloc((size_t)st.st_size + 1);
    size_t off = 0;
    SHA256_CTX ctx;
    sha256_init(&ctx);
    while (off < (size_t)st.st_size) {
        ssize_t n = read(fd, buf + off, (size_t)st.st_size - off);
        if (n < 0) {
            if (errno == EINTR) continue;
            fprintf(stderr, "warn: cannot read %s: %s\n", path, strerror(errno));
            free(buf);
            close(fd);
            return NULL;
        }
        if (n == 0) break;
        sha256_update(&ctx, (const uint8_t *)(buf + off), (size_t)n);
        off += (size_t)n;
    }
    close(fd);
    buf[off] = '\0';
    uint8_t hash[32];
    sha256_final(&ctx, hash);
    for (int i = 0; i < 32; i++) sprintf(sha_hex + i * 2, "%02x", hash[i]);
    sha_hex[64] = '\0';
    if (out_len) *out_len = off;
    if (out_size) *out_size = st.st_size;
    return buf;
}

static char *to_absolute_path(const char *path) {
    char *resolved = realpath(path, NULL);
    if (resolved) return resolved;
    return xstrdup(path);
}

static int exec_sql(sqlite3 *db, const char *sql) {
    char *err = NULL;
    int rc = sqlite3_exec(db, sql, NULL, NULL, &err);
    if (rc != SQLITE_OK) {
        fprintf(stderr, "sqlite exec failed: %s\nSQL: %s\n", err ? err : "?", sql);
        sqlite3_free(err);
    }
    return rc;
}

static void begin_tx(sqlite3 *db) {
    if (exec_sql(db, "BEGIN IMMEDIATE;") != SQLITE_OK) die_sqlite(db, "begin tx");
}

static void commit_tx(sqlite3 *db) {
    if (exec_sql(db, "COMMIT;") != SQLITE_OK) die_sqlite(db, "commit tx");
}

static int table_has_column(sqlite3 *db, const char *table, const char *column) {
    sqlite3_stmt *stmt = NULL;
    char sql[256];
    snprintf(sql, sizeof(sql), "PRAGMA table_info(%s);", table);
    if (sqlite3_prepare_v2(db, sql, -1, &stmt, NULL) != SQLITE_OK) die_sqlite(db, "prepare table_info");
    int found = 0;
    while (sqlite3_step(stmt) == SQLITE_ROW) {
        const unsigned char *name = sqlite3_column_text(stmt, 1);
        if (name && !strcmp((const char *)name, column)) {
            found = 1;
            break;
        }
    }
    sqlite3_finalize(stmt);
    return found;
}

static void ensure_column(sqlite3 *db, const char *table, const char *column, const char *alter_sql) {
    if (!table_has_column(db, table, column) && exec_sql(db, alter_sql) != SQLITE_OK) {
        die_sqlite(db, "alter table");
    }
}

static int valid_scope(const char *scope) {
    if (!scope || !*scope) return 0;
    if (!strcmp(scope, "public")) return 1;
    if (!strncmp(scope, "private:", 8) && scope[8] != '\0') return 1;
    if (!strncmp(scope, "shared:", 7) && scope[7] != '\0') return 1;
    return 0;
}

static void require_valid_scope(const char *scope, const char *context) {
    if (!valid_scope(scope)) {
        fprintf(stderr, "invalid scope for %s: %s\n", context, scope ? scope : "<null>");
        fprintf(stderr, "scope must be public | private:model_name | shared:group_name\n");
        exit(1);
    }
}

static void ensure_schema(sqlite3 *db) {
    const char *sql =
        "PRAGMA journal_mode=WAL;"
        "PRAGMA foreign_keys=ON;"
        "CREATE TABLE IF NOT EXISTS namespaces ("
        "  id INTEGER PRIMARY KEY,"
        "  name TEXT NOT NULL UNIQUE,"
        "  scope TEXT NOT NULL,"
        "  visibility TEXT NOT NULL,"
        "  created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP"
        ");"
        "CREATE TABLE IF NOT EXISTS documents ("
        "  id INTEGER PRIMARY KEY,"
        "  namespace_id INTEGER NOT NULL REFERENCES namespaces(id),"
        "  path TEXT NOT NULL,"
        "  filename TEXT NOT NULL,"
        "  source_type TEXT NOT NULL,"
        "  size_bytes INTEGER NOT NULL DEFAULT 0,"
        "  created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,"
        "  latest_version_id INTEGER,"
        "  UNIQUE(namespace_id, path)"
        ");"
        "CREATE TABLE IF NOT EXISTS document_versions ("
        "  id INTEGER PRIMARY KEY,"
        "  document_id INTEGER NOT NULL REFERENCES documents(id) ON DELETE CASCADE,"
        "  version_num INTEGER NOT NULL,"
        "  sha256 TEXT NOT NULL,"
        "  content TEXT NOT NULL,"
        "  ingest_ts TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,"
        "  previous_version_id INTEGER REFERENCES document_versions(id),"
        "  is_latest INTEGER NOT NULL DEFAULT 1,"
        "  trust REAL NOT NULL DEFAULT 0.60,"
        "  content_bytes INTEGER NOT NULL DEFAULT 0,"
        "  delta_chars INTEGER NOT NULL DEFAULT 0,"
        "  delta_ratio REAL NOT NULL DEFAULT 0.0,"
        "  change_summary TEXT NOT NULL DEFAULT '',"
        "  UNIQUE(document_id, version_num)"
        ");"
        "CREATE TABLE IF NOT EXISTS sections ("
        "  id INTEGER PRIMARY KEY,"
        "  version_id INTEGER NOT NULL REFERENCES document_versions(id) ON DELETE CASCADE,"
        "  parent_document_id INTEGER NOT NULL REFERENCES documents(id) ON DELETE CASCADE,"
        "  ordinal INTEGER NOT NULL,"
        "  heading TEXT NOT NULL,"
        "  heading_level INTEGER NOT NULL DEFAULT 0,"
        "  char_start INTEGER NOT NULL,"
        "  char_end INTEGER NOT NULL,"
        "  body_text TEXT NOT NULL"
        ");"
        "CREATE TABLE IF NOT EXISTS chunks ("
        "  id INTEGER PRIMARY KEY,"
        "  version_id INTEGER NOT NULL REFERENCES document_versions(id) ON DELETE CASCADE,"
        "  parent_document_id INTEGER NOT NULL REFERENCES documents(id) ON DELETE CASCADE,"
        "  parent_section_id INTEGER NOT NULL REFERENCES sections(id) ON DELETE CASCADE,"
        "  ordinal INTEGER NOT NULL,"
        "  char_start INTEGER NOT NULL,"
        "  char_end INTEGER NOT NULL,"
        "  token_estimate INTEGER NOT NULL,"
        "  raw_text TEXT NOT NULL"
        ");"
        "CREATE TABLE IF NOT EXISTS links ("
        "  id INTEGER PRIMARY KEY,"
        "  from_chunk_id INTEGER NOT NULL REFERENCES chunks(id) ON DELETE CASCADE,"
        "  to_chunk_id INTEGER NOT NULL REFERENCES chunks(id) ON DELETE CASCADE,"
        "  kind INTEGER NOT NULL,"
        "  weight REAL NOT NULL DEFAULT 1.0,"
        "  reason TEXT NOT NULL"
        ");"
        "CREATE TABLE IF NOT EXISTS retrieval_log ("
        "  id INTEGER PRIMARY KEY,"
        "  query_text TEXT NOT NULL,"
        "  access_scope TEXT NOT NULL,"
        "  namespace_filter TEXT,"
        "  mode TEXT NOT NULL,"
        "  top_k INTEGER NOT NULL,"
        "  created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP"
        ");"
        "CREATE TABLE IF NOT EXISTS resonance_policy ("
        "  key TEXT PRIMARY KEY,"
        "  value REAL NOT NULL"
        ");"
        "CREATE VIRTUAL TABLE IF NOT EXISTS chunk_fts USING fts5("
        "  chunk_id UNINDEXED, raw_text, namespace, scope, path, filename, section_title"
        ");"
        "CREATE INDEX IF NOT EXISTS idx_documents_namespace_path ON documents(namespace_id, path);"
        "CREATE INDEX IF NOT EXISTS idx_versions_doc_latest ON document_versions(document_id, is_latest, version_num DESC);"
        "CREATE INDEX IF NOT EXISTS idx_versions_sha ON document_versions(sha256);"
        "CREATE INDEX IF NOT EXISTS idx_sections_version_ord ON sections(version_id, ordinal);"
        "CREATE INDEX IF NOT EXISTS idx_chunks_version_ord ON chunks(version_id, ordinal);"
        "CREATE INDEX IF NOT EXISTS idx_links_from_kind ON links(from_chunk_id, kind);"
        "CREATE INDEX IF NOT EXISTS idx_links_to_kind ON links(to_chunk_id, kind);";
    if (exec_sql(db, sql) != SQLITE_OK) die_sqlite(db, "schema init");

    ensure_column(db, "document_versions", "content_bytes",
                  "ALTER TABLE document_versions ADD COLUMN content_bytes INTEGER NOT NULL DEFAULT 0;");
    ensure_column(db, "document_versions", "delta_chars",
                  "ALTER TABLE document_versions ADD COLUMN delta_chars INTEGER NOT NULL DEFAULT 0;");
    ensure_column(db, "document_versions", "delta_ratio",
                  "ALTER TABLE document_versions ADD COLUMN delta_ratio REAL NOT NULL DEFAULT 0.0;");
    ensure_column(db, "document_versions", "change_summary",
                  "ALTER TABLE document_versions ADD COLUMN change_summary TEXT NOT NULL DEFAULT '';");

    exec_sql(db, "INSERT OR IGNORE INTO resonance_policy(key, value) VALUES"
                 "('lexical', 0.38),"
                 "('recency', 0.12),"
                 "('trust', 0.10),"
                 "('linkage', 0.14),"
                 "('scope', 0.12),"
                 "('namespace', 0.08),"
                 "('freshness', 0.06);");
}

static sqlite3 *open_db(const char *db_path) {
    sqlite3 *db = NULL;
    if (sqlite3_open(db_path, &db) != SQLITE_OK) die_sqlite(db, "open db");
    ensure_schema(db);
    return db;
}

static int get_namespace_id(sqlite3 *db, const char *name, const char *scope) {
    const char *visibility = (!strncmp(scope, "public", 6)) ? "public" :
                             (!strncmp(scope, "shared:", 7)) ? "shared" : "private";
    sqlite3_stmt *stmt = NULL;
    const char *ins = "INSERT INTO namespaces(name, scope, visibility) VALUES(?, ?, ?) "
                      "ON CONFLICT(name) DO UPDATE SET scope=excluded.scope RETURNING id;";
    if (sqlite3_prepare_v2(db, ins, -1, &stmt, NULL) != SQLITE_OK) die_sqlite(db, "prepare namespace insert");
    sqlite3_bind_text(stmt, 1, name, -1, SQLITE_STATIC);
    sqlite3_bind_text(stmt, 2, scope, -1, SQLITE_STATIC);
    sqlite3_bind_text(stmt, 3, visibility, -1, SQLITE_STATIC);
    int rc = sqlite3_step(stmt);
    if (rc != SQLITE_ROW) die_sqlite(db, "insert namespace");
    int id = sqlite3_column_int(stmt, 0);
    sqlite3_finalize(stmt);
    return id;
}

static ResonancePolicy load_resonance_policy(sqlite3 *db) {
    ResonancePolicy policy = {0.38, 0.12, 0.10, 0.14, 0.12, 0.08, 0.06};
    sqlite3_stmt *stmt = NULL;
    const char *sql = "SELECT key, value FROM resonance_policy;";
    if (sqlite3_prepare_v2(db, sql, -1, &stmt, NULL) != SQLITE_OK) die_sqlite(db, "prepare policy");
    while (sqlite3_step(stmt) == SQLITE_ROW) {
        const char *key = (const char *)sqlite3_column_text(stmt, 0);
        double value = sqlite3_column_double(stmt, 1);
        if (!strcmp(key, "lexical")) policy.lexical = value;
        else if (!strcmp(key, "recency")) policy.recency = value;
        else if (!strcmp(key, "trust")) policy.trust = value;
        else if (!strcmp(key, "linkage")) policy.linkage = value;
        else if (!strcmp(key, "scope")) policy.scope = value;
        else if (!strcmp(key, "namespace")) policy.namespace_score = value;
        else if (!strcmp(key, "freshness")) policy.freshness = value;
    }
    sqlite3_finalize(stmt);
    return policy;
}

static double policy_weight_sum(const ResonancePolicy *policy) {
    return policy->lexical + policy->recency + policy->trust + policy->linkage +
           policy->scope + policy->namespace_score + policy->freshness;
}

static void print_policy(const ResonancePolicy *policy) {
    double sum = policy_weight_sum(policy);
    if (sum <= 0.0) sum = 1.0;
    printf("resonance policy\n");
    printf("  lexical   %.4f (norm %.4f)\n", policy->lexical, policy->lexical / sum);
    printf("  recency   %.4f (norm %.4f)\n", policy->recency, policy->recency / sum);
    printf("  trust     %.4f (norm %.4f)\n", policy->trust, policy->trust / sum);
    printf("  linkage   %.4f (norm %.4f)\n", policy->linkage, policy->linkage / sum);
    printf("  scope     %.4f (norm %.4f)\n", policy->scope, policy->scope / sum);
    printf("  namespace %.4f (norm %.4f)\n", policy->namespace_score, policy->namespace_score / sum);
    printf("  freshness %.4f (norm %.4f)\n", policy->freshness, policy->freshness / sum);
}

static int set_policy_value(sqlite3 *db, const char *key, double value) {
    if (value < 0.0) return 0;
    if (strcmp(key, "lexical") && strcmp(key, "recency") && strcmp(key, "trust") &&
        strcmp(key, "linkage") && strcmp(key, "scope") && strcmp(key, "namespace") &&
        strcmp(key, "freshness")) {
        return 0;
    }
    sqlite3_stmt *stmt = NULL;
    const char *sql = "INSERT INTO resonance_policy(key, value) VALUES(?, ?) "
                      "ON CONFLICT(key) DO UPDATE SET value=excluded.value;";
    if (sqlite3_prepare_v2(db, sql, -1, &stmt, NULL) != SQLITE_OK) die_sqlite(db, "prepare set policy");
    sqlite3_bind_text(stmt, 1, key, -1, SQLITE_STATIC);
    sqlite3_bind_double(stmt, 2, value);
    if (sqlite3_step(stmt) != SQLITE_DONE) die_sqlite(db, "set policy value");
    sqlite3_finalize(stmt);
    return 1;
}

static int estimate_tokens(const char *text) {
    int count = 0, in_token = 0;
    for (const unsigned char *p = (const unsigned char *)text; *p; p++) {
        if (isalnum(*p)) {
            if (!in_token) count++;
            in_token = 1;
        } else {
            in_token = 0;
        }
    }
    return count > 0 ? count : 1;
}

static int contains_word_ci(const char *haystack, const char *needle) {
    size_t n = strlen(needle);
    if (n == 0) return 0;
    for (const char *p = haystack; *p; p++) {
        if (!strncasecmp(p, needle, n)) return 1;
    }
    return 0;
}

static double clamp01(double v) {
    if (v < 0.0) return 0.0;
    if (v > 1.0) return 1.0;
    return v;
}

static int access_scope_allows(const char *doc_scope, const char *access_scope) {
    if (!strcmp(doc_scope, "public")) return 1;
    if (!strcmp(doc_scope, access_scope)) return 1;
    if (!strncmp(doc_scope, "shared:", 7) && !strcmp(doc_scope, access_scope)) return 1;
    return 0;
}

static double scope_compatibility(const char *doc_scope, const char *access_scope) {
    if (!strcmp(doc_scope, access_scope)) return 1.0;
    if (!strcmp(doc_scope, "public")) return 0.75;
    if (!strncmp(doc_scope, "shared:", 7) && !strcmp(doc_scope, access_scope)) return 0.95;
    return 0.0;
}

static char *normalize_text(const char *input) {
    StrBuf out;
    sb_init(&out);
    int prev_space = 0;
    for (const unsigned char *p = (const unsigned char *)input; *p; p++) {
        unsigned char c = *p;
        if (c == '\r') continue;
        if (c == '\t') c = ' ';
        if (iscntrl(c) && c != '\n') c = ' ';
        if (c == '\n') {
            sb_append_n(&out, "\n", 1);
            prev_space = 0;
            continue;
        }
        if (isspace(c)) {
            if (!prev_space) sb_append_n(&out, " ", 1);
            prev_space = 1;
        } else {
            sb_append_n(&out, (char *)&c, 1);
            prev_space = 0;
        }
    }
    return out.data;
}

static int count_lines_in_span(const char *text, size_t start, size_t end) {
    if (end <= start) return 0;
    int lines = 1;
    for (size_t i = start; i < end; i++) if (text[i] == '\n') lines++;
    return lines;
}

static void summarize_delta(const char *previous, const char *current, int *delta_chars, double *delta_ratio, char **summary_out) {
    size_t prev_len = previous ? strlen(previous) : 0;
    size_t cur_len = current ? strlen(current) : 0;
    size_t prefix = 0;
    while (prefix < prev_len && prefix < cur_len && previous[prefix] == current[prefix]) prefix++;
    size_t suffix = 0;
    while (suffix + prefix < prev_len && suffix + prefix < cur_len &&
           previous[prev_len - 1 - suffix] == current[cur_len - 1 - suffix]) {
        suffix++;
    }
    size_t prev_changed = prev_len > prefix + suffix ? prev_len - prefix - suffix : 0;
    size_t cur_changed = cur_len > prefix + suffix ? cur_len - prefix - suffix : 0;
    int prev_lines = count_lines_in_span(previous ? previous : "", prefix, prev_len - suffix);
    int cur_lines = count_lines_in_span(current ? current : "", prefix, cur_len - suffix);
    int chars = (int)(prev_changed + cur_changed);
    double denom = (double)(prev_len + cur_len);
    double ratio = denom > 0.0 ? (double)chars / denom : 0.0;
    StrBuf sb;
    sb_init(&sb);
    sb_appendf(&sb, "prefix=%zu suffix=%zu changed_prev=%zu changed_new=%zu lines_prev=%d lines_new=%d",
               prefix, suffix, prev_changed, cur_changed, prev_lines, cur_lines);
    *delta_chars = chars;
    *delta_ratio = clamp01(ratio);
    *summary_out = sb.data;
}

static int is_stopword(const char *term) {
    static const char *words[] = {
        "the","and","for","with","that","this","from","into","your","have","will","just","about","than","then",
        "were","been","being","when","what","where","which","while","their","there","after","before","under",
        "into","onto","between","within","using","used","also","does","did","done","not","are","you","but","all",
        "can","its","our","out","per","any","each","via","over","same","more","less","than","them"
    };
    for (size_t i = 0; i < sizeof(words) / sizeof(words[0]); i++) {
        if (!strcmp(term, words[i])) return 1;
    }
    return 0;
}

static int unique_terms(const char *text, char terms[][48], int max_terms) {
    int count = 0;
    char *copy = xstrdup(text ? text : "");
    char *save = NULL;
    for (char *tok = strtok_r(copy, " \t\n,.;:!?()[]{}<>\"'/\\|`~@#$%^&*-_=+", &save);
         tok && count < max_terms;
         tok = strtok_r(NULL, " \t\n,.;:!?()[]{}<>\"'/\\|`~@#$%^&*-_=+", &save)) {
        size_t n = strlen(tok);
        if (n < 4 || n >= 48) continue;
        char lower[48];
        for (size_t i = 0; i < n; i++) lower[i] = (char)tolower((unsigned char)tok[i]);
        lower[n] = '\0';
        if (is_stopword(lower)) continue;
        int seen = 0;
        for (int i = 0; i < count; i++) {
            if (!strcmp(terms[i], lower)) {
                seen = 1;
                break;
            }
        }
        if (!seen) strcpy(terms[count++], lower);
    }
    free(copy);
    return count;
}

static int overlap_terms(char a_terms[][48], int a_count, char b_terms[][48], int b_count) {
    int overlap = 0;
    for (int i = 0; i < a_count; i++) {
        for (int j = 0; j < b_count; j++) {
            if (!strcmp(a_terms[i], b_terms[j])) {
                overlap++;
                break;
            }
        }
    }
    return overlap;
}

static void add_section(SectionInfo **arr, int *count, int *cap, const char *text, size_t start, size_t end, int level, int ordinal) {
    if (end <= start) return;
    if (*count == *cap) {
        *cap = *cap ? (*cap * 2) : 8;
        *arr = xrealloc(*arr, (size_t)*cap * sizeof(**arr));
    }
    (*arr)[*count].text = xstrndup(text + start, end - start);
    (*arr)[*count].start = start;
    (*arr)[*count].end = end;
    (*arr)[*count].level = level;
    (*arr)[*count].ordinal = ordinal;
    (*count)++;
}

static SectionInfo *split_sections(const char *text, int *out_count) {
    SectionInfo *sections = NULL;
    int count = 0, cap = 0;
    size_t len = strlen(text);
    size_t pos = 0, section_start = 0;
    int ordinal = 0;
    char current_heading[256] = "root";
    int current_level = 0;
    (void)current_heading;
    while (pos < len) {
        size_t line_start = pos;
        while (pos < len && text[pos] != '\n') pos++;
        size_t line_end = pos;
        if (pos < len && text[pos] == '\n') pos++;
        size_t line_len = line_end - line_start;
        char *line = xstrndup(text + line_start, line_len);
        int level = 0;
        if (is_markdown_heading(line, &level) && line_start != section_start) {
            add_section(&sections, &count, &cap, text, section_start, line_start, current_level, ordinal++);
            section_start = line_start;
            current_level = level;
        } else if (is_markdown_heading(line, &level) && line_start == section_start) {
            current_level = level;
        }
        free(line);
    }
    add_section(&sections, &count, &cap, text, section_start, len, current_level, ordinal++);
    if (count == 0) add_section(&sections, &count, &cap, text, 0, len, 0, 0);
    *out_count = count;
    return sections;
}

static char *section_heading_from_text(const char *text) {
    const char *line_end = strchr(text, '\n');
    size_t len = line_end ? (size_t)(line_end - text) : strlen(text);
    char *line = xstrndup(text, len);
    char *trimmed = trim_inplace(line);
    if (trimmed[0] == '#') {
        while (*trimmed == '#') trimmed++;
        while (*trimmed == ' ' || *trimmed == '\t') trimmed++;
    }
    char *res = xstrdup(*trimmed ? trimmed : "root");
    free(line);
    return res;
}

static void add_chunk(ChunkInfo **arr, int *count, int *cap, const char *text, size_t start, size_t end, int ordinal) {
    if (end <= start) return;
    while (start < end && isspace((unsigned char)text[start])) start++;
    while (end > start && isspace((unsigned char)text[end - 1])) end--;
    if (end <= start) return;
    if (*count == *cap) {
        *cap = *cap ? (*cap * 2) : 16;
        *arr = xrealloc(*arr, (size_t)*cap * sizeof(**arr));
    }
    (*arr)[*count].text = xstrndup(text + start, end - start);
    (*arr)[*count].start = start;
    (*arr)[*count].end = end;
    (*arr)[*count].ordinal = ordinal;
    (*count)++;
}

static ChunkInfo *split_chunks(const char *section_text, size_t section_base, int *out_count) {
    ChunkInfo *chunks = NULL;
    int count = 0, cap = 0, ordinal = 0;
    size_t len = strlen(section_text);
    size_t para_start = 0;
    for (size_t pos = 0; pos <= len; pos++) {
        int boundary = 0;
        if (pos == len) boundary = 1;
        else if (section_text[pos] == '\n' && pos + 1 < len && section_text[pos + 1] == '\n') boundary = 1;
        if (!boundary) continue;
        size_t para_end = pos;
        while (pos < len && section_text[pos] == '\n') pos++;
        size_t start = para_start;
        while (start < para_end && isspace((unsigned char)section_text[start])) start++;
        while (para_end > start && isspace((unsigned char)section_text[para_end - 1])) para_end--;
        if (para_end > start) {
            size_t seg = start;
            while (seg < para_end) {
                size_t take = para_end - seg;
                if (take > KK_MAX_CHUNK_CHARS) {
                    size_t cut = seg + KK_MAX_CHUNK_CHARS;
                    size_t best = cut;
                    for (size_t i = cut; i > seg + KK_MIN_CHUNK_CHARS; i--) {
                        if (isspace((unsigned char)section_text[i])) { best = i; break; }
                    }
                    take = best - seg;
                }
                add_chunk(&chunks, &count, &cap, section_text, seg, seg + take, ordinal++);
                seg += take;
                while (seg < para_end && isspace((unsigned char)section_text[seg])) seg++;
            }
        }
        para_start = pos;
    }
    if (count == 0) add_chunk(&chunks, &count, &cap, section_text, 0, len, 0);
    for (int i = 0; i < count; i++) {
        chunks[i].start += section_base;
        chunks[i].end += section_base;
    }
    *out_count = count;
    return chunks;
}

static int insert_document(sqlite3 *db, int namespace_id, const char *path, const char *filename, const char *source_type, sqlite3_int64 size_bytes) {
    sqlite3_stmt *stmt = NULL;
    const char *sql = "INSERT INTO documents(namespace_id, path, filename, source_type, size_bytes) VALUES(?, ?, ?, ?, ?) "
                      "ON CONFLICT(namespace_id, path) DO UPDATE SET filename=excluded.filename, source_type=excluded.source_type, size_bytes=excluded.size_bytes "
                      "RETURNING id;";
    if (sqlite3_prepare_v2(db, sql, -1, &stmt, NULL) != SQLITE_OK) die_sqlite(db, "prepare insert document");
    sqlite3_bind_int(stmt, 1, namespace_id);
    sqlite3_bind_text(stmt, 2, path, -1, SQLITE_STATIC);
    sqlite3_bind_text(stmt, 3, filename, -1, SQLITE_STATIC);
    sqlite3_bind_text(stmt, 4, source_type, -1, SQLITE_STATIC);
    sqlite3_bind_int64(stmt, 5, size_bytes);
    if (sqlite3_step(stmt) != SQLITE_ROW) die_sqlite(db, "insert document");
    int id = sqlite3_column_int(stmt, 0);
    sqlite3_finalize(stmt);
    return id;
}

static int get_latest_version(sqlite3 *db, int document_id, int *version_num, char sha_out[65], int *version_id, char **content_out) {
    sqlite3_stmt *stmt = NULL;
    const char *sql = "SELECT id, version_num, sha256, content FROM document_versions WHERE document_id=? AND is_latest=1 ORDER BY version_num DESC LIMIT 1;";
    if (sqlite3_prepare_v2(db, sql, -1, &stmt, NULL) != SQLITE_OK) die_sqlite(db, "prepare latest version");
    sqlite3_bind_int(stmt, 1, document_id);
    int found = 0;
    if (sqlite3_step(stmt) == SQLITE_ROW) {
        if (version_id) *version_id = sqlite3_column_int(stmt, 0);
        if (version_num) *version_num = sqlite3_column_int(stmt, 1);
        const unsigned char *sha = sqlite3_column_text(stmt, 2);
        if (sha_out) { memcpy(sha_out, (const char *)sha, 64); sha_out[64] = '\0'; }
        if (content_out) {
            const unsigned char *content = sqlite3_column_text(stmt, 3);
            *content_out = xstrdup(content ? (const char *)content : "");
        }
        found = 1;
    }
    sqlite3_finalize(stmt);
    return found;
}

static int insert_version(sqlite3 *db, int doc_id, int version_num, const char *sha256, const char *content,
                          int prev_version_id, int content_bytes, int delta_chars, double delta_ratio,
                          const char *change_summary) {
    sqlite3_stmt *stmt = NULL;
    if (prev_version_id > 0) {
        const char *upd = "UPDATE document_versions SET is_latest=0 WHERE id=?;";
        if (sqlite3_prepare_v2(db, upd, -1, &stmt, NULL) != SQLITE_OK) die_sqlite(db, "prepare version update");
        sqlite3_bind_int(stmt, 1, prev_version_id);
        if (sqlite3_step(stmt) != SQLITE_DONE) die_sqlite(db, "clear latest version");
        sqlite3_finalize(stmt);
    }
    const char *ins =
        "INSERT INTO document_versions(document_id, version_num, sha256, content, previous_version_id, content_bytes, delta_chars, delta_ratio, change_summary) "
        "VALUES(?, ?, ?, ?, ?, ?, ?, ?, ?) RETURNING id;";
    if (sqlite3_prepare_v2(db, ins, -1, &stmt, NULL) != SQLITE_OK) die_sqlite(db, "prepare insert version");
    sqlite3_bind_int(stmt, 1, doc_id);
    sqlite3_bind_int(stmt, 2, version_num);
    sqlite3_bind_text(stmt, 3, sha256, -1, SQLITE_STATIC);
    sqlite3_bind_text(stmt, 4, content, -1, SQLITE_STATIC);
    if (prev_version_id > 0) sqlite3_bind_int(stmt, 5, prev_version_id); else sqlite3_bind_null(stmt, 5);
    sqlite3_bind_int(stmt, 6, content_bytes);
    sqlite3_bind_int(stmt, 7, delta_chars);
    sqlite3_bind_double(stmt, 8, delta_ratio);
    sqlite3_bind_text(stmt, 9, change_summary ? change_summary : "", -1, SQLITE_STATIC);
    if (sqlite3_step(stmt) != SQLITE_ROW) die_sqlite(db, "insert version");
    int version_id = sqlite3_column_int(stmt, 0);
    sqlite3_finalize(stmt);

    const char *upd_doc = "UPDATE documents SET latest_version_id=? WHERE id=?;";
    if (sqlite3_prepare_v2(db, upd_doc, -1, &stmt, NULL) != SQLITE_OK) die_sqlite(db, "prepare update document latest");
    sqlite3_bind_int(stmt, 1, version_id);
    sqlite3_bind_int(stmt, 2, doc_id);
    if (sqlite3_step(stmt) != SQLITE_DONE) die_sqlite(db, "update document latest");
    sqlite3_finalize(stmt);
    return version_id;
}

static int insert_section_row(sqlite3 *db, int version_id, int document_id, int ordinal, const char *heading, int level, int start, int end, const char *body_text) {
    sqlite3_stmt *stmt = NULL;
    const char *sql = "INSERT INTO sections(version_id, parent_document_id, ordinal, heading, heading_level, char_start, char_end, body_text) VALUES(?, ?, ?, ?, ?, ?, ?, ?) RETURNING id;";
    if (sqlite3_prepare_v2(db, sql, -1, &stmt, NULL) != SQLITE_OK) die_sqlite(db, "prepare section insert");
    sqlite3_bind_int(stmt, 1, version_id);
    sqlite3_bind_int(stmt, 2, document_id);
    sqlite3_bind_int(stmt, 3, ordinal);
    sqlite3_bind_text(stmt, 4, heading, -1, SQLITE_STATIC);
    sqlite3_bind_int(stmt, 5, level);
    sqlite3_bind_int(stmt, 6, start);
    sqlite3_bind_int(stmt, 7, end);
    sqlite3_bind_text(stmt, 8, body_text, -1, SQLITE_STATIC);
    if (sqlite3_step(stmt) != SQLITE_ROW) die_sqlite(db, "insert section");
    int id = sqlite3_column_int(stmt, 0);
    sqlite3_finalize(stmt);
    return id;
}

static int insert_chunk_row(sqlite3 *db, int version_id, int document_id, int section_id, int ordinal, int start, int end, int token_estimate, const char *raw_text) {
    sqlite3_stmt *stmt = NULL;
    const char *sql = "INSERT INTO chunks(version_id, parent_document_id, parent_section_id, ordinal, char_start, char_end, token_estimate, raw_text) VALUES(?, ?, ?, ?, ?, ?, ?, ?) RETURNING id;";
    if (sqlite3_prepare_v2(db, sql, -1, &stmt, NULL) != SQLITE_OK) die_sqlite(db, "prepare chunk insert");
    sqlite3_bind_int(stmt, 1, version_id);
    sqlite3_bind_int(stmt, 2, document_id);
    sqlite3_bind_int(stmt, 3, section_id);
    sqlite3_bind_int(stmt, 4, ordinal);
    sqlite3_bind_int(stmt, 5, start);
    sqlite3_bind_int(stmt, 6, end);
    sqlite3_bind_int(stmt, 7, token_estimate);
    sqlite3_bind_text(stmt, 8, raw_text, -1, SQLITE_STATIC);
    if (sqlite3_step(stmt) != SQLITE_ROW) die_sqlite(db, "insert chunk");
    int id = sqlite3_column_int(stmt, 0);
    sqlite3_finalize(stmt);
    return id;
}

static void insert_link(sqlite3 *db, int from_chunk_id, int to_chunk_id, int kind, double weight, const char *reason) {
    sqlite3_stmt *stmt = NULL;
    const char *sql = "INSERT INTO links(from_chunk_id, to_chunk_id, kind, weight, reason) VALUES(?, ?, ?, ?, ?);";
    if (sqlite3_prepare_v2(db, sql, -1, &stmt, NULL) != SQLITE_OK) die_sqlite(db, "prepare insert link");
    sqlite3_bind_int(stmt, 1, from_chunk_id);
    sqlite3_bind_int(stmt, 2, to_chunk_id);
    sqlite3_bind_int(stmt, 3, kind);
    sqlite3_bind_double(stmt, 4, weight);
    sqlite3_bind_text(stmt, 5, reason, -1, SQLITE_STATIC);
    if (sqlite3_step(stmt) != SQLITE_DONE) die_sqlite(db, "insert link");
    sqlite3_finalize(stmt);
}

static void insert_fts_row(sqlite3 *db, int chunk_id, const char *raw_text, const char *namespace_name, const char *scope, const char *path, const char *filename, const char *section_title) {
    sqlite3_stmt *stmt = NULL;
    const char *sql = "INSERT INTO chunk_fts(chunk_id, raw_text, namespace, scope, path, filename, section_title) VALUES(?, ?, ?, ?, ?, ?, ?);";
    if (sqlite3_prepare_v2(db, sql, -1, &stmt, NULL) != SQLITE_OK) die_sqlite(db, "prepare insert fts");
    sqlite3_bind_int(stmt, 1, chunk_id);
    sqlite3_bind_text(stmt, 2, raw_text, -1, SQLITE_STATIC);
    sqlite3_bind_text(stmt, 3, namespace_name, -1, SQLITE_STATIC);
    sqlite3_bind_text(stmt, 4, scope, -1, SQLITE_STATIC);
    sqlite3_bind_text(stmt, 5, path, -1, SQLITE_STATIC);
    sqlite3_bind_text(stmt, 6, filename, -1, SQLITE_STATIC);
    sqlite3_bind_text(stmt, 7, section_title, -1, SQLITE_STATIC);
    if (sqlite3_step(stmt) != SQLITE_DONE) die_sqlite(db, "insert fts row");
    sqlite3_finalize(stmt);
}

static void infer_related_links(sqlite3 *db, IngestChunkRef *chunks, int count) {
    char terms[256][12][48];
    int term_counts[256];
    if (count > 256) count = 256;
    for (int i = 0; i < count; i++) {
        term_counts[i] = unique_terms(chunks[i].raw_text, terms[i], 12);
    }
    for (int i = 0; i < count; i++) {
        for (int j = i + 1; j < count; j++) {
            int overlap = overlap_terms(terms[i], term_counts[i], terms[j], term_counts[j]);
            if (overlap == 0) continue;
            double heading_affinity = 0.0;
            if (!strcmp(chunks[i].section_title, chunks[j].section_title)) heading_affinity = 1.0;
            else {
                char a_head[8][48], b_head[8][48];
                int a_head_n = unique_terms(chunks[i].section_title, a_head, 8);
                int b_head_n = unique_terms(chunks[j].section_title, b_head, 8);
                int shared_head = overlap_terms(a_head, a_head_n, b_head, b_head_n);
                if (shared_head > 0) heading_affinity = clamp01((double)shared_head / 3.0);
            }
            int section_gap = abs(chunks[i].section_ordinal - chunks[j].section_ordinal);
            double proximity = section_gap == 0 ? 1.0 : (section_gap == 1 ? 0.45 : (section_gap == 2 ? 0.20 : 0.0));
            int min_terms = term_counts[i] < term_counts[j] ? term_counts[i] : term_counts[j];
            if (min_terms < 1) min_terms = 1;
            double overlap_score = clamp01((double)overlap / (double)min_terms);
            double weight = clamp01(0.65 * overlap_score + 0.20 * heading_affinity + 0.15 * proximity);
            if (weight < 0.22) continue;
            char reason[160];
            snprintf(reason, sizeof(reason), "signature overlap=%d heading=%.2f proximity=%.2f", overlap, heading_affinity, proximity);
            insert_link(db, chunks[i].chunk_id, chunks[j].chunk_id, KK_LINK_KIND_RELATED, weight, reason);
            insert_link(db, chunks[j].chunk_id, chunks[i].chunk_id, KK_LINK_KIND_RELATED, weight, reason);
        }
    }
}

static int ingest_file(sqlite3 *db, const char *path, const char *namespace_name, const char *scope) {
    char sha[65];
    size_t len = 0;
    off_t size = 0;
    char *raw = read_file_all(path, &len, sha, &size);
    if (!raw) return 0;
    char *content = normalize_text(raw);
    free(raw);

    char *abs = to_absolute_path(path);
    const char *filename = strrchr(abs, '/');
    filename = filename ? filename + 1 : abs;
    const char *source_type = detect_source_type(abs);

    begin_tx(db);
    int inserted = 0;
    int namespace_id = get_namespace_id(db, namespace_name, scope);
    int doc_id = insert_document(db, namespace_id, abs, filename, source_type, size);
    int latest_num = 0, prev_version_id = 0;
    char latest_sha[65] = {0};
    char *previous_content = NULL;
    if (get_latest_version(db, doc_id, &latest_num, latest_sha, &prev_version_id, &previous_content) && !strcmp(latest_sha, sha)) {
        printf("skip unchanged: %s [%s]\n", abs, sha);
        commit_tx(db);
        free(abs);
        free(content);
        free(previous_content);
        return 0;
    }

    int version_num = latest_num + 1;
    int delta_chars = 0;
    double delta_ratio = 0.0;
    char *change_summary = NULL;
    summarize_delta(previous_content, content, &delta_chars, &delta_ratio, &change_summary);
    int version_id = insert_version(db, doc_id, version_num, sha, content, prev_version_id,
                                    (int)len, delta_chars, delta_ratio, change_summary);

    int section_count = 0;
    SectionInfo *sections = split_sections(content, &section_count);
    int chunk_ordinal = 0;
    int prev_chunk_id = 0;
    int previous_section_anchor = 0;
    IngestChunkRef *chunk_refs = NULL;
    int chunk_ref_count = 0, chunk_ref_cap = 0;
    for (int i = 0; i < section_count; i++) {
        char *heading = section_heading_from_text(sections[i].text);
        int section_id = insert_section_row(db, version_id, doc_id, i, heading, sections[i].level,
                                           (int)sections[i].start, (int)sections[i].end, sections[i].text);
        int chunk_count = 0;
        ChunkInfo *chunks = split_chunks(sections[i].text, sections[i].start, &chunk_count);
        int section_anchor_chunk_id = 0;
        for (int j = 0; j < chunk_count; j++) {
            int chunk_id = insert_chunk_row(db, version_id, doc_id, section_id, chunk_ordinal++,
                                            (int)chunks[j].start, (int)chunks[j].end,
                                            estimate_tokens(chunks[j].text), chunks[j].text);
            insert_fts_row(db, chunk_id, chunks[j].text, namespace_name, scope, abs, filename, heading);
            if (chunk_ref_count == chunk_ref_cap) {
                chunk_ref_cap = chunk_ref_cap ? chunk_ref_cap * 2 : 32;
                chunk_refs = xrealloc(chunk_refs, (size_t)chunk_ref_cap * sizeof(*chunk_refs));
            }
            chunk_refs[chunk_ref_count].chunk_id = chunk_id;
            chunk_refs[chunk_ref_count].section_id = section_id;
            chunk_refs[chunk_ref_count].section_ordinal = i;
            chunk_refs[chunk_ref_count].chunk_ordinal = chunk_ordinal - 1;
            chunk_refs[chunk_ref_count].section_title = xstrdup(heading);
            chunk_refs[chunk_ref_count].raw_text = xstrdup(chunks[j].text);
            chunk_ref_count++;
            if (prev_chunk_id > 0) {
                insert_link(db, prev_chunk_id, chunk_id, KK_LINK_KIND_STRUCTURAL, 1.0, "adjacent chunk");
                insert_link(db, chunk_id, prev_chunk_id, KK_LINK_KIND_STRUCTURAL, 1.0, "adjacent chunk");
            }
            if (section_anchor_chunk_id == 0) {
                section_anchor_chunk_id = chunk_id;
                if (previous_section_anchor > 0) {
                    insert_link(db, previous_section_anchor, section_anchor_chunk_id, KK_LINK_KIND_STRUCTURAL, 0.72, "adjacent section");
                    insert_link(db, section_anchor_chunk_id, previous_section_anchor, KK_LINK_KIND_STRUCTURAL, 0.72, "adjacent section");
                }
            } else {
                insert_link(db, section_anchor_chunk_id, chunk_id, KK_LINK_KIND_STRUCTURAL, 0.64, "shared section anchor");
                insert_link(db, chunk_id, section_anchor_chunk_id, KK_LINK_KIND_STRUCTURAL, 0.64, "shared section anchor");
            }
            prev_chunk_id = chunk_id;
            free(chunks[j].text);
        }
        if (section_anchor_chunk_id > 0) previous_section_anchor = section_anchor_chunk_id;
        free(chunks);
        free(heading);
        free(sections[i].text);
    }
    free(sections);
    infer_related_links(db, chunk_refs, chunk_ref_count);
    commit_tx(db);
    printf("ingested: %s => doc=%d version=%d sha=%s delta=%.3f %s\n",
           abs, doc_id, version_num, sha, delta_ratio, change_summary ? change_summary : "");
    inserted = 1;
    for (int i = 0; i < chunk_ref_count; i++) {
        free(chunk_refs[i].section_title);
        free(chunk_refs[i].raw_text);
    }
    free(chunk_refs);
    free(abs);
    free(content);
    free(previous_content);
    free(change_summary);
    return inserted;
}

static void scan_dir(sqlite3 *db, const char *root, const char *namespace_name, const char *scope, int *count) {
    DIR *dir = opendir(root);
    if (!dir) {
        fprintf(stderr, "warn: cannot open directory %s: %s\n", root, strerror(errno));
        return;
    }
    struct dirent *ent;
    while ((ent = readdir(dir))) {
        if (!strcmp(ent->d_name, ".") || !strcmp(ent->d_name, "..")) continue;
        char path[PATH_MAX];
        snprintf(path, sizeof(path), "%s/%s", root, ent->d_name);
        struct stat st;
        if (lstat(path, &st) != 0) continue;
        if (S_ISDIR(st.st_mode)) {
            scan_dir(db, path, namespace_name, scope, count);
        } else if (S_ISREG(st.st_mode) && is_supported_ext(path)) {
            *count += ingest_file(db, path, namespace_name, scope);
        }
    }
    closedir(dir);
}

static int build_query_terms(const char *query_text, char terms[KK_MAX_QUERY_TOKENS][64]);
static void free_query_result_fields(QueryResult *r);

static void log_retrieval(sqlite3 *db, const char *query_text, const char *access_scope, const char *namespace_filter, const char *mode, int top_k) {
    sqlite3_stmt *stmt = NULL;
    const char *sql = "INSERT INTO retrieval_log(query_text, access_scope, namespace_filter, mode, top_k) VALUES(?, ?, ?, ?, ?);";
    if (sqlite3_prepare_v2(db, sql, -1, &stmt, NULL) != SQLITE_OK) die_sqlite(db, "prepare retrieval log");
    sqlite3_bind_text(stmt, 1, query_text, -1, SQLITE_STATIC);
    sqlite3_bind_text(stmt, 2, access_scope, -1, SQLITE_STATIC);
    if (namespace_filter) sqlite3_bind_text(stmt, 3, namespace_filter, -1, SQLITE_STATIC); else sqlite3_bind_null(stmt, 3);
    sqlite3_bind_text(stmt, 4, mode, -1, SQLITE_STATIC);
    sqlite3_bind_int(stmt, 5, top_k);
    if (sqlite3_step(stmt) != SQLITE_DONE) die_sqlite(db, "insert retrieval log");
    sqlite3_finalize(stmt);
}

static char *build_fts_match(const char *query_text) {
    char terms[KK_MAX_QUERY_TOKENS][64];
    int count = build_query_terms(query_text, terms);
    if (count == 0) return xstrdup("kernel");
    StrBuf sb;
    sb_init(&sb);
    for (int i = 0; i < count; i++) {
        if (i) sb_append_n(&sb, " OR ", 4);
        sb_append_n(&sb, terms[i], strlen(terms[i]));
    }
    return sb.data;
}

static int build_query_terms(const char *query_text, char terms[KK_MAX_QUERY_TOKENS][64]) {
    int count = 0;
    char *copy = xstrdup(query_text);
    char *save = NULL;
    for (char *tok = strtok_r(copy, " \t\n,.;:!?()[]{}<>\"'", &save); tok && count < KK_MAX_QUERY_TOKENS; tok = strtok_r(NULL, " \t\n,.;:!?()[]{}<>\"'", &save)) {
        char lower[64];
        size_t n = strlen(tok);
        if (n >= sizeof(lower)) n = sizeof(lower) - 1;
        for (size_t i = 0; i < n; i++) lower[i] = (char)tolower((unsigned char)tok[i]);
        lower[n] = '\0';
        if (n >= 2) strncpy(terms[count++], lower, sizeof(terms[0]));
    }
    free(copy);
    return count;
}

static void explain_score(const QueryResult *r, const char *query_text, const ResonancePolicy *policy, char *buf, size_t buf_sz) {
    char terms[KK_MAX_QUERY_TOKENS][64];
    int term_count = build_query_terms(query_text, terms);
    int overlap = 0;
    for (int i = 0; i < term_count; i++) if (contains_word_ci(r->raw_text, terms[i])) overlap++;
    double sum = policy_weight_sum(policy);
    if (sum <= 0.0) sum = 1.0;
    snprintf(buf, buf_sz,
             "overlap=%d/%d lexical=%.3f[x%.3f=%.3f] recency=%.3f[x%.3f=%.3f] trust=%.3f[x%.3f=%.3f] linkage=%.3f[x%.3f=%.3f] scope=%.3f[x%.3f=%.3f] namespace=%.3f[x%.3f=%.3f] freshness=%.3f[x%.3f=%.3f] delta_ratio=%.3f structural=%d related=%d",
             overlap, term_count,
             r->lexical_norm, policy->lexical / sum, r->lexical_norm * (policy->lexical / sum),
             r->recency, policy->recency / sum, r->recency * (policy->recency / sum),
             r->trust, policy->trust / sum, r->trust * (policy->trust / sum),
             r->linkage, policy->linkage / sum, r->linkage * (policy->linkage / sum),
             r->scope_score, policy->scope / sum, r->scope_score * (policy->scope / sum),
             r->namespace_score, policy->namespace_score / sum, r->namespace_score * (policy->namespace_score / sum),
             r->freshness, policy->freshness / sum, r->freshness * (policy->freshness / sum),
             r->delta_ratio, r->structural_links, r->related_links);
}

static int fetch_results(sqlite3 *db, const char *query_text, const char *access_scope, const char *namespace_filter,
                         int top_k, QueryResult **out_results, ResonancePolicy *policy_out) {
    const char *sql =
        "SELECT c.id, c.parent_document_id, c.version_id, dv.version_num, "
        "COALESCE((SELECT COUNT(*) FROM links l WHERE l.from_chunk_id=c.id AND l.kind=1),0) AS structural_links,"
        "COALESCE((SELECT COUNT(*) FROM links l WHERE l.from_chunk_id=c.id AND l.kind=2),0) AS related_links,"
        "c.token_estimate, -bm25(chunk_fts) AS lexical, "
        "d.path, d.filename, ns.name, ns.scope, c.raw_text, dv.sha256, dv.ingest_ts, s.heading, dv.trust, "
        "dv.previous_version_id, dv.delta_chars, dv.delta_ratio, dv.change_summary, "
        "CASE WHEN dv.is_latest=1 THEN 1.0 ELSE 0.5 END AS freshness,"
        "julianday('now') - julianday(dv.ingest_ts) AS age_days "
        "FROM chunk_fts "
        "JOIN chunks c ON c.id = chunk_fts.chunk_id "
        "JOIN document_versions dv ON dv.id = c.version_id "
        "JOIN documents d ON d.id = c.parent_document_id "
        "JOIN namespaces ns ON ns.id = d.namespace_id "
        "JOIN sections s ON s.id = c.parent_section_id "
        "WHERE chunk_fts MATCH ? "
        "AND (ns.scope='public' OR ns.scope=?) "
        "AND (? IS NULL OR ns.name = ?) "
        "ORDER BY lexical DESC LIMIT ?;";
    sqlite3_stmt *stmt = NULL;
    char *fts_query = build_fts_match(query_text);
    ResonancePolicy policy = load_resonance_policy(db);
    double weight_sum = policy_weight_sum(&policy);
    if (weight_sum <= 0.0) weight_sum = 1.0;
    if (sqlite3_prepare_v2(db, sql, -1, &stmt, NULL) != SQLITE_OK) die_sqlite(db, "prepare query");
    sqlite3_bind_text(stmt, 1, fts_query, -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt, 2, access_scope, -1, SQLITE_STATIC);
    if (namespace_filter) {
        sqlite3_bind_text(stmt, 3, namespace_filter, -1, SQLITE_STATIC);
        sqlite3_bind_text(stmt, 4, namespace_filter, -1, SQLITE_STATIC);
    } else {
        sqlite3_bind_null(stmt, 3);
        sqlite3_bind_null(stmt, 4);
    }
    sqlite3_bind_int(stmt, 5, top_k * 4);

    QueryResult *results = xmalloc((size_t)(top_k * 4 + 4) * sizeof(*results));
    int count = 0;
    while (sqlite3_step(stmt) == SQLITE_ROW) {
        QueryResult r;
        memset(&r, 0, sizeof(r));
        r.chunk_id = sqlite3_column_int(stmt, 0);
        r.doc_id = sqlite3_column_int(stmt, 1);
        r.version_id = sqlite3_column_int(stmt, 2);
        r.version_num = sqlite3_column_int(stmt, 3);
        r.structural_links = sqlite3_column_int(stmt, 4);
        r.related_links = sqlite3_column_int(stmt, 5);
        r.token_estimate = sqlite3_column_int(stmt, 6);
        r.lexical = sqlite3_column_double(stmt, 7);
        r.path = xstrdup((const char *)sqlite3_column_text(stmt, 8));
        r.filename = xstrdup((const char *)sqlite3_column_text(stmt, 9));
        r.namespace_name = xstrdup((const char *)sqlite3_column_text(stmt, 10));
        r.scope_name = xstrdup((const char *)sqlite3_column_text(stmt, 11));
        r.raw_text = xstrdup((const char *)sqlite3_column_text(stmt, 12));
        r.sha256 = xstrdup((const char *)sqlite3_column_text(stmt, 13));
        r.ingest_ts = xstrdup((const char *)sqlite3_column_text(stmt, 14));
        r.section_title = xstrdup((const char *)sqlite3_column_text(stmt, 15));
        r.trust = sqlite3_column_double(stmt, 16);
        r.previous_version_id = sqlite3_column_type(stmt, 17) == SQLITE_NULL ? 0 : sqlite3_column_int(stmt, 17);
        r.delta_chars = sqlite3_column_int(stmt, 18);
        r.delta_ratio = sqlite3_column_double(stmt, 19);
        r.change_summary = xstrdup((const char *)sqlite3_column_text(stmt, 20));
        r.freshness = sqlite3_column_double(stmt, 21);
        double age_days = sqlite3_column_double(stmt, 22);

        if (!access_scope_allows(r.scope_name, access_scope)) {
            free_query_result_fields(&r);
            continue;
        }
        r.scope_score = scope_compatibility(r.scope_name, access_scope);
        r.namespace_score = namespace_filter ? (!strcmp(r.namespace_name, namespace_filter) ? 1.0 : 0.0) : 0.85;
        r.recency = 1.0 / (1.0 + fmax(0.0, age_days) / 14.0);
        double density = (double)(r.structural_links + r.related_links) / (double)(r.token_estimate + 3);
        r.linkage = clamp01(density * 12.0);
        r.lexical_norm = clamp01(r.lexical / 8.0);
        r.resonance = clamp01(
            (policy.lexical / weight_sum) * r.lexical_norm +
            (policy.recency / weight_sum) * r.recency +
            (policy.trust / weight_sum) * r.trust +
            (policy.linkage / weight_sum) * r.linkage +
            (policy.scope / weight_sum) * r.scope_score +
            (policy.namespace_score / weight_sum) * r.namespace_score +
            (policy.freshness / weight_sum) * r.freshness
        );
        results[count++] = r;
        if (count >= top_k * 4 + 4) break;
    }
    sqlite3_finalize(stmt);
    free(fts_query);

    for (int i = 0; i < count; i++) {
        for (int j = i + 1; j < count; j++) {
            if (results[j].resonance > results[i].resonance) {
                QueryResult tmp = results[i];
                results[i] = results[j];
                results[j] = tmp;
            }
        }
    }
    if (count > top_k) count = top_k;
    if (policy_out) *policy_out = policy;
    *out_results = results;
    return count;
}

static void free_query_results(QueryResult *results, int count) {
    if (!results) return;
    for (int i = 0; i < count; i++) {
        free_query_result_fields(&results[i]);
    }
    free(results);
}

static void free_query_result_fields(QueryResult *r) {
    free((char *)r->path);
    free((char *)r->filename);
    free((char *)r->namespace_name);
    free((char *)r->scope_name);
    free((char *)r->raw_text);
    free((char *)r->sha256);
    free((char *)r->ingest_ts);
    free((char *)r->section_title);
    free((char *)r->change_summary);
}

static void print_chunk_excerpt(const char *text, size_t limit) {
    size_t len = strlen(text);
    if (len <= limit) {
        printf("%s\n", text);
        return;
    }
    fwrite(text, 1, limit, stdout);
    printf("...\n");
}

static void render_query_results(const char *mode, const char *query_text, const ResonancePolicy *policy, QueryResult *results, int count) {
    if (!strcmp(mode, "compressed")) {
        printf("mode: compressed knowledge packet\n");
        for (int i = 0; i < count; i++) {
            char reason[512];
            explain_score(&results[i], query_text, policy, reason, sizeof(reason));
            const char *text = results[i].raw_text;
            const char *dot1 = strchr(text, '.');
            const char *dot2 = dot1 ? strchr(dot1 + 1, '.') : NULL;
            size_t sent_len = dot2 ? (size_t)(dot2 - text + 1) : strlen(text);
            if (sent_len > 240) sent_len = 240;
            printf("packet %d\n", i + 1);
            printf("  anchor: %s:%s#v%d/chunk-%d\n", results[i].namespace_name, results[i].filename, results[i].version_num, results[i].chunk_id);
            printf("  provenance: scope=%s section=%s sha=%s ingest_ts=%s\n",
                   results[i].scope_name, results[i].section_title, results[i].sha256, results[i].ingest_ts);
            printf("  lineage: prev_version_id=%d delta_chars=%d delta_ratio=%.3f summary=%s\n",
                   results[i].previous_version_id, results[i].delta_chars, results[i].delta_ratio, results[i].change_summary);
            printf("  resonance: %.3f\n", results[i].resonance);
            printf("  packet: ");
            fwrite(text, 1, sent_len, stdout);
            printf("\n");
            printf("  citation: file=%s version=%d chunk=%d namespace=%s\n",
                   results[i].filename, results[i].version_num, results[i].chunk_id, results[i].namespace_name);
            printf("  audit: %s\n\n", reason);
        }
        return;
    }

    for (int i = 0; i < count; i++) {
        char reason[512];
        explain_score(&results[i], query_text, policy, reason, sizeof(reason));
        printf("result %d\n", i + 1);
        printf("  doc: %s\n", results[i].path);
        printf("  version: %d (version_id=%d prev=%d sha=%s)\n",
               results[i].version_num, results[i].version_id, results[i].previous_version_id, results[i].sha256);
        printf("  chunk: %d section: %s\n", results[i].chunk_id, results[i].section_title);
        printf("  namespace: %s\n", results[i].namespace_name);
        printf("  scope: %s\n", results[i].scope_name);
        printf("  score: resonance=%.3f lexical=%.3f lexical_norm=%.3f recency=%.3f linkage=%.3f trust=%.3f freshness=%.3f\n",
               results[i].resonance, results[i].lexical, results[i].lexical_norm, results[i].recency,
               results[i].linkage, results[i].trust, results[i].freshness);
        printf("  lineage: delta_chars=%d delta_ratio=%.3f summary=%s\n",
               results[i].delta_chars, results[i].delta_ratio, results[i].change_summary);
        printf("  why: %s\n", reason);
        if (!strcmp(mode, "citation")) {
            printf("  citation: file=%s version=%d chunk=%d ingest_ts=%s sha=%s\n",
                   results[i].filename, results[i].version_num, results[i].chunk_id, results[i].ingest_ts, results[i].sha256);
        }
        printf("  text: ");
        print_chunk_excerpt(results[i].raw_text, 260);
        printf("\n");
    }
}

static void cmd_init(const char *db_path) {
    sqlite3 *db = open_db(db_path);
    sqlite3_close(db);
    printf("initialized knowledge kernel: %s\n", db_path);
}

static void cmd_ingest(const char *db_path, const char *dir, const char *namespace_name, const char *scope) {
    require_valid_scope(scope, "ingest");
    sqlite3 *db = open_db(db_path);
    int count = 0;
    scan_dir(db, dir, namespace_name, scope, &count);
    printf("ingest complete: %d file(s) updated in namespace=%s scope=%s\n", count, namespace_name, scope);
    sqlite3_close(db);
}

static void cmd_query(const char *db_path, const char *query_text, const char *access_scope, int top_k, const char *mode, const char *namespace_filter) {
    require_valid_scope(access_scope, "query");
    sqlite3 *db = open_db(db_path);
    log_retrieval(db, query_text, access_scope, namespace_filter, mode, top_k);
    QueryResult *results = NULL;
    ResonancePolicy policy;
    int count = fetch_results(db, query_text, access_scope, namespace_filter, top_k, &results, &policy);
    printf("query: %s\n", query_text);
    printf("access_scope: %s\n", access_scope);
    printf("namespace_filter: %s\n", namespace_filter ? namespace_filter : "<none>");
    printf("mode: %s\n", mode);
    printf("hits: %d\n\n", count);
    print_policy(&policy);
    printf("\n");
    render_query_results(mode, query_text, &policy, results, count);
    free_query_results(results, count);
    sqlite3_close(db);
}

static void cmd_policy(const char *db_path, int arg_count, char **args) {
    sqlite3 *db = open_db(db_path);
    if (arg_count > 0) {
        begin_tx(db);
        for (int i = 0; i < arg_count; i++) {
            char *pair = xstrdup(args[i]);
            char *eq = strchr(pair, '=');
            if (!eq) {
                fprintf(stderr, "invalid policy assignment: %s\n", args[i]);
                free(pair);
                exit(1);
            }
            *eq = '\0';
            double value = atof(eq + 1);
            if (!set_policy_value(db, pair, value)) {
                fprintf(stderr, "invalid policy key/value: %s=%s\n", pair, eq + 1);
                free(pair);
                exit(1);
            }
            free(pair);
        }
        commit_tx(db);
    }
    ResonancePolicy policy = load_resonance_policy(db);
    print_policy(&policy);
    sqlite3_close(db);
}

static void cmd_watch(const char *db_path, const char *dir, const char *namespace_name, const char *scope, int interval_sec, int rounds) {
    require_valid_scope(scope, "watch");
    if (interval_sec < 1) interval_sec = 1;
    int cycle = 0;
    for (;;) {
        cycle++;
        sqlite3 *db = open_db(db_path);
        int count = 0;
        printf("watch cycle %d begin\n", cycle);
        scan_dir(db, dir, namespace_name, scope, &count);
        printf("watch cycle %d complete: %d file(s) updated\n", cycle, count);
        sqlite3_close(db);
        if (rounds > 0 && cycle >= rounds) break;
        sleep((unsigned int)interval_sec);
    }
}

static void cmd_stats(const char *db_path) {
    sqlite3 *db = open_db(db_path);
    const char *sql =
        "SELECT (SELECT COUNT(*) FROM namespaces),"
        "       (SELECT COUNT(*) FROM documents),"
        "       (SELECT COUNT(*) FROM document_versions),"
        "       (SELECT COUNT(*) FROM sections),"
        "       (SELECT COUNT(*) FROM chunks),"
        "       (SELECT COUNT(*) FROM links),"
        "       (SELECT COUNT(*) FROM retrieval_log);";
    sqlite3_stmt *stmt = NULL;
    if (sqlite3_prepare_v2(db, sql, -1, &stmt, NULL) != SQLITE_OK) die_sqlite(db, "prepare stats");
    if (sqlite3_step(stmt) == SQLITE_ROW) {
        printf("namespaces: %d\n", sqlite3_column_int(stmt, 0));
        printf("documents: %d\n", sqlite3_column_int(stmt, 1));
        printf("versions: %d\n", sqlite3_column_int(stmt, 2));
        printf("sections: %d\n", sqlite3_column_int(stmt, 3));
        printf("chunks: %d\n", sqlite3_column_int(stmt, 4));
        printf("links: %d\n", sqlite3_column_int(stmt, 5));
        printf("retrievals: %d\n", sqlite3_column_int(stmt, 6));
    }
    sqlite3_finalize(stmt);
    sqlite3_close(db);
}

static void usage(void) {
    fprintf(stderr,
            "Knowledge Kernel CLI\n"
            "Usage:\n"
            "  kk init <db>\n"
            "  kk ingest <db> <dir> <namespace> [scope=public]\n"
            "  kk query <db> <query> <access_scope> <top_k> [mode] [namespace_filter]\n"
            "  kk policy <db> [key=value ...]\n"
            "  kk watch <db> <dir> <namespace> <scope> [interval_sec] [rounds]\n"
            "  kk stats <db>\n"
            "\nModes: raw | citation | compressed\n");
    exit(1);
}

int main(int argc, char **argv) {
    if (argc < 3) usage();
    if (!strcmp(argv[1], "init")) {
        if (argc != 3) usage();
        cmd_init(argv[2]);
        return 0;
    }
    if (!strcmp(argv[1], "ingest")) {
        if (argc < 5 || argc > 6) usage();
        const char *scope = (argc == 6) ? argv[5] : "public";
        cmd_ingest(argv[2], argv[3], argv[4], scope);
        return 0;
    }
    if (!strcmp(argv[1], "query")) {
        if (argc < 6 || argc > 8) usage();
        const char *mode = (argc >= 7) ? argv[6] : "citation";
        const char *namespace_filter = (argc >= 8) ? argv[7] : NULL;
        cmd_query(argv[2], argv[3], argv[4], atoi(argv[5]), mode, namespace_filter);
        return 0;
    }
    if (!strcmp(argv[1], "policy")) {
        if (argc < 3) usage();
        cmd_policy(argv[2], argc - 3, argv + 3);
        return 0;
    }
    if (!strcmp(argv[1], "watch")) {
        if (argc < 6 || argc > 8) usage();
        int interval_sec = (argc >= 7) ? atoi(argv[6]) : 5;
        int rounds = (argc >= 8) ? atoi(argv[7]) : 0;
        cmd_watch(argv[2], argv[3], argv[4], argv[5], interval_sec, rounds);
        return 0;
    }
    if (!strcmp(argv[1], "stats")) {
        if (argc != 3) usage();
        cmd_stats(argv[2]);
        return 0;
    }
    usage();
    return 0;
}
