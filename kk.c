#define _POSIX_C_SOURCE 200809L
#include <ctype.h>
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <math.h>
#include <sqlite3.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <time.h>
#include <unistd.h>

#define ARRAY_LEN(a) ((int)(sizeof(a) / sizeof((a)[0])))
#define CHUNK_TARGET 900
#define CHUNK_FALLBACK 1400
#define TERM_LIMIT 16
#define MAX_RESULTS 64

typedef struct {
    uint8_t data[64];
    uint32_t datalen;
    unsigned long long bitlen;
    uint32_t state[8];
} SHA256_CTX;

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

static uint32_t rotr(uint32_t a, uint32_t b) { return (((a) >> (b)) | ((a) << (32-(b)))); }
static uint32_t ch(uint32_t x, uint32_t y, uint32_t z) { return ((x & y) ^ (~x & z)); }
static uint32_t maj(uint32_t x, uint32_t y, uint32_t z) { return ((x & y) ^ (x & z) ^ (y & z)); }
static uint32_t ep0(uint32_t x) { return (rotr(x,2) ^ rotr(x,13) ^ rotr(x,22)); }
static uint32_t ep1(uint32_t x) { return (rotr(x,6) ^ rotr(x,11) ^ rotr(x,25)); }
static uint32_t sig0(uint32_t x) { return (rotr(x,7) ^ rotr(x,18) ^ ((x) >> 3)); }
static uint32_t sig1(uint32_t x) { return (rotr(x,17) ^ rotr(x,19) ^ ((x) >> 10)); }

static void sha256_transform(SHA256_CTX *ctx, const uint8_t data[]) {
    uint32_t a, b, c, d, e, f, g, h, i, j, m[64], t1, t2;
    for (i = 0, j = 0; i < 16; ++i, j += 4)
        m[i] = (data[j] << 24) | (data[j + 1] << 16) | (data[j + 2] << 8) | (data[j + 3]);
    for ( ; i < 64; ++i)
        m[i] = sig1(m[i - 2]) + m[i - 7] + sig0(m[i - 15]) + m[i - 16];

    a = ctx->state[0];
    b = ctx->state[1];
    c = ctx->state[2];
    d = ctx->state[3];
    e = ctx->state[4];
    f = ctx->state[5];
    g = ctx->state[6];
    h = ctx->state[7];

    for (i = 0; i < 64; ++i) {
        t1 = h + ep1(e) + ch(e,f,g) + k256[i] + m[i];
        t2 = ep0(a) + maj(a,b,c);
        h = g;
        g = f;
        f = e;
        e = d + t1;
        d = c;
        c = b;
        b = a;
        a = t1 + t2;
    }

    ctx->state[0] += a;
    ctx->state[1] += b;
    ctx->state[2] += c;
    ctx->state[3] += d;
    ctx->state[4] += e;
    ctx->state[5] += f;
    ctx->state[6] += g;
    ctx->state[7] += h;
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

static void sha256_update(SHA256_CTX *ctx, const uint8_t data[], size_t len) {
    for (size_t i = 0; i < len; ++i) {
        ctx->data[ctx->datalen] = data[i];
        ctx->datalen++;
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
        while (i < 56)
            ctx->data[i++] = 0x00;
    } else {
        ctx->data[i++] = 0x80;
        while (i < 64)
            ctx->data[i++] = 0x00;
        sha256_transform(ctx, ctx->data);
        memset(ctx->data, 0, 56);
    }

    ctx->bitlen += ctx->datalen * 8;
    ctx->data[63] = ctx->bitlen;
    ctx->data[62] = ctx->bitlen >> 8;
    ctx->data[61] = ctx->bitlen >> 16;
    ctx->data[60] = ctx->bitlen >> 24;
    ctx->data[59] = ctx->bitlen >> 32;
    ctx->data[58] = ctx->bitlen >> 40;
    ctx->data[57] = ctx->bitlen >> 48;
    ctx->data[56] = ctx->bitlen >> 56;
    sha256_transform(ctx, ctx->data);

    for (i = 0; i < 4; ++i) {
        hash[i]      = (ctx->state[0] >> (24 - i * 8)) & 0x000000ff;
        hash[i + 4]  = (ctx->state[1] >> (24 - i * 8)) & 0x000000ff;
        hash[i + 8]  = (ctx->state[2] >> (24 - i * 8)) & 0x000000ff;
        hash[i + 12] = (ctx->state[3] >> (24 - i * 8)) & 0x000000ff;
        hash[i + 16] = (ctx->state[4] >> (24 - i * 8)) & 0x000000ff;
        hash[i + 20] = (ctx->state[5] >> (24 - i * 8)) & 0x000000ff;
        hash[i + 24] = (ctx->state[6] >> (24 - i * 8)) & 0x000000ff;
        hash[i + 28] = (ctx->state[7] >> (24 - i * 8)) & 0x000000ff;
    }
}

typedef struct {
    char *data;
    size_t len;
    size_t cap;
} StrBuf;

typedef struct {
    int id;
    int level;
    char *title;
    size_t start;
    size_t end;
} SectionInfo;

typedef struct {
    char **items;
    int count;
    int cap;
} StrList;

typedef struct {
    int chunk_id;
    int doc_id;
    int version_id;
    char namespace_name[256];
    char filename[512];
    char path[1024];
    int version_no;
    double lexical;
    double recency;
    double trust;
    double linkage;
    double namespace_match;
    double version_freshness;
    double resonance;
    int link_count;
    int token_estimate;
    int char_start;
    int char_end;
    char explanation[512];
    char snippet[640];
} QueryHit;

static void die(const char *msg) {
    fprintf(stderr, "error: %s\n", msg);
    exit(1);
}

static void die_sqlite(sqlite3 *db, const char *msg) {
    fprintf(stderr, "error: %s: %s\n", msg, sqlite3_errmsg(db));
    exit(1);
}

static void sb_init(StrBuf *sb) {
    sb->data = NULL; sb->len = 0; sb->cap = 0;
}

static void sb_reserve(StrBuf *sb, size_t need) {
    if (need <= sb->cap) return;
    size_t newcap = sb->cap ? sb->cap * 2 : 256;
    while (newcap < need) newcap *= 2;
    char *n = realloc(sb->data, newcap);
    if (!n) die("out of memory");
    sb->data = n; sb->cap = newcap;
}

static void sb_append_n(StrBuf *sb, const char *s, size_t n) {
    sb_reserve(sb, sb->len + n + 1);
    memcpy(sb->data + sb->len, s, n);
    sb->len += n;
    sb->data[sb->len] = '\0';
}

static char *sb_take(StrBuf *sb) {
    if (!sb->data) return strdup("");
    char *d = sb->data;
    sb->data = NULL; sb->len = sb->cap = 0;
    return d;
}

static void strlist_push(StrList *list, char *s) {
    if (list->count == list->cap) {
        int nc = list->cap ? list->cap * 2 : 8;
        char **ni = realloc(list->items, sizeof(char *) * nc);
        if (!ni) die("out of memory");
        list->items = ni; list->cap = nc;
    }
    list->items[list->count++] = s;
}

static char *xstrndup(const char *s, size_t n) {
    char *d = malloc(n + 1);
    if (!d) die("out of memory");
    memcpy(d, s, n);
    d[n] = '\0';
    return d;
}

static char *trim_copy(const char *s, size_t n) {
    while (n > 0 && isspace((unsigned char)*s)) { s++; n--; }
    while (n > 0 && isspace((unsigned char)s[n - 1])) n--;
    return xstrndup(s, n);
}

static bool ends_with_ignore_case(const char *s, const char *suffix) {
    size_t sl = strlen(s), tl = strlen(suffix);
    if (tl > sl) return false;
    return strcasecmp(s + sl - tl, suffix) == 0;
}

static bool supported_extension(const char *path) {
    return ends_with_ignore_case(path, ".md") || ends_with_ignore_case(path, ".txt") ||
           ends_with_ignore_case(path, ".json") || ends_with_ignore_case(path, ".html") ||
           ends_with_ignore_case(path, ".csv");
}

static const char *source_type_for_path(const char *path) {
    const char *dot = strrchr(path, '.');
    return dot ? dot + 1 : "text";
}

static long unix_time_now(void) { return (long)time(NULL); }

static char *path_join(const char *a, const char *b) {
    size_t al = strlen(a), bl = strlen(b);
    bool slash = al > 0 && a[al - 1] == '/';
    char *out = malloc(al + bl + 2);
    if (!out) die("out of memory");
    memcpy(out, a, al);
    out[al] = '\0';
    if (!slash) strcat(out, "/");
    strcat(out, b);
    return out;
}

static char *filename_from_path(const char *path) {
    const char *slash = strrchr(path, '/');
    return strdup(slash ? slash + 1 : path);
}

static bool read_file_bytes(const char *path, unsigned char **data_out, size_t *len_out) {
    FILE *f = fopen(path, "rb");
    if (!f) return false;
    if (fseek(f, 0, SEEK_END) != 0) { fclose(f); return false; }
    long sz = ftell(f);
    if (sz < 0) { fclose(f); return false; }
    rewind(f);
    unsigned char *buf = malloc((size_t)sz + 1);
    if (!buf) die("out of memory");
    size_t rd = fread(buf, 1, (size_t)sz, f);
    fclose(f);
    if (rd != (size_t)sz) { free(buf); return false; }
    buf[rd] = '\0';
    *data_out = buf;
    *len_out = rd;
    return true;
}

static void sha256_hex(const unsigned char *data, size_t len, char out[65]) {
    SHA256_CTX ctx;
    uint8_t hash[32];
    sha256_init(&ctx);
    sha256_update(&ctx, data, len);
    sha256_final(&ctx, hash);
    for (int i = 0; i < 32; ++i) sprintf(out + i * 2, "%02x", hash[i]);
    out[64] = '\0';
}

static char *normalize_text(const char *input, size_t len) {
    StrBuf out; sb_init(&out);
    bool prev_space = false;
    for (size_t i = 0; i < len; ++i) {
        unsigned char c = (unsigned char)input[i];
        if (c == '\r') continue;
        if (c == '\t') c = ' ';
        if (c == '\0') c = ' ';
        if (c < 32 && c != '\n') c = ' ';
        if (c == '\n') {
            prev_space = false;
            sb_append_n(&out, "\n", 1);
            continue;
        }
        if (isspace(c)) {
            if (!prev_space) {
                sb_append_n(&out, " ", 1);
                prev_space = true;
            }
        } else {
            char ch = (char)c;
            sb_append_n(&out, &ch, 1);
            prev_space = false;
        }
    }
    return sb_take(&out);
}

static int count_tokens_estimate(const char *text) {
    int tokens = 0;
    bool in_word = false;
    for (const unsigned char *p = (const unsigned char *)text; *p; ++p) {
        if (isalnum(*p) || *p == '_' || *p >= 128) {
            if (!in_word) tokens++;
            in_word = true;
        } else {
            in_word = false;
        }
    }
    return tokens ? tokens : 1;
}

static bool line_is_markdown_heading(const char *line, size_t len, int *level_out, char **title_out) {
    size_t i = 0;
    while (i < len && line[i] == ' ') i++;
    int level = 0;
    while (i < len && line[i] == '#') { level++; i++; }
    if (level == 0 || level > 6) return false;
    if (i >= len || !isspace((unsigned char)line[i])) return false;
    while (i < len && isspace((unsigned char)line[i])) i++;
    *level_out = level;
    *title_out = trim_copy(line + i, len - i);
    return true;
}

static int ensure_namespace(sqlite3 *db, const char *name) {
    const char *kind = "custom";
    const char *owner = "";
    if (strcmp(name, "public") == 0) kind = "public";
    else if (strncmp(name, "private:", 8) == 0) { kind = "private"; owner = name + 8; }
    else if (strncmp(name, "shared:", 7) == 0) { kind = "shared"; owner = name + 7; }

    sqlite3_stmt *stmt = NULL;
    if (sqlite3_prepare_v2(db, "INSERT INTO namespaces(name, kind, owner, created_at) VALUES(?,?,?,?) ON CONFLICT(name) DO UPDATE SET kind=excluded.kind, owner=excluded.owner RETURNING id;", -1, &stmt, NULL) != SQLITE_OK)
        die_sqlite(db, "prepare ensure_namespace");
    sqlite3_bind_text(stmt, 1, name, -1, SQLITE_STATIC);
    sqlite3_bind_text(stmt, 2, kind, -1, SQLITE_STATIC);
    sqlite3_bind_text(stmt, 3, owner, -1, SQLITE_STATIC);
    sqlite3_bind_int64(stmt, 4, unix_time_now());
    int id = -1;
    if (sqlite3_step(stmt) == SQLITE_ROW) id = sqlite3_column_int(stmt, 0);
    sqlite3_finalize(stmt);
    if (id < 0) die("failed to ensure namespace");
    return id;
}

static void exec_sql(sqlite3 *db, const char *sql) {
    char *errmsg = NULL;
    if (sqlite3_exec(db, sql, NULL, NULL, &errmsg) != SQLITE_OK) {
        fprintf(stderr, "sqlite error: %s\n", errmsg ? errmsg : "unknown");
        sqlite3_free(errmsg);
        exit(1);
    }
}

static void init_db(sqlite3 *db) {
    exec_sql(db,
        "PRAGMA journal_mode=WAL;"
        "PRAGMA foreign_keys=ON;"
        "CREATE TABLE IF NOT EXISTS namespaces ("
        "  id INTEGER PRIMARY KEY,"
        "  name TEXT NOT NULL UNIQUE,"
        "  kind TEXT NOT NULL,"
        "  owner TEXT,"
        "  created_at INTEGER NOT NULL"
        ");"
        "CREATE TABLE IF NOT EXISTS documents ("
        "  id INTEGER PRIMARY KEY,"
        "  path TEXT NOT NULL,"
        "  filename TEXT NOT NULL,"
        "  source_type TEXT NOT NULL,"
        "  namespace_id INTEGER NOT NULL REFERENCES namespaces(id),"
        "  scope TEXT NOT NULL,"
        "  created_at INTEGER NOT NULL,"
        "  updated_at INTEGER NOT NULL,"
        "  latest_version_id INTEGER,"
        "  UNIQUE(path, namespace_id)"
        ");"
        "CREATE TABLE IF NOT EXISTS document_versions ("
        "  id INTEGER PRIMARY KEY,"
        "  document_id INTEGER NOT NULL REFERENCES documents(id) ON DELETE CASCADE,"
        "  version_no INTEGER NOT NULL,"
        "  sha256 TEXT NOT NULL,"
        "  size_bytes INTEGER NOT NULL,"
        "  ingest_ts INTEGER NOT NULL,"
        "  previous_version_id INTEGER REFERENCES document_versions(id),"
        "  trust REAL NOT NULL DEFAULT 0.60,"
        "  is_latest INTEGER NOT NULL DEFAULT 1,"
        "  raw_text TEXT NOT NULL,"
        "  UNIQUE(document_id, version_no),"
        "  UNIQUE(document_id, sha256)"
        ");"
        "CREATE TABLE IF NOT EXISTS sections ("
        "  id INTEGER PRIMARY KEY,"
        "  document_version_id INTEGER NOT NULL REFERENCES document_versions(id) ON DELETE CASCADE,"
        "  parent_section_id INTEGER REFERENCES sections(id),"
        "  heading TEXT,"
        "  heading_level INTEGER NOT NULL DEFAULT 0,"
        "  ordinal INTEGER NOT NULL,"
        "  char_start INTEGER NOT NULL,"
        "  char_end INTEGER NOT NULL"
        ");"
        "CREATE TABLE IF NOT EXISTS chunks ("
        "  id INTEGER PRIMARY KEY,"
        "  document_id INTEGER NOT NULL REFERENCES documents(id) ON DELETE CASCADE,"
        "  document_version_id INTEGER NOT NULL REFERENCES document_versions(id) ON DELETE CASCADE,"
        "  section_id INTEGER REFERENCES sections(id) ON DELETE SET NULL,"
        "  ordinal INTEGER NOT NULL,"
        "  char_start INTEGER NOT NULL,"
        "  char_end INTEGER NOT NULL,"
        "  token_estimate INTEGER NOT NULL,"
        "  scope TEXT NOT NULL,"
        "  namespace_id INTEGER NOT NULL REFERENCES namespaces(id),"
        "  raw_text TEXT NOT NULL"
        ");"
        "CREATE VIRTUAL TABLE IF NOT EXISTS chunk_fts USING fts5(raw_text, tokenize='unicode61', content='chunks', content_rowid='id');"
        "CREATE TABLE IF NOT EXISTS links ("
        "  id INTEGER PRIMARY KEY,"
        "  from_chunk_id INTEGER REFERENCES chunks(id) ON DELETE CASCADE,"
        "  to_chunk_id INTEGER REFERENCES chunks(id) ON DELETE CASCADE,"
        "  link_type TEXT NOT NULL,"
        "  weight REAL NOT NULL DEFAULT 1.0,"
        "  created_at INTEGER NOT NULL"
        ");"
        "CREATE TABLE IF NOT EXISTS retrieval_log ("
        "  id INTEGER PRIMARY KEY,"
        "  query_text TEXT NOT NULL,"
        "  namespace_query TEXT NOT NULL,"
        "  requested_topk INTEGER NOT NULL,"
        "  adapter_mode TEXT NOT NULL,"
        "  created_at INTEGER NOT NULL,"
        "  result_count INTEGER NOT NULL,"
        "  explanation TEXT"
        ");"
        "CREATE INDEX IF NOT EXISTS idx_documents_namespace ON documents(namespace_id, path);"
        "CREATE INDEX IF NOT EXISTS idx_doc_versions_doc ON document_versions(document_id, is_latest, ingest_ts DESC);"
        "CREATE INDEX IF NOT EXISTS idx_sections_version ON sections(document_version_id, ordinal);"
        "CREATE INDEX IF NOT EXISTS idx_chunks_version ON chunks(document_version_id, ordinal);"
        "CREATE INDEX IF NOT EXISTS idx_chunks_namespace ON chunks(namespace_id, scope);"
        "CREATE INDEX IF NOT EXISTS idx_links_from ON links(from_chunk_id);"
        "CREATE INDEX IF NOT EXISTS idx_links_to ON links(to_chunk_id);"
    );
}

static bool namespace_accessible(const char *requested, const char *stored) {
    return strcmp(stored, "public") == 0 || strcmp(stored, requested) == 0;
}

static int upsert_document(sqlite3 *db, const char *path, const char *filename, const char *source_type, int namespace_id, const char *scope) {
    sqlite3_stmt *stmt = NULL;
    long now = unix_time_now();
    if (sqlite3_prepare_v2(db,
        "INSERT INTO documents(path, filename, source_type, namespace_id, scope, created_at, updated_at) VALUES(?,?,?,?,?,?,?) "
        "ON CONFLICT(path, namespace_id) DO UPDATE SET filename=excluded.filename, source_type=excluded.source_type, scope=excluded.scope, updated_at=excluded.updated_at "
        "RETURNING id;",
        -1, &stmt, NULL) != SQLITE_OK) die_sqlite(db, "prepare upsert_document");
    sqlite3_bind_text(stmt, 1, path, -1, SQLITE_STATIC);
    sqlite3_bind_text(stmt, 2, filename, -1, SQLITE_STATIC);
    sqlite3_bind_text(stmt, 3, source_type, -1, SQLITE_STATIC);
    sqlite3_bind_int(stmt, 4, namespace_id);
    sqlite3_bind_text(stmt, 5, scope, -1, SQLITE_STATIC);
    sqlite3_bind_int64(stmt, 6, now);
    sqlite3_bind_int64(stmt, 7, now);
    int id = -1;
    if (sqlite3_step(stmt) == SQLITE_ROW) id = sqlite3_column_int(stmt, 0);
    sqlite3_finalize(stmt);
    if (id < 0) die("unable to upsert document");
    return id;
}

static bool get_latest_version(sqlite3 *db, int document_id, int *version_id, int *version_no, char sha256[65]) {
    sqlite3_stmt *stmt = NULL;
    if (sqlite3_prepare_v2(db,
        "SELECT id, version_no, sha256 FROM document_versions WHERE document_id=? AND is_latest=1 ORDER BY version_no DESC LIMIT 1;",
        -1, &stmt, NULL) != SQLITE_OK) die_sqlite(db, "prepare get_latest_version");
    sqlite3_bind_int(stmt, 1, document_id);
    bool found = false;
    if (sqlite3_step(stmt) == SQLITE_ROW) {
        *version_id = sqlite3_column_int(stmt, 0);
        *version_no = sqlite3_column_int(stmt, 1);
        const unsigned char *sha = sqlite3_column_text(stmt, 2);
        snprintf(sha256, 65, "%s", sha ? (const char *)sha : "");
        found = true;
    }
    sqlite3_finalize(stmt);
    return found;
}

static int insert_document_version(sqlite3 *db, int document_id, int version_no, const char *sha256, size_t size_bytes, int previous_version_id, const char *text) {
    sqlite3_stmt *stmt = NULL;
    long now = unix_time_now();
    if (sqlite3_prepare_v2(db, "UPDATE document_versions SET is_latest=0 WHERE document_id=? AND is_latest=1;", -1, &stmt, NULL) != SQLITE_OK)
        die_sqlite(db, "prepare reset_latest_versions");
    sqlite3_bind_int(stmt, 1, document_id);
    if (sqlite3_step(stmt) != SQLITE_DONE) die_sqlite(db, "reset latest document versions");
    sqlite3_finalize(stmt);

    if (sqlite3_prepare_v2(db,
        "INSERT INTO document_versions(document_id, version_no, sha256, size_bytes, ingest_ts, previous_version_id, raw_text) VALUES(?,?,?,?,?,?,?) RETURNING id;",
        -1, &stmt, NULL) != SQLITE_OK) die_sqlite(db, "prepare insert_document_version");
    sqlite3_bind_int(stmt, 1, document_id);
    sqlite3_bind_int(stmt, 2, version_no);
    sqlite3_bind_text(stmt, 3, sha256, -1, SQLITE_STATIC);
    sqlite3_bind_int64(stmt, 4, (sqlite3_int64)size_bytes);
    sqlite3_bind_int64(stmt, 5, now);
    if (previous_version_id > 0) sqlite3_bind_int(stmt, 6, previous_version_id); else sqlite3_bind_null(stmt, 6);
    sqlite3_bind_text(stmt, 7, text, -1, SQLITE_STATIC);

    int version_id = -1;
    while (sqlite3_step(stmt) == SQLITE_ROW) {
        version_id = sqlite3_column_int(stmt, 0);
    }
    sqlite3_finalize(stmt);
    if (version_id < 0) die("unable to insert document version");

    if (sqlite3_prepare_v2(db, "UPDATE documents SET latest_version_id=?, updated_at=? WHERE id=?;", -1, &stmt, NULL) != SQLITE_OK)
        die_sqlite(db, "prepare update latest_version_id");
    sqlite3_bind_int(stmt, 1, version_id);
    sqlite3_bind_int64(stmt, 2, now);
    sqlite3_bind_int(stmt, 3, document_id);
    if (sqlite3_step(stmt) != SQLITE_DONE) die_sqlite(db, "update document latest version");
    sqlite3_finalize(stmt);
    return version_id;
}

static int insert_section(sqlite3 *db, int version_id, int parent_section_id, const char *heading, int heading_level, int ordinal, int char_start, int char_end) {
    sqlite3_stmt *stmt = NULL;
    if (sqlite3_prepare_v2(db,
        "INSERT INTO sections(document_version_id, parent_section_id, heading, heading_level, ordinal, char_start, char_end) VALUES(?,?,?,?,?,?,?) RETURNING id;",
        -1, &stmt, NULL) != SQLITE_OK) die_sqlite(db, "prepare insert_section");
    sqlite3_bind_int(stmt, 1, version_id);
    if (parent_section_id > 0) sqlite3_bind_int(stmt, 2, parent_section_id); else sqlite3_bind_null(stmt, 2);
    if (heading) sqlite3_bind_text(stmt, 3, heading, -1, SQLITE_STATIC); else sqlite3_bind_null(stmt, 3);
    sqlite3_bind_int(stmt, 4, heading_level);
    sqlite3_bind_int(stmt, 5, ordinal);
    sqlite3_bind_int(stmt, 6, char_start);
    sqlite3_bind_int(stmt, 7, char_end);
    int section_id = -1;
    if (sqlite3_step(stmt) == SQLITE_ROW) section_id = sqlite3_column_int(stmt, 0);
    sqlite3_finalize(stmt);
    if (section_id < 0) die("unable to insert section");
    return section_id;
}

static int insert_chunk(sqlite3 *db, int document_id, int version_id, int section_id, int ordinal, int char_start, int char_end, int token_estimate, const char *scope, int namespace_id, const char *raw_text) {
    sqlite3_stmt *stmt = NULL;
    if (sqlite3_prepare_v2(db,
        "INSERT INTO chunks(document_id, document_version_id, section_id, ordinal, char_start, char_end, token_estimate, scope, namespace_id, raw_text) VALUES(?,?,?,?,?,?,?,?,?,?) RETURNING id;",
        -1, &stmt, NULL) != SQLITE_OK) die_sqlite(db, "prepare insert_chunk");
    sqlite3_bind_int(stmt, 1, document_id);
    sqlite3_bind_int(stmt, 2, version_id);
    if (section_id > 0) sqlite3_bind_int(stmt, 3, section_id); else sqlite3_bind_null(stmt, 3);
    sqlite3_bind_int(stmt, 4, ordinal);
    sqlite3_bind_int(stmt, 5, char_start);
    sqlite3_bind_int(stmt, 6, char_end);
    sqlite3_bind_int(stmt, 7, token_estimate);
    sqlite3_bind_text(stmt, 8, scope, -1, SQLITE_STATIC);
    sqlite3_bind_int(stmt, 9, namespace_id);
    sqlite3_bind_text(stmt, 10, raw_text, -1, SQLITE_STATIC);
    int chunk_id = -1;
    if (sqlite3_step(stmt) == SQLITE_ROW) chunk_id = sqlite3_column_int(stmt, 0);
    sqlite3_finalize(stmt);
    if (chunk_id < 0) die("unable to insert chunk");

    if (sqlite3_prepare_v2(db, "INSERT INTO chunk_fts(rowid, raw_text) VALUES(?, ?);", -1, &stmt, NULL) != SQLITE_OK)
        die_sqlite(db, "prepare insert chunk_fts");
    sqlite3_bind_int(stmt, 1, chunk_id);
    sqlite3_bind_text(stmt, 2, raw_text, -1, SQLITE_STATIC);
    if (sqlite3_step(stmt) != SQLITE_DONE) die_sqlite(db, "insert chunk_fts");
    sqlite3_finalize(stmt);
    return chunk_id;
}

static void insert_link(sqlite3 *db, int from_chunk_id, int to_chunk_id, const char *type, double weight) {
    sqlite3_stmt *stmt = NULL;
    if (sqlite3_prepare_v2(db, "INSERT INTO links(from_chunk_id, to_chunk_id, link_type, weight, created_at) VALUES(?,?,?,?,?);", -1, &stmt, NULL) != SQLITE_OK)
        die_sqlite(db, "prepare insert_link");
    sqlite3_bind_int(stmt, 1, from_chunk_id);
    sqlite3_bind_int(stmt, 2, to_chunk_id);
    sqlite3_bind_text(stmt, 3, type, -1, SQLITE_STATIC);
    sqlite3_bind_double(stmt, 4, weight);
    sqlite3_bind_int64(stmt, 5, unix_time_now());
    if (sqlite3_step(stmt) != SQLITE_DONE) die_sqlite(db, "insert link");
    sqlite3_finalize(stmt);
}

static void free_sections(SectionInfo *sections, int count) {
    for (int i = 0; i < count; ++i) free(sections[i].title);
    free(sections);
}

static SectionInfo *extract_sections(const char *text, int *count_out) {
    int cap = 8, count = 0;
    SectionInfo *sections = calloc((size_t)cap, sizeof(SectionInfo));
    if (!sections) die("out of memory");

    sections[count].level = 0;
    sections[count].title = strdup("Document Root");
    sections[count].start = 0;
    sections[count].end = strlen(text);
    count++;

    size_t pos = 0;
    int heading_count = 0;
    while (text[pos]) {
        size_t line_start = pos;
        while (text[pos] && text[pos] != '\n') pos++;
        size_t line_len = pos - line_start;
        int level = 0;
        char *title = NULL;
        if (line_is_markdown_heading(text + line_start, line_len, &level, &title)) {
            heading_count++;
            if (count == cap) {
                cap *= 2;
                SectionInfo *ns = realloc(sections, sizeof(SectionInfo) * (size_t)cap);
                if (!ns) die("out of memory");
                sections = ns;
            }
            sections[count].level = level;
            sections[count].title = title;
            sections[count].start = line_start;
            sections[count].end = strlen(text);
            count++;
        }
        if (text[pos] == '\n') pos++;
    }

    if (heading_count == 0) {
        *count_out = count;
        return sections;
    }

    for (int i = 0; i < count - 1; ++i) sections[i].end = sections[i + 1].start;
    sections[count - 1].end = strlen(text);
    *count_out = count;
    return sections;
}

static bool line_blank(const char *start, size_t len) {
    for (size_t i = 0; i < len; ++i) if (!isspace((unsigned char)start[i])) return false;
    return true;
}

static void emit_chunk_text(StrList *chunks, const char *text, size_t start, size_t end) {
    char *trimmed = trim_copy(text + start, end - start);
    if (trimmed[0]) strlist_push(chunks, trimmed);
    else free(trimmed);
}

static StrList paragraph_chunks_for_section(const char *text, size_t start, size_t end) {
    StrList chunks = {0};
    size_t pos = start;
    StrBuf current; sb_init(&current);
    bool started = false;

    while (pos < end) {
        size_t line_start = pos;
        while (pos < end && text[pos] != '\n') pos++;
        size_t line_len = pos - line_start;
        bool blank = line_blank(text + line_start, line_len);
        if (!blank) {
            if (!started) {
                started = true;
            }
            sb_append_n(&current, text + line_start, line_len);
            sb_append_n(&current, "\n", 1);
        }
        if (blank || pos >= end - 1) {
            if (current.len > 0) {
                char *paragraph = sb_take(&current);
                size_t plen = strlen(paragraph);
                if (plen > CHUNK_FALLBACK) {
                    size_t p = 0;
                    while (p < plen) {
                        size_t remaining = plen - p;
                        size_t slice = remaining > CHUNK_TARGET ? CHUNK_TARGET : remaining;
                        if (remaining > CHUNK_TARGET) {
                            size_t cut = slice;
                            while (cut > CHUNK_TARGET / 2 && !isspace((unsigned char)paragraph[p + cut])) cut--;
                            if (cut > CHUNK_TARGET / 2) slice = cut;
                        }
                        emit_chunk_text(&chunks, paragraph, p, p + slice);
                        p += slice;
                        while (p < plen && isspace((unsigned char)paragraph[p])) p++;
                    }
                    free(paragraph);
                } else {
                    char *trimmed = trim_copy(paragraph, plen);
                    free(paragraph);
                    if (trimmed[0]) strlist_push(&chunks, trimmed); else free(trimmed);
                }
                started = false;
            }
        }
        if (pos < end && text[pos] == '\n') pos++;
    }
    free(current.data);
    return chunks;
}

static void free_strlist(StrList *list) {
    for (int i = 0; i < list->count; ++i) free(list->items[i]);
    free(list->items);
}

static void create_related_links(sqlite3 *db, int current_chunk_id, int section_id, int namespace_id, const char *text) {
    sqlite3_stmt *stmt = NULL;
    if (sqlite3_prepare_v2(db,
        "SELECT c.id, c.raw_text FROM chunks c WHERE c.section_id=? AND c.namespace_id=? AND c.id<>? ORDER BY c.id DESC LIMIT 12;",
        -1, &stmt, NULL) != SQLITE_OK) die_sqlite(db, "prepare related_links");
    sqlite3_bind_int(stmt, 1, section_id);
    sqlite3_bind_int(stmt, 2, namespace_id);
    sqlite3_bind_int(stmt, 3, current_chunk_id);

    while (sqlite3_step(stmt) == SQLITE_ROW) {
        int other_id = sqlite3_column_int(stmt, 0);
        const char *other = (const char *)sqlite3_column_text(stmt, 1);
        if (!other) continue;
        int overlap = 0;
        char lowered[512] = {0};
        snprintf(lowered, sizeof(lowered), "%s", text);
        for (char *p = lowered; *p; ++p) *p = (char)tolower((unsigned char)*p);
        char other_lower[512] = {0};
        snprintf(other_lower, sizeof(other_lower), "%s", other);
        for (char *p = other_lower; *p; ++p) *p = (char)tolower((unsigned char)*p);
        const char *delims = " \n\r\t,.;:!?()[]{}<>\"'`/\\|-_";
        char *save = NULL;
        for (char *tok = strtok_r(lowered, delims, &save); tok; tok = strtok_r(NULL, delims, &save)) {
            if (strlen(tok) < 5) continue;
            if (strstr(other_lower, tok)) overlap++;
            if (overlap >= 2) break;
        }
        if (overlap >= 2) insert_link(db, current_chunk_id, other_id, "semantic_overlap", 0.55 + 0.10 * overlap);
    }
    sqlite3_finalize(stmt);
}

static void ingest_text(sqlite3 *db, int document_id, int version_id, int namespace_id, const char *scope, const char *text) {
    int section_count = 0;
    SectionInfo *sections = extract_sections(text, &section_count);
    int *section_ids = calloc((size_t)section_count, sizeof(int));
    int stack_ids[8] = {0};

    int chunk_ordinal = 0;
    int previous_chunk_id = 0;
    for (int i = 0; i < section_count; ++i) {
        int parent_id = 0;
        if (sections[i].level > 0) {
            int level = sections[i].level;
            if (level > 7) level = 7;
            parent_id = stack_ids[level - 1];
            section_ids[i] = insert_section(db, version_id, parent_id, sections[i].title, sections[i].level, i, (int)sections[i].start, (int)sections[i].end);
            stack_ids[level] = section_ids[i];
            for (int j = level + 1; j < 8; ++j) stack_ids[j] = 0;
        } else {
            section_ids[i] = insert_section(db, version_id, 0, sections[i].title, 0, i, (int)sections[i].start, (int)sections[i].end);
            memset(stack_ids, 0, sizeof(stack_ids));
        }

        StrList chunks = paragraph_chunks_for_section(text, sections[i].start, sections[i].end);
        for (int c = 0; c < chunks.count; ++c) {
            const char *chunk_text = chunks.items[c];
            const char *found = strstr(text + sections[i].start, chunk_text);
            int char_start = found ? (int)(found - text) : (int)sections[i].start;
            int char_end = char_start + (int)strlen(chunk_text);
            int token_est = count_tokens_estimate(chunk_text);
            int chunk_id = insert_chunk(db, document_id, version_id, section_ids[i], chunk_ordinal++, char_start, char_end, token_est, scope, namespace_id, chunk_text);
            if (previous_chunk_id > 0) insert_link(db, previous_chunk_id, chunk_id, "adjacent", 1.0);
            create_related_links(db, chunk_id, section_ids[i], namespace_id, chunk_text);
            previous_chunk_id = chunk_id;
        }
        free_strlist(&chunks);
    }

    free(section_ids);
    free_sections(sections, section_count);
}

static void ingest_file(sqlite3 *db, const char *path, const char *namespace_name) {
    if (!supported_extension(path)) return;

    unsigned char *bytes = NULL;
    size_t len = 0;
    if (!read_file_bytes(path, &bytes, &len)) {
        fprintf(stderr, "warn: failed to read %s\n", path);
        return;
    }

    char sha[65];
    sha256_hex(bytes, len, sha);
    char *text = normalize_text((const char *)bytes, len);
    free(bytes);

    char *filename = filename_from_path(path);
    const char *source_type = source_type_for_path(path);
    int namespace_id = ensure_namespace(db, namespace_name);
    int document_id = upsert_document(db, path, filename, source_type, namespace_id, namespace_name);

    int latest_version_id = 0, latest_version_no = 0;
    char latest_sha[65] = {0};
    bool has_latest = get_latest_version(db, document_id, &latest_version_id, &latest_version_no, latest_sha);
    if (has_latest && strcmp(latest_sha, sha) == 0) {
        printf("skip  %s [unchanged v%d]\n", path, latest_version_no);
        free(filename);
        free(text);
        return;
    }

    int version_no = has_latest ? latest_version_no + 1 : 1;
    int version_id = insert_document_version(db, document_id, version_no, sha, len, latest_version_id, text);
    ingest_text(db, document_id, version_id, namespace_id, namespace_name, text);
    printf("ingest %s [v%d sha=%s]\n", path, version_no, sha);
    free(filename);
    free(text);
}

static void ingest_dir(sqlite3 *db, const char *root, const char *namespace_name) {
    DIR *dir = opendir(root);
    if (!dir) {
        fprintf(stderr, "error: cannot open directory %s: %s\n", root, strerror(errno));
        exit(1);
    }
    struct dirent *ent;
    while ((ent = readdir(dir)) != NULL) {
        if (strcmp(ent->d_name, ".") == 0 || strcmp(ent->d_name, "..") == 0) continue;
        char *full = path_join(root, ent->d_name);
        struct stat st;
        if (stat(full, &st) != 0) { free(full); continue; }
        if (S_ISDIR(st.st_mode)) ingest_dir(db, full, namespace_name);
        else if (S_ISREG(st.st_mode)) ingest_file(db, full, namespace_name);
        free(full);
    }
    closedir(dir);
}

static void shell_escape_match(char *dst, size_t dstlen, const char *src) {
    size_t j = 0;
    for (size_t i = 0; src[i] && j + 2 < dstlen; ++i) {
        char c = src[i];
        if (c == '"') dst[j++] = ' ';
        else dst[j++] = c;
    }
    dst[j] = '\0';
}

static int split_terms(const char *query, char terms[TERM_LIMIT][64]) {
    char buf[1024];
    snprintf(buf, sizeof(buf), "%s", query);
    for (char *p = buf; *p; ++p) {
        unsigned char uc = (unsigned char)*p;
        if (!(isalnum(uc) || uc == '_' || uc >= 128)) *p = ' ';
        else *p = (char)tolower(uc);
    }
    int count = 0;
    char *save = NULL;
    for (char *tok = strtok_r(buf, " ", &save); tok && count < TERM_LIMIT; tok = strtok_r(NULL, " ", &save)) {
        if (strlen(tok) < 2) continue;
        snprintf(terms[count++], 64, "%s", tok);
    }
    return count;
}

static int count_keyword_overlap(const char *text, char terms[TERM_LIMIT][64], int term_count, int *matched_terms) {
    char buf[2048];
    snprintf(buf, sizeof(buf), "%s", text ? text : "");
    for (char *p = buf; *p; ++p) *p = (char)tolower((unsigned char)*p);
    int hits = 0;
    *matched_terms = 0;
    for (int i = 0; i < term_count; ++i) {
        if (strstr(buf, terms[i])) {
            hits += (int)strlen(terms[i]);
            (*matched_terms)++;
        }
    }
    return hits;
}

static int get_link_count(sqlite3 *db, int chunk_id) {
    sqlite3_stmt *stmt = NULL;
    if (sqlite3_prepare_v2(db, "SELECT COUNT(*) FROM links WHERE from_chunk_id=? OR to_chunk_id=?;", -1, &stmt, NULL) != SQLITE_OK)
        die_sqlite(db, "prepare get_link_count");
    sqlite3_bind_int(stmt, 1, chunk_id);
    sqlite3_bind_int(stmt, 2, chunk_id);
    int count = 0;
    if (sqlite3_step(stmt) == SQLITE_ROW) count = sqlite3_column_int(stmt, 0);
    sqlite3_finalize(stmt);
    return count;
}

static int latest_version_no_for_doc(sqlite3 *db, int doc_id) {
    sqlite3_stmt *stmt = NULL;
    if (sqlite3_prepare_v2(db, "SELECT MAX(version_no) FROM document_versions WHERE document_id=?;", -1, &stmt, NULL) != SQLITE_OK)
        die_sqlite(db, "prepare latest_version_no_for_doc");
    sqlite3_bind_int(stmt, 1, doc_id);
    int version_no = 1;
    if (sqlite3_step(stmt) == SQLITE_ROW) version_no = sqlite3_column_int(stmt, 0);
    sqlite3_finalize(stmt);
    return version_no;
}

static double compute_recency(long ingest_ts) {
    double age_days = difftime(time(NULL), (time_t)ingest_ts) / 86400.0;
    if (age_days < 0) age_days = 0;
    return 1.0 / (1.0 + age_days / 7.0);
}

static double compute_resonance(double lexical, double linkage, double recency, double trust, double scope_match, double namespace_match, double version_freshness) {
    double local_density = linkage;
    return lexical * 0.42 + linkage * 0.14 + recency * 0.12 + trust * 0.08 + scope_match * 0.10 + namespace_match * 0.08 + version_freshness * 0.06 + local_density * 0.00;
}

static int cmp_hits_desc(const void *a, const void *b) {
    const QueryHit *qa = a, *qb = b;
    if (qa->resonance < qb->resonance) return 1;
    if (qa->resonance > qb->resonance) return -1;
    return qa->chunk_id - qb->chunk_id;
}

static void log_retrieval(sqlite3 *db, const char *query, const char *namespace_name, int topk, const char *mode, int result_count, const char *explanation) {
    sqlite3_stmt *stmt = NULL;
    if (sqlite3_prepare_v2(db,
        "INSERT INTO retrieval_log(query_text, namespace_query, requested_topk, adapter_mode, created_at, result_count, explanation) VALUES(?,?,?,?,?,?,?);",
        -1, &stmt, NULL) != SQLITE_OK) die_sqlite(db, "prepare retrieval_log");
    sqlite3_bind_text(stmt, 1, query, -1, SQLITE_STATIC);
    sqlite3_bind_text(stmt, 2, namespace_name, -1, SQLITE_STATIC);
    sqlite3_bind_int(stmt, 3, topk);
    sqlite3_bind_text(stmt, 4, mode, -1, SQLITE_STATIC);
    sqlite3_bind_int64(stmt, 5, unix_time_now());
    sqlite3_bind_int(stmt, 6, result_count);
    sqlite3_bind_text(stmt, 7, explanation, -1, SQLITE_STATIC);
    if (sqlite3_step(stmt) != SQLITE_DONE) die_sqlite(db, "insert retrieval_log");
    sqlite3_finalize(stmt);
}

static void render_raw_chunks(QueryHit *hits, int count) {
    for (int i = 0; i < count; ++i) {
        printf("[%d] chunk=%d score=%.3f\n%s\n\n", i + 1, hits[i].chunk_id, hits[i].resonance, hits[i].snippet);
    }
}

static void render_citation_packet(QueryHit *hits, int count) {
    for (int i = 0; i < count; ++i) {
        printf("[%d] doc=%d file=%s version=%d chunk=%d namespace=%s score=%.3f\n", i + 1, hits[i].doc_id, hits[i].filename, hits[i].version_no, hits[i].chunk_id, hits[i].namespace_name, hits[i].resonance);
        printf("    char_range=%d..%d tokens~%d\n", hits[i].char_start, hits[i].char_end, hits[i].token_estimate);
        printf("    breakdown lexical=%.3f recency=%.3f trust=%.3f linkage=%.3f namespace=%.3f freshness=%.3f\n", hits[i].lexical, hits[i].recency, hits[i].trust, hits[i].linkage, hits[i].namespace_match, hits[i].version_freshness);
        printf("    why: %s\n", hits[i].explanation);
        printf("    text: %s\n\n", hits[i].snippet);
    }
}

static void render_compressed_packet(QueryHit *hits, int count) {
    printf("knowledge_packet {\n");
    printf("  results: %d\n", count);
    for (int i = 0; i < count; ++i) {
        printf("  - chunk: %d\n", hits[i].chunk_id);
        printf("    source: %s#v%d\n", hits[i].filename, hits[i].version_no);
        printf("    resonance: %.3f\n", hits[i].resonance);
        printf("    note: %s\n", hits[i].explanation);
    }
    printf("}\n");
}

static void query_db(sqlite3 *db, const char *query, const char *namespace_name, int topk, const char *mode) {
    char match_query[1024];
    shell_escape_match(match_query, sizeof(match_query), query);

    sqlite3_stmt *stmt = NULL;
    if (sqlite3_prepare_v2(db,
        "SELECT c.id, c.document_id, c.document_version_id, c.char_start, c.char_end, c.token_estimate, c.raw_text, "
        "       d.filename, d.path, dv.version_no, dv.ingest_ts, dv.trust, ns.name, -bm25(chunk_fts, 10.0, 1.0) AS lexical "
        "FROM chunk_fts "
        "JOIN chunks c ON c.id = chunk_fts.rowid "
        "JOIN document_versions dv ON dv.id = c.document_version_id "
        "JOIN documents d ON d.id = c.document_id "
        "JOIN namespaces ns ON ns.id = c.namespace_id "
        "WHERE chunk_fts MATCH ? AND dv.is_latest=1;",
        -1, &stmt, NULL) != SQLITE_OK) die_sqlite(db, "prepare query_db");
    sqlite3_bind_text(stmt, 1, match_query, -1, SQLITE_STATIC);

    char terms[TERM_LIMIT][64] = {{0}};
    int term_count = split_terms(query, terms);
    QueryHit hits[MAX_RESULTS] = {0};
    int count = 0;

    while (sqlite3_step(stmt) == SQLITE_ROW && count < MAX_RESULTS) {
        QueryHit *hit = &hits[count];
        hit->chunk_id = sqlite3_column_int(stmt, 0);
        hit->doc_id = sqlite3_column_int(stmt, 1);
        hit->version_id = sqlite3_column_int(stmt, 2);
        hit->char_start = sqlite3_column_int(stmt, 3);
        hit->char_end = sqlite3_column_int(stmt, 4);
        hit->token_estimate = sqlite3_column_int(stmt, 5);
        const char *raw_text = (const char *)sqlite3_column_text(stmt, 6);
        snprintf(hit->filename, sizeof(hit->filename), "%s", sqlite3_column_text(stmt, 7));
        snprintf(hit->path, sizeof(hit->path), "%s", sqlite3_column_text(stmt, 8));
        hit->version_no = sqlite3_column_int(stmt, 9);
        long ingest_ts = sqlite3_column_int64(stmt, 10);
        hit->trust = sqlite3_column_double(stmt, 11);
        snprintf(hit->namespace_name, sizeof(hit->namespace_name), "%s", sqlite3_column_text(stmt, 12));
        double lexical_raw = sqlite3_column_double(stmt, 13);

        if (!namespace_accessible(namespace_name, hit->namespace_name)) continue;

        int matched_terms = 0;
        int overlap_len = count_keyword_overlap(raw_text, terms, term_count, &matched_terms);
        hit->lexical = lexical_raw > 0.0 ? lexical_raw / (lexical_raw + 8.0) : (matched_terms ? 0.35 : 0.05);
        if (matched_terms > 0) hit->lexical += fmin(0.35, matched_terms * 0.08 + overlap_len / 256.0);
        if (hit->lexical > 1.0) hit->lexical = 1.0;
        hit->recency = compute_recency(ingest_ts);
        hit->link_count = get_link_count(db, hit->chunk_id);
        hit->linkage = fmin(1.0, hit->link_count / 6.0);
        hit->namespace_match = strcmp(namespace_name, hit->namespace_name) == 0 ? 1.0 : 0.75;
        double scope_match = hit->namespace_match;
        int latest_version = latest_version_no_for_doc(db, hit->doc_id);
        hit->version_freshness = latest_version > 0 ? (double)hit->version_no / (double)latest_version : 1.0;
        hit->resonance = compute_resonance(hit->lexical, hit->linkage, hit->recency, hit->trust, scope_match, hit->namespace_match, hit->version_freshness);
        snprintf(hit->snippet, sizeof(hit->snippet), "%s", raw_text ? raw_text : "");
        snprintf(hit->explanation, sizeof(hit->explanation),
                 "matched_terms=%d/%d, lexical=%s, recency=%.2f, namespace=%s, links=%d, latest_version=%s",
                 matched_terms, term_count,
                 hit->lexical > 0.72 ? "high" : (hit->lexical > 0.45 ? "medium" : "low"),
                 hit->recency,
                 strcmp(namespace_name, hit->namespace_name) == 0 ? "exact" : "public-fallback",
                 hit->link_count,
                 hit->version_freshness > 0.99 ? "yes" : "near-latest");
        count++;
    }
    sqlite3_finalize(stmt);

    qsort(hits, (size_t)count, sizeof(QueryHit), cmp_hits_desc);
    if (topk > count) topk = count;

    printf("query=\"%s\" namespace=%s mode=%s results=%d\n\n", query, namespace_name, mode, topk);
    if (strcmp(mode, "raw") == 0) render_raw_chunks(hits, topk);
    else if (strcmp(mode, "compressed") == 0) render_compressed_packet(hits, topk);
    else render_citation_packet(hits, topk);

    char log_summary[256];
    snprintf(log_summary, sizeof(log_summary), "resonance-ranked retrieval over %d candidates", count);
    log_retrieval(db, query, namespace_name, topk, mode, topk, log_summary);
}

static void stats_db(sqlite3 *db) {
    const char *queries[][2] = {
        {"namespaces", "SELECT COUNT(*) FROM namespaces;"},
        {"documents", "SELECT COUNT(*) FROM documents;"},
        {"versions", "SELECT COUNT(*) FROM document_versions;"},
        {"sections", "SELECT COUNT(*) FROM sections;"},
        {"chunks", "SELECT COUNT(*) FROM chunks;"},
        {"links", "SELECT COUNT(*) FROM links;"},
        {"retrieval_log", "SELECT COUNT(*) FROM retrieval_log;"}
    };
    for (int i = 0; i < ARRAY_LEN(queries); ++i) {
        sqlite3_stmt *stmt = NULL;
        if (sqlite3_prepare_v2(db, queries[i][1], -1, &stmt, NULL) != SQLITE_OK) die_sqlite(db, "prepare stats");
        if (sqlite3_step(stmt) == SQLITE_ROW) printf("%-14s %d\n", queries[i][0], sqlite3_column_int(stmt, 0));
        sqlite3_finalize(stmt);
    }
}

static void usage(void) {
    fprintf(stderr,
        "Knowledge Kernel (kk)\n"
        "Usage:\n"
        "  kk init <db>\n"
        "  kk ingest <db> <dir> <namespace>\n"
        "  kk query <db> <query> <namespace> <topk> [raw|citation|compressed]\n"
        "  kk stats <db>\n");
}

int main(int argc, char **argv) {
    if (argc < 3) {
        usage();
        return 1;
    }

    const char *cmd = argv[1];
    const char *db_path = argv[2];
    sqlite3 *db = NULL;
    if (sqlite3_open(db_path, &db) != SQLITE_OK) die_sqlite(db, "open database");
    init_db(db);

    if (strcmp(cmd, "init") == 0) {
        printf("initialized %s\n", db_path);
    } else if (strcmp(cmd, "ingest") == 0) {
        if (argc < 5) { usage(); sqlite3_close(db); return 1; }
        exec_sql(db, "BEGIN;");
        ingest_dir(db, argv[3], argv[4]);
        exec_sql(db, "COMMIT;");
    } else if (strcmp(cmd, "query") == 0) {
        if (argc < 6) { usage(); sqlite3_close(db); return 1; }
        int topk = atoi(argv[5]);
        if (topk <= 0) topk = 5;
        if (topk > MAX_RESULTS) topk = MAX_RESULTS;
        const char *mode = argc >= 7 ? argv[6] : "citation";
        query_db(db, argv[3], argv[4], topk, mode);
    } else if (strcmp(cmd, "stats") == 0) {
        stats_db(db);
    } else {
        usage();
        sqlite3_close(db);
        return 1;
    }

    sqlite3_close(db);
    return 0;
}
