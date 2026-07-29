/*
 * Realistic end-to-end workloads for FrankenLibC versus host glibc.
 *
 * This executable is linked only against the system libc. The controller runs
 * this exact ELF normally and with FrankenLibC in LD_PRELOAD, so startup, input
 * I/O, parsing, allocation, sorting, formatting, output I/O, and teardown are
 * all inside the measured job.
 */

#define _XOPEN_SOURCE 700
#define _DEFAULT_SOURCE
#define _GNU_SOURCE

#include <dlfcn.h>
#include <limits.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

/* ------------------------------------------------------------------------- */
/* In-process SHA-256 identity reporting.                                    */
/* ------------------------------------------------------------------------- */

typedef struct {
    uint8_t data[64];
    uint32_t state[8];
    uint64_t bitlen;
    size_t datalen;
} Sha256;

static uint32_t rotr32(uint32_t x, uint32_t n) {
    return (x >> n) | (x << (32U - n));
}

static void sha256_transform(Sha256 *ctx, const uint8_t block[64]) {
    static const uint32_t k[64] = {
        0x428a2f98U, 0x71374491U, 0xb5c0fbcfU, 0xe9b5dba5U,
        0x3956c25bU, 0x59f111f1U, 0x923f82a4U, 0xab1c5ed5U,
        0xd807aa98U, 0x12835b01U, 0x243185beU, 0x550c7dc3U,
        0x72be5d74U, 0x80deb1feU, 0x9bdc06a7U, 0xc19bf174U,
        0xe49b69c1U, 0xefbe4786U, 0x0fc19dc6U, 0x240ca1ccU,
        0x2de92c6fU, 0x4a7484aaU, 0x5cb0a9dcU, 0x76f988daU,
        0x983e5152U, 0xa831c66dU, 0xb00327c8U, 0xbf597fc7U,
        0xc6e00bf3U, 0xd5a79147U, 0x06ca6351U, 0x14292967U,
        0x27b70a85U, 0x2e1b2138U, 0x4d2c6dfcU, 0x53380d13U,
        0x650a7354U, 0x766a0abbU, 0x81c2c92eU, 0x92722c85U,
        0xa2bfe8a1U, 0xa81a664bU, 0xc24b8b70U, 0xc76c51a3U,
        0xd192e819U, 0xd6990624U, 0xf40e3585U, 0x106aa070U,
        0x19a4c116U, 0x1e376c08U, 0x2748774cU, 0x34b0bcb5U,
        0x391c0cb3U, 0x4ed8aa4aU, 0x5b9cca4fU, 0x682e6ff3U,
        0x748f82eeU, 0x78a5636fU, 0x84c87814U, 0x8cc70208U,
        0x90befffaU, 0xa4506cebU, 0xbef9a3f7U, 0xc67178f2U,
    };
    uint32_t w[64];
    for (size_t i = 0; i < 16; i++) {
        size_t j = i * 4;
        w[i] = ((uint32_t)block[j] << 24) |
               ((uint32_t)block[j + 1] << 16) |
               ((uint32_t)block[j + 2] << 8) |
               (uint32_t)block[j + 3];
    }
    for (size_t i = 16; i < 64; i++) {
        uint32_t s0 = rotr32(w[i - 15], 7) ^ rotr32(w[i - 15], 18) ^
                      (w[i - 15] >> 3);
        uint32_t s1 = rotr32(w[i - 2], 17) ^ rotr32(w[i - 2], 19) ^
                      (w[i - 2] >> 10);
        w[i] = w[i - 16] + s0 + w[i - 7] + s1;
    }

    uint32_t a = ctx->state[0];
    uint32_t b = ctx->state[1];
    uint32_t c = ctx->state[2];
    uint32_t d = ctx->state[3];
    uint32_t e = ctx->state[4];
    uint32_t f = ctx->state[5];
    uint32_t g = ctx->state[6];
    uint32_t h = ctx->state[7];
    for (size_t i = 0; i < 64; i++) {
        uint32_t s1 = rotr32(e, 6) ^ rotr32(e, 11) ^ rotr32(e, 25);
        uint32_t ch = (e & f) ^ ((~e) & g);
        uint32_t t1 = h + s1 + ch + k[i] + w[i];
        uint32_t s0 = rotr32(a, 2) ^ rotr32(a, 13) ^ rotr32(a, 22);
        uint32_t maj = (a & b) ^ (a & c) ^ (b & c);
        uint32_t t2 = s0 + maj;
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

static void sha256_init(Sha256 *ctx) {
    ctx->datalen = 0;
    ctx->bitlen = 0;
    ctx->state[0] = 0x6a09e667U;
    ctx->state[1] = 0xbb67ae85U;
    ctx->state[2] = 0x3c6ef372U;
    ctx->state[3] = 0xa54ff53aU;
    ctx->state[4] = 0x510e527fU;
    ctx->state[5] = 0x9b05688cU;
    ctx->state[6] = 0x1f83d9abU;
    ctx->state[7] = 0x5be0cd19U;
}

static void sha256_update(Sha256 *ctx, const uint8_t *data, size_t len) {
    for (size_t i = 0; i < len; i++) {
        ctx->data[ctx->datalen++] = data[i];
        if (ctx->datalen == 64) {
            sha256_transform(ctx, ctx->data);
            ctx->bitlen += 512;
            ctx->datalen = 0;
        }
    }
}

static void sha256_final(Sha256 *ctx, uint8_t out[32]) {
    size_t i = ctx->datalen;
    ctx->data[i++] = 0x80;
    if (i > 56) {
        while (i < 64) {
            ctx->data[i++] = 0;
        }
        sha256_transform(ctx, ctx->data);
        i = 0;
    }
    while (i < 56) {
        ctx->data[i++] = 0;
    }
    ctx->bitlen += (uint64_t)ctx->datalen * 8;
    for (size_t j = 0; j < 8; j++) {
        ctx->data[63 - j] = (uint8_t)(ctx->bitlen >> (j * 8));
    }
    sha256_transform(ctx, ctx->data);
    for (size_t j = 0; j < 8; j++) {
        out[j * 4] = (uint8_t)(ctx->state[j] >> 24);
        out[j * 4 + 1] = (uint8_t)(ctx->state[j] >> 16);
        out[j * 4 + 2] = (uint8_t)(ctx->state[j] >> 8);
        out[j * 4 + 3] = (uint8_t)ctx->state[j];
    }
}

static int sha256_file(const char *path, char hex[65]) {
    FILE *f = fopen(path, "rb");
    if (!f) {
        return 0;
    }
    Sha256 ctx;
    sha256_init(&ctx);
    uint8_t buf[32768];
    for (;;) {
        size_t n = fread(buf, 1, sizeof(buf), f);
        if (n) {
            sha256_update(&ctx, buf, n);
        }
        if (n != sizeof(buf)) {
            if (ferror(f)) {
                fclose(f);
                return 0;
            }
            break;
        }
    }
    fclose(f);
    uint8_t digest[32];
    sha256_final(&ctx, digest);
    static const char alphabet[] = "0123456789abcdef";
    for (size_t i = 0; i < 32; i++) {
        hex[i * 2] = alphabet[digest[i] >> 4];
        hex[i * 2 + 1] = alphabet[digest[i] & 15];
    }
    hex[64] = '\0';
    return 1;
}

static void report_loaded_symbol(const char *label, void *symbol) {
    Dl_info info;
    char hash[65];
    if (!dladdr(symbol, &info) || !info.dli_fname ||
        !sha256_file(info.dli_fname, hash)) {
        fprintf(stderr, "cannot identify loaded symbol %s\n", label);
        exit(1);
    }
    printf("%s_PATH=%s\n", label, info.dli_fname);
    printf("%s_SHA256=%s\n", label, hash);
}

static int run_identity(void) {
    char exe_path[PATH_MAX];
    ssize_t n = readlink("/proc/self/exe", exe_path, sizeof(exe_path) - 1);
    if (n < 0) {
        fprintf(stderr, "cannot resolve /proc/self/exe\n");
        return 1;
    }
    exe_path[n] = '\0';
    char hash[65];
    if (!sha256_file("/proc/self/exe", hash)) {
        fprintf(stderr, "cannot hash /proc/self/exe\n");
        return 1;
    }
    printf("WORKLOAD_ELF_PATH=%s\n", exe_path);
    printf("WORKLOAD_ELF_SHA256=%s\n", hash);
    report_loaded_symbol("MALLOC_ELF", (void *)malloc);
    report_loaded_symbol("FOPEN_ELF", (void *)fopen);
    report_loaded_symbol("FGETS_ELF", (void *)fgets);
    report_loaded_symbol("STRFTIME_ELF", (void *)strftime);
    return 0;
}

/* ------------------------------------------------------------------------- */
/* Shared open-addressing string-to-statistics table.                        */
/* ------------------------------------------------------------------------- */

typedef struct {
    char *key;
    long count;
    double sum;
    double min;
    double max;
} Entry;

typedef struct {
    Entry *slots;
    size_t cap;
    size_t len;
} Table;

static unsigned long hash_str(const char *s) {
    unsigned long h = 1469598103934665603UL;
    while (*s) {
        h ^= (unsigned char)*s++;
        h *= 1099511628211UL;
    }
    return h;
}

static void table_init(Table *t, size_t cap) {
    t->cap = cap;
    t->len = 0;
    t->slots = calloc(cap, sizeof(Entry));
    if (!t->slots) {
        fprintf(stderr, "oom\n");
        exit(1);
    }
}

static void table_grow(Table *t);

static Entry *table_find(Table *t, const char *key) {
    if ((t->len + 1) * 10 >= t->cap * 7) {
        table_grow(t);
    }
    size_t mask = t->cap - 1;
    size_t i = (size_t)hash_str(key) & mask;
    while (t->slots[i].key) {
        if (strcmp(t->slots[i].key, key) == 0) {
            return &t->slots[i];
        }
        i = (i + 1) & mask;
    }
    t->slots[i].key = strdup(key);
    if (!t->slots[i].key) {
        fprintf(stderr, "oom\n");
        exit(1);
    }
    t->slots[i].count = 0;
    t->slots[i].sum = 0.0;
    t->slots[i].min = 0.0;
    t->slots[i].max = 0.0;
    t->len++;
    return &t->slots[i];
}

static void table_grow(Table *t) {
    size_t old_cap = t->cap;
    Entry *old = t->slots;
    t->cap = old_cap * 2;
    t->len = 0;
    t->slots = calloc(t->cap, sizeof(Entry));
    if (!t->slots) {
        fprintf(stderr, "oom\n");
        exit(1);
    }
    size_t mask = t->cap - 1;
    for (size_t i = 0; i < old_cap; i++) {
        if (!old[i].key) {
            continue;
        }
        size_t j = (size_t)hash_str(old[i].key) & mask;
        while (t->slots[j].key) {
            j = (j + 1) & mask;
        }
        t->slots[j] = old[i];
        t->len++;
    }
    free(old);
}

static void table_free(Table *t) {
    for (size_t i = 0; i < t->cap; i++) {
        free(t->slots[i].key);
    }
    free(t->slots);
}

static Entry *table_collect(Table *t, size_t *out_n) {
    Entry *v = malloc(t->len ? t->len * sizeof(Entry) : 1);
    if (!v) {
        fprintf(stderr, "oom\n");
        exit(1);
    }
    size_t n = 0;
    for (size_t i = 0; i < t->cap; i++) {
        if (t->slots[i].key) {
            v[n++] = t->slots[i];
        }
    }
    *out_n = n;
    return v;
}

static int cmp_sum_desc(const void *a, const void *b) {
    const Entry *x = a;
    const Entry *y = b;
    if (x->sum < y->sum) return 1;
    if (x->sum > y->sum) return -1;
    return strcmp(x->key, y->key);
}

static int cmp_count_desc(const void *a, const void *b) {
    const Entry *x = a;
    const Entry *y = b;
    if (x->count < y->count) return 1;
    if (x->count > y->count) return -1;
    return strcmp(x->key, y->key);
}

static int cmp_key_asc(const void *a, const void *b) {
    const Entry *x = a;
    const Entry *y = b;
    return strcmp(x->key, y->key);
}

static FILE *open_or_die(const char *path, const char *mode) {
    FILE *f = fopen(path, mode);
    if (!f) {
        fprintf(stderr, "cannot open %s\n", path);
        exit(1);
    }
    return f;
}

/* ------------------------------------------------------------------------- */
/* Workload 1: Apache combined-log analytics.                                */
/* ------------------------------------------------------------------------- */

static int run_logparse(const char *path) {
    FILE *f = open_or_die(path, "r");
    Table t;
    table_init(&t, 1024);
    char line[2048];
    long status_class[6] = {0, 0, 0, 0, 0, 0};
    long total_lines = 0;
    long parsed_ts = 0;
    double total_bytes = 0.0;
    long earliest = 0;
    long latest = 0;
    int have_span = 0;

    while (fgets(line, sizeof(line), f)) {
        total_lines++;
        char *lb = strchr(line, '[');
        char *rb = lb ? strchr(lb, ']') : NULL;
        if (!lb || !rb) {
            continue;
        }
        *rb = '\0';
        struct tm tmv;
        memset(&tmv, 0, sizeof(tmv));
        if (strptime(lb + 1, "%d/%b/%Y:%H:%M:%S", &tmv)) {
            parsed_ts++;
            tmv.tm_isdst = 0;
            long secs = (long)timegm(&tmv);
            if (!have_span) {
                earliest = latest = secs;
                have_span = 1;
            } else {
                if (secs < earliest) earliest = secs;
                if (secs > latest) latest = secs;
            }
        }

        char *q1 = strchr(rb + 1, '"');
        char *q2 = q1 ? strchr(q1 + 1, '"') : NULL;
        if (!q1 || !q2) {
            continue;
        }
        *q2 = '\0';
        char *request = q1 + 1;
        char *sp1 = strchr(request, ' ');
        if (!sp1) {
            continue;
        }
        char *url = sp1 + 1;
        char *sp2 = strchr(url, ' ');
        if (sp2) {
            *sp2 = '\0';
        }

        char *endp = NULL;
        long status = strtol(q2 + 1, &endp, 10);
        long nbytes = strtol(endp, NULL, 10);
        int cls = (int)(status / 100);
        if (cls >= 1 && cls <= 5) {
            status_class[cls]++;
        }
        if (nbytes > 0) {
            total_bytes += (double)nbytes;
        }
        Entry *e = table_find(&t, url);
        e->count++;
        e->sum += (double)(nbytes > 0 ? nbytes : 0);
    }
    fclose(f);

    size_t n = 0;
    Entry *v = table_collect(&t, &n);
    qsort(v, n, sizeof(Entry), cmp_sum_desc);
    printf("lines=%ld parsed_ts=%ld distinct_paths=%zu total_bytes=%.0f\n",
           total_lines, parsed_ts, n, total_bytes);
    printf("status 1xx=%ld 2xx=%ld 3xx=%ld 4xx=%ld 5xx=%ld\n",
           status_class[1], status_class[2], status_class[3], status_class[4],
           status_class[5]);
    if (have_span) {
        char buf[64];
        struct tm out;
        time_t e0 = (time_t)earliest;
        time_t e1 = (time_t)latest;
        gmtime_r(&e0, &out);
        strftime(buf, sizeof(buf), "%Y-%m-%dT%H:%M:%S", &out);
        printf("window_start=%s", buf);
        gmtime_r(&e1, &out);
        strftime(buf, sizeof(buf), "%Y-%m-%dT%H:%M:%S", &out);
        printf(" window_end=%s span_s=%ld\n", buf, latest - earliest);
    }
    size_t top = n < 20 ? n : 20;
    for (size_t i = 0; i < top; i++) {
        printf("%-40s hits=%-8ld bytes=%.0f\n",
               v[i].key, v[i].count, v[i].sum);
    }
    free(v);
    table_free(&t);
    return 0;
}

/* ------------------------------------------------------------------------- */
/* Workload 2: RFC3164-to-ISO8601 log normalization and serialization.       */
/* ------------------------------------------------------------------------- */

static int run_tsreformat(const char *path, const char *output_path) {
    FILE *f = open_or_die(path, "r");
    FILE *outf = open_or_die(output_path, "w");
    char line[2048];
    char out[64];
    long converted = 0;
    long skipped = 0;
    unsigned long checksum = 0;
    unsigned long output_bytes = 0;

    while (fgets(line, sizeof(line), f)) {
        size_t len = strlen(line);
        if (len && line[len - 1] == '\n') {
            line[--len] = '\0';
        }
        struct tm tmv;
        memset(&tmv, 0, sizeof(tmv));
        tmv.tm_year = 123;
        char *rest = strptime(line, "%b %e %H:%M:%S", &tmv);
        if (!rest ||
            strftime(out, sizeof(out), "%Y-%m-%dT%H:%M:%SZ", &tmv) == 0) {
            skipped++;
            continue;
        }
        converted++;
        size_t out_len = strlen(out);
        size_t rest_len = strlen(rest);
        if (fwrite(out, 1, out_len, outf) != out_len ||
            fwrite(rest, 1, rest_len, outf) != rest_len ||
            fputc('\n', outf) == EOF) {
            fprintf(stderr, "output write failed\n");
            exit(1);
        }
        output_bytes += (unsigned long)(out_len + rest_len + 1);
        for (const char *p = out; *p; p++) {
            checksum = checksum * 131 + (unsigned char)*p;
        }
        for (const char *p = rest; *p; p++) {
            checksum = checksum * 131 + (unsigned char)*p;
        }
    }
    if (fclose(outf) != 0) {
        fprintf(stderr, "output close failed\n");
        exit(1);
    }
    fclose(f);
    printf("converted=%ld skipped=%ld output_bytes=%lu checksum=%lu\n",
           converted, skipped, output_bytes, checksum);
    return 0;
}

/* ------------------------------------------------------------------------- */
/* Workload 3: Zipf-skewed corpus word-frequency report.                     */
/* ------------------------------------------------------------------------- */

static int run_wordfreq(const char *path) {
    FILE *f = open_or_die(path, "r");
    Table t;
    table_init(&t, 4096);
    char line[4096];
    char word[256];
    long total_words = 0;

    while (fgets(line, sizeof(line), f)) {
        size_t w = 0;
        for (const char *p = line;; p++) {
            unsigned char c = (unsigned char)*p;
            int alpha = (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z');
            if (alpha) {
                if (w + 1 < sizeof(word)) {
                    word[w++] =
                        (char)((c >= 'A' && c <= 'Z') ? c + 32 : c);
                }
            } else {
                if (w) {
                    word[w] = '\0';
                    Entry *e = table_find(&t, word);
                    e->count++;
                    total_words++;
                    w = 0;
                }
                if (!c) {
                    break;
                }
            }
        }
    }
    fclose(f);

    size_t n = 0;
    Entry *v = table_collect(&t, &n);
    qsort(v, n, sizeof(Entry), cmp_count_desc);
    printf("total_words=%ld distinct_words=%zu\n", total_words, n);
    size_t top = n < 30 ? n : 30;
    for (size_t i = 0; i < top; i++) {
        printf("%-24s %ld\n", v[i].key, v[i].count);
    }
    free(v);
    table_free(&t);
    return 0;
}

/* ------------------------------------------------------------------------- */
/* Workload 4: skewed-category CSV numeric aggregation and report.           */
/* ------------------------------------------------------------------------- */

static int run_csvstat(const char *path) {
    FILE *f = open_or_die(path, "r");
    Table t;
    table_init(&t, 1024);
    char line[1024];
    long rows = 0;
    long bad = 0;

    if (!fgets(line, sizeof(line), f)) {
        fclose(f);
        printf("rows=0 groups=0\n");
        table_free(&t);
        return 0;
    }
    while (fgets(line, sizeof(line), f)) {
        char *c1 = strchr(line, ',');
        char *c2 = c1 ? strchr(c1 + 1, ',') : NULL;
        if (!c1 || !c2) {
            bad++;
            continue;
        }
        *c1 = '\0';
        *c2 = '\0';
        const char *category = c1 + 1;
        char *endp = NULL;
        double value = strtod(c2 + 1, &endp);
        if (endp == c2 + 1) {
            bad++;
            continue;
        }
        rows++;
        Entry *e = table_find(&t, category);
        if (e->count == 0) {
            e->min = value;
            e->max = value;
        } else {
            if (value < e->min) e->min = value;
            if (value > e->max) e->max = value;
        }
        e->count++;
        e->sum += value;
    }
    fclose(f);

    size_t n = 0;
    Entry *v = table_collect(&t, &n);
    qsort(v, n, sizeof(Entry), cmp_key_asc);
    printf("rows=%ld bad=%ld groups=%zu\n", rows, bad, n);
    for (size_t i = 0; i < n; i++) {
        printf("%-16s n=%-8ld sum=%.4f min=%.4f max=%.4f mean=%.6f\n",
               v[i].key, v[i].count, v[i].sum, v[i].min, v[i].max,
               v[i].count ? v[i].sum / (double)v[i].count : 0.0);
    }
    free(v);
    table_free(&t);
    return 0;
}

int main(int argc, char **argv) {
    if (argc == 2 && strcmp(argv[1], "identity") == 0) {
        return run_identity();
    }
    if (argc < 3) {
        fprintf(stderr,
                "usage: %s <logparse|tsreformat|wordfreq|csvstat> <input> "
                "[output]\n",
                argv[0]);
        return 2;
    }
    if (strcmp(argv[1], "logparse") == 0) {
        return run_logparse(argv[2]);
    }
    if (strcmp(argv[1], "tsreformat") == 0) {
        if (argc != 4) {
            fprintf(stderr, "tsreformat requires an output path\n");
            return 2;
        }
        return run_tsreformat(argv[2], argv[3]);
    }
    if (strcmp(argv[1], "wordfreq") == 0) {
        return run_wordfreq(argv[2]);
    }
    if (strcmp(argv[1], "csvstat") == 0) {
        return run_csvstat(argv[2]);
    }
    fprintf(stderr, "unknown workload %s\n", argv[1]);
    return 2;
}
