/*
 * End-to-end workloads for the frankenlibc vs host-glibc comparison.
 *
 * These are WHOLE JOBS, not symbol microbenchmarks: input file in, report on
 * stdout, including startup, I/O, parsing, hashing, sorting and formatting.
 * The unit of measurement is "the program finished", which is the only unit a
 * user actually experiences.
 *
 * Built with plain `cc` and linked only against the system libc, so the ONLY
 * difference between the two arms is LD_PRELOAD. Nothing here links Rust or
 * references frankenlibc directly.
 *
 * Every workload writes deterministic output so the two arms can be compared
 * byte-for-byte before either is timed.
 *
 * Usage: e2e_workloads <logparse|tsreformat|wordfreq|csvstat> <input-file>
 */

#define _XOPEN_SOURCE 700
#define _DEFAULT_SOURCE

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

/* ---------------------------------------------------------------- */
/* Small open-addressing string->stats table, shared by the workloads. */
/* ---------------------------------------------------------------- */

typedef struct {
    char *key;
    long count;
    double sum;
    double min;
    double max;
} Entry;

typedef struct {
    Entry *slots;
    size_t cap;   /* power of two */
    size_t len;
} Table;

static unsigned long hash_str(const char *s) {
    /* FNV-1a */
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
    t->slots = NULL;
}

/* Collect occupied entries into a dense array for sorting. */
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

/* Descending by sum, ties broken lexicographically so output is total-ordered
   and therefore identical across runs and across the two arms. */
static int cmp_sum_desc(const void *a, const void *b) {
    const Entry *x = a, *y = b;
    if (x->sum < y->sum) return 1;
    if (x->sum > y->sum) return -1;
    return strcmp(x->key, y->key);
}

static int cmp_count_desc(const void *a, const void *b) {
    const Entry *x = a, *y = b;
    if (x->count < y->count) return 1;
    if (x->count > y->count) return -1;
    return strcmp(x->key, y->key);
}

static int cmp_key_asc(const void *a, const void *b) {
    const Entry *x = a, *y = b;
    return strcmp(x->key, y->key);
}

static FILE *open_or_die(const char *path) {
    FILE *f = fopen(path, "r");
    if (!f) {
        fprintf(stderr, "cannot open %s\n", path);
        exit(1);
    }
    return f;
}

/* ---------------------------------------------------------------- */
/* Workload 1: access-log analysis.                                  */
/*                                                                   */
/* Apache combined format. Per line: locate the bracketed timestamp, */
/* parse it with strptime (%d/%b/%Y:%H:%M:%S — a NAME-bearing        */
/* format), pull method/path/status/bytes, aggregate bytes per path, */
/* histogram the status classes, then report the top 20 paths.       */
/* Exercises stdio + strptime + strtol + strchr + malloc + qsort.    */
/* ---------------------------------------------------------------- */

static int run_logparse(const char *path) {
    FILE *f = open_or_die(path);
    Table t;
    table_init(&t, 1024);

    char line[2048];
    long status_class[6] = {0, 0, 0, 0, 0, 0};
    long total_lines = 0, parsed_ts = 0;
    double total_bytes = 0.0;
    long earliest = 0, latest = 0;
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
        /* Timestamp looks like 14/Nov/2023:22:13:20 +0000 */
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

        /* Request is the next quoted field after the timestamp. */
        char *q1 = strchr(rb + 1, '"');
        char *q2 = q1 ? strchr(q1 + 1, '"') : NULL;
        if (!q1 || !q2) {
            continue;
        }
        *q2 = '\0';
        char *req = q1 + 1;
        char *sp1 = strchr(req, ' ');
        if (!sp1) {
            continue;
        }
        char *urlp = sp1 + 1;
        char *sp2 = strchr(urlp, ' ');
        if (sp2) {
            *sp2 = '\0';
        }

        /* status and bytes follow the closing quote */
        char *rest = q2 + 1;
        char *endp = NULL;
        long status = strtol(rest, &endp, 10);
        long nbytes = strtol(endp, NULL, 10);

        int cls = (int)(status / 100);
        if (cls >= 1 && cls <= 5) {
            status_class[cls]++;
        }
        if (nbytes > 0) {
            total_bytes += (double)nbytes;
        }

        Entry *e = table_find(&t, urlp);
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
        time_t e0 = (time_t)earliest, e1 = (time_t)latest;
        gmtime_r(&e0, &out);
        strftime(buf, sizeof(buf), "%Y-%m-%dT%H:%M:%S", &out);
        printf("window_start=%s", buf);
        gmtime_r(&e1, &out);
        strftime(buf, sizeof(buf), "%Y-%m-%dT%H:%M:%S", &out);
        printf(" window_end=%s span_s=%ld\n", buf, latest - earliest);
    }
    size_t top = n < 20 ? n : 20;
    for (size_t i = 0; i < top; i++) {
        printf("%-40s hits=%-8ld bytes=%.0f\n", v[i].key, v[i].count, v[i].sum);
    }

    free(v);
    table_free(&t);
    return 0;
}

/* ---------------------------------------------------------------- */
/* Workload 2: timestamp normalisation.                              */
/*                                                                   */
/* Read syslog RFC 3164 lines, parse "%b %e %H:%M:%S", re-emit each  */
/* as ISO-8601 with the rest of the line intact. This is the whole   */
/* job a log-shipper does. strptime + strftime + stdio dominated.    */
/* ---------------------------------------------------------------- */

static int run_tsreformat(const char *path) {
    FILE *f = open_or_die(path);
    char line[2048];
    char out[64];
    long converted = 0, skipped = 0;
    unsigned long checksum = 0;

    while (fgets(line, sizeof(line), f)) {
        size_t len = strlen(line);
        if (len && line[len - 1] == '\n') {
            line[--len] = '\0';
        }
        struct tm tmv;
        memset(&tmv, 0, sizeof(tmv));
        tmv.tm_year = 123; /* syslog omits the year */
        char *rest = strptime(line, "%b %e %H:%M:%S", &tmv);
        if (!rest) {
            skipped++;
            continue;
        }
        if (strftime(out, sizeof(out), "%Y-%m-%dT%H:%M:%SZ", &tmv) == 0) {
            skipped++;
            continue;
        }
        converted++;
        /* Fold the rewritten line into a checksum instead of writing it, so the
           measurement is the parse/format job and not the terminal. */
        for (const char *p = out; *p; p++) {
            checksum = checksum * 131 + (unsigned char)*p;
        }
        for (const char *p = rest; *p; p++) {
            checksum = checksum * 131 + (unsigned char)*p;
        }
    }
    fclose(f);
    printf("converted=%ld skipped=%ld checksum=%lu\n", converted, skipped,
           checksum);
    return 0;
}

/* ---------------------------------------------------------------- */
/* Workload 3: word frequency.                                       */
/*                                                                   */
/* Classic text pipeline: tokenise on non-alphabetic bytes, fold to  */
/* lower case, count in a hash table, report the top 30. Allocation- */
/* heavy (a strdup per new word) and strcmp-heavy on probe.          */
/* ---------------------------------------------------------------- */

static int run_wordfreq(const char *path) {
    FILE *f = open_or_die(path);
    Table t;
    table_init(&t, 4096);

    char line[4096];
    char word[256];
    long total_words = 0;

    while (fgets(line, sizeof(line), f)) {
        size_t w = 0;
        for (const char *p = line;; p++) {
            unsigned char c = (unsigned char)*p;
            int is_alpha = (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z');
            if (is_alpha) {
                if (w + 1 < sizeof(word)) {
                    word[w++] = (char)((c >= 'A' && c <= 'Z') ? c + 32 : c);
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

/* ---------------------------------------------------------------- */
/* Workload 4: CSV numeric aggregation.                              */
/*                                                                   */
/* Read id,category,value CSV, parse the value with strtod, group by */
/* category, report count/sum/min/max/mean per group. strtod- and    */
/* strchr-dominated, which is the shape of every CSV ingest job.     */
/* ---------------------------------------------------------------- */

static int run_csvstat(const char *path) {
    FILE *f = open_or_die(path);
    Table t;
    table_init(&t, 1024);

    char line[1024];
    long rows = 0, bad = 0;

    /* discard the header */
    if (!fgets(line, sizeof(line), f)) {
        fclose(f);
        printf("rows=0 groups=0\n");
        table_free(&t);
        return 0;
    }

    while (fgets(line, sizeof(line), f)) {
        char *c1 = strchr(line, ',');
        if (!c1) {
            bad++;
            continue;
        }
        char *c2 = strchr(c1 + 1, ',');
        if (!c2) {
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
        printf("%-16s n=%-8ld sum=%.4f min=%.4f max=%.4f mean=%.6f\n", v[i].key,
               v[i].count, v[i].sum, v[i].min, v[i].max,
               v[i].count ? v[i].sum / (double)v[i].count : 0.0);
    }

    free(v);
    table_free(&t);
    return 0;
}

int main(int argc, char **argv) {
    if (argc != 3) {
        fprintf(stderr, "usage: %s <workload> <input-file>\n", argv[0]);
        return 2;
    }
    const char *what = argv[1];
    if (strcmp(what, "logparse") == 0) {
        return run_logparse(argv[2]);
    }
    if (strcmp(what, "tsreformat") == 0) {
        return run_tsreformat(argv[2]);
    }
    if (strcmp(what, "wordfreq") == 0) {
        return run_wordfreq(argv[2]);
    }
    if (strcmp(what, "csvstat") == 0) {
        return run_csvstat(argv[2]);
    }
    fprintf(stderr, "unknown workload %s\n", what);
    return 2;
}
