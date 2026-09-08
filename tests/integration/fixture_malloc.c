/* fixture_malloc.c — malloc/free/realloc/calloc under LD_PRELOAD
 * Part of frankenlibc C fixture suite (bd-3jh).
 * Exit 0 = PASS, nonzero = FAIL with diagnostic to stderr.
 */
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <dlfcn.h>
#include <stdint.h>
#include <limits.h>

/* Isolated, deployed-ABI observations for harness verify-membrane. No expected
 * answer is emitted here: the Rust runner checks these raw results independently.
 * Strict runs use valid counterparts; invalid strict C calls have no portable
 * oracle. Compile with -fno-builtin, and resolve every operation from the exact
 * library rather than accidentally measuring the host or a compiler intrinsic. */
static void *probe_symbol(const char *symbol, const char *library) {
    void *address = dlsym(RTLD_DEFAULT, symbol);
    Dl_info info;
    char actual[PATH_MAX], expected[PATH_MAX];
    if (!address || !dladdr(address, &info) || !info.dli_fname ||
        !realpath(info.dli_fname, actual) || !realpath(library, expected) ||
        strcmp(actual, expected) != 0) {
        fprintf(stderr, "healing probe: wrong/missing provider for %s\n", symbol);
        return NULL;
    }
    return address;
}

static int healing_probe(const char *id, const char *library) {
    const char *mode = getenv("FRANKENLIBC_MODE");
    if (!mode || (strcmp(mode, "strict") && strcmp(mode, "hardened"))) return 2;
    int hardened = strcmp(mode, "hardened") == 0;
    const char *dash = strrchr(id, '-');
    if (!dash || !dash[1]) return 2;
    const char *symbol = dash + 1;
    void *operation = probe_symbol(symbol, library);
    void *(*allocate)(size_t) = probe_symbol("malloc", library);
    void (*release)(void *) = probe_symbol("free", library);
    uint64_t (*counter)(unsigned) = probe_symbol("__frankenlibc_healing_action_count", library);
    int (*ready)(void) = probe_symbol("__frankenlibc_is_runtime_ready", library);
    if (!operation || !allocate || !release || !counter || !ready || !ready()) return 2;

    unsigned action;
    if (!strncmp(id, "null-pointer-", 13)) action = 6;
    else if (!strncmp(id, "foreign-free-", 13)) action = 4;
    else if (!strcmp(symbol, "realloc") || !strcmp(symbol, "reallocarray")) action = 5;
    else if (!strcmp(symbol, "free") || !strcmp(symbol, "cfree")) action = 3;
    else if (!strcmp(symbol, "strcpy")) action = 2;
    else if (!strcmp(symbol, "strncpy") || !strcmp(symbol, "memcpy") || !strcmp(symbol, "memmove")) action = 1;
    else return 2;

    unsigned char *p = NULL;
    unsigned char foreign[32] = {0};
    unsigned char before[8] = {0}, after[8] = {0};
    size_t capacity = hardened ? 8 : 64;
    /* Exercise both grow and shrink realloc on quarantined allocations. */
    if (action == 5 && !strncmp(id, "realloc-freed-", 14)) capacity = 64;
    if (action != 6) {
        p = (action == 4 && hardened) ? foreign : allocate(capacity);
        if (!p) return 2;
        for (size_t i = 0; i < capacity; i++) p[i] = 'J';
        if (action <= 2) {
            /* Deliberate allocator-tail inspection in this fault subprocess.
             * In hardened mode the eight-byte trailing canary is mapped after
             * the requested extent. In strict controls this lies inside p. */
            for (size_t i = 0; i < 8; i++) before[i] = ((volatile unsigned char *)p)[8 + i];
        }
        if (hardened && (action == 3 || action == 5)) release(p);
    }

    uint64_t count_before = counter(action);
    errno = 0;
    long value = 0;
    unsigned char *result = NULL;
    if (!strcmp(symbol, "strlen")) {
        size_t (*call)(const char *) = operation;
        value = (long)call(hardened ? NULL : "x");
    } else if (!strcmp(symbol, "strcmp")) {
        int (*call)(const char *, const char *) = operation;
        value = call(hardened ? NULL : "x", "x");
    } else if (action == 3 || action == 4) {
        void (*call)(void *) = operation;
        call(p);
    } else if (action == 5) {
        if (!strcmp(symbol, "reallocarray")) {
            void *(*call)(void *, size_t, size_t) = operation;
            result = call(p, 4, 8);
        } else {
            void *(*call)(void *, size_t) = operation;
            result = call(p, 32);
        }
        value = result != NULL;
    } else if (!strcmp(symbol, "strcpy")) {
        char *(*call)(char *, const char *) = operation;
        value = call((char *)p, "ABCDEFGHIJKLMNOPQRSTUVWXYZ01234") == (char *)p;
    } else if (!strcmp(symbol, "strncpy")) {
        char *(*call)(char *, const char *, size_t) = operation;
        value = call((char *)p, "ABCDEFGHIJKLMNOPQRSTUVWXYZ01234", 32) == (char *)p;
    } else {
        void *(*call)(void *, const void *, size_t) = operation;
        value = call(p, "ABCDEFGHIJKLMNOPQRSTUVWXYZ01234", 32) == p;
    }
    int observed_errno = errno;
    uint64_t count_after = counter(action);
    unsigned prefix = 0;
    int nul = -1;
    if (action <= 2) {
        for (size_t i = 0; i < 8; i++) {
            after[i] = ((volatile unsigned char *)p)[8 + i];
            if (p[i] == (unsigned char)('A' + i)) prefix++;
            if (p[i] == 0 && nul == -1) nul = (int)i;
        }
    } else if (action == 5 && result) {
        if (!hardened) for (size_t i = 0; i < 8; i++) if (result[i] == 'J') prefix++;
        /* Exercise the returned allocation, not merely its non-null address. */
        for (size_t i = 0; i < 32; i++) ((volatile unsigned char *)result)[i] = 'R';
    } else if (action == 4 && hardened) {
        for (size_t i = 0; i < 8; i++) if (foreign[i] == 'J') prefix++;
    }
    printf("{\"case_id\":\"%s\",\"mode\":\"%s\",\"action\":%u,"
           "\"value\":%ld,\"errno\":%d,\"prefix\":%u,\"nul\":%d,\"same_pointer\":%s,"
           "\"counter_before\":%llu,\"counter_after\":%llu,\"guard_before\":[",
           id, mode, action, value, observed_errno, prefix, nul, result == p ? "true" : "false",
           (unsigned long long)count_before, (unsigned long long)count_after);
    for (int i = 0; i < 8; i++) printf("%s%u", i ? "," : "", before[i]);
    printf("],\"guard_after\":[");
    for (int i = 0; i < 8; i++) printf("%s%u", i ? "," : "", after[i]);
    printf("]}\n");
    if (action <= 2) release(p);
    if (result) release(result);
    return 0;
}

static int test_malloc_free(void) {
    char *p = malloc(128);
    if (!p) { fprintf(stderr, "FAIL: malloc(128) returned NULL\n"); return 1; }
    memset(p, 'X', 128);
    if (p[0] != 'X' || p[127] != 'X') {
        fprintf(stderr, "FAIL: memset after malloc\n"); free(p); return 1;
    }
    free(p);
    return 0;
}

static int test_calloc_zeroed(void) {
    int *arr = calloc(256, sizeof(int));
    if (!arr) { fprintf(stderr, "FAIL: calloc returned NULL\n"); return 1; }
    for (int i = 0; i < 256; i++) {
        if (arr[i] != 0) {
            fprintf(stderr, "FAIL: calloc not zeroed at %d\n", i);
            free(arr); return 1;
        }
    }
    free(arr);
    return 0;
}

static int test_realloc_grow(void) {
    char *p = malloc(16);
    if (!p) { fprintf(stderr, "FAIL: malloc(16) returned NULL\n"); return 1; }
    memcpy(p, "hello, realloc!", 16);

    char *q = realloc(p, 256);
    if (!q) { fprintf(stderr, "FAIL: realloc(256) returned NULL\n"); free(p); return 1; }
    if (memcmp(q, "hello, realloc!", 16) != 0) {
        fprintf(stderr, "FAIL: realloc did not preserve contents\n"); free(q); return 1;
    }
    free(q);
    return 0;
}

static int test_realloc_shrink(void) {
    char *p = malloc(1024);
    if (!p) { fprintf(stderr, "FAIL: malloc(1024) returned NULL\n"); return 1; }
    memset(p, 'Z', 1024);

    char *q = realloc(p, 8);
    if (!q) { fprintf(stderr, "FAIL: realloc(8) returned NULL\n"); free(p); return 1; }
    if (q[0] != 'Z' || q[7] != 'Z') {
        fprintf(stderr, "FAIL: realloc shrink lost data\n"); free(q); return 1;
    }
    free(q);
    return 0;
}

static int test_malloc_zero(void) {
    /* malloc(0) is implementation-defined but must not crash */
    void *p = malloc(0);
    free(p); /* free(NULL) or free(valid) both fine */
    return 0;
}

static int test_realloc_null(void) {
    /* realloc(NULL, n) == malloc(n) */
    char *p = realloc(NULL, 64);
    if (!p) { fprintf(stderr, "FAIL: realloc(NULL, 64) returned NULL\n"); return 1; }
    p[0] = 'A';
    free(p);
    return 0;
}

int main(int argc, char **argv) {
    if (argc == 4 && !strcmp(argv[1], "--healing-case")) {
        return healing_probe(argv[2], argv[3]);
    }
    if (argc != 1) return 2;
    int fails = 0;
    fails += test_malloc_free();
    fails += test_calloc_zeroed();
    fails += test_realloc_grow();
    fails += test_realloc_shrink();
    fails += test_malloc_zero();
    fails += test_realloc_null();

    if (fails) {
        fprintf(stderr, "fixture_malloc: %d FAILED\n", fails);
        return 1;
    }
    printf("fixture_malloc: PASS (6 tests)\n");
    return 0;
}
