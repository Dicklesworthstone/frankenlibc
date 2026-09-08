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

/* These are deployed-ABI observations, not standalone proof. The controller
 * must reject host-libc mappings before claiming isolation. Observer I/O and
 * JSON serialization may use the host; every workload operation is resolved
 * below and its address is included for independent mapping verification. */
static void ws8_json_string(const char *s) {
    putchar('"');
    for (const unsigned char *p = (const unsigned char *)s; *p; p++) {
        if (*p == '"' || *p == '\\') printf("\\%c", *p);
        else if (*p < 32 || *p >= 127) printf("\\u%04x", *p);
        else putchar(*p);
    }
    putchar('"');
}

static int ws8_probe(const char *id, const char *library) {
    const char *mode = getenv("FRANKENLIBC_MODE");
    if (!mode || (strcmp(mode, "strict") && strcmp(mode, "hardened"))) return 2;
    int kind = !strcmp(id, "string_pipeline") ? 1 :
               !strcmp(id, "memory_lifecycle") ? 2 :
               !strcmp(id, "format_stdio") ? 3 :
               !strcmp(id, "edge_boundary") ? 4 :
               !strcmp(id, "error_handling") ? 5 : 0;
    if (!kind || (kind == 5 && strcmp(mode, "hardened"))) return 2;
    const char *symbols[] = {"malloc", "free", "calloc", "realloc", "strlen",
        "memcpy", "memmove", "strcmp", "snprintf",
        "__frankenlibc_healing_action_count", "__frankenlibc_is_runtime_ready"};
    void *addresses[sizeof(symbols) / sizeof(symbols[0])];
    for (size_t i = 0; i < sizeof(symbols) / sizeof(symbols[0]); i++) {
        addresses[i] = probe_symbol(symbols[i], library);
        if (!addresses[i]) return 2;
    }
    void *(*allocate)(size_t) = addresses[0];
    void (*release)(void *) = addresses[1];
    void *(*zero_allocate)(size_t, size_t) = addresses[2];
    void *(*resize)(void *, size_t) = addresses[3];
    size_t (*length)(const char *) = addresses[4];
    void *(*copy)(void *, const void *, size_t) = addresses[5];
    void *(*move)(void *, const void *, size_t) = addresses[6];
    int (*compare)(const char *, const char *) = addresses[7];
    int (*format)(char *, size_t, const char *, ...) = addresses[8];
    uint64_t (*counter)(unsigned) = addresses[9];
    int (*ready)(void) = addresses[10];
    const char *names[16];
    int passed[16], count = 0;
#define WS8_CHECK(name, outcome) do { names[count] = (name); passed[count++] = !!(outcome); } while (0)
    WS8_CHECK("runtime_ready", ready());
    if (kind == 1) {
        char buffer[32] = {0};
        void *copied = copy(buffer, "abcdef", 7);
        WS8_CHECK("copy_exact", copied == buffer && compare(buffer, "abcdef") == 0);
        WS8_CHECK("length_exact", length(buffer) == 6);
        void *moved = move(buffer + 1, buffer, 7);
        WS8_CHECK("overlap_move", moved == buffer + 1 && compare(buffer, "aabcdef") == 0);
    } else if (kind == 2) {
        unsigned char *p = zero_allocate(16, 1);
        int zeroed = p != NULL;
        if (p) for (size_t i = 0; i < 16; i++) if (p[i]) zeroed = 0;
        WS8_CHECK("calloc_zeroed", zeroed);
        if (p) for (size_t i = 0; i < 16; i++) p[i] = (unsigned char)(i + 1);
        unsigned char *q = p ? resize(p, 64) : NULL;
        int preserved = q != NULL;
        if (q) for (size_t i = 0; i < 16; i++) if (q[i] != i + 1) preserved = 0;
        WS8_CHECK("realloc_grow_preserves", preserved);
        if (q) p = q;
        q = p ? resize(p, 8) : NULL;
        preserved = q != NULL;
        if (q) for (size_t i = 0; i < 8; i++) if (q[i] != i + 1) preserved = 0;
        WS8_CHECK("realloc_shrink_preserves", preserved);
        release(q ? q : p);
    } else if (kind == 3) {
        char full[32], small[5];
        int n = format(full, sizeof(full), "%s:%d", "ws8", 42);
        WS8_CHECK("format_exact", n == 6 && compare(full, "ws8:42") == 0);
        n = format(small, sizeof(small), "%s:%d", "ws8", 42);
        WS8_CHECK("format_truncation", n == 6 && small[4] == 0 && compare(small, "ws8:") == 0);
    } else if (kind == 4) {
        char byte = 'Q';
        int n = format(&byte, 0, "%s", "abc");
        WS8_CHECK("format_zero_capacity", n == 3 && byte == 'Q');
        n = format(&byte, 1, "%s", "");
        WS8_CHECK("empty_format", n == 0 && byte == 0);
        WS8_CHECK("empty_string", length("") == 0 && compare("", "") == 0);
        void *p = allocate(0);
        /* NULL is a conforming malloc(0) result. The observable obligation is
         * safe release; subsequent real allocation checks allocator liveness. */
        release(p);
        unsigned char *q = allocate(1);
        if (q) q[0] = 73;
        WS8_CHECK("zero_allocation_then_live_allocation", q && q[0] == 73);
        release(q);
    } else {
        uint64_t before = counter(6);
        size_t n = length(NULL);
        uint64_t after = counter(6);
        WS8_CHECK("null_strlen_healed", n == 0 && after > before);
        unsigned char foreign[8] = {17, 18, 19, 20, 21, 22, 23, 24};
        before = counter(4);
        release(foreign);
        after = counter(4);
        int intact = 1;
        for (size_t i = 0; i < 8; i++) if (foreign[i] != 17 + i) intact = 0;
        WS8_CHECK("foreign_free_healed", after > before && intact);
        void *p = allocate(32);
        WS8_CHECK("double_free_allocation", p != NULL);
        if (p) {
            release(p);
            before = counter(3);
            release(p);
            after = counter(3);
            WS8_CHECK("double_free_healed", after > before);
        } else WS8_CHECK("double_free_healed", 0);
    }
    /* Read maps in this process after the workload, never via a shell child.
     * Reject truncation rather than accidentally hiding a late host mapping. */
    char maps[131072];
    FILE *file = fopen("/proc/self/maps", "r");
    size_t used = file ? fread(maps, 1, sizeof(maps) - 1, file) : 0;
    int maps_ok = file && used > 0 && !ferror(file) && feof(file);
    if (file && fclose(file) != 0) maps_ok = 0;
    maps[used] = 0;
    WS8_CHECK("child_maps_complete", maps_ok);
    int ok = 1;
    for (int i = 0; i < count; i++) if (!passed[i]) ok = 0;
    printf("{\"case_id\":"); ws8_json_string(id);
    printf(",\"mode\":"); ws8_json_string(mode);
    printf(",\"checks\":[");
    for (int i = 0; i < count; i++) {
        printf("%s{\"name\":", i ? "," : ""); ws8_json_string(names[i]);
        printf(",\"passed\":%s}", passed[i] ? "true" : "false");
    }
    printf("],\"providers\":[");
    for (size_t i = 0; i < sizeof(symbols) / sizeof(symbols[0]); i++) {
        printf("%s{\"symbol\":", i ? "," : ""); ws8_json_string(symbols[i]);
        printf(",\"address\":\"%p\"}", addresses[i]);
    }
    printf("],\"maps\":"); ws8_json_string(maps);
    printf(",\"status\":\"%s\",\"executed\":%d}\n", ok ? "pass" : "fail", count);
#undef WS8_CHECK
    return ok ? 0 : 1;
}

int main(int argc, char **argv) {
    if (argc == 4 && !strcmp(argv[1], "--ws8-case")) {
        return ws8_probe(argv[2], argv[3]);
    }
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
