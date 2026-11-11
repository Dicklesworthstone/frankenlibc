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
#include <unistd.h>
#include <sys/wait.h>
#if defined(__linux__)
#include <sys/personality.h>
#endif

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

static uint64_t raw_read_u64_le(const volatile unsigned char *src) {
    uint64_t val = 0;
    for (size_t i = 0; i < 8; i++) {
        val |= ((uint64_t)src[i]) << (8 * i);
    }
    return val;
}

static void raw_write_u64_le(volatile unsigned char *dst, uint64_t val) {
    for (size_t i = 0; i < 8; i++) {
        dst[i] = (unsigned char)((val >> (8 * i)) & 0xFFU);
    }
}

static int print_canary_hex(const char *library) {
    const char *mode = getenv("FRANKENLIBC_MODE");
    if (!mode || strcmp(mode, "hardened") != 0) return 2;
    void *(*allocate)(size_t) = probe_symbol("malloc", library);
    void (*release)(void *) = probe_symbol("free", library);
    int (*ready)(void) = probe_symbol("__frankenlibc_is_runtime_ready", library);
    if (!allocate || !release || !ready || !ready()) return 2;
    unsigned char *p = allocate(32);
    if (!p) return 2;
    uint64_t hash = raw_read_u64_le((const volatile unsigned char *)(p - 24));
    uint64_t canary = raw_read_u64_le((const volatile unsigned char *)(p + 32));
    release(p);
    printf("%p:%016llx:%016llx\n", (void *)p, (unsigned long long)hash, (unsigned long long)canary);
    fflush(stdout);
    return 0;
}

static int capture_exec_canary(const char *library, uintptr_t *out_addr, uint64_t *out_hash, uint64_t *out_canary) {
    int pipefd[2];
    if (pipe(pipefd) != 0) return -1;
    pid_t pid = fork();
    if (pid < 0) {
        close(pipefd[0]);
        close(pipefd[1]);
        return -1;
    }
    if (pid == 0) {
        close(pipefd[0]);
        if (dup2(pipefd[1], STDOUT_FILENO) < 0) _exit(126);
        close(pipefd[1]);
#if defined(__linux__) && defined(ADDR_NO_RANDOMIZE)
        int pers = personality(0xffffffffUL);
        if (pers != -1) {
            (void)personality((unsigned long)pers | ADDR_NO_RANDOMIZE);
        }
#endif
        execl("/proc/self/exe", "/proc/self/exe", "--print-canary-hex", library, (char *)NULL);
        _exit(127);
    }
    close(pipefd[1]);
    char buf[128];
    size_t total = 0;
    while (total + 1 < sizeof(buf)) {
        ssize_t n = read(pipefd[0], buf + total, sizeof(buf) - 1 - total);
        if (n <= 0) break;
        total += (size_t)n;
    }
    buf[total] = '\0';
    close(pipefd[0]);
    int status = 0;
    if (waitpid(pid, &status, 0) < 0 || !WIFEXITED(status) || WEXITSTATUS(status) != 0) {
        return -1;
    }
    void *parsed_ptr = NULL;
    unsigned long long parsed_hash = 0, parsed_canary = 0;
    if (sscanf(buf, "%p:%llx:%llx", &parsed_ptr, &parsed_hash, &parsed_canary) != 3) {
        return -1;
    }
    *out_addr = (uintptr_t)parsed_ptr;
    *out_hash = (uint64_t)parsed_hash;
    *out_canary = (uint64_t)parsed_canary;
    return 0;
}

static int canary_probe(const char *id, const char *library) {
    const char *mode = getenv("FRANKENLIBC_MODE");
    if (!mode || (strcmp(mode, "strict") && strcmp(mode, "hardened"))) return 2;
    int hardened = strcmp(mode, "hardened") == 0;
    int kind = !strcmp(id, "intact") ? 1 :
               !strcmp(id, "corrupt-legacy-fold") ? 2 :
               !strcmp(id, "corrupt-symmetric-pair") ? 3 :
               !strcmp(id, "corrupt-header") ? 4 :
               !strcmp(id, "corrupt-after-warm-tls-write") ? 5 :
               !strcmp(id, "corrupt-header-after-warm-tls") ? 6 :
               !strcmp(id, "fork-preserves-canary-exec-reseeds") ? 7 : 0;
    if (!kind || (kind > 1 && !hardened)) return 2;

    const char *symbols[] = {"malloc", "free", "mprobe", "memcpy", "strlen",
        "__frankenlibc_healing_action_count", "__frankenlibc_is_runtime_ready"};
    void *addresses[sizeof(symbols) / sizeof(symbols[0])];
    for (size_t i = 0; i < sizeof(symbols) / sizeof(symbols[0]); i++) {
        addresses[i] = probe_symbol(symbols[i], library);
        if (!addresses[i]) return 2;
    }
    void *(*allocate)(size_t) = addresses[0];
    void (*release)(void *) = addresses[1];
    int (*probe)(void *) = addresses[2];
    void *(*copy)(void *, const void *, size_t) = addresses[3];
    size_t (*str_len)(const char *) = addresses[4];
    uint64_t (*counter)(unsigned) = addresses[5];
    int (*ready)(void) = addresses[6];

    const char *names[32];
    int passed[32], count = 0;
#define CANARY_CHECK(name, outcome) do { names[count] = (name); passed[count++] = !!(outcome); } while (0)
    CANARY_CHECK("runtime_ready", ready());

    size_t capacity = 32;
    unsigned char *p = allocate(capacity);
    CANARY_CHECK("allocation_non_null", p != NULL);
    uint64_t gen = 0, sz = 0, hash = 0, canary_word = 0, forged_xor_canary = 0, legacy_canary = 0;
    uint64_t clamp_before = 0, clamp_after = 0;
    int mprobe_initial = -1, mprobe_mutated = -1, mprobe_freed = -1;
    int already_released = 0;

    if (p) {
        for (size_t i = 0; i < capacity; i++) ((volatile unsigned char *)p)[i] = (unsigned char)(0xA0 + i);
        mprobe_initial = probe(p);
        CANARY_CHECK("mprobe_initial_ok", mprobe_initial == 0);

        if (hardened) {
            /* Direct volatile byte reads bypass interposed memcpy, which would
             * clamp redzone reads at p - 24 and p + capacity to 0 bytes. */
            hash = raw_read_u64_le((const volatile unsigned char *)(p - 24));
            gen = raw_read_u64_le((const volatile unsigned char *)(p - 16));
            sz = raw_read_u64_le((const volatile unsigned char *)(p - 8));
            canary_word = raw_read_u64_le((const volatile unsigned char *)(p + capacity));
            forged_xor_canary = hash ^ 0xDEADBEEFCAFEBABEULL;
            uint64_t rot = (hash << 32) | (hash >> 32);
            legacy_canary = (hash ^ rot) ^ 0xDEADBEEFCAFEBABEULL;

            CANARY_CHECK("header_layout_24b", gen > 0 && sz == capacity && hash != 0 && canary_word != 0);
            CANARY_CHECK("tail_domain_separated_from_header", canary_word != forged_xor_canary);
            CANARY_CHECK("tail_not_legacy_fold", rot == 0 || canary_word != legacy_canary);

            if (kind == 1) {
                clamp_before = counter(1);
                copy(p, "ABCDEFGH", 8);
                clamp_after = counter(1);
                CANARY_CHECK("memcpy_intact_allowed",
                    clamp_after == clamp_before && ((volatile unsigned char *)p)[0] == 'A');
            } else if (kind == 2) {
                /* Forged header-XOR canary must be rejected under K_tail != K_hdr. */
                raw_write_u64_le((volatile unsigned char *)(p + capacity), forged_xor_canary);
                CANARY_CHECK("mprobe_detects_header_xor_forged_tail", probe(p) == 3);
                clamp_before = counter(1);
                copy(p, "YYYYYYYY", 8);
                clamp_after = counter(1);
                CANARY_CHECK("membrane_rejects_header_xor_forged_canary",
                    clamp_after > clamp_before && ((volatile unsigned char *)p)[0] == 0xA0);

                uint64_t replacement = (rot != 0) ? legacy_canary : (canary_word ^ 1ULL);
                raw_write_u64_le((volatile unsigned char *)(p + capacity), replacement);
                mprobe_mutated = probe(p);
                CANARY_CHECK("mprobe_detects_legacy_fold_tail", mprobe_mutated == 3);
                clamp_before = counter(1);
                copy(p, "ZZZZZZZZ", 8);
                clamp_after = counter(1);
                CANARY_CHECK("membrane_rejects_legacy_fold_canary",
                    clamp_after > clamp_before && ((volatile unsigned char *)p)[0] == 0xA0);
            } else if (kind == 3) {
                uint64_t mask = (1ULL << 7) | (1ULL << 39);
                uint64_t replacement = canary_word ^ mask;
                raw_write_u64_le((volatile unsigned char *)(p + capacity), replacement);
                mprobe_mutated = probe(p);
                CANARY_CHECK("mprobe_detects_symmetric_pair_tail", mprobe_mutated == 3);
                clamp_before = counter(1);
                copy(p, "ZZZZZZZZ", 8);
                clamp_after = counter(1);
                CANARY_CHECK("membrane_rejects_symmetric_pair_canary",
                    clamp_after > clamp_before && ((volatile unsigned char *)p)[0] == 0xA0);
            } else if (kind == 4) {
                volatile unsigned char *hdr_byte = (volatile unsigned char *)(p - 24);
                unsigned char saved = *hdr_byte;
                *hdr_byte = (unsigned char)(saved ^ 0x80U);
                mprobe_mutated = probe(p);
                CANARY_CHECK("mprobe_detects_header_corruption", mprobe_mutated == 2);
                clamp_before = counter(1);
                copy(p, "ZZZZZZZZ", 8);
                clamp_after = counter(1);
                CANARY_CHECK("membrane_rejects_corrupted_header",
                    clamp_after > clamp_before && ((volatile unsigned char *)p)[0] == 0xA0);
                *hdr_byte = saved;
                CANARY_CHECK("mprobe_restored_ok", probe(p) == 0);
            } else if (kind == 5) {
                /* Warm TLS_CACHE via strlen + two intact memcpy hits. */
                ((volatile unsigned char *)p)[0] = 'W';
                ((volatile unsigned char *)p)[7] = '\0';
                size_t warm_len = str_len((const char *)p);
                clamp_before = counter(1);
                copy(p, "WARM1234", 8);
                copy(p, "WARM5678", 8);
                clamp_after = counter(1);
                CANARY_CHECK("warm_tls_initial_write_ok",
                    warm_len >= 1 && clamp_after == clamp_before &&
                    ((volatile unsigned char *)p)[0] == 'W' &&
                    ((volatile unsigned char *)p)[4] == '5');

                /* Flip 1 bit in the trailing canary AFTER TLS_CACHE is warm,
                 * and immediately write without calling mprobe first. */
                raw_write_u64_le((volatile unsigned char *)(p + capacity), canary_word ^ 1ULL);
                clamp_before = counter(1);
                copy(p, "ZZZZZZZZ", 8);
                clamp_after = counter(1);
                CANARY_CHECK("warm_tls_write_detects_tail_canary_and_clamps",
                    clamp_after > clamp_before &&
                    ((volatile unsigned char *)p)[0] == 'W' &&
                    ((volatile unsigned char *)p)[4] == '5');
                mprobe_mutated = probe(p);
                CANARY_CHECK("mprobe_confirms_tail_corruption", mprobe_mutated == 3);

                /* Near-tail write on 256B allocation (rem = 56 <= 64) catches immediately,
                 * and 1-in-16 cadence catches front-of-buffer writes (rem = 256 > 64). */
                unsigned char *big_tail = allocate(256);
                unsigned char *big_cadence = allocate(256);
                if (big_tail && big_cadence) {
                    copy(big_tail, "WARMBIG!", 8);
                    copy(big_tail, "WARMBIG2", 8);
                    uint64_t big_tail_canary = raw_read_u64_le((const volatile unsigned char *)(big_tail + 256));
                    raw_write_u64_le((volatile unsigned char *)(big_tail + 256), big_tail_canary ^ 1ULL);
                    uint64_t bt_before = counter(1);
                    ((volatile unsigned char *)big_tail)[200] = 'K';
                    copy(big_tail + 200, "ZZZZZZZZ", 8);
                    uint64_t bt_after = counter(1);
                    CANARY_CHECK("warm_tls_near_tail_256b_immediate_clamp",
                        bt_after > bt_before && ((volatile unsigned char *)big_tail)[200] == 'K');
                    raw_write_u64_le((volatile unsigned char *)(big_tail + 256), big_tail_canary);
                    release(big_tail);

                    copy(big_cadence, "CADENCE1", 8);
                    copy(big_cadence, "CADENCE2", 8);
                    uint64_t big_cad_canary = raw_read_u64_le((const volatile unsigned char *)(big_cadence + 256));
                    raw_write_u64_le((volatile unsigned char *)(big_cadence + 256), big_cad_canary ^ 1ULL);
                    uint64_t bc_before = counter(1);
                    int cadence_detected = 0;
                    for (int step = 0; step < 16; step++) {
                        copy(big_cadence, "X", 1);
                        if (counter(1) > bc_before) {
                            cadence_detected = 1;
                            break;
                        }
                    }
                    CANARY_CHECK("warm_tls_cadence_1_in_16_detects_front_write", cadence_detected);
                    raw_write_u64_le((volatile unsigned char *)(big_cadence + 256), big_cad_canary);
                    release(big_cadence);
                } else {
                    CANARY_CHECK("warm_tls_256b_allocations_non_null", 0);
                    if (big_tail) release(big_tail);
                    if (big_cadence) release(big_cadence);
                }

                /* Freeing p with corrupted tail canary must emit structured heal audit. */
                uint64_t free_clamp_before = counter(1);
                release(p);
                uint64_t free_clamp_after = counter(1);
                already_released = 1;
                mprobe_freed = probe(p);
                CANARY_CHECK("free_corrupted_canary_records_heal_event",
                    free_clamp_after > free_clamp_before);
                CANARY_CHECK("mprobe_after_free", mprobe_freed == 1);
            } else if (kind == 6) {
                /* Warm TLS_CACHE, then corrupt 1 bit in 24B pre-user header. */
                copy(p, "WARM1234", 8);
                copy(p, "WARM5678", 8);
                volatile unsigned char *hdr_byte = (volatile unsigned char *)(p - 24);
                unsigned char saved = *hdr_byte;
                *hdr_byte = (unsigned char)(saved ^ 0x80U);
                clamp_before = counter(1);
                copy(p, "ZZZZZZZZ", 8);
                clamp_after = counter(1);
                CANARY_CHECK("warm_tls_detects_corrupted_header_and_clamps",
                    clamp_after > clamp_before &&
                    ((volatile unsigned char *)p)[0] == 'W' &&
                    ((volatile unsigned char *)p)[4] == '5');
                mprobe_mutated = probe(p);
                CANARY_CHECK("mprobe_detects_warm_header_corruption", mprobe_mutated == 2);
                *hdr_byte = saved;
                CANARY_CHECK("mprobe_restored_ok", probe(p) == 0);
            } else if (kind == 7) {
                /* fork() child must inherit (K_hdr, K_tail); execve() must re-seed via OS CSPRNG. */
                copy(p, "PARENTOK", 8);
                pid_t pid = fork();
                if (pid == 0) {
                    int child_probe_ok = (probe(p) == 0);
                    uint64_t c_before = counter(1);
                    copy(p, "CHILDOK!", 8);
                    uint64_t c_after = counter(1);
                    unsigned char *cp = allocate(32);
                    int cp_ok = (cp != NULL && probe(cp) == 0);
                    if (cp) release(cp);
                    release(p);
                    int child_ok = child_probe_ok && cp_ok &&
                                   (c_after == c_before) &&
                                   (((volatile unsigned char *)p)[0] == 'C');
                    _exit(child_ok ? 0 : 1);
                }
                int fork_status = 0;
                int waited = (pid > 0 && waitpid(pid, &fork_status, 0) == pid);
                CANARY_CHECK("fork_child_inherits_dual_keys",
                    waited && WIFEXITED(fork_status) && WEXITSTATUS(fork_status) == 0);
                CANARY_CHECK("parent_canary_intact_after_fork",
                    probe(p) == 0 && ((volatile unsigned char *)p)[0] == 'P');

                uintptr_t exec_addr_1 = 0, exec_addr_2 = 0;
                uint64_t exec_hash_1 = 0, exec_canary_1 = 0;
                uint64_t exec_hash_2 = 0, exec_canary_2 = 0;
                int rc1 = capture_exec_canary(library, &exec_addr_1, &exec_hash_1, &exec_canary_1);
                int rc2 = capture_exec_canary(library, &exec_addr_2, &exec_hash_2, &exec_canary_2);
                CANARY_CHECK("exec_reseed_probes_succeeded",
                    rc1 == 0 && rc2 == 0 && exec_addr_1 != 0 && exec_addr_2 != 0 &&
                    exec_canary_1 != 0 && exec_canary_2 != 0);
                CANARY_CHECK("exec_reseeds_independent_keys_across_fresh_processes",
                    exec_hash_1 != exec_hash_2 && exec_canary_1 != exec_canary_2 &&
                    exec_canary_1 != canary_word && exec_canary_2 != canary_word);
            }
        }

        if (!already_released) {
            release(p);
            mprobe_freed = probe(p);
            CANARY_CHECK("mprobe_after_free", mprobe_freed == 1);
        }
    }

    int ok = 1;
    for (int i = 0; i < count; i++) if (!passed[i]) ok = 0;
    printf("{\"case_id\":"); ws8_json_string(id);
    printf(",\"mode\":"); ws8_json_string(mode);
    printf(",\"header_generation\":%llu,\"header_size\":%llu",
           (unsigned long long)gen, (unsigned long long)sz);
    printf(",\"mprobe_initial\":%d,\"mprobe_mutated\":%d,\"mprobe_freed\":%d",
           mprobe_initial, mprobe_mutated, mprobe_freed);
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
    printf("],\"status\":\"%s\",\"executed\":%d}\n", ok ? "pass" : "fail", count);
#undef CANARY_CHECK
    return ok ? 0 : 1;
}

int main(int argc, char **argv) {
    if (argc == 3 && !strcmp(argv[1], "--print-canary-hex")) {
        return print_canary_hex(argv[2]);
    }
    if (argc == 4 && !strcmp(argv[1], "--ws8-case")) {
        return ws8_probe(argv[2], argv[3]);
    }
    if (argc == 4 && !strcmp(argv[1], "--healing-case")) {
        return healing_probe(argv[2], argv[3]);
    }
    if (argc == 4 && !strcmp(argv[1], "--canary-case")) {
        return canary_probe(argv[2], argv[3]);
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
