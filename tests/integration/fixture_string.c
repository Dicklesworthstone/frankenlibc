/* fixture_string.c — memcpy/memmove/memset/strlen/strcmp under LD_PRELOAD
 * Part of frankenlibc C fixture suite (bd-3jh).
 * Exit 0 = PASS, nonzero = FAIL with diagnostic to stderr.
 */
#include <stddef.h>
#include <stdio.h>
#include <string.h>
#include <malloc.h>
#include <stdlib.h>
#include <sys/mman.h>
#include <unistd.h>

static int test_memcpy(void) {
    char src[32] = "frankenlibc memcpy test";
    char dst[32] = {0};
    memcpy(dst, src, sizeof(src));
    if (memcmp(dst, src, sizeof(src)) != 0) {
        fprintf(stderr, "FAIL: memcpy content mismatch\n"); return 1;
    }
    return 0;
}

static int test_memmove_nonoverlap(void) {
    char src[16] = "non-overlap!!!!";
    char dst[16] = {0};
    memmove(dst, src, 16);
    if (memcmp(dst, src, 16) != 0) {
        fprintf(stderr, "FAIL: memmove non-overlapping\n"); return 1;
    }
    return 0;
}

static int test_memmove_overlap_forward(void) {
    char buf[32] = "ABCDEFGHIJKLMNOP";
    /* Move bytes 0..8 to bytes 4..12 (overlapping forward) */
    memmove(buf + 4, buf, 8);
    if (memcmp(buf + 4, "ABCDEFGH", 8) != 0) {
        fprintf(stderr, "FAIL: memmove overlap forward\n"); return 1;
    }
    return 0;
}

static int test_memmove_overlap_backward(void) {
    char buf[32] = "ABCDEFGHIJKLMNOP";
    /* Move bytes 4..12 to bytes 0..8 (overlapping backward) */
    memmove(buf, buf + 4, 8);
    if (memcmp(buf, "EFGHIJKL", 8) != 0) {
        fprintf(stderr, "FAIL: memmove overlap backward\n"); return 1;
    }
    return 0;
}

static int test_memset(void) {
    char buf[64];
    memset(buf, 0x42, sizeof(buf));
    for (int i = 0; i < 64; i++) {
        if (buf[i] != 0x42) {
            fprintf(stderr, "FAIL: memset byte %d\n", i); return 1;
        }
    }
    return 0;
}

static int test_strlen(void) {
    if (strlen("") != 0) { fprintf(stderr, "FAIL: strlen empty\n"); return 1; }
    if (strlen("abc") != 3) { fprintf(stderr, "FAIL: strlen 3\n"); return 1; }
    char buf[256];
    memset(buf, 'x', 255);
    buf[255] = '\0';
    if (strlen(buf) != 255) { fprintf(stderr, "FAIL: strlen 255\n"); return 1; }
    return 0;
}

/* strlen must stop at an allocator-tracked bound (bd-k3skh6).
 *
 * This case is only reachable from a preloaded process. The strict fast path is
 * selected by `strict_passthrough_active()`, which is false under `cfg(test)`, so
 * the Rust unit test of the same name exercises the VALIDATING path instead and
 * cannot observe a regression in the strict one — the reason bd-k3skh6 closed
 * with no gate over the mode it was reported against.
 *
 * The buffer is filled to its full usable size with non-NUL bytes and its
 * neighbours are filled the same way, so nothing but the bound can stop the scan:
 * an unbounded scan runs off the end and reports a length far past the allocation.
 */
static int test_strlen_tracked_unterminated_bound(void) {
    int fails = 0;
    int observed = 0;
    for (size_t n = 1; n <= 64; n++) {
        char *before = malloc(64);
        char *p = malloc(n);
        char *after = malloc(64);
        if (before == NULL || p == NULL || after == NULL) {
            fprintf(stderr, "FAIL: strlen bound n=%zu allocation failed\n", n);
            free(before); free(p); free(after);
            return 1;
        }
        memset(before, 'G', 64);
        memset(after, 'G', 64);

        size_t usable = malloc_usable_size(p);
        if (usable < n) {
            /* Not tracked by the allocator under this mode: the bound property has
             * nothing to attach to. Reported, never silently counted as a pass. */
            fprintf(stderr, "SKIP: strlen bound n=%zu untracked (usable=%zu)\n", n, usable);
            free(before); free(p); free(after);
            continue;
        }
        /* Through a volatile pointer: writing the whole USABLE region is exactly
         * what `malloc_usable_size` licenses, but the compiler's object-size
         * analysis only knows the REQUESTED size and turns the fill into an
         * aborting `__memset_chk` at -O2 under _FORTIFY_SOURCE. */
        char *volatile vp = p;
        memset(vp, 'A', usable);
        size_t len = strlen(vp);
        observed++;
        if (len < n || len > usable) {
            fprintf(stderr,
                    "FAIL: strlen tracked unterminated n=%zu usable=%zu -> %zu\n",
                    n, usable, len);
            fails = 1;
        }
        free(before); free(p); free(after);
    }
    if (observed == 0) {
        fprintf(stderr, "FAIL: strlen bound saw no tracked allocation (0 of 64 observed)\n");
        return 1;
    }
    return fails;
}

/* strlen must not read past the terminator into the next page (bd-k3skh6).
 *
 * Two pages are mapped and the second is made PROT_NONE, then a terminated string
 * is placed so that its NUL is the LAST readable byte of the first page. Every
 * start alignment in [0,128] is covered because the string start walks backwards
 * one byte per iteration. The region is not allocator-tracked, so the strict path
 * gets no bound and must rely on the page-safe scanner: a window that reads even
 * one byte past the terminator's page dies with SIGSEGV rather than returning a
 * wrong answer, which is why this is a gate and not an assertion about a value.
 */
static int test_strlen_page_boundary(void) {
    long page = sysconf(_SC_PAGESIZE);
    if (page <= 0) {
        fprintf(stderr, "FAIL: strlen page boundary sysconf(_SC_PAGESIZE)=%ld\n", page);
        return 1;
    }
    size_t ps = (size_t)page;
    char *region = mmap(NULL, ps * 2, PROT_READ | PROT_WRITE,
                        MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (region == MAP_FAILED) {
        fprintf(stderr, "FAIL: strlen page boundary mmap failed\n");
        return 1;
    }
    if (mprotect(region + ps, ps, PROT_NONE) != 0) {
        fprintf(stderr, "FAIL: strlen page boundary mprotect failed\n");
        munmap(region, ps * 2);
        return 1;
    }
    int fails = 0;
    for (size_t len = 0; len <= 128; len++) {
        char *s = region + ps - len - 1;
        memset(s, 'x', len);
        s[len] = '\0';
        size_t got = strlen(s);
        if (got != len) {
            fprintf(stderr, "FAIL: strlen page boundary len=%zu -> %zu\n", len, got);
            fails = 1;
        }
    }
    munmap(region, ps * 2);
    return fails;
}

/* Byte-at-a-time span: the POSIX definition, independent of the library under test. */
static size_t ref_span(const char *s, const char *set, int stop_in_set) {
    size_t i = 0;
    for (; s[i] != '\0'; i++) {
        int member = 0;
        for (const char *c = set; *c != '\0'; c++) {
            if (*c == s[i]) { member = 1; break; }
        }
        if (member == stop_in_set) break;
    }
    return i;
}

/* strspn/strcspn/strpbrk/strtok/strtok_r/strsep over 5..64-byte sets
 * (bd-rc0923-epic-eeuy4f.13).
 *
 * These sets take the SSE4.2 `pcmpistri` probe and the AVX2 PSHUFB classifier.
 * A baseline x86-64 build must select those at run time: run on a CPU without
 * them, an unguarded call is SIGILL. Spans long enough to outrun the probe
 * (hundreds of bytes) and sets on both sides of the 16-byte needle boundary are
 * covered, each checked against `ref_span`. */
static int test_span_long_sets(void) {
    static const char *const sets[] = {
        "abcde",                                                  /* 5 */
        "abcdefghijklmnop",                                       /* 16 */
        "abcdefghijklmnopq",                                      /* 17 */
        "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMN",               /* 40 */
        "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789+/", /* 64 */
    };
    static const size_t spans[] = {0, 3, 31, 100, 700};
    char buf[1024];
    int fails = 0;
    for (size_t si = 0; si < sizeof sets / sizeof sets[0]; si++) {
        const char *set = sets[si];
        size_t set_len = strlen(set);
        for (size_t pi = 0; pi < sizeof spans / sizeof spans[0]; pi++) {
            size_t span = spans[pi];
            /* `span` members (cycling through the set), one non-member, a tail. */
            for (size_t i = 0; i < span; i++) buf[i] = set[i % set_len];
            memcpy(buf + span, "!tail", 6);
            size_t want = ref_span(buf, set, 0);
            size_t got = strspn(buf, set);
            if (got != want || want != span) {
                fprintf(stderr, "FAIL: strspn set=%zu span=%zu -> %zu (want %zu)\n",
                        set_len, span, got, want);
                fails = 1;
            }
            /* The complement: `span` non-members, then a member. */
            for (size_t i = 0; i < span; i++) buf[i] = '.';
            buf[span] = set[set_len - 1];
            buf[span + 1] = '\0';
            want = ref_span(buf, set, 1);
            got = strcspn(buf, set);
            char *hit = strpbrk(buf, set);
            if (got != want || want != span || hit != buf + span) {
                fprintf(stderr, "FAIL: strcspn/strpbrk set=%zu span=%zu -> %zu/%td (want %zu)\n",
                        set_len, span, got, hit ? hit - buf : (ptrdiff_t)-1, want);
                fails = 1;
            }
            /* Tokenizers: delimiters around a `span`-byte token of non-members. */
            if (span == 0) continue;
            memcpy(buf, set, 3);
            for (size_t i = 0; i < span; i++) buf[3 + i] = '.';
            memcpy(buf + 3 + span, set, set_len);
            buf[3 + span + set_len] = '\0';
            char copy[1024];
            memcpy(copy, buf, sizeof copy);
            char *save = NULL;
            char *tok = strtok_r(copy, set, &save);
            if (tok != copy + 3 || strlen(tok) != span || strtok_r(NULL, set, &save) != NULL) {
                fprintf(stderr, "FAIL: strtok_r set=%zu span=%zu\n", set_len, span);
                fails = 1;
            }
            memcpy(copy, buf, sizeof copy);
            tok = strtok(copy, set);
            if (tok != copy + 3 || strlen(tok) != span || strtok(NULL, set) != NULL) {
                fprintf(stderr, "FAIL: strtok set=%zu span=%zu\n", set_len, span);
                fails = 1;
            }
            memcpy(copy, buf, sizeof copy);
            char *cursor = copy + 3;
            tok = strsep(&cursor, set);
            if (tok != copy + 3 || strlen(tok) != span || cursor != copy + 4 + span) {
                fprintf(stderr, "FAIL: strsep set=%zu span=%zu\n", set_len, span);
                fails = 1;
            }
        }
    }
    return fails;
}

static int test_strcmp(void) {
    if (strcmp("abc", "abc") != 0) { fprintf(stderr, "FAIL: strcmp equal\n"); return 1; }
    if (strcmp("abc", "abd") >= 0) { fprintf(stderr, "FAIL: strcmp less\n"); return 1; }
    if (strcmp("abd", "abc") <= 0) { fprintf(stderr, "FAIL: strcmp greater\n"); return 1; }
    if (strcmp("", "") != 0) { fprintf(stderr, "FAIL: strcmp empty\n"); return 1; }
    return 0;
}

int main(void) {
    int fails = 0;
    fails += test_memcpy();
    fails += test_memmove_nonoverlap();
    fails += test_memmove_overlap_forward();
    fails += test_memmove_overlap_backward();
    fails += test_memset();
    fails += test_strlen();
    fails += test_strlen_tracked_unterminated_bound();
    fails += test_strlen_page_boundary();
    fails += test_strcmp();
    fails += test_span_long_sets();

    if (fails) {
        fprintf(stderr, "fixture_string: %d FAILED\n", fails);
        return 1;
    }
    printf("fixture_string: PASS (10 tests)\n");
    return 0;
}
