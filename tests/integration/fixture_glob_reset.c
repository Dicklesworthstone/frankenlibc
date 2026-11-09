/* glob() resets the glob_t on every return, so globfree() is always safe.
 *
 * GNU make's parse_file_seq globs into an uninitialized stack glob_t and calls
 * globfree() whatever glob returned. fl left gl_pathv untouched on
 * GLOB_NOMATCH, so globfree freed stack garbage and make aborted with
 * "free(): invalid pointer" (any Makefile using $(wildcard) of a missing
 * file). Output matches glibc.
 */
#define _GNU_SOURCE
#include <dlfcn.h>
#include <errno.h>
#include <glob.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

/* The first four members are the common initial sequence of these two GNU
 * structs. Keep the actual selected object type for the public calls. */
union glob_state {
    glob_t normal;
    glob64_t large;
};

static int call_glob(int large, const char *pattern, int flags, union glob_state *state) {
    return large ? glob64(pattern, flags, NULL, &state->large) :
                   glob(pattern, flags, NULL, &state->normal);
}

static void release_glob(int large, union glob_state *state) {
    if (large) globfree64(&state->large);
    else globfree(&state->normal);
}

static int check_glob_providers(const char *expected) {
    const char *names[] = {"glob", "globfree", "glob64", "globfree64"};
    for (size_t i = 0; i < sizeof(names) / sizeof(names[0]); ++i) {
        void *symbol = dlsym(RTLD_DEFAULT, names[i]);
        Dl_info info;
        if (!symbol || !dladdr(symbol, &info) || !info.dli_fname ||
            strcmp(info.dli_fname, expected)) {
            fprintf(stderr, "FAIL: wrong glob provider for %s\n", names[i]);
            return 2;
        }
    }
    return 0;
}

static int append_vector_matches(const union glob_state *state, size_t offset,
                                 size_t count, const char *const *words,
                                 char *const *previous, size_t previous_count) {
    const glob_t *g = &state->normal;
    if (g->gl_pathc != count || g->gl_offs != offset ||
        ((count || offset) && !g->gl_pathv)) return 0;
    if (!g->gl_pathv) return count == 0;
    for (size_t i = 0; i < offset; ++i)
        if (g->gl_pathv[i]) return 0;
    /* Do not dereference a corrupted prior slot in a rejected old library.
     * GNU retains the pathname allocations even when it moves the vector. */
    for (size_t i = 0; i < previous_count; ++i)
        if (memcmp(&g->gl_pathv[offset + i], &previous[i], sizeof(char *))) return 0;
    for (size_t i = 0; i < count; ++i)
        if (!g->gl_pathv[offset + i] || strcmp(g->gl_pathv[offset + i], words[i])) return 0;
    return g->gl_pathv[offset + count] == NULL;
}

static int test_append_offsets(int large, size_t offset, int initial_nomatch) {
    static const char *const words[] = {
        "glob-offset-z", "glob-offset-b", "glob-offset-a", "glob-offset-z"
    };
    union glob_state state = {0};
    state.normal.gl_offs = offset;
    char *previous[4] = {0};
    size_t previous_count = 0;
    int bad = 0, stage = 0;
    if (initial_nomatch) {
        bad = call_glob(large, "", GLOB_DOOFFS, &state) != GLOB_NOMATCH ||
              !append_vector_matches(&state, offset, 0, words, previous, 0);
        if (bad) goto done;
    }
    for (size_t i = 0; i < sizeof(words) / sizeof(words[0]); ++i) {
        stage = (int)i + 1;
        int flags = GLOB_DOOFFS | GLOB_NOCHECK;
        if (i || initial_nomatch) flags |= GLOB_APPEND;
        bad = call_glob(large, words[i], flags, &state) != 0 ||
              !append_vector_matches(&state, offset, i + 1, words, previous, previous_count);
        if (bad) goto done;
        for (size_t j = 0; j <= i; ++j) previous[j] = state.normal.gl_pathv[offset + j];
        previous_count = i + 1;

        /* An unsuccessful append must leave the accumulated vector usable,
         * including its reserved prefix and terminal null pointer. */
        bad = call_glob(large, "", GLOB_DOOFFS | GLOB_APPEND, &state) != GLOB_NOMATCH ||
              !append_vector_matches(&state, offset, i + 1, words, previous, previous_count);
        if (bad) goto done;
    }
done:
    if (!bad) release_glob(large, &state);
    /* A rejected old implementation may return uninitialized pointer slots;
     * do not pass its corrupt result to globfree after detecting that defect. */
    printf("append api=glob%s offset=%zu initial_nomatch=%d stage=%d result=%s\n",
           large ? "64" : "", offset, initial_nomatch, stage, bad ? "FAIL" : "PASS");
    return bad;
}

static int test_offset_overflow(int large, size_t index) {
    const size_t offsets[] = {
        SIZE_MAX, SIZE_MAX / sizeof(char *), SIZE_MAX / sizeof(char *) + 1,
        (size_t)PTRDIFF_MAX / sizeof(char *)
    };
    union glob_state state = {0};
    state.normal.gl_offs = offsets[index];
    errno = EDOM;
    int result = call_glob(large, "glob-offset-overflow", GLOB_DOOFFS | GLOB_NOCHECK, &state);
    int saved_errno = errno;
    int bad = result != GLOB_NOSPACE || state.normal.gl_pathc || state.normal.gl_pathv ||
              state.normal.gl_offs != offsets[index] || saved_errno != (index == 3 ? ENOMEM : EDOM);
    if (!bad) release_glob(large, &state);
    printf("overflow api=glob%s index=%zu result=%d errno=%d pass=%d\n",
           large ? "64" : "", index, result, saved_errno, !bad);
    return bad;
}

int main(int argc, char **argv) {
    int append_only = 0;
    const char *expected_provider = NULL;
    for (int i = 1; i < argc; ++i) {
        if (!strcmp(argv[i], "--append-only")) append_only = 1;
        else if (!expected_provider) expected_provider = argv[i];
        else return 2;
    }
    if (expected_provider && check_glob_providers(expected_provider)) return 2;

    glob_t g;
    memset(&g, 0xA5, sizeof g); /* what an uninitialized stack slot holds */
    int rc = glob("/nonexistent-dir-xyz/*.none", 0, NULL, &g);
    printf("nomatch rc=%d pathc=%zu pathv=%s\n", rc, g.gl_pathc, g.gl_pathv ? "set" : "NULL");
    globfree(&g);

    memset(&g, 0xA5, sizeof g);
    g.gl_offs = 2;
    rc = glob("/nonexistent-dir-xyz/*.none", GLOB_DOOFFS, NULL, &g);
    printf("dooffs nomatch rc=%d pathc=%zu slots=%s,%s,%s\n", rc, g.gl_pathc,
           g.gl_pathv && !g.gl_pathv[0] ? "null" : "?", g.gl_pathv && !g.gl_pathv[1] ? "null" : "?",
           g.gl_pathv && !g.gl_pathv[2] ? "null" : "?");
    globfree(&g);

    memset(&g, 0xA5, sizeof g);
    rc = glob("/etc/host*", 0, NULL, &g);
    printf("match rc=%d any=%d first=%s\n", rc, g.gl_pathc > 0, g.gl_pathc ? g.gl_pathv[0] : "");
    rc = glob("/nonexistent-dir-xyz/*", GLOB_APPEND, NULL, &g);
    printf("append nomatch rc=%d kept=%d\n", rc, g.gl_pathc > 0);
    globfree(&g);

    int failed = 0, cases = 0;
    const size_t offsets[] = {0, 1, 2, 8};
    for (int large = 0; large <= 1; ++large)
        for (size_t i = 0; i < sizeof(offsets) / sizeof(offsets[0]); ++i)
            for (int initial_nomatch = 0; initial_nomatch <= 1; ++initial_nomatch) {
                failed += test_append_offsets(large, offsets[i], initial_nomatch);
                ++cases;
            }
    if (!append_only)
        for (int large = 0; large <= 1; ++large)
            for (size_t i = 0; i < 4; ++i) {
                failed += test_offset_overflow(large, i);
                ++cases;
            }
    printf("fixture_glob_reset: %s (%d cases, %d failed)\n",
           failed ? "FAIL" : "PASS", cases, failed);
    return failed != 0;
}
