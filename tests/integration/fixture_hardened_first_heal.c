/* fixture_hardened_first_heal.c — first heal of a hardened process must not
 * deadlock (bd-rc0923-epic-eeuy4f.9).
 *
 * The global healing policy is a lazily initialized object. Its constructor
 * used to read FRANKENLIBC_HEAL_LOG through Rust's std::env::var, which calls
 * FrankenLibC's own exported memcpy; hardened memcpy records a heal through the
 * same, still-initializing policy, and the process blocked forever inside the
 * very first memchr/memcpy that healed. The bounded memcpy below deliberately
 * requests more bytes than its two tracked allocations contain, making that
 * first repair deterministic. Host glibc and strict mode skip the deliberately
 * invalid call, so output remains byte-identical in the preload smoke battery.
 * The invalid kill also gives the runtime-log gate one deterministic semantic
 * denial without sending a signal or changing the fixture's output.
 */
#define _GNU_SOURCE
#include <errno.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

extern int __frankenlibc_is_runtime_ready(void) __attribute__((weak));

static int induce_hardened_bounds_repair(void) {
    const char *mode = getenv("FRANKENLIBC_MODE");
    if (!__frankenlibc_is_runtime_ready || !__frankenlibc_is_runtime_ready() || mode == NULL ||
        strcmp(mode, "hardened") != 0)
        return 0;

    unsigned char *src = malloc(8), *dst = malloc(8);
    if (src == NULL || dst == NULL) {
        free(src);
        free(dst);
        return 3;
    }
    memset(src, 'R', 8);
    memset(dst, 0, 8);

    /* Prevent the compiler from replacing this test of the interposed ABI
     * entrypoint with an inline builtin copy. */
    void *(*volatile copy_fn)(void *, const void *, size_t) = memcpy;
    void *ret = copy_fn(dst, src, 32);
    int failed = ret != dst;
    for (size_t i = 0; i < 8; i++)
        failed |= dst[i] != 'R';
    free(dst);
    free(src);
    return failed ? 4 : 0;
}

int main(void) {
    int repair_rc = induce_hardened_bounds_repair();
    if (repair_rc != 0)
        return repair_rc;

    char *b = malloc(120);
    if (b == NULL) return 1;
    memset(b, 'z', 120);
    memcpy(b, "alpha one\n", 10);
    long sum = 0;
    for (size_t n = 1; n <= 120; n += 7) {
        char *p = memchr(b, 'a', n), *q = memrchr(b, 'a', n), *r = memchr(b, '\n', n);
        sum += (p ? p - b : -1) + (q ? q - b : -1) + (r ? r - b : -1);
    }
    errno = 0;
    if (kill(getpid(), -1) != -1 || errno != EINVAL)
        return 2;
    printf("fixture_hardened_first_heal: sum=%ld\n", sum);
    free(b);
    return 0;
}
