/* fixture_hardened_first_heal.c — first heal of a hardened process must not
 * deadlock (bd-rc0923-epic-eeuy4f.9).
 *
 * The global healing policy is a lazily initialized object. Its constructor
 * used to read FRANKENLIBC_HEAL_LOG through Rust's std::env::var, which calls
 * FrankenLibC's own exported memcpy; hardened memcpy records a heal through the
 * same, still-initializing policy, and the process blocked forever inside the
 * very first memchr/memcpy that healed. Output is deterministic and matches
 * host glibc, so the preload smoke battery can require byte parity.
 */
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int main(void) {
    char *b = malloc(120);
    if (b == NULL) return 1;
    memset(b, 'z', 120);
    memcpy(b, "alpha one\n", 10);
    long sum = 0;
    for (size_t n = 1; n <= 120; n += 7) {
        char *p = memchr(b, 'a', n), *q = memrchr(b, 'a', n), *r = memchr(b, '\n', n);
        sum += (p ? p - b : -1) + (q ? q - b : -1) + (r ? r - b : -1);
    }
    printf("fixture_hardened_first_heal: sum=%ld\n", sum);
    free(b);
    return 0;
}
