/* Hardened mode: a use-after-free through the freed pointer or an interior
 * pointer, while the block is still in the arena's quarantine, is healed by
 * string/memory entry points (memcpy copies nothing, strlen reads nothing).
 * Before, the validator flagged the block but known_remaining discarded the
 * non-live record and fell back to the host-block table, so the access read
 * freed memory.
 *
 * Output is identical everywhere (the smoke gate compares it with glibc); the
 * healing is asserted through the exit status, only under frankenlibc in
 * hardened mode, since glibc and strict perform the (UB) access.
 */
#define _GNU_SOURCE
#include <dlfcn.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int main(void) {
    const char *mode = getenv("FRANKENLIBC_MODE");
    int expect_heal = dlsym(RTLD_DEFAULT, "__frankenlibc_is_runtime_ready") != NULL && mode != NULL &&
                      strcmp(mode, "hardened") == 0;

    char *p = malloc(64);
    if (!p)
        return 1;
    strcpy(p, "hello world, this is a test");
    printf("live: strlen(p)=%zu strlen(p+6)=%zu\n", strlen(p), strlen(p + 6));
    free(p);

    int failures = 0;
    char dst[16];
    memset(dst, 'X', sizeof dst);
    memcpy(dst, p, 10);
    if (expect_heal && (dst[0] != 'X' || strlen(p) != 0)) {
        fprintf(stderr, "base pointer: freed memory was read\n");
        failures++;
    }
    memset(dst, 'X', sizeof dst);
    memcpy(dst, p + 6, 10);
    if (expect_heal && (dst[0] != 'X' || strlen(p + 6) != 0)) {
        fprintf(stderr, "interior pointer: freed memory was read\n");
        failures++;
    }

    /* A live allocation is unaffected. */
    char *q = malloc(32);
    if (!q)
        return 1;
    strcpy(q, "still fine");
    printf("live neighbour: [%s] %zu\n", q, strlen(q));
    free(q);
    return failures ? 1 : 0;
}
