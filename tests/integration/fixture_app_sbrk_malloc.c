/* An application that supplies its own sbrk-based malloc (as bash does with
 * its bundled lib/malloc) must get fresh memory from sbrk.
 *
 * fl cached the program break inside sbrk, but the host allocator behind
 * fl's native paths moves the break with its own brk calls; sbrk then handed
 * the application memory the host heap already owned, and the two heaps
 * overwrote each other (bash 5.2 built from source segfaulted in its first
 * getenv, its environ array clobbered). Output matches glibc.
 */
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

/* A minimal sbrk heap: 16-byte header holding the size, never reused. */
void *malloc(size_t n) {
    size_t total = (n + 16 + 15) & ~(size_t)15;
    char *p = sbrk((intptr_t)total);
    if (p == (char *)-1) {
        return NULL;
    }
    *(size_t *)p = n;
    return p + 16;
}
void free(void *p) { (void)p; }
void *calloc(size_t a, size_t b) {
    void *p = malloc(a * b);
    if (p) {
        memset(p, 0, a * b);
    }
    return p;
}
void *realloc(void *p, size_t n) {
    void *q = malloc(n);
    if (p && q) {
        size_t old = *(size_t *)((char *)p - 16);
        memcpy(q, p, old < n ? old : n);
    }
    return q;
}

int main(void) {
    enum { N = 400 };
    static char *blocks[N];
    for (int i = 0; i < N; i++) {
        blocks[i] = malloc(200 + i);
        memset(blocks[i], 'A' + i % 26, 200 + i);
        /* libc work that allocates inside fl on every iteration */
        char buf[64];
        snprintf(buf, sizeof buf, "FIXTURE_VAR_%d", i);
        setenv(buf, "some value that is long enough to need memory", 1);
        char *d = strdup(buf);
        if (getenv(buf) == NULL || d == NULL) {
            puts("lost an environment variable");
            return 1;
        }
    }
    int bad = 0;
    for (int i = 0; i < N; i++) {
        for (int j = 0; j < 200 + i; j++) {
            bad += blocks[i][j] != 'A' + i % 26;
        }
    }
    int env_ok = 0;
    for (int i = 0; i < N; i++) {
        char buf[64];
        snprintf(buf, sizeof buf, "FIXTURE_VAR_%d", i);
        env_ok += getenv(buf) != NULL;
    }
    printf("clobbered bytes=%d env vars=%d/%d\n", bad, env_ok, N);
    return bad != 0 || env_ok != N;
}
