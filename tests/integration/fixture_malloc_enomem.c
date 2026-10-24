/* Every failed allocation leaves errno == ENOMEM, as glibc does. fl returned
 * NULL with errno untouched (requests above PTRDIFF_MAX never reached a check;
 * host-allocator failures set glibc's internal errno, not the application's),
 * failing gnulib's test-malloc-gnu, test-calloc-gnu, test-realloc-gnu and
 * test-reallocarray (sed 4.9 gnulib-tests). Also: aligned_alloc accepts a size
 * that is not a multiple of the alignment. Output matches glibc.
 */
#define _GNU_SOURCE
#include <errno.h>
#include <malloc.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>

#define CHECK(label, expr)                                                     \
    do {                                                                       \
        errno = 0;                                                             \
        void *volatile p_ = (expr);                                            \
        printf("%-18s null=%d errno=%d\n", label, p_ == NULL, errno);          \
    } while (0)

int main(int argc, char **argv) {
    (void)argv;
    size_t one = argc != 12345; /* defeat constant folding */
    size_t big = PTRDIFF_MAX + one;
    CHECK("malloc", malloc(big));
    CHECK("malloc SIZE_MAX", malloc(SIZE_MAX * one));
    CHECK("calloc", calloc(PTRDIFF_MAX / 2 + 1, 2 * one));
    CHECK("calloc overflow", calloc(SIZE_MAX / 2 + 1, 2 * one));
    void *q = malloc(10);
    CHECK("realloc", realloc(q, big));
    CHECK("reallocarray", reallocarray(q, PTRDIFF_MAX / 2 + 1, 2 * one));
    CHECK("aligned_alloc", aligned_alloc(64, big - 63));
    void *a = aligned_alloc(64 * one, 100);
    printf("%-18s ok=%d\n", "aligned_alloc 100", a != NULL && (size_t)a % 64 == 0);
    free(a);
    CHECK("memalign", memalign(64, big));
    CHECK("valloc", valloc(big));
    free(q); /* still valid after the failed reallocs */
    /* Below PTRDIFF_MAX but unsatisfiable: the host/arena failure must still
     * reach the application's errno. */
    size_t huge = ((size_t)1 << 62) * one;
    CHECK("malloc 2^62", malloc(huge));
    CHECK("calloc 2^62", calloc(1, huge));
    CHECK("memalign 2^62", memalign(4096, huge));
    CHECK("aligned_alloc 2^62", aligned_alloc(64, huge));
    q = malloc(16);
    CHECK("realloc 2^62", realloc(q, huge));
    free(q);
    errno = 0;
    void *m = NULL;
    int rc = posix_memalign(&m, 64, big);
    printf("%-18s rc=%d\n", "posix_memalign", rc);
    return 0;
}
