/* qsort is stable, as glibc 2.43's (a merge sort) is: equal keys keep their
 * input order at every size (bd-8p8q15). fl's pdqsort reordered them from
 * n = 31 up, so any program sorting records by a partial key printed them in
 * a different order. Prints stability and an FNV hash of the resulting order
 * for 12 sizes and 3 element widths; compared byte-for-byte with glibc.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

struct rec {
    int key, seq;
};

struct wide {
    int key, seq;
    double payload[2];
};

static int by_key(const void *a, const void *b) {
    const struct rec *x = a, *y = b;
    return (x->key > y->key) - (x->key < y->key);
}

static int by_key_wide(const void *a, const void *b) {
    const struct wide *x = a, *y = b;
    return (x->key > y->key) - (x->key < y->key);
}

static int by_key_ptr(const void *a, const void *b) {
    return by_key(*(const struct rec *const *)a, *(const struct rec *const *)b);
}

static unsigned long long fnv(unsigned long long h, int key, int seq) {
    h = (h ^ (unsigned)key) * 1099511628211ULL;
    return (h ^ (unsigned)seq) * 1099511628211ULL;
}

int main(void) {
    size_t sizes[] = {1, 5, 7, 16, 17, 31, 64, 100, 257, 1000, 5000, 100000};
    unsigned state = 12345;
    for (size_t s = 0; s < sizeof sizes / sizeof *sizes; s++) {
        size_t n = sizes[s];
        struct rec *r = malloc(n * sizeof *r);
        struct wide *w = malloc(n * sizeof *w);
        struct rec **p = malloc(n * sizeof *p);
        for (size_t i = 0; i < n; i++) {
            state = state * 1103515245u + 12345u;
            r[i].key = w[i].key = (int)((state >> 16) % 5);
            r[i].seq = w[i].seq = (int)i;
            p[i] = &r[i];
        }
        qsort(p, n, sizeof *p, by_key_ptr);
        qsort(r, n, sizeof *r, by_key);
        qsort(w, n, sizeof *w, by_key_wide);
        int stable = 1;
        unsigned long long h8 = 1469598103934665603ULL, h24 = h8, hp = h8;
        for (size_t i = 0; i < n; i++) {
            if (i && r[i].key == r[i - 1].key && r[i].seq < r[i - 1].seq)
                stable = 0;
            if (i && w[i].key == w[i - 1].key && w[i].seq < w[i - 1].seq)
                stable = 0;
            h8 = fnv(h8, r[i].key, r[i].seq);
            h24 = fnv(h24, w[i].key, w[i].seq);
            hp = fnv(hp, p[i]->key, (int)(p[i] - r));
        }
        printf("n=%zu stable=%d width8=%016llx width24=%016llx pointers=%016llx\n", n, stable, h8, h24, hp);
        free(r);
        free(w);
        free(p);
    }
    return 0;
}
