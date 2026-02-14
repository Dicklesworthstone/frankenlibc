/* fixture_malloc_stress.c — allocator stress fixture under LD_PRELOAD
 * Covers concurrent alloc/free pressure + fragmentation wave behavior.
 * Exit 0 = PASS, nonzero = FAIL with diagnostics to stderr.
 */
#include <errno.h>
#include <pthread.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define STRESS_THREADS 4
#define STRESS_ITERS 5000

typedef struct {
    uint64_t seed;
    int worker_id;
    int failure_code;
} worker_arg_t;

static uint64_t xorshift64(uint64_t *state) {
    uint64_t x = *state;
    x ^= x >> 12;
    x ^= x << 25;
    x ^= x >> 27;
    *state = x;
    return x * 0x2545F4914F6CDD1DULL;
}

static uint64_t checksum_mix(uint64_t acc, uint64_t value) {
    acc ^= value + 0x9E3779B97F4A7C15ULL + (acc << 6) + (acc >> 2);
    return acc;
}

static void *worker_alloc_free(void *argp) {
    worker_arg_t *arg = (worker_arg_t *)argp;
    uint64_t rng = arg->seed;

    for (int i = 0; i < STRESS_ITERS; i++) {
        size_t size = (size_t)(xorshift64(&rng) % 2048ULL) + 1U;
        unsigned char pattern = (unsigned char)((arg->worker_id * 31 + i) & 0xFF);

        unsigned char *p = (unsigned char *)malloc(size);
        if (!p) {
            arg->failure_code = 100 + arg->worker_id;
            return NULL;
        }

        memset(p, pattern, size);
        if (p[0] != pattern || p[size - 1] != pattern) {
            free(p);
            arg->failure_code = 120 + arg->worker_id;
            return NULL;
        }

        if ((i % 8) == 0) {
            size_t new_size = (size_t)(xorshift64(&rng) % 4096ULL) + 1U;
            unsigned char *q = (unsigned char *)realloc(p, new_size);
            if (!q) {
                free(p);
                arg->failure_code = 140 + arg->worker_id;
                return NULL;
            }
            p = q;
            size = new_size;
            pattern ^= 0x5AU;
            memset(p, pattern, size);
            if (p[0] != pattern || p[size - 1] != pattern) {
                free(p);
                arg->failure_code = 160 + arg->worker_id;
                return NULL;
            }
        }

        free(p);
    }

    arg->failure_code = 0;
    return NULL;
}

static int test_concurrent_alloc_free(void) {
    pthread_t threads[STRESS_THREADS];
    worker_arg_t args[STRESS_THREADS];

    for (int i = 0; i < STRESS_THREADS; i++) {
        args[i].seed = 0xA5A55A5AF00DBAA0ULL ^ (uint64_t)(i + 1) * 0xD1B54A32D192ED03ULL;
        args[i].worker_id = i;
        args[i].failure_code = 0;
        if (pthread_create(&threads[i], NULL, worker_alloc_free, &args[i]) != 0) {
            fprintf(stderr, "FAIL: pthread_create worker=%d errno=%d\n", i, errno);
            return 1;
        }
    }

    for (int i = 0; i < STRESS_THREADS; i++) {
        if (pthread_join(threads[i], NULL) != 0) {
            fprintf(stderr, "FAIL: pthread_join worker=%d errno=%d\n", i, errno);
            return 1;
        }
        if (args[i].failure_code != 0) {
            fprintf(stderr, "FAIL: worker=%d failure_code=%d\n", i, args[i].failure_code);
            return 1;
        }
    }

    return 0;
}

static int test_fragmentation_wave(uint64_t *out_checksum) {
    enum { N = 2048 };
    unsigned char *ptrs[N];
    size_t sizes[N];
    uint64_t checksum = 0;

    memset(ptrs, 0, sizeof(ptrs));
    memset(sizes, 0, sizeof(sizes));

    for (int i = 0; i < N; i++) {
        size_t size = (size_t)(((i * 37) % 4096) + 16);
        unsigned char *p = (unsigned char *)malloc(size);
        if (!p) {
            fprintf(stderr, "FAIL: fragmentation initial malloc i=%d size=%zu\n", i, size);
            return 1;
        }
        memset(p, (unsigned char)(i & 0xFF), size);
        ptrs[i] = p;
        sizes[i] = size;
    }

    for (int i = 1; i < N; i += 2) {
        free(ptrs[i]);
        ptrs[i] = NULL;
        sizes[i] = 0;
    }

    for (int i = 0; i < N; i += 2) {
        size_t new_size = sizes[i] + (size_t)(((i % 5) + 1) * 32);
        unsigned char expected = (unsigned char)(i & 0xFF);
        unsigned char *q = (unsigned char *)realloc(ptrs[i], new_size);
        if (!q) {
            fprintf(stderr, "FAIL: fragmentation realloc i=%d new_size=%zu\n", i, new_size);
            return 1;
        }
        if (q[0] != expected) {
            free(q);
            fprintf(stderr, "FAIL: fragmentation realloc prefix mismatch i=%d\n", i);
            return 1;
        }
        memset(q, (unsigned char)(expected ^ 0xA5U), new_size);
        ptrs[i] = q;
        sizes[i] = new_size;
    }

    for (int i = 1; i < N; i += 2) {
        size_t size = (size_t)(((i * 53) % 2048) + 24);
        unsigned char *p = (unsigned char *)calloc(size, 1);
        if (!p) {
            fprintf(stderr, "FAIL: fragmentation refill calloc i=%d size=%zu\n", i, size);
            return 1;
        }
        p[0] = (unsigned char)(i & 0xFF);
        p[size - 1] = (unsigned char)((i * 3) & 0xFF);
        ptrs[i] = p;
        sizes[i] = size;
    }

    for (int i = 0; i < N; i++) {
        unsigned char *p = ptrs[i];
        size_t size = sizes[i];
        if (!p || size == 0) {
            fprintf(stderr, "FAIL: fragmentation final null slot i=%d\n", i);
            return 1;
        }
        checksum = checksum_mix(checksum, (uint64_t)p[0]);
        checksum = checksum_mix(checksum, (uint64_t)p[size - 1]);
    }

    for (int i = 0; i < N; i++) {
        free(ptrs[i]);
    }

    *out_checksum = checksum;
    return 0;
}

static int test_conformance_signature(uint64_t *out_checksum) {
    uint64_t rng = 0xC0FFEE1234567890ULL;
    uint64_t checksum = 0;

    for (int i = 0; i < 3000; i++) {
        size_t size = (size_t)(xorshift64(&rng) % 512ULL) + 1U;
        unsigned char *p = (unsigned char *)calloc(size, 1);
        if (!p) {
            fprintf(stderr, "FAIL: conformance calloc i=%d size=%zu\n", i, size);
            return 1;
        }

        size_t probe = size < 8 ? size : 8;
        for (size_t j = 0; j < probe; j++) {
            if (p[j] != 0) {
                free(p);
                fprintf(stderr, "FAIL: conformance calloc not zeroed i=%d j=%zu\n", i, j);
                return 1;
            }
        }

        for (size_t j = 0; j < size; j++) {
            p[j] = (unsigned char)((i + (int)j) & 0xFF);
        }

        if ((i % 3) == 0) {
            size_t new_size = size + (size_t)(xorshift64(&rng) % 256ULL);
            unsigned char *q = (unsigned char *)realloc(p, new_size);
            if (!q) {
                free(p);
                fprintf(stderr, "FAIL: conformance realloc i=%d new_size=%zu\n", i, new_size);
                return 1;
            }
            p = q;
            size = new_size;
        }

        checksum = checksum_mix(checksum, (uint64_t)p[0]);
        checksum = checksum_mix(checksum, (uint64_t)p[size - 1]);
        free(p);
    }

    *out_checksum = checksum;
    return 0;
}

int main(void) {
    int fails = 0;
    uint64_t checksum = 0;

    fails += test_concurrent_alloc_free();

    uint64_t frag_checksum = 0;
    fails += test_fragmentation_wave(&frag_checksum);
    checksum = checksum_mix(checksum, frag_checksum);

    uint64_t conf_checksum = 0;
    fails += test_conformance_signature(&conf_checksum);
    checksum = checksum_mix(checksum, conf_checksum);

    if (fails) {
        fprintf(stderr, "fixture_malloc_stress: %d FAILED\n", fails);
        return 1;
    }

    printf("fixture_malloc_stress: PASS (3 tests) checksum=%llu\n",
           (unsigned long long)checksum);
    return 0;
}
