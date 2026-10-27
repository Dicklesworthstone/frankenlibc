/* fixture_pthread_key_destructors.c — POSIX key destructors run when a thread
 * exits, by return and by pthread_exit, including destructor re-rounds when a
 * destructor stores a new value (bd-v6cz9v). fl kept keys in its own table
 * while host-created threads exited through the host's start_thread, so no
 * key destructor ever ran. Output must be byte-identical to glibc.
 */
#define _GNU_SOURCE
#include <dlfcn.h>
#include <limits.h>
#include <pthread.h>
#include <stdatomic.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/mman.h>
#include <unistd.h>

static pthread_key_t plain, again;
static int plain_calls, again_calls;
static pthread_mutex_t lock = PTHREAD_MUTEX_INITIALIZER;

static void plain_dtor(void *v) {
    pthread_mutex_lock(&lock);
    plain_calls += (int)(intptr_t)v;
    pthread_mutex_unlock(&lock);
}

/* Re-arms itself once: POSIX runs another destructor round for it. */
static void again_dtor(void *v) {
    pthread_mutex_lock(&lock);
    again_calls++;
    pthread_mutex_unlock(&lock);
    if ((intptr_t)v == 1) pthread_setspecific(again, (void *)2);
}

static void *worker(void *arg) {
    pthread_setspecific(plain, (void *)1);
    pthread_setspecific(again, (void *)1);
    if (arg) pthread_exit(NULL);
    return NULL;
}

static int legacy_fixture(void) {
    pthread_key_create(&plain, plain_dtor);
    pthread_key_create(&again, again_dtor);
    enum { N = 200 };
    for (int i = 0; i < N; i++) {
        pthread_t t;
        pthread_create(&t, NULL, worker, (i & 1) ? (void *)1 : NULL);
        pthread_join(t, NULL);
    }
    /* The main thread's values are not destroyed at exit. */
    pthread_setspecific(plain, (void *)1000);
    printf("threads=%d plain destructor sum=%d again destructor calls=%d\n", N, plain_calls, again_calls);
    return 0;
}

/* Each lifecycle case runs in its own process so a stack-overflow regression
 * cannot hide a different ownership or destructor-order failure. */
enum { LIFECYCLE_KEYS = 64 };
struct lifecycle_case {
    const char *name;
    int values;
    int explicit_exit;
    int rounds;
    int mutation; /* 1 replaces the next value; 2 deletes/recreates its key. */
    int minimum_stack;
    int borrowed_stack;
};
static const struct lifecycle_case lifecycle_cases[] = {
    {"empty-return",    0, 0, 0, 0, 0, 0},
    {"empty-exit",      0, 1, 0, 0, 0, 0},
    {"values-return",   1, 0, 0, 0, 0, 0},
    {"values-exit",     1, 1, 0, 0, 0, 0},
    {"rounds-return",   1, 0, 1, 0, 0, 0},
    {"rounds-exit",     1, 1, 1, 0, 0, 0},
    {"replace-later",   1, 0, 0, 1, 0, 0},
    {"delete-later",    1, 0, 0, 2, 0, 0},
    {"minimum-return",  1, 0, 0, 0, 1, 0},
    {"minimum-exit",    1, 1, 0, 0, 1, 0},
    {"borrowed-return", 1, 0, 0, 0, 1, 1},
    {"borrowed-exit",   1, 1, 0, 0, 1, 1},
};
struct lifecycle_value {
    int index;
    int parent;
    int replacement;
};
static const struct lifecycle_case *active_case;
static pthread_key_t lifecycle_keys[LIFECYCLE_KEYS];
static struct lifecycle_value parent_values[LIFECYCLE_KEYS];
static struct lifecycle_value child_values[LIFECYCLE_KEYS];
static struct lifecycle_value replacement_value = {1, 0, 1};
static _Atomic unsigned lifecycle_calls[LIFECYCLE_KEYS];
static _Atomic unsigned parent_calls, replacement_calls, lifecycle_errors;

static void lifecycle_destructor(void *pointer) {
    struct lifecycle_value *value = pointer;
    if (value->parent) {
        atomic_fetch_add(&parent_calls, 1);
        return;
    }
    unsigned call = atomic_fetch_add(&lifecycle_calls[value->index], 1) + 1;
    if (pthread_getspecific(lifecycle_keys[value->index]) != NULL)
        atomic_fetch_add(&lifecycle_errors, 1);
    if (value->replacement)
        atomic_fetch_add(&replacement_calls, 1);
    if (active_case->mutation && value->index == 1 && !value->replacement)
        atomic_fetch_add(&lifecycle_errors, 1);

    if (active_case->rounds && value->index == 0) {
        /* Re-arm even the fourth callback: teardown must stop at the limit. */
        if (pthread_setspecific(lifecycle_keys[0], value) != 0)
            atomic_fetch_add(&lifecycle_errors, 1);
        if (call > PTHREAD_DESTRUCTOR_ITERATIONS)
            atomic_fetch_add(&lifecycle_errors, 1);
    }
    if (active_case->mutation && value->index == 0) {
        /* GNU visits the still-live next key after this callback. A snapshot
         * of every callback/value before the first call gets both cases wrong. */
        if (pthread_getspecific(lifecycle_keys[1]) != &child_values[1])
            atomic_fetch_add(&lifecycle_errors, 1);
        if (active_case->mutation == 2) {
            pthread_key_t new_key;
            if (pthread_key_delete(lifecycle_keys[1]) != 0 ||
                pthread_key_create(&new_key, lifecycle_destructor) != 0) {
                atomic_fetch_add(&lifecycle_errors, 1);
                return;
            }
            lifecycle_keys[1] = new_key;
        }
        if (pthread_setspecific(lifecycle_keys[1], &replacement_value) != 0)
            atomic_fetch_add(&lifecycle_errors, 1);
    }
}

static void *lifecycle_worker(void *unused) {
    (void)unused;
    for (int i = 0; i < LIFECYCLE_KEYS; ++i) {
        if (pthread_getspecific(lifecycle_keys[i]) != NULL)
            atomic_fetch_add(&lifecycle_errors, 1);
        if (active_case->values && (!active_case->rounds || i == 0) &&
            pthread_setspecific(lifecycle_keys[i], &child_values[i]) != 0)
            atomic_fetch_add(&lifecycle_errors, 1);
    }
    if (active_case->explicit_exit)
        pthread_exit((void *)(uintptr_t)0x1234);
    return (void *)(uintptr_t)0x1234;
}

static int verify_lifecycle_provider(const char *candidate) {
    const struct {
        const char *name;
        void *address;
    } symbols[] = {
        {"pthread_create", (void *)pthread_create},
        {"pthread_join", (void *)pthread_join},
        {"pthread_exit", (void *)pthread_exit},
        {"pthread_key_create", (void *)pthread_key_create},
        {"pthread_key_delete", (void *)pthread_key_delete},
        {"pthread_getspecific", (void *)pthread_getspecific},
        {"pthread_setspecific", (void *)pthread_setspecific},
    };
    if (candidate == NULL)
        return 0;
    for (size_t i = 0; i < sizeof(symbols) / sizeof(symbols[0]); ++i) {
        Dl_info provider;
        if (dladdr(symbols[i].address, &provider) == 0 ||
            strcmp(provider.dli_fname, candidate) != 0) {
            fprintf(stderr, "FAIL: %s is not from the requested candidate\n", symbols[i].name);
            return 1;
        }
    }
    return 0;
}

static int lifecycle_fixture(const char *name, const char *candidate) {
    if (verify_lifecycle_provider(candidate))
        return 1;
    for (size_t i = 0; i < sizeof(lifecycle_cases) / sizeof(lifecycle_cases[0]); ++i) {
        if (strcmp(name, lifecycle_cases[i].name) == 0)
            active_case = &lifecycle_cases[i];
    }
    if (active_case == NULL) {
        fprintf(stderr, "FAIL: unknown key lifecycle case %s\n", name);
        return 1;
    }
    for (int i = 0; i < LIFECYCLE_KEYS; ++i) {
        parent_values[i] = (struct lifecycle_value){i, 1, 0};
        child_values[i] = (struct lifecycle_value){i, 0, 0};
        if (pthread_key_create(&lifecycle_keys[i], lifecycle_destructor) != 0 ||
            pthread_setspecific(lifecycle_keys[i], &parent_values[i]) != 0) {
            fprintf(stderr, "FAIL: key lifecycle setup\n");
            return 1;
        }
    }

    pthread_attr_t attr;
    if (pthread_attr_init(&attr) != 0)
        return 1;
    void *mapping = MAP_FAILED;
    size_t mapping_size = 0;
    unsigned char *borrowed = NULL;
    if (active_case->borrowed_stack) {
        long page = sysconf(_SC_PAGESIZE);
        if (page <= 0)
            return 1;
        size_t size = (size_t)PTHREAD_STACK_MIN;
        mapping_size = size + 2 * (size_t)page;
        mapping = mmap(NULL, mapping_size, PROT_NONE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
        if (mapping == MAP_FAILED)
            return 1;
        borrowed = (unsigned char *)mapping + page;
        if (mprotect(borrowed, size, PROT_READ | PROT_WRITE) != 0 ||
            pthread_attr_setstack(&attr, borrowed, size) != 0)
            return 1;
    } else if (active_case->minimum_stack &&
               pthread_attr_setstacksize(&attr, PTHREAD_STACK_MIN) != 0) {
        return 1;
    }

    pthread_t thread;
    int create = pthread_create(&thread, &attr, lifecycle_worker, NULL);
    pthread_attr_destroy(&attr);
    void *result = NULL;
    int join = create == 0 ? pthread_join(thread, &result) : -1;
    int failed = create != 0 || join != 0 || result != (void *)(uintptr_t)0x1234;
    unsigned parent_lost = 0;
    for (int i = 0; i < LIFECYCLE_KEYS; ++i) {
        void *expected_parent = active_case->mutation == 2 && i == 1
                                    ? NULL : &parent_values[i];
        if (pthread_getspecific(lifecycle_keys[i]) != expected_parent)
            ++parent_lost;
        unsigned expected = !active_case->values ? 0 :
                            active_case->rounds ? (i == 0 ? PTHREAD_DESTRUCTOR_ITERATIONS : 0) : 1;
        if (atomic_load(&lifecycle_calls[i]) != expected)
            failed = 1;
    }
    if (parent_lost || atomic_load(&parent_calls) || atomic_load(&lifecycle_errors) ||
        atomic_load(&replacement_calls) != (unsigned)(active_case->mutation != 0))
        failed = 1;

    if (borrowed != NULL) {
        /* join must leave a caller-owned stack mapped and writable. */
        borrowed[0] = 0x5a;
        borrowed[PTHREAD_STACK_MIN - 1] = 0xa5;
        if (munmap(mapping, mapping_size) != 0)
            failed = 1;
    }
    for (int i = 0; i < LIFECYCLE_KEYS; ++i) {
        if (pthread_setspecific(lifecycle_keys[i], NULL) != 0 ||
            pthread_key_delete(lifecycle_keys[i]) != 0)
            failed = 1;
    }
    if (failed) {
        fprintf(stderr, "FAIL: key-lifecycle %s create=%d join=%d parent_lost=%u "
                "parent_calls=%u callback_errors=%u replacements=%u\n",
                name, create, join, parent_lost, atomic_load(&parent_calls),
                atomic_load(&lifecycle_errors), atomic_load(&replacement_calls));
        return 1;
    }
    printf("key-lifecycle %s PASS\n", name);
    return 0;
}

int main(int argc, char **argv) {
    if (argc >= 3 && strcmp(argv[1], "--key-lifecycle") == 0)
        return lifecycle_fixture(argv[2], argc >= 4 ? argv[3] : NULL);
    return legacy_fixture();
}
