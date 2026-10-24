/* A program that defines its own malloc family, and whose allocator starts a
 * helper thread the first time a secondary thread allocates (mimalloc-style
 * per-thread setup; the Bun-based Claude Code binary). The executable's
 * malloc wins symbol lookup over the preload, so fl's internal tables grow
 * through it. fl used to grow its host-thread TID registry while holding the
 * registry lock, from inside the new thread's start trampoline: the
 * allocator's pthread_create then waited on that same lock, held by the same
 * thread, forever. Output matches glibc.
 */
#define _GNU_SOURCE
#include <pthread.h>
#include <stdatomic.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/mman.h>

static unsigned char *arena;
static atomic_size_t used;
#define CAP ((size_t)256 << 20)

static void *grab(size_t n) {
    if (!arena) {
        void *p = mmap(NULL, CAP, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
        if (p == MAP_FAILED) return NULL;
        arena = p;
    }
    n = (n + 15) & ~(size_t)15;
    size_t off = atomic_fetch_add(&used, n + 16);
    if (off + n + 16 > CAP) return NULL;
    unsigned char *r = arena + off + 16;
    ((size_t *)r)[-1] = n;
    return r;
}

static pthread_t main_thread;
static atomic_int main_started;
static atomic_int helper_started;
static atomic_int helper_ran;
static __thread int in_setup;

static void *helper(void *arg) {
    (void)arg;
    atomic_store(&helper_ran, 1);
    return NULL;
}

/* First allocation on a secondary thread starts the allocator's helper. */
static void per_thread_setup(void) {
    if (in_setup || !atomic_load(&main_started) || pthread_equal(pthread_self(), main_thread))
        return;
    int expected = 0;
    if (!atomic_compare_exchange_strong(&helper_started, &expected, 1)) return;
    in_setup = 1;
    pthread_t h;
    if (pthread_create(&h, NULL, helper, NULL) == 0) pthread_detach(h);
    in_setup = 0;
}

void *malloc(size_t n) {
    per_thread_setup();
    return grab(n ? n : 1);
}
void free(void *p) { (void)p; }
void *calloc(size_t a, size_t b) {
    void *p = malloc(a * b ? a * b : 1);
    if (p) memset(p, 0, a * b);
    return p;
}
void *realloc(void *p, size_t n) {
    void *q = malloc(n ? n : 1);
    if (q && p) {
        size_t old = ((size_t *)p)[-1];
        memcpy(q, p, old < n ? old : n);
    }
    return q;
}
int posix_memalign(void **out, size_t align, size_t n) {
    void *p = malloc(n + align);
    if (!p) return 12;
    *out = (void *)(((uintptr_t)p + align - 1) & ~(uintptr_t)(align - 1));
    return 0;
}
void *aligned_alloc(size_t align, size_t n) {
    void *p;
    return posix_memalign(&p, align, n) ? NULL : p;
}
void *memalign(size_t align, size_t n) { return aligned_alloc(align, n); }

static void *worker(void *arg) {
    char *s = malloc(32);
    snprintf(s, 32, "worker %ld", (long)(intptr_t)arg);
    return s;
}

int main(void) {
    main_thread = pthread_self();
    atomic_store(&main_started, 1);
    for (long i = 0; i < 4; i++) {
        pthread_t t;
        if (pthread_create(&t, NULL, worker, (void *)(intptr_t)i) != 0) {
            puts("pthread_create failed");
            return 1;
        }
        void *r;
        pthread_join(t, &r);
        printf("%s joined\n", (char *)r);
    }
    for (int i = 0; i < 1000 && !atomic_load(&helper_ran); i++) {
        struct timespec ts = {0, 1000000};
        nanosleep(&ts, NULL);
    }
    printf("helper started=%d ran=%d\n", atomic_load(&helper_started), atomic_load(&helper_ran));
    return 0;
}
