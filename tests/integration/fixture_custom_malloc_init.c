// A program that brings its own malloc and initialises it lazily, the way
// jemalloc/mimalloc do: the first allocation calls the libc functions such an
// allocator needs (page size, auxv, a TSD key, fork handlers, its config from
// the environment) while holding its initialisation state. None of those may
// call malloc: glibc's do not, and a re-entrant allocation into a half-built
// allocator deadlocks it or makes it fail.
//
// fl did both: sysconf(_SC_PAGESIZE) read /proc/self/auxv with an allocating
// file read (rustc hung forever in jemalloc's init lock), and
// pthread_key_create published its registry with a heap allocation (rustc then
// aborted: 'memory allocation of 16384 bytes failed').
#define _GNU_SOURCE
#include <pthread.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/auxv.h>
#include <unistd.h>

static char arena[8 << 20];
static size_t used;
static int initialising, initialised, reentered;
static pthread_key_t key;

static void prepare(void) {}
static void parent(void) {}
static void child(void) {}

static void init_allocator(void) {
    initialising = 1;
    long page = sysconf(_SC_PAGESIZE);
    int pages_ok = page == (long)getpagesize() && page == (long)getauxval(AT_PAGESZ);
    int key_ok = pthread_key_create(&key, NULL) == 0;
    int atfork_ok = pthread_atfork(prepare, parent, child) == 0;
    const char *conf = secure_getenv("FIXTURE_MALLOC_CONF");
    long ncpu = sysconf(_SC_NPROCESSORS_ONLN);
    initialising = 0;
    initialised = 1;
    // Report after init, through a path that allocates normally.
    fprintf(stderr, "allocator init: pagesize consistent=%d key=%d atfork=%d conf=%s ncpu>0=%d\n",
            pages_ok, key_ok, atfork_ok, conf ? conf : "(unset)", ncpu > 0);
}

static void *bump(size_t n) {
    n = (n + 15) & ~(size_t)15;
    if (used + n > sizeof arena) return NULL;
    void *p = arena + used;
    used += n;
    return p;
}

void *malloc(size_t n) {
    if (initialising) {
        reentered = 1;
        return bump(n); // a real allocator would deadlock or fail here
    }
    if (!initialised) init_allocator();
    return bump(n);
}

void free(void *p) { (void)p; }

void *calloc(size_t a, size_t b) {
    void *p = malloc(a * b);
    if (p) memset(p, 0, a * b);
    return p;
}

void *realloc(void *p, size_t n) {
    void *q = malloc(n);
    if (q && p) memcpy(q, p, n); // bump arena: copying n bytes is always in bounds
    return q;
}

int main(void) {
    char *s = malloc(32);
    strcpy(s, "hello");
    pthread_setspecific(key, s);
    printf("%s via key: %s\n", s, (char *)pthread_getspecific(key));
    printf("re-entered malloc during allocator init: %s\n", reentered ? "YES" : "no");
    return 0;
}
