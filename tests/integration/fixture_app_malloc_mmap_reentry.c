/* A program that defines its own malloc family which calls mmap while it
 * initializes (Bun/mimalloc, e.g. the Claude Code binary). The executable's
 * malloc symbol wins lookup over the preload, so fl's internal Rust
 * allocations land in it. fl's mmap used to build its runtime-math kernel on
 * the first call, allocating through that malloc while it was mid-init: the
 * allocator returned NULL to the re-entrant call and fl aborted with "memory
 * allocation of N bytes failed". Output matches glibc.
 */
#define _GNU_SOURCE
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/mman.h>

static unsigned char *arena;
static size_t used, cap;
static int busy;
static unsigned long reentered;

static void *grab(size_t n) {
    if (busy) { /* re-entered from inside our own mmap call */
        reentered++;
        return NULL;
    }
    if (!arena) {
        busy = 1;
        cap = 64u << 20;
        void *p = mmap(NULL, cap, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
        busy = 0;
        if (p == MAP_FAILED) return NULL;
        arena = p;
    }
    n = (n + 15) & ~(size_t)15;
    if (used + n + 16 > cap) return NULL;
    unsigned char *r = arena + used + 16;
    ((size_t *)r)[-1] = n;
    used += n + 16;
    return r;
}

void *malloc(size_t n) { return grab(n ? n : 1); }
void free(void *p) { (void)p; }
void *calloc(size_t a, size_t b) {
    void *p = grab(a * b ? a * b : 1);
    if (p) memset(p, 0, a * b);
    return p;
}
void *realloc(void *p, size_t n) {
    void *q = grab(n ? n : 1);
    if (q && p) {
        size_t old = ((size_t *)p)[-1];
        memcpy(q, p, old < n ? old : n);
    }
    return q;
}
int posix_memalign(void **out, size_t align, size_t n) {
    void *p = grab(n + align);
    if (!p) return 12;
    *out = (void *)(((uintptr_t)p + align - 1) & ~(uintptr_t)(align - 1));
    return 0;
}
void *aligned_alloc(size_t align, size_t n) {
    void *p;
    return posix_memalign(&p, align, n) ? NULL : p;
}

/* mimalloc initializes from an early constructor, before fl has built its
 * kernel on any other path. */
static char *early;
static void early_init(void) { early = malloc(32); }
__attribute__((section(".preinit_array"), used)) static void (*early_init_ptr)(void) = early_init;

int main(void) {
    printf("early allocation %s\n", early ? "ok" : "NULL");
    char *s = malloc(32);
    strcpy(s, "own allocator works");
    void *m = mmap(NULL, 4096, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    printf("%s; mmap %s; reentered=%lu\n", s, m != MAP_FAILED ? "ok" : "failed", reentered);
    return 0;
}
