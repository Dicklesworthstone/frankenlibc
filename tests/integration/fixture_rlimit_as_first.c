/* A program that caps its address space before doing anything else (gnulib's
 * printf-posix2 tests, `ulimit -v`-style self limits). fl built its runtime
 * state lazily, so the first libc calls after the cap crashed: strict faulted
 * growing the stack for the runtime-math kernel's constructor at the first
 * mmap decision, hardened aborted building the validation pipeline (at exit's
 * stdio flush) or a signal-safety table (inside realloc). Must match glibc in
 * strict and hardened. */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/resource.h>

int main(void) {
    struct rlimit lim = {10000000, 10000000};
    if (setrlimit(RLIMIT_AS, &lim) != 0)
        return 77;
    /* The first mmap decision (its result is not compared: fl's own mappings
     * already exceed the cap, so no new mapping fits, unlike glibc's). */
    void *m = mmap(NULL, 1 << 16, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (m != MAP_FAILED)
        munmap(m, 1 << 16);
    char *p = malloc(64);
    p = p ? realloc(p, 1000) : NULL;
    if (p)
        strcpy(p, "realloc ok");
    printf("%s\n", p ? p : "realloc failed");
    free(p);
    fprintf(stdout, "%d %s\n", 42, "done");
    return 0;
}
