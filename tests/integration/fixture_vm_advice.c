/* madvise / mmap / mprotect / msync with values fl's lists did not know.
 *
 * Hardened mode rewrote every madvise advice outside a 7-value list to
 * MADV_NORMAL and reported success (MADV_FREE freed nothing, MADV_DONTDUMP
 * kept secrets in core dumps, MADV_WIPEONFORK claimed to wipe RNG state on
 * fork and did not), stripped MAP_SHARED_VALIDATE to MAP_PRIVATE and dropped
 * MAP_32BIT, and turned msync(MS_INVALIDATE) into MS_ASYNC. Output is
 * compared byte-for-byte with glibc in strict and hardened; it holds no
 * addresses, only whether each call worked and what it did.
 */
#define _GNU_SOURCE
#include <errno.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/wait.h>
#include <unistd.h>

#ifndef MADV_COLLAPSE
#define MADV_COLLAPSE 25
#endif

static const char *err(int r) { return r == 0 ? "ok" : strerrorname_np(errno); }

int main(void) {
    setvbuf(stdout, NULL, _IONBF, 0);
    long page = sysconf(_SC_PAGESIZE);
    struct {
        const char *name;
        int advice;
    } advices[] = {
        {"NORMAL", MADV_NORMAL},         {"DONTNEED", MADV_DONTNEED},     {"FREE", MADV_FREE},
        {"DONTFORK", MADV_DONTFORK},     {"DOFORK", MADV_DOFORK},         {"DONTDUMP", MADV_DONTDUMP},
        {"DODUMP", MADV_DODUMP},         {"WIPEONFORK", MADV_WIPEONFORK}, {"KEEPONFORK", MADV_KEEPONFORK},
        {"COLD", MADV_COLD},             {"PAGEOUT", MADV_PAGEOUT},       {"POPULATE_READ", MADV_POPULATE_READ},
        {"POPULATE_WRITE", MADV_POPULATE_WRITE},
    };
    for (size_t i = 0; i < sizeof advices / sizeof *advices; i++) {
        char *p = mmap(NULL, 4 * page, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
        p[0] = 'x';
        errno = 0;
        int r = madvise(p, 4 * page, advices[i].advice);
        printf("madvise %s: %s\n", advices[i].name, err(r));
        munmap(p, 4 * page);
    }

    /* WIPEONFORK must really wipe: the child sees zeros. */
    char *secret = mmap(NULL, page, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    strcpy(secret, "rng-state");
    madvise(secret, page, MADV_WIPEONFORK);
    pid_t pid = fork();
    if (pid == 0)
        _exit(secret[0] == 0 ? 0 : 1);
    int status;
    waitpid(pid, &status, 0);
    printf("WIPEONFORK child sees wiped page: %s\n", WEXITSTATUS(status) == 0 ? "yes" : "no");

    /* MAP_SHARED_VALIDATE: writes reach the file (shared, not private). */
    int fd = memfd_create("fl-vm", 0);
    ftruncate(fd, page);
    char *shared = mmap(NULL, page, PROT_READ | PROT_WRITE, MAP_SHARED_VALIDATE, fd, 0);
    if (shared != MAP_FAILED) {
        shared[0] = 'S';
        char c = 0;
        pread(fd, &c, 1, 0);
        printf("MAP_SHARED_VALIDATE write visible through fd: %s\n", c == 'S' ? "yes" : "no");
        errno = 0;
        int r = msync(shared, page, MS_INVALIDATE);
        printf("msync MS_INVALIDATE: %s\n", err(r));
        r = msync(shared, page, 0);
        printf("msync 0: %s\n", err(r));
        munmap(shared, page);
    } else {
        printf("MAP_SHARED_VALIDATE: %s\n", strerrorname_np(errno));
    }
    close(fd);

    char *low = mmap(NULL, page, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS | MAP_32BIT, -1, 0);
    printf("MAP_32BIT below 4 GiB: %s\n",
           low != MAP_FAILED && (uintptr_t)low + page <= (1ULL << 32) ? "yes" : "no");
    return 0;
}
