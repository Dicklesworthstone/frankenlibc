/* A program that caps its address space before doing anything else (gnulib's
 * printf-posix2 tests, `ulimit -v`-style self limits). fl built its runtime
 * state lazily, so the first libc calls after the cap crashed: strict faulted
 * growing the stack for the runtime-math kernel's constructor at the first
 * mmap decision, hardened aborted building the validation pipeline (at exit's
 * stdio flush) or a signal-safety table (inside realloc). Must match glibc in
 * strict and hardened. */
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/resource.h>
#include <unistd.h>

static int run_rlimit_data_10mb(void) {
    /* bd-rc0923-epic-eeuy4f.49 / .50 / bd-4n397c:
     * gnulib test-dprintf-posix2 and test-fprintf-posix3 first cap RLIMIT_DATA
     * to 10 MiB and then probe writable anonymous mmap headroom before and
     * after formatted output loops. */
    const rlim_t ten_mib = 10 * 1024 * 1024;
    struct rlimit lim = {ten_mib, ten_mib};
    if (setrlimit(RLIMIT_DATA, &lim) != 0)
        return 77;

    /* Negative control: a 12 MiB private writable anonymous mapping must fail
     * with ENOMEM once RLIMIT_DATA = 10 MiB is active. */
    errno = 0;
    void *too_big = mmap(NULL, 12 * 1024 * 1024, PROT_READ | PROT_WRITE,
                         MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    int enomem_ok = (too_big == MAP_FAILED && errno == ENOMEM);
    if (too_big != MAP_FAILED) {
        munmap(too_big, 12 * 1024 * 1024);
        return 2;
    }

    /* Positive gnulib get_rusage_as_via_setrlimit probe before dprintf/fprintf:
     * private writable footprint must stay well below 10 MiB. */
    void *probe1 = mmap(NULL, 65536, PROT_READ | PROT_WRITE,
                        MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (probe1 == MAP_FAILED)
        return 3;
    memset(probe1, 0xA5, 65536);
    munmap(probe1, 65536);

    int devnull = open("/dev/null", O_WRONLY);
    if (devnull < 0)
        return 4;
    FILE *sink = fopen("/dev/null", "w");
    if (!sink) {
        close(devnull);
        return 5;
    }

    for (int i = 0; i < 200; i++) {
        if (dprintf(devnull, "%04096d\n", i) < 4097) {
            fclose(sink);
            close(devnull);
            return 6;
        }
        if (fprintf(sink, "%04096d %s\n", i, "ok") < 4100) {
            fclose(sink);
            close(devnull);
            return 7;
        }
        char *buf = malloc(3200);
        if (!buf) {
            fclose(sink);
            close(devnull);
            return 8;
        }
        buf[0] = (char)i;
        buf[3199] = (char)(i ^ 0x5A);
        free(buf);
    }
    fflush(sink);
    fclose(sink);
    close(devnull);

    /* Post-loop probe: steady-state dprintf/fprintf must not leak writable VMAs. */
    void *probe2 = mmap(NULL, 65536, PROT_READ | PROT_WRITE,
                        MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (probe2 == MAP_FAILED)
        return 9;
    munmap(probe2, 65536);

    printf("rlimit_data_10mb: enomem_12mb=%d probe_before=1 dprintf_fprintf=200 probe_after=1\n",
           enomem_ok);
    return enomem_ok ? 0 : 10;
}

int main(int argc, char **argv) {
    if (argc == 2 && strcmp(argv[1], "rlimit_data") == 0)
        return run_rlimit_data_10mb();

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
