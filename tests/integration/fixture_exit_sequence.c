/* fixture_exit_sequence.c — the glibc exit sequence, on return from main and
 * on an explicit exit(): every atexit / on_exit / __cxa_atexit handler in one
 * reverse-registration order (atexit is a __cxa_atexit call since glibc 2.34),
 * on_exit handlers receive the status, and destructor functions run AFTER the
 * handlers (_dl_fini is glibc's first-registered exit function). fl used to
 * skip every __cxa_atexit handler and destructor on exit(), drop on_exit
 * handlers when main returned, and run destructors before the handlers.
 * Output must be byte-identical to glibc in strict and hardened modes. Each
 * sequence runs in a forked child (the parent reports its exit status and
 * exits 0, as the smoke battery requires).
 */
#define _GNU_SOURCE
#include <dlfcn.h>
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <unistd.h>

static int stdio_probe;

static void a(void) { printf("atexit a\n"); }
static void b(void) { printf("atexit b\n"); }
static void on(int st, void *arg) { printf("on_exit status=%d arg=%s\n", st, (const char *)arg); }
__attribute__((destructor)) static void dtor(void) {
    if (!stdio_probe) printf("destructor\n");
}

static int child_main(int use_exit) {
    atexit(a);
    on_exit(on, "x");
    atexit(b);
    printf("main %s\n", use_exit ? "calls exit(7)" : "returns 5");
    if (use_exit) exit(7);
    return 5;
}

static int verify_stdio_provider(const char *expected) {
    const char *names[] = {"printf", "fflush", "exit", "__libc_start_main"};
    struct stat wanted;
    if (stat(expected, &wanted) != 0) return 86;
    for (size_t i = 0; i < sizeof names / sizeof *names; i++) {
        void *address = dlsym(RTLD_DEFAULT, names[i]);
        Dl_info info;
        struct stat actual;
        if (!address || !dladdr(address, &info) || !info.dli_fname ||
            stat(info.dli_fname, &actual) != 0 || actual.st_dev != wanted.st_dev ||
            actual.st_ino != wanted.st_ino) {
            fprintf(stderr, "fixture-exit-sequence:provider-mismatch:%s\n", names[i]);
            return 86;
        }
    }
    return 0;
}

/* Keep stdout fully buffered and make the flush boundary observable through
 * a pipe. _Exit after an explicit flush prevents a later exit flush from
 * concealing a broken fflush(NULL). Closed stdout must remain retired. */
static int check_stdio_exit(const char *mode) {
    static char output_buffer[256];
    static volatile int value = 42;
    if (setvbuf(stdout, output_buffer, _IOFBF, sizeof output_buffer) != 0) return 2;
    if (printf("stdio-exit:%d\n", value) != 14) return 3;
    if (!strcmp(mode, "stdio-return")) return 0;
    if (!strcmp(mode, "stdio-exit")) exit(7);
    if (!strcmp(mode, "stdio-flush-all")) _Exit(fflush(NULL) == 0 ? 0 : 4);
    if (!strcmp(mode, "stdio-flush-stream")) _Exit(fflush(stdout) == 0 ? 0 : 4);
    if (!strcmp(mode, "stdio-closed-stdout")) {
        if (fclose(stdout) != 0 || fflush(NULL) != 0) return 4;
        errno = 0;
        if (fcntl(STDOUT_FILENO, F_GETFD) != -1 || errno != EBADF) return 5;
        _Exit(0);
    }
    return 2;
}

int main(int argc, char **argv) {
    if (argc >= 2 && !strncmp(argv[1], "stdio-", 6)) {
        stdio_probe = 1;
        if (argc == 3) {
            int result = verify_stdio_provider(argv[2]);
            if (result) return result;
        } else if (argc != 2) {
            return 2;
        }
        return check_stdio_exit(argv[1]);
    }
    for (int use_exit = 0; use_exit <= 1; use_exit++) {
        fflush(stdout);
        pid_t pid = fork();
        if (pid == 0) {
            /* A return from main, reproduced: exit(main's value). */
            exit(child_main(use_exit));
        }
        int status = 0;
        waitpid(pid, &status, 0);
        printf("child exit status %d\n", WIFEXITED(status) ? WEXITSTATUS(status) : -1);
    }
    return 0;
}
