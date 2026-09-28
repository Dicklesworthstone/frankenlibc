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
#include <stdio.h>
#include <stdlib.h>
#include <sys/wait.h>
#include <unistd.h>

static void a(void) { printf("atexit a\n"); }
static void b(void) { printf("atexit b\n"); }
static void on(int st, void *arg) { printf("on_exit status=%d arg=%s\n", st, (const char *)arg); }
__attribute__((destructor)) static void dtor(void) { printf("destructor\n"); }

static int child_main(int use_exit) {
    atexit(a);
    on_exit(on, "x");
    atexit(b);
    printf("main %s\n", use_exit ? "calls exit(7)" : "returns 5");
    if (use_exit) exit(7);
    return 5;
}

int main(void) {
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
