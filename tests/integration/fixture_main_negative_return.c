// Returning from main is exit(main(...)) for every int, negative ones included:
// status & 0xff, with atexit handlers run and stdio flushed.
//
// fl's startup read a negative main result as its own "startup failed" code
// and returned from __libc_start_main into _start, whose next instruction is a
// trap: JxrEncApp (main returns -105, exit status 151) died with SIGSEGV.
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/wait.h>
#include <unistd.h>

static void handler(void) { printf("  atexit handler ran\n"); }

int main(int argc, char **argv) {
    if (argc > 1) {
        // Child: buffered output, a handler, then return the requested status.
        atexit(handler);
        printf("  child returning %s from main\n", argv[1]);
        return atoi(argv[1]);
    }
    const char *statuses[] = {"-105", "-1", "-256", "0", "1", "255", "256", "2147483647"};
    for (size_t i = 0; i < sizeof statuses / sizeof *statuses; i++) {
        fflush(stdout);
        int fds[2];
        if (pipe(fds) != 0) return 1;
        pid_t pid = fork();
        if (pid == 0) {
            dup2(fds[1], 1);
            close(fds[0]);
            close(fds[1]);
            execl("/proc/self/exe", argv[0], statuses[i], (char *)NULL);
            _exit(127);
        }
        close(fds[1]);
        char buf[512];
        ssize_t n = read(fds[0], buf, sizeof buf - 1);
        ssize_t m;
        while (n >= 0 && (m = read(fds[0], buf + n, sizeof buf - 1 - (size_t)n)) > 0) n += m;
        close(fds[0]);
        buf[n > 0 ? n : 0] = 0;
        int st;
        waitpid(pid, &st, 0);
        printf("main returns %-11s -> ", statuses[i]);
        if (WIFEXITED(st))
            printf("exit status %d\n", WEXITSTATUS(st));
        else
            printf("killed by signal %d\n", WTERMSIG(st));
        fputs(buf, stdout);
    }
    return 0;
}
