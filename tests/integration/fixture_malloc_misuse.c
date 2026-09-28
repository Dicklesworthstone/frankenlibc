/* fixture_malloc_misuse.c — strict mode is at least as fail-safe as glibc for
 * allocator misuse (bd-rc0923-epic-eeuy4f.8).
 *
 * Each misuse runs in a forked child whose stderr goes to a pipe; the parent
 * prints the child's termination and diagnostic. glibc aborts every case below
 * with a fixed malloc_printerr message, so the preload smoke battery requires
 * byte parity in STRICT mode (hardened mode heals these instead, by design).
 * The cases are chosen so glibc's own diagnostic is deterministic:
 *   - double free of a tcache-sized block;
 *   - double free of a 4000-byte block with a live neighbour after it (its
 *     PREV_INUSE bit catches it, not the top-chunk check);
 *   - free / realloc of p+8, misaligned, which fails glibc's pointer check
 *     before it reads any header.
 */
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/wait.h>
#include <unistd.h>

static void run(const char *label, void (*misuse)(void)) {
    int fds[2];
    if (pipe(fds) != 0) {
        perror("pipe");
        exit(2);
    }
    fflush(stdout);
    pid_t pid = fork();
    if (pid < 0) {
        perror("fork");
        exit(2);
    }
    if (pid == 0) {
        close(fds[0]);
        dup2(fds[1], 2);
        misuse();
        _exit(0);
    }
    close(fds[1]);
    char msg[512];
    size_t len = 0;
    ssize_t n;
    while (len < sizeof msg - 1 && (n = read(fds[0], msg + len, sizeof msg - 1 - len)) > 0) {
        len += (size_t)n;
    }
    msg[len] = '\0';
    close(fds[0]);
    int status = 0;
    waitpid(pid, &status, 0);
    if (WIFSIGNALED(status)) {
        printf("%s: signal %d: %s", label, WTERMSIG(status), msg);
    } else {
        printf("%s: exit %d (no abort): %s\n", label, WEXITSTATUS(status), msg);
    }
}

/* Every pointer goes through this volatile slot: a double free is UB, and
 * the compiler otherwise deletes the whole malloc/free sequence. */
static void *volatile keep;

static void double_free_small(void) {
    keep = malloc(24);
    memset(keep, 0, 24);
    free(keep);
    free(keep);
}

static void *volatile neighbour;

static void double_free_large(void) {
    keep = malloc(4000);
    neighbour = malloc(32);
    memset(keep, 0, 4000);
    free(keep);
    free(keep);
}

static void free_misaligned(void) {
    keep = malloc(64);
    memset(keep, 0, 64);
    keep = (char *)keep + 8;
    free(keep);
}

static void realloc_misaligned(void) {
    keep = malloc(64);
    memset(keep, 0, 64);
    keep = (char *)keep + 8;
    keep = realloc(keep, 128);
}

int main(void) {
    /* Older glibc wrote fatal messages to /dev/tty unless this is set. */
    setenv("LIBC_FATAL_STDERR_", "1", 1);
    run("double_free_small", double_free_small);
    run("double_free_large", double_free_large);
    run("free_misaligned", free_misaligned);
    run("realloc_misaligned", realloc_misaligned);
    return 0;
}
