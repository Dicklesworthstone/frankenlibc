/* Arguments the kernel (or glibc) accepts that fl's own lists refused.
 *
 * - sigaction(SIGKILL/SIGSTOP, NULL, &old) is a query and succeeds; fl
 *   refused it. sigaction(32/33) -- glibc's internal SIGCANCEL/SIGSETXID --
 *   is EINVAL in glibc; fl accepted it.
 * - mkostemp/mkostemps take any open flags (glibc forces O_RDWR); fl
 *   refused O_NOFOLLOW, O_NONBLOCK, O_NOATIME ... with EINVAL.
 * - waitpid(..., __WALL) is valid; hardened fl stripped __WALL.
 * - listen(fd, -1) asks for the maximum backlog; fl made it 0.
 * Output is compared byte-for-byte with glibc in strict and hardened.
 */
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/wait.h>
#include <unistd.h>

static const char *err(int r) { return r >= 0 ? "ok" : strerrorname_np(errno); }

int main(void) {
    setvbuf(stdout, NULL, _IONBF, 0);
    int sigs[] = {0, 1, 9, 19, 31, 32, 33, 34, 64, 65};
    for (size_t i = 0; i < sizeof sigs / sizeof *sigs; i++) {
        struct sigaction old, sa;
        errno = 0;
        int q = sigaction(sigs[i], NULL, &old);
        const char *qs = err(q);
        memset(&sa, 0, sizeof sa);
        sa.sa_handler = SIG_DFL;
        errno = 0;
        int s = sigaction(sigs[i], &sa, NULL);
        printf("sigaction %d: query=%s set_default=%s\n", sigs[i], qs, err(s));
    }

    int flags[] = {0, O_NOFOLLOW, O_NONBLOCK, O_NOATIME, O_CLOEXEC | O_APPEND, O_WRONLY, O_DIRECT};
    for (size_t i = 0; i < sizeof flags / sizeof *flags; i++) {
        char path[] = "/tmp/fl_mkostemp_XXXXXX";
        errno = 0;
        int fd = mkostemp(path, flags[i]);
        int acc = fd >= 0 ? fcntl(fd, F_GETFL) & O_ACCMODE : -1;
        printf("mkostemp flags=%#o: %s access=%s\n", flags[i], err(fd),
               fd < 0 ? "-" : acc == O_RDWR ? "O_RDWR" : "other");
        if (fd >= 0) {
            close(fd);
            unlink(path);
        }
    }

    pid_t pid = fork();
    if (pid == 0)
        _exit(7);
    int status = 0;
    pid_t w = waitpid(pid, &status, __WALL);
    printf("waitpid __WALL: %s exit=%d\n", w == pid ? "child" : err(w), WEXITSTATUS(status));

    int s = socket(AF_INET, SOCK_STREAM, 0);
    struct sockaddr_in a = {.sin_family = AF_INET, .sin_addr.s_addr = htonl(INADDR_LOOPBACK)};
    bind(s, (struct sockaddr *)&a, sizeof a);
    printf("listen backlog -1: %s\n", err(listen(s, -1)));
    close(s);
    return 0;
}
