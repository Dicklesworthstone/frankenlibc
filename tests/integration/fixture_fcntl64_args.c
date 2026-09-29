// fcntl's optional third argument through fcntl64 -- what every program built
// with _FILE_OFFSET_BITS=64 calls (the smoke battery compiles this one so).
//
// fl's fcntl64 read that argument from the va_list STRUCTURE instead of the
// argument list, so every command that takes one got 0x3000000010: F_SETLK
// failed with EFAULT (sqlite3 on any on-disk database: "disk I/O error"),
// F_SETFL/F_SETFD set garbage, F_DUPFD returned the wrong descriptor.
#define _GNU_SOURCE
#define _FILE_OFFSET_BITS 64
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/wait.h>
#include <unistd.h>

static const char *err(int r) { return r < 0 ? strerrorname_np(errno) : "ok"; }

int main(void) {
    char path[] = "/tmp/fl_fcntl64_XXXXXX";
    int fd = mkstemp(path);
    if (write(fd, "0123456789", 10) != 10) return 1;

    int r = fcntl(fd, F_SETFL, O_NONBLOCK | O_APPEND);
    int fl = fcntl(fd, F_GETFL);
    printf("F_SETFL %s, F_GETFL nonblock=%d append=%d\n", err(r), !!(fl & O_NONBLOCK), !!(fl & O_APPEND));

    r = fcntl(fd, F_SETFD, FD_CLOEXEC);
    printf("F_SETFD %s, F_GETFD cloexec=%d\n", err(r), fcntl(fd, F_GETFD) & FD_CLOEXEC);

    int d = fcntl(fd, F_DUPFD, 40);
    int dc = fcntl(fd, F_DUPFD_CLOEXEC, 50);
    printf("F_DUPFD >= 40: %d, F_DUPFD_CLOEXEC >= 50: %d cloexec=%d\n", d, dc, fcntl(dc, F_GETFD) & FD_CLOEXEC);

    struct flock lk = {.l_type = F_WRLCK, .l_whence = SEEK_SET, .l_start = 2, .l_len = 3};
    r = fcntl(fd, F_SETLK, &lk);
    printf("F_SETLK write lock bytes 2..4: %s\n", err(r));
    fflush(stdout);
    pid_t pid = fork();
    if (pid == 0) {
        int cfd = open(path, O_RDWR);
        struct flock probe = {.l_type = F_WRLCK, .l_whence = SEEK_SET, .l_start = 0, .l_len = 10};
        int g = fcntl(cfd, F_GETLK, &probe);
        printf("child F_GETLK %s: type=%s start=%lld len=%lld holder_is_parent=%d\n", err(g),
               probe.l_type == F_WRLCK ? "F_WRLCK" : probe.l_type == F_UNLCK ? "F_UNLCK" : "?",
               (long long)probe.l_start, (long long)probe.l_len, probe.l_pid == getppid());
        struct flock try = {.l_type = F_RDLCK, .l_whence = SEEK_SET, .l_start = 3, .l_len = 1};
        errno = 0;
        int t = fcntl(cfd, F_SETLK, &try);
        printf("child F_SETLK conflicting read lock: %s\n", t < 0 ? strerrorname_np(errno) : "granted");
        struct flock free_range = {.l_type = F_RDLCK, .l_whence = SEEK_SET, .l_start = 6, .l_len = 2};
        printf("child F_SETLK non-overlapping read lock: %s\n", err(fcntl(cfd, F_SETLK, &free_range)));
        fflush(stdout);
        _exit(0);
    }
    waitpid(pid, NULL, 0);
    lk.l_type = F_UNLCK;
    printf("F_SETLK unlock: %s\n", err(fcntl(fd, F_SETLK, &lk)));

    struct flock ofd = {.l_type = F_WRLCK, .l_whence = SEEK_SET, .l_start = 0, .l_len = 1};
    printf("F_OFD_SETLK: %s\n", err(fcntl(fd, F_OFD_SETLK, &ofd)));
    printf("F_SETPIPE_SZ on a file: %s\n", err(fcntl(fd, F_SETPIPE_SZ, 65536)));
    int p[2];
    pipe(p);
    printf("F_SETPIPE_SZ on a pipe: %d, F_GETPIPE_SZ: %d\n", fcntl(p[0], F_SETPIPE_SZ, 131072), fcntl(p[0], F_GETPIPE_SZ));
    printf("bad fd: %s\n", err(fcntl(999, F_SETFL, 0)));
    unlink(path);
    return 0;
}
