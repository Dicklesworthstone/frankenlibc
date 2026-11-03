// fcntl's optional third argument through fcntl64 -- what every program built
// with _FILE_OFFSET_BITS=64 calls (the smoke battery compiles this one so).
//
// fl's fcntl64 read that argument from the va_list STRUCTURE instead of the
// argument list, so every command that takes one got 0x3000000010: F_SETLK
// failed with EFAULT (sqlite3 on any on-disk database: "disk I/O error"),
// F_SETFL/F_SETFD set garbage, F_DUPFD returned the wrong descriptor.
#define _GNU_SOURCE
#define _FILE_OFFSET_BITS 64
#include <dlfcn.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <unistd.h>

static const char *err(int r) { return r < 0 ? strerrorname_np(errno) : "ok"; }

/* Keep both real GNU symbol imports despite the large-file redirect. */
extern int narrow_lockf(int, int, off_t) __asm__("lockf");
typedef int (*lock_function)(int, int, off_t);
extern int narrow_posix_fallocate(int, off_t, off_t) __asm__("posix_fallocate");
typedef int (*allocate_function)(int, off_t, off_t);

#define CHECK(condition) do { if (!(condition)) { \
    fprintf(stderr, "fd contract failed at line %d\n", __LINE__); return 1; \
} } while (0)

static int check_lock_provider(void) {
    const char *expected = getenv("FLC_LOCKF_EXPECT_PROVIDER");
    if (!expected) return 0;
    struct stat want, got;
    if (stat(expected, &want) != 0) return 42;
    const void *symbols[] = {(const void *)narrow_lockf, (const void *)lockf,
                             (const void *)narrow_posix_fallocate, (const void *)posix_fallocate,
                             (const void *)__errno_location};
    for (size_t i = 0; i < sizeof symbols / sizeof *symbols; i++) {
        Dl_info info;
        if (!dladdr(symbols[i], &info) || !info.dli_fname ||
            stat(info.dli_fname, &got) != 0 || got.st_dev != want.st_dev ||
            got.st_ino != want.st_ino) {
            fprintf(stderr, "lockf provider mismatch\n");
            return 42;
        }
    }
    return 0;
}

static int clear_locks(int fd) {
    struct flock lock = {.l_type = F_UNLCK, .l_whence = SEEK_SET};
    return fcntl(fd, F_SETLK, &lock);
}

static int lockf_contract(void) {
    char path[] = "/tmp/fl_lockf_retained_XXXXXX";
    int fd = mkstemp(path), ends[2];
    CHECK(fd >= 0 && write(fd, "0123456789abcdef", 16) == 16);
    int ro = open(path, O_RDONLY);
    CHECK(ro >= 0 && pipe(ends) == 0 && write(ends[1], "q", 1) == 1);
    int closed = dup(ends[0]);
    CHECK(closed >= 0 && close(closed) == 0);
    int descriptors[] = {fd, ro, ends[0], ends[1], -1, closed};
    int commands[] = {-1, F_ULOCK, F_LOCK, F_TLOCK, F_TEST, 4, INT_MIN, INT_MAX};
    off_t lengths[] = {-3, 0, 4};
    lock_function functions[] = {narrow_lockf, lockf};
    size_t cases = 0;
    for (size_t a = 0; a < 2; a++) {
        for (size_t d = 0; d < 6; d++) {
            for (size_t c = 0; c < 8; c++) {
                for (size_t l = 0; l < 3; l++) {
                    CHECK(clear_locks(fd) == 0 && lseek(fd, 7, SEEK_SET) == 7);
                    CHECK(lseek(ro, 7, SEEK_SET) == 7);
                    errno = 0;
                    int rc = functions[a](descriptors[d], commands[c], lengths[l]);
                    int error = rc < 0 ? errno : 0;
                    printf("lockf/%zu fd=%zu cmd=%d len=%lld rc=%d errno=%s pos=%lld/%lld\n",
                           a, d, commands[c], (long long)lengths[l], rc,
                           error ? strerrorname_np(error) : "ok",
                           (long long)lseek(fd, 0, SEEK_CUR), (long long)lseek(ro, 0, SEEK_CUR));
                    cases++;
                }
            }
        }
    }
    CHECK(cases == 288 && clear_locks(fd) == 0);

    size_t conflicts = 0;
    for (int exclusive = 0; exclusive < 2; exclusive++) {
        int ready[2], release[2];
        CHECK(pipe(ready) == 0 && pipe(release) == 0);
        pid_t child = fork();
        CHECK(child >= 0);
        if (child == 0) {
            close(ready[0]); close(release[1]);
            struct flock lock = {.l_type = exclusive ? F_WRLCK : F_RDLCK,
                                 .l_whence = SEEK_SET, .l_start = 7, .l_len = 4};
            if (fcntl(fd, F_SETLK, &lock) != 0 || write(ready[1], "r", 1) != 1) _exit(2);
            char byte;
            if (read(release[0], &byte, 1) != 0) _exit(3);
            _exit(0);
        }
        close(ready[1]); close(release[0]);
        char byte;
        CHECK(read(ready[0], &byte, 1) == 1 && byte == 'r');
        for (size_t a = 0; a < 2; a++) {
            for (int test = 0; test < 2; test++) {
                int cmd = test ? F_TEST : F_TLOCK;
                CHECK(lseek(fd, 7, SEEK_SET) == 7);
                errno = 0;
                int rc = functions[a](fd, cmd, 4), error = rc < 0 ? errno : 0;
                printf("lockf/%zu holder=%s cmd=%d rc=%d errno=%s\n", a,
                       exclusive ? "write" : "read", cmd, rc,
                       error ? strerrorname_np(error) : "ok");
                CHECK((rc == 0) == (!exclusive && test));
                CHECK(lseek(fd, 0, SEEK_CUR) == 7);
                conflicts++;
            }
        }
        close(release[1]); close(ready[0]);
        int status;
        CHECK(waitpid(child, &status, 0) == child && WIFEXITED(status) && WEXITSTATUS(status) == 0);
    }
    CHECK(conflicts == 8);

    size_t ranges = 0;
    for (size_t a = 0; a < 2; a++) {
        for (size_t l = 0; l < 3; l++) {
            CHECK(clear_locks(fd) == 0 && lseek(fd, 7, SEEK_SET) == 7);
            CHECK(functions[a](fd, F_TLOCK, lengths[l]) == 0);
            int reply[2];
            CHECK(pipe(reply) == 0);
            pid_t child = fork();
            CHECK(child >= 0);
            if (child == 0) {
                close(reply[0]);
                struct flock query = {.l_type = F_WRLCK, .l_whence = SEEK_SET};
                if (fcntl(fd, F_GETLK, &query) != 0 ||
                    write(reply[1], &query, sizeof query) != (ssize_t)sizeof query) _exit(4);
                _exit(0);
            }
            close(reply[1]);
            struct flock query;
            CHECK(read(reply[0], &query, sizeof query) == (ssize_t)sizeof query);
            close(reply[0]);
            int status;
            CHECK(waitpid(child, &status, 0) == child && WIFEXITED(status) && WEXITSTATUS(status) == 0);
            off_t start = lengths[l] < 0 ? 7 + lengths[l] : 7;
            off_t size = lengths[l] < 0 ? -lengths[l] : lengths[l];
            CHECK(query.l_type == F_WRLCK && query.l_start == start && query.l_len == size && query.l_pid == getpid());
            CHECK(lseek(fd, 0, SEEK_CUR) == 7);
            printf("lockf/%zu range=%lld/%lld holder_is_parent=1\n", a, (long long)start, (long long)size);
            ranges++;
        }
    }
    char bytes[16], byte;
    struct stat metadata;
    CHECK(ranges == 6 && clear_locks(fd) == 0);
    CHECK(pread(fd, bytes, sizeof bytes, 0) == (ssize_t)sizeof bytes && memcmp(bytes, "0123456789abcdef", sizeof bytes) == 0);
    CHECK(fstat(fd, &metadata) == 0 && metadata.st_size == (off_t)sizeof bytes);
    CHECK(read(ends[0], &byte, 1) == 1 && byte == 'q');
    CHECK(close(fd) == 0 && close(ro) == 0 && close(ends[0]) == 0 && close(ends[1]) == 0);
    printf("lockf contract: %zu descriptor cases, %zu conflicts, %zu ranges passed\n", cases, conflicts, ranges);
    /* Retain both uniquely named test inputs for diagnosis. */
    return 0;
}

static int allocation_contract(void) {
    char path[] = "/tmp/fl_posix_alloc_retained_XXXXXX";
    const char seed[] = "0123456789abcdef";
    int fd = mkstemp(path), ends[2];
    CHECK(fd >= 0);
    int ro = open(path, O_RDONLY), append = open(path, O_WRONLY | O_APPEND);
    int directory = open("/tmp", O_RDONLY | O_DIRECTORY);
    CHECK(ro >= 0 && append >= 0 && directory >= 0 && pipe(ends) == 0);
    CHECK(write(ends[1], "q", 1) == 1);
    int closed = dup(directory);
    CHECK(closed >= 0 && close(closed) == 0);
    int descriptors[] = {fd, ro, append, ends[0], ends[1], directory, -1, closed};
    off_t offsets[] = {-1, 0, 7, 31, INT64_MIN};
    off_t lengths[] = {-1, 0, 1, 4, INT64_MIN};
    allocate_function functions[] = {narrow_posix_fallocate, posix_fallocate};
    size_t cases = 0, successes = 0;
    for (size_t a = 0; a < 2; a++) {
        for (size_t d = 0; d < 8; d++) {
            for (size_t o = 0; o < 5; o++) {
                for (size_t l = 0; l < 5; l++) {
                    CHECK(ftruncate(fd, 16) == 0 && pwrite(fd, seed, 16, 0) == 16);
                    CHECK(lseek(fd, 3, SEEK_SET) == 3 && lseek(ro, 3, SEEK_SET) == 3 && lseek(append, 3, SEEK_SET) == 3);
                    errno = 0x3bad;
                    int rc = functions[a](descriptors[d], offsets[o], lengths[l]);
                    int error = errno;
                    CHECK(rc >= 0 && error == 0x3bad);
                    struct stat metadata;
                    CHECK(fstat(fd, &metadata) == 0 && metadata.st_size >= 16 && metadata.st_size <= 35);
                    unsigned char bytes[35];
                    ssize_t count = pread(fd, bytes, sizeof bytes, 0);
                    CHECK(count == metadata.st_size && memcmp(bytes, seed, 16) == 0);
                    for (ssize_t i = 16; i < count; i++) CHECK(bytes[i] == 0);
                    off_t expected = 16;
                    if (rc == 0) {
                        CHECK(offsets[o] >= 0 && lengths[l] > 0);
                        off_t end = offsets[o] + lengths[l];
                        if (end > expected) expected = end;
                        successes++;
                    }
                    CHECK(metadata.st_size == expected);
                    CHECK(lseek(fd, 0, SEEK_CUR) == 3 && lseek(ro, 0, SEEK_CUR) == 3 && lseek(append, 0, SEEK_CUR) == 3);
                    printf("posix allocation/%zu fd=%zu off=%lld len=%lld rc=%d errno=%d size=%lld data=",
                           a, d, (long long)offsets[o], (long long)lengths[l], rc, error, (long long)metadata.st_size);
                    for (ssize_t i = 0; i < count; i++) printf("%02x", bytes[i]);
                    putchar('\n');
                    cases++;
                }
            }
        }
    }
    CHECK(cases == 400 && successes == 24);
    CHECK(narrow_posix_fallocate(-1, -1, -1) == EBADF);
    CHECK(posix_fallocate(-1, -1, -1) == EBADF);
    char byte;
    CHECK(read(ends[0], &byte, 1) == 1 && byte == 'q');
    CHECK(close(fd) == 0 && close(ro) == 0 && close(append) == 0 && close(directory) == 0);
    CHECK(close(ends[0]) == 0 && close(ends[1]) == 0);
    printf("posix allocation contract: %zu cases, %zu successes passed\n", cases, successes);
    return 0;
}

int main(void) {
    int provider = check_lock_provider();
    if (provider) return provider;
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
    CHECK(pipe(p) == 0);
    printf("F_SETPIPE_SZ on a pipe: %d, F_GETPIPE_SZ: %d\n", fcntl(p[0], F_SETPIPE_SZ, 131072), fcntl(p[0], F_GETPIPE_SZ));
    printf("bad fd: %s\n", err(fcntl(999, F_SETFL, 0)));
    CHECK(lockf_contract() == 0);
    return allocation_contract();
}
