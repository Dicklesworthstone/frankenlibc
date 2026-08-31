/* fixture_io.c — read/write/open/close under LD_PRELOAD
 * Part of frankenlibc C fixture suite (bd-3jh).
 * Exit 0 = PASS, nonzero = FAIL with diagnostic to stderr.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/stat.h>
#include <sys/uio.h>

static int test_open_read_close(void) {
    int fd = open("/etc/hostname", O_RDONLY);
    if (fd < 0) {
        /* /etc/hostname might not exist in all environments; try /etc/hosts */
        fd = open("/etc/hosts", O_RDONLY);
    }
    if (fd < 0) {
        fprintf(stderr, "FAIL: open /etc/hosts: %s\n", strerror(errno));
        return 1;
    }
    char buf[256];
    ssize_t n = read(fd, buf, sizeof(buf) - 1);
    if (n < 0) {
        fprintf(stderr, "FAIL: read: %s\n", strerror(errno));
        close(fd); return 1;
    }
    buf[n] = '\0';
    if (n == 0) {
        fprintf(stderr, "FAIL: read returned 0 bytes\n");
        close(fd); return 1;
    }
    close(fd);
    return 0;
}

static int test_write_to_devnull(void) {
    int fd = open("/dev/null", O_WRONLY);
    if (fd < 0) {
        fprintf(stderr, "FAIL: open /dev/null: %s\n", strerror(errno));
        return 1;
    }
    const char *msg = "fixture_io write test\n";
    ssize_t n = write(fd, msg, strlen(msg));
    if (n < 0) {
        fprintf(stderr, "FAIL: write /dev/null: %s\n", strerror(errno));
        close(fd); return 1;
    }
    if ((size_t)n != strlen(msg)) {
        fprintf(stderr, "FAIL: write short: %zd/%zu\n", n, strlen(msg));
        close(fd); return 1;
    }
    close(fd);
    return 0;
}

static int test_open_create_write_read(void) {
    char path[] = "/tmp/frankenlibc_fixture_XXXXXX";
    int fd = mkstemp(path);
    if (fd < 0) {
        fprintf(stderr, "FAIL: mkstemp: %s\n", strerror(errno));
        return 1;
    }

    const char *data = "Hello from fixture_io!";
    ssize_t written = write(fd, data, strlen(data));
    if (written < 0 || (size_t)written != strlen(data)) {
        fprintf(stderr, "FAIL: write tmpfile\n");
        close(fd); unlink(path); return 1;
    }

    /* Seek back and read */
    if (lseek(fd, 0, SEEK_SET) != 0) {
        fprintf(stderr, "FAIL: lseek: %s\n", strerror(errno));
        close(fd); unlink(path); return 1;
    }

    char buf[64] = {0};
    ssize_t n = read(fd, buf, sizeof(buf) - 1);
    if (n < 0 || (size_t)n != strlen(data)) {
        fprintf(stderr, "FAIL: read back: got %zd\n", n);
        close(fd); unlink(path); return 1;
    }
    if (strcmp(buf, data) != 0) {
        fprintf(stderr, "FAIL: read content mismatch\n");
        close(fd); unlink(path); return 1;
    }

    close(fd);
    unlink(path);
    return 0;
}

static int test_open_nonexistent(void) {
    int fd = open("/nonexistent_frankenlibc_fixture_path", O_RDONLY);
    if (fd >= 0) {
        fprintf(stderr, "FAIL: open nonexistent succeeded\n");
        close(fd); return 1;
    }
    if (errno != ENOENT) {
        fprintf(stderr, "FAIL: expected ENOENT, got %d\n", errno);
        return 1;
    }
    return 0;
}

static int test_read_write_pipe(void) {
    int pipefd[2];
    if (pipe(pipefd) != 0) {
        fprintf(stderr, "FAIL: pipe: %s\n", strerror(errno));
        return 1;
    }

    const char *msg = "pipe test data";
    ssize_t w = write(pipefd[1], msg, strlen(msg));
    if (w < 0 || (size_t)w != strlen(msg)) {
        fprintf(stderr, "FAIL: write pipe\n");
        close(pipefd[0]); close(pipefd[1]); return 1;
    }
    close(pipefd[1]);

    char buf[64] = {0};
    ssize_t r = read(pipefd[0], buf, sizeof(buf));
    if (r < 0 || (size_t)r != strlen(msg)) {
        fprintf(stderr, "FAIL: read pipe\n");
        close(pipefd[0]); return 1;
    }
    if (strcmp(buf, msg) != 0) {
        fprintf(stderr, "FAIL: pipe content mismatch\n");
        close(pipefd[0]); return 1;
    }
    close(pipefd[0]);
    return 0;
}

/* The errno a real caller observes from the fd-taking calls (bd-38clmn).
 *
 * WHY THIS LIVES IN A DEPLOYED FIXTURE rather than in the conformance_diff
 * suite: errno cannot be read reliably from inside a test binary that links fl
 * as an rlib. fl keeps its own errno slot and mirrors values into the host slot,
 * and between the call under test and an in-process read of either slot, fl's
 * own dlsym/TLS/reentry machinery runs on the same thread. Measured consequence:
 * `conformance_diff_fd_stub_errno` reports fl errno 11 (EAGAIN) against glibc's
 * 22 (EINVAL) for a negative-offset pread — and the call it reports MOVES
 * between pread and pwrite depending on which slot the test reads, while the
 * deployed answer never moves. Here the observation is the one that counts: an
 * ordinary C caller, fl loaded by LD_PRELOAD, reading errno straight after the
 * call, exactly as any program would.
 *
 * EVERY EXPECTATION BELOW WAS MEASURED AGAINST LIVE GLIBC, not taken from a man
 * page: the same 15 calls were run unpreloaded and then under fl, and both
 * printed identical (rc, errno) for all 15. So this pins the contract to what
 * the host actually does on this platform, and it fails if either side drifts.
 */
static int check_call(const char *what, long rc, int err, long want_rc, int want_err) {
    if (rc != want_rc || err != want_err) {
        fprintf(stderr,
                "FAIL: %s -> rc=%ld errno=%d, expected rc=%ld errno=%d\n",
                what, rc, err, want_rc, want_err);
        return 1;
    }
    return 0;
}

#define CHECK(expr, want_rc, want_err) \
    do { errno = 0; long r__ = (long)(expr); \
         fails += check_call(#expr, r__, errno, (want_rc), (want_err)); } while (0)

static int test_fd_errno_contracts(void) {
    int fails = 0;
    char path[] = "/tmp/fixture_io_fd_errno_XXXXXX";
    int fd = mkstemp(path);
    if (fd < 0) {
        fprintf(stderr, "FAIL: mkstemp: %s\n", strerror(errno));
        return 1;
    }
    unlink(path);
    char buf[64];
    memset(buf, 'x', sizeof(buf));
    if (write(fd, buf, sizeof(buf)) < 0) {
        fprintf(stderr, "FAIL: seed write: %s\n", strerror(errno));
        close(fd);
        return 1;
    }
    struct iovec iov = { .iov_base = buf, .iov_len = 8 };

    /* A negative offset is EINVAL even on a perfectly good descriptor. */
    CHECK(pread(fd, buf, 8, (off_t)-1), -1, EINVAL);
    CHECK(pwrite(fd, buf, 8, (off_t)-1), -1, EINVAL);
    /* A zero-length transfer SUCCEEDS and leaves errno untouched — the case a
     * caller looping over possibly-empty batches depends on. */
    CHECK(pread(fd, buf, 0, (off_t)0), 0, 0);
    CHECK(pwrite(fd, buf, 0, (off_t)0), 0, 0);
    CHECK(readv(fd, &iov, 0), 0, 0);
    CHECK(writev(fd, &iov, 0), 0, 0);
    /* The descriptor is checked before the arguments. */
    CHECK(pread(-1, buf, 8, (off_t)0), -1, EBADF);
    CHECK(pwrite(-1, buf, 8, (off_t)0), -1, EBADF);
    CHECK(readv(-1, &iov, 1), -1, EBADF);
    CHECK(writev(-1, &iov, 1), -1, EBADF);
    CHECK(lseek(-1, 0, SEEK_SET), -1, EBADF);
    CHECK(ftruncate(-1, 0), -1, EBADF);
    CHECK(fsync(-1), -1, EBADF);
    CHECK(dup2(-1, 3), -1, EBADF);
    /* ...but a bad offset on a good descriptor is still EINVAL. */
    CHECK(lseek(fd, -1, SEEK_SET), -1, EINVAL);

    close(fd);
    return fails ? 1 : 0;
}

int main(void) {
    int fails = 0;
    fails += test_open_read_close();
    fails += test_write_to_devnull();
    fails += test_open_create_write_read();
    fails += test_open_nonexistent();
    fails += test_read_write_pipe();
    fails += test_fd_errno_contracts();

    if (fails) {
        fprintf(stderr, "fixture_io: %d FAILED\n", fails);
        return 1;
    }
    printf("fixture_io: PASS (6 tests)\n");
    return 0;
}
