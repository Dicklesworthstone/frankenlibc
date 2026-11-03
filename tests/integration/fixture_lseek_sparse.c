/* lseek SEEK_DATA / SEEK_HOLE on a sparse file.
 *
 * fl's lseek accepted only SEEK_SET/CUR/END: strict failed SEEK_DATA and
 * SEEK_HOLE with EINVAL (cp, tar and rsync then copy holes as zeros), and
 * hardened rewrote them to SEEK_SET, returning the offset itself as if
 * data started there. Output is compared byte-for-byte with glibc (both
 * runs use the same file system).
 */
#define _GNU_SOURCE
#include <dlfcn.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#define CHECK(condition) do { if (!(condition)) { \
    fprintf(stderr, "lseek contract failed at line %d\n", __LINE__); return 1; \
} } while (0)

/* Optional ownership check for standalone/preload qualification. Ordinary
 * corpus runs still compare identical stdout/stderr against host glibc. */
static int check_provider(void) {
    const char *expected = getenv("FLC_LSEEK_EXPECT_PROVIDER");
    if (!expected)
        return 0;
    struct stat want, got;
    CHECK(stat(expected, &want) == 0);
    const void *symbols[] = {(const void *)lseek, (const void *)lseek64,
                             (const void *)__errno_location};
    for (size_t i = 0; i < sizeof symbols / sizeof *symbols; i++) {
        Dl_info info;
        if (!dladdr(symbols[i], &info) || !info.dli_fname ||
            stat(info.dli_fname, &got) != 0 ||
            got.st_dev != want.st_dev || got.st_ino != want.st_ino) {
            fprintf(stderr, "lseek provider mismatch\n");
            return 42;
        }
    }
    return 0;
}

static int error_contract(int fd) {
    int duplicate = dup(fd), ends[2];
    CHECK(duplicate >= 0 && pipe(ends) == 0);
    CHECK(write(ends[1], "q", 1) == 1);
    int closed = dup(ends[0]);
    CHECK(closed >= 0 && close(closed) == 0);
    int descriptors[] = {fd, duplicate, ends[0], -1, closed};
    int invalid[] = {-1, 5, 123456, INT_MIN, INT_MAX};
    off_t offsets[] = {-9, 0, 7};
    size_t cases = 0;
    for (int alias = 0; alias < 2; alias++) {
        for (size_t d = 0; d < sizeof descriptors / sizeof *descriptors; d++) {
            for (size_t w = 0; w < sizeof invalid / sizeof *invalid; w++) {
                for (size_t o = 0; o < sizeof offsets / sizeof *offsets; o++) {
                    CHECK(lseek(fd, 1, SEEK_SET) == 1);
                    errno = 0;
                    off_t rc = alias ? lseek64(descriptors[d], offsets[o], invalid[w])
                                     : lseek(descriptors[d], offsets[o], invalid[w]);
                    int error = errno;
                    CHECK(rc == -1 && error == (d >= 3 ? EBADF : EINVAL));
                    CHECK(lseek(duplicate, 0, SEEK_CUR) == 1);
                    cases++;
                }
            }
        }
        for (int whence = SEEK_SET; whence <= SEEK_END; whence++) {
            CHECK(lseek(fd, 1, SEEK_SET) == 1);
            errno = 0;
            off_t rc = alias ? lseek64(fd, -(4 << 20), whence)
                             : lseek(fd, -(4 << 20), whence);
            CHECK(rc == -1 && errno == EINVAL);
            CHECK(lseek(duplicate, 0, SEEK_CUR) == 1);
            cases++;
        }
        for (int whence = SEEK_SET; whence <= SEEK_HOLE; whence++) {
            errno = 0;
            off_t rc = alias ? lseek64(ends[0], 0, whence) : lseek(ends[0], 0, whence);
            CHECK(rc == -1 && errno == ESPIPE);
            cases++;
        }
    }
    char byte = 0, head[4], tail[4];
    struct stat metadata;
    CHECK(read(ends[0], &byte, 1) == 1 && byte == 'q');
    CHECK(pread(fd, head, 4, 0) == 4 && memcmp(head, "head", 4) == 0);
    CHECK(pread(fd, tail, 4, 3 << 20) == 4 && memcmp(tail, "tail", 4) == 0);
    CHECK(fstat(fd, &metadata) == 0 && metadata.st_size == (3 << 20) + 4);
    CHECK(close(duplicate) == 0 && close(ends[0]) == 0 && close(ends[1]) == 0);
    CHECK(cases == 166);
    printf("lseek error contract: %zu cases passed\n", cases);
    return 0;
}

int main(void) {
    int provider = check_provider();
    if (provider)
        return provider;
    char path[] = "/tmp/fl_sparse_XXXXXX";
    int fd = mkstemp(path);
    if (fd < 0)
        return 1;
    /* Retain the uniquely named sparse input for failure diagnosis. */
    const off_t mib = 1 << 20;
    if (pwrite(fd, "head", 4, 0) != 4 || pwrite(fd, "tail", 4, 3 * mib) != 4)
        return 1;
    if (error_contract(fd))
        return 1;
    off_t probes[] = {0, 4, 4096, mib, 3 * mib, 3 * mib + 4, 4 * mib};
    const char *names[] = {"SEEK_DATA", "SEEK_HOLE"};
    for (int w = 0; w < 2; w++) {
        for (size_t i = 0; i < sizeof probes / sizeof *probes; i++) {
            errno = 0;
            off_t r = lseek(fd, probes[i], w ? SEEK_HOLE : SEEK_DATA);
            printf("%s from %lld -> %lld errno=%s\n", names[w], (long long)probes[i], (long long)r,
                   r < 0 ? strerrorname_np(errno) : "0");
        }
    }
    close(fd);
    return 0;
}
