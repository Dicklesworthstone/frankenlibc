/* lseek SEEK_DATA / SEEK_HOLE on a sparse file.
 *
 * fl's lseek accepted only SEEK_SET/CUR/END: strict failed SEEK_DATA and
 * SEEK_HOLE with EINVAL (cp, tar and rsync then copy holes as zeros), and
 * hardened rewrote them to SEEK_SET, returning the offset itself as if
 * data started there. Output is compared byte-for-byte with glibc (both
 * runs use the same file system).
 */
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

int main(void) {
    char path[] = "/tmp/fl_sparse_XXXXXX";
    int fd = mkstemp(path);
    if (fd < 0)
        return 1;
    unlink(path);
    const off_t mib = 1 << 20;
    if (pwrite(fd, "head", 4, 0) != 4 || pwrite(fd, "tail", 4, 3 * mib) != 4)
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
