/* remove() deletes an empty directory, and ftello() on a stream whose
 * descriptor was closed behind stdio's back fails with EBADF.
 *
 * fl's remove read a stale errno after its raw unlink (the raw syscall reports
 * EISDIR in its return value, not errno), so it never fell back to rmdir
 * (gnulib test-canonicalize-lgpl). Its first-ftell lseek probe treated EBADF as
 * "seekable" and returned the tracked offset 0 (gnulib test-ftello4). Output
 * matches glibc.
 */
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <unistd.h>

int main(void) {
    char dir[] = "/tmp/fl_remove_XXXXXX";
    if (!mkdtemp(dir)) return 1;
    errno = 0;
    int rc = remove(dir);
    printf("remove(empty dir) rc=%d errno=%d exists=%d\n", rc, errno, access(dir, F_OK) == 0);
    errno = 0;
    rc = remove(dir);
    printf("remove(missing) rc=%d errno=%d\n", rc, errno);

    char file[] = "/tmp/fl_ftell_XXXXXX";
    int fd = mkstemp(file);
    if (fd < 0) return 1;
    write(fd, "abc", 3);
    close(fd);
    FILE *fp = fopen(file, "r");
    setvbuf(fp, NULL, _IONBF, 0);
    close(fileno(fp));
    errno = 0;
    long off = (long)ftello(fp);
    printf("ftello(closed fd)=%ld errno=%d\n", off, errno);
    fclose(fp);
    errno = 0;
    rc = remove(file);
    printf("remove(file) rc=%d errno=%d\n", rc, errno);
    return 0;
}
