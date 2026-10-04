/* Read errors reach every error check, and a closed standard stream is never
 * handed to host glibc.
 *
 * coreutils 9.5 tests under fl: uniq/tsort/shuf freopen a directory onto
 * stdin and check ferror via glibc's inline ferror_unlocked, which reads
 * _flags; fl did not mirror the error into the reopened std handle, so they
 * exited 0 (tests/misc/read-errors.sh). fscanf's read error looked like EOF.
 * After close_stdout's failed fclose(stdout), GNU error() calls
 * fflush(stdout); fl delegated the closed fl handle to host glibc, which
 * aborted with "invalid stdio handle" (false --version > /dev/full).
 * Output matches glibc.
 */
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>

int main(void) {
    FILE *f = fopen(".", "r");
    char buf[64];
    errno = 0;
    int r = fscanf(f, "%63s", buf);
    printf("fscanf(dir)=%d errno=%d ferror=%d ferror_unlocked=%d\n", r, errno, ferror(f), ferror_unlocked(f));
    fclose(f);

    if (!freopen(".", "r", stdin)) return 1;
    errno = 0;
    int c = getc_unlocked(stdin);
    printf("freopen(dir) getc=%d errno=%d ferror=%d ferror_unlocked=%d\n", c, errno, ferror(stdin),
           ferror_unlocked(stdin));
    fflush(stdout);

    /* A failed fclose(stdout) followed by fflush(stdout), as error() does. */
    FILE *full = freopen("/dev/full", "w", stdout);
    if (!full) return 1;
    fputs("this write fails on close\n", stdout);
    errno = 0;
    int rc = fclose(stdout);
    int e = errno;
    fflush(stdout); /* must not abort */
    fprintf(stderr, "fclose(/dev/full)=%d errno=%d; survived fflush after fclose\n", rc, e);
    return 0;
}
