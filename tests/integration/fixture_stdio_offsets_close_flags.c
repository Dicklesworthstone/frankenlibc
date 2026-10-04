/* Stream positions, close semantics and the caller-visible error bit, as
 * coreutils' gnulib close_stdin/close_stdout rely on (gnulib-tests: fclose,
 * closein, yesno, fseterr).
 *
 *  - stdin inherited mid-file starts at the descriptor's offset (fl started
 *    its logical offset at 0, so ftell lied and close synced to the wrong
 *    place);
 *  - fdopen starts at the descriptor's offset; fclose/fflush of an input
 *    stream leave the descriptor at the stream position;
 *  - fclose(stdin) closes fd 0 and reports EBADF if it was already closed;
 *  - ferror_unlocked (an inline _flags read) sees a read error, and a bit set
 *    in _flags from outside (gnulib fseterr) shows in ferror until clearerr.
 * Output matches glibc.
 */
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

int main(void) {
    char path[] = "/tmp/fl_stdio_offsets_XXXXXX";
    int fd = mkstemp(path);
    if (fd < 0) return 1;
    if (write(fd, "line1\nline2\nline3\n", 18) != 18) return 1;
    /* Hand stdin a descriptor already at offset 6, before any stdio use. */
    lseek(fd, 6, SEEK_SET);
    dup2(fd, 0);
    char buf[32];
    if (!fgets(buf, sizeof buf, stdin)) return 1;
    long after = ftell(stdin);
    printf("stdin fgets=%s", buf);
    printf("stdin ftell=%ld\n", after);

    /* fdopen at offset 1; one fgetc; close leaves the fd at 2. */
    lseek(fd, 1, SEEK_SET);
    int fd2 = dup(fd);
    FILE *f = fdopen(fd2, "r");
    int c = fgetc(f);
    long t = ftell(f);
    int rc = fclose(f);
    printf("fdopen fgetc=%c ftell=%ld fclose=%d fd at %ld\n", c, t, rc, (long)lseek(fd, 0, SEEK_CUR));
    fd2 = dup(fd);
    f = fdopen(fd2, "r");
    c = fgetc(f);
    rc = fflush(f);
    printf("fdopen fgetc=%c fflush=%d fd at %ld\n", c, rc, (long)lseek(fd2, 0, SEEK_CUR));
    fclose(f);

    /* External error bit (gnulib fseterr) and clearerr. */
    stdout->_flags |= 0x20; /* _IO_ERR_SEEN */
    int e1 = ferror(stdout);
    clearerr(stdout);
    int e2 = ferror(stdout);
    printf("fseterr ferror=%d after clearerr=%d\n", e1, e2);

    /* A read error on a closed stdin reaches the inline ferror_unlocked:
     * drain the buffered rest, clear EOF, then read from the closed fd. */
    while (fgets(buf, sizeof buf, stdin))
        ;
    clearerr(stdin);
    close(0);
    errno = 0;
    size_t n = fread(buf, 1, 6, stdin);
    int ferr = ferror_unlocked(stdin);
    errno = 0;
    rc = fclose(stdin);
    printf("closed stdin fread=%zu ferror_unlocked=%d fclose=%d errno=%d\n", n, ferr, rc, errno);
    unlink(path);
    return 0;
}
