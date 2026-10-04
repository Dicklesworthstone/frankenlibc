/* __fpurge leaves the position where glibc's ftell reports it, and freopen of
 * a standard stream returns that same FILE *.
 *
 * gnulib test-fpurge (sed 4.9 gnulib-tests) expects ftell == 4 after fflush at
 * 4 and two purged bytes; fl reported 6, and after purging read-ahead it
 * reported the consumed position although the next read was at EOF. gnulib
 * test-perror2 asserts freopen(path, "w+", stderr) == stderr; fl returned an
 * internal sentinel. Output matches glibc.
 */
#define _GNU_SOURCE
#include <stdio.h>
#include <stdio_ext.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

int main(void) {
    char path[] = "/tmp/fl_fpurge_XXXXXX";
    int fd = mkstemp(path);
    if (fd < 0) return 1;
    close(fd);

    FILE *fp = fopen(path, "w");
    fwrite("foobarsh", 1, 8, fp);
    fclose(fp);

    fp = fopen(path, "r+");
    fseek(fp, 3, SEEK_CUR);
    fwrite("g", 1, 1, fp);
    fflush(fp);
    fwrite("bz", 1, 2, fp);
    printf("pending=%zu ftell=%ld\n", __fpending(fp), ftell(fp));
    __fpurge(fp);
    printf("write purge: pending=%zu ftell=%ld\n", __fpending(fp), ftell(fp));
    fclose(fp);

    char buf[9] = {0};
    fp = fopen(path, "r");
    printf("read %zu content=%s\n", fread(buf, 1, 8, fp), buf);
    fclose(fp);

    fp = fopen(path, "r");
    int c = fgetc(fp);
    printf("fgetc=%c ftell=%ld\n", c, ftell(fp));
    __fpurge(fp);
    printf("read purge: ftell=%ld next=%d\n", ftell(fp), fgetc(fp));
    fclose(fp);

    FILE *orig = stderr;
    FILE *r = freopen(path, "w+", stderr);
    printf("freopen(stderr) same=%d fileno=%d\n", r == orig, r ? fileno(r) : -1);
    fputs("err-line", stderr);
    fflush(stderr);
    rewind(stderr);
    memset(buf, 0, sizeof buf);
    printf("stderr readback=%zu %s\n", fread(buf, 1, 8, stderr), buf);
    unlink(path);
    return 0;
}
