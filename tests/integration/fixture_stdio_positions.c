/* fixture_stdio_positions.c — FILE position semantics that fl got wrong until
 * 2026-09-28. Output must be byte-identical to glibc (strict and hardened):
 *  - "a+" reads from the start; writes land at the end and ftell reports it;
 *  - ftell on a pipe fails with ESPIPE;
 *  - fflush of a read stream moves the fd to the stream's position, so a
 *    child that inherits the fd reads right after what stdio consumed;
 *  - open_memstream truncates at the position on fclose;
 *  - stdout into a pipe is fully buffered (ordering against a raw write).
 */
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/wait.h>
#include <unistd.h>

int main(void) {
    char path[64];
    snprintf(path, sizeof path, "/tmp/fl_stdio_pos_%d", (int)getpid());

    FILE *f = fopen(path, "w");
    fputs("line one\nline two\nline three\n", f);
    fclose(f);

    f = fopen(path, "a+");
    char buf[64] = {0};
    fgets(buf, sizeof buf, f);
    printf("a+ first read: %s", buf);
    fputs("appended\n", f);
    printf("a+ ftell after append: %ld\n", ftell(f));
    fclose(f);

    int fds[2];
    if (pipe(fds) != 0) return 1;
    FILE *p = fdopen(fds[0], "r");
    errno = 0;
    long pos = ftell(p);
    printf("ftell on pipe: %ld %s\n", pos, errno == ESPIPE ? "ESPIPE" : strerror(errno));
    fclose(p);
    close(fds[1]);

    int fd = open(path, O_RDONLY);
    f = fdopen(fd, "r");
    fgets(buf, sizeof buf, f);
    printf("parent read: %s", buf);
    fflush(f);
    fflush(stdout);
    pid_t c = fork();
    if (c == 0) {
        char rest[16] = {0};
        ssize_t n = read(fd, rest, 8);
        printf("child read(8) after fflush: %.*s\n", (int)(n > 0 ? n : 0), rest);
        fflush(stdout);
        _exit(0);
    }
    waitpid(c, NULL, 0);
    fclose(f);

    char *ms = NULL;
    size_t sz = 0;
    FILE *m = open_memstream(&ms, &sz);
    fputs("abc123", m);
    fseek(m, 1, SEEK_SET);
    fputc('Q', m);
    fclose(m);
    printf("memstream after fclose: size=%zu [%s]\n", sz, ms);
    free(ms);

    int ofds[2];
    if (pipe(ofds) != 0) return 1;
    fflush(stdout);
    pid_t w = fork();
    if (w == 0) {
        dup2(ofds[1], 1);
        close(ofds[0]);
        printf("stdio first\n");
        if (write(1, "raw second\n", 11) != 11) _exit(1);
        exit(0);
    }
    close(ofds[1]);
    char order[64] = {0};
    ssize_t len = 0, n;
    while ((n = read(ofds[0], order + len, sizeof order - 1 - len)) > 0) len += n;
    waitpid(w, NULL, 0);
    for (char *q = order; *q; q++)
        if (*q == '\n') *q = '|';
    printf("stdout-to-pipe order: %s\n", order);

    unlink(path);
    return 0;
}
