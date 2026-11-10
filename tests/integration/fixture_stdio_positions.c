/* fixture_stdio_positions.c — FILE position semantics that fl got wrong until
 * 2026-09-28. Output must be byte-identical to glibc (strict and hardened):
 *  - "a+" reads from the start; writes land at the end and ftell reports it;
 *  - ftell on a pipe fails with ESPIPE;
 *  - fflush of a read stream moves the fd to the stream's position, so a
 *    child that inherits the fd reads right after what stdio consumed;
 *  - open_memstream truncates at the position on fclose;
 *  - stdout into a pipe is fully buffered (ordering against a raw write).
 */
#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <locale.h>
#include <stdint.h>
#include <stdio_ext.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <unistd.h>
#include <wchar.h>

static int position_checks;
#define POSITION_CHECK(expr) do { \
    if (!(expr)) { \
        fprintf(stderr, "position check failed at line %d: %s (errno=%d)\n", \
                __LINE__, #expr, errno); \
        return 1; \
    } \
    ++position_checks; \
} while (0)

struct position_cookie {
    off64_t position;
    size_t end;
    char bytes[32];
    unsigned writes;
    int seek_error;
};

static struct position_cookie new_position_cookie(void) {
    struct position_cookie state = {0, 0, {0}, 0, 0};
    state.position = 4;
    state.end = 10;
    memcpy(state.bytes, "ABCDEFGHIJ", 10);
    return state;
}

static ssize_t position_read(void *opaque, char *dst, size_t count) {
    struct position_cookie *state = (struct position_cookie *)opaque;
    size_t position = (size_t)state->position;
    size_t available = position < state->end ? state->end - position : 0;
    if (count > available) count = available;
    if (count) memcpy(dst, state->bytes + position, count);
    state->position += (off64_t)count;
    return (ssize_t)count;
}

static ssize_t position_write(void *opaque, const char *src, size_t count) {
    struct position_cookie *state = (struct position_cookie *)opaque;
    size_t position = (size_t)state->position;
    size_t available = position < sizeof state->bytes ? sizeof state->bytes - position : 0;
    if (count > available) count = available;
    if (count) memcpy(state->bytes + position, src, count);
    state->position += (off64_t)count;
    if ((size_t)state->position > state->end) state->end = (size_t)state->position;
    ++state->writes;
    return (ssize_t)count;
}

static int position_seek(void *opaque, off64_t *offset, int whence) {
    struct position_cookie *state = (struct position_cookie *)opaque;
    if (state->seek_error) {
        errno = state->seek_error;
        return -1;
    }
    off64_t base = whence == SEEK_CUR ? state->position : whence == SEEK_END ? (off64_t)state->end : 0;
    if (whence < SEEK_SET || whence > SEEK_END || *offset < -base ||
        *offset > INT64_MAX - base) {
        errno = EINVAL;
        return -1;
    }
    state->position = base + *offset;
    *offset = state->position;
    return 0;
}

static int untouched_position(const void *position, size_t size) {
    const unsigned char *bytes = (const unsigned char *)position;
    for (size_t i = 0; i < size; ++i) if (bytes[i] != 0xa5) return 0;
    return 1;
}

static int check_saved_positions(void) {
    /* Both an uncached and a read-cached unseekable stream must fail without
       publishing any part of the opaque output or setting its I/O error bit. */
    for (int socket = 0; socket < 2; ++socket) {
        int descriptors[2];
        POSITION_CHECK((socket ? socketpair(AF_UNIX, SOCK_STREAM, 0, descriptors) : pipe(descriptors)) == 0);
        POSITION_CHECK(write(descriptors[1], "Q", 1) == 1);
        FILE *stream = fdopen(descriptors[0], "r");
        POSITION_CHECK(stream != NULL);
        for (int warm = 0; warm < 2; ++warm) {
            if (warm) POSITION_CHECK(fgetc(stream) == 'Q');
            fpos_t position;
            memset(&position, 0xa5, sizeof position);
            errno = 0;
            POSITION_CHECK(fgetpos(stream, &position) == -1 && errno == ESPIPE);
            POSITION_CHECK(untouched_position(&position, sizeof position) && !ferror(stream));
            fpos64_t position64;
            memset(&position64, 0xa5, sizeof position64);
            errno = 0;
            POSITION_CHECK(fgetpos64(stream, &position64) == -1 && errno == ESPIPE);
            POSITION_CHECK(untouched_position(&position64, sizeof position64) && !ferror(stream));
        }
        POSITION_CHECK(fclose(stream) == 0);
        POSITION_CHECK(close(descriptors[1]) == 0);
    }

    FILE *seed = tmpfile();
    POSITION_CHECK(seed != NULL && fwrite("ABCDEF", 1, 6, seed) == 6 && fflush(seed) == 0);
    int descriptor = dup(fileno(seed));
    POSITION_CHECK(descriptor >= 0 && lseek(descriptor, 0, SEEK_SET) == 0);
    FILE *append = fdopen(descriptor, "a+");
    POSITION_CHECK(append != NULL && fwrite("XY", 1, 2, append) == 2);
    struct stat status;
    POSITION_CHECK(fstat(descriptor, &status) == 0 && status.st_size == 6);
    fpos_t saved;
    fpos64_t saved64;
    POSITION_CHECK(fgetpos(append, &saved) == 0 && ftell(append) == 8);
    POSITION_CHECK(fgetpos64(append, &saved64) == 0 && ftello64(append) == 8);
    POSITION_CHECK(fstat(descriptor, &status) == 0 && status.st_size == 6 && __fpending(append) == 2);
    POSITION_CHECK(lseek(descriptor, 0, SEEK_CUR) == 6);
    POSITION_CHECK(fwrite("Z", 1, 1, append) == 1);
    POSITION_CHECK(fsetpos(append, &saved) == 0 && fgetc(append) == 'Z');
    POSITION_CHECK(fsetpos64(append, &saved64) == 0 && fgetc(append) == 'Z');
    POSITION_CHECK(fclose(append) == 0 && fclose(seed) == 0);

    cookie_io_functions_t callbacks = {position_read, position_write, position_seek, NULL};
    struct position_cookie cookie = new_position_cookie();
    FILE *stream = fopencookie(&cookie, "r+", callbacks);
    POSITION_CHECK(stream != NULL && fgetpos(stream, &saved) == 0 && ftell(stream) == 4);
    POSITION_CHECK(fgetc(stream) == 'E' && ungetc('X', stream) == 'X' && ftello64(stream) == 4);
    POSITION_CHECK(fseek(stream, 0, SEEK_CUR) == 0 && fgetc(stream) == 'E');
    POSITION_CHECK(fsetpos(stream, &saved) == 0 && fgetc(stream) == 'E');
    POSITION_CHECK(ungetc('Y', stream) == 'Y');
    cookie.seek_error = EACCES;
    fpos_t failed;
    memset(&failed, 0xa5, sizeof failed);
    errno = 0;
    POSITION_CHECK(fgetpos(stream, &failed) == -1 && errno == EACCES);
    POSITION_CHECK(untouched_position(&failed, sizeof failed) && !ferror(stream));
    POSITION_CHECK(fgetc(stream) == 'Y');
    errno = 0;
    POSITION_CHECK(fsetpos(stream, &saved) == -1 && errno == EACCES && !ferror(stream));
    cookie.seek_error = 0;
    POSITION_CHECK(fsetpos(stream, &saved) == 0 && fgetc(stream) == 'E');
    POSITION_CHECK(fclose(stream) == 0);

    for (int appending = 0; appending < 2; ++appending) {
        cookie = new_position_cookie();
        stream = fopencookie(&cookie, appending ? "a" : "w", callbacks);
        POSITION_CHECK(stream != NULL && fwrite("XY", 1, 2, stream) == 2);
        POSITION_CHECK(fgetpos64(stream, &saved64) == 0);
        POSITION_CHECK(ftell(stream) == (appending ? 12 : 6));
        POSITION_CHECK(cookie.writes == 0 && memcmp(cookie.bytes, "ABCDEFGHIJ", 10) == 0);
        POSITION_CHECK(fsetpos64(stream, &saved64) == 0 && cookie.position == (appending ? 12 : 6));
        POSITION_CHECK(cookie.writes == 1 && fclose(stream) == 0);
    }

    cookie = new_position_cookie();
    cookie.position = INT64_MAX - 1;
    stream = fopencookie(&cookie, "w", callbacks);
    POSITION_CHECK(stream != NULL && fwrite("XY", 1, 2, stream) == 2);
    memset(&failed, 0xa5, sizeof failed);
    errno = 0;
    POSITION_CHECK(fgetpos(stream, &failed) == -1 && errno == EINVAL);
    POSITION_CHECK(untouched_position(&failed, sizeof failed) && !ferror(stream));
    memset(&saved64, 0xa5, sizeof saved64);
    errno = 0;
    POSITION_CHECK(fgetpos64(stream, &saved64) == -1 && errno == EINVAL);
    POSITION_CHECK(untouched_position(&saved64, sizeof saved64) && !ferror(stream));
    POSITION_CHECK(cookie.writes == 0 && memcmp(cookie.bytes, "ABCDEFGHIJ", 10) == 0);
    cookie.position = 4;
    POSITION_CHECK(fclose(stream) == 0);

    callbacks.seek = NULL;
    cookie = new_position_cookie();
    stream = fopencookie(&cookie, "r", callbacks);
    POSITION_CHECK(stream != NULL);
    memset(&failed, 0xa5, sizeof failed);
    errno = 0;
    POSITION_CHECK(fgetpos(stream, &failed) == -1 && errno == EIO);
    POSITION_CHECK(untouched_position(&failed, sizeof failed) && !ferror(stream));
    errno = EDOM;
    POSITION_CHECK(ftell(stream) == -1 && errno == EDOM);
    POSITION_CHECK(fclose(stream) == 0);

    /* Saved positions must restore wide input at multibyte boundaries and
       clear EOF before the next wide read. */
    POSITION_CHECK(setlocale(LC_CTYPE, "C.UTF-8") != NULL);
    seed = tmpfile();
    const char wide_bytes[] = "A\xc3\xa9\xf0\x9f\x98\x80Z";
    POSITION_CHECK(seed != NULL);
    POSITION_CHECK(write(fileno(seed), wide_bytes, sizeof wide_bytes - 1) == (ssize_t)(sizeof wide_bytes - 1));
    POSITION_CHECK(lseek(fileno(seed), 0, SEEK_SET) == 0);
    POSITION_CHECK(fgetwc(seed) == L'A' && fgetpos(seed, &saved) == 0);
    POSITION_CHECK(fgetwc(seed) == 0xe9 && fgetpos64(seed, &saved64) == 0);
    POSITION_CHECK(fgetwc(seed) == 0x1f600 && fgetwc(seed) == L'Z' && fgetwc(seed) == WEOF && feof(seed));
    POSITION_CHECK(fsetpos(seed, &saved) == 0 && !feof(seed) && fgetwc(seed) == 0xe9);
    POSITION_CHECK(fsetpos64(seed, &saved64) == 0 && fgetwc(seed) == 0x1f600);
    POSITION_CHECK(fclose(seed) == 0 && setlocale(LC_CTYPE, "C") != NULL);

    printf("saved position contracts: %d passed\n", position_checks);
    return 0;
}

int main(void) {
    if (check_saved_positions() != 0) return 1;
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
