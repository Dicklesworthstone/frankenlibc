#define _GNU_SOURCE 1
#include <errno.h>
#include <stddef.h>
#include <stdio.h>
#include <stdio_ext.h>
#include <stdlib.h>
#include <string.h>
#include <sys/wait.h>
#include <unistd.h>
#include <wchar.h>

/* Compile with -O2: these calls must exercise the caller's glibc FILE macros,
 * not just an out-of-line fgetc/feof implementation in the candidate library.
 * Each constructor runs in its own process so a broken one cannot hide others.
 */
#define CHECK(test) do { \
    if (!(test)) { \
        dprintf(STDERR_FILENO, "%s:%d: %s (errno=%d)\n", \
                __func__, __LINE__, #test, errno); \
        return 1; \
    } \
} while (0)

static int check_header(FILE *f, int fd, int orientation) {
    CHECK(f != NULL);
    CHECK(((unsigned)f->_flags & 0xffff0000u) == 0xfbad0000u);
    CHECK(f->_fileno == fd);
    CHECK(!(f->_flags & 0x30));
    CHECK(!feof_unlocked(f));
    CHECK(!ferror_unlocked(f));
    CHECK(f->_mode == orientation);
    CHECK(f->_lock != NULL);
    return 0;
}

static int check_read(FILE *f) {
    CHECK(getc_unlocked(f) == 'a');
    CHECK(getc_unlocked(f) == 'b');
    CHECK(getc_unlocked(f) == EOF);
    CHECK(feof_unlocked(f));
    CHECK(f->_flags & 0x10);
    CHECK(!ferror_unlocked(f));
    CHECK(__freading(f));
    CHECK(f->_mode < 0);
    CHECK(ungetc('z', f) == 'z');
    CHECK(!feof_unlocked(f));
    CHECK(getc_unlocked(f) == 'z');
    CHECK(getc_unlocked(f) == EOF);
    clearerr(f);
    CHECK(!feof_unlocked(f));
    CHECK(!ferror_unlocked(f));
    CHECK(!(f->_flags & 0x30));
    return 0;
}

static int check_update(FILE *f) {
    CHECK(putc_unlocked('a', f) == 'a');
    CHECK(putc_unlocked('b', f) == 'b');
    CHECK(f->_mode < 0);
    CHECK(__fwriting(f));
    CHECK(ftell(f) == 2);
    CHECK(fflush(f) == 0);
    CHECK(__fpending(f) == 0);
    CHECK(fseek(f, 0, SEEK_SET) == 0);
    CHECK(check_read(f) == 0);
    CHECK(fclose(f) == 0);
    return 0;
}

static int check_fopen(void) {
    char path[] = "/tmp/frankenlibc-file-layout-XXXXXX";
    int fd = mkstemp(path);
    CHECK(fd >= 0);
    CHECK(close(fd) == 0);
    FILE *f = fopen(path, "w+");
    CHECK(f != NULL);
    CHECK(unlink(path) == 0);
    CHECK(check_header(f, fileno(f), 0) == 0);
    CHECK(fileno_unlocked(f) == fileno(f));
    return check_update(f);
}

static int check_fdopen(void) {
    char path[] = "/tmp/frankenlibc-fd-layout-XXXXXX";
    int fd = mkstemp(path);
    CHECK(fd >= 0);
    CHECK(unlink(path) == 0);
    FILE *f = fdopen(fd, "w+");
    CHECK(check_header(f, fd, 0) == 0);
    CHECK(fileno_unlocked(f) == fd);
    return check_update(f);
}

static int check_tmpfile(void) {
    FILE *f = tmpfile();
    CHECK(f != NULL);
    CHECK(check_header(f, fileno(f), 0) == 0);
    return check_update(f);
}

static int check_fmemopen(void) {
    char data[] = "ab";
    FILE *f = fmemopen(data, 2, "r");
    CHECK(check_header(f, -2, -1) == 0);
    CHECK(check_read(f) == 0);
    CHECK(fclose(f) == 0);
    return 0;
}

static int check_open_memstream(void) {
    char *data = NULL;
    size_t size = 0;
    FILE *f = open_memstream(&data, &size);
    /* glibc gives open_memstream byte orientation at creation. */
    CHECK(f != NULL);
    CHECK(((unsigned)f->_flags & 0xffff0000u) == 0xfbad0000u);
    CHECK(f->_fileno == 0 || f->_fileno == -1);
    CHECK(putc_unlocked('a', f) == 'a');
    CHECK(putc_unlocked('b', f) == 'b');
    CHECK(fflush(f) == 0);
    CHECK(size == 2 && memcmp(data, "ab\0", 3) == 0);
    CHECK(fclose(f) == 0);
    CHECK(size == 2 && memcmp(data, "ab\0", 3) == 0);
    free(data);
    return 0;
}

static int check_popen(void) {
    FILE *f = popen("printf ab", "r");
    CHECK(f != NULL);
    CHECK(check_header(f, fileno(f), -1) == 0);
    CHECK(check_read(f) == 0);
    int status = pclose(f);
    CHECK(status >= 0 && WIFEXITED(status) && WEXITSTATUS(status) == 0);
    return 0;
}

struct cookie { const char *text; size_t position; int closed; };
static ssize_t cookie_read(void *opaque, char *buf, size_t size) {
    struct cookie *c = opaque;
    size_t left = 2 - c->position;
    if (size > left) size = left;
    memcpy(buf, c->text + c->position, size);
    c->position += size;
    return (ssize_t)size;
}
static int cookie_close(void *opaque) {
    ((struct cookie *)opaque)->closed++;
    return 0;
}
static int check_fopencookie(void) {
    struct cookie c = {"ab", 0, 0};
    cookie_io_functions_t ops = {.read = cookie_read, .close = cookie_close};
    FILE *f = fopencookie(&c, "r", ops);
    CHECK(check_header(f, -2, -1) == 0);
    CHECK(check_read(f) == 0);
    CHECK(fclose(f) == 0);
    CHECK(c.closed == 1);
    return 0;
}

static int check_error(void) {
    FILE *f = fopen("/dev/null", "r");
    CHECK(f != NULL);
    CHECK(check_header(f, fileno(f), 0) == 0);
    CHECK(f->_flags & 0x8); /* _IO_NO_WRITES */
    errno = 0;
    CHECK(putc_unlocked('x', f) == EOF);
    CHECK(errno == EBADF);
    CHECK(ferror_unlocked(f));
    CHECK(f->_flags & 0x20);
    clearerr(f);
    CHECK(!ferror_unlocked(f));
    CHECK(fclose(f) == 0);
    return 0;
}

static int check_freopen(void) {
    FILE *f = tmpfile();
    CHECK(f != NULL);
    CHECK(putc_unlocked('x', f) == 'x');
    FILE *reopened = freopen("/dev/null", "r", f);
    CHECK(reopened == f);
    CHECK(check_header(reopened, fileno(reopened), 0) == 0);
    CHECK(getc_unlocked(reopened) == EOF);
    CHECK(feof_unlocked(reopened));
    CHECK(fclose(reopened) == 0);
    return 0;
}

static int check_reuse(void) {
    for (int i = 0; i < 200; ++i) {
        FILE *f = tmpfile();
        CHECK(f != NULL);
        CHECK(check_header(f, fileno(f), 0) == 0);
        CHECK(putc_unlocked('a', f) == 'a');
        CHECK(fclose(f) == 0);
    }
    return 0;
}

int main(int argc, char **argv) {
    struct { const char *name; int (*run)(void); } cases[] = {
        {"fopen", check_fopen}, {"fdopen", check_fdopen},
        {"tmpfile", check_tmpfile}, {"fmemopen", check_fmemopen},
        {"open_memstream", check_open_memstream}, {"popen", check_popen},
        {"fopencookie", check_fopencookie}, {"error", check_error},
        {"freopen", check_freopen}, {"reuse", check_reuse},
    };
    if (argc != 2) return 2;
    for (size_t i = 0; i < sizeof cases / sizeof *cases; ++i) {
        if (!strcmp(argv[1], cases[i].name)) {
            if (cases[i].run()) return 1;
            static const char ok[] = "stdio FILE layout: passed\n";
            return write(STDOUT_FILENO, ok, sizeof ok - 1) == sizeof ok - 1 ? 0 : 1;
        }
    }
    return 2;
}
