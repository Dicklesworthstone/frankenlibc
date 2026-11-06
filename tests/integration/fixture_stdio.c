/* fixture_stdio.c — stdio phase-1 stream operations under LD_PRELOAD
 * Part of frankenlibc C fixture suite.
 * Exit 0 = PASS, nonzero = FAIL with diagnostic to stderr.
 */
#define _GNU_SOURCE
#include <dlfcn.h>
#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <pthread.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/resource.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/time.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>
#include <wchar.h>

static int make_temp_path(char path[64]) {
    strcpy(path, "/tmp/frankenlibc_fixture_stdio_XXXXXX");
    int fd = mkstemp(path);
    if (fd < 0) {
        fprintf(stderr, "FAIL: mkstemp: %s\n", strerror(errno));
        return 1;
    }
    close(fd);
    return 0;
}

static int test_fopen_fileno_setvbuf_setbuf(void) {
    char path[64];
    if (make_temp_path(path) != 0) {
        return 1;
    }

    FILE *fp = fopen(path, "w+");
    if (fp == NULL) {
        fprintf(stderr, "FAIL: fopen w+: %s\n", strerror(errno));
        unlink(path);
        return 1;
    }

    if (fileno(fp) < 0) {
        fprintf(stderr, "FAIL: fileno returned negative fd\n");
        fclose(fp);
        unlink(path);
        return 1;
    }

    if (setvbuf(fp, NULL, _IONBF, 0) != 0) {
        fprintf(stderr, "FAIL: setvbuf(_IONBF) before I/O failed\n");
        fclose(fp);
        unlink(path);
        return 1;
    }

    setbuf(fp, NULL);

    fclose(fp);
    unlink(path);
    return 0;
}

static int test_fputs_fputc_fflush_and_fread_roundtrip(void) {
    char path[64];
    if (make_temp_path(path) != 0) {
        return 1;
    }

    FILE *fp = fopen(path, "w+");
    if (fp == NULL) {
        fprintf(stderr, "FAIL: fopen w+ for write path: %s\n", strerror(errno));
        unlink(path);
        return 1;
    }

    if (fputs("alpha", fp) == EOF) {
        fprintf(stderr, "FAIL: fputs failed\n");
        fclose(fp);
        unlink(path);
        return 1;
    }
    if (fputc('!', fp) == EOF) {
        fprintf(stderr, "FAIL: fputc failed\n");
        fclose(fp);
        unlink(path);
        return 1;
    }
    if (fflush(fp) != 0) {
        fprintf(stderr, "FAIL: fflush failed\n");
        fclose(fp);
        unlink(path);
        return 1;
    }
    fclose(fp);

    fp = fopen(path, "r");
    if (fp == NULL) {
        fprintf(stderr, "FAIL: fopen r for verify path: %s\n", strerror(errno));
        unlink(path);
        return 1;
    }

    char buf[16] = {0};
    size_t n = fread(buf, 1, sizeof(buf) - 1, fp);
    buf[n] = '\0';
    if (strcmp(buf, "alpha!") != 0) {
        fprintf(stderr, "FAIL: fread mismatch: got '%s'\n", buf);
        fclose(fp);
        unlink(path);
        return 1;
    }

    fclose(fp);
    unlink(path);
    return 0;
}

static int test_fgets_fgetc_ungetc_sequence(void) {
    char path[64];
    if (make_temp_path(path) != 0) {
        return 1;
    }

    FILE *fp = fopen(path, "w+");
    if (fp == NULL) {
        fprintf(stderr, "FAIL: fopen w+ for fgets path: %s\n", strerror(errno));
        unlink(path);
        return 1;
    }
    if (fputs("abc\nxyz", fp) == EOF) {
        fprintf(stderr, "FAIL: fputs fixture payload failed\n");
        fclose(fp);
        unlink(path);
        return 1;
    }
    if (fflush(fp) != 0) {
        fprintf(stderr, "FAIL: fflush fixture payload failed\n");
        fclose(fp);
        unlink(path);
        return 1;
    }
    fclose(fp);

    fp = fopen(path, "r");
    if (fp == NULL) {
        fprintf(stderr, "FAIL: fopen r for fgets path: %s\n", strerror(errno));
        unlink(path);
        return 1;
    }

    char line[16] = {0};
    if (fgets(line, (int)sizeof(line), fp) == NULL) {
        fprintf(stderr, "FAIL: fgets returned NULL\n");
        fclose(fp);
        unlink(path);
        return 1;
    }
    if (strcmp(line, "abc\n") != 0) {
        fprintf(stderr, "FAIL: fgets line mismatch: got '%s'\n", line);
        fclose(fp);
        unlink(path);
        return 1;
    }

    int ch = fgetc(fp);
    if (ch != 'x') {
        fprintf(stderr, "FAIL: fgetc expected 'x', got %d\n", ch);
        fclose(fp);
        unlink(path);
        return 1;
    }
    if (ungetc(ch, fp) == EOF) {
        fprintf(stderr, "FAIL: ungetc returned EOF\n");
        fclose(fp);
        unlink(path);
        return 1;
    }
    if (fgetc(fp) != 'x') {
        fprintf(stderr, "FAIL: fgetc after ungetc mismatch\n");
        fclose(fp);
        unlink(path);
        return 1;
    }

    char tail[4] = {0};
    size_t n = fread(tail, 1, 2, fp);
    tail[n] = '\0';
    if (n != 2 || strcmp(tail, "yz") != 0) {
        fprintf(stderr, "FAIL: fread tail mismatch: n=%zu tail='%s'\n", n, tail);
        fclose(fp);
        unlink(path);
        return 1;
    }

    fclose(fp);
    unlink(path);
    return 0;
}

static int test_invalid_mode_and_ungetc_eof(void) {
    char path[64];
    if (make_temp_path(path) != 0) {
        return 1;
    }

    FILE *bad = fopen(path, "z");
    if (bad != NULL) {
        fprintf(stderr, "FAIL: fopen with invalid mode unexpectedly succeeded\n");
        fclose(bad);
        unlink(path);
        return 1;
    }

    FILE *fp = fopen(path, "w+");
    if (fp == NULL) {
        fprintf(stderr, "FAIL: fopen w+ for ungetc EOF path failed: %s\n", strerror(errno));
        unlink(path);
        return 1;
    }
    if (ungetc(EOF, fp) != EOF) {
        fprintf(stderr, "FAIL: ungetc(EOF) expected EOF return\n");
        fclose(fp);
        unlink(path);
        return 1;
    }

    fclose(fp);
    unlink(path);
    return 0;
}

static int test_setvbuf_rejects_post_io_change(void) {
    char path[64];
    if (make_temp_path(path) != 0) {
        return 1;
    }

    FILE *fp = fopen(path, "w+");
    if (fp == NULL) {
        fprintf(stderr, "FAIL: fopen w+ for setvbuf-after-io path failed: %s\n", strerror(errno));
        unlink(path);
        return 1;
    }
    if (fputc('A', fp) == EOF) {
        fprintf(stderr, "FAIL: fputc setup failed\n");
        fclose(fp);
        unlink(path);
        return 1;
    }

    /* Per glibc iosetvbuf.c (bd-bjcusw), valid setvbuf after I/O flushes and succeeds,
     * while an invalid mode after I/O is rejected. */
    if (setvbuf(fp, NULL, _IOFBF, 128) != 0) {
        fprintf(stderr, "FAIL: setvbuf(_IOFBF) after I/O failed\n");
        fclose(fp);
        unlink(path);
        return 1;
    }
    if (setvbuf(fp, NULL, -999, 128) == 0) {
        fprintf(stderr, "FAIL: setvbuf with invalid mode after I/O unexpectedly succeeded\n");
        fclose(fp);
        unlink(path);
        return 1;
    }

    fclose(fp);
    unlink(path);
    return 0;
}

static int test_fread_fwrite_zero_size_contract(void) {
    char path[64];
    if (make_temp_path(path) != 0) {
        return 1;
    }

    FILE *fp = fopen(path, "w+");
    if (fp == NULL) {
        fprintf(stderr, "FAIL: fopen w+ for zero-size path failed: %s\n", strerror(errno));
        unlink(path);
        return 1;
    }

    const char *data = "z";
    if (fwrite(data, 0, 1, fp) != 0 || fwrite(data, 1, 0, fp) != 0) {
        fprintf(stderr, "FAIL: fwrite zero-sized contract violated\n");
        fclose(fp);
        unlink(path);
        return 1;
    }

    char buf[4] = {0};
    if (fread(buf, 0, 1, fp) != 0 || fread(buf, 1, 0, fp) != 0) {
        fprintf(stderr, "FAIL: fread zero-sized contract violated\n");
        fclose(fp);
        unlink(path);
        return 1;
    }

    fclose(fp);
    unlink(path);
    return 0;
}

static int test_fprintf_fscanf_fseek_roundtrip(void) {
    char path[64];
    if (make_temp_path(path) != 0) {
        return 1;
    }

    FILE *fp = fopen(path, "w+");
    if (fp == NULL) {
        fprintf(stderr, "FAIL: fopen w+ for formatted roundtrip failed: %s\n", strerror(errno));
        unlink(path);
        return 1;
    }

    int written = fprintf(fp, "name=%s count=%d\n", "beta", 42);
    if (written != 19) {
        fprintf(stderr, "FAIL: fprintf formatted length expected 19 got %d\n", written);
        fclose(fp);
        unlink(path);
        return 1;
    }
    if (fflush(fp) != 0) {
        fprintf(stderr, "FAIL: fflush formatted roundtrip failed\n");
        fclose(fp);
        unlink(path);
        return 1;
    }
    if (fseek(fp, 0, SEEK_SET) != 0) {
        fprintf(stderr, "FAIL: fseek rewind formatted roundtrip failed\n");
        fclose(fp);
        unlink(path);
        return 1;
    }

    char name[16] = {0};
    int count = 0;
    int scanned = fscanf(fp, "name=%15s count=%d", name, &count);
    if (scanned != 2 || strcmp(name, "beta") != 0 || count != 42) {
        fprintf(
            stderr,
            "FAIL: fscanf formatted roundtrip scanned=%d name='%s' count=%d\n",
            scanned,
            name,
            count
        );
        fclose(fp);
        unlink(path);
        return 1;
    }

    fclose(fp);
    unlink(path);
    return 0;
}

/* GNU callback table is passed by value. A Rust-only signature comparison
 * cannot establish this contract; compile this caller against system headers. */
struct interrupted_cookie {
    size_t delivered;
    int interrupted;
    int closed;
};

static ssize_t read_then_eintr(void *opaque, char *buf, size_t count) {
    struct interrupted_cookie *cookie = opaque;
    if (cookie->delivered < 3) {
        size_t n = 3 - cookie->delivered;
        if (n > count) n = count;
        memcpy(buf, "abc" + cookie->delivered, n);
        cookie->delivered += n;
        return (ssize_t)n;
    }
    if (!cookie->interrupted) {
        cookie->interrupted = 1;
        errno = EINTR;
        return -1;
    }
    /* Make an erroneous retry observable rather than hanging the fixture. */
    if (count) buf[0] = 'X';
    return count ? 1 : 0;
}

static int close_interrupted_cookie(void *opaque) {
    ((struct interrupted_cookie *)opaque)->closed++;
    return 0;
}

static int test_cookie_mid_read_eintr(int mode) {
    struct interrupted_cookie cookie = {0};
    cookie_io_functions_t hooks = {
        .read = read_then_eintr,
        .close = close_interrupted_cookie,
    };
    FILE *stream = fopencookie(&cookie, "r", hooks);
    if (!stream) return 1;
    if (setvbuf(stream, NULL, mode, 0)) {
        fclose(stream);
        return 1;
    }
    unsigned char out[8];
    memset(out, 0xA5, sizeof(out));
    errno = 0x5EED;
    size_t n = fread(out, 1, sizeof(out), stream);
    int saved_errno = errno;
    int error = ferror(stream) != 0;
    int eof = feof(stream) != 0;
    int closed = fclose(stream);
    printf("cookie mode=%s n=%zu errno=%d error=%d eof=%d close=%d hooks_closed=%d bytes=",
           mode == _IONBF ? "unbuffered" : "buffered", n, saved_errno,
           error, eof, closed, cookie.closed);
    for (size_t i = 0; i < sizeof(out); ++i) printf("%02x", out[i]);
    putchar('\n');
    const unsigned char expected[8] = {'a', 'b', 'c', 0xA5, 0xA5, 0xA5, 0xA5, 0xA5};
    return n != 3 || saved_errno != EINTR || !error || eof || closed ||
           cookie.closed != 1 || memcmp(out, expected, sizeof(out));
}

/* A scanf read-ahead suffix must remain visible through both character and
 * block input on a callback stream, which has no backing file descriptor. */
struct scanf_cookie {
    size_t position;
};

static ssize_t read_scanf_cookie(void *opaque, char *buf, size_t count) {
    struct scanf_cookie *cookie = opaque;
    const char input[] = "12 34XYZ";
    size_t available = sizeof(input) - 1 - cookie->position;
    if (count > available) count = available;
    memcpy(buf, input + cookie->position, count);
    cookie->position += count;
    return (ssize_t)count;
}

static int test_cookie_scanf_preserves_unread_suffix(void) {
    struct scanf_cookie cookie = {0};
    cookie_io_functions_t hooks = {.read = read_scanf_cookie};
    FILE *stream = fopencookie(&cookie, "r", hooks);
    if (!stream) return 1;
    int first = -1, second = -1;
    int first_count = fscanf(stream, "%d", &first);
    int second_count = fscanf(stream, "%d", &second);
    int next = fgetc(stream);
    char suffix[2] = {0};
    size_t remaining = fread(suffix, 1, sizeof(suffix), stream);
    int error = ferror(stream) != 0;
    int closed = fclose(stream);
    if (first_count != 1 || first != 12 || second_count != 1 || second != 34 ||
        next != 'X' || remaining != 2 || memcmp(suffix, "YZ", 2) || error || closed) {
        fprintf(stderr, "FAIL: cookie scanf counts=%d,%d values=%d,%d next=%d remaining=%zu error=%d close=%d\n",
                first_count, second_count, first, second, next, remaining, error, closed);
        return 1;
    }
    return 0;
}

static int check_stdio_providers(const char *expected, const char *const *symbols,
                                 size_t count) {
    struct stat wanted;
    if (stat(expected, &wanted)) return 1;
    int failed = 0;
    for (size_t i = 0; i < count; ++i) {
        Dl_info info;
        void *address = dlsym(RTLD_DEFAULT, symbols[i]);
        if (!address || !dladdr(address, &info)) { failed = 1; break; }
        struct stat actual;
        fprintf(stderr, "provider %s=%s\n", symbols[i], info.dli_fname);
        if (stat(info.dli_fname, &actual)) {
            fprintf(stderr, "FAIL: cannot resolve stdio provider path for %s\n", symbols[i]);
            failed = 1;
        } else if (actual.st_dev != wanted.st_dev || actual.st_ino != wanted.st_ino) {
            fprintf(stderr, "FAIL: wrong stdio provider for %s\n", symbols[i]);
            failed = 1;
        }
    }
    return failed;
}

/* Line input must use the cookie hooks, including short reads and errors;
 * these streams intentionally have no kernel descriptor to read from. */
struct line_cookie {
    const unsigned char *data;
    size_t length, position;
    int error, calls, closed;
};

static ssize_t read_line_cookie(void *opaque, char *buf, size_t count) {
    struct line_cookie *cookie = opaque;
    ++cookie->calls;
    size_t available = cookie->length - cookie->position;
    if (available) {
        if (count > available) count = available;
        if (count > 3) count = 3; /* force multiple successful callbacks */
        memcpy(buf, cookie->data + cookie->position, count);
        cookie->position += count;
        return (ssize_t)count;
    }
    if (cookie->error) {
        errno = cookie->error;
        return -1;
    }
    return 0;
}

static int close_line_cookie(void *opaque) {
    ++((struct line_cookie *)opaque)->closed;
    return 0;
}

typedef ssize_t (*cookie_getline_fn)(char **, size_t *, FILE *);
typedef ssize_t (*cookie_getdelim_fn)(char **, size_t *, int, FILE *);
static cookie_getline_fn cookie_getline;
static cookie_getdelim_fn cookie_getdelim, cookie_getdelim_alias;

static ssize_t cookie_line_call(int api, char **line, size_t *capacity, FILE *stream) {
    if (api == 0) return cookie_getline(line, capacity, stream);
    if (api == 1) return cookie_getdelim(line, capacity, ';', stream);
    return cookie_getdelim_alias(line, capacity, api == 2 ? '\n' : ';', stream);
}

static int test_cookie_line_reads(void) {
    /* Resolve before planting errno, and call exact public entrypoints instead
     * of letting a glibc header inline getline as __getdelim. */
    cookie_getline = (cookie_getline_fn)dlsym(RTLD_DEFAULT, "getline");
    cookie_getdelim = (cookie_getdelim_fn)dlsym(RTLD_DEFAULT, "getdelim");
    cookie_getdelim_alias = (cookie_getdelim_fn)dlsym(RTLD_DEFAULT, "__getdelim");
    if (!cookie_getline || !cookie_getdelim || !cookie_getdelim_alias) return 1;
    int failed = 0, cases = 0;
    for (int api = 0; api < 4; ++api) {
        for (int unbuffered = 0; unbuffered < 2; ++unbuffered) {
            unsigned char payload[] = {'a', 0, 'b', '\n', 'n', 'e', 'x', 't', '\n', 'l', 'a', 's', 't'};
            unsigned char delimiter = api % 2 ? ';' : '\n';
            payload[3] = payload[8] = delimiter;
            struct line_cookie cookie = {.data = payload, .length = sizeof(payload)};
            FILE *stream = fopencookie(&cookie, "r", (cookie_io_functions_t){
                .read = read_line_cookie, .close = close_line_cookie});
            if (!stream) return 1;
            int bad = setvbuf(stream, NULL, unbuffered ? _IONBF : _IOFBF, 0) != 0;
            bad |= ungetc('P', stream) != 'P';
            char *line = malloc(2);
            size_t capacity = 2;
            if (!line) { fclose(stream); return 1; }
            ssize_t length = cookie_line_call(api, &line, &capacity, stream);
            const unsigned char first[] = {'P', 'a', 0, 'b', delimiter, 0};
            bad |= length != 5 || capacity < 6 || memcmp(line, first, sizeof(first));
            bad |= ferror(stream) != 0 || feof(stream) != 0;
            length = cookie_line_call(api, &line, &capacity, stream);
            const unsigned char second[] = {'n', 'e', 'x', 't', delimiter, 0};
            bad |= length != 5 || capacity < 6 || memcmp(line, second, sizeof(second));
            length = cookie_line_call(api, &line, &capacity, stream);
            bad |= length != 4 || capacity < 5 || memcmp(line, "last", 5) || !feof(stream) || ferror(stream);
            int calls_at_eof = cookie.calls;
            bad |= fgetc(stream) != EOF;
            bad |= cookie.calls != calls_at_eof;
            bad |= cookie_line_call(api, &line, &capacity, stream) != -1;
            bad |= cookie.calls != calls_at_eof;
            clearerr(stream);
            cookie.position = 0;
            bad |= cookie_line_call(api, &line, &capacity, stream) != 4;
            bad |= !line || capacity < 5 || memcmp(line, payload, 4) || line[4] != 0 ||
                   ferror(stream) || feof(stream);
            free(line);
            bad |= fclose(stream) != 0 || cookie.closed != 1;
            printf("cookie-lines api=%d unbuffered=%d sequence=%s\n", api, unbuffered, bad ? "FAIL" : "PASS");
            failed += bad != 0; ++cases;

            for (int error_case = 0; error_case < 4; ++error_case) {
                for (int partial = 0; partial < 2; ++partial) {
                    const int errors[] = {0, EINTR, EAGAIN, EIO};
                    struct line_cookie error_cookie = {
                        .data = (const unsigned char *)"abc", .length = partial ? 3 : 0,
                        .error = errors[error_case]};
                    stream = fopencookie(&error_cookie, "r", (cookie_io_functions_t){
                        .read = read_line_cookie, .close = close_line_cookie});
                    if (!stream) return 1;
                    bad = setvbuf(stream, NULL, unbuffered ? _IONBF : _IOFBF, 0) != 0;
                    line = NULL; capacity = 0;
                    errno = 0x5EED;
                    length = cookie_line_call(api, &line, &capacity, stream);
                    int saved_errno = errno;
                    bad |= length != (partial ? 3 : -1);
                    bad |= saved_errno != (error_case ? errors[error_case] : 0x5EED);
                    bad |= !!ferror(stream) != !!error_case || !!feof(stream) != !error_case;
                    if (partial) bad |= !line || capacity < 4 || memcmp(line, "abc", 4);
                    int calls_at_stop = error_cookie.calls;
                    errno = 0x5EED;
                    bad |= cookie_line_call(api, &line, &capacity, stream) != -1;
                    bad |= error_cookie.calls != calls_at_stop || errno != 0x5EED;
                    clearerr(stream);
                    error_cookie.position = 0; error_cookie.length = 3; error_cookie.error = 0;
                    bad |= cookie_line_call(api, &line, &capacity, stream) != 3;
                    bad |= !line || capacity < 4 || memcmp(line, "abc", 4) ||
                           !feof(stream) || ferror(stream);
                    free(line);
                    bad |= fclose(stream) != 0 || error_cookie.closed != 1;
                    printf("cookie-lines api=%d unbuffered=%d error=%d partial=%d result=%s\n",
                           api, unbuffered, errors[error_case], partial, bad ? "FAIL" : "PASS");
                    failed += bad != 0; ++cases;
                }
            }

            struct line_cookie fresh = {.data = payload, .length = sizeof(payload)};
            stream = fopencookie(&fresh, "r", (cookie_io_functions_t){
                .read = read_line_cookie, .close = close_line_cookie});
            if (!stream) return 1;
            bad = setvbuf(stream, NULL, unbuffered ? _IONBF : _IOFBF, 0) != 0;
            line = NULL;
            size_t fresh_capacity; /* Output-only when line is NULL. */
            errno = 0x5EED;
            length = cookie_line_call(api, &line, &fresh_capacity, stream);
            bad |= length != 4 || errno != 0x5EED || !line || fresh_capacity < 5;
            if (length == 4 && line && fresh_capacity >= 5)
                bad |= memcmp(line, payload, 4) || line[4] != 0;
            bad |= ferror(stream) || feof(stream);
            free(line);
            bad |= fclose(stream) != 0 || fresh.closed != 1;
            printf("cookie-lines api=%d unbuffered=%d null-buffer=%s\n",
                   api, unbuffered, bad ? "FAIL" : "PASS");
            failed += bad != 0; ++cases;

            struct line_cookie write_only = {.data = payload, .length = sizeof(payload)};
            stream = fopencookie(&write_only, "w", (cookie_io_functions_t){
                .read = read_line_cookie, .close = close_line_cookie});
            if (!stream) return 1;
            bad = setvbuf(stream, NULL, unbuffered ? _IONBF : _IOFBF, 0) != 0;
            line = NULL; capacity = 0;
            errno = 0x5EED;
            bad |= cookie_line_call(api, &line, &capacity, stream) != -1;
            bad |= errno != EBADF || !ferror(stream) || feof(stream) || write_only.calls;
            clearerr(stream);
            errno = 0x5EED;
            bad |= fgetc(stream) != EOF;
            bad |= errno != EBADF || !ferror(stream) || feof(stream) || write_only.calls;
            free(line);
            bad |= fclose(stream) != 0 || write_only.closed != 1;
            printf("cookie-lines api=%d unbuffered=%d write-only=%s\n",
                   api, unbuffered, bad ? "FAIL" : "PASS");
            failed += bad != 0; ++cases;
        }
    }
    printf("fixture_stdio cookie-lines: %s (%d cases, %d failed)\n",
           failed ? "FAIL" : "PASS", cases, failed);
    return failed != 0;
}

/* Real descriptor errors must stay visible at the FILE boundary. The second
 * alarm supplies data and EOF only as a bounded negative control: an incorrect
 * EINTR retry then produces a mismatching result instead of hanging this test.
 * These cases use only anonymous pipes and never remove filesystem objects. */
static volatile sig_atomic_t fd_error_signals;
static volatile sig_atomic_t fd_error_writer = -1;

static void interrupt_stdio_read(int signal_number) {
    (void)signal_number;
    int saved_errno = errno;
    ++fd_error_signals;
    if (fd_error_signals == 2) {
        (void)syscall(SYS_write, fd_error_writer, "X\n", 2);
        (void)syscall(SYS_close, fd_error_writer);
        fd_error_writer = -1;
    }
    errno = saved_errno;
}

enum fd_read_api {
    FD_GETC, FD_READ, FD_READ_LARGE, FD_READ_ELEMENTS, FD_GETS, FD_GETLINE,
    FD_GETDELIM, FD_READ_API_COUNT
};

struct nonblocking_cookie {
    size_t remaining;
};

static ssize_t read_cookie_eagain(void *opaque, char *buf, size_t count) {
    struct nonblocking_cookie *cookie = opaque;
    if (cookie->remaining) {
        size_t n = cookie->remaining < count ? cookie->remaining : count;
        memcpy(buf, "abc" + 3 - cookie->remaining, n);
        cookie->remaining -= n;
        return (ssize_t)n;
    }
    errno = EAGAIN;
    return -1;
}

static int test_cookie_read_eagain(int unbuffered, int partial, int line_read) {
    struct nonblocking_cookie cookie = {.remaining = partial ? 3 : 0};
    FILE *stream = fopencookie(&cookie, "r", (cookie_io_functions_t){.read = read_cookie_eagain});
    if (!stream) return 1;
    if (setvbuf(stream, NULL, unbuffered ? _IONBF : _IOFBF, 0)) {
        fclose(stream);
        return 1;
    }
    unsigned char bytes[8], expected[8];
    memset(bytes, 0xA5, sizeof(bytes));
    memset(expected, 0xA5, sizeof(expected));
    if (partial) memcpy(expected, "abc", 3);
    if (line_read && partial) expected[3] = 0;
    errno = 0;
    long result = line_read ? fgets((char *)bytes, sizeof(bytes), stream) != NULL
                            : (long)fread(bytes, 1, sizeof(bytes), stream);
    int saved_errno = errno;
    int error = ferror(stream) != 0, eof = feof(stream) != 0;
    long expected_result = partial ? (line_read ? 1 : 3) : 0;
    int failed = result != expected_result || saved_errno != EAGAIN || !error || eof ||
                 memcmp(bytes, expected, sizeof(bytes));
    printf("cookie-error:%s:%s:%s result=%ld errno=%d error=%d eof=%d\n",
           line_read ? "fgets" : "fread", unbuffered ? "unbuffered" : "buffered",
           partial ? "partial" : "empty", result, saved_errno, error, eof);
    if (fclose(stream) != 0) failed = 1;
    if (failed) fprintf(stderr, "FAIL: cookie EAGAIN case %d/%d/%d\n",
                        unbuffered, partial, line_read);
    return failed;
}

static int test_fd_read_error(enum fd_read_api api, int unbuffered,
                              int interrupted, int partial, int warmed) {
    static const char *names[] = {
        "fgetc", "fread", "fread-large", "fread-elements", "fgets", "getline", "getdelim"
    };
    int fds[2];
    if (pipe2(fds, interrupted ? 0 : O_NONBLOCK) != 0) return 1;
    FILE *stream = fdopen(fds[0], "r");
    if (!stream) {
        close(fds[0]);
        close(fds[1]);
        return 1;
    }
    if (setvbuf(stream, NULL, unbuffered ? _IONBF : _IOFBF, 0) != 0) {
        fclose(stream);
        close(fds[1]);
        return 1;
    }
    if (warmed && (write(fds[1], "W", 1) != 1 || fgetc(stream) != 'W')) {
        fclose(stream);
        close(fds[1]);
        return 1;
    }
    if (partial && write(fds[1], "abc", 3) != 3) {
        fclose(stream);
        close(fds[1]);
        return 1;
    }
    fd_error_signals = 0;
    fd_error_writer = fds[1];
    struct itimerval timer = {0};
    if (interrupted) {
        timer.it_interval.tv_usec = 250000;
        timer.it_value.tv_usec = 50000;
        if (setitimer(ITIMER_REAL, &timer, NULL) != 0) {
            fclose(stream);
            close(fds[1]);
            return 1;
        }
    }
    unsigned char bytes[16384];
    memset(bytes, 0xA5, sizeof(bytes));
    char *line = NULL;
    size_t capacity = 0;
    long result = -99;
    errno = 0;
    switch (api) {
    case FD_GETC:
        result = fgetc(stream);
        break;
    case FD_READ:
        result = (long)fread(bytes, 1, 8, stream);
        break;
    case FD_READ_LARGE:
        result = (long)fread(bytes, 1, sizeof(bytes), stream);
        break;
    case FD_READ_ELEMENTS:
        result = (long)fread(bytes, 2, 4, stream);
        break;
    case FD_GETS:
        result = fgets((char *)bytes, 8, stream) != NULL;
        break;
    case FD_GETLINE:
        result = getline(&line, &capacity, stream);
        break;
    case FD_GETDELIM:
        result = getdelim(&line, &capacity, '\n', stream);
        break;
    default:
        break;
    }
    int saved_errno = errno;
    /* Disarm before querying stream state so a delayed diagnostic path cannot
     * accidentally trip the retry watchdog after a correct return. */
    memset(&timer, 0, sizeof(timer));
    if (setitimer(ITIMER_REAL, &timer, NULL) != 0) return 1;
    int signals = fd_error_signals;
    int error = ferror(stream) != 0;
    int eof = feof(stream) != 0;
    long expected_result = partial ? 3 : 0;
    if (api == FD_GETC) expected_result = EOF;
    if (api == FD_READ_ELEMENTS) expected_result /= 2;
    if (api == FD_GETS) expected_result = partial && !interrupted;
    if ((api == FD_GETLINE || api == FD_GETDELIM) && !partial) expected_result = -1;
    int failed = result != expected_result || saved_errno != (interrupted ? EINTR : EAGAIN) ||
                 !error || eof || signals != interrupted;
    if (api >= FD_GETLINE) {
        if (partial && (!line || memcmp(line, "abc\0", 4))) failed = 1;
    } else {
        unsigned char expected[8];
        memset(expected, 0xA5, sizeof(expected));
        if (partial) memcpy(expected, "abc", 3);
        if (api == FD_GETS && expected_result) expected[3] = 0;
        if (memcmp(bytes, expected, sizeof(expected))) failed = 1;
        for (size_t i = sizeof(expected); i < sizeof(bytes); ++i)
            if (bytes[i] != 0xA5) failed = 1;
    }
    int sticky = 1;
    if (api == FD_GETLINE || api == FD_GETDELIM) {
        /* An existing error stops line input even with a pushed-back byte.
         * Queue data before recovery so a broken implementation that consumed
         * the pushback still terminates on the blocking EINTR pipe. */
        sticky = ungetc('P', stream) == 'P';
        errno = 0x5EED;
        ssize_t stopped = api == FD_GETLINE ? getline(&line, &capacity, stream)
                                            : getdelim(&line, &capacity, '\n', stream);
        sticky &= stopped == -1 && errno == 0x5EED && ferror(stream) && !feof(stream);
        sticky &= fd_error_writer >= 0 && write(fd_error_writer, "Z", 1) == 1;
        clearerr(stream);
        sticky &= fgetc(stream) == 'P' && !ferror(stream) && !feof(stream);
        failed |= !sticky;
    }
    /* The error is sticky, but clearerr must allow the same stream to consume
     * new data. This also exercises cache reuse after an interrupted refill. */
    clearerr(stream);
    int recovered = !ferror(stream) && !feof(stream) && fd_error_writer >= 0 &&
                    write(fd_error_writer, "Z", 1) == 1 && fgetc(stream) == 'Z' &&
                    !ferror(stream) && !feof(stream);
    failed |= !recovered;
    printf("fd-error:%s:%s:%s:%s:%s result=%ld errno=%d error=%d eof=%d signals=%d sticky=%d recovery=%d\n",
           names[api], unbuffered ? "unbuffered" : "buffered",
           interrupted ? "EINTR" : "EAGAIN", partial ? "partial" : "empty",
           warmed ? "warm" : "cold", result, saved_errno, error, eof, signals, sticky, recovered);
    free(line);
    if (fclose(stream) != 0) failed = 1;
    if (fd_error_writer >= 0 && close(fd_error_writer) != 0) failed = 1;
    fd_error_writer = -1;
    if (failed) fprintf(stderr, "FAIL: descriptor read error case %s/%d/%d/%d/%d\n",
                        names[api], unbuffered, interrupted, partial, warmed);
    return failed;
}

static int test_fd_read_errors(void) {
    struct sigaction action = {.sa_handler = interrupt_stdio_read}, previous;
    sigemptyset(&action.sa_mask);
    if (sigaction(SIGALRM, &action, &previous) != 0) return 1;
    int failed = 0, cases = 0;
    for (int interrupted = 0; interrupted <= 1; ++interrupted)
        for (int unbuffered = 0; unbuffered <= 1; ++unbuffered)
            for (int api = 0; api < FD_READ_API_COUNT; ++api)
                for (int partial = 0; partial <= 1; ++partial)
                    for (int warmed = 0; warmed <= 1; ++warmed) {
                        if (api == FD_GETC && partial) continue;
                        failed += test_fd_read_error((enum fd_read_api)api, unbuffered,
                                                     interrupted, partial, warmed);
                        ++cases;
                    }
    if (sigaction(SIGALRM, &previous, NULL) != 0) ++failed;
    for (int unbuffered = 0; unbuffered <= 1; ++unbuffered)
        for (int partial = 0; partial <= 1; ++partial)
            for (int line_read = 0; line_read <= 1; ++line_read) {
                failed += test_cookie_read_eagain(unbuffered, partial, line_read);
                ++cases;
            }
    printf("fixture_stdio fd-errors: %s (%d cases, %d failed)\n",
           failed ? "FAIL" : "PASS", cases, failed);
    return failed != 0;
}

static volatile sig_atomic_t write_error_signals;
static volatile sig_atomic_t write_error_reader = -1;

static ssize_t drain_write_pipe(int fd) {
    char bytes[4096];
    ssize_t total = 0, count;
    while ((count = syscall(SYS_read, fd, bytes, sizeof(bytes))) > 0) total += count;
    return total;
}

static void interrupt_stdio_write(int signal_number) {
    (void)signal_number;
    int saved_errno = errno;
    /* A forbidden EINTR retry is released by the second alarm, and fails the
     * result, signal-count and data checks instead of hanging the fixture. */
    if (++write_error_signals == 2) (void)drain_write_pipe(write_error_reader);
    errno = saved_errno;
}

static int test_fd_write_error(int interrupted, int immediate, int partial) {
    int fds[2];
    if (pipe2(fds, O_NONBLOCK) != 0) return 1;
    if (fcntl(fds[1], F_SETPIPE_SZ, 4096) != 4096) return 1;
    char bytes[6000], buffer[16384];
    memset(bytes, 'A', sizeof(bytes));
    if (!partial && syscall(SYS_write, fds[1], bytes, 4096) != 4096) return 1;
    if (interrupted && fcntl(fds[1], F_SETFL, 0) != 0) return 1;
    FILE *stream = fdopen(fds[1], "w");
    if (!stream || setvbuf(stream, buffer, immediate ? _IONBF : _IOFBF, sizeof(buffer))) return 1;
    size_t count = partial ? sizeof(bytes) : 3;
    if (!immediate && fwrite(bytes, 1, count, stream) != count) return 1;
    write_error_signals = 0;
    write_error_reader = fds[0];
    struct itimerval timer = {0};
    if (interrupted) {
        timer.it_value.tv_usec = 50000;
        timer.it_interval.tv_usec = 250000;
        if (setitimer(ITIMER_REAL, &timer, NULL) != 0) return 1;
    }
    errno = 0;
    long result = immediate ? (long)fwrite(bytes, 1, count, stream) : fflush(stream);
    int saved_errno = errno;
    memset(&timer, 0, sizeof(timer));
    if (setitimer(ITIMER_REAL, &timer, NULL) != 0) return 1;
    int error = ferror(stream) != 0, eof = feof(stream) != 0;
    int signals = write_error_signals;
    ssize_t first = drain_write_pipe(fds[0]);
    clearerr(stream);
    errno = 0;
    int retry = fflush(stream), retry_errno = errno, retry_error = ferror(stream) != 0;
    ssize_t replay = drain_write_pipe(fds[0]);
    /* Keep fclose bounded even when qualifying the buggy predecessor. */
    if (fcntl(fds[1], F_SETFL, O_NONBLOCK) != 0) return 1;
    int closed = fclose(stream);
    ssize_t close_replay = drain_write_pipe(fds[0]);
    close(fds[0]);
    write_error_reader = -1;
    int failed = result != (immediate ? 0 : EOF) ||
                 saved_errno != (interrupted ? EINTR : EAGAIN) || !error || eof ||
                 signals != interrupted || first != 4096 || retry || retry_errno ||
                 retry_error || replay || closed || close_replay;
    printf("fd-write:%s:%s:%s result=%ld errno=%d error=%d eof=%d signals=%d first=%zd retry=%d retry_errno=%d retry_error=%d replay=%zd close=%d close_replay=%zd\n",
           immediate ? "fwrite" : "fflush", interrupted ? "EINTR" : "EAGAIN",
           partial ? "partial" : "full", result, saved_errno, error, eof, signals,
           first, retry, retry_errno, retry_error, replay, closed, close_replay);
    if (failed) fprintf(stderr, "FAIL: descriptor write error case %d/%d/%d\n",
                        interrupted, immediate, partial);
    return failed;
}

static int test_flush_failure_position(int append, int initial, int start, int limit) {
    int fd = (int)syscall(SYS_memfd_create, "stdio-write-errors", 0);
    if (fd < 0) return 1;
    char buffer[16384], expected[32] = {0}, actual[32] = {0};
    memset(expected, 'S', (size_t)initial);
    if (syscall(SYS_write, fd, expected, initial) != initial ||
        syscall(SYS_lseek, fd, start, SEEK_SET) != start) return 1;
    if (append && fcntl(fd, F_SETFL, O_NONBLOCK)) return 1;
    FILE *stream = fdopen(fd, append ? (append == 1 ? "a+" : "a") : "w+");
    if (!stream || setvbuf(stream, buffer, _IOFBF, sizeof(buffer)) ||
        fseek(stream, start, SEEK_SET) || fwrite("abcdefghij", 1, 10, stream) != 10) return 1;
    int descriptor_flags = fcntl(fd, F_GETFL);
    int append_enabled = descriptor_flags >= 0 && (descriptor_flags & O_APPEND) != 0;
    int nonblocking = descriptor_flags >= 0 && (descriptor_flags & O_NONBLOCK) != 0;
    struct rlimit previous_limit, restricted;
    struct sigaction ignore = {.sa_handler = SIG_IGN}, previous_action;
    sigemptyset(&ignore.sa_mask);
    if (getrlimit(RLIMIT_FSIZE, &previous_limit) ||
        sigaction(SIGXFSZ, &ignore, &previous_action)) return 1;
    restricted = previous_limit;
    restricted.rlim_cur = (rlim_t)limit;
    if (setrlimit(RLIMIT_FSIZE, &restricted)) {
        (void)sigaction(SIGXFSZ, &previous_action, NULL);
        fclose(stream);
        return 1;
    }
    errno = 0;
    int result = fflush(stream), saved_errno = errno, error = ferror(stream) != 0;
    long position = ftell(stream);
    off_t kernel_position = (off_t)syscall(SYS_lseek, fd, 0, SEEK_CUR);
    /* CI redirects diagnostics to regular files, so restore the limit before
     * reporting anything. The hard limit was never changed. */
    if (setrlimit(RLIMIT_FSIZE, &previous_limit) ||
        sigaction(SIGXFSZ, &previous_action, NULL)) _exit(2);
    clearerr(stream);
    int retry = fflush(stream), retry_error = ferror(stream) != 0;
    struct stat st;
    int accepted = limit - (append ? initial : start);
    int expected_position = accepted ? limit : start;
    int expected_size = accepted ? limit : initial;
    memcpy(expected + (append ? initial : start), "abcdefghij", (size_t)accepted);
    int failed = result != EOF || saved_errno != EFBIG || !error ||
                 position != expected_position || kernel_position != expected_position ||
                 (append && (!append_enabled || !nonblocking)) ||
                 retry || retry_error || fstat(fd, &st) || st.st_size != expected_size ||
                 pread(fd, actual, sizeof(actual), 0) != expected_size ||
                 memcmp(actual, expected, (size_t)expected_size);
    int closed = fclose(stream);
    failed |= closed != 0;
    printf("fd-position:%s:initial=%d:start=%d:limit=%d append=%d nonblocking=%d result=%d errno=%d error=%d position=%ld kernel=%ld retry=%d retry_error=%d close=%d\n",
           append ? (append == 1 ? "a+" : "a") : "regular", initial, start, limit,
           append_enabled, nonblocking, result, saved_errno, error, position,
           (long)kernel_position, retry, retry_error, closed);
    if (failed) fprintf(stderr, "FAIL: failed flush position case %d/%d/%d/%d\n",
                        append, initial, start, limit);
    return failed;
}

struct flush_error_cookie { int calls, error_number; };

static ssize_t write_cookie_failure(void *opaque, const char *bytes, size_t count) {
    (void)bytes;
    (void)count;
    struct flush_error_cookie *cookie = opaque;
    ++cookie->calls;
    errno = cookie->error_number;
    return 0;
}

static int test_cookie_flush_error(int error_number) {
    struct flush_error_cookie cookie = {.error_number = error_number};
    FILE *stream = fopencookie(&cookie, "w", (cookie_io_functions_t){.write = write_cookie_failure});
    char buffer[16384];
    if (!stream || setvbuf(stream, buffer, _IOFBF, sizeof(buffer)) ||
        fwrite("abc", 1, 3, stream) != 3) return 1;
    errno = 0;
    int result = fflush(stream), saved_errno = errno, error = ferror(stream) != 0;
    clearerr(stream);
    int retry = fflush(stream), retry_error = ferror(stream) != 0;
    int closed = fclose(stream);
    int failed = result != EOF || saved_errno != error_number || !error ||
                 retry || retry_error || closed || cookie.calls != 1;
    printf("cookie-write:errno_in=%d result=%d errno=%d error=%d retry=%d retry_error=%d close=%d calls=%d\n",
           error_number, result, saved_errno, error, retry, retry_error, closed, cookie.calls);
    if (failed) fprintf(stderr, "FAIL: cookie flush error case %d\n", error_number);
    return failed;
}

static int test_fd_write_errors(void) {
    struct sigaction action = {.sa_handler = interrupt_stdio_write}, previous;
    sigemptyset(&action.sa_mask);
    if (sigaction(SIGALRM, &action, &previous)) return 1;
    int failed = 0, cases = 0;
    for (int interrupted = 0; interrupted <= 1; ++interrupted)
        for (int immediate = 0; immediate <= 1; ++immediate) {
            failed += test_fd_write_error(interrupted, immediate, 0);
            ++cases;
        }
    failed += test_fd_write_error(0, 0, 1);
    ++cases;
    if (sigaction(SIGALRM, &previous, NULL)) ++failed;
    const int positions[][4] = {
        {0, 0, 0, 4}, {0, 7, 5, 9}, {0, 7, 7, 7},
        {1, 7, 0, 11}, {1, 7, 0, 7}, {2, 7, 3, 7}
    };
    for (size_t i = 0; i < sizeof(positions) / sizeof(positions[0]); ++i) {
        failed += test_flush_failure_position(positions[i][0], positions[i][1],
                                               positions[i][2], positions[i][3]);
        ++cases;
    }
    failed += test_cookie_flush_error(EINTR);
    failed += test_cookie_flush_error(EAGAIN);
    cases += 2;
    printf("fixture_stdio write-errors: %s (%d cases, %d failed)\n",
           failed ? "FAIL" : "PASS", cases, failed);
    return failed != 0;
}

/* Process-stream tests use anonymous pipes and this executable as the shell's
 * child. A parent-specific /proc path also works for memory-backed executables.
 * Every blocking case has an explicit release path plus the suite watchdog. */
static char popen_executable[64];
static int (*volatile popen_fclose)(FILE *) = fclose;
static volatile sig_atomic_t popen_wait_signals;

static int popen_write_byte(int fd, char value) {
    ssize_t result;
    do result = write(fd, &value, 1); while (result < 0 && errno == EINTR);
    return result != 1;
}

static int popen_read_pid(int fd, pid_t *pid) {
    char text[32];
    size_t length = 0;
    while (length + 1 < sizeof(text)) {
        ssize_t result = read(fd, text + length, 1);
        if (result < 0 && errno == EINTR) continue;
        if (result != 1) return 1;
        if (text[length++] == '\n') break;
    }
    text[length] = 0;
    *pid = (pid_t)strtol(text, NULL, 10);
    return *pid <= 0;
}

static int popen_helper(int argc, char **argv) {
    if (argc == 5 && !strcmp(argv[1], "popen-helper-inherit")) {
        struct stat info;
        int inherited = !fstat(atoi(argv[2]), &info) &&
                        (unsigned long long)info.st_dev == strtoull(argv[3], NULL, 10) &&
                        (unsigned long long)info.st_ino == strtoull(argv[4], NULL, 10);
        printf("%d\n", inherited);
        return 0;
    }
    if (argc == 2 && !strcmp(argv[1], "popen-helper-drain")) {
        char data[256];
        for (;;) {
            ssize_t count = read(STDIN_FILENO, data, sizeof(data));
            if (count == 0) return 0;
            if (count < 0 && errno != EINTR) return 1;
        }
    }
    if (argc == 3 && !strcmp(argv[1], "popen-helper-epipe")) {
        if (close(STDIN_FILENO)) return 1;
        return dprintf(atoi(argv[2]), "%ld\n", (long)getpid()) < 0;
    }
    if (argc == 4 && !strcmp(argv[1], "popen-helper-wait")) {
        if (dprintf(atoi(argv[3]), "%ld\n", (long)getpid()) < 0) return 1;
        char release;
        ssize_t result;
        do result = read(atoi(argv[2]), &release, 1); while (result < 0 && errno == EINTR);
        return result != 1;
    }
    return -1;
}

static void popen_drain_command(char command[128]) {
    snprintf(command, 128, "exec %s popen-helper-drain", popen_executable);
}

static int popen_child_reaped(pid_t pid) {
    int status;
    errno = 0;
    pid_t result = waitpid(pid, &status, WNOHANG);
    int reaped = result < 0 && errno == ECHILD;
    /* A negative implementation must not leave a zombie behind the fixture. */
    if (result == 0)
        while (waitpid(pid, &status, 0) < 0 && errno == EINTR) {}
    return reaped;
}

static int test_popen_inheritance(const char *first_mode, const char *second_mode) {
    char command[256], first_command[128];
    popen_drain_command(first_command);
    FILE *first = popen(first_mode[0] == 'r' ? "exit 0" : first_command, first_mode);
    if (!first) return 1;
    int fd = fileno(first);
    struct stat info;
    if (fstat(fd, &info)) { pclose(first); return 1; }
    int first_cloexec = (fcntl(fd, F_GETFD) & FD_CLOEXEC) != 0;
    snprintf(command, sizeof(command), "exec %s popen-helper-inherit %d %llu %llu",
             popen_executable, fd, (unsigned long long)info.st_dev,
             (unsigned long long)info.st_ino);
    FILE *second = popen(command, second_mode);
    if (!second) { pclose(first); return 1; }
    int second_cloexec = (fcntl(fileno(second), F_GETFD) & FD_CLOEXEC) != 0;
    char line[16];
    int inherited = fgets(line, sizeof(line), second) ? atoi(line) : -1;
    int second_status = pclose(second), first_status = pclose(first);
    int failed = inherited != 0 || first_status || second_status ||
                 first_cloexec != (strchr(first_mode, 'e') != NULL) ||
                 second_cloexec != (strchr(second_mode, 'e') != NULL);
    printf("popen-inherit:first=%s second=%s inherited=%d flags=%d,%d status=%d,%d\n",
           first_mode, second_mode, inherited, first_cloexec, second_cloexec,
           first_status, second_status);
    return failed;
}

struct popen_closer {
    FILE *stream;
    int notify_fd;
    int status;
    int saved_errno;
    int cleanup;
    int cancel_after;
};

static void popen_close_cleanup(void *opaque) {
    struct popen_closer *closer = opaque;
    ++closer->cleanup;
    (void)popen_write_byte(closer->notify_fd, 'C');
}

static void *popen_close_worker(void *opaque) {
    struct popen_closer *closer = opaque;
    pthread_cleanup_push(popen_close_cleanup, closer);
    closer->status = pclose(closer->stream);
    closer->saved_errno = errno;
    if (closer->cancel_after) pthread_testcancel();
    (void)popen_write_byte(closer->notify_fd, 'D');
    pthread_cleanup_pop(0);
    return NULL;
}

static int popen_ready(int fd, int milliseconds) {
    struct pollfd poll_fd = {.fd = fd, .events = POLLIN};
    int result;
    do result = poll(&poll_fd, 1, milliseconds); while (result < 0 && errno == EINTR);
    return result > 0 && (poll_fd.revents & POLLIN);
}

static int test_popen_independent_eof(void) {
    char command[128];
    popen_drain_command(command);
    FILE *first = popen(command, "w"), *second = popen(command, "w");
    if (!first || !second) {
        if (second) pclose(second);
        if (first) pclose(first);
        return 1;
    }
    int done[2];
    if (pipe(done)) { pclose(second); pclose(first); return 1; }
    struct popen_closer closer = {.stream = first, .notify_fd = done[1], .status = -99};
    pthread_t thread;
    if (pthread_create(&thread, NULL, popen_close_worker, &closer)) {
        pclose(second); pclose(first); close(done[0]); close(done[1]); return 1;
    }
    int independent = popen_ready(done[0], 3000);
    /* Release the second child before joining even on failure: the old writer
     * inheritance defect is a bounded mismatch, never a hung test process. */
    int second_status = pclose(second);
    int joined = pthread_join(thread, NULL);
    close(done[0]); close(done[1]);
    printf("popen-eof:independent=%d status=%d,%d joined=%d\n",
           independent, closer.status, second_status, joined);
    return !independent || closer.status || second_status || joined;
}

static int test_popen_exit_status(int use_fclose, int kind) {
    const char *commands[] = {
        "printf '%s\\n' \"$$\"; exit 0",
        "printf '%s\\n' \"$$\"; exit 7",
        "printf '%s\\n' \"$$\"; kill -TERM \"$$\""
    };
    const int expected[] = {0, 7 << 8, SIGTERM};
    FILE *stream = popen(commands[kind], "r");
    if (!stream) return 1;
    char line[32];
    pid_t child = fgets(line, sizeof(line), stream) ? (pid_t)strtol(line, NULL, 10) : -1;
    int status = use_fclose ? popen_fclose(stream) : pclose(stream);
    int reaped = child > 0 && popen_child_reaped(child);
    printf("popen-status:close=%s kind=%d status=%d reaped=%d\n",
           use_fclose ? "fclose" : "pclose", kind, status, reaped);
    return status != expected[kind] || !reaped;
}

static int test_popen_flush_error(int use_fclose) {
    int ready[2];
    if (pipe(ready)) return 1;
    char command[160];
    snprintf(command, sizeof(command), "exec %s popen-helper-epipe %d",
             popen_executable, ready[1]);
    FILE *stream = popen(command, "w");
    close(ready[1]);
    if (!stream) { close(ready[0]); return 1; }
    pid_t child;
    int failed = popen_read_pid(ready[0], &child);
    close(ready[0]);
    char buffer[4096];
    if (setvbuf(stream, buffer, _IOFBF, sizeof(buffer)) || fputs("abc", stream) == EOF)
        failed = 1;
    errno = 0;
    int status = use_fclose ? popen_fclose(stream) : pclose(stream);
    int saved_errno = errno;
    int reaped = !failed && popen_child_reaped(child);
    printf("popen-flush:close=%s status=%d errno=%d reaped=%d\n",
           use_fclose ? "fclose" : "pclose", status, saved_errno, reaped);
    return failed || status != EOF || saved_errno != EPIPE || !reaped;
}

static int test_popen_closed_stdio(const char *mode) {
    if (fflush(stdout)) return 1;
    int saved_input = fcntl(STDIN_FILENO, F_DUPFD_CLOEXEC, 3);
    int saved_output = fcntl(STDOUT_FILENO, F_DUPFD_CLOEXEC, 3);
    if (saved_input < 0 || saved_output < 0) {
        if (saved_input >= 0) close(saved_input);
        if (saved_output >= 0) close(saved_output);
        return 1;
    }
    close(STDIN_FILENO); close(STDOUT_FILENO);
    int reading = mode[0] == 'r';
    FILE *stream = popen(reading ? "printf 'ok\\n'" : "IFS= read -r value; test \"$value\" = ok", mode);
    int transferred = 0, cloexec = -1, status = -99;
    if (stream) {
        cloexec = (fcntl(fileno(stream), F_GETFD) & FD_CLOEXEC) != 0;
        if (reading) {
            char line[16];
            transferred = fgets(line, sizeof(line), stream) && !strcmp(line, "ok\n");
        } else {
            transferred = fputs("ok\n", stream) != EOF;
        }
        status = pclose(stream);
    }
    int restored_input = dup2(saved_input, STDIN_FILENO);
    int restored_output = dup2(saved_output, STDOUT_FILENO);
    close(saved_input); close(saved_output);
    printf("popen-closed-stdio:mode=%s transfer=%d cloexec=%d status=%d\n",
           mode, transferred, cloexec, status);
    return !transferred || status || cloexec != (strchr(mode, 'e') != NULL) ||
           restored_input != STDIN_FILENO || restored_output != STDOUT_FILENO;
}

static void popen_interrupt_wait(int signal_number) {
    (void)signal_number;
    ++popen_wait_signals;
}

static int test_popen_wait(int cancelled) {
    int control[2], ready[2], done[2];
    if (pipe(control)) return 1;
    if (pipe(ready)) { close(control[0]); close(control[1]); return 1; }
    if (pipe(done)) {
        close(control[0]); close(control[1]); close(ready[0]); close(ready[1]); return 1;
    }
    char command[160];
    snprintf(command, sizeof(command), "exec %s popen-helper-wait %d %d",
             popen_executable, control[0], ready[1]);
    FILE *stream = popen(command, "r");
    close(control[0]); close(ready[1]);
    if (!stream) {
        close(control[1]); close(ready[0]); close(done[0]); close(done[1]); return 1;
    }
    pid_t child;
    int failed = popen_read_pid(ready[0], &child);
    close(ready[0]);
    struct popen_closer closer = {
        .stream = stream, .notify_fd = done[1], .status = -99, .cancel_after = cancelled
    };
    pthread_t thread;
    popen_wait_signals = 0;
    if (pthread_create(&thread, NULL, popen_close_worker, &closer)) {
        (void)popen_write_byte(control[1], 'X');
        close(control[1]); pclose(stream); close(done[0]); close(done[1]); return 1;
    }
    int premature = popen_ready(done[0], 100);
    if (cancelled) {
        if (pthread_cancel(thread)) failed = 1;
    } else {
        const struct timespec pause = {.tv_nsec = 20000000};
        for (int i = 0; i < 3; ++i) {
            if (pthread_kill(thread, SIGUSR1)) failed = 1;
            nanosleep(&pause, NULL);
        }
    }
    premature |= popen_ready(done[0], 250);
    if (popen_write_byte(control[1], 'X')) failed = 1;
    close(control[1]);
    void *result = NULL;
    if (pthread_join(thread, &result)) failed = 1;
    close(done[0]); close(done[1]);
    int reaped = !failed && popen_child_reaped(child);
    int did_cancel = result == PTHREAD_CANCELED;
    int signalled = popen_wait_signals != 0;
    printf("popen-wait:cancel=%d premature=%d status=%d cancelled=%d cleanup=%d signalled=%d reaped=%d\n",
           cancelled, premature, closer.status, did_cancel, closer.cleanup, signalled, reaped);
    return failed || premature || closer.status || did_cancel != cancelled ||
           closer.cleanup != cancelled || signalled != !cancelled || !reaped;
}

static int test_popen_exhausted_descriptors(void) {
    struct rlimit previous;
    if (getrlimit(RLIMIT_NOFILE, &previous) || previous.rlim_max < 3) return 1;
    struct rlimit limited = previous;
    limited.rlim_cur = 3;
    if (setrlimit(RLIMIT_NOFILE, &limited)) return 1;
    errno = 0;
    FILE *stream = popen("exit 0", "r");
    int saved_errno = errno;
    int restored = setrlimit(RLIMIT_NOFILE, &previous);
    if (stream) pclose(stream);
    int status;
    errno = 0;
    pid_t child = waitpid(-1, &status, WNOHANG);
    int no_child = child < 0 && errno == ECHILD;
    if (child == 0) while (waitpid(-1, &status, 0) < 0 && errno == EINTR) {}
    printf("popen-exhaustion:failed=%d errno=%d no_child=%d\n",
           stream == NULL, saved_errno, no_child);
    return stream != NULL || saved_errno != EMFILE || !no_child || restored;
}

static int test_popen_lifecycle(void) {
    snprintf(popen_executable, sizeof(popen_executable), "/proc/%ld/exe", (long)getpid());
    struct sigaction ignore_pipe = {.sa_handler = SIG_IGN}, previous_pipe;
    struct sigaction interrupt_wait = {.sa_handler = popen_interrupt_wait}, previous_wait;
    sigemptyset(&ignore_pipe.sa_mask);
    sigemptyset(&interrupt_wait.sa_mask);
    if (sigaction(SIGPIPE, &ignore_pipe, &previous_pipe) ||
        sigaction(SIGUSR1, &interrupt_wait, &previous_wait)) return 1;
    alarm(30);
    const char *modes[] = {"r", "w", "re", "we"};
    const char *read_modes[] = {"r", "re"};
    int failed = 0, cases = 0;
    for (size_t i = 0; i < sizeof(modes) / sizeof(modes[0]); ++i)
        for (size_t j = 0; j < sizeof(read_modes) / sizeof(read_modes[0]); ++j) {
            failed += test_popen_inheritance(modes[i], read_modes[j]);
            ++cases;
        }
    failed += test_popen_independent_eof(); ++cases;
    for (int use_fclose = 0; use_fclose <= 1; ++use_fclose) {
        for (int kind = 0; kind < 3; ++kind) {
            failed += test_popen_exit_status(use_fclose, kind);
            ++cases;
        }
        failed += test_popen_flush_error(use_fclose); ++cases;
    }
    for (size_t i = 0; i < sizeof(modes) / sizeof(modes[0]); ++i) {
        failed += test_popen_closed_stdio(modes[i]); ++cases;
    }
    failed += test_popen_wait(0); ++cases;
    failed += test_popen_wait(1); ++cases;
    failed += test_popen_exhausted_descriptors(); ++cases;
    alarm(0);
    if (sigaction(SIGPIPE, &previous_pipe, NULL) ||
        sigaction(SIGUSR1, &previous_wait, NULL)) ++failed;
    printf("fixture_stdio popen: %s (%d cases, %d failed)\n",
           failed ? "FAIL" : "PASS", cases, failed);
    return failed != 0;
}

/* Caller-backed memory must be sampled at refill, never at open, and only
 * actual output may change it. This lane uses no filesystem objects. */
static int test_host_line_buffer_growth(int use_getline) {
    void *host = dlopen("libc.so.6", RTLD_NOW | RTLD_LOCAL);
    if (!host) return 1;
    FILE *(*host_fmemopen)(void *, size_t, const char *) = dlsym(host, "fmemopen");
    cookie_getline_fn read_line = (cookie_getline_fn)dlsym(RTLD_DEFAULT, "getline");
    cookie_getdelim_fn read_field = (cookie_getdelim_fn)dlsym(RTLD_DEFAULT, "getdelim");
    Dl_info provider = {0};
    if (!host_fmemopen || !read_line || !read_field ||
        !dladdr((void *)host_fmemopen, &provider) || !provider.dli_fname) {
        dlclose(host);
        return 1;
    }
    const char *base = strrchr(provider.dli_fname, '/');
    if (strcmp(base ? base + 1 : provider.dli_fname, "libc.so.6")) {
        dlclose(host);
        return 1;
    }
    char input[257];
    memset(input, 'z', sizeof(input));
    input[sizeof(input) - 1] = '\n';
    FILE *stream = host_fmemopen(input, sizeof(input), "r");
    char *line = malloc(16);
    if (!stream || !line) {
        if (stream) fclose(stream);
        free(line);
        dlclose(host);
        return 1;
    }
    memset(line, 0x5A, 16);
    size_t capacity = 16;
    int bad = fputc('X', stream) != EOF;
    errno = 0x5EED;
    ssize_t result = use_getline ? read_line(&line, &capacity, stream)
                                : read_field(&line, &capacity, '\n', stream);
    ssize_t first_result = result;
    int first_errno = errno, first_error = ferror(stream), first_eof = feof(stream);
    size_t first_capacity = capacity;
    bad |= result != -1 || first_errno != 0x5EED || !first_error || first_eof;
    char expected[16];
    memset(expected, 0x5A, sizeof(expected));
    bad |= !line || capacity != 16 || memcmp(line, expected, sizeof(expected));
    clearerr(stream);
    result = use_getline ? read_line(&line, &capacity, stream)
                        : read_field(&line, &capacity, '\n', stream);
    bad |= result != (ssize_t)sizeof(input) || !line || capacity <= sizeof(input);
    if (result == (ssize_t)sizeof(input) && line && capacity > sizeof(input))
        bad |= memcmp(line, input, sizeof(input)) || line[sizeof(input)] != 0;
    free(line);
    bad |= fclose(stream) != 0;
    bad |= dlclose(host) != 0;
    if (bad) fprintf(stderr, "FAIL host-line-growth api=%d first=%zd errno=%d error=%d eof=%d capacity=%zu growth=%zd capacity=%zu\n",
                     use_getline, first_result, first_errno, first_error, first_eof,
                     first_capacity, result, capacity);
    printf("host-line-growth api=%s pass=%d\n", use_getline ? "getline" : "getdelim", !bad);
    return bad != 0;
}

static int test_host_line_partial_error(int use_getline, int cookie_source) {
    void *host = dlopen("libc.so.6", RTLD_NOW | RTLD_LOCAL);
    if (!host) return 1;
    FILE *(*host_cookie)(void *, const char *, cookie_io_functions_t) = dlsym(host, "fopencookie");
    FILE *(*host_fdopen)(int, const char *) = dlsym(host, "fdopen");
    cookie_getline_fn read_line = (cookie_getline_fn)dlsym(RTLD_DEFAULT, "getline");
    cookie_getdelim_fn read_field = (cookie_getdelim_fn)dlsym(RTLD_DEFAULT, "getdelim");
    Dl_info provider = {0};
    if (!host_cookie || !host_fdopen || !read_line || !read_field ||
        !dladdr(cookie_source ? (void *)host_cookie : (void *)host_fdopen, &provider) ||
        !provider.dli_fname) {
        dlclose(host);
        return 1;
    }
    const char *base = strrchr(provider.dli_fname, '/');
    if (strcmp(base ? base + 1 : provider.dli_fname, "libc.so.6")) {
        dlclose(host);
        return 1;
    }
    struct nonblocking_cookie cookie = {.remaining = 3};
    int fds[2] = {-1, -1};
    FILE *stream;
    if (cookie_source) {
        stream = host_cookie(&cookie, "r", (cookie_io_functions_t){.read = read_cookie_eagain});
    } else {
        if (pipe2(fds, O_NONBLOCK)) { dlclose(host); return 1; }
        if (write(fds[1], "abc", 3) != 3) {
            close(fds[0]); close(fds[1]); dlclose(host); return 1;
        }
        stream = host_fdopen(fds[0], "r");
    }
    if (!stream) {
        if (fds[0] >= 0) close(fds[0]);
        if (fds[1] >= 0) close(fds[1]);
        dlclose(host); return 1;
    }
    char *line = NULL;
    size_t capacity = 0;
    errno = 0x5EED;
    ssize_t result = use_getline ? read_line(&line, &capacity, stream)
                                : read_field(&line, &capacity, '\n', stream);
    int saved_errno = errno;
    int bad = result != 3 || saved_errno != EAGAIN || !ferror(stream) || feof(stream);
    bad |= !line || capacity < 4 || memcmp(line, "abc\0", 4);
    free(line);
    bad |= fclose(stream) != 0;
    if (fds[1] >= 0) bad |= close(fds[1]) != 0;
    bad |= dlclose(host) != 0;
    if (bad) fprintf(stderr, "FAIL host-line-partial api=%d cookie=%d result=%zd errno=%d\n",
                     use_getline, cookie_source, result, saved_errno);
    printf("host-line-partial api=%s cookie=%d pass=%d\n",
           use_getline ? "getline" : "getdelim", cookie_source, !bad);
    return bad != 0;
}

static int test_fmemopen_coherence(void) {
    const char *modes[] = {"r", "r+"};
    int failed = 0, cases = 0;
    for (int m = 0; m < 2; ++m) {
        for (int op = 0; op < 5; ++op) {
            char backing[] = "12\nold\n!", output[16] = {0};
            FILE *stream = fmemopen(backing, sizeof(backing) - 1, modes[m]);
            if (!stream) return 1;
            memcpy(backing, "42\nnew\n", 7);
            int bad = 0, number = 0;
            long expected_position = 0;
            if (op == 0) {
                bad = fgetc(stream) != '4'; expected_position = 1;
            } else if (op == 1) {
                bad = fread(output, 1, 7, stream) != 7 || memcmp(output, "42\nnew\n", 7);
                expected_position = 7;
            } else if (op == 2) {
                bad = !fgets(output, sizeof(output), stream) || strcmp(output, "42\n");
                expected_position = 3;
            } else if (op == 3) {
                bad = fscanf(stream, "%d", &number) != 1 || number != 42;
                expected_position = 2;
                bad |= fgetc(stream) != '\n';
                ++expected_position;
            } else {
                char *line = NULL;
                size_t capacity = 0;
                bad = getline(&line, &capacity, stream) != 3 || !line || strcmp(line, "42\n");
                free(line);
                expected_position = 3;
            }
            bad |= ftell(stream) != expected_position;
            bad |= fclose(stream) != 0;
            bad |= memcmp(backing, "42\nnew\n!", 8) != 0;
            printf("fmemopen-first mode=%s op=%d pass=%d\n", modes[m], op, !bad);
            failed += bad != 0; ++cases;
        }
        for (int unbuffered = 0; unbuffered < 2; ++unbuffered) {
            char backing[] = "abcde", output[2] = {0};
            FILE *stream = fmemopen(backing, 5, modes[m]);
            if (!stream) return 1;
            int bad = setvbuf(stream, NULL, unbuffered ? _IONBF : _IOFBF, 0) != 0;
            backing[0] = 'X';
            bad |= fgetc(stream) != 'X';
            backing[1] = 'Y';
            bad |= fgetc(stream) != (unbuffered ? 'Y' : 'b');
            bad |= fseek(stream, 2, SEEK_SET) != 0;
            backing[2] = 'Z';
            bad |= fgetc(stream) != (unbuffered ? 'Z' : 'c');
            bad |= fseek(stream, 0, SEEK_SET) != 0;
            backing[0] = 'Q';
            bad |= fread(output, 1, 2, stream) != 2 || memcmp(output, "QY", 2);
            bad |= ungetc('!', stream) != '!';
            bad |= fgetc(stream) != '!';
            backing[2] = 'R';
            bad |= fflush(stream) != 0 || fgetc(stream) != 'R';
            bad |= fseek(stream, 0, SEEK_END) != 0 || fgetc(stream) != EOF || !feof(stream);
            bad |= fseek(stream, 0, SEEK_SET) != 0 || feof(stream) != 0;
            bad |= fclose(stream) != 0 || memcmp(backing, "QYRde", 5);
            printf("fmemopen-trace mode=%s unbuffered=%d pass=%d\n", modes[m], unbuffered, !bad);
            failed += bad != 0; ++cases;
        }
    }
    const char *write_modes[] = {"w+", "r+"};
    for (int m = 0; m < 2; ++m) {
        char backing[16];
        memset(backing, 'Z', sizeof(backing));
        FILE *stream = fmemopen(backing, sizeof(backing), write_modes[m]);
        if (!stream) return 1;
        int bad = fwrite("W", 1, 1, stream) != 1 || fflush(stream) != 0;
        backing[3] = 'Q';
        bad |= fflush(stream) != 0 || fclose(stream) != 0;
        bad |= backing[0] != 'W' || backing[3] != 'Q';
        printf("fmemopen-sync mode=%s pass=%d\n", write_modes[m], !bad);
        failed += bad != 0; ++cases;
    }
    for (int line = 0; line <= 1; ++line) {
        failed += test_host_line_buffer_growth(line);
        ++cases;
        for (int cookie = 0; cookie <= 1; ++cookie) {
            failed += test_host_line_partial_error(line, cookie);
            ++cases;
        }
    }
    printf("fixture_stdio fmemopen: %s (%d cases, %d failed)\n",
           failed ? "FAIL" : "PASS", cases, failed);
    return failed != 0;
}

static int test_internal_line_reads(void) {
    typedef size_t (*line_info_fn)(FILE *, char *, size_t, int, int, int *);
    typedef size_t (*line_fn)(FILE *, char *, size_t, int, int);
    line_info_fn read_info = (line_info_fn)dlsym(RTLD_DEFAULT, "_IO_getline_info");
    line_fn read_line = (line_fn)dlsym(RTLD_DEFAULT, "_IO_getline");
    if (!read_info || !read_line) return 1;
    void *host = dlopen("libc.so.6", RTLD_NOW | RTLD_LOCAL);
    if (!host) return 1;
    FILE *(*host_fdopen)(int, const char *) = dlsym(host, "fdopen");
    int (*host_fwide)(FILE *, int) = dlsym(host, "fwide");
    int (*host_fgetc)(FILE *) = dlsym(host, "fgetc");
    int (*host_feof)(FILE *) = dlsym(host, "feof");
    int (*host_ferror)(FILE *) = dlsym(host, "ferror");
    int (*host_fclose)(FILE *) = dlsym(host, "fclose");
    void *host_functions[] = {(void *)host_fdopen, (void *)host_fwide,
        (void *)host_fgetc, (void *)host_feof, (void *)host_ferror, (void *)host_fclose};
    for (size_t i = 0; i < sizeof(host_functions) / sizeof(host_functions[0]); ++i) {
        Dl_info provider = {0};
        if (!host_functions[i] || !dladdr(host_functions[i], &provider) || !provider.dli_fname) {
            dlclose(host); return 1;
        }
        const char *base = strrchr(provider.dli_fname, '/');
        if (strcmp(base ? base + 1 : provider.dli_fname, "libc.so.6")) {
            dlclose(host); return 1;
        }
    }
    const char *inputs[] = {"", "abc", "ab\ncd", "", "abc", "abc"};
    const size_t limits[] = {0, 2, 8};
    int cases = 0, failed = 0;
    for (int kind = 0; kind < 6; ++kind) {
        for (size_t limit = 0; limit < sizeof(limits) / sizeof(limits[0]); ++limit) {
            for (int extract = -1; extract <= 1; ++extract) {
                for (int api = 0; api < 3; ++api) {
                    char backing[8] = {0};
                    size_t input_size = strlen(inputs[kind]);
                    memcpy(backing, inputs[kind], input_size);
                    int fds[2] = {-1, -1};
                    FILE *stream;
                    if (kind >= 3) {
                        if (pipe2(fds, O_NONBLOCK)) { dlclose(host); return 1; }
                        if (kind >= 4 && write(fds[1], backing, input_size) != (ssize_t)input_size) {
                            close(fds[0]); close(fds[1]); dlclose(host); return 1;
                        }
                        stream = kind == 5 ? host_fdopen(fds[0], "r") : fdopen(fds[0], "r");
                    } else {
                        stream = fmemopen(backing, input_size, "r");
                    }
                    if (!stream) {
                        if (fds[0] >= 0) close(fds[0]);
                        if (fds[1] >= 0) close(fds[1]);
                        dlclose(host); return 1;
                    }
                    int before = kind == 5 ? host_fwide(stream, 0) : fwide(stream, 0);
                    before = (before > 0) - (before < 0);
                    int bad = before != (kind >= 3 ? 0 : -1);
                    unsigned char output[32];
                    memset(output, 0xA5, sizeof(output));
                    int status = 0x5EED;
                    size_t n = limits[limit];
                    size_t count = api == 2
                        ? read_line(stream, (char *)output, n, '\n', extract)
                        : read_info(stream, (char *)output, n, '\n', extract,
                                    api == 0 ? &status : NULL);
                    int orientation = kind == 5 ? host_fwide(stream, 0) : fwide(stream, 0);
                    orientation = (orientation > 0) - (orientation < 0);
                    int at_eof = (kind == 5 ? host_feof(stream) : feof(stream)) != 0;
                    int error = (kind == 5 ? host_ferror(stream) : ferror(stream)) != 0;
                    int next[2] = {kind == 5 ? host_fgetc(stream) : fgetc(stream), 0};
                    next[1] = kind == 5 ? host_fgetc(stream) : fgetc(stream);

                    size_t expected_count = 0;
                    int expected_status = 0, expected_eof = 0, expected_error = 0;
                    int expected_next[2] = {EOF, EOF};
                    if (n == 0) {
                        if (kind == 1 || kind == 2 || kind >= 4) {
                            expected_next[0] = 'a'; expected_next[1] = 'b';
                        }
                    } else if (kind == 0 || kind == 3) {
                        expected_status = EOF;
                        expected_eof = kind == 0;
                        expected_error = kind == 3;
                    } else if (n == 2) {
                        expected_count = 2;
                        expected_next[0] = kind == 2 ? '\n' : 'c';
                        expected_next[1] = kind == 2 ? 'c' : EOF;
                    } else if (kind == 2) {
                        expected_count = extract > 0 ? 3 : 2;
                        expected_next[0] = extract < 0 ? '\n' : 'c';
                        expected_next[1] = extract < 0 ? 'c' : 'd';
                    } else {
                        expected_count = 3;
                        expected_status = EOF;
                        expected_eof = kind == 1;
                        expected_error = kind >= 4;
                    }
                    bad |= count != expected_count || count > n || orientation != -1;
                    bad |= at_eof != expected_eof || error != expected_error;
                    bad |= api == 0 ? status != expected_status : status != 0x5EED;
                    bad |= next[0] != expected_next[0] || next[1] != expected_next[1];
                    bad |= memcmp(output, backing, expected_count) != 0;
                    for (size_t i = expected_count; i < sizeof(output); ++i)
                        bad |= output[i] != 0xA5;
                    bad |= (kind == 5 ? host_fclose(stream) : fclose(stream)) != 0;
                    if (fds[1] >= 0) bad |= close(fds[1]) != 0;
                    if (bad) fprintf(stderr,
                        "FAIL internal-line kind=%d n=%zu extract=%d api=%d count=%zu status=%d orientation=%d eof=%d error=%d next=%d,%d\n",
                        kind, n, extract, api, count, status, orientation,
                        at_eof, error, next[0], next[1]);
                    printf("internal-line kind=%d n=%zu extract=%d api=%d count=%zu status=%d orientation=%d eof=%d error=%d next=%d,%d\n",
                           kind, n, extract, api, count, status, orientation,
                           at_eof, error, next[0], next[1]);
                    failed += bad != 0;
                    ++cases;
                }
            }
        }
    }
    printf("fixture_stdio internal-lines: %s (%d cases, %d failed)\n",
           failed ? "FAIL" : "PASS", cases, failed);
    failed += dlclose(host) != 0;
    return failed != 0;
}

int main(int argc, char **argv) {
    if (argc >= 2 && strcmp(argv[1], "internal-lines") == 0) {
        const char *symbols[] = {"_IO_getline_info", "_IO_getline", "fmemopen", "fdopen",
                                 "fwide", "fgetc", "ferror", "feof", "fclose"};
        if (argc != 3 || check_stdio_providers(argv[2], symbols,
                                              sizeof(symbols) / sizeof(symbols[0]))) return 2;
        return test_internal_line_reads();
    }
    if (argc >= 2 && strcmp(argv[1], "cookie-lines") == 0) {
        const char *symbols[] = {"fopencookie", "getline", "getdelim", "__getdelim",
                                 "fgetc", "ungetc", "setvbuf", "clearerr", "ferror", "feof", "fclose"};
        if (argc != 3 || check_stdio_providers(argv[2], symbols,
                                              sizeof(symbols) / sizeof(symbols[0]))) return 2;
        return test_cookie_line_reads();
    }
    if (argc >= 2 && strcmp(argv[1], "fmemopen") == 0) {
        const char *symbols[] = {"fmemopen", "fgetc", "fread", "fgets", "__isoc99_fscanf",
                                 "getline", "getdelim", "malloc", "free", "fputc", "ferror",
                                 "clearerr", "fwrite", "fflush", "ftell", "fseek", "ungetc",
                                 "setvbuf", "feof", "fclose"};
        if (argc != 3 || check_stdio_providers(argv[2], symbols,
                                              sizeof(symbols) / sizeof(symbols[0]))) return 2;
        return test_fmemopen_coherence();
    }
    int helper_result = popen_helper(argc, argv);
    if (helper_result >= 0) return helper_result;
    if (argc >= 2 && strcmp(argv[1], "popen") == 0) {
        const char *symbols[] = {"popen", "pclose", "fclose", "fileno", "fgets", "fread",
                                 "fwrite", "fputs", "setvbuf", "pthread_create", "pthread_join",
                                 "pthread_cancel"};
        if (argc == 3 && check_stdio_providers(argv[2], symbols,
                                              sizeof(symbols) / sizeof(symbols[0]))) return 2;
        return test_popen_lifecycle();
    }
    if (argc >= 2 && strcmp(argv[1], "cookie-eintr") == 0) {
        const char *symbols[] = {"fopencookie", "fread", "setvbuf", "ferror", "feof", "fclose"};
        if (argc == 3 && check_stdio_providers(argv[2], symbols,
                                              sizeof(symbols) / sizeof(symbols[0]))) return 2;
        int failed = test_cookie_mid_read_eintr(_IOFBF);
        failed += test_cookie_mid_read_eintr(_IONBF);
        return failed ? 1 : 0;
    }
    if (argc >= 2 && strcmp(argv[1], "fd-errors") == 0) {
        const char *symbols[] = {"fdopen", "fgetc", "fread", "fgets", "getline", "getdelim",
                                 "setvbuf", "clearerr", "ferror", "feof", "fclose", "fopencookie"};
        if (argc == 3 && check_stdio_providers(argv[2], symbols,
                                              sizeof(symbols) / sizeof(symbols[0]))) return 2;
        return test_fd_read_errors();
    }
    if (argc >= 2 && strcmp(argv[1], "write-errors") == 0) {
        const char *symbols[] = {"fdopen", "fwrite", "fflush", "ftell", "fseek", "setvbuf",
                                 "clearerr", "ferror", "feof", "fclose", "fopencookie"};
        if (argc == 3 && check_stdio_providers(argv[2], symbols,
                                              sizeof(symbols) / sizeof(symbols[0]))) return 2;
        return test_fd_write_errors();
    }
    int fails = 0;
    fails += test_fopen_fileno_setvbuf_setbuf();
    fails += test_fputs_fputc_fflush_and_fread_roundtrip();
    fails += test_fgets_fgetc_ungetc_sequence();
    fails += test_invalid_mode_and_ungetc_eof();
    fails += test_setvbuf_rejects_post_io_change();
    fails += test_fread_fwrite_zero_size_contract();
    fails += test_fprintf_fscanf_fseek_roundtrip();
    fails += test_cookie_mid_read_eintr(_IOFBF);
    fails += test_cookie_mid_read_eintr(_IONBF);
    fails += test_cookie_scanf_preserves_unread_suffix();

    if (fails) {
        fprintf(stderr, "fixture_stdio: %d FAILED\n", fails);
        return 1;
    }
    printf("fixture_stdio: PASS (10 tests)\n");
    return 0;
}
