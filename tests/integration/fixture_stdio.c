/* fixture_stdio.c — stdio phase-1 stream operations under LD_PRELOAD
 * Part of frankenlibc C fixture suite.
 * Exit 0 = PASS, nonzero = FAIL with diagnostic to stderr.
 */
#define _GNU_SOURCE
#include <dlfcn.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

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

    if (setvbuf(fp, NULL, _IOFBF, 128) == 0) {
        fprintf(stderr, "FAIL: setvbuf after I/O unexpectedly succeeded\n");
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

static int check_cookie_providers(const char *expected) {
    const char *symbols[] = {"fopencookie", "fread", "setvbuf", "ferror", "feof", "fclose"};
    char *wanted = realpath(expected, NULL);
    if (!wanted) return 1;
    int failed = 0;
    for (size_t i = 0; i < sizeof(symbols) / sizeof(symbols[0]); ++i) {
        Dl_info info;
        void *address = dlsym(RTLD_DEFAULT, symbols[i]);
        if (!address || !dladdr(address, &info)) { failed = 1; break; }
        char *actual = realpath(info.dli_fname, NULL);
        fprintf(stderr, "provider %s=%s\n", symbols[i], info.dli_fname);
        if (!actual || strcmp(actual, wanted)) failed = 1;
        free(actual);
    }
    free(wanted);
    return failed;
}

int main(int argc, char **argv) {
    if (argc >= 2 && strcmp(argv[1], "cookie-eintr") == 0) {
        if (argc == 3 && check_cookie_providers(argv[2])) return 2;
        int failed = test_cookie_mid_read_eintr(_IOFBF);
        failed += test_cookie_mid_read_eintr(_IONBF);
        return failed ? 1 : 0;
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

    if (fails) {
        fprintf(stderr, "fixture_stdio: %d FAILED\n", fails);
        return 1;
    }
    printf("fixture_stdio: PASS (9 tests)\n");
    return 0;
}
