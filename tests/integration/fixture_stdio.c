/* fixture_stdio.c — stdio phase-1 stream operations under LD_PRELOAD
 * Part of frankenlibc C fixture suite.
 * Exit 0 = PASS, nonzero = FAIL with diagnostic to stderr.
 */
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

int main(void) {
    int fails = 0;
    fails += test_fopen_fileno_setvbuf_setbuf();
    fails += test_fputs_fputc_fflush_and_fread_roundtrip();
    fails += test_fgets_fgetc_ungetc_sequence();
    fails += test_invalid_mode_and_ungetc_eof();
    fails += test_setvbuf_rejects_post_io_change();
    fails += test_fread_fwrite_zero_size_contract();

    if (fails) {
        fprintf(stderr, "fixture_stdio: %d FAILED\n", fails);
        return 1;
    }
    printf("fixture_stdio: PASS (6 tests)\n");
    return 0;
}
