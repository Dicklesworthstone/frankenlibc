/* fixture_stdio_printf.c — stdio phase-2 printf-family operations under LD_PRELOAD
 * Part of frankenlibc C fixture suite.
 * Exit 0 = PASS, nonzero = FAIL with diagnostic to stderr.
 */
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

static int make_temp_path(char path[72]) {
    strcpy(path, "/tmp/frankenlibc_fixture_stdio_printf_XXXXXX");
    int fd = mkstemp(path);
    if (fd < 0) {
        fprintf(stderr, "FAIL: mkstemp: %s\n", strerror(errno));
        return 1;
    }
    close(fd);
    return 0;
}

static int read_file_exact(const char *path, char *buf, size_t cap) {
    FILE *fp = fopen(path, "r");
    if (fp == NULL) {
        fprintf(stderr, "FAIL: fopen read '%s': %s\n", path, strerror(errno));
        return -1;
    }
    size_t n = fread(buf, 1, cap - 1, fp);
    if (ferror(fp)) {
        fprintf(stderr, "FAIL: fread '%s': %s\n", path, strerror(errno));
        fclose(fp);
        return -1;
    }
    buf[n] = '\0';
    fclose(fp);
    return (int)n;
}

static int test_snprintf_contracts(void) {
    char buf[5] = {0};
    int rc = snprintf(buf, sizeof(buf), "abcdef");
    if (rc != 6) {
        fprintf(stderr, "FAIL: snprintf length expected 6 got %d\n", rc);
        return 1;
    }
    if (strcmp(buf, "abcd") != 0) {
        fprintf(stderr, "FAIL: snprintf truncation mismatch got '%s'\n", buf);
        return 1;
    }

    rc = snprintf(NULL, 0, "xyz=%d", 9);
    if (rc != 5) {
        fprintf(stderr, "FAIL: snprintf(NULL,0,...) expected 5 got %d\n", rc);
        return 1;
    }
    return 0;
}

static int test_sprintf_contracts(void) {
    char buf[64] = {0};
    int rc = sprintf(buf, "x=%d %s", 17, "ok");
    if (rc != 7) {
        fprintf(stderr, "FAIL: sprintf length expected 7 got %d\n", rc);
        return 1;
    }
    if (strcmp(buf, "x=17 ok") != 0) {
        fprintf(stderr, "FAIL: sprintf output mismatch got '%s'\n", buf);
        return 1;
    }
    return 0;
}

static int test_fprintf_contracts(void) {
    char path[72];
    if (make_temp_path(path) != 0) {
        return 1;
    }

    FILE *fp = fopen(path, "w+");
    if (fp == NULL) {
        fprintf(stderr, "FAIL: fopen w+ for fprintf: %s\n", strerror(errno));
        unlink(path);
        return 1;
    }

    int rc = fprintf(fp, "v=%u:%c", 42u, 'Z');
    if (rc != 6) {
        fprintf(stderr, "FAIL: fprintf length expected 6 got %d\n", rc);
        fclose(fp);
        unlink(path);
        return 1;
    }

    if (fflush(fp) != 0 || fclose(fp) != 0) {
        fprintf(stderr, "FAIL: fflush/fclose after fprintf failed\n");
        unlink(path);
        return 1;
    }

    char out[32] = {0};
    if (read_file_exact(path, out, sizeof(out)) < 0) {
        unlink(path);
        return 1;
    }
    if (strcmp(out, "v=42:Z") != 0) {
        fprintf(stderr, "FAIL: fprintf persisted output mismatch got '%s'\n", out);
        unlink(path);
        return 1;
    }

    unlink(path);
    return 0;
}

static int test_printf_redirect_contracts(void) {
    char path[72];
    if (make_temp_path(path) != 0) {
        return 1;
    }

    int out_fd = open(path, O_CREAT | O_TRUNC | O_WRONLY, 0600);
    if (out_fd < 0) {
        fprintf(stderr, "FAIL: open redirect path: %s\n", strerror(errno));
        unlink(path);
        return 1;
    }

    int saved_stdout = dup(STDOUT_FILENO);
    if (saved_stdout < 0) {
        fprintf(stderr, "FAIL: dup stdout: %s\n", strerror(errno));
        close(out_fd);
        unlink(path);
        return 1;
    }

    if (dup2(out_fd, STDOUT_FILENO) < 0) {
        fprintf(stderr, "FAIL: dup2 redirect stdout: %s\n", strerror(errno));
        close(saved_stdout);
        close(out_fd);
        unlink(path);
        return 1;
    }
    close(out_fd);

    int rc = printf("p=%d", 91);
    if (rc != 4) {
        fprintf(stderr, "FAIL: printf length expected 4 got %d\n", rc);
        dup2(saved_stdout, STDOUT_FILENO);
        close(saved_stdout);
        unlink(path);
        return 1;
    }
    fflush(stdout);

    if (dup2(saved_stdout, STDOUT_FILENO) < 0) {
        fprintf(stderr, "FAIL: dup2 restore stdout: %s\n", strerror(errno));
        close(saved_stdout);
        unlink(path);
        return 1;
    }
    close(saved_stdout);

    char out[32] = {0};
    if (read_file_exact(path, out, sizeof(out)) < 0) {
        unlink(path);
        return 1;
    }
    if (strcmp(out, "p=91") != 0) {
        fprintf(stderr, "FAIL: printf redirected output mismatch got '%s'\n", out);
        unlink(path);
        return 1;
    }

    unlink(path);
    return 0;
}

static int test_dprintf_contracts(void) {
    char path[72];
    if (make_temp_path(path) != 0) {
        return 1;
    }

    int fd = open(path, O_CREAT | O_TRUNC | O_WRONLY, 0600);
    if (fd < 0) {
        fprintf(stderr, "FAIL: open for dprintf: %s\n", strerror(errno));
        unlink(path);
        return 1;
    }

    int rc = dprintf(fd, "dprintf-%u", 77u);
    if (rc != 10) {
        fprintf(stderr, "FAIL: dprintf length expected 10 got %d\n", rc);
        close(fd);
        unlink(path);
        return 1;
    }
    close(fd);

    char out[32] = {0};
    if (read_file_exact(path, out, sizeof(out)) < 0) {
        unlink(path);
        return 1;
    }
    if (strcmp(out, "dprintf-77") != 0) {
        fprintf(stderr, "FAIL: dprintf output mismatch got '%s'\n", out);
        unlink(path);
        return 1;
    }

    unlink(path);
    return 0;
}

int main(void) {
    int fails = 0;
    fails += test_snprintf_contracts();
    fails += test_sprintf_contracts();
    fails += test_fprintf_contracts();
    fails += test_printf_redirect_contracts();
    fails += test_dprintf_contracts();

    if (fails) {
        fprintf(stderr, "fixture_stdio_printf: %d FAILED\n", fails);
        return 1;
    }
    printf("fixture_stdio_printf: PASS (5 tests)\n");
    return 0;
}
