/* fixture_stdio_printf.c — stdio phase-2 printf-family operations under LD_PRELOAD
 * Part of frankenlibc C fixture suite.
 * Exit 0 = PASS, nonzero = FAIL with diagnostic to stderr.
 */
#define _GNU_SOURCE 1
#include <dlfcn.h>
#include <errno.h>
#include <fenv.h>
#include <fcntl.h>
#include <float.h>
#include <limits.h>
#include <stdint.h>
#include <pthread.h>
#include <sched.h>
#include <stdatomic.h>
#include <stdarg.h>
#include <stdio.h>
#include <printf.h>
#include <math.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>
#include <wchar.h>

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

static int call_vsnprintf(char *buf, size_t size, const char *fmt, ...) {
    va_list ap;
    va_start(ap, fmt);
    int rc = vsnprintf(buf, size, fmt, ap);
    va_end(ap);
    return rc;
}

static int call_vsprintf(char *buf, const char *fmt, ...) {
    va_list ap;
    va_start(ap, fmt);
    int rc = vsprintf(buf, fmt, ap);
    va_end(ap);
    return rc;
}

static int call_vdprintf(int fd, const char *fmt, ...) {
    va_list ap;
    va_start(ap, fmt);
    int rc = vdprintf(fd, fmt, ap);
    va_end(ap);
    return rc;
}

static int call_vasprintf(char **out, const char *fmt, ...) {
    va_list ap;
    va_start(ap, fmt);
    int rc = vasprintf(out, fmt, ap);
    va_end(ap);
    return rc;
}

static int call_vfprintf(FILE *fp, const char *fmt, ...) {
    va_list ap;
    va_start(ap, fmt);
    int rc = vfprintf(fp, fmt, ap);
    va_end(ap);
    return rc;
}

static int call_vswprintf(wchar_t *buf, size_t size, const wchar_t *fmt, ...) {
    va_list ap;
    va_start(ap, fmt);
    int rc = vswprintf(buf, size, fmt, ap);
    va_end(ap);
    return rc;
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

static int test_vsnprintf_contracts(void) {
    char buf[6] = {0};
    int rc = call_vsnprintf(buf, sizeof(buf), "v-%d-%s", 12, "xy");
    if (rc != 7) {
        fprintf(stderr, "FAIL: vsnprintf length expected 7 got %d\n", rc);
        return 1;
    }
    if (strcmp(buf, "v-12-") != 0) {
        fprintf(stderr, "FAIL: vsnprintf truncation mismatch got '%s'\n", buf);
        return 1;
    }

    rc = call_vsnprintf(NULL, 0, "x=%d", 7);
    if (rc != 3) {
        fprintf(stderr, "FAIL: vsnprintf(NULL,0,...) expected 3 got %d\n", rc);
        return 1;
    }
    return 0;
}

static int test_vsprintf_contracts(void) {
    char buf[64] = {0};
    int rc = call_vsprintf(buf, "vsprintf:%u:%c", 5u, 'Q');
    if (rc != 12) {
        fprintf(stderr, "FAIL: vsprintf length expected 12 got %d\n", rc);
        return 1;
    }
    if (strcmp(buf, "vsprintf:5:Q") != 0) {
        fprintf(stderr, "FAIL: vsprintf output mismatch got '%s'\n", buf);
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

static int test_vdprintf_contracts(void) {
    char path[72];
    if (make_temp_path(path) != 0) {
        return 1;
    }

    int fd = open(path, O_CREAT | O_TRUNC | O_WRONLY, 0600);
    if (fd < 0) {
        fprintf(stderr, "FAIL: open for vdprintf: %s\n", strerror(errno));
        unlink(path);
        return 1;
    }

    int rc = call_vdprintf(fd, "vdp-%u", 66u);
    if (rc != 6) {
        fprintf(stderr, "FAIL: vdprintf length expected 6 got %d\n", rc);
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
    if (strcmp(out, "vdp-66") != 0) {
        fprintf(stderr, "FAIL: vdprintf output mismatch got '%s'\n", out);
        unlink(path);
        return 1;
    }

    unlink(path);
    return 0;
}

static int test_asprintf_contracts(void) {
    char *out = NULL;
    int rc = asprintf(&out, "asprintf-%d:%s", 55, "ok");
    if (rc != 14) {
        fprintf(stderr, "FAIL: asprintf length expected 14 got %d\n", rc);
        free(out);
        return 1;
    }
    if (out == NULL) {
        fprintf(stderr, "FAIL: asprintf returned NULL output pointer\n");
        return 1;
    }
    if (strcmp(out, "asprintf-55:ok") != 0) {
        fprintf(stderr, "FAIL: asprintf output mismatch got '%s'\n", out);
        free(out);
        return 1;
    }
    free(out);
    return 0;
}

static int test_vasprintf_contracts(void) {
    char *out = NULL;
    int rc = call_vasprintf(&out, "vasprintf-%u:%s", 66u, "ok");
    if (rc != 15) {
        fprintf(stderr, "FAIL: vasprintf length expected 15 got %d\n", rc);
        free(out);
        return 1;
    }
    if (out == NULL) {
        fprintf(stderr, "FAIL: vasprintf returned NULL output pointer\n");
        return 1;
    }
    if (strcmp(out, "vasprintf-66:ok") != 0) {
        fprintf(stderr, "FAIL: vasprintf output mismatch got '%s'\n", out);
        free(out);
        return 1;
    }
    free(out);
    return 0;
}

/* Direct calls exercise the GNU callbacks independently of registration.  The
 * same executable runs against glibc and each candidate; output includes return
 * values, write bounds, and bytes so a plausible-looking string cannot pass. */
static int check_gnu_provider(const char *name) {
    const char *expected = getenv("FRANKENLIBC_TEST_LIBRARY");
    if (!expected) return 0;
    Dl_info info;
    struct stat actual, wanted;
    void *symbol = dlsym(RTLD_DEFAULT, name);
    if (!symbol || !dladdr(symbol, &info) || stat(info.dli_fname, &actual) ||
        stat(expected, &wanted) || actual.st_dev != wanted.st_dev ||
        actual.st_ino != wanted.st_ino) {
        fprintf(stderr, "FAIL: wrong provider for %s\n", name);
        return 1;
    }
    return 0;
}

static int gnu_types(void) {
    if (check_gnu_provider("parse_printf_format") ||
        check_gnu_provider("printf_size_info")) return 1;
    static const char *formats[] = {
        "%d %i %u %o %x %X %b %B", "%hhd %hd %ld %lld %jd %zd %td %qd %Ld",
        "%c %lc %C %s %ls %S %p", "%f %lf %Lf %a %La",
        "%n %hhn %hn %ln %lln %zn %Ln", "%*.*f", "%3$*2$.*1$f",
        "%2$s %1$d %2$s", "%5$d", "%% %m %Q", "%*Q %.*m %d",
        "%Iu %'d", "%w8d %w16d %w32d %w64d %wf16d", "end%", "%0$d",
        "%2$*4$d %1$s", "%2$d %2$f", "%*2$d %d",
        "%5$Q %3$m %2$%", "%4$*2$Q %1$s", "%2147483648$d",
        "%hhf %hf %llf %qf"
    };
    for (size_t f = 0; f < sizeof(formats) / sizeof(formats[0]); ++f) {
        for (size_t cap = 0; cap <= 12; ++cap) {
            int types[14];
            for (size_t k = 0; k < 14; ++k) types[k] = -77;
            size_t count = parse_printf_format(formats[f], cap, types);
            printf("types:%zu:%zu:%zu", f, cap, count);
            for (size_t k = 0; k < 14; ++k) printf(":%d", types[k]);
            putchar('\n');
        }
    }
    struct printf_info info = {0};
    for (unsigned flags = 0; flags < 4; ++flags) {
        info.is_long_double = flags & 1;
        info.is_binary128 = (flags >> 1) & 1;
        for (size_t cap = 0; cap < 3; ++cap) {
            int types[3] = {-77, -77, -77};
            int rc = printf_size_info(&info, cap, types);
            printf("info:%u:%zu:%d:%d:%d:%d\n", flags, cap, rc,
                   types[0], types[1], types[2]);
        }
    }
    return 0;
}

static int gnu_sizes(void) {
    if (check_gnu_provider("printf_size")) return 1;
    static const long double values[] = {
        0.0L, -0.0L, 1.0L, 999.9995L, 1000.0L, 1023.9995L, 1024.0L,
        1048576.0L, -1048576.0L, 1e30L, INFINITY, -INFINITY, NAN,
        3.141592653589793238512809L, 1e400L
    };
    for (unsigned kind = 0; kind < 3; ++kind) {
        for (size_t v = 0; v < sizeof(values) / sizeof(values[0]); ++v) {
            for (unsigned style = 0; style < 26; ++style) {
                if (style >= 24 && v != 6) continue;
                struct printf_info info = {0};
                info.prec = style >= 24 ? 65535 + (int)(style - 24) :
                            style < 8 ? -1 : style >= 16 ? 25 : (int)(style % 4);
                info.width = style % 4 ? 16 : 0;
                info.spec = style & 1 ? L'S' : L's';
                info.pad = style & 2 ? L'0' : L' ';
                info.left = (style >> 2) & 1;
                info.showsign = (style >> 3) & 1;
                info.space = style == 3;
                info.alt = style == 4;
                info.group = style == 5;
                info.is_long_double = kind == 1;
                info.is_binary128 = kind == 2;
                double d = (double)values[v];
                long double ld = values[v];
                _Float128 q = (_Float128)values[v];
                if (v == 13) q = 3.141592653589793238462643383279502884197F128;
                const void *arg = kind == 0 ? (void *)&d :
                                  kind == 1 ? (void *)&ld : (void *)&q;
                for (unsigned wide = 0; wide < 2; ++wide) {
                    char *bytes = NULL;
                    wchar_t *chars = NULL;
                    size_t count = 0;
                    FILE *fp = wide ? open_wmemstream(&chars, &count) :
                                      open_memstream(&bytes, &count);
                    if (!fp) return 1;
                    info.wide = wide;
                    errno = 0;
                    int rc = printf_size(fp, &info, &arg);
                    int err = errno;
                    if (fclose(fp)) return 1;
                    printf("size:%u:%zu:%u:%u:%d:%d:%zu:", kind, v, style,
                           wide, rc, err, count);
                    for (size_t k = 0; k < count; ++k)
                        printf("%02x", wide ? (unsigned)chars[k] :
                               (unsigned)(unsigned char)bytes[k]);
                    putchar('\n');
                    free(bytes);
                    free(chars);
                }
            }
        }
    }
    return 0;
}

static int gnu_size_errors(void) {
    if (check_gnu_provider("printf_size")) return 1;
    for (unsigned wide = 0; wide < 2; ++wide) {
        for (unsigned broken = 0; broken < 2; ++broken) {
            FILE *fp = fopen("/dev/full", "w");
            if (!fp || setvbuf(fp, NULL, _IONBF, 0)) return 1;
            if (wide && fwide(fp, 1) <= 0) return 1;
            if (broken && close(fileno(fp))) return 1;
            struct printf_info info = { .prec = 3, .spec = L's', .pad = L' ' };
            info.wide = wide;
            double d = 1024.0;
            const void *arg = &d;
            errno = 0;
            int rc = printf_size(fp, &info, &arg);
            int err = errno;
            printf("error:%u:%u:%d:%d:%d\n", wide, broken, rc, err, !!ferror(fp));
            fclose(fp);
        }
    }
    return 0;
}

/* These use exactly representable inputs so the rounding mode controls the
 * conversion rather than the construction of the test value. */
static int gnu_extended_rounding(void) {
    if (check_gnu_provider("printf_size") || check_gnu_provider("strfromf128") ||
        check_gnu_provider("snprintf") || check_gnu_provider("swprintf") ||
        check_gnu_provider("fegetround") || check_gnu_provider("fesetround") ||
        check_gnu_provider("fegetenv") || check_gnu_provider("fesetenv")) return 1;
    static const int modes[] = { FE_TONEAREST, FE_DOWNWARD, FE_UPWARD, FE_TOWARDZERO };
    static const long double values[] = {
        0.0L, -0.0L, 0.125L, -0.125L, 0.5L, -0.5L, 1.25L, -1.25L,
        1.75L, -1.75L, 9.5L, -9.5L, 15.5L, -15.5L, 0x1p-20L,
        -0x1p-20L, 0x1.fffffffffffffffep+3L, 0x1p+80L,
        1024.0L, 1234567.0L, INFINITY, -INFINITY, NAN,
        LDBL_MIN, LDBL_TRUE_MIN, -LDBL_TRUE_MIN,
        0x1.fffffffffffffffep-1L, 0x1.0000000000000002p+0L,
        0x1.fffffffffffffffep+80L, 0x1.f4p+80L
    };
    static const char convs[] = "feg aFEGA";
    static const int precisions[] = {0, 1, 2, 6, 25};
    int saved = fegetround();
    for (unsigned m = 0; m < sizeof(modes) / sizeof(modes[0]); ++m) {
        if (fesetround(modes[m]) || fegetround() != modes[m]) return 1;
        for (unsigned v = 0; v < sizeof(values) / sizeof(values[0]); ++v) {
            for (unsigned c = 0; c < sizeof(convs) - 1; ++c) {
                if (convs[c] == ' ') continue;
                for (unsigned p = 0; p < sizeof(precisions) / sizeof(precisions[0]); ++p) {
                    for (unsigned kind = 0; kind < 3; ++kind) {
                        char fmt[32], buf[256] = {0};
                        snprintf(fmt, sizeof(fmt), kind == 1 ? "%%.%d%c" : "%%.%dL%c", precisions[p], convs[c]);
                        _Float128 q = (_Float128)values[v];
                        if (v == 24) q = 0x1p-16494F128;
                        if (v == 25) q = -0x1p-16494F128;
                        if (v == 26) q = 0x1.ffffffffffffffffffffffffffffp-1F128;
                        if (v == 27) q = 0x1.0000000000000000000000000001p+0F128;
                        if (v == 28) q = 0x1.ffffffffffffffffffffffffffffp+80F128;
                        if (v == 29) q = 0x1.f400000000000000000000000001p+80F128;
                        errno = 0;
                        int rc;
                        if (kind == 2) {
                            wchar_t wfmt[32], wide[256];
                            for (size_t k = 0; k <= strlen(fmt); ++k) wfmt[k] = (unsigned char)fmt[k];
                            rc = swprintf(wide, sizeof(wide) / sizeof(wide[0]), wfmt, values[v]);
                            if (rc < 0 || rc >= (int)sizeof(buf)) return 1;
                            for (int k = 0; k <= rc; ++k) buf[k] = (char)wide[k];
                        } else {
                            rc = kind ? strfromf128(buf, sizeof(buf), fmt, q) :
                                        snprintf(buf, sizeof(buf), fmt, values[v]);
                        }
                        int err = errno;
                        printf("round:%u:%u:%u:%u:%u:%d:%d:", m, v, c, p, kind, rc, err);
                        for (unsigned k = 0; k < strlen(buf); ++k) printf("%02x", (unsigned char)buf[k]);
                        putchar('\n');
                    }
                }
            }
            for (unsigned kind = 0; kind < 3; ++kind) {
                for (unsigned upper = 0; upper < 2; ++upper) {
                  for (unsigned wide = 0; wide < 2; ++wide) {
                    struct printf_info info = { .prec = 1, .spec = upper ? L'S' : L's', .pad = L' ' };
                    info.is_long_double = kind == 1;
                    info.is_binary128 = kind == 2;
                    double d = (double)values[v];
                    long double ld = values[v];
                    _Float128 q = (_Float128)values[v];
                    if (v == 24) q = 0x1p-16494F128;
                    if (v == 25) q = -0x1p-16494F128;
                    if (v == 28) q = 0x1.ffffffffffffffffffffffffffffp+80F128;
                    if (v == 29) q = 0x1.f400000000000000000000000001p+80F128;
                    const void *arg = kind == 0 ? (void *)&d : kind == 1 ? (void *)&ld : (void *)&q;
                    char *buf = NULL;
                    wchar_t *chars = NULL;
                    size_t len = 0;
                    FILE *fp = wide ? open_wmemstream(&chars, &len) : open_memstream(&buf, &len);
                    if (!fp) return 1;
                    info.wide = wide;
                    errno = 0;
                    int rc = printf_size(fp, &info, &arg), err = errno;
                    if (fclose(fp)) return 1;
                    printf("round-size:%u:%u:%u:%u:%u:%d:%d:", m, v, kind, upper, wide, rc, err);
                    for (size_t k = 0; k < len; ++k) printf("%02x", wide ? (unsigned)chars[k] : (unsigned char)buf[k]);
                    putchar('\n');
                    free(buf);
                    free(chars);
                  }
                }
            }
        }
    }
    return fesetround(saved) != 0;
}

static int gnu_double_rounding(void) {
    static const char *providers[] = {
        "snprintf", "vsnprintf", "sprintf", "vsprintf", "asprintf", "vasprintf",
        "fprintf", "vfprintf", "swprintf", "vswprintf",
        "fegetround", "fesetround", "fegetenv", "fesetenv"
    };
    for (unsigned i = 0; i < sizeof(providers) / sizeof(providers[0]); ++i)
        if (check_gnu_provider(providers[i])) return 1;
    static const int modes[] = { FE_TONEAREST, FE_DOWNWARD, FE_UPWARD, FE_TOWARDZERO };
    static const double values[] = {
        0.0, -0.0, 0.125, -0.125, 0.5, -0.5, 1.25, -1.25, 9.5, -9.5,
        0.1, -0.1, DBL_TRUE_MIN, -DBL_TRUE_MIN, DBL_MIN, -DBL_MIN,
        DBL_MAX, -DBL_MAX, 0x1.fffffffffffffp-1, 0x1.fffffffffffffp+3,
        INFINITY, -INFINITY, NAN, -NAN
    };
    static const char convs[] = "feg aFEGA";
    static const int precisions[] = {0, 1, 2, 6};
    static const int boundaries[] = {17, 25, 99, 100, 1101};
    int saved = fegetround();
    for (unsigned m = 0; m < sizeof(modes) / sizeof(modes[0]); ++m) {
        if (fesetround(modes[m]) || fegetround() != modes[m]) return 1;
        for (unsigned v = 0; v < sizeof(values) / sizeof(values[0]); ++v) {
            double value = values[v];
            for (unsigned c = 0; c < sizeof(convs) - 1; ++c) {
                if (convs[c] == ' ') continue;
                for (unsigned p = 0; p < sizeof(precisions) / sizeof(precisions[0]); ++p) {
                    int precision = precisions[p];
                    for (unsigned style = 0; style < 9; ++style) {
                        if (style >= 3 && convs[c] != 'f' && convs[c] != 'F') continue;
                        char fmt[48];
                        if (style == 2) snprintf(fmt, sizeof(fmt), "[%%2$0*1$.*3$%c]", convs[c]);
                        else if (style >= 3) {
                            static const char *flags[] = {"+020", "-020", " 20", "3", "+400", "#010"};
                            snprintf(fmt, sizeof(fmt), "[%%%s.%d%c]", flags[style - 3], precision, convs[c]);
                        }
                        else snprintf(fmt, sizeof(fmt), style ? "%%+#18.%d%c" : "%%.%d%c", precision, convs[c]);
                        for (unsigned kind = 0; kind < 10; ++kind) {
                            char buf[512] = {0}, *allocated = NULL;
                            wchar_t wfmt[48], wide[512];
                            for (size_t k = 0; k <= strlen(fmt); ++k) wfmt[k] = (unsigned char)fmt[k];
                            size_t len = 0;
                            FILE *fp = NULL;
                            if (kind == 6 || kind == 7) {
                                fp = open_memstream(&allocated, &len);
                                if (!fp) return 1;
                            }
                            errno = 0;
                            int rc;
#define DOUBLE_CALL(fn, form, ...) (style == 2 ? fn(__VA_ARGS__, form, 18, value, precision) : fn(__VA_ARGS__, form, value))
                            switch (kind) {
                            case 0: rc = DOUBLE_CALL(snprintf, fmt, buf, sizeof(buf)); break;
                            case 1: rc = DOUBLE_CALL(call_vsnprintf, fmt, buf, 8); break;
                            case 2: rc = DOUBLE_CALL(sprintf, fmt, buf); break;
                            case 3: rc = DOUBLE_CALL(call_vsprintf, fmt, buf); break;
                            case 4: rc = DOUBLE_CALL(asprintf, fmt, &allocated); break;
                            case 5: rc = DOUBLE_CALL(call_vasprintf, fmt, &allocated); break;
                            case 6: rc = DOUBLE_CALL(fprintf, fmt, fp); break;
                            case 7: rc = DOUBLE_CALL(call_vfprintf, fmt, fp); break;
                            case 8: rc = DOUBLE_CALL(swprintf, wfmt, wide, sizeof(wide) / sizeof(wide[0])); break;
                            default: rc = DOUBLE_CALL(call_vswprintf, wfmt, wide, sizeof(wide) / sizeof(wide[0])); break;
                            }
#undef DOUBLE_CALL
                            int err = errno;
                            if (fp && fclose(fp)) return 1;
                            if (rc < 0) return 1;
                            if (kind >= 8) {
                                if (rc >= (int)sizeof(buf)) return 1;
                                for (int k = 0; k <= rc; ++k) buf[k] = (char)wide[k];
                            }
                            const char *text = allocated ? allocated : buf;
                            printf("double:%u:%u:%u:%u:%u:%u:%d:%d:", m, v, c, p, style, kind, rc, err);
                            for (size_t k = 0; k < strlen(text); ++k) printf("%02x", (unsigned char)text[k]);
                            putchar('\n');
                            free(allocated);
                        }
                    }
                }
            }
        }
        static const double edge_values[] = {0.1, -0.1, DBL_TRUE_MIN, -DBL_MAX};
        for (unsigned v = 0; v < sizeof(edge_values) / sizeof(edge_values[0]); ++v) {
            for (unsigned c = 0; c < sizeof(convs) - 1; ++c) {
                if (convs[c] == ' ') continue;
                for (unsigned p = 0; p < sizeof(boundaries) / sizeof(boundaries[0]); ++p) {
                    char fmt[32], *buf = NULL;
                    snprintf(fmt, sizeof(fmt), "%%#.%d%c", boundaries[p], convs[c]);
                    errno = 0;
                    int rc = asprintf(&buf, fmt, edge_values[v]), err = errno;
                    if (rc < 0 || !buf) return 1;
                    printf("double-edge:%u:%u:%u:%u:%d:%d:", m, v, c, p, rc, err);
                    for (size_t k = 0; k < strlen(buf); ++k) printf("%02x", (unsigned char)buf[k]);
                    putchar('\n');
                    free(buf);
                }
            }
        }
    }
    return fesetround(saved) != 0;
}

struct rounding_thread_case {
    int mode;
    atomic_int *ready;
    unsigned failures;
    int ordinary;
};

static void *rounding_thread(void *opaque) {
    struct rounding_thread_case *test = opaque;
    if (fesetround(test->mode)) test->failures++;
    fenv_t selected;
    if (fegetenv(&selected) || fesetround(FE_TONEAREST) || fesetenv(&selected) ||
        fegetround() != test->mode) test->failures++;
    atomic_fetch_add(test->ready, 1);
    while (atomic_load(test->ready) != 4) sched_yield();
    const char *positive = test->mode == FE_UPWARD ? "0.13" : "0.12";
    const char *negative = test->mode == FE_DOWNWARD ? "-0.13" : "-0.12";
    for (unsigned i = 0; i < 100; ++i) {
        for (unsigned sign = 0; sign < 2; ++sign) {
            const char *expected = sign ? negative : positive;
            long double value = sign ? -0.125L : 0.125L;
            char buf[32] = {0};
            wchar_t wide[32];
            int rc = test->ordinary ? snprintf(buf, sizeof(buf), "%.2f", (double)value) :
                                     snprintf(buf, sizeof(buf), "%.*Lf", 2, value);
            test->failures += rc != (int)strlen(expected) || strcmp(buf, expected) != 0;
            rc = test->ordinary ? call_vsnprintf(buf, sizeof(buf), "%.*f", 2, (double)value) :
                                  strfromf128(buf, sizeof(buf), "%.2f", (_Float128)value);
            test->failures += rc != (int)strlen(expected) || strcmp(buf, expected) != 0;
            rc = test->ordinary ? swprintf(wide, sizeof(wide) / sizeof(wide[0]), L"%.2f", (double)value) :
                                 swprintf(wide, sizeof(wide) / sizeof(wide[0]), L"%.*Lf", 2, value);
            test->failures += rc != (int)strlen(expected);
            if (rc == (int)strlen(expected))
                for (int k = 0; k <= rc; ++k) test->failures += wide[k] != (unsigned char)expected[k];
        }
    }
    return NULL;
}

static int gnu_rounding_threads(int ordinary) {
    atomic_int ready = 0;
    struct rounding_thread_case cases[4] = {
        {FE_TONEAREST, &ready, 0, ordinary}, {FE_DOWNWARD, &ready, 0, ordinary},
        {FE_UPWARD, &ready, 0, ordinary}, {FE_TOWARDZERO, &ready, 0, ordinary}
    };
    pthread_t threads[4];
    for (unsigned i = 0; i < 4; ++i)
        if (pthread_create(&threads[i], NULL, rounding_thread, &cases[i])) return 1;
    for (unsigned i = 0; i < 4; ++i) {
        if (pthread_join(threads[i], NULL)) return 1;
        printf("round-thread:%u:%u\n", i, cases[i].failures);
    }
    return 0;
}

static int unknown_vsnprintf(char *buf, size_t cap, const char *fmt, ...) {
    int (*render)(char *, size_t, const char *, va_list) = dlsym(RTLD_DEFAULT, "vsnprintf");
    va_list ap;
    va_start(ap, fmt);
    int rc = render(buf, cap, fmt, ap);
    va_end(ap);
    return rc;
}

static int unknown_vswprintf(wchar_t *buf, size_t cap, const wchar_t *fmt, ...) {
    int (*render)(wchar_t *, size_t, const wchar_t *, va_list) = dlsym(RTLD_DEFAULT, "vswprintf");
    va_list ap;
    va_start(ap, fmt);
    int rc = render(buf, cap, fmt, ap);
    va_end(ap);
    return rc;
}

static int gnu_unknown_conversions(void) {
    const char *providers[] = {"snprintf", "vsnprintf", "swprintf", "vswprintf"};
    for (unsigned i = 0; i < sizeof(providers) / sizeof(providers[0]); ++i)
        if (check_gnu_provider(providers[i])) return 1;
    /* Bind ordinary symbols explicitly: fortified header wrappers deliberately
     * reject %n in a generated writable format and test a different contract. */
    int (*narrow)(char *, size_t, const char *, ...) = dlsym(RTLD_DEFAULT, "snprintf");
    int (*wide_render)(wchar_t *, size_t, const wchar_t *, ...) = dlsym(RTLD_DEFAULT, "swprintf");
    if (!narrow || !wide_render) return 1;
    static const struct { const char *directive; unsigned args; } cases[] = {
        {"%Q", 0}, {"%#Q", 0}, {"%+ Q", 0}, {"%-05Q", 0},
        {"%'# +0-12.003Q", 0}, {"%0Q", 0}, {"%.0Q", 0}, {"%9.2Q", 0},
        {"%hhQ", 0}, {"%lQ", 0}, {"%llQ", 0}, {"%LQ", 0},
        {"%jQ", 0}, {"%zQ", 0}, {"%tQ", 0}, {"%qQ", 0},
        {"%*Q", 1}, {"%0*Q", 1}, {"%.*Q", 2}, {"%*.*Q", 3},
        {"%#0+*.*Q", 3}, {"%3$*1$.*2$Q", 4},
        {"%*Q%*R%*V%*K%*Y", 5}, {"%I*Q", 1}, {"%#I0*.*Q", 3}
    };
    static const size_t caps[] = {0, 1, 2, 5, 8, 64};
    static const int widths[] = {7, -7, 0, INT_MAX, INT_MIN};
    static const int precisions[] = {3, -3, 0, INT_MAX, INT_MIN};
    for (size_t c = 0; c < sizeof(cases) / sizeof(cases[0]); ++c) {
        for (unsigned sign = 0; sign < sizeof(widths) / sizeof(widths[0]); ++sign) {
            const int width = widths[sign], precision = precisions[sign];
            for (unsigned variant = 0; variant < 4; ++variant) {
                for (size_t k = 0; k < sizeof(caps) / sizeof(caps[0]); ++k) {
                    const int wide = variant >= 2;
                    char fmt[160];
                    const char *suffix = cases[c].args == 4 ? ":%3$d:%4$s:%5$.1f" : ":%d:%s:%.1f";
                    /* Wide truncation can stop before a final %n. Test its
                     * count with a full buffer, and bounds without a side
                     * effect for the deliberately truncated wide calls. */
                    const char *count_fmt = wide && caps[k] < 64 ? "" :
                        (cases[c].args == 4 ? "%6$n" : "%n");
                    snprintf(fmt, sizeof(fmt), "%s%s%s", cases[c].directive, suffix, count_fmt);
                    wchar_t wfmt[160];
                    for (size_t i = 0; i <= strlen(fmt); ++i) wfmt[i] = (unsigned char)fmt[i];
                    char bytes[64];
                    wchar_t words[64];
                    memset(bytes, 0x5a, sizeof(bytes));
                    for (unsigned i = 0; i < 64; ++i) words[i] = 0x5a;
                    int count = -77, rc = -99;
                    errno = 0;
#define UNKNOWN_CALL(function, destination, format) do { \
    switch (cases[c].args) { \
    case 0: rc = function(destination, caps[k], format, 701, "tail", 1.5, &count); break; \
    case 1: rc = function(destination, caps[k], format, width, 701, "tail", 1.5, &count); break; \
    case 2: rc = function(destination, caps[k], format, precision, 701, "tail", 1.5, &count); break; \
    case 3: case 4: rc = function(destination, caps[k], format, width, precision, 701, "tail", 1.5, &count); break; \
    case 5: rc = function(destination, caps[k], format, 1, -2, 3, -4, 5, 701, "tail", 1.5, &count); break; \
    } \
} while (0)
                    if (variant == 0) UNKNOWN_CALL(narrow, bytes, fmt);
                    else if (variant == 1) UNKNOWN_CALL(unknown_vsnprintf, bytes, fmt);
                    else if (variant == 2) UNKNOWN_CALL(wide_render, words, wfmt);
                    else UNKNOWN_CALL(unknown_vswprintf, words, wfmt);
#undef UNKNOWN_CALL
                    int error = errno;
                    printf("unknown:%zu:%u:%u:%zu:%d:%d:%d:", c, sign, variant, caps[k], rc, count, error);
                    for (unsigned i = 0; i < 64; ++i) {
                        if (wide) printf("%08x", (unsigned)words[i]);
                        else printf("%02x", (unsigned char)bytes[i]);
                    }
                    putchar('\n');
                }
            }
        }
    }
    return 0;
}

/* Registration is exercised in fresh processes so GNU's global registry cannot
 * contaminate unrelated oracles. Callbacks deliberately call printf again: a
 * lock held over either callback would deadlock rather than merely misformat. */
#define REG_CHECK(expr) do { if (!(expr)) { \
    fprintf(stderr, "registration failure at line %i: %s\n", __LINE__, #expr); \
    _Exit(91); \
} } while (0)

struct reg_pair { int number; double real; };
static int reg_pair_type;
static int reg_info_width, reg_info_precision;

static int reg_noargs(const struct printf_info *info, size_t n, int *types, int *sizes) {
    (void)info; (void)n; (void)types; (void)sizes;
    return 0;
}

static int reg_letter(FILE *stream, const struct printf_info *info, const void *const *args) {
    (void)args;
    return info->wide ? (fputwc(L'K', stream) == WEOF ? -1 : 1)
                      : (fputc('K', stream) == EOF ? -1 : 1);
}

static int reg_reenter(FILE *stream, const struct printf_info *info, const void *const *args) {
    (void)args;
    REG_CHECK(register_printf_specifier('K', reg_letter, reg_noargs) == 0);
    const char *fmt = "R%K";
    const wchar_t *wfmt = L"R%K";
    return info->wide ? fwprintf(stream, wfmt, 0) : fprintf(stream, fmt, 0);
}

static int reg_two_info(const struct printf_info *info, size_t n, int *types, int *sizes) {
    reg_info_width = info->width;
    reg_info_precision = info->prec;
    if (n > 0) { types[0] = PA_INT; if (sizes) sizes[0] = sizeof(int); }
    if (n > 1) { types[1] = PA_STRING; if (sizes) sizes[1] = sizeof(char *); }
    return 2;
}

static int reg_two(FILE *stream, const struct printf_info *info, const void *const *args) {
    int number = *(const int *)args[0];
    const char *text = *(const char *const *)args[1];
    unsigned flags = info->alt | (info->space << 1) | (info->left << 2) |
        (info->showsign << 3) | (info->group << 4) | (info->is_char << 5) |
        (info->is_short << 6) | (info->is_long << 7) |
        (info->is_long_double << 8) | (info->i18n << 9);
    return info->wide
        ? fwprintf(stream, L"Q{%i,%hs,%i,%i,%u,%u,%i}", number, text,
                   info->width, info->prec, (unsigned)info->user, flags, (int)info->pad)
        : fprintf(stream, "Q{%i,%s,%i,%i,%u,%u,%i}", number, text,
                  info->width, info->prec, (unsigned)info->user, flags, (int)info->pad);
}

static int reg_legacy_info(const struct printf_info *info, size_t n, int *types) {
    (void)info;
    if (n) types[0] = PA_INT;
    return 1;
}

static int reg_legacy(FILE *stream, const struct printf_info *info, const void *const *args) {
    return info->wide ? fwprintf(stream, L"Y{%i}", *(const int *)args[0])
                      : fprintf(stream, "Y{%i}", *(const int *)args[0]);
}

static void reg_pair_read(void *memory, va_list *ap) {
    *(struct reg_pair *)memory = va_arg(*ap, struct reg_pair);
}

static int reg_pair_info(const struct printf_info *info, size_t n, int *types, int *sizes) {
    (void)info;
    if (n) { types[0] = reg_pair_type; if (sizes) sizes[0] = sizeof(struct reg_pair); }
    return 1;
}

static int reg_pair_print(FILE *stream, const struct printf_info *info, const void *const *args) {
    const struct reg_pair *value = *(const struct reg_pair *const *)args[0];
    return info->wide ? fwprintf(stream, L"T{%i,%.2f}", value->number, value->real)
                      : fprintf(stream, "T{%i,%.2f}", value->number, value->real);
}

static int reg_float_info(const struct printf_info *info, size_t n, int *types, int *sizes) {
    (void)info;
    if (n) { types[0] = PA_FLOAT; if (sizes) sizes[0] = sizeof(double); }
    return 1;
}

static int reg_float_print(FILE *stream, const struct printf_info *info, const void *const *args) {
    double value = *(const double *)args[0];
    return info->wide ? fwprintf(stream, L"U{%.3f}", value)
                      : fprintf(stream, "U{%.3f}", value);
}

static int reg_d_info(const struct printf_info *info, size_t n, int *types, int *sizes) {
    if (info->is_long || info->is_long_double) return -1;
    if (n) { types[0] = PA_INT; if (sizes) sizes[0] = sizeof(int); }
    return 1;
}

static int reg_d_print(FILE *stream, const struct printf_info *info, const void *const *args) {
    if (info->is_long || info->is_long_double) return -2;
    int value = *(const int *)args[0];
    if (value == 42) return -2;
    return info->wide ? fwprintf(stream, L"D{%i}", value)
                      : fprintf(stream, "D{%i}", value);
}

static int reg_errno_print(FILE *stream, const struct printf_info *info, const void *const *args) {
    int rc = reg_letter(stream, info, args);
    errno = EINVAL;
    return rc;
}

static int reg_error(FILE *stream, const struct printf_info *info, const void *const *args) {
    (void)stream; (void)info; (void)args;
    errno = EIO;
    return -1;
}

static void reg_row(const char *label, int rc, int count, const char *buffer, size_t n) {
    static const char digits[] = "0123456789abcdef";
    char hex[2049];
    REG_CHECK(n <= 1024);
    for (size_t i = 0; i < n; ++i) {
        hex[2 * i] = digits[(unsigned char)buffer[i] >> 4];
        hex[2 * i + 1] = digits[(unsigned char)buffer[i] & 15];
    }
    hex[2 * n] = 0;
    printf("reg:%s:%i:%i:%s\n", label, rc, count, hex);
}

static void reg_wrow(const char *label, int rc, int count, const wchar_t *buffer) {
    char bytes[1024];
    size_t n = wcslen(buffer);
    REG_CHECK(n < sizeof bytes);
    for (size_t i = 0; i < n; ++i) {
        REG_CHECK(buffer[i] >= 0 && buffer[i] < 128);
        bytes[i] = (char)buffer[i];
    }
    reg_row(label, rc, count, bytes, n);
}

static void reg_setup(void) {
    static const char *providers[] = {
        "register_printf_specifier", "register_printf_function", "register_printf_type",
        "register_printf_modifier", "parse_printf_format", "printf", "vprintf", "fprintf",
        "vfprintf", "snprintf", "vsnprintf", "sprintf", "vsprintf", "asprintf", "vasprintf",
        "dprintf", "vdprintf", "swprintf", "vswprintf", "fwprintf", "vfwprintf", "wprintf", "vwprintf"
    };
    for (size_t i = 0; i < sizeof providers / sizeof providers[0]; ++i)
        REG_CHECK(check_gnu_provider(providers[i]) == 0);
    reg_pair_type = register_printf_type(reg_pair_read);
    REG_CHECK(reg_pair_type >= PA_LAST);
    REG_CHECK(register_printf_specifier('Q', reg_two, reg_two_info) == 0);
    int (*legacy)(int, printf_function *, printf_arginfo_function *) =
        (int (*)(int, printf_function *, printf_arginfo_function *))dlsym(RTLD_DEFAULT, "register_printf_function");
    REG_CHECK(legacy && legacy('Y', reg_legacy, reg_legacy_info) == 0);
    REG_CHECK(register_printf_specifier('T', reg_pair_print, reg_pair_info) == 0);
    REG_CHECK(register_printf_specifier('U', reg_float_print, reg_float_info) == 0);
    REG_CHECK(register_printf_specifier('R', reg_reenter, reg_noargs) == 0);
    REG_CHECK(register_printf_specifier(0xe9, reg_letter, reg_noargs) == 0);
}

static int reg_vprintf(const char *fmt, ...) {
    va_list ap; va_start(ap, fmt); int rc = vprintf(fmt, ap); va_end(ap); return rc;
}
static int reg_vfwprintf(FILE *stream, const wchar_t *fmt, ...) {
    va_list ap; va_start(ap, fmt); int rc = vfwprintf(stream, fmt, ap); va_end(ap); return rc;
}
static int reg_vwprintf(const wchar_t *fmt, ...) {
    va_list ap; va_start(ap, fmt); int rc = vwprintf(fmt, ap); va_end(ap); return rc;
}

static int gnu_registration(void) {
    alarm(20);
    setvbuf(stdout, NULL, _IONBF, 0);
    reg_setup();
    int first = register_printf_modifier(L"zz");
    int second = register_printf_modifier(L"xy");
    int replacement = register_printf_modifier(L"xy");
    REG_CHECK(first > 0 && second > 0 && replacement > 0 && second != replacement);
    printf("reg:ids:%i:%i:%i:%i\n", reg_pair_type, first, second, replacement);
    const char *formats[] = {
        "%Q %Y %T %R %U", "%3$*1$.*2$Q %5$Y", "%zzQ %xyQ %llQ",
        "%ls %lc %S %C %Ld %qd %llf", "%Q %d %Q"
    };
    for (size_t f = 0; f < sizeof formats / sizeof formats[0]; ++f) {
        for (size_t cap = 0; cap < 9; ++cap) {
            int types[10]; for (size_t k = 0; k < 10; ++k) types[k] = -77;
            size_t n = parse_printf_format(formats[f], cap, types);
            printf("reg:types:%zu:%zu:%zu", f, cap, n);
            for (size_t k = 0; k < 10; ++k) printf(":%i", types[k]);
            putchar('\n');
        }
    }
    int dynamic_types[4];
    parse_printf_format("%*.*Q", 4, dynamic_types);
    printf("reg:dynamic-arginfo:%i:%i\n", reg_info_width, reg_info_precision);
    struct reg_pair pair = { 23, 3.25 };
    char buffer[1024]; int count, rc;
    const char *fmt = "begin:%Q|%Y|%T|%R|%U%n:end";
#define REG_ARGS 7, "text", 11, pair, 1.25, &count
#define REG_BUFFER(label, expression) do { \
    memset(buffer, 0xa5, sizeof buffer); count = -1; rc = (expression); \
    reg_row(label, rc, count, buffer, strlen(buffer)); \
    REG_CHECK(rc >= 0 && count > 0); \
} while (0)
    REG_BUFFER("snprintf", snprintf(buffer, sizeof buffer, fmt, REG_ARGS));
    REG_BUFFER("vsnprintf", call_vsnprintf(buffer, sizeof buffer, fmt, REG_ARGS));
    REG_BUFFER("sprintf", sprintf(buffer, fmt, REG_ARGS));
    REG_BUFFER("vsprintf", call_vsprintf(buffer, fmt, REG_ARGS));
    for (int variant = 0; variant < 2; ++variant) {
        char *allocated = NULL; count = -1;
        rc = variant ? call_vasprintf(&allocated, fmt, REG_ARGS) : asprintf(&allocated, fmt, REG_ARGS);
        REG_CHECK(rc >= 0 && allocated && (size_t)rc == strlen(allocated));
        reg_row(variant ? "vasprintf" : "asprintf", rc, count, allocated, strlen(allocated));
        free(allocated);
    }
    for (int variant = 0; variant < 2; ++variant) {
        char *allocated = NULL; size_t len = 0; count = -1;
        FILE *stream = open_memstream(&allocated, &len); REG_CHECK(stream);
        rc = variant ? call_vfprintf(stream, fmt, REG_ARGS) : fprintf(stream, fmt, REG_ARGS);
        REG_CHECK(fclose(stream) == 0 && rc >= 0 && len == (size_t)rc);
        reg_row(variant ? "vfprintf" : "fprintf", rc, count, allocated, len);
        free(allocated);
    }
    for (int variant = 0; variant < 2; ++variant) {
        int descriptors[2]; REG_CHECK(pipe(descriptors) == 0); count = -1;
        rc = variant ? call_vdprintf(descriptors[1], fmt, REG_ARGS) : dprintf(descriptors[1], fmt, REG_ARGS);
        REG_CHECK(close(descriptors[1]) == 0 && rc >= 0);
        ssize_t n = read(descriptors[0], buffer, sizeof buffer); close(descriptors[0]);
        REG_CHECK(n == rc); reg_row(variant ? "vdprintf" : "dprintf", rc, count, buffer, (size_t)n);
    }
    const char *stdout_fmt = "reg:stdout:%Q|%Y|%T|%R|%U%n\n";
    count = -1; rc = printf(stdout_fmt, REG_ARGS); printf("reg:printf-result:%i:%i\n", rc, count);
    count = -1; rc = reg_vprintf(stdout_fmt, REG_ARGS); printf("reg:vprintf-result:%i:%i\n", rc, count);
    const size_t caps[] = { 0, 1, 2, 8, 32, 64 };
    for (size_t i = 0; i < sizeof caps / sizeof caps[0]; ++i) {
        memset(buffer, 0xa5, sizeof buffer); count = -1;
        rc = snprintf(buffer, caps[i], fmt, REG_ARGS);
        REG_CHECK(rc >= 0 && count > 0);
        for (size_t k = caps[i]; k < sizeof buffer; ++k) REG_CHECK((unsigned char)buffer[k] == 0xa5);
        char label[32]; snprintf(label, sizeof label, "cap-%zu", caps[i]);
        reg_row(label, rc, count, buffer, 72);
    }
    count = -1; rc = snprintf(NULL, 0, fmt, REG_ARGS);
    printf("reg:null-query:%i:%i\n", rc, count);
    const char *positional = "%3$*1$.*2$Q|%5$Y|%6$n";
    REG_BUFFER("positional", snprintf(buffer, sizeof buffer, positional, -12, 4, 31, "slot", 17, &count));
    printf("reg:dynamic-runtime:%i:%i\n", reg_info_width, reg_info_precision);
    const char *modifiers = "%# +0'I12.3zzQ|%xyQ|%llQ%n";
    REG_BUFFER("modifiers", snprintf(buffer, sizeof buffer, modifiers, 1, "a", 2, "b", 3, "c", &count));
    const char *ordinary = "%u|%lu|%llu|%hhd|%hd|%ld|%lld|%s|%ls|%lc|%S|%C|%p|%a|%La|%llf%n";
    REG_BUFFER("ordinary", snprintf(buffer, sizeof buffer, ordinary, UINT_MAX, ULONG_MAX, ULLONG_MAX,
        -7, -301, -123456789L, -4294967297LL, "abc", L"wide", (wint_t)L'J', L"alias", (wint_t)L'Z',
        (void *)(uintptr_t)0x1234, 0.125, 1.25L, 3.5L, &count));
    const char *lengths = "%Ld|%qd|%Ld%n";
    REG_BUFFER("lengths", snprintf(buffer, sizeof buffer, lengths, -1, 4294967297LL, 4294967297LL, &count));
    const char *unknown = "%#-+ 08.3W|%*W|%.*W%n";
    REG_BUFFER("unknown", snprintf(buffer, sizeof buffer, unknown, 12, 4, &count));
    REG_CHECK(register_printf_specifier('V', reg_errno_print, reg_noargs) == 0);
    const char *errfmt = "%m|%V|%m"; errno = ENOENT;
    rc = snprintf(buffer, sizeof buffer, errfmt, 0); int error = errno;
    reg_row("errno-snapshot", rc, error, buffer, strlen(buffer));
    REG_CHECK(register_printf_specifier('d', reg_d_print, reg_d_info) == 0);
    const char *override = "%d%n";
    REG_BUFFER("override", snprintf(buffer, sizeof buffer, override, 9, &count));
    REG_BUFFER("renderer-fallback", snprintf(buffer, sizeof buffer, override, 42, &count));
    REG_BUFFER("arginfo-fallback-long", snprintf(buffer, sizeof buffer, "%ld%n", -123L, &count));
    REG_BUFFER("arginfo-fallback-long-long", snprintf(buffer, sizeof buffer, "%lld%n", -456LL, &count));
    REG_CHECK(register_printf_specifier('d', NULL, NULL) == 0);
    REG_BUFFER("unregister-builtin", snprintf(buffer, sizeof buffer, "%d%n", 19, &count));
    REG_CHECK(register_printf_specifier('Q', reg_legacy, reg_two_info) == 0);
    const char *replaced = "%Q%n";
    REG_BUFFER("replacement", snprintf(buffer, sizeof buffer, replaced, 71, "unused", &count));
    REG_CHECK(register_printf_specifier('Q', NULL, NULL) == 0);
    const char *unregistered = "[%Q]%n";
    REG_BUFFER("unregister-custom", snprintf(buffer, sizeof buffer, unregistered, &count));
    REG_CHECK(register_printf_specifier('V', reg_error, reg_noargs) == 0);
    memset(buffer, 0xa5, sizeof buffer); errno = 0;
    const char *failed = "before%Vafter";
    rc = snprintf(buffer, sizeof buffer, failed, 0); error = errno;
    reg_row("callback-error", rc, error, buffer, 24);
    REG_CHECK(rc == -1 && error == EIO);
    for (int variant = 0; variant < 2; ++variant) {
        errno = 0;
        int result = register_printf_modifier(variant ? L"\u0100" : L"");
        printf("reg:bad-modifier:%i:%i:%i\n", variant, result, errno);
    }
    puts("reg:complete:narrow");
    alarm(0);
    return 0;
#undef REG_ARGS
#undef REG_BUFFER
}

/* GNU 2.39 writes 17 characters and stores 17 through %n but returns 14 for
 * this compound case, although each fallback alone returns its byte length.
 * Retain the actual return value as an executable diagnostic. The acceptance
 * matrix above checks the isolated callback/fallback contracts exactly. */
static int gnu_registration_combined_fallback(void) {
    alarm(20);
    reg_setup();
    REG_CHECK(register_printf_specifier('d', reg_d_print, reg_d_info) == 0);
    const char *fmt = "%d|%d|%ld|%lld%n";
    char buffer[128]; int count = -1;
    int rc = snprintf(buffer, sizeof buffer, fmt, 9, 42, -123L, -456LL, &count);
    REG_CHECK(rc >= 0 && count == 17 && strcmp(buffer, "D{9}|42|-123|-456") == 0);
    reg_row("combined-fallback", rc, count, buffer, strlen(buffer));
    alarm(0);
    return 0;
}

static int gnu_registration_wide(void) {
    alarm(20);
    reg_setup();
    struct reg_pair pair = { 23, 3.25 };
    const wchar_t *fmt = L"begin:%Q|%Y|%T|%R|%U|%\u00e9%n:end";
    wchar_t buffer[512]; int count, rc;
#define REG_WARGS 7, "text", 11, pair, 1.25, &count
    for (int variant = 0; variant < 2; ++variant) {
        count = -1;
        rc = variant ? call_vswprintf(buffer, 512, fmt, REG_WARGS) : swprintf(buffer, 512, fmt, REG_WARGS);
        REG_CHECK(rc >= 0 && (size_t)rc == wcslen(buffer));
        reg_wrow(variant ? "vswprintf" : "swprintf", rc, count, buffer);
    }
    for (int variant = 0; variant < 2; ++variant) {
        wchar_t *allocated = NULL; size_t len = 0; count = -1;
        FILE *stream = open_wmemstream(&allocated, &len); REG_CHECK(stream);
        rc = variant ? reg_vfwprintf(stream, fmt, REG_WARGS) : fwprintf(stream, fmt, REG_WARGS);
        REG_CHECK(fclose(stream) == 0 && rc >= 0 && len == (size_t)rc);
        reg_wrow(variant ? "vfwprintf" : "fwprintf", rc, count, allocated); free(allocated);
    }
    /* stdout is byte-oriented above; separate real wide streams bind both
     * stdout entry points without changing the orientation of an existing FILE. */
    fflush(stdout);
    FILE *saved = stdout;
    for (int variant = 0; variant < 2; ++variant) {
        wchar_t *allocated = NULL; size_t len = 0; count = -1;
        FILE *stream = open_wmemstream(&allocated, &len); REG_CHECK(stream);
        stdout = stream;
        rc = variant ? reg_vwprintf(fmt, REG_WARGS) : wprintf(fmt, REG_WARGS);
        stdout = saved;
        REG_CHECK(fclose(stream) == 0 && rc >= 0 && len == (size_t)rc);
        reg_wrow(variant ? "vwprintf" : "wprintf", rc, count, allocated); free(allocated);
    }
    puts("reg:complete:wide");
    alarm(0);
    return 0;
#undef REG_WARGS
}

int main(int argc, char **argv) {
    if (argc == 2 && strcmp(argv[1], "--gnu-register") == 0) return gnu_registration();
    if (argc == 2 && strcmp(argv[1], "--gnu-register-wide") == 0) return gnu_registration_wide();
    if (argc == 2 && strcmp(argv[1], "--gnu-register-combined-fallback") == 0) return gnu_registration_combined_fallback();
    if (argc == 2 && strcmp(argv[1], "--gnu-types") == 0) return gnu_types();
    if (argc == 2 && strcmp(argv[1], "--gnu-size") == 0) return gnu_sizes();
    if (argc == 2 && strcmp(argv[1], "--gnu-errors") == 0) return gnu_size_errors();
    if (argc == 2 && strcmp(argv[1], "--gnu-unknown") == 0) return gnu_unknown_conversions();
    if (argc == 2 && strcmp(argv[1], "--gnu-rounding") == 0) {
        int rc = gnu_extended_rounding();
        return rc ? rc : gnu_rounding_threads(0);
    }
    if (argc == 2 && strcmp(argv[1], "--gnu-double-rounding") == 0) {
        int rc = gnu_double_rounding();
        return rc ? rc : gnu_rounding_threads(1);
    }
    int fails = 0;
    fails += test_snprintf_contracts();
    fails += test_sprintf_contracts();
    fails += test_vsnprintf_contracts();
    fails += test_vsprintf_contracts();
    fails += test_fprintf_contracts();
    fails += test_printf_redirect_contracts();
    fails += test_dprintf_contracts();
    fails += test_vdprintf_contracts();
    fails += test_asprintf_contracts();
    fails += test_vasprintf_contracts();

    if (fails) {
        fprintf(stderr, "fixture_stdio_printf: %d FAILED\n", fails);
        return 1;
    }
    printf("fixture_stdio_printf: PASS (10 tests)\n");
    return 0;
}
