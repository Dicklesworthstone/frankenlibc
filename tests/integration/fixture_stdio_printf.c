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
                    for (unsigned style = 0; style < 3; ++style) {
                        char fmt[48];
                        if (style == 2) snprintf(fmt, sizeof(fmt), "[%%2$0*1$.*3$%c]", convs[c]);
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

int main(int argc, char **argv) {
    if (argc == 2 && strcmp(argv[1], "--gnu-types") == 0) return gnu_types();
    if (argc == 2 && strcmp(argv[1], "--gnu-size") == 0) return gnu_sizes();
    if (argc == 2 && strcmp(argv[1], "--gnu-errors") == 0) return gnu_size_errors();
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
