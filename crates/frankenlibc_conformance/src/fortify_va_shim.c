/* C va_list forwarder shim for the fortify wave-06 checked-wrapper fixtures
 * (bd-reality-202609-lx578q.6.1).
 *
 * Rust cannot construct a C va_list, so each fixture driver calls one of
 * these forwarders with plain varargs; the forwarder opens a va_list over
 * them and hands it to FrankenLibC's __v*_chk implementation exactly the way
 * a C caller would.
 *
 * The __v*_chk externs are declared with `va_list` (not void*) so the
 * compiler's builtin declarations match: GCC knows these names as builtins
 * and rejects a void*-parameter prototype under -Werror
 * (builtin-declaration-mismatch). At the ABI level va_list in a prototype
 * passes the same decayed state pointer the Rust `ap: *mut c_void`
 * parameter receives. */

#include <stdarg.h>
#include <stdio.h>

extern int __vasprintf_chk(char **str, int flag, const char *fmt, va_list ap);
extern int __vdprintf_chk(int fd, int flag, const char *fmt, va_list ap);
extern int __vfprintf_chk(FILE *stream, int flag, const char *fmt, va_list ap);
extern int __vprintf_chk(int flag, const char *fmt, va_list ap);
extern int __vsnprintf_chk(char *buf, size_t maxlen, int flag, size_t buflen,
                           const char *fmt, va_list ap);
extern int __vsprintf_chk(char *buf, int flag, size_t buflen, const char *fmt,
                          va_list ap);
extern int __vwprintf_chk(int flag, const int *fmt, va_list ap);

int shim_vasprintf_chk(char **str, int flag, const char *fmt, ...) {
    va_list ap;
    va_start(ap, fmt);
    int rc = __vasprintf_chk(str, flag, fmt, ap);
    va_end(ap);
    return rc;
}

int shim_vdprintf_chk(int fd, int flag, const char *fmt, ...) {
    va_list ap;
    va_start(ap, fmt);
    int rc = __vdprintf_chk(fd, flag, fmt, ap);
    va_end(ap);
    return rc;
}

int shim_vfprintf_chk(FILE *stream, int flag, const char *fmt, ...) {
    va_list ap;
    va_start(ap, fmt);
    int rc = __vfprintf_chk(stream, flag, fmt, ap);
    va_end(ap);
    return rc;
}

int shim_vprintf_chk(int flag, const char *fmt, ...) {
    va_list ap;
    va_start(ap, fmt);
    int rc = __vprintf_chk(flag, fmt, ap);
    va_end(ap);
    return rc;
}

int shim_vsnprintf_chk(char *buf, size_t maxlen, int flag, size_t buflen,
                       const char *fmt, ...) {
    va_list ap;
    va_start(ap, fmt);
    int rc = __vsnprintf_chk(buf, maxlen, flag, buflen, fmt, ap);
    va_end(ap);
    return rc;
}

int shim_vsprintf_chk(char *buf, int flag, size_t buflen, const char *fmt,
                      ...) {
    va_list ap;
    va_start(ap, fmt);
    int rc = __vsprintf_chk(buf, flag, buflen, fmt, ap);
    va_end(ap);
    return rc;
}

int shim_vwprintf_chk(int flag, const int *fmt, ...) {
    va_list ap;
    va_start(ap, fmt);
    int rc = __vwprintf_chk(flag, fmt, ap);
    va_end(ap);
    return rc;
}

/* Drives an arbitrary __vfprintf_chk-style implementation (fl's own, passed
 * as a function pointer by the fixture) with a va_list opened over this
 * shim's varargs. This is the production-truth pattern for an interposed
 * C caller: the va_list is constructed per the C ABI and handed to the
 * implementation selected by the fixture. */
int shim_drive_vfprintf(void *impl, void *stream, int flag, const char *fmt,
                        ...) {
    typedef int (*vfprintf_chk_t)(void *, int, const char *, void *);
    va_list ap;
    va_start(ap, fmt);
    vfprintf_chk_t f = (vfprintf_chk_t)impl;
    int rc = f(stream, flag, fmt, ap);
    va_end(ap);
    return rc;
}
