/* C va_list forwarder shim for the fortify wave-06/07 checked-wrapper fixtures
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
#include <stddef.h>
#include <stdio.h>

/* glibc-shaped opaque stream handle for the vfprintf/vfwprintf members. */
typedef struct _IO_FILE SHIM_FILE;

extern int __vasprintf_chk(char **str, int flag, const char *fmt, va_list ap);
extern int __vdprintf_chk(int fd, int flag, const char *fmt, va_list ap);
extern int __vfprintf_chk(FILE *stream, int flag, const char *fmt, va_list ap);
extern int __vprintf_chk(int flag, const char *fmt, va_list ap);
extern int __vsnprintf_chk(char *buf, size_t maxlen, int flag, size_t buflen,
                           const char *fmt, va_list ap);
extern int __vsprintf_chk(char *buf, int flag, size_t buflen, const char *fmt,
                          va_list ap);
extern int __vwprintf_chk(int flag, const int *fmt, va_list ap);
extern void __vsyslog_chk(int priority, int flag, const char *fmt, va_list ap);
extern int __vfwprintf_chk(SHIM_FILE *stream, int flag, const int *fmt,
                           va_list ap);

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

void shim_vsyslog_chk(int priority, int flag, const char *fmt, ...) {
    va_list ap;
    va_start(ap, fmt);
    __vsyslog_chk(priority, flag, fmt, ap);
    va_end(ap);
}

int shim_vfwprintf_chk(SHIM_FILE *stream, int flag, const int *fmt, ...) {
    va_list ap;
    va_start(ap, fmt);
    int rc = __vfwprintf_chk(stream, flag, fmt, ap);
    va_end(ap);
    return rc;
}

/* Drives fl's own __vfprintf_chk with a va_list opened over this shim's
 * varargs. The fixture passes fl's __vfprintf_chk as impl — the stream is
 * fl-native, so the host implementation cannot be used (bd-6cynxn class). */
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

/* Same drive pattern for the wide member: fl's __vfwprintf_chk handles
 * fl-native streams; the host's would segfault (bd-6cynxn class). */
int shim_drive_vfwprintf(void *impl, void *stream, int flag, const int *fmt,
                         ...) {
    typedef int (*vfwprintf_chk_t)(void *, int, const int *, void *);
    va_list ap;
    va_start(ap, fmt);
    vfwprintf_chk_t f = (vfwprintf_chk_t)impl;
    int rc = f(stream, flag, fmt, ap);
    va_end(ap);
    return rc;
}
