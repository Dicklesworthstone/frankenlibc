// GNU `%m` assignment-allocation in the scanf family: `%ms`, `%m[...]` and
// `%mc` store a malloc'd buffer through a `char **`.
//
// Under fl every successful `%m` conversion reached through the va_list path
// -- __isoc23_sscanf (what glibc 2.38+ headers turn sscanf into), vsscanf,
// vfscanf -- wrote the token over the caller's `char *` itself, so the next use
// of the pointer crashed. fuser (psmisc) parses /proc/net/unix with
// "%*x: %*x %*x %*x %*x %*d %llu %ms" and died with SIGSEGV on `--version`.
//
// glibc also stores NULL through the `char **` of a %m conversion that fails
// when the call does not return EOF; on EOF the pointer is left alone.
#define _GNU_SOURCE
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/wait.h>
#include <unistd.h>

#define UNTOUCHED ((char *)0x1)

static const char *show(const char *p) { return p == UNTOUCHED ? "(untouched)" : p ? p : "(null)"; }

// Run each case in a child so a crash is reported instead of ending the run.
#define CASE(label, ...)                                            \
    do {                                                            \
        fflush(stdout);                                             \
        pid_t pid_ = fork();                                        \
        if (pid_ == 0) {                                            \
            printf("%-30s ", label);                                \
            __VA_ARGS__;                                            \
            fflush(stdout);                                         \
            _exit(0);                                               \
        }                                                           \
        int st_;                                                    \
        waitpid(pid_, &st_, 0);                                     \
        if (WIFSIGNALED(st_)) printf("%-30s killed by signal %d\n", label, WTERMSIG(st_)); \
    } while (0)

static int via_vsscanf(const char *in, const char *fmt, ...) {
    va_list ap;
    va_start(ap, fmt);
    int n = vsscanf(in, fmt, ap);
    va_end(ap);
    return n;
}

int main(void) {
    CASE("%ms", {
        char *a = UNTOUCHED;
        int n = sscanf("  hello world", "%ms", &a);
        printf("n=%d a=%s\n", n, show(a));
        free(a);
    });
    CASE("%m[a-z] %ms", {
        char *a = UNTOUCHED, *b = UNTOUCHED;
        int n = sscanf("abc123 tail", "%m[a-z]%*d %ms", &a, &b);
        printf("n=%d a=%s b=%s\n", n, show(a), show(b));
        free(a);
        free(b);
    });
    CASE("%3mc", {
        char *a = UNTOUCHED;
        int n = sscanf("xyzw", "%3mc", &a);
        printf("n=%d a=%.3s\n", n, a);
        free(a);
    });
    CASE("%5ms width", {
        char *a = UNTOUCHED;
        int n = sscanf("abcdefgh", "%5ms", &a);
        printf("n=%d a=%s len=%zu\n", n, show(a), strlen(a));
        free(a);
    });
    CASE("%*ms suppressed", {
        char *a = UNTOUCHED;
        int n = sscanf("skip keep", "%*ms %ms", &a);
        printf("n=%d a=%s\n", n, show(a));
        free(a);
    });
    CASE("fuser /proc/net/unix line", {
        unsigned long long ino = 0;
        char *path = NULL;
        int n = sscanf("0000000000000000: 00000002 00000000 00010000 0001 01 12345 /run/systemd/notify",
                       "%*x: %*x %*x %*x %*x %*d %llu %ms", &ino, &path);
        printf("n=%d ino=%llu path=%s\n", n, ino, show(path));
        free(path);
    });
    CASE("fuser line without path", {
        unsigned long long ino = 0;
        char *path = UNTOUCHED;
        int n = sscanf("0000000000000000: 00000003 00000000 00000000 0001 03 67890",
                       "%*x: %*x %*x %*x %*x %*d %llu %ms", &ino, &path);
        printf("n=%d ino=%llu path=%s\n", n, ino, show(path));
    });
    CASE("%m[ matching failure", {
        int x = 0;
        char *a = UNTOUCHED;
        int n = sscanf("5 9", "%d %m[a-z]", &x, &a);
        printf("n=%d x=%d a=%s\n", n, x, show(a));
    });
    CASE("EOF before any conversion", {
        char *a = UNTOUCHED;
        int n = sscanf("", "%ms", &a);
        printf("n=%d a=%s\n", n, show(a));
    });
    CASE("%n then %ms at EOF", {
        int n = -7;
        char *a = UNTOUCHED;
        int r = sscanf("", "%n%ms", &n, &a);
        printf("r=%d n=%d a=%s\n", r, n, show(a));
    });
    CASE("%ms never reached at EOF", {
        char *a = UNTOUCHED;
        int r = sscanf("", "%*ms%ms", &a);
        printf("r=%d a=%s\n", r, show(a));
    });
    CASE("literal mismatch before %ms", {
        int x = 0;
        char *a = UNTOUCHED;
        int n = sscanf("5 y", "%d x%ms", &x, &a);
        printf("n=%d x=%d a=%s\n", n, x, show(a));
    });
    CASE("vsscanf", {
        char *a = UNTOUCHED, *b = UNTOUCHED;
        int n = via_vsscanf("key=value", "%m[^=]=%ms", &a, &b);
        printf("n=%d a=%s b=%s\n", n, show(a), show(b));
        free(a);
        free(b);
    });
    CASE("fscanf from a stream", {
        FILE *f = tmpfile();
        fputs("first second\n", f);
        rewind(f);
        char *a = UNTOUCHED, *b = UNTOUCHED;
        int n = fscanf(f, "%ms %ms", &a, &b);
        printf("n=%d a=%s b=%s\n", n, show(a), show(b));
        free(a);
        free(b);
        fclose(f);
    });
    return 0;
}
