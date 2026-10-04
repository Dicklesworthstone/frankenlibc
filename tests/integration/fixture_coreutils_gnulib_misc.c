/* Divergences found by coreutils 9.5 gnulib-tests under fl (glibc: 0 FAIL).
 *
 *  - printf C23 %b/%B and %wN/%wfN: fl printed "%b" literally and did not
 *    consume the argument, shifting every later conversion;
 *  - getopt writes its diagnostic through the stderr stream (fl wrote fd 2,
 *    so ftell(stderr) never moved); getopt_long "--p=" sets optarg to "";
 *  - strtod parses a number at the start of a long buffer (a 128 KiB NUL
 *    scan cap made it parse nothing);
 *  - fnmatch "**(!()" with FNM_EXTMATCH (fl recursed until the stack died);
 *  - futimens(AT_FDCWD, NULL) is EBADF (fl touched the cwd).
 * Output matches glibc.
 */
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <fnmatch.h>
#include <getopt.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>
#include <wchar.h>

int main(void) {
    printf("[%b] [%#b] [%#B] [%08b] [%.4b] [%llb] [%hhb] %d\n", 5u, 5u, 5u, 5u, 5u, ~0ull, 0x1ffu, 33);
    printf("[%w8d] [%w16d] [%w32d] [%w64d] [%wf8d] [%wf16d] [%wf64u] [%w16x] %d\n", (int8_t)-42,
           (int16_t)-30000, (int32_t)-7, (int64_t)-9000000000000000000LL, (int_fast8_t)-5,
           (int_fast16_t)-70000, (uint_fast64_t)6000000000ULL, (uint16_t)0xffff, 44);
    wchar_t w[64];
    swprintf(w, 64, L"[%b] [%#B]", 6u, 6u);
    printf("%ls\n", w);

    /* getopt diagnostics go through stderr (here: a file). */
    char path[] = "/tmp/fl_getopt_err_XXXXXX";
    int tfd = mkstemp(path);
    close(tfd);
    if (freopen(path, "w", stderr) != stderr) return 1;
    long before = ftell(stderr);
    char *argv1[] = {"prog", "-x", NULL};
    optind = 1;
    int r = getopt(2, argv1, "ab");
    long after = ftell(stderr);
    printf("getopt=%c optopt=%c stderr moved=%d\n", r, optopt, after > before);
    static struct option longopts[] = {{"p", optional_argument, NULL, 'p'},
                                       {"q", required_argument, NULL, 'q'},
                                       {NULL, 0, NULL, 0}};
    char *argv2[] = {"prog", "--p=", "--q=", "rest", NULL};
    optind = 1;
    r = getopt_long(4, argv2, "", longopts, NULL);
    printf("--p= -> %c optarg=%s\n", r, optarg ? (*optarg ? optarg : "(empty)") : "(null)");
    r = getopt_long(4, argv2, "", longopts, NULL);
    printf("--q= -> %c optarg=%s optind=%d\n", r, optarg ? (*optarg ? optarg : "(empty)") : "(null)",
           optind);
    unlink(path);

    /* strtod: a number at the start of a buffer longer than 128 KiB. */
    size_t big = 300000;
    char *s = malloc(big + 1);
    memset(s, ' ', big);
    memcpy(s, "-0e1", 4);
    memset(s + 4, '0', 40);
    s[big] = 0;
    char *end;
    double d = strtod(s, &end);
    printf("strtod long buffer: %g signbit=%d consumed=%td\n", d, !!__builtin_signbit(d), end - s);
    memcpy(s, "1.5x", 4);
    float fv = strtof(s, &end);
    printf("strtof long buffer: %g consumed=%td\n", fv, end - s);
    free(s);

    printf("fnmatch **(!() = %d\n", fnmatch("**(!()", "**(!()", FNM_EXTMATCH));
    errno = 0;
    r = futimens(AT_FDCWD, NULL);
    printf("futimens(AT_FDCWD)=%d errno=%d\n", r, errno);
    return 0;
}
