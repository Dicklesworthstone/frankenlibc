/* Regressions found by running a gnulib testdir (189 libc-facing modules)
 * under LD_PRELOAD; every line must match glibc in strict and hardened:
 *   strncpy  -- hardened over-read past the NUL into an unmapped page
 *   fstatat  -- NULL path with AT_EMPTY_PATH rejected before the kernel
 *   popen    -- child lost its stdout when the parent had closed fd 1
 *   glob     -- "/*" + thousands of slashes + "sh" built a path past PATH_MAX
 *   fnmatch  -- '?' could not match a multibyte character in a UTF-8 locale
 *   printf   -- widths/precisions silently cut at 1 MiB / 65535
 *   printf   -- trailing '%', cut-off directives and bad %wN printed literally
 *               (glibc: -1/EINVAL); a field too large for the memory left
 *               returned a truncated success count (glibc: -1/ENOMEM)
 *   RLIMIT_AS -- capping the address space before fl's lazily built runtime
 *               state existed crashed the process (strict: stack growth in the
 *               kernel constructor; hardened: abort at exit / in realloc)
 */
#define _GNU_SOURCE
#include <fcntl.h>
#include <fnmatch.h>
#include <glob.h>
#include <locale.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <sys/mman.h>
#include <sys/resource.h>
#include <sys/stat.h>
#include <unistd.h>

int main(void) {
    /* strncpy: source ends right before a PROT_NONE page; n runs past it. */
    long pg = sysconf(_SC_PAGESIZE);
    char *two = mmap(NULL, 2 * pg, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    mprotect(two + pg, pg, PROT_NONE);
    char *src = two + pg - 6;
    memcpy(src, "hello", 6);
    char dst[32];
    memset(dst, 'X', sizeof dst);
    strncpy(dst, src, 20);
    printf("strncpy: [%s] pad=%d\n", dst, dst[19] == 0);

    /* fstatat(fd, NULL, AT_EMPTY_PATH): the kernel decides (Linux >= 6.11). */
    struct stat st;
    int dfd = open("/", O_RDONLY | O_DIRECTORY);
    printf("fstatat_null: %d\n", fstatat(dfd, NULL, &st, AT_EMPTY_PATH) == 0);
    close(dfd);

    /* popen with stdin and stdout closed: pipe2 returns fds 0 and 1, so the
     * child's write end is already on its stdout. */
    fflush(stdout);
    int saved_in = dup(0), saved = dup(1);
    close(0);
    close(1);
    FILE *child = popen("echo c", "r");
    int got = child ? fgetc(child) : -1;
    int status = child ? pclose(child) : -1;
    dup2(saved, 1);
    dup2(saved_in, 0);
    close(saved);
    close(saved_in);
    printf("popen_closed_stdout: %c status=%d\n", got, status);

    /* glob: thousands of slashes after a wildcard component. */
    char *pat = malloc(10000);
    memset(pat, '/', 9997);
    pat[1] = '*';
    strcpy(pat + 9997, "sh");
    glob_t g;
    int rc = glob(pat, 0, NULL, &g);
    printf("glob_slashes: rc=%d first=%s\n", rc, rc == 0 ? g.gl_pathv[0] : "-");
    if (rc == 0)
        globfree(&g);
    free(pat);
    rc = glob("///", 0, NULL, &g);
    printf("glob_root: rc=%d first=%s\n", rc, rc == 0 ? g.gl_pathv[0] : "-");
    if (rc == 0)
        globfree(&g);

    /* fnmatch by characters in a UTF-8 locale. */
    if (setlocale(LC_ALL, "C.UTF-8")) {
        printf("fnmatch_utf8: %d %d %d %d\n", fnmatch("x?y", "x\303\274y", 0),
               fnmatch("x?y", "x\360\237\230\213y", 0), fnmatch("??", "\303\234", 0),
               fnmatch("???", "\303\234", 0));
        setlocale(LC_ALL, "C");
    }

    /* printf: no silent caps on width or precision. */
    printf("printf_wide: %d %d %d\n", snprintf(NULL, 0, "%2000000d", 1),
           snprintf(NULL, 0, "%.70000f", 1.5), snprintf(NULL, 0, "%-1500000s|", "x"));

    /* printf: directives glibc rejects outright fail the call with EINVAL. */
    static const char *const bad[] = {"a%", "a%5", "a%l", "a%.", "a%w7d", "a%w128d", "a%wfd"};
    char sbuf[32];
    for (size_t i = 0; i < sizeof bad / sizeof bad[0]; i++) {
        errno = 0;
        int r = snprintf(sbuf, sizeof sbuf, bad[i], 7);
        printf("printf_invalid %s: %d %d\n", bad[i], r, r < 0 ? errno : 0);
    }
    printf("printf_literal: %d %d\n", snprintf(sbuf, sizeof sbuf, "a%yb"), snprintf(sbuf, sizeof sbuf, "%w32d", 5));

    /* Last: cap the address space (as gnulib's printf-posix2 does), then a
     * float too wide for the memory left fails with ENOMEM, and the process
     * still prints, reallocs and exits normally. */
    struct rlimit lim = {10000000, 10000000};
    fflush(stdout);
    if (setrlimit(RLIMIT_AS, &lim) == 0) {
        errno = 0;
        int r = snprintf(NULL, 0, "%.10000000f", 1.0);
        printf("rlimit_as_float: %d %d\n", r, r < 0 ? errno : 0);
        char *grow = malloc(16);
        grow = grow ? realloc(grow, 4096) : NULL;
        printf("rlimit_as_realloc: %d\n", grow != NULL);
        free(grow);
    }
    return 0;
}
