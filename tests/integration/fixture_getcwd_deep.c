/* getcwd beyond PATH_MAX. The Linux getcwd syscall fails with ENAMETOOLONG
 * once the path exceeds a page; glibc falls back to walking ".." and naming
 * each directory by its (dev, ino) in the parent. fl returned the syscall's
 * error (gnulib test-getcwd, coreutils gnulib-tests). Output matches glibc.
 */
#define _GNU_SOURCE
#include <errno.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

int main(void) {
    char base[] = "/tmp/fl_getcwd_deep_XXXXXX";
    if (!mkdtemp(base) || chdir(base) != 0) return 1;
    static const char dir[] = "d0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcde";
    int depth = 0;
    while (depth < 120) { /* 120 * 64 > 7 KiB */
        if (mkdir(dir, 0700) != 0 || chdir(dir) != 0) break;
        depth++;
    }
    char *cwd = getcwd(NULL, 0);
    size_t expect = strlen(base) + (size_t)depth * (sizeof dir);
    printf("depth=%d getcwd(NULL,0)=%s len_ok=%d\n", depth, cwd ? "ok" : "NULL",
           cwd && strlen(cwd) == expect && strncmp(cwd, base, strlen(base)) == 0);
    char small[256];
    errno = 0;
    char *r = getcwd(small, sizeof small);
    printf("small buffer: %s errno=%d\n", r ? "ok" : "NULL", errno);
    char *big = malloc(16384);
    r = getcwd(big, 16384);
    printf("big buffer: %s same=%d\n", r ? "ok" : "NULL", r && cwd && strcmp(r, cwd) == 0);
    free(big);
    free(cwd);
    while (depth-- > 0) {
        if (chdir("..") != 0) return 1;
        rmdir(dir);
    }
    if (chdir("/") != 0) return 1;
    rmdir(base);
    return 0;
}
