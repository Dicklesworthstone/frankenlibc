/* memchr never reads past the first occurrence (Austin Group 454), so a length
 * that runs past the object into an unmapped page is fine when the byte is
 * found first. fl's word/SIMD scan read the following page and SIGSEGV'd
 * (gnulib test-memchr, sed 4.9 gnulib-tests). Output matches glibc.
 */
#include <stdio.h>
#include <string.h>
#include <sys/mman.h>
#include <unistd.h>

int main(void) {
    long page = sysconf(_SC_PAGESIZE);
    char *map = mmap(NULL, 2 * page, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (map == MAP_FAILED || mprotect(map + page, page, PROT_NONE) != 0) {
        perror("mmap");
        return 1;
    }
    char *boundary = map + page;
    unsigned long checks = 0, bad = 0;
    for (size_t n = 1; n <= 300; n++) {
        char *mem = boundary - n;
        memset(mem, 'X', n);
        for (size_t i = 0; i < n; i++) {
            mem[i] = 'U';
            for (size_t k = i + 1; k < n + 300; k += 7) {
                bad += memchr(mem, 'U', k) != mem + i;
                checks++;
            }
            mem[i] = 0;
            for (size_t k = i + 1; k < n + 300; k += 7) {
                bad += memchr(mem, 0, k) != mem + i;
                checks++;
            }
            mem[i] = 'X';
        }
        bad += memchr(mem, 'U', n) != NULL;
    }
    printf("memchr page-boundary checks=%lu bad=%lu\n", checks, bad);

    /* memccpy likewise reads only up to the first `c`. */
    static char dst[1024];
    checks = bad = 0;
    for (size_t n = 1; n <= 300; n++) {
        char *s = boundary - n;
        memset(s, 'a', n - 1);
        s[n - 1] = 0;
        bad += memccpy(dst, s, 0, sizeof dst) != dst + n;
        bad += memcmp(dst, s, n) != 0;
        checks++;
    }
    printf("memccpy page-boundary checks=%lu bad=%lu\n", checks, bad);
    return 0;
}
