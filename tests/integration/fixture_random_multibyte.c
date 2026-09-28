/* fixture_random_multibyte.c — glibc-observable PRNG and multibyte results
 * (2026-09-28). Byte-identical to glibc in strict and hardened:
 *  - rand/srand/rand_r/random/srandom sequences, initstate over all five
 *    generator sizes, setstate RESUMING a saved generator and returning the
 *    previous buffer, the drand48 family, seed48/lcong48, random_r;
 *  - mbrtowc/wcrtomb/mbstowcs/wcstombs/mblen/wcwidth/towupper in C, C.UTF-8
 *    and en_US.UTF-8, including EILSEQ from mbstowcs/wcstombs.
 */
#define _GNU_SOURCE
#include <errno.h>
#include <locale.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <wchar.h>
#include <wctype.h>

static void show_mbrtowc(const char *label, const char *s, size_t n) {
    mbstate_t st;
    memset(&st, 0, sizeof st);
    wchar_t wc = 0;
    errno = 0;
    size_t r = mbrtowc(&wc, s, n, &st);
    printf("  mbrtowc %-14s n=%zu -> %zd wc=U+%04X errno=%d init=%d\n", label, n, (ssize_t)r, (unsigned)wc, errno, mbsinit(&st));
}

static void random_sequences(void) {
    printf("rand default:");
    for (int i = 0; i < 5; i++) printf(" %d", rand());
    srand(42);
    printf("\nrand srand(42):");
    for (int i = 0; i < 5; i++) printf(" %d", rand());
    srand(0);
    printf("\nrand srand(0):");
    for (int i = 0; i < 3; i++) printf(" %d", rand());
    unsigned seed = 7;
    printf("\nrand_r(7):");
    for (int i = 0; i < 5; i++) printf(" %d", rand_r(&seed));
    srandom(99);
    printf("\nrandom srandom(99):");
    for (int i = 0; i < 5; i++) printf(" %ld", random());
    static char st8[8], st32[32], st64[64], st128[128], st256[256];
    char *states[] = {st8, st32, st64, st128, st256};
    size_t lens[] = {8, 32, 64, 128, 256};
    for (int s = 0; s < 5; s++) {
        initstate(1234, states[s], lens[s]);
        printf("\ninitstate(%zu):", lens[s]);
        for (int i = 0; i < 4; i++) printf(" %ld", random());
    }
    char *prev = setstate(st32);
    printf("\nsetstate back to 32 -> next %ld (prev==st256:%d)", random(), prev == st256);
    srand48(2024);
    printf("\ndrand48:");
    for (int i = 0; i < 3; i++) printf(" %.17g", drand48());
    printf("\nlrand48:");
    for (int i = 0; i < 3; i++) printf(" %ld", lrand48());
    printf("\nmrand48:");
    for (int i = 0; i < 3; i++) printf(" %ld", mrand48());
    unsigned short xs[3] = {1, 2, 3};
    printf("\nerand48/nrand48/jrand48: %.17g %ld %ld", erand48(xs), nrand48(xs), jrand48(xs));
    unsigned short s48[3] = {0x1234, 0x5678, 0x9abc};
    unsigned short *old = seed48(s48);
    printf("\nseed48 old=%x,%x,%x next lrand48=%ld", old[0], old[1], old[2], lrand48());
    unsigned short p[7] = {1, 2, 3, 5, 0, 0, 11};
    lcong48(p);
    printf("\nlcong48 lrand48=%ld %ld", lrand48(), lrand48());
    struct random_data rd;
    memset(&rd, 0, sizeof rd);
    static char rbuf[64];
    initstate_r(5, rbuf, sizeof rbuf, &rd);
    int32_t r1, r2;
    random_r(&rd, &r1);
    random_r(&rd, &r2);
    printf("\nrandom_r: %d %d\n", r1, r2);
    }

static void multibyte(void) {
    const char *locs[] = {"C", "C.UTF-8", "en_US.UTF-8"};
    for (int l = 0; l < 3; l++) {
        const char *got = setlocale(LC_ALL, locs[l]);
        printf("locale %s -> %s MB_CUR_MAX=%zu\n", locs[l], got ? got : "NULL", MB_CUR_MAX);
        show_mbrtowc("ascii", "A", 1);
        show_mbrtowc("e-acute", "\xc3\xa9", 2);
        show_mbrtowc("e-acute part", "\xc3", 1);
        show_mbrtowc("euro", "\xe2\x82\xac", 3);
        show_mbrtowc("emoji", "\xf0\x9f\x98\x80", 4);
        show_mbrtowc("invalid", "\xff", 1);
        show_mbrtowc("overlong", "\xc0\xaf", 2);
        show_mbrtowc("surrogate", "\xed\xa0\x80", 3);
        show_mbrtowc("high-byte", "\x80", 1);
        show_mbrtowc("nul", "", 1);
        mbstate_t st;
        memset(&st, 0, sizeof st);
        wchar_t wc = 0;
        size_t a = mbrtowc(&wc, "\xe2\x82", 2, &st);
        size_t b = mbrtowc(&wc, "\xac", 1, &st);
        printf("  split euro: %zd then %zd wc=U+%04X\n", (ssize_t)a, (ssize_t)b, (unsigned)wc);
        char buf[8];
        memset(&st, 0, sizeof st);
        wchar_t tests[] = {L'A', 0xE9, 0x20AC, 0x1F600, 0xD800, 0x110000};
        for (int i = 0; i < 6; i++) {
            errno = 0;
            size_t n = wcrtomb(buf, tests[i], &st);
            printf("  wcrtomb U+%04X -> %zd errno=%d", (unsigned)tests[i], (ssize_t)n, errno);
            for (size_t k = 0; n != (size_t)-1 && k < n; k++) printf(" %02x", (unsigned char)buf[k]);
            printf("\n");
        }
        wchar_t wbuf[16];
        errno = 0;
        size_t n = mbstowcs(wbuf, "h\xc3\xa9llo\xff", 16);
        printf("  mbstowcs with invalid -> %zd errno=%d\n", (ssize_t)n, errno);
        n = mbstowcs(NULL, "h\xc3\xa9llo", 0);
        printf("  mbstowcs(NULL) -> %zd\n", (ssize_t)n);
        errno = 0;
        n = wcstombs(buf, L"héllo", sizeof buf);
        printf("  wcstombs -> %zd errno=%d\n", (ssize_t)n, errno);
        printf("  mblen(\"\\xc3\\xa9\",2)=%d mblen(NULL)=%d wctob(0xE9)=%d btowc(0xE9)=%d\n", mblen("\xc3\xa9", 2), mblen(NULL, 0), wctob(0xE9), (int)btowc(0xE9));
        printf("  wcwidth: A=%d U+00E9=%d U+4E00=%d U+0301=%d U+1F600=%d U+0007=%d\n", wcwidth(L'A'), wcwidth(0xE9), wcwidth(0x4E00), wcwidth(0x301), wcwidth(0x1F600), wcwidth(7));
        printf("  towupper(U+00E9)=U+%04X iswalpha(U+00E9)=%d iswupper(U+00C9)=%d\n", (unsigned)towupper(0xE9), !!iswalpha(0xE9), !!iswupper(0xC9));
    }
    }

int main(void) {
    random_sequences();
    multibyte();
    return 0;
}
