/* fixture_wide_ctype.c — wide-character classification, case mapping and
 * width over every code point (bd-rc0923-epic-eeuy4f.10). Prints a hash and
 * count per function for the locale named by argv[1]. glibc is ASCII-only in
 * C/POSIX and uses the installed LC_CTYPE tables in C.UTF-8 and named
 * locales; the smoke corpus requires byte parity with host glibc.
 */
#define _GNU_SOURCE
#include <locale.h>
#include <stdio.h>
#include <wctype.h>
#include <wchar.h>
#include <stdlib.h>
int main(int c, char **v) {
    setlocale(LC_ALL, v[1]);
    const char *names[] = {"alnum","alpha","blank","cntrl","digit","graph","lower","print","punct","space","upper","xdigit","towupper","towlower","wcwidth"};
    for (int f = 0; f < 15; f++) {
        unsigned long h = 0, cnt = 0; long first = -1;
        for (unsigned cp = 0; cp <= 0x10FFFF; cp++) {
            long r;
            switch (f) { case 0: r = !!iswalnum(cp); break; case 1: r = !!iswalpha(cp); break; case 2: r = !!iswblank(cp); break; case 3: r = !!iswcntrl(cp); break; case 4: r = !!iswdigit(cp); break; case 5: r = !!iswgraph(cp); break; case 6: r = !!iswlower(cp); break; case 7: r = !!iswprint(cp); break; case 8: r = !!iswpunct(cp); break; case 9: r = !!iswspace(cp); break; case 10: r = !!iswupper(cp); break; case 11: r = !!iswxdigit(cp); break; case 12: r = towupper(cp); break; case 13: r = towlower(cp); break; default: r = wcwidth(cp); }
            h = h * 1000003 + (unsigned long)(r + 7); if (r != 0 && f < 12) cnt++;
        }
        printf("%s %s hash=%lx cnt=%lu\n", v[1], names[f], h, cnt);
    }
}
