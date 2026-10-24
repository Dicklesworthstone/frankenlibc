/* POSIX regex in a UTF-8 locale: `.`, bracket expressions, `\w`/`\W`/`\b`
 * and REG_ICASE work on whole characters, as glibc's regcomp decides from
 * LC_CTYPE. fl's engine was byte-oriented: `.` matched one byte of `é`,
 * `[[:lower:]]` never matched a non-ASCII letter, `é*` repeated only its last
 * byte, and grep -o printed half characters ("binary file matches"). Under
 * REG_ICASE glibc compares by towupper: µ, Μ and μ match each other; the Ohm,
 * Kelvin and Angstrom signs match only themselves. Collation-dependent
 * features ([a-z] matching é, [[=e=]]) differ between locales and are not
 * covered. Output matches glibc.
 */
#define _GNU_SOURCE
#include <locale.h>
#include <regex.h>
#include <stdio.h>
#include <string.h>
#include <wchar.h>

static void t(const char *pat, const char *s, int cflags) {
    regex_t re;
    int rc = regcomp(&re, pat, cflags);
    if (rc) {
        char buf[100];
        regerror(rc, &re, buf, sizeof buf);
        printf("comp-err %s\n", buf);
        return;
    }
    regmatch_t m[3];
    if (regexec(&re, s, 3, m, 0))
        printf("nomatch\n");
    else
        printf("[%d,%d] g1=[%d,%d]\n", (int)m[0].rm_so, (int)m[0].rm_eo, (int)m[1].rm_so,
               (int)m[1].rm_eo);
    regfree(&re);
}

static const unsigned trip[][3] = {
    {0xB5, 0x39C, 0x3BC},  {0x49, 0x69, 0x130},   {0x49, 0x69, 0x131},   {0x53, 0x73, 0x17F},
    {0x1C4, 0x1C5, 0x1C6}, {0x345, 0x399, 0x3B9}, {0x3A3, 0x3C2, 0x3C3}, {0x3A9, 0x3C9, 0x2126},
    {0x4B, 0x6B, 0x212A},  {0xC5, 0xE5, 0x212B},  {0x1E9E, 0xDF, 0xDF},
};

static void enc(unsigned cp, char *out) {
    mbstate_t st;
    memset(&st, 0, sizeof st);
    size_t n = wcrtomb(out, (wchar_t)cp, &st);
    out[n] = 0;
}

int main(void) {
    if (!setlocale(LC_ALL, "C.UTF-8") && !setlocale(LC_ALL, "en_US.UTF-8")) {
        puts("no UTF-8 locale");
        return 0;
    }
    const int E = REG_EXTENDED;
    t(".", "\xc3\xa9", E);
    t("^.$", "\xc3\xa9", E);
    t("^..$", "\xc3\xa9", E);
    t(".$", "a\xc3\xa9", E);
    t("[[:lower:]]", "\xc3\xa9", E);
    t("[[:upper:]]", "x\xc3\x89", E);
    t("[[:alpha:]]+", "1\xc3\xa9t\xc3\xa9!", E);
    t("[[:punct:]]", "\xc2\xbf", E);
    t("[[:space:]]", "a\xe2\x80\x83", E);
    t("[^a]", "\xc3\xa9", E);
    t("^[^a]$", "\xc3\xa9", E);
    t("\xc3\xa9*", "\xc3\xa9\xc3\xa9x", E);
    t("^\xc3\xa9+$", "\xc3\xa9\xc3\xa9", E);
    t("^\xc3\xa9\\{2\\}$", "\xc3\xa9\xc3\xa9", 0);
    t("[\xc3\xa9]", "x\xc3\xa9", E);
    t("(.)\\1", "\xc3\xa9\xc3\xa9", E);
    t("\\w+", "\xc3\xa9t\xc3\xa9 x", E);
    t("\\bt", "\xc3\xa9t", E);
    t("\\<t", "-t", E);
    t("\\W", "\xc3\xa9-", E);
    t("\\s", "a\xe2\x80\x83", E);
    t("\xc3\x89", "\xc3\xa9", E | REG_ICASE);
    t("[\xc3\x89]", "\xc3\xa9", E | REG_ICASE);
    /* invalid bytes: `.` and nonmatching lists skip them; a raw pattern byte
     * still matches the same byte */
    t(".", "\xff", E);
    t("a.b", "a\xff" "b", E);
    t("a.b", "a\xc3\xa9" "b", E);
    t("a..b", "a\xc3\xa9" "b", E);
    t("[^x]", "\xff", E);
    t(".", "\xa9", E);
    t("\xa9", "\xc3\xa9", E);
    t("\xe2\x82\xac.", "\xe2\x82\xac\xf0\x9f\x98\x80", E);
    t("x*", "\xc3\xa9", E);
    t("$", "\xc3\xa9", E);
    /* REG_ICASE: which members of each case triple match each other */
    for (int i = 0; i < (int)(sizeof trip / sizeof trip[0]); i++) {
        printf("%04x/%04x/%04x:", trip[i][0], trip[i][1], trip[i][2]);
        for (int form = 0; form < 2; form++) {
            for (int p = 0; p < 3; p++) {
                char c[8], pat[16];
                enc(trip[i][p], c);
                snprintf(pat, sizeof pat, form ? "[%s]" : "%s", c);
                regex_t re;
                if (regcomp(&re, pat, REG_ICASE | REG_NOSUB)) {
                    printf(" E");
                    continue;
                }
                int mask = 0;
                for (int k = 0; k < 3; k++) {
                    char s[8];
                    enc(trip[i][k], s);
                    if (regexec(&re, s, 0, NULL, 0) == 0) mask |= 1 << k;
                }
                printf(" %d", mask);
                regfree(&re);
            }
        }
        printf("\n");
    }
    return 0;
}
