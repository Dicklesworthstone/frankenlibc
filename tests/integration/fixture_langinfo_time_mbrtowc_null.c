/* C-locale LC_TIME items past ERA_T_FMT, and mbrtowc(pwc, NULL, ...) leaving
 * *pwc untouched.
 *
 * fl returned "" for every LC_TIME item from 50 on: ALTMON_n and _NL_ABALTMON_n
 * (gnulib test-nl_langinfo asserts strlen(ALTMON_1) > 0), _DATE_FMT, the week
 * data, and the _NL_W* wide strings, which then read past a one-byte narrow
 * literal. mbrtowc(&wc, NULL, n, ps) is mbrtowc(NULL, "", 1, ps), but fl stored
 * 0 into wc (gnulib test-mbrtowc). Output matches glibc.
 */
#define _GNU_SOURCE
#include <langinfo.h>
#include <locale.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <uchar.h>
#include <wchar.h>

int main(void) {
    setlocale(LC_ALL, "C");
    for (int i = 0; i < 12; i++)
        printf("ALTMON_%d=%s ABALTMON_%d=%s WALTMON_%d=%ls\n", i + 1, nl_langinfo(ALTMON_1 + i), i + 1,
               nl_langinfo(_NL_ABALTMON_1 + i), i + 1, (const wchar_t *)nl_langinfo(_NL_WALTMON_1 + i));
    printf("_DATE_FMT=%s\n", nl_langinfo(_DATE_FMT));
    printf("_NL_W_DATE_FMT=%ls\n", (const wchar_t *)nl_langinfo(_NL_W_DATE_FMT));
    printf("_NL_TIME_CODESET=%s\n", nl_langinfo(_NL_TIME_CODESET));
    printf("_NL_WDAY_1=%ls _NL_WMON_12=%ls _NL_WT_FMT_AMPM=%ls\n", (const wchar_t *)nl_langinfo(_NL_WDAY_1),
           (const wchar_t *)nl_langinfo(_NL_WMON_12), (const wchar_t *)nl_langinfo(_NL_WT_FMT_AMPM));
    printf("WEEK_NDAYS=%d WEEK_1STDAY=%lu WEEK_1STWEEK=%d FIRST_WEEKDAY=%d FIRST_WORKDAY=%d\n",
           nl_langinfo(_NL_TIME_WEEK_NDAYS)[0], (unsigned long)(uintptr_t)nl_langinfo(_NL_TIME_WEEK_1STDAY),
           nl_langinfo(_NL_TIME_WEEK_1STWEEK)[0], nl_langinfo(_NL_TIME_FIRST_WEEKDAY)[0],
           nl_langinfo(_NL_TIME_FIRST_WORKDAY)[0]);
    printf("ERA_NUM_ENTRIES=%lu\n", (unsigned long)(uintptr_t)nl_langinfo(_NL_TIME_ERA_NUM_ENTRIES));

    mbstate_t st;
    memset(&st, 0, sizeof st);
    wchar_t wc = (wchar_t)0xBADFACE;
    size_t r = mbrtowc(&wc, NULL, 5, &st);
    printf("mbrtowc(NULL s)=%zu wc=%#x mbsinit=%d\n", r, (unsigned)wc, mbsinit(&st));
    char16_t c16 = 0x1234;
    memset(&st, 0, sizeof st);
    r = mbrtoc16(&c16, NULL, 5, &st);
    printf("mbrtoc16(NULL s)=%zu c16=%#x\n", r, (unsigned)c16);
    char32_t c32 = 0x12345;
    r = mbrtoc32(&c32, NULL, 5, &st);
    printf("mbrtoc32(NULL s)=%zu c32=%#x\n", r, (unsigned)c32);
    return 0;
}
