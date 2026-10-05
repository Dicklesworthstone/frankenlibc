/* The *_l functions take their locale from the argument (newlocale),
 * uselocale selects the thread's locale for the plain ones. fl's strftime_l,
 * strcoll_l, strxfrm_l, wcscoll_l, wcsxfrm_l, wcsftime_l ignored the
 * argument, and the glibc-internal __strcoll_l / __wcscoll_l (which
 * libstdc++'s std::collate calls) compared bytewise / by code point: a C++
 * program sorting with std::locale("en_US.UTF-8") got C order. Needs the
 * en_US.UTF-8 locale; prints a skip line otherwise. Output matches glibc.
 */
#define _GNU_SOURCE
#include <langinfo.h>
#include <locale.h>
#include <stdio.h>
#include <string.h>
#include <time.h>
#include <wchar.h>

int __strcoll_l(const char *, const char *, locale_t);

int main(void) {
    locale_t l = newlocale(LC_ALL_MASK, "en_US.UTF-8", (locale_t)0);
    if (!l) {
        puts("en_US.UTF-8 not installed: skipped");
        return 0;
    }
    printf("D_T_FMT_l=[%s] AM=[%s] DAY_1=[%s]\n", nl_langinfo_l(D_T_FMT, l), nl_langinfo_l(AM_STR, l),
           nl_langinfo_l(DAY_1, l));
    struct tm tm = {0};
    tm.tm_year = 70;
    tm.tm_mday = 1;
    tm.tm_hour = 13;
    tm.tm_wday = 4;
    char buf[128];
    strftime_l(buf, sizeof buf, "%c|%x|%X|%p|%r", &tm, l);
    printf("strftime_l=[%s]\n", buf);
    wchar_t wbuf[128];
    wcsftime_l(wbuf, 128, L"%x|%p", &tm, l);
    printf("wcsftime_l=[%ls]\n", wbuf);
    const char *w[] = {"a", "B", "c", "A", "b", "\xc3\xa9", "e", "Z"};
    printf("strcoll_l:  ");
    for (int i = 0; i < 8; i++)
        for (int j = 0; j < 8; j++) {
            int r = strcoll_l(w[i], w[j], l);
            putchar(r < 0 ? '<' : r > 0 ? '>' : '=');
        }
    printf("\n__strcoll_l:");
    for (int i = 0; i < 8; i++)
        for (int j = 0; j < 8; j++) {
            int r = __strcoll_l(w[i], w[j], l);
            putchar(r < 0 ? '<' : r > 0 ? '>' : '=');
        }
    printf("\n");
    char k1[64], k2[64];
    strxfrm_l(k1, "apple", sizeof k1, l);
    strxfrm_l(k2, "Banana", sizeof k2, l);
    printf("strxfrm_l order apple/Banana=%d\n", strcmp(k1, k2) < 0 ? -1 : 1);
    printf("wcscoll_l(apple,Banana)=%d\n", wcscoll_l(L"apple", L"Banana", l) < 0 ? -1 : 1);
    /* the global locale stays C */
    strftime(buf, sizeof buf, "%c|%p", &tm);
    printf("global strftime=[%s] strcoll(a,B)=%d\n", buf, strcoll("a", "B") < 0 ? -1 : 1);
    locale_t old = uselocale(l);
    strftime(buf, sizeof buf, "%c", &tm);
    printf("uselocale strftime=[%s] strcoll(a,B)=%d\n", buf, strcoll("a", "B") < 0 ? -1 : 1);
    /* printf's ' grouping follows the thread's LC_NUMERIC */
    printf("uselocale %%'d=[%'d] %%'.2f=[%'.2f]\n", 1234567, 9876543.21);
    uselocale(old);
    printf("restored  %%'d=[%'d]\n", 1234567);
    freelocale(l);
    return 0;
}
