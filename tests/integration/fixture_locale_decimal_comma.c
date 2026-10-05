/* A locale whose LC_NUMERIC radix is ',' and thousands separator '.'
 * (de_DE.UTF-8): printf's %f/%e/%a radix, %' grouping, strtod's radix and
 * localeconv, both for the global locale (setlocale) and for one thread
 * (uselocale), then back to C. The smoke runner compiles de_DE into a private
 * LOCPATH with localedef; without it every line is the skip line. Output
 * matches glibc.
 */
#define _GNU_SOURCE
#include <locale.h>
#include <stdio.h>
#include <stdlib.h>

static void show(const char *tag) {
    char buf[200];
    struct lconv *lc = localeconv();
    char *end;
    double d = strtod("3,25xyz", &end);
    double e = strtod("3.25xyz", &end);
    snprintf(buf, sizeof buf, "%f|%.2f|%g|%e|%'d|%'.1f|%a", 1234.5, 0.25, 1e-5, 12.5, 1234567,
             12345.25, 1.5);
    printf("%s: [%s] radix=[%s] thou=[%s] strtod(3,25)=%g strtod(3.25)=%g end=[%s]\n", tag, buf,
           lc->decimal_point, lc->thousands_sep, d, e, end);
}

int main(void) {
    show("C");
    if (!setlocale(LC_ALL, "de_DE.UTF-8")) {
        puts("de_DE.UTF-8 not available: skipped");
        return 0;
    }
    show("de global");
    setlocale(LC_ALL, "C");
    locale_t l = newlocale(LC_ALL_MASK, "de_DE.UTF-8", (locale_t)0);
    uselocale(l);
    show("de uselocale");
    uselocale(LC_GLOBAL_LOCALE);
    show("C again");
    freelocale(l);
    return 0;
}
