#define _GNU_SOURCE
#include <errno.h>
#include <langinfo.h>
#include <locale.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <wchar.h>
#include <wctype.h>

#define CHECK(expr) do { if (!(expr)) { \
    fprintf(stderr, "%s:%d: %s (errno=%d)\n", __FILE__, __LINE__, #expr, errno); \
    exit(1); } } while (0)

static void codeset(locale_t locale, const char *want) {
    CHECK(strcmp(nl_langinfo_l(CODESET, locale), want) == 0);
}

static void lifecycle(void) {
    CHECK(uselocale((locale_t)0) == LC_GLOBAL_LOCALE);
    CHECK(setlocale(LC_ALL, "C"));
    locale_t c = newlocale(LC_ALL_MASK, "C", (locale_t)0);
    locale_t u = newlocale(LC_ALL_MASK, "C.UTF-8", (locale_t)0);
    CHECK(c && u);
    CHECK(uselocale(u) == LC_GLOBAL_LOCALE);
    CHECK(uselocale((locale_t)0) == u);
    CHECK(strcmp(nl_langinfo(CODESET), "UTF-8") == 0);
    CHECK(MB_CUR_MAX == 6);
    CHECK(iswalpha(L'\u00e4'));
    CHECK(strcmp(setlocale(LC_CTYPE, NULL), "C") == 0);
    CHECK(uselocale(c) == u);
    CHECK(MB_CUR_MAX == 1);
    CHECK(!iswalpha(L'\u00e4'));
    CHECK(uselocale(u) == c);
    CHECK(MB_CUR_MAX == 6);
    CHECK(uselocale(LC_GLOBAL_LOCALE) == u);
    CHECK(MB_CUR_MAX == 1);
    freelocale(u);
    freelocale(c);
    puts("lifecycle: ok");
}

static void composition(void) {
    CHECK(setlocale(LC_ALL, "C.UTF-8"));
    locale_t c = newlocale(LC_NUMERIC_MASK, "C", (locale_t)0);
    CHECK(c);
    codeset(c, "ANSI_X3.4-1968"); /* unspecified categories start in C, not global */
    locale_t u = newlocale(LC_CTYPE_MASK, "C.UTF-8", (locale_t)0);
    CHECK(u);
    locale_t copy = duplocale(u);
    CHECK(copy);
    locale_t composed = newlocale(LC_NUMERIC_MASK, "C", copy);
    CHECK(composed);
    codeset(composed, "UTF-8");
    errno = 0;
    CHECK(!newlocale(LC_TIME_MASK, "fl_missing_locale_4937", composed));
    CHECK(errno == ENOENT);
    codeset(composed, "UTF-8"); /* failed update must not consume base */
    locale_t snapshot = duplocale(LC_GLOBAL_LOCALE);
    CHECK(snapshot);
    CHECK(setlocale(LC_ALL, "C"));
    codeset(snapshot, "UTF-8");
    codeset(u, "UTF-8");
    codeset(c, "ANSI_X3.4-1968");
    errno = 0;
    CHECK(!newlocale(-1, "C", (locale_t)0));
    CHECK(errno == EINVAL);
    /* GNU compatibility form used by libstdc++ during static initialization. */
    locale_t all = newlocale(1 << LC_ALL, "C", (locale_t)0);
    CHECK(all);
    freelocale(all);
    freelocale(snapshot);
    freelocale(composed);
    freelocale(u);
    freelocale(c);
    puts("composition: ok");
}

struct thread_case { locale_t locale; size_t width; int alpha; pthread_barrier_t *barrier; };
static void *worker(void *opaque) {
    struct thread_case *arg = opaque;
    CHECK(uselocale((locale_t)0) == LC_GLOBAL_LOCALE);
    CHECK(uselocale(arg->locale) == LC_GLOBAL_LOCALE);
    for (int i = 0; i < 100; ++i) {
        int rc = pthread_barrier_wait(arg->barrier);
        CHECK(rc == 0 || rc == PTHREAD_BARRIER_SERIAL_THREAD);
        CHECK(MB_CUR_MAX == arg->width);
        CHECK(!!iswalpha(L'\u00e4') == arg->alpha);
        CHECK(uselocale((locale_t)0) == arg->locale);
        CHECK(strcmp(setlocale(LC_CTYPE, NULL), "C") == 0);
        mbstate_t state = {0};
        wchar_t wc = 0;
        size_t n = mbrtowc(&wc, "\xc3\xa4", 2, &state);
        if (arg->alpha) { CHECK(n == 2 && wc == L'\u00e4'); }
        else { CHECK(n == (size_t)-1 && errno == EILSEQ); }
    }
    CHECK(uselocale(LC_GLOBAL_LOCALE) == arg->locale);
    return NULL;
}

static void threads(void) {
    CHECK(setlocale(LC_ALL, "C"));
    locale_t c = newlocale(LC_ALL_MASK, "C", (locale_t)0);
    locale_t u = newlocale(LC_ALL_MASK, "C.UTF-8", (locale_t)0);
    CHECK(c && u);
    pthread_barrier_t barrier;
    CHECK(pthread_barrier_init(&barrier, NULL, 2) == 0);
    struct thread_case a = {c, 1, 0, &barrier}, b = {u, 6, 1, &barrier};
    pthread_t ta, tb;
    CHECK(pthread_create(&ta, NULL, worker, &a) == 0);
    CHECK(pthread_create(&tb, NULL, worker, &b) == 0);
    CHECK(pthread_join(ta, NULL) == 0);
    CHECK(pthread_join(tb, NULL) == 0);
    CHECK(uselocale((locale_t)0) == LC_GLOBAL_LOCALE);
    CHECK(MB_CUR_MAX == 1);
    CHECK(pthread_barrier_destroy(&barrier) == 0);
    freelocale(u);
    freelocale(c);
    puts("threads: ok");
}

static void named(void) {
    CHECK(setlocale(LC_ALL, "C"));
    locale_t de = newlocale(LC_ALL_MASK, "de_DE.UTF-8", (locale_t)0);
    locale_t fr = newlocale(LC_ALL_MASK, "fr_FR.UTF-8", (locale_t)0);
    CHECK(de && fr); /* the runner installs these: never silently skip coverage */
    CHECK(strcmp(nl_langinfo_l(RADIXCHAR, de), ",") == 0);
    CHECK(strcmp(nl_langinfo_l(THOUSEP, de), ".") == 0);
    CHECK(strcmp(nl_langinfo_l(DAY_2, fr), "lundi") == 0);
    CHECK(strcmp(nl_langinfo(RADIXCHAR), ".") == 0);
    struct tm tm = {.tm_year=126, .tm_mon=8, .tm_mday=21, .tm_wday=1};
    char out[80];
    CHECK(strftime_l(out, sizeof out, "%A", &tm, fr) == 5);
    CHECK(strcmp(out, "lundi") == 0);
    CHECK(strcoll_l("\xc3\xa4", "z", de) < 0);
    CHECK(uselocale(de) == LC_GLOBAL_LOCALE);
    CHECK(strcmp(localeconv()->decimal_point, ",") == 0);
    CHECK(strcmp(nl_langinfo(DAY_2), "Montag") == 0);
    CHECK(strftime(out, sizeof out, "%A", &tm) == 6);
    CHECK(strcmp(out, "Montag") == 0);
    CHECK(strcmp(setlocale(LC_ALL, NULL), "C") == 0);
    CHECK(strcmp(nl_langinfo_l(DAY_2, fr), "lundi") == 0);
    CHECK(uselocale((locale_t)0) == de); /* _l calls must not leak a switch */
    CHECK(uselocale(LC_GLOBAL_LOCALE) == de);
    locale_t mixed = newlocale(LC_TIME_MASK, "fr_FR.UTF-8", duplocale(de));
    CHECK(mixed);
    CHECK(strcmp(nl_langinfo_l(DAY_2, mixed), "lundi") == 0);
    CHECK(strcmp(nl_langinfo_l(THOUSEP, mixed), ".") == 0);
    freelocale(mixed);
    freelocale(fr);
    freelocale(de);
    puts("named: ok");
}

int main(int argc, char **argv) {
    CHECK(argc == 2);
    if (!strcmp(argv[1], "lifecycle")) lifecycle();
    else if (!strcmp(argv[1], "composition")) composition();
    else if (!strcmp(argv[1], "threads")) threads();
    else if (!strcmp(argv[1], "named")) named();
    else return 2;
    return 0;
}
