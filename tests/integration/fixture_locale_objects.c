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

/* The GNU categories follow LC_ALL numerically; LC_ALL itself is not a
 * category bit in a mask. Check every combination, including zero/all. */
static const int category_ids[] = {
    LC_CTYPE, LC_NUMERIC, LC_TIME, LC_COLLATE, LC_MONETARY, LC_MESSAGES,
    LC_PAPER, LC_NAME, LC_ADDRESS, LC_TELEPHONE, LC_MEASUREMENT,
    LC_IDENTIFICATION,
};

static void category_names(locale_t loc, int utf8_mask) {
    for (size_t i = 0; i < sizeof category_ids / sizeof *category_ids; i++) {
        int category = category_ids[i];
        const char *expected = utf8_mask & (1 << category) ? "C.UTF-8" : "C";
        CHECK(strcmp(nl_langinfo_l(_NL_LOCALE_NAME(category), loc), expected) == 0);
        /* libstdc++ and GNU callers access this ABI prefix directly. */
        CHECK(strcmp(loc->__names[category], expected) == 0);
    }
    codeset(loc, utf8_mask & LC_CTYPE_MASK ? "UTF-8" : "ANSI_X3.4-1968");
}

static void category_matrix(void) {
    CHECK(setlocale(LC_ALL, "C.UTF-8"));
    const unsigned count = sizeof category_ids / sizeof *category_ids;
    for (unsigned subset = 0; subset < (1U << count); subset++) {
        int mask = 0;
        for (unsigned i = 0; i < count; i++) {
            if (subset & (1U << i)) mask |= 1 << category_ids[i];
        }
        locale_t loc = newlocale(mask, "C.UTF-8", (locale_t)0);
        CHECK(loc);
        /* A null base starts unselected categories in C, NOT the global
         * C.UTF-8 locale. Reading only CODESET would miss 11 categories. */
        category_names(loc, mask);
        locale_t copy = duplocale(loc);
        CHECK(copy);
        freelocale(loc);
        category_names(copy, mask);
        locale_t changed = newlocale(LC_NUMERIC_MASK, "C", copy);
        CHECK(changed);
        category_names(changed, mask & ~LC_NUMERIC_MASK);
        errno = 0;
        CHECK(!newlocale(LC_TIME_MASK, "fl_missing_locale_4937", changed));
        CHECK(errno == ENOENT);
        category_names(changed, mask & ~LC_NUMERIC_MASK);
        freelocale(changed);
    }
    locale_t zero = newlocale(0, "fl_missing_locale_4937", (locale_t)0);
    CHECK(zero);
    category_names(zero, 0);
    freelocale(zero);
    CHECK(setlocale(LC_ALL, "C"));
    printf("category-matrix: %u masks, category/duplicate/compose/failure checks ok\n",
           1U << count);
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
    /* GLOBAL must snapshot the process even inside an explicit UTF-8
     * selection, not duplicate the current thread's selected object. */
    CHECK(uselocale(u) == LC_GLOBAL_LOCALE);
    locale_t global_c = duplocale(LC_GLOBAL_LOCALE);
    CHECK(global_c);
    codeset(global_c, "ANSI_X3.4-1968");
    CHECK(MB_CUR_MAX == 6);
    CHECK(uselocale(LC_GLOBAL_LOCALE) == u);
    freelocale(global_c);
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
    category_matrix(); /* Keep the matrix on the existing runner's path. */
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
    /* A fresh thread must start on GLOBAL, not inherit this parent's u. */
    CHECK(uselocale(u) == LC_GLOBAL_LOCALE);
    CHECK(pthread_create(&ta, NULL, worker, &a) == 0);
    CHECK(pthread_create(&tb, NULL, worker, &b) == 0);
    CHECK(pthread_join(ta, NULL) == 0);
    CHECK(pthread_join(tb, NULL) == 0);
    CHECK(uselocale((locale_t)0) == u);
    CHECK(MB_CUR_MAX == 6);
    CHECK(uselocale(LC_GLOBAL_LOCALE) == u);
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
