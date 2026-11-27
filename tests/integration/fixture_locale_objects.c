#define _GNU_SOURCE
#include <dlfcn.h>
#include <errno.h>
#include <fnmatch.h>
#include <langinfo.h>
#include <locale.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <time.h>
#include <uchar.h>
#include <unistd.h>
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
        char missing[64];
        CHECK((size_t)snprintf(missing, sizeof missing, "fl_missing_locale_%u", subset) < sizeof missing);
        errno = 0;
        CHECK(!newlocale(LC_TIME_MASK, missing, changed));
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

/* Explicit wide-character locale APIs must consult the object's LC_CTYPE,
 * independently of the selected thread locale and its other categories.
 * Descriptor constructors and consumers always belong to the same provider
 * and use the same locale: GNU's opaque descriptors are not interchangeable
 * with another libc's representation. */
struct wide_class {
    const char *name;
    const char *symbol;
    int (*classify)(wint_t, locale_t);
    int (*internal)(wint_t, locale_t);
};
static struct wide_class wide_classes[] = {
    {"alnum", "iswalnum_l", iswalnum_l, NULL},
    {"alpha", "iswalpha_l", iswalpha_l, NULL},
    {"blank", "iswblank_l", iswblank_l, NULL},
    {"cntrl", "iswcntrl_l", iswcntrl_l, NULL},
    {"digit", "iswdigit_l", iswdigit_l, NULL},
    {"graph", "iswgraph_l", iswgraph_l, NULL},
    {"lower", "iswlower_l", iswlower_l, NULL},
    {"print", "iswprint_l", iswprint_l, NULL},
    {"punct", "iswpunct_l", iswpunct_l, NULL},
    {"space", "iswspace_l", iswspace_l, NULL},
    {"upper", "iswupper_l", iswupper_l, NULL},
    {"xdigit", "iswxdigit_l", iswxdigit_l, NULL},
};
static wctype_t (*wide_internal_wctype)(const char *, locale_t);
static int (*wide_internal_iswctype)(wint_t, wctype_t, locale_t);
static wctrans_t (*wide_internal_wctrans)(const char *, locale_t);
static wint_t (*wide_internal_towctrans)(wint_t, wctrans_t, locale_t);
static wint_t (*wide_internal_toupper)(wint_t, locale_t);
static wint_t (*wide_internal_tolower)(wint_t, locale_t);
static int (*wide_internal_compare)(const wchar_t *, const wchar_t *, locale_t);
static int (*wide_internal_ncompare)(const wchar_t *, const wchar_t *, size_t, locale_t);

static void *locale_symbol(const char *family, const char *expected,
                           const char *name, const void *address) {
    struct stat wanted, actual;
    Dl_info info = {0};
    CHECK(stat(expected, &wanted) == 0);
    void *symbol = address ? (void *)address : dlsym(RTLD_DEFAULT, name);
    if (!symbol || !dladdr(symbol, &info) || !info.dli_fname ||
        stat(info.dli_fname, &actual) != 0 || wanted.st_dev != actual.st_dev ||
        wanted.st_ino != actual.st_ino) {
        fprintf(stderr, "%s:provider-mismatch:%s\n", family, name);
        exit(86);
    }
    return symbol;
}

static void *wide_symbol(const char *expected, const char *name, const void *address) {
    return locale_symbol("locale-wide", expected, name, address);
}

static void wide_provider(const char *expected) {
    static const struct { const char *name; const void *address; } functions[] = {
        {"newlocale", (const void *)newlocale}, {"setlocale", (const void *)setlocale},
        {"uselocale", (const void *)uselocale}, {"freelocale", (const void *)freelocale},
        {"nl_langinfo_l", (const void *)nl_langinfo_l},
        {"__ctype_get_mb_cur_max", (const void *)__ctype_get_mb_cur_max},
        {"iswalpha", (const void *)iswalpha}, {"towlower", (const void *)towlower},
        {"towupper", (const void *)towupper}, {"wctype_l", (const void *)wctype_l},
        {"iswctype_l", (const void *)iswctype_l}, {"wctrans_l", (const void *)wctrans_l},
        {"towctrans_l", (const void *)towctrans_l},
        {"towlower_l", (const void *)towlower_l}, {"towupper_l", (const void *)towupper_l},
        {"wcscasecmp", (const void *)wcscasecmp}, {"wcsncasecmp", (const void *)wcsncasecmp},
        {"wcscasecmp_l", (const void *)wcscasecmp_l},
        {"wcsncasecmp_l", (const void *)wcsncasecmp_l},
    };
    for (size_t i = 0; i < sizeof functions / sizeof *functions; ++i)
        (void)wide_symbol(expected, functions[i].name, functions[i].address);
    for (size_t i = 0; i < sizeof wide_classes / sizeof *wide_classes; ++i) {
        struct wide_class *entry = &wide_classes[i];
        (void)wide_symbol(expected, entry->symbol, (const void *)entry->classify);
        char alias[32];
        CHECK(snprintf(alias, sizeof alias, "__%s", entry->symbol) > 0);
        entry->internal = (int (*)(wint_t, locale_t))wide_symbol(expected, alias, NULL);
    }
    wide_internal_wctype = (wctype_t (*)(const char *, locale_t))
        wide_symbol(expected, "__wctype_l", NULL);
    wide_internal_iswctype = (int (*)(wint_t, wctype_t, locale_t))
        wide_symbol(expected, "__iswctype_l", NULL);
    wide_internal_wctrans = (wctrans_t (*)(const char *, locale_t))
        wide_symbol(expected, "__wctrans_l", NULL);
    wide_internal_towctrans = (wint_t (*)(wint_t, wctrans_t, locale_t))
        wide_symbol(expected, "__towctrans_l", NULL);
    wide_internal_toupper = (wint_t (*)(wint_t, locale_t))
        wide_symbol(expected, "__towupper_l", NULL);
    wide_internal_tolower = (wint_t (*)(wint_t, locale_t))
        wide_symbol(expected, "__towlower_l", NULL);
    wide_internal_compare = (int (*)(const wchar_t *, const wchar_t *, locale_t))
        wide_symbol(expected, "__wcscasecmp_l", NULL);
    wide_internal_ncompare = (int (*)(const wchar_t *, const wchar_t *, size_t, locale_t))
        wide_symbol(expected, "__wcsncasecmp_l", NULL);
}

static void wide_rows(locale_t loc, const char *name) {
    static const wint_t values[] = {
        0, 9, 10, 11, 12, 13, 31, 32, 33, 48, 57, 65, 70, 90, 97, 102, 122, 127,
        0x85, 0xa0, 0xc4, 0xe4, 0xdf, 0x130, 0x131, 0x3a3, 0x3c2, 0x3c3,
        0x2003, 0x2028, 0x2029, 0x3000, 0x4e00, 0x10400, 0x10428, 0x1f600,
        /* GNU compatibility observations, beyond POSIX's character domain. */
        0xd7ff, 0xd800, 0xdfff, 0xe000, 0x10ffff, 0x110000, 0x7fffffff, WEOF,
    };
    wctype_t descriptors[12], internal_descriptors[12];
    CHECK(!wctype_l("fl_missing_class", loc));
    CHECK(!wctrans_l("fl_missing_mapping", loc));
    for (size_t i = 0; i < sizeof wide_classes / sizeof *wide_classes; ++i) {
        descriptors[i] = wctype_l(wide_classes[i].name, loc);
        internal_descriptors[i] = wide_internal_wctype(wide_classes[i].name, loc);
        CHECK(descriptors[i] && internal_descriptors[i]);
    }
    wctrans_t upper = wctrans_l("toupper", loc), lower = wctrans_l("tolower", loc);
    wctrans_t internal_upper = wide_internal_wctrans("toupper", loc);
    wctrans_t internal_lower = wide_internal_wctrans("tolower", loc);
    CHECK(upper && lower && internal_upper && internal_lower);
    locale_t selected = uselocale((locale_t)0);
    size_t width = MB_CUR_MAX;
    for (size_t j = 0; j < sizeof values / sizeof *values; ++j) {
        wint_t wc = values[j];
        unsigned mask = 0;
        for (size_t i = 0; i < sizeof wide_classes / sizeof *wide_classes; ++i) {
            int classified = !!wide_classes[i].classify(wc, loc);
            CHECK(!!wide_classes[i].internal(wc, loc) == classified);
            CHECK(!!iswctype_l(wc, descriptors[i], loc) == classified);
            CHECK(!!wide_internal_iswctype(wc, internal_descriptors[i], loc) == classified);
            mask |= (unsigned)classified << i;
        }
        wint_t up = towupper_l(wc, loc), down = towlower_l(wc, loc);
        CHECK(wide_internal_toupper(wc, loc) == up);
        CHECK(wide_internal_tolower(wc, loc) == down);
        CHECK(towctrans_l(wc, upper, loc) == up);
        CHECK(towctrans_l(wc, lower, loc) == down);
        CHECK(wide_internal_towctrans(wc, internal_upper, loc) == up);
        CHECK(wide_internal_towctrans(wc, internal_lower, loc) == down);
        CHECK(uselocale((locale_t)0) == selected && MB_CUR_MAX == width);
        printf("wide:%s:%08x:%03x:%08x:%08x\n", name, (unsigned)wc, mask,
               (unsigned)up, (unsigned)down);
    }
}

static int wide_sign(int value) { return (value > 0) - (value < 0); }

static void wide_comparisons(locale_t loc, const char *name) {
    static const struct { const wchar_t *left, *right; } pairs[] = {
        {L"", L""}, {L"ASCII-long-PREFIX", L"ascii-LONG-prefix"},
        {L"\u00c4pfel", L"\u00e4PFEL"}, {L"\u03a3", L"\u03c3"},
        {L"\U00010400", L"\U00010428"}, {L"\u0130", L"i"},
        {L"I", L"\u0131"}, {L"I", L"i"}, {L"xI-tail", L"Xi-TaIL"},
        {L"ab", L"ABx"}, {L"abcdefX", L"ABCDEFy"},
    };
    static const size_t bounds[] = {0, 1, 2, 3, 8, 64};
    locale_t ambient = uselocale((locale_t)0);
    for (size_t i = 0; i < sizeof pairs / sizeof *pairs; ++i) {
        const wchar_t *left = pairs[i].left, *right = pairs[i].right;
        int cmp = wcscasecmp_l(left, right, loc);
        CHECK(wide_internal_compare(left, right, loc) == cmp);
        CHECK(uselocale((locale_t)0) == ambient);
        CHECK(uselocale(loc) == ambient);
        CHECK(wide_sign(wcscasecmp(left, right)) == wide_sign(cmp));
        CHECK(uselocale(ambient) == loc);
        printf("wide-compare:%s:%zu:%d", name, i, wide_sign(cmp));
        for (size_t j = 0; j < sizeof bounds / sizeof *bounds; ++j) {
            size_t n = bounds[j];
            int bounded = wcsncasecmp_l(left, right, n, loc);
            CHECK(wide_internal_ncompare(left, right, n, loc) == bounded);
            CHECK(uselocale((locale_t)0) == ambient);
            CHECK(uselocale(loc) == ambient);
            CHECK(wide_sign(wcsncasecmp(left, right, n)) == wide_sign(bounded));
            CHECK(uselocale(ambient) == loc);
            printf(":%d", wide_sign(bounded));
        }
        putchar('\n');
    }
    long page = sysconf(_SC_PAGESIZE);
    CHECK(page > 0);
    size_t length = (size_t)page * 4;
    char *mapping = mmap(NULL, length, PROT_NONE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    CHECK(mapping != MAP_FAILED);
    CHECK(mprotect(mapping, (size_t)page, PROT_READ | PROT_WRITE) == 0);
    CHECK(mprotect(mapping + 2 * page, (size_t)page, PROT_READ | PROT_WRITE) == 0);
    wchar_t *left_end = (wchar_t *)(mapping + page);
    wchar_t *right_end = (wchar_t *)(mapping + 3 * page);
    left_end[-2] = 0x00c4; right_end[-2] = 0x00e4;
    left_end[-1] = 0; right_end[-1] = 0;
    int terminated = wcscasecmp_l(left_end - 2, right_end - 2, loc);
    CHECK(wide_internal_compare(left_end - 2, right_end - 2, loc) == terminated);
    CHECK(wide_sign(terminated) == wide_sign(towlower_l(0xc4, loc) - towlower_l(0xe4, loc)));
    CHECK(wcsncasecmp_l(left_end - 2, right_end - 2, 3, loc) == terminated);
    /* Equal one-element prefixes have no accessible terminator. Both the
     * nonzero bound and n == 0 with inaccessible pointers must stop in time. */
    left_end[-1] = L'I'; right_end[-1] = 0x0131;
    int bounded = wcsncasecmp_l(left_end - 1, right_end - 1, 1, loc);
    CHECK(wide_internal_ncompare(left_end - 1, right_end - 1, 1, loc) == bounded);
    CHECK(wcsncasecmp_l(left_end, right_end, 0, loc) == 0);
    CHECK(wide_internal_ncompare(left_end, right_end, 0, loc) == 0);
    CHECK(uselocale((locale_t)0) == ambient);
    CHECK(munmap(mapping, length) == 0);
    printf("wide-guard:%s:%d:%d\n", name, wide_sign(terminated), wide_sign(bounded));
}

static void wide(const char *provider) {
    wide_provider(provider);
    CHECK(setlocale(LC_ALL, "C"));
    locale_t c = newlocale(LC_NUMERIC_MASK, "tr_TR.UTF-8", (locale_t)0);
    locale_t u = newlocale(LC_CTYPE_MASK, "C.UTF-8", (locale_t)0);
    locale_t tr = newlocale(LC_CTYPE_MASK, "tr_TR.UTF-8", (locale_t)0);
    CHECK(c && u && tr);
    /* Contradicting categories catch accidental use of the object's name,
     * numeric category, or the thread's selected locale in place of CTYPE. */
    CHECK(!strcmp(nl_langinfo_l(RADIXCHAR, c), ","));
    CHECK(!strcmp(nl_langinfo_l(RADIXCHAR, tr), "."));
    locale_t locales[] = {c, u, tr};
    const char *names[] = {"C-ctype-Turkish-numeric", "C.UTF-8", "tr_TR.UTF-8"};
    for (size_t i = 0; i < sizeof locales / sizeof *locales; ++i) {
        locale_t ambient = i == 0 ? u : c;
        CHECK(uselocale(ambient) == LC_GLOBAL_LOCALE);
        wide_rows(locales[i], names[i]);
        wide_comparisons(locales[i], names[i]);
        CHECK(uselocale((locale_t)0) == ambient);
        CHECK(!strcmp(setlocale(LC_CTYPE, NULL), "C"));
        CHECK(uselocale(LC_GLOBAL_LOCALE) == ambient);
    }
    CHECK(towlower_l(L'I', tr) == 0x0131);
    CHECK(towupper_l(L'i', tr) == 0x0130);
    CHECK(towlower_l(L'I', u) == L'i');
    CHECK(towupper_l(L'i', u) == L'I');
    CHECK(!iswalpha_l(0x00e4, c) && iswalpha_l(0x00e4, u));
    freelocale(tr);
    freelocale(u);
    freelocale(c);
    puts("wide: ok");
}

struct wide_thread_case {
    locale_t selected, explicit, turkish;
    int unicode;
    pthread_barrier_t *barrier;
};
static void *wide_worker(void *opaque) {
    struct wide_thread_case *arg = opaque;
    CHECK(uselocale(arg->selected) == LC_GLOBAL_LOCALE);
    for (unsigned i = 0; i < 100; ++i) {
        int rc = pthread_barrier_wait(arg->barrier);
        CHECK(rc == 0 || rc == PTHREAD_BARRIER_SERIAL_THREAD);
        CHECK(!!iswalpha_l(0x00e4, arg->explicit) == !arg->unicode);
        CHECK(towlower_l(0x00c4, arg->explicit) == (arg->unicode ? 0x00c4U : 0x00e4U));
        CHECK(towlower_l(L'I', arg->turkish) == 0x0131);
        CHECK(towupper_l(L'i', arg->turkish) == 0x0130);
        CHECK(wcscasecmp_l(L"I", L"\u0131", arg->turkish) == 0);
        CHECK((wcscasecmp_l(L"\u00c4", L"\u00e4", arg->explicit) == 0) == !arg->unicode);
        CHECK(!!iswalpha(0x00e4) == arg->unicode);
        CHECK((wcscasecmp(L"\u00c4", L"\u00e4") == 0) == arg->unicode);
        CHECK(uselocale((locale_t)0) == arg->selected);
        CHECK(MB_CUR_MAX == (arg->unicode ? 6U : 1U));
        CHECK(!strcmp(setlocale(LC_CTYPE, NULL), "C"));
    }
    CHECK(uselocale(LC_GLOBAL_LOCALE) == arg->selected);
    return NULL;
}

static void wide_threads(const char *provider) {
    wide_provider(provider);
    CHECK(setlocale(LC_ALL, "C"));
    locale_t c = newlocale(LC_ALL_MASK, "C", (locale_t)0);
    locale_t u = newlocale(LC_CTYPE_MASK, "C.UTF-8", (locale_t)0);
    locale_t tr = newlocale(LC_CTYPE_MASK, "tr_TR.UTF-8", (locale_t)0);
    CHECK(c && u && tr);
    pthread_barrier_t barrier;
    CHECK(pthread_barrier_init(&barrier, NULL, 2) == 0);
    struct wide_thread_case a = {c, u, tr, 0, &barrier}, b = {u, c, tr, 1, &barrier};
    pthread_t ta, tb;
    CHECK(pthread_create(&ta, NULL, wide_worker, &a) == 0);
    CHECK(pthread_create(&tb, NULL, wide_worker, &b) == 0);
    CHECK(pthread_join(ta, NULL) == 0);
    CHECK(pthread_join(tb, NULL) == 0);
    CHECK(pthread_barrier_destroy(&barrier) == 0);
    CHECK(uselocale((locale_t)0) == LC_GLOBAL_LOCALE && MB_CUR_MAX == 1);
    freelocale(tr);
    freelocale(u);
    freelocale(c);
    puts("wide-threads: ok");
}

/* These vectors are independent of the implementation's iconv tables. The
 * runner compiles real localedef data and compares the same caller with GNU
 * and both deployed modes. In particular, SHIFT_JIS is not an ASCII superset. */
struct codec_vector { wchar_t value; const char *bytes; size_t length; };
struct codec_case {
    const char *name;
    const char *codeset;
    size_t width;
    unsigned char invalid_byte;
    const struct codec_vector *vectors;
    size_t count;
    wchar_t middle, last;
    const char *text;
    const char *utf8;
};

static const struct codec_vector sjis_vectors[] = {
    {L'A', "A", 1}, {0x00a5, "\x5c", 1}, {0x203e, "\x7e", 1},
    {0xff71, "\xb1", 1}, {0x3042, "\x82\xa0", 2}, {0x4e00, "\x88\xea", 2},
};
static const struct codec_vector eucjp_vectors[] = {
    {L'A', "A", 1}, {L'\\', "\x5c", 1}, {L'~', "\x7e", 1},
    {0xff71, "\x8e\xb1", 2}, {0x3042, "\xa4\xa2", 2},
    {0x4e00, "\xb0\xec", 2}, {0x4e02, "\x8f\xb0\xa1", 3},
    {0x02d8, "\x8f\xa2\xaf", 3},
};
static const struct codec_vector gb18030_vectors[] = {
    {L'A', "A", 1}, {0x3042, "\xa4\xa2", 2}, {0x4e00, "\xd2\xbb", 2},
    {0x4e02, "\x81\x40", 2}, {0x1f600, "\x94\x39\xfc\x36", 4},
};
static const struct codec_vector big5_vectors[] = {
    {0x4e2d, "\xa4\xa4", 2}, {0x6587, "\xa4\xe5", 2}, {0x20ac, "\xa3\xe1", 2},
};
static const struct codec_vector gbk_vectors[] = {
    {0x4e2d, "\xd6\xd0", 2}, {0x4e02, "\x81\x40", 2}, {0x20ac, "\x80", 1},
};
static const struct codec_vector gb2312_vectors[] = {
    {0x4e2d, "\xd6\xd0", 2}, {0x6587, "\xce\xc4", 2},
};
static const struct codec_vector euckr_vectors[] = {
    {0xac00, "\xb0\xa1", 2}, {0xd55c, "\xc7\xd1", 2}, {0x20ac, "\xa2\xe6", 2},
};
static const struct codec_vector cp949_vectors[] = {
    {0xac00, "\xb0\xa1", 2}, {0xac02, "\x81\x41", 2},
};
static const struct codec_vector cp932_vectors[] = {
    {0x3042, "\x82\xa0", 2}, {0x8a9e, "\x8c\xea", 2}, {0xff71, "\xb1", 1},
};
static const struct codec_case codec_cases[] = {
    {"ja_JP.SJIS", "SHIFT_JIS", 2, 0xff, sjis_vectors,
     sizeof sjis_vectors / sizeof *sjis_vectors, 0x3042, 0x4e00,
     "A\x82\xa0\x88\xea", "A\xe3\x81\x82\xe4\xb8\x80"},
    {"ja_JP.EUC-JP", "EUC-JP", 3, 0xff, eucjp_vectors,
     sizeof eucjp_vectors / sizeof *eucjp_vectors, 0x3042, 0x4e02,
     "A\xa4\xa2\x8f\xb0\xa1", "A\xe3\x81\x82\xe4\xb8\x82"},
    {"zh_CN.GB18030", "GB18030", 4, 0xff, gb18030_vectors,
     sizeof gb18030_vectors / sizeof *gb18030_vectors, 0x3042, 0x1f600,
     "A\xa4\xa2\x94\x39\xfc\x36", "A\xe3\x81\x82\xf0\x9f\x98\x80"},
    {"zh_TW.BIG5", "BIG5", 2, 0xff, big5_vectors,
     sizeof big5_vectors / sizeof *big5_vectors, 0x4e2d, 0x6587,
     "A\xa4\xa4\xa4\xe5", "A\xe4\xb8\xad\xe6\x96\x87"},
    {"zh_CN.GBK", "GBK", 2, 0xff, gbk_vectors,
     sizeof gbk_vectors / sizeof *gbk_vectors, 0x4e2d, 0x4e02,
     "A\xd6\xd0\x81\x40", "A\xe4\xb8\xad\xe4\xb8\x82"},
    {"zh_CN.GB2312", "GB2312", 2, 0xff, gb2312_vectors,
     sizeof gb2312_vectors / sizeof *gb2312_vectors, 0x4e2d, 0x6587,
     "A\xd6\xd0\xce\xc4", "A\xe4\xb8\xad\xe6\x96\x87"},
    {"ko_KR.EUC-KR", "EUC-KR", 2, 0xa0, euckr_vectors,
     sizeof euckr_vectors / sizeof *euckr_vectors, 0xac00, 0xd55c,
     "A\xb0\xa1\xc7\xd1", "A\xea\xb0\x80\xed\x95\x9c"},
    {"ko_KR.CP949", "CP949", 2, 0xff, cp949_vectors,
     sizeof cp949_vectors / sizeof *cp949_vectors, 0xac00, 0xac02,
     "A\xb0\xa1\x81\x41", "A\xea\xb0\x80\xea\xb0\x82"},
    {"ja_JP.WINDOWS-31J", "WINDOWS-31J", 2, 0xff, cp932_vectors,
     sizeof cp932_vectors / sizeof *cp932_vectors, 0x3042, 0x8a9e,
     "A\x82\xa0\x8c\xea", "A\xe3\x81\x82\xe8\xaa\x9e"},
};

/* GNU headers contain constant-argument inlines for these two APIs. Force
 * actual calls to the provider whose address the fixture verifies below. */
static wint_t (*volatile codec_btowc)(int) = btowc;
static int (*volatile codec_wctob)(wint_t) = wctob;

static void codec_provider(const char *expected) {
    struct stat wanted, actual;
    CHECK(stat(expected, &wanted) == 0);
    static const struct { const char *name; const void *address; } functions[] = {
        {"newlocale", (const void *)newlocale}, {"setlocale", (const void *)setlocale},
        {"uselocale", (const void *)uselocale}, {"freelocale", (const void *)freelocale},
        {"nl_langinfo_l", (const void *)nl_langinfo_l},
        {"__ctype_get_mb_cur_max", (const void *)__ctype_get_mb_cur_max},
        {"mbrtowc", (const void *)mbrtowc}, {"mbrlen", (const void *)mbrlen},
        {"mblen", (const void *)mblen}, {"mbtowc", (const void *)mbtowc},
        {"wcrtomb", (const void *)wcrtomb}, {"mbsinit", (const void *)mbsinit},
        {"mbrtoc16", (const void *)mbrtoc16}, {"c16rtomb", (const void *)c16rtomb},
        {"mbsrtowcs", (const void *)mbsrtowcs}, {"mbsnrtowcs", (const void *)mbsnrtowcs},
        {"wcsrtombs", (const void *)wcsrtombs}, {"wcsnrtombs", (const void *)wcsnrtombs},
        {"mbstowcs", (const void *)mbstowcs}, {"wcstombs", (const void *)wcstombs},
        {"btowc", (const void *)btowc}, {"wctob", (const void *)wctob},
        {"tmpfile", (const void *)tmpfile}, {"fwide", (const void *)fwide},
        {"fgetwc", (const void *)fgetwc}, {"fputwc", (const void *)fputwc},
        {"fwprintf", (const void *)fwprintf}, {"fflush", (const void *)fflush},
        {"fileno", (const void *)fileno}, {"fseek", (const void *)fseek},
        {"feof", (const void *)feof}, {"fclose", (const void *)fclose},
    };
    for (size_t i = 0; i < sizeof functions / sizeof *functions; ++i) {
        Dl_info info = {0};
        if (!dladdr(functions[i].address, &info) || !info.dli_fname ||
            stat(info.dli_fname, &actual) != 0 || wanted.st_dev != actual.st_dev ||
            wanted.st_ino != actual.st_ino) {
            fprintf(stderr, "locale-codec:provider-mismatch:%s\n", functions[i].name);
            exit(86);
        }
    }
}

static void codec_scalars(const struct codec_case *test) {
    for (size_t i = 0; i < test->count; ++i) {
        const struct codec_vector *v = &test->vectors[i];
        mbstate_t state = {0};
        wchar_t value = 0xdddd;
        errno = 717;
        CHECK(mbrtowc(&value, v->bytes, v->length, &state) == v->length);
        CHECK(value == v->value && mbsinit(&state) && errno == 717);
        CHECK(mbrlen(v->bytes, v->length, &state) == v->length);
        char encoded[16] = {0};
        CHECK(wcrtomb(encoded, value, &state) == v->length);
        CHECK(!memcmp(encoded, v->bytes, v->length) && mbsinit(&state));
        CHECK(codec_wctob(value) == (v->length == 1 ? (unsigned char)v->bytes[0] : EOF));
        unsigned char byte = (unsigned char)v->bytes[0];
        /* The GNU btowc ABI preserves ASCII identity even for SHIFT_JIS's
         * yen/overline bytes; mbrtowc above uses their codeset mappings. */
        wint_t expected_byte = byte < 0x80 ? (wint_t)byte :
            v->length == 1 ? (wint_t)v->value : WEOF;
        if (!strcmp(test->codeset, "GBK") && byte >= 0x80)
            expected_byte = WEOF;
        CHECK(codec_btowc(byte) == expected_byte);
        for (size_t split = 1; split < v->length; ++split) {
            memset(&state, 0, sizeof state);
            value = 0xdddd;
            CHECK(mbrtowc(&value, v->bytes, split, &state) == (size_t)-2);
            CHECK(value == 0xdddd && !mbsinit(&state));
            CHECK(mbrtowc(&value, v->bytes + split, v->length - split, &state) ==
                  v->length - split);
            CHECK(value == v->value && mbsinit(&state));
        }
        /* Resume repeatedly, including the third and fourth input calls.
         * This exercises accumulation beyond a single saved lead byte. */
        memset(&state, 0, sizeof state);
        value = 0xdddd;
        for (size_t byte_index = 0; byte_index < v->length; ++byte_index) {
            size_t converted = mbrtowc(&value, v->bytes + byte_index, 1, &state);
            if (byte_index + 1 == v->length) {
                CHECK(converted == 1 && value == v->value && mbsinit(&state));
            } else {
                CHECK(converted == (size_t)-2 && value == 0xdddd && !mbsinit(&state));
            }
        }
    }
    mbstate_t state = {0};
    wchar_t value = 0xdddd;
    CHECK(mbrtowc(&value, "", 0, &state) == (size_t)-2 && mbsinit(&state));
    CHECK(mbrtowc(&value, "", 1, &state) == 0 && value == 0 && mbsinit(&state));
    CHECK(mbrtowc(NULL, NULL, 0, &state) == 0);
    CHECK(codec_btowc(EOF) == WEOF && codec_wctob(WEOF) == EOF);
    errno = 717;
    char invalid_byte = (char)test->invalid_byte;
    CHECK(mbrtowc(&value, &invalid_byte, 1, &state) == (size_t)-1 && errno == EILSEQ);
    memset(&state, 0, sizeof state);
    char encoded[16];
    errno = 717;
    CHECK(wcrtomb(encoded, 0x110000, &state) == (size_t)-1 && errno == EILSEQ);
    memset(&state, 0, sizeof state);
    const char invalid_pair[] = {test->text[1], 0};
    const char *invalid = test->width == 2 ? invalid_pair :
                          test->width == 3 ? "\x8f\x00" : "\x81\x30\x00\x30";
    size_t length = test->width == 4 ? 4 : 2;
    errno = 717;
    CHECK(mbrtowc(&value, invalid, length, &state) == (size_t)-1 && errno == EILSEQ);
    if (test->width == 4) {
        memset(&state, 0, sizeof state);
        errno = 717;
        CHECK(mbrtowc(&value, invalid, 3, &state) == (size_t)-2 && errno == 717);
        CHECK(!mbsinit(&state));
        CHECK(mbrtowc(&value, invalid + 3, 1, &state) == (size_t)-1 && errno == EILSEQ);
        memset(&state, 0, sizeof state);
        char16_t unit = 0;
        CHECK(mbrtoc16(&unit, "\x94\x39\xfc", 3, &state) == (size_t)-2);
        CHECK(mbrtoc16(&unit, "\x36", 1, &state) == 1 && unit == 0xd83d);
        CHECK(!mbsinit(&state));
        CHECK(mbrtoc16(&unit, "", 0, &state) == (size_t)-3 && unit == 0xde00);
        CHECK(mbsinit(&state));
        CHECK(c16rtomb(encoded, 0xd83d, &state) == 0 && !mbsinit(&state));
        CHECK(c16rtomb(encoded, 0xde00, &state) == 4 && mbsinit(&state));
        CHECK(!memcmp(encoded, "\x94\x39\xfc\x36", 4));
    }
}

static void codec_guard_pages(const struct codec_case *test) {
    long page_size = sysconf(_SC_PAGESIZE);
    CHECK(page_size > 0);
    size_t page = (size_t)page_size;
    char *mapping = mmap(NULL, 2 * page, PROT_READ | PROT_WRITE,
                         MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    CHECK(mapping != MAP_FAILED);
    CHECK(mprotect(mapping + page, page, PROT_NONE) == 0);

    for (size_t i = 0; i < test->count; ++i) {
        const struct codec_vector *v = &test->vectors[i];
        char *input = mapping + page - v->length;
        memcpy(input, v->bytes, v->length);
        mbstate_t state = {0};
        wchar_t value = 0xdddd;
        errno = 717;
        CHECK(mbrtowc(&value, input, (size_t)-1, &state) == v->length);
        CHECK(value == v->value && mbsinit(&state) && errno == 717);
        CHECK(mbrlen(input, (size_t)-1, &state) == v->length);
        CHECK(mblen(input, (size_t)-1) == (int)v->length);
        CHECK(mbtowc(NULL, NULL, 0) == 0);
        value = 0xdddd;
        CHECK(mbtowc(&value, input, (size_t)-1) == (int)v->length);
        CHECK(value == v->value);

        for (size_t split = 1; split < v->length; ++split) {
            memset(&state, 0, sizeof state);
            value = 0xdddd;
            input = mapping + page - split;
            memcpy(input, v->bytes, split);
            CHECK(mbrtowc(&value, input, split, &state) == (size_t)-2);
            CHECK(value == 0xdddd && !mbsinit(&state));
            size_t remaining = v->length - split;
            input = mapping + page - remaining;
            memcpy(input, v->bytes + split, remaining);
            CHECK(mbrtowc(&value, input, remaining, &state) == remaining);
            CHECK(value == v->value && mbsinit(&state));
        }
    }

    mbstate_t state = {0};
    wchar_t value = 0xdddd;
    CHECK(mbrtowc(&value, mapping + page, 0, &state) == (size_t)-2);
    CHECK(value == 0xdddd && mbsinit(&state));
    mapping[page - 1] = 0;
    CHECK(mbrtowc(&value, mapping + page - 1, (size_t)-1, &state) == 0);
    CHECK(value == 0 && mbsinit(&state));
    mapping[page - 1] = (char)test->invalid_byte;
    value = 0xdddd;
    errno = 717;
    CHECK(mbrtowc(&value, mapping + page - 1, (size_t)-1, &state) == (size_t)-1);
    CHECK(value == 0xdddd && errno == EILSEQ);

    /* These prefixes become invalid at byte two; no decoder may inspect the
     * inaccessible byte three even though the caller's bound is SIZE_MAX. */
    const char invalid_pair[] = {test->text[1], 0};
    const char *invalid = test->width == 2 ? invalid_pair :
                          test->width == 3 ? "\x8f\x00" : "\x81\x20";
    memcpy(mapping + page - 2, invalid, 2);
    memset(&state, 0, sizeof state);
    value = 0xdddd;
    errno = 717;
    CHECK(mbrtowc(&value, mapping + page - 2, (size_t)-1, &state) == (size_t)-1);
    CHECK(value == 0xdddd && errno == EILSEQ);
    memset(&state, 0, sizeof state);
    CHECK(mbrtowc(&value, invalid, 1, &state) == (size_t)-2);
    errno = 717;
    CHECK(mbrtowc(&value, mapping + page - 1, 1, &state) == (size_t)-1);
    CHECK(value == 0xdddd && errno == EILSEQ);
    CHECK(munmap(mapping, 2 * page) == 0);
}

static void codec_bulk(const struct codec_case *test) {
    wchar_t wide[] = {L'A', test->middle, test->last, 0};
    wchar_t decoded[8] = {0};
    const size_t bytes = strlen(test->text);
    mbstate_t state = {0};
    const char *source = test->text;
    CHECK(mbsrtowcs(NULL, &source, 0, &state) == 3 && source == test->text);
    CHECK(mbsrtowcs(decoded, &source, 2, &state) == 2 && source == test->text + 3);
    CHECK(mbsrtowcs(decoded + 2, &source, 6, &state) == 1 && !source);
    CHECK(!memcmp(decoded, wide, sizeof wide) && mbsinit(&state));
    source = test->text + 1;
    memset(&state, 0, sizeof state);
    CHECK(mbsnrtowcs(decoded, &source, 1, 8, &state) == 0);
    CHECK(source == test->text + 2 && !mbsinit(&state));
    CHECK(mbsnrtowcs(decoded, &source, bytes - 1, 8, &state) == 2 && !source);
    CHECK(decoded[0] == wide[1] && decoded[1] == wide[2] && decoded[2] == 0);
    CHECK(mbstowcs(decoded, test->text, 8) == 3 && !memcmp(decoded, wide, sizeof wide));

    char encoded[64];
    memset(encoded, 0x5a, sizeof encoded);
    const wchar_t *wsource = wide;
    memset(&state, 0, sizeof state);
    CHECK(wcsrtombs(NULL, &wsource, 0, &state) == bytes && wsource == wide);
    CHECK(wcsrtombs(encoded, &wsource, 2, &state) == 1 && wsource == wide + 1);
    /* GNU SHIFT_JIS may touch an uncommitted lead byte inside the capacity;
     * only the returned prefix and source position describe converted data. */
    CHECK(encoded[0] == 'A' && encoded[2] == 0x5a && mbsinit(&state));
    CHECK(wcsrtombs(encoded + 1, &wsource, sizeof encoded - 1, &state) == bytes - 1);
    CHECK(!wsource && !memcmp(encoded, test->text, bytes + 1));
    wsource = wide;
    memset(&state, 0, sizeof state);
    CHECK(wcsnrtombs(encoded, &wsource, 2, sizeof encoded, &state) == 3);
    CHECK(wsource == wide + 2 && mbsinit(&state));
    CHECK(wcsnrtombs(encoded + 3, &wsource, 2, sizeof encoded - 3, &state) == bytes - 3);
    CHECK(!wsource && !memcmp(encoded, test->text, bytes + 1));
    CHECK(wcstombs(encoded, wide, sizeof encoded) == bytes);
    CHECK(!memcmp(encoded, test->text, bytes + 1));
}

static void codec_streams(const struct codec_case *test, locale_t selected) {
    wchar_t wide[] = {L'A', test->middle, test->last, 0};
    size_t bytes = strlen(test->text);
    locale_t utf8 = newlocale(LC_CTYPE_MASK, "C.UTF-8", (locale_t)0);
    CHECK(utf8);
    FILE *stream = tmpfile();
    CHECK(stream && fwide(stream, 1) > 0);
    CHECK(uselocale(utf8) == selected);
    /* Input %s follows the current locale; stream output retains the codec
     * selected at orientation even after the calling thread changes locale. */
    CHECK(fwprintf(stream, L"%s|%ls", test->utf8, wide) == 7);
    CHECK(fflush(stream) == 0);
    char actual[64];
    CHECK(pread(fileno(stream), actual, sizeof actual, 0) == (ssize_t)(2 * bytes + 1));
    CHECK(!memcmp(actual, test->text, bytes) && actual[bytes] == '|');
    CHECK(!memcmp(actual + bytes + 1, test->text, bytes));
    CHECK(fseek(stream, 0, SEEK_SET) == 0);
    for (int i = 0; i < 3; ++i) CHECK(fgetwc(stream) == (wint_t)wide[i]);
    CHECK(fgetwc(stream) == L'|');
    for (int i = 0; i < 3; ++i) CHECK(fgetwc(stream) == (wint_t)wide[i]);
    CHECK(fgetwc(stream) == WEOF && feof(stream));
    CHECK(fclose(stream) == 0);
    CHECK(uselocale(selected) == utf8);
    stream = tmpfile();
    CHECK(stream && fwide(stream, 1) > 0);
    CHECK(uselocale(utf8) == selected);
    for (int i = 0; i < 3; ++i) CHECK(fputwc(wide[i], stream) == (wint_t)wide[i]);
    CHECK(fflush(stream) == 0);
    CHECK(pread(fileno(stream), actual, sizeof actual, 0) == (ssize_t)bytes);
    CHECK(!memcmp(actual, test->text, bytes));
    CHECK(fclose(stream) == 0);
    CHECK(uselocale(selected) == utf8);
    stream = tmpfile();
    CHECK(stream && fwide(stream, 1) > 0);
    CHECK(uselocale(utf8) == selected);
    char long_utf8[1040], long_encoded[1040];
    memset(long_utf8, 'A', 1023);
    strcpy(long_utf8 + 1023, test->utf8 + 4);
    /* Put one complete 2/3/4-byte output character across the formatter's
     * 1024-byte staging boundary, with UTF-8 input and a named output codec. */
    CHECK(fwprintf(stream, L"%s", long_utf8) == 1024);
    CHECK(fflush(stream) == 0);
    CHECK(pread(fileno(stream), long_encoded, sizeof long_encoded, 0) ==
          (ssize_t)(1023 + bytes - 3));
    for (int i = 0; i < 1023; ++i) CHECK(long_encoded[i] == 'A');
    CHECK(!memcmp(long_encoded + 1023, test->text + 3, bytes - 3));
    CHECK(fclose(stream) == 0);
    CHECK(uselocale(selected) == utf8);
    CHECK(uselocale(utf8) == selected);
    stream = tmpfile();
    CHECK(stream && fwide(stream, 1) > 0);
    CHECK(uselocale(selected) == utf8);
    /* Reverse the two codec roles as well: named multibyte %s input must be
     * decoded before an already UTF-8-oriented stream encodes the result. */
    CHECK(fwprintf(stream, L"%s", test->text) == 3);
    CHECK(fflush(stream) == 0);
    size_t utf8_bytes = strlen(test->utf8);
    CHECK(pread(fileno(stream), actual, sizeof actual, 0) == (ssize_t)utf8_bytes);
    CHECK(!memcmp(actual, test->utf8, utf8_bytes));
    CHECK(fclose(stream) == 0);
    freelocale(utf8);
}

static void multibyte(unsigned index, const char *provider) {
    codec_provider(provider);
    const struct codec_case *test = &codec_cases[index];
    CHECK(setlocale(LC_ALL, "C"));
    CHECK(setlocale(LC_CTYPE, test->name));
    CHECK(MB_CUR_MAX == test->width);
    CHECK(setlocale(LC_CTYPE, "C"));
    locale_t selected = newlocale(LC_CTYPE_MASK, test->name, (locale_t)0);
    CHECK(selected);
    codeset(selected, test->codeset);
    CHECK(uselocale(selected) == LC_GLOBAL_LOCALE);
    CHECK(MB_CUR_MAX == test->width && !strcmp(setlocale(LC_CTYPE, NULL), "C"));
    codec_scalars(test);
    if (!strcmp(test->codeset, "GBK")) {
        /* GNU's GBK btowc accepts only ASCII. The ordinary decoder and
         * reverse encoder both handle the Euro extension at byte 0x80. */
        for (int byte = 0; byte <= 0xff; ++byte)
            CHECK(codec_btowc(byte) == (byte < 0x80 ? (wint_t)byte : WEOF));
        mbstate_t state = {0};
        wchar_t euro = 0;
        CHECK(mbrtowc(&euro, "\x80", 1, &state) == 1);
        CHECK(euro == 0x20ac && mbsinit(&state));
        CHECK(codec_wctob(euro) == 0x80);
    }
    codec_guard_pages(test);
    codec_bulk(test);
    codec_streams(test, selected);
    CHECK(uselocale(LC_GLOBAL_LOCALE) == selected);
    CHECK(MB_CUR_MAX == 1);
    freelocale(selected);
    printf("multibyte-%s: ok\n", test->codeset);
}

/* The global locale stays C while the thread selects each named decoder.
 * Let GNU supply the return codes for malformed input and extended groups. */
static void named_fnmatch(const char *provider) {
    static const struct { const char *name; const void *address; } functions[] = {
        {"fnmatch", (const void *)fnmatch}, {"newlocale", (const void *)newlocale},
        {"setlocale", (const void *)setlocale}, {"uselocale", (const void *)uselocale},
        {"freelocale", (const void *)freelocale}, {"nl_langinfo_l", (const void *)nl_langinfo_l},
    };
    for (size_t i = 0; i < sizeof functions / sizeof *functions; ++i)
        locale_symbol("locale-fnmatch", provider, functions[i].name, functions[i].address);
    CHECK(setlocale(LC_ALL, "C"));
    for (size_t i = 0; i < 2; ++i) {
        const struct codec_case *test = &codec_cases[i];
        /* The final scalar in the fixed fixture is 2 bytes in SHIFT_JIS and
         * 3 bytes in EUC-JP. No host conversion builds either operand. */
        const char *unit = test->text + 3;
        size_t width = strlen(unit);
        CHECK(width >= 2 && width <= 3);
        CHECK(fnmatch("?", unit, 0) == FNM_NOMATCH);
        locale_t selected = newlocale(LC_CTYPE_MASK, test->name, (locale_t)0);
        CHECK(selected);
        codeset(selected, test->codeset);
        CHECK(uselocale(selected) == LC_GLOBAL_LOCALE);
        CHECK(fnmatch("?", unit, 0) == 0);
        CHECK(fnmatch("????", unit, 0) == FNM_NOMATCH);
        char bracket[16], nested[32], suffix[16], malformed[16], partial[4];
        CHECK((size_t)snprintf(bracket, sizeof bracket, "[%s]", unit) < sizeof bracket);
        CHECK((size_t)snprintf(nested, sizeof nested, "@(@(%s|x)|z)?", unit) < sizeof nested);
        CHECK((size_t)snprintf(suffix, sizeof suffix, "%s!", unit) < sizeof suffix);
        memcpy(malformed, unit, width);
        malformed[width] = (char)test->invalid_byte;
        malformed[width + 1] = '\0';
        memcpy(partial, unit, width - 1);
        partial[width - 1] = '\0';
        const struct { const char *tag, *pattern, *text; int flags; } cases[] = {
            {"two-wildcards", "??", unit, 0},
            {"three-wildcards", "???", unit, 0},
            {"literal", unit, unit, 0},
            {"bracket", bracket, unit, 0},
            {"nested", nested, suffix, FNM_EXTMATCH},
            {"nested-miss", nested, unit, FNM_EXTMATCH},
            {"partial-name", "?", partial, 0},
            {"partial-pattern", partial, partial, 0},
            {"invalid-name", "??", malformed, 0},
            {"invalid-pattern", malformed, unit, 0},
            {"invalid-both", malformed, malformed, 0},
        };
        for (size_t j = 0; j < sizeof cases / sizeof *cases; ++j) {
            printf("fnmatch-%s:%s:%d\n", test->codeset, cases[j].tag,
                   fnmatch(cases[j].pattern, cases[j].text, cases[j].flags));
        }
        CHECK(uselocale(LC_GLOBAL_LOCALE) == selected);
        freelocale(selected);
        CHECK(fnmatch("?", unit, 0) == FNM_NOMATCH);
        printf("fnmatch-%s: ok\n", test->codeset);
    }
}

int main(int argc, char **argv) {
    CHECK(argc == 2 || argc == 3);
    if (!strcmp(argv[1], "lifecycle")) lifecycle();
    else if (!strcmp(argv[1], "composition")) composition();
    else if (!strcmp(argv[1], "threads")) threads();
    else if (!strcmp(argv[1], "named")) named();
    else if (!strcmp(argv[1], "wide")) { CHECK(argc == 3); wide(argv[2]); }
    else if (!strcmp(argv[1], "wide-threads")) { CHECK(argc == 3); wide_threads(argv[2]); }
    else if (!strcmp(argv[1], "named-fnmatch")) { CHECK(argc == 3); named_fnmatch(argv[2]); }
    else if (!strcmp(argv[1], "multibyte-sjis")) { CHECK(argc == 3); multibyte(0, argv[2]); }
    else if (!strcmp(argv[1], "multibyte-eucjp")) { CHECK(argc == 3); multibyte(1, argv[2]); }
    else if (!strcmp(argv[1], "multibyte-gb18030")) { CHECK(argc == 3); multibyte(2, argv[2]); }
    else if (!strcmp(argv[1], "multibyte-big5")) { CHECK(argc == 3); multibyte(3, argv[2]); }
    else if (!strcmp(argv[1], "multibyte-gbk")) { CHECK(argc == 3); multibyte(4, argv[2]); }
    else if (!strcmp(argv[1], "multibyte-gb2312")) { CHECK(argc == 3); multibyte(5, argv[2]); }
    else if (!strcmp(argv[1], "multibyte-euckr")) { CHECK(argc == 3); multibyte(6, argv[2]); }
    else if (!strcmp(argv[1], "multibyte-cp949")) { CHECK(argc == 3); multibyte(7, argv[2]); }
    else if (!strcmp(argv[1], "multibyte-cp932")) { CHECK(argc == 3); multibyte(8, argv[2]); }
    else if (!strcmp(argv[1], "provider")) {
        Dl_info info = {0};
        CHECK(dladdr((const void *)mbrtowc, &info) && info.dli_fname);
        puts(info.dli_fname);
    }
    else return 2;
    return 0;
}
