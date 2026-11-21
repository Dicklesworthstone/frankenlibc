#define _GNU_SOURCE
#include <dlfcn.h>
#include <errno.h>
#include <langinfo.h>
#include <locale.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
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

/* These vectors are independent of the implementation's iconv tables. The
 * runner compiles real localedef data and compares the same caller with GNU
 * and both deployed modes. In particular, SHIFT_JIS is not an ASCII superset. */
struct codec_vector { wchar_t value; const char *bytes; size_t length; };
struct codec_case {
    const char *name;
    const char *codeset;
    size_t width;
    const struct codec_vector *vectors;
    size_t count;
    wchar_t last;
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
static const struct codec_case codec_cases[] = {
    {"ja_JP.SJIS", "SHIFT_JIS", 2, sjis_vectors,
     sizeof sjis_vectors / sizeof *sjis_vectors, 0x4e00,
     "A\x82\xa0\x88\xea", "A\xe3\x81\x82\xe4\xb8\x80"},
    {"ja_JP.EUC-JP", "EUC-JP", 3, eucjp_vectors,
     sizeof eucjp_vectors / sizeof *eucjp_vectors, 0x4e02,
     "A\xa4\xa2\x8f\xb0\xa1", "A\xe3\x81\x82\xe4\xb8\x82"},
    {"zh_CN.GB18030", "GB18030", 4, gb18030_vectors,
     sizeof gb18030_vectors / sizeof *gb18030_vectors, 0x1f600,
     "A\xa4\xa2\x94\x39\xfc\x36", "A\xe3\x81\x82\xf0\x9f\x98\x80"},
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
        CHECK(codec_btowc(byte) ==
              (byte < 0x80 ? (wint_t)byte : v->length == 1 ? (wint_t)v->value : WEOF));
        for (size_t split = 1; split < v->length; ++split) {
            memset(&state, 0, sizeof state);
            value = 0xdddd;
            CHECK(mbrtowc(&value, v->bytes, split, &state) == (size_t)-2);
            CHECK(value == 0xdddd && !mbsinit(&state));
            CHECK(mbrtowc(&value, v->bytes + split, v->length - split, &state) ==
                  v->length - split);
            CHECK(value == v->value && mbsinit(&state));
        }
    }
    mbstate_t state = {0};
    wchar_t value = 0xdddd;
    CHECK(mbrtowc(&value, "", 0, &state) == (size_t)-2 && mbsinit(&state));
    CHECK(mbrtowc(&value, "", 1, &state) == 0 && value == 0 && mbsinit(&state));
    CHECK(mbrtowc(NULL, NULL, 0, &state) == 0);
    CHECK(codec_btowc(EOF) == WEOF && codec_wctob(WEOF) == EOF);
    errno = 717;
    CHECK(mbrtowc(&value, "\xff", 1, &state) == (size_t)-1 && errno == EILSEQ);
    memset(&state, 0, sizeof state);
    char encoded[16];
    errno = 717;
    CHECK(wcrtomb(encoded, 0x110000, &state) == (size_t)-1 && errno == EILSEQ);
    memset(&state, 0, sizeof state);
    const char *invalid = test->width == 2 ? "\x82\x00" :
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

static void codec_bulk(const struct codec_case *test) {
    wchar_t wide[] = {L'A', 0x3042, test->last, 0};
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
    wchar_t wide[] = {L'A', 0x3042, test->last, 0};
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
    codec_bulk(test);
    codec_streams(test, selected);
    CHECK(uselocale(LC_GLOBAL_LOCALE) == selected);
    CHECK(MB_CUR_MAX == 1);
    freelocale(selected);
    printf("multibyte-%s: ok\n", test->codeset);
}

int main(int argc, char **argv) {
    CHECK(argc == 2 || argc == 3);
    if (!strcmp(argv[1], "lifecycle")) lifecycle();
    else if (!strcmp(argv[1], "composition")) composition();
    else if (!strcmp(argv[1], "threads")) threads();
    else if (!strcmp(argv[1], "named")) named();
    else if (!strcmp(argv[1], "multibyte-sjis")) { CHECK(argc == 3); multibyte(0, argv[2]); }
    else if (!strcmp(argv[1], "multibyte-eucjp")) { CHECK(argc == 3); multibyte(1, argv[2]); }
    else if (!strcmp(argv[1], "multibyte-gb18030")) { CHECK(argc == 3); multibyte(2, argv[2]); }
    else if (!strcmp(argv[1], "provider")) {
        Dl_info info = {0};
        CHECK(dladdr((const void *)mbrtowc, &info) && info.dli_fname);
        puts(info.dli_fname);
    }
    else return 2;
    return 0;
}
