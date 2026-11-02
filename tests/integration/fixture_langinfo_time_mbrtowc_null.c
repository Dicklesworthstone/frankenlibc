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
#include <dlfcn.h>
#include <errno.h>
#include <langinfo.h>
#include <locale.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#include <uchar.h>
#include <wchar.h>

static void *state_symbol(const char *name, const char *provider) {
    void *symbol = dlsym(RTLD_DEFAULT, name);
    Dl_info info;
    struct stat wanted, actual;
    if (!symbol || !dladdr(symbol, &info) || !info.dli_fname ||
        stat(provider, &wanted) || stat(info.dli_fname, &actual) ||
        wanted.st_dev != actual.st_dev || wanted.st_ino != actual.st_ino) {
        fprintf(stderr, "wrong state provider: %s\n", name);
        return NULL;
    }
    return symbol;
}

static int restartable_state(const char *provider, int isolation) {
    typedef size_t (*length_fn)(const char *, size_t, mbstate_t *);
    typedef size_t (*encode_fn)(char *, char16_t, mbstate_t *);
    typedef int *(*errno_fn)(void);
    typedef char *(*locale_fn)(int, const char *);
    /* The pointed-to output types have their declared signatures below. */
    typedef size_t (*wide_fn)(wchar_t *, const char *, size_t, mbstate_t *);
    typedef size_t (*utf32_fn)(char32_t *, const char *, size_t, mbstate_t *);
    typedef size_t (*utf16_fn)(char16_t *, const char *, size_t, mbstate_t *);
    typedef size_t (*bounded_fn)(wchar_t *, const char **, size_t, size_t, mbstate_t *);
    wide_fn wide = (wide_fn)state_symbol("mbrtowc", provider);
    length_fn length = (length_fn)state_symbol("mbrlen", provider);
    utf32_fn utf32 = (utf32_fn)state_symbol("mbrtoc32", provider);
    utf16_fn utf16 = (utf16_fn)state_symbol("mbrtoc16", provider);
    bounded_fn bounded = (bounded_fn)state_symbol("mbsnrtowcs", provider);
    encode_fn encode = (encode_fn)state_symbol("c16rtomb", provider);
    errno_fn error = (errno_fn)state_symbol("__errno_location", provider);
    locale_fn locale = (locale_fn)state_symbol("setlocale", provider);
    if (!wide || !length || !utf32 || !utf16 || !bounded || !encode || !error || !locale)
        return 91;
    if (!locale(LC_ALL, "C.UTF-8")) {
        fprintf(stderr, "C.UTF-8 unavailable\n");
        return 92;
    }
    const char *names[] = {"mbrtowc", "mbrlen", "mbrtoc32", "mbrtoc16"};
    const char *input[] = {"\xc3\xa9", "\xe2\x82\xac", "\xf0\x9f\x99\x82"};
    const size_t sizes[] = {2, 3, 4};
    if (isolation) {
        for (int phase = 0; phase < 2; ++phase) {
            for (int i = 0; i < 4; ++i) {
                int kind = phase ? 3 - i : i;
                int sample = kind < 2 ? kind : 2;
                const char *s = input[sample] + (phase ? 1 : 0);
                size_t n = phase ? sizes[sample] - 1 : 1;
                wchar_t wc = 0x1234;
                char32_t c32 = 0x1234;
                char16_t c16 = 0x1234;
                *error() = E2BIG;
                size_t r = kind == 0 ? wide(&wc, s, n, NULL)
                    : kind == 1 ? length(s, n, NULL)
                    : kind == 2 ? utf32(&c32, s, n, NULL)
                    : utf16(&c16, s, n, NULL);
                int e = *error();
                unsigned unit = kind == 0 ? (unsigned)wc
                    : kind == 2 ? (unsigned)c32 : (unsigned)c16;
                printf("isolation %s phase=%d ret=%zu unit=%x errno=%d\n", names[kind], phase, r, unit, e);
            }
        }
        char16_t low = 0x1234;
        *error() = E2BIG;
        size_t low_r = utf16(&low, "A", 1, NULL);
        int low_e = *error();
        printf("isolation low ret=%zu unit=%x errno=%d\n", low_r, (unsigned)low, low_e);
        for (int explicit_state = 0; explicit_state < 2; ++explicit_state) {
            mbstate_t state = {0};
            mbstate_t *ps = explicit_state ? &state : NULL;
            wchar_t wc = 0x1234;
            *error() = E2BIG;
            size_t a = wide(&wc, "\xc3", 1, NULL);
            const char *prefix = "\xe2";
            const char *s = prefix;
            size_t b = bounded(&wc, &s, 1, 1, ps);
            size_t used_b = (size_t)(s - prefix);
            size_t c = wide(&wc, "\xa9", 1, NULL);
            unsigned unit_c = (unsigned)wc;
            const char *tail = "\x82\xac";
            s = tail;
            size_t d = bounded(&wc, &s, 2, 1, ps);
            int e = *error();
            printf("isolation bounded explicit=%d ret=%zu,%zu,%zu,%zu unit=%x,%x used=%zu,%zu errno=%d\n",
                   explicit_state, a, b, c, d, unit_c, (unsigned)wc, used_b, (size_t)(s - tail), e);
        }
        for (int kind = 0; kind < 4; ++kind) {
            for (int pending = 0; pending < 2; ++pending) {
                mbstate_t state = {0};
                wchar_t wc = 0x1234;
                char32_t c32 = 0x1234;
                char16_t c16 = 0x1234;
                if (pending) {
                    if (kind == 0) wide(&wc, "\xe2", 1, &state);
                    else if (kind == 1) length("\xe2", 1, &state);
                    else if (kind == 2) utf32(&c32, "\xe2", 1, &state);
                    else utf16(&c16, "\xe2", 1, &state);
                }
                *error() = E2BIG;
                size_t r = kind == 0 ? wide(&wc, NULL, 99, &state)
                    : kind == 1 ? length(NULL, 99, &state)
                    : kind == 2 ? utf32(&c32, NULL, 99, &state)
                    : utf16(&c16, NULL, 99, &state);
                int e = *error();
                unsigned unit = kind == 0 ? (unsigned)wc
                    : kind == 2 ? (unsigned)c32 : (unsigned)c16;
                printf("isolation null %s pending=%d ret=%zu unit=%x errno=%d\n", names[kind], pending, r, unit, e);
            }
        }
        for (int pending = 0; pending < 2; ++pending) {
            const char16_t ignored[] = {0, 'A', 0xd800, 0xdc00};
            for (int i = 0; i < 4; ++i) {
                for (int initial = 0; initial < 2; ++initial) {
                    mbstate_t state = {0};
                    char out[8];
                    if (pending) encode(out, 0xd83d, &state);
                    *error() = initial ? E2BIG : 0;
                    size_t r = encode(NULL, ignored[i], &state);
                    int e = *error();
                    printf("isolation encode-null pending=%d c16=%x initial=%d ret=%zu errno=%d\n",
                           pending, (unsigned)ignored[i], initial, r, e);
                }
            }
        }
        return 0;
    }
    for (int kind = 0; kind < 4; ++kind) {
        for (int explicit_state = 0; explicit_state < 2; ++explicit_state) {
            for (int sample = 0; sample < 3; ++sample) {
                for (size_t split = 1; split < sizes[sample]; ++split) {
                    mbstate_t state = {0};
                    mbstate_t *ps = explicit_state ? &state : NULL;
                    for (int part = 0; part < 3; ++part) {
                        const char *s = input[sample] + (part ? split : 0);
                        size_t n = part == 0 ? split : part == 1 ? 0 : sizes[sample] - split;
                        wchar_t wc = 0x1234;
                        char32_t c32 = 0x1234;
                        char16_t c16 = 0x1234;
                        *error() = E2BIG;
                        size_t r = kind == 0 ? wide(&wc, s, n, ps)
                            : kind == 1 ? length(s, n, ps)
                            : kind == 2 ? utf32(&c32, s, n, ps)
                            : utf16(&c16, s, n, ps);
                        int e = *error();
                        unsigned unit = kind == 0 ? (unsigned)wc
                            : kind == 2 ? (unsigned)c32 : (unsigned)c16;
                        printf("state %s explicit=%d sample=%d split=%zu part=%d ret=%zu unit=%x errno=%d\n",
                               names[kind], explicit_state, sample, split, part, r, unit, e);
                    }
                    if (kind == 3 && sample == 2) {
                        char16_t low = 0x1234;
                        *error() = E2BIG;
                        size_t r = utf16(&low, "A", 1, ps);
                        int e = *error();
                        printf("state low explicit=%d split=%zu ret=%zu unit=%x errno=%d\n",
                               explicit_state, split, r, (unsigned)low, e);
                    }
                }
            }
        }
    }
    for (int order = 0; order < 2; ++order) {
        char out[8] = {0};
        char16_t high = 0x1234, low = 0x1234;
        *error() = E2BIG;
        size_t a = order ? utf16(&high, input[2], 4, NULL) : encode(out, 0xd83d, NULL);
        int ea = *error();
        *error() = E2BIG;
        size_t b = order ? encode(out, 0xd83d, NULL) : utf16(&high, input[2], 4, NULL);
        int eb = *error();
        *error() = E2BIG;
        size_t c = encode(out, 0xde00, NULL);
        int ec = *error();
        *error() = E2BIG;
        size_t d = utf16(&low, "A", 1, NULL);
        int ed = *error();
        printf("state interleave=%d ret=%zu,%zu,%zu,%zu unit=%x,%x bytes=%02x%02x%02x%02x errno=%d,%d,%d,%d\n",
               order, a, b, c, d, (unsigned)high, (unsigned)low,
               (unsigned char)out[0], (unsigned char)out[1], (unsigned char)out[2], (unsigned char)out[3],
               ea, eb, ec, ed);
    }
    const char16_t ignored[] = {0, 'A', 0xd800, 0xdc00};
    for (int i = 0; i < 4; ++i) {
        mbstate_t state = {0};
        *error() = E2BIG;
        size_t r = encode(NULL, ignored[i], &state);
        int e = *error();
        printf("state null c16=%x ret=%zu errno=%d\n", (unsigned)ignored[i], r, e);
    }
    return 0;
}

static long source_offset(const char *current, const char *start) {
    return current ? (long)(current - start) : -1;
}

static int string_state(const char *provider) {
    typedef size_t (*wide_fn)(wchar_t *, const char *, size_t, mbstate_t *);
    typedef size_t (*string_fn)(wchar_t *, const char **, size_t, mbstate_t *);
    typedef size_t (*bounded_fn)(wchar_t *, const char **, size_t, size_t, mbstate_t *);
    typedef int (*initial_fn)(const mbstate_t *);
    typedef int *(*errno_fn)(void);
    typedef char *(*locale_fn)(int, const char *);
    wide_fn wide = (wide_fn)state_symbol("mbrtowc", provider);
    string_fn convert = (string_fn)state_symbol("mbsrtowcs", provider);
    bounded_fn bounded = (bounded_fn)state_symbol("mbsnrtowcs", provider);
    initial_fn initial = (initial_fn)state_symbol("mbsinit", provider);
    errno_fn error = (errno_fn)state_symbol("__errno_location", provider);
    locale_fn locale = (locale_fn)state_symbol("setlocale", provider);
    if (!wide || !convert || !bounded || !initial || !error || !locale)
        return 91;
    if (!locale(LC_ALL, "C.UTF-8"))
        return 92;
    const char *input[] = {"AZ", "\xc3\xa9Z", "\xe2\x82\xacZ", "\xf0\x9f\x99\x82Z"};
    const size_t width[] = {1, 2, 3, 4};
    for (int kind = 0; kind < 2; ++kind) {
        for (int sample = 0; sample < 4; ++sample) {
            for (size_t split = 0; split < width[sample]; ++split) {
                const char *start = input[sample] + split;
                size_t remaining = strlen(start) + 1;
                const size_t windows[] = {0, 1, remaining};
                for (int window = 0; window < (kind ? 3 : 1); ++window) {
                    for (int count = 0; count < 2; ++count) {
                        for (size_t capacity = 0; capacity < 4; ++capacity) {
                            for (int saved = 0; saved < 2; ++saved) {
                                mbstate_t state = {0};
                                if (split && wide(NULL, input[sample], split, &state) != (size_t)-2)
                                    return 93;
                                wchar_t out[4] = {0x1234, 0x1234, 0x1234, 0x1234};
                                const char *src = start;
                                *error() = saved ? E2BIG : 0;
                                size_t r = kind ? bounded(count ? NULL : out, &src, windows[window], capacity, &state)
                                    : convert(count ? NULL : out, &src, capacity, &state);
                                int e = *error();
                                int state_initial = !!initial(&state);
                                long offset = source_offset(src, start);
                                /* Sizing must leave the original stream usable. For write
                                 * calls, finish from the actual returned source/state. */
                                if (count) src = start;
                                wchar_t next[4] = {0x1234, 0x1234, 0x1234, 0x1234};
                                size_t again = (size_t)-4;
                                int next_error = saved ? E2BIG : 0;
                                if (src && r != (size_t)-1) {
                                    *error() = saved ? E2BIG : 0;
                                    again = convert(next, &src, 3, &state);
                                    next_error = *error();
                                }
                                printf("string kind=%d sample=%d split=%zu window=%d count=%d cap=%zu saved=%d ret=%zu off=%ld errno=%d initial=%d out=%x,%x,%x,%x again=%zu next_off=%ld next_errno=%d next_initial=%d next=%x,%x,%x,%x\n",
                                       kind, sample, split, window, count, capacity, saved, r, offset, e, state_initial,
                                       (unsigned)out[0], (unsigned)out[1], (unsigned)out[2], (unsigned)out[3],
                                       again, source_offset(src, start), next_error, !!initial(&state),
                                       (unsigned)next[0], (unsigned)next[1], (unsigned)next[2], (unsigned)next[3]);
                            }
                        }
                    }
                }
            }
        }
    }
    return 0;
}

int main(int argc, char **argv) {
    if (argc == 3 && strcmp(argv[1], "--restartable-state") == 0)
        return restartable_state(argv[2], 0);
    if (argc == 3 && strcmp(argv[1], "--state-isolation") == 0)
        return restartable_state(argv[2], 1);
    if (argc == 3 && strcmp(argv[1], "--string-state") == 0)
        return string_state(argv[2]);
    if (argc != 1)
        return 90;
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
