/* wcscoll / wcsxfrm under a named locale (bd-rc0923-epic-eeuy4f.10).
 *
 * fl compared wide strings in code-point order whatever LC_COLLATE said,
 * so under en_US.UTF-8 'à' sorted after 'b' (CPython's locale.strcoll and
 * locale.strxfrm use these). Prints the sign of wcscoll for every pair of a
 * word list, and the order wcsxfrm keys give them. The key values
 * themselves differ from glibc's; their order must not. Run under
 * LANG=en_US.UTF-8; compared byte-for-byte with glibc.
 */
#include <locale.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <wchar.h>

static const wchar_t *words[] = {L"b",     L"a",      L"à", L"A",     L"À", L"z",   L"Zebra",
                                 L"apple", L"Apple",  L"été", L"ete", L"_x", L"-y", L"10",
                                 L"9",     L"straße", L"strasse", L"",  L"co-op", L"coop"};
#define N (sizeof words / sizeof *words)

static wchar_t keys[N][256];

static int by_key(const void *a, const void *b) {
    return wcscmp(keys[*(const int *)a], keys[*(const int *)b]);
}

static int sign(int v) { return (v > 0) - (v < 0); }

int main(void) {
    if (!setlocale(LC_ALL, "")) {
        puts("setlocale failed");
        return 1;
    }
    for (size_t i = 0; i < N; i++) {
        for (size_t j = 0; j < N; j++)
            putchar("-0+"[sign(wcscoll(words[i], words[j])) + 1]);
        putchar('\n');
    }
    int order[N];
    for (size_t i = 0; i < N; i++) {
        size_t len = wcsxfrm(keys[i], words[i], 256);
        if (len >= 256)
            return 1;
        order[i] = (int)i;
    }
    qsort(order, N, sizeof *order, by_key);
    printf("wcsxfrm order:");
    for (size_t i = 0; i < N; i++)
        printf(" %d", order[i]);
    putchar('\n');
    /* Keys must order exactly as wcscoll does. */
    int consistent = 1;
    for (size_t i = 0; i + 1 < N; i++)
        consistent &= wcscoll(words[order[i]], words[order[i + 1]]) <= 0;
    printf("keys agree with wcscoll: %d\n", consistent);
    return 0;
}
