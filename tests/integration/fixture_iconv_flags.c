/* fixture_iconv_flags.c — iconv //TRANSLIT and //IGNORE semantics
 * (bd-rc0923-epic-eeuy4f.22). Unconvertible characters, invalid and
 * truncated input, a small output buffer, suffix spellings and suffixes on
 * fromcode, against ASCII / ISO-8859-1 / UTF-8 targets; plus Unicode tag
 * characters, which glibc drops when the target cannot encode them. The
 * preload smoke corpus requires byte parity with host glibc.
 */
#include <iconv.h>
#include <stdio.h>
#include <string.h>
#include <errno.h>
static void run(const char *to, const char *from, const char *in, size_t inlen, size_t outcap) {
    iconv_t cd = iconv_open(to, from);
    if (cd == (iconv_t)-1) { printf("%-26s <- %-14s open fails errno=%d\n", to, from, errno); return; }
    char out[128]; char *ip = (char *)in, *op = out; size_t il = inlen, ol = outcap;
    errno = 0;
    size_t r = iconv(cd, &ip, &il, &op, &ol);
    int e = errno;
    printf("%-26s <- %-14s cap=%zu r=%zd errno=%d out=[", to, from, outcap, r, r == (size_t)-1 ? e : 0);
    for (char *p = out; p < op; p++) printf((unsigned char)*p < 0x80 && *p >= 0x20 ? "%c" : "\\x%02x", (unsigned char)*p);
    printf("] consumed=%zu\n", inlen - il);
    iconv_close(cd);
}
static void tags(void) {
    const char *tos[] = {"ASCII", "ISO-8859-1", "UTF-16LE", "UTF-8"};
    for (int i = 0; i < 4; i++) {
        iconv_t cd = iconv_open(tos[i], "UTF-8");
        char in[] = "a\xf3\xa0\x81\x81" "b", out[32], *ip = in, *op = out;
        size_t il = 6, ol = 32;
        size_t r = iconv(cd, &ip, &il, &op, &ol);
        printf("tag %s r=%zd errno=%d written=%zu left=%zu\n", tos[i], r,
               r == (size_t)-1 ? errno : 0, (size_t)(op - out), il);
        iconv_close(cd);
    }
}

int main(void) {
    tags();
    const char *tos[] = {"ASCII", "ASCII//TRANSLIT", "ASCII//IGNORE", "ASCII//TRANSLIT//IGNORE", "ASCII//TRANSLIT,IGNORE", "ascii//translit", "ISO-8859-1//TRANSLIT", "ISO-8859-1//IGNORE", "UTF-8//IGNORE", "ASCII//BOGUS"};
    const char unconv[] = "a\xe2\x82\xac" "b\xc3\xa9" "c";      /* euro, e-acute */
    const char invalid[] = "a\xff" "b\xc3" "c";                  /* bad byte, bad continuation */
    const char trunc[] = "ab\xc3";                               /* truncated at end */
    for (int i = 0; i < 10; i++) {
        run(tos[i], "UTF-8", unconv, sizeof unconv - 1, 64);
        run(tos[i], "UTF-8", invalid, sizeof invalid - 1, 64);
        run(tos[i], "UTF-8", trunc, sizeof trunc - 1, 64);
        run(tos[i], "UTF-8", unconv, sizeof unconv - 1, 3);
    }
    run("ASCII", "UTF-8//IGNORE", unconv, sizeof unconv - 1, 64);
    run("ASCII", "UTF-8//TRANSLIT", unconv, sizeof unconv - 1, 64);
    run("UTF-8", "ASCII//IGNORE", "a\x80" "b", 3, 64);
    run("UTF-8//IGNORE", "ASCII", "a\x80" "b", 3, 64);
    run("UTF-8", "ISO-8859-1//", "a\xe9", 2, 64);
    return 0;
}
