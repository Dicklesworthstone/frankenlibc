/* gettext with real .mo catalogs (bd-rc0923-epic-eeuy4f.10).
 *
 * fl's gettext family used to return every msgid untranslated. This writes
 * its own catalogs into a temporary directory -- Polish (three plural forms,
 * a msgctxt entry), Japanese (one form) and an ISO-8859-1 German catalog --
 * and prints dgettext/dngettext/dcgettext results across LANGUAGE chains,
 * plural counts, categories and bind_textdomain_codeset conversions. The
 * output is compared byte-for-byte with glibc's; it never contains the
 * temporary path. Run under LANG=en_US.UTF-8 (a C locale disables
 * translation in both implementations).
 *
 * Pass 1 switches LANGUAGE without telling libintl, so glibc keeps serving
 * translations it cached under the previous LANGUAGE; pass 2 bumps
 * _nl_msg_cat_cntr after each switch, the documented way to apply it.
 */
#include <libintl.h>
#include <locale.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

extern int _nl_msg_cat_cntr;

struct entry {
    const char *id;
    size_t id_len;
    const char *str;
    size_t str_len;
};

#define E(id, str) {id, sizeof(id) - 1, str, sizeof(str) - 1}

static int cmp_entry(const void *a, const void *b) {
    const struct entry *x = a, *y = b;
    size_t n = x->id_len < y->id_len ? x->id_len : y->id_len;
    int c = memcmp(x->id, y->id, n);
    return c ? c : (x->id_len > y->id_len) - (x->id_len < y->id_len);
}

static void put32(FILE *f, uint32_t v) { fwrite(&v, 4, 1, f); }

static void write_mo(const char *root, const char *lang, struct entry *e, size_t n) {
    char path[512];
    snprintf(path, sizeof path, "%s/%s", root, lang);
    mkdir(path, 0700);
    snprintf(path, sizeof path, "%s/%s/LC_MESSAGES", root, lang);
    mkdir(path, 0700);
    snprintf(path, sizeof path, "%s/%s/LC_MESSAGES/fltest.mo", root, lang);
    qsort(e, n, sizeof *e, cmp_entry);
    FILE *f = fopen(path, "wb");
    if (!f) {
        perror("fopen");
        exit(1);
    }
    uint32_t orig = 28, trans = orig + 8 * n, at = trans + 8 * n;
    put32(f, 0x950412de);
    put32(f, 0);
    put32(f, n);
    put32(f, orig);
    put32(f, trans);
    put32(f, 0);
    put32(f, 0);
    for (size_t i = 0; i < n; i++) {
        put32(f, e[i].id_len);
        put32(f, at);
        at += e[i].id_len + 1;
    }
    for (size_t i = 0; i < n; i++) {
        put32(f, e[i].str_len);
        put32(f, at);
        at += e[i].str_len + 1;
    }
    for (size_t i = 0; i < n; i++)
        fwrite(e[i].id, 1, e[i].id_len + 1, f);
    for (size_t i = 0; i < n; i++)
        fwrite(e[i].str, 1, e[i].str_len + 1, f);
    fclose(f);
}

static void show(const char *what, const char *s) {
    printf("%s: ", what);
    if (!s) {
        puts("(null)");
        return;
    }
    for (const unsigned char *p = (const unsigned char *)s; *p; p++) {
        if (*p >= 0x20 && *p < 0x7f)
            putchar(*p);
        else
            printf("\\x%02x", *p);
    }
    putchar('\n');
}

static const char *const msgids[] = {"Hello", "Bye", "Only ja", "menu\004Open", "absent", "", "%d file"};

static void lookups(const char *tag) {
    char what[160];
    for (size_t i = 0; i < sizeof msgids / sizeof *msgids; i++) {
        snprintf(what, sizeof what, "%s dgettext[%zu]", tag, i);
        show(what, dgettext("fltest", msgids[i]));
        snprintf(what, sizeof what, "%s LC_TIME[%zu]", tag, i);
        show(what, dcgettext("fltest", msgids[i], LC_TIME));
    }
    unsigned long counts[] = {0, 1, 2, 3, 4, 5, 11, 12, 14, 21, 22, 25, 101, 102, 111, 112, 122,
                              1000001, 4294967297UL, (unsigned long)-1};
    for (size_t i = 0; i < sizeof counts / sizeof *counts; i++) {
        snprintf(what, sizeof what, "%s n=%lu", tag, counts[i]);
        show(what, dngettext("fltest", "%d file", "%d files", counts[i]));
    }
}

int main(void) {
    if (!setlocale(LC_ALL, "")) {
        puts("setlocale failed");
        return 1;
    }
    char root[] = "/tmp/fl_gettext_XXXXXX";
    if (!mkdtemp(root)) {
        perror("mkdtemp");
        return 1;
    }
    struct entry pl[] = {
        E("", "Content-Type: text/plain; charset=UTF-8\n"
              "Plural-Forms: nplurals=3; plural=(n==1 ? 0 : n%10>=2 && n%10<=4 && "
              "(n%100<10 || n%100>=20) ? 1 : 2);\n"),
        E("Hello", "Cze\xc5\x9b\xc4\x87"),
        E("%d file\0%d files", "%d plik\0%d pliki\0%d plik\xc3\xb3w"),
        E("menu\004Open", "Otw\xc3\xb3rz"),
    };
    struct entry ja[] = {
        E("", "Content-Type: text/plain; charset=UTF-8\nPlural-Forms: nplurals=1; plural=0;\n"),
        E("%d file\0%d files", "%d \xe3\x83\x95\xe3\x82\xa1\xe3\x82\xa4\xe3\x83\xab"),
        E("Only ja", "\xe6\x97\xa5\xe6\x9c\xac\xe8\xaa\x9e"),
    };
    struct entry de[] = {
        E("", "Content-Type: text/plain; charset=ISO-8859-1\n"),
        E("Hello", "Gr\xfc\xdf dich"),
        E("Bye", "Tsch\xfcss \xab" "bald\xbb"),
        E("%d file\0%d files", "%d Datei\0%d Dateien"),
    };
    write_mo(root, "pl", pl, sizeof pl / sizeof *pl);
    write_mo(root, "ja_JP", ja, sizeof ja / sizeof *ja);
    write_mo(root, "de", de, sizeof de / sizeof *de);
    bindtextdomain("fltest", root);

    const char *languages[] = {"", "pl", "pl:ja_JP", "ja_JP.UTF-8:pl", "de", "xx:de", "C:pl", "pl_PL.UTF-8"};
    char tag[96];
    for (int pass = 1; pass <= 2; pass++) {
        for (size_t i = 0; i < sizeof languages / sizeof *languages; i++) {
            setenv("LANGUAGE", languages[i], 1);
            if (pass == 2)
                ++_nl_msg_cat_cntr;
            snprintf(tag, sizeof tag, "pass%d LANGUAGE=%s", pass, languages[i]);
            lookups(tag);
        }
    }
    const char *codesets[][2] = {{"pl", "ISO-8859-2"}, {"de", "UTF-8"}, {"pl", "ASCII"}, {"ja_JP", "ASCII"}};
    for (size_t i = 0; i < sizeof codesets / sizeof *codesets; i++) {
        setenv("LANGUAGE", codesets[i][0], 1);
        bind_textdomain_codeset("fltest", codesets[i][1]);
        snprintf(tag, sizeof tag, "LANGUAGE=%s codeset=%s", codesets[i][0], codesets[i][1]);
        lookups(tag);
    }

    const char *langs[] = {"pl", "ja_JP", "de"};
    char path[512];
    for (size_t i = 0; i < 3; i++) {
        snprintf(path, sizeof path, "%s/%s/LC_MESSAGES/fltest.mo", root, langs[i]);
        unlink(path);
        snprintf(path, sizeof path, "%s/%s/LC_MESSAGES", root, langs[i]);
        rmdir(path);
        snprintf(path, sizeof path, "%s/%s", root, langs[i]);
        rmdir(path);
    }
    rmdir(root);
    return 0;
}
