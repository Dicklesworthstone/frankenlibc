// catopen's NLSPATH search: a name without a slash is looked up through the
// NLSPATH templates (%N %L %l %t %c, an empty component meaning %N) and then
// /usr/share/locale/%L[/LC_MESSAGES]/%N and /usr/share/locale/%l[...]/%N,
// with %L from LANG (or LC_MESSAGES for NL_CAT_LOCALE). The first candidate
// that OPENS decides: a directory or malformed file there is EINVAL even if a
// later candidate is valid. A name with a slash is opened as given.
//
// fl once opened every name literally, relative to the working directory, so
// no installed catalog could be found by name.
#define _GNU_SOURCE
#include <errno.h>
#include <nl_types.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

static char root[64];

static void put_le(FILE *f, uint32_t w) { fwrite(&w, 4, 1, f); }
static void put_be(FILE *f, uint32_t w) {
    uint32_t b = __builtin_bswap32(w);
    fwrite(&b, 4, 1, f);
}

// gencat layout with one message, (set 1, message 1) -> text.
static void write_catalog(const char *rel, const char *text) {
    char path[256];
    snprintf(path, sizeof path, "%s/%s", root, rel);
    FILE *f = fopen(path, "wb");
    put_le(f, 0x960408de);
    put_le(f, 1); // plane size
    put_le(f, 1); // plane depth
    put_le(f, 2); put_le(f, 1); put_le(f, 0); // native table: stored set = set + 1
    put_be(f, 2); put_be(f, 1); put_be(f, 0); // foreign-endian table
    fwrite(text, strlen(text) + 1, 1, f);
    fclose(f);
}

static void subdir(const char *rel) {
    char path[256];
    snprintf(path, sizeof path, "%s/%s", root, rel);
    mkdir(path, 0755);
}

static void try_open(const char *label, const char *name, int flag) {
    errno = 0;
    nl_catd c = catopen(name, flag);
    if (c == (nl_catd)-1) {
        printf("%-34s -> fail errno=%s\n", label, strerrorname_np(errno));
        return;
    }
    printf("%-34s -> \"%s\"\n", label, catgets(c, 1, 1, "(default)"));
    printf("%-34s    missing message -> \"%s\"\n", "", catgets(c, 1, 9, "(default)"));
    catclose(c);
}

static void nlspath(const char *tmpl) {
    char buf[512];
    snprintf(buf, sizeof buf, tmpl, root, root);
    setenv("NLSPATH", buf, 1);
}

int main(void) {
    snprintf(root, sizeof root, "/tmp/fl_catopen_%d", (int)getpid());
    mkdir(root, 0755);
    subdir("fr");
    subdir("fr_FR.UTF-8");
    subdir("C");
    subdir("dir");
    subdir("bad");
    write_catalog("fr/app", "bonjour (language)");
    write_catalog("fr_FR.UTF-8/app", "bonjour (whole locale)");
    write_catalog("C/app", "hello (C)");
    write_catalog("plain", "literal path");
    char bad[128];
    snprintf(bad, sizeof bad, "%s/bad/app", root);
    FILE *f = fopen(bad, "w");
    fputs("not a catalog", f);
    fclose(f);
    char empty[128];
    snprintf(empty, sizeof empty, "%s/empty", root);
    fclose(fopen(empty, "w"));

    setenv("LANG", "fr_FR.UTF-8", 1);
    nlspath("%s/%%L/%%N:%s/%%l/%%N");
    try_open("%L before %l", "app", 0);
    nlspath("%s/nowhere/%%N:%s/%%l/%%N");
    try_open("missing then %l", "app", 0);
    nlspath("%s/%%l_%%t.%%c/%%N:%s/%%l/%%N");
    try_open("%l_%t.%c", "app", 0);
    nlspath("%s/bad/%%N:%s/%%l/%%N");
    try_open("malformed first candidate", "app", 0);
    // A malformed catalog does not set errno: the failed open before it shows.
    nlspath("%s/nowhere/%%N:%s/bad/%%N");
    try_open("missing, then malformed", "app", 0);
    nlspath("%s/%%N:%s/%%l/%%N");
    try_open("empty file first", "empty", 0);
    nlspath("%s/%%N:%s/%%l/%%N");
    try_open("directory first candidate", "dir", 0);
    try_open("unknown name", "zz_no_such_catalog", 0);

    // NL_CAT_LOCALE takes %L from LC_MESSAGES (still "C": no setlocale), not LANG.
    nlspath("%s/%%L/%%N:%s/%%L/%%N");
    try_open("NL_CAT_LOCALE uses LC_MESSAGES", "app", NL_CAT_LOCALE);
    try_open("flag 0 uses LANG", "app", 0);

    // Empty LANG counts as C.
    setenv("LANG", "", 1);
    try_open("empty LANG is C", "app", 0);
    unsetenv("LANG");
    try_open("unset LANG is C", "app", 0);

    // An empty NLSPATH component means %N, relative to the working directory.
    if (chdir(root) != 0) return 1;
    setenv("NLSPATH", ":/nonexistent/%N", 1);
    try_open("empty component = %N", "plain", 0);

    // The empty name is searched for too: %N expands to nothing, so the
    // candidates are directories.
    nlspath("%s/%%L/%%N:%s/%%L/%%N");
    setenv("LANG", "fr", 1);
    try_open("empty name, candidate dir exists", "", 0);

    // A slash selects the path itself and ignores NLSPATH.
    char literal[128];
    snprintf(literal, sizeof literal, "%s/plain", root);
    try_open("absolute path", literal, 0);
    try_open("relative path with slash", "./plain", 0);
    try_open("directory path", "./", 0);
    try_open("missing path", "./zz_missing", 0);

    char cmd[128];
    snprintf(cmd, sizeof cmd, "rm -rf %s", root);
    if (chdir("/") != 0) return 1;
    return system(cmd) == 0 ? 0 : 1;
}
