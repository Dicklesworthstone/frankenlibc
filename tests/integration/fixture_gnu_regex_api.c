/* GNU re_compile_pattern / re_search semantics that sed depends on.
 *
 * sed 4.9's testsuite under fl failed subst-options, regex-errors, nulldata,
 * dc.sed (infinite loop) and misc (factor) on these:
 *  - newline_anchor is read at search time; re_compile_pattern sets it and
 *    sed clears or sets it per regex (s///M);
 *  - compile errors return glibc's specific message ("Invalid back reference");
 *  - without RE_DOT_NOT_NULL, `.` matches NUL;
 *  - REGS_REALLOCATE grows a too-small re_registers array (sed reuses one);
 *  - backreference patterns: earlier repeats are greedy, and an empty \1
 *    satisfies \{9\}.
 * Output matches glibc.
 */
#define _GNU_SOURCE
#include <regex.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static void compile(struct re_pattern_buffer *b, const char *pat, reg_syntax_t syn) {
    memset(b, 0, sizeof *b);
    re_set_syntax(syn);
    const char *err = re_compile_pattern(pat, strlen(pat), b);
    if (err) printf("compile %s: %s\n", pat, err);
}

static void search(struct re_pattern_buffer *b, const char *s, size_t n, struct re_registers *r) {
    int pos = re_search(b, s, (int)n, 0, (int)n, r);
    printf("  pos=%d", pos);
    if (pos >= 0 && r)
        for (size_t i = 0; i < b->re_nsub + 1; i++) printf(" [%d,%d]", (int)r->start[i], (int)r->end[i]);
    printf("\n");
}

int main(void) {
    struct re_pattern_buffer b;
    struct re_registers regs = {0};
    reg_syntax_t basic = RE_SYNTAX_POSIX_BASIC & ~RE_DOT_NOT_NULL;

    compile(&b, "^b", basic);
    printf("newline_anchor after compile=%d\n", b.newline_anchor);
    search(&b, "foo\nbar", 7, NULL);
    b.newline_anchor = 0;
    search(&b, "foo\nbar", 7, NULL);
    regfree(&b);

    compile(&b, "o.b", basic);
    search(&b, "foo\nbar", 7, NULL);
    regfree(&b);
    /* sed s///M: no RE_DOT_NEWLINE, RE_HAT_LISTS_NOT_NEWLINE. */
    compile(&b, "o.b", (basic & ~RE_DOT_NEWLINE) | RE_HAT_LISTS_NOT_NEWLINE);
    search(&b, "foo\nbar", 7, NULL);
    regfree(&b);
    compile(&b, "o[^x]b", (basic & ~RE_DOT_NEWLINE) | RE_HAT_LISTS_NOT_NEWLINE);
    search(&b, "foo\nbar", 7, NULL);
    regfree(&b);
    compile(&b, "o[^x]b", basic);
    search(&b, "foo\nbar", 7, NULL);
    regfree(&b);

    memset(&b, 0, sizeof b);
    re_set_syntax(basic);
    const char *err = re_compile_pattern("\\1", 2, &b);
    printf("backref error: %s\n", err ? err : "(none)");
    err = re_compile_pattern("a\\{1", 4, &b);
    printf("brace error: %s\n", err ? err : "(none)");

    compile(&b, "^.", basic);
    search(&b, "\0x", 2, NULL);
    regfree(&b);
    compile(&b, "^.", RE_SYNTAX_POSIX_BASIC);
    search(&b, "\0x", 2, NULL);
    regfree(&b);

    /* One re_registers reused across regexes with growing group counts. */
    compile(&b, "a", basic);
    b.regs_allocated = REGS_UNALLOCATED;
    search(&b, "xa", 2, &regs);
    regfree(&b);
    compile(&b, "\\(x*\\)\\(a\\)", basic);
    b.regs_allocated = REGS_REALLOCATE;
    search(&b, "xa", 2, &regs);
    regfree(&b);

    compile(&b, "~\\(-*\\)\\1\\(-*\\);0*\\([^;]*[0-9]\\)[^~]*", basic);
    b.regs_allocated = REGS_REALLOCATE;
    search(&b, "~;020.02;0~", 11, &regs);
    regfree(&b);
    compile(&b, "^\\(a*\\)\\1\\{9\\}\\(a\\{0,9\\}\\)\\([0-9]*\\)", basic);
    b.regs_allocated = REGS_REALLOCATE;
    search(&b, "a1;", 3, &regs);
    regfree(&b);

    free(regs.start);
    free(regs.end);
    return 0;
}
