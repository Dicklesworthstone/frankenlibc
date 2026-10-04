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

    /* Syntax bits: egrep drops an operator with nothing to repeat and keeps a
     * malformed interval as text; awk takes leading operators, `{` and `\1`
     * literally; grep's newline separates alternatives and lets `**` stack;
     * POSIX ERE has backreferences. */
    static const struct {
        const char *pat;
        reg_syntax_t syn;
        const char *name;
    } syn_cases[] = {
        {"*a", RE_SYNTAX_POSIX_EGREP, "egrep"},  {"{1", RE_SYNTAX_POSIX_EGREP, "egrep"},
        {"a{1", RE_SYNTAX_POSIX_EGREP, "egrep"}, {"a{}", RE_SYNTAX_POSIX_EGREP, "egrep"},
        {"zz\na", RE_SYNTAX_POSIX_EGREP, "egrep"}, {"*a", RE_SYNTAX_AWK, "awk"},
        {"a{1", RE_SYNTAX_AWK, "awk"},           {"(a)\\1", RE_SYNTAX_AWK, "awk"},
        {"a**", RE_SYNTAX_GREP, "grep"},         {"a**", RE_SYNTAX_POSIX_BASIC, "pbasic"},
        {"(a)\\1", RE_SYNTAX_POSIX_EXTENDED, "pext"}, {"^*a", RE_SYNTAX_POSIX_EXTENDED, "pext"},
        {"a{x}", RE_SYNTAX_POSIX_EXTENDED, "pext"},
        /* Default syntax 0 (Emacs; coreutils tac -r): unescaped + and ? repeat,
         * \{ is literal. */
        {"a_+", 0, "emacs"}, {"\\._+", 0, "emacs"}, {"a\\+", 0, "emacs"},
        {"a\\{1\\}", 0, "emacs"},
        /* coreutils expr: POSIX BRE without RE_CONTEXT_INVALID_DUP. */
        {"a\\)", RE_SYNTAX_POSIX_BASIC & ~RE_CONTEXT_INVALID_DUP, "expr"},
        {"^\\{1\\}", RE_SYNTAX_POSIX_BASIC & ~RE_CONTEXT_INVALID_DUP, "expr"},
        {"a\\{1a\\}", RE_SYNTAX_POSIX_BASIC & ~RE_CONTEXT_INVALID_DUP, "expr"},
        {"a\\{1,x", RE_SYNTAX_POSIX_BASIC & ~RE_CONTEXT_INVALID_DUP, "expr"},
    };
    const char *subj = "xa{1aa*a1{1}a__x._+.__a+";
    for (unsigned i = 0; i < sizeof syn_cases / sizeof syn_cases[0]; i++) {
        memset(&b, 0, sizeof b);
        re_set_syntax(syn_cases[i].syn);
        err = re_compile_pattern(syn_cases[i].pat, strlen(syn_cases[i].pat), &b);
        printf("%-6s %-6s %s", syn_cases[i].name, syn_cases[i].pat[0] == 'z' ? "zz\\na" : syn_cases[i].pat,
               err ? err : "ok");
        if (!err) {
            printf(" pos=%d", re_search(&b, subj, (int)strlen(subj), 0, (int)strlen(subj), NULL));
            regfree(&b);
        }
        printf("\n");
    }

    free(regs.start);
    free(regs.end);
    return 0;
}
