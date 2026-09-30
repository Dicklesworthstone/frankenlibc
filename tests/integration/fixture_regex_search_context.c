#define _GNU_SOURCE
#include <regex.h>
#include <stdio.h>
#include <string.h>

/* re_search / re_match / REG_STARTEND from an offset: the bytes before the
   start are context for ^, \<, \>, \b, exactly as sed's s///g restarts rely
   on (`echo 'aab bcb' | sed 's/\<b/X/g'` must give "aab Xcb"). Output is
   diffed against host glibc by the smoke battery. */
static void rs(const char *pat, int start, int range) {
    struct re_pattern_buffer b;
    memset(&b, 0, sizeof b);
    const char *err = re_compile_pattern(pat, strlen(pat), &b);
    if (err) { printf("compile %s: %s\n", pat, err); return; }
    const char *h = "aab bcb acb ca";
    struct re_registers regs = {0};
    int r = re_search(&b, h, (int)strlen(h), start, range, &regs);
    int m = re_match(&b, h, (int)strlen(h), start, NULL);
    printf("re_search(%s,%d,%d)=%d reg0=[%d,%d] re_match=%d\n", pat, start, range, r,
           r >= 0 ? (int)regs.start[0] : -1, r >= 0 ? (int)regs.end[0] : -1, m);
    regfree(&b);
}

static void se(const char *pat, int cf, const char *s, int so, int eo, int ef) {
    regex_t re;
    if (regcomp(&re, pat, cf)) { printf("regcomp %s failed\n", pat); return; }
    regmatch_t pm[2] = {{so, eo}, {-1, -1}};
    int r = regexec(&re, s, 2, pm, REG_STARTEND | ef);
    printf("startend(%s,[%d,%d),cf=%d,ef=%d)=%d [%d,%d]\n", pat, so, eo, cf, ef, r,
           r ? -1 : (int)pm[0].rm_so, r ? -1 : (int)pm[0].rm_eo);
    regfree(&re);
}

int main(void) {
    re_syntax_options = 0;
    rs("^a", 1, 13);
    rs("\\<b", 1, 13);
    rs("\\<b", 5, 9);
    rs("\\bc", 5, 9);
    rs("b\\>", 3, 11);
    rs("\\<b", 6, -6);
    rs("^a", 13, -13);
    rs("\\(b\\)c", 0, 14);
    se("\\<b", REG_EXTENDED, "ab b", 1, 4, 0);
    se("\\Bb", REG_EXTENDED, "ab b", 1, 4, 0);
    se("^b", REG_EXTENDED | REG_NEWLINE, "a\nb", 2, 3, REG_NOTBOL);
    se("^b", REG_EXTENDED, "a\nb", 2, 3, 0);
    se("a\\>", REG_EXTENDED, "ab a", 0, 4, 0);
    return 0;
}
