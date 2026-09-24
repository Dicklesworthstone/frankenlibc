/* fixture_strftime_locale.c — strftime under the environment's locale
 * (bd-rc0923-epic-eeuy4f.10). Names, AM/PM, %c/%x/%X/%r (from LC_TIME's
 * D_T_FMT/D_FMT/T_FMT/T_FMT_AMPM), flags and widths on locale strings, and
 * E/O modifiers, at several instants. The smoke corpus runs it under
 * LANG=en_US.UTF-8 and C.UTF-8 and requires byte parity with host glibc.
 */
#include <locale.h>
#include <stdio.h>
#include <time.h>
int main(void) {
    setlocale(LC_ALL, "");
    const char *fmts[] = {"%c", "%x", "%X", "%r", "%p", "%P", "%a %A %b %B %h", "%^a %^B %#p %10A|", "%Ec %Ex %EX %Oy", "%D %T %F %R", "%-10c|", "%^c"};
    time_t ts[] = {1700000000, 1700040000, 0, 951782400};
    for (int t = 0; t < 4; t++) { struct tm tm; gmtime_r(&ts[t], &tm);
      for (int i = 0; i < 12; i++) { char b[256]; size_t n = strftime(b, sizeof b, fmts[i], &tm); printf("[%s] %zu %s\n", fmts[i], n, b); } }
    return 0;
}
