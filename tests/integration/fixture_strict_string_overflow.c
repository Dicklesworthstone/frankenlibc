/* Strict mode reports glibc's result for the same memory: a string that
 * overflows its allocation measures its real length. fl's strict strlen and
 * strstr capped their scans at the allocation's tracked size (strcpy of 26
 * bytes into malloc(8) measured 8, strstr missed the tail), a silent repair
 * that belongs to hardened mode, which keeps truncating by design
 * (bd-rc0923-epic-eeuy4f.8). A large neighbour keeps the overflow inside
 * mapped heap. Strict output matches glibc; registered for strict only.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int main(void) {
    char *p = malloc(8);
    char *pad = malloc(4096);
    if (!p || !pad)
        return 1;
    memset(pad, 0, 4096);
    /* volatile source so the compiler cannot see the overflow */
    static const char *volatile src = "abcdefghijklmnopqrstuvwxyz";
    strcpy(p, src);
    printf("strlen=%zu strstr=%s strchr=%s\n", strlen(p), strstr(p, "xyz") ? "found" : "null",
           strchr(p, 'z') ? "found" : "null");
    return 0;
}
