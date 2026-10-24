/* glob() resets the glob_t on every return, so globfree() is always safe.
 *
 * GNU make's parse_file_seq globs into an uninitialized stack glob_t and calls
 * globfree() whatever glob returned. fl left gl_pathv untouched on
 * GLOB_NOMATCH, so globfree freed stack garbage and make aborted with
 * "free(): invalid pointer" (any Makefile using $(wildcard) of a missing
 * file). Output matches glibc.
 */
#include <glob.h>
#include <stdio.h>
#include <string.h>

int main(void) {
    glob_t g;
    memset(&g, 0xA5, sizeof g); /* what an uninitialized stack slot holds */
    int rc = glob("/nonexistent-dir-xyz/*.none", 0, NULL, &g);
    printf("nomatch rc=%d pathc=%zu pathv=%s\n", rc, g.gl_pathc, g.gl_pathv ? "set" : "NULL");
    globfree(&g);

    memset(&g, 0xA5, sizeof g);
    g.gl_offs = 2;
    rc = glob("/nonexistent-dir-xyz/*.none", GLOB_DOOFFS, NULL, &g);
    printf("dooffs nomatch rc=%d pathc=%zu slots=%s,%s,%s\n", rc, g.gl_pathc,
           g.gl_pathv && !g.gl_pathv[0] ? "null" : "?", g.gl_pathv && !g.gl_pathv[1] ? "null" : "?",
           g.gl_pathv && !g.gl_pathv[2] ? "null" : "?");
    globfree(&g);

    memset(&g, 0xA5, sizeof g);
    rc = glob("/etc/host*", 0, NULL, &g);
    printf("match rc=%d any=%d first=%s\n", rc, g.gl_pathc > 0, g.gl_pathc ? g.gl_pathv[0] : "");
    rc = glob("/nonexistent-dir-xyz/*", GLOB_APPEND, NULL, &g);
    printf("append nomatch rc=%d kept=%d\n", rc, g.gl_pathc > 0);
    globfree(&g);
    return 0;
}
