/* fixture_stdio_globals.c — exported stdin/stdout/stderr sanity under LD_PRELOAD
 * Exit 0 = PASS, nonzero = FAIL with diagnostic to stderr.
 */
#include <stdio.h>
#include <string.h>

int main(void) {
    char user_buf[128];

    if (stdin == NULL || stdout == NULL || stderr == NULL) {
        fprintf(stderr, "FAIL: standard stream globals must be non-null\n");
        return 1;
    }

    if (setvbuf(stdout, user_buf, _IOFBF, sizeof(user_buf)) != 0) {
        fprintf(stderr, "FAIL: setvbuf(stdout,_IOFBF,user_buf) failed\n");
        return 1;
    }
    if (fprintf(stdout, "stdout-buffered\n") < 0) {
        fprintf(stderr, "FAIL: fprintf(stdout,...) failed in full-buffered mode\n");
        return 1;
    }
    if (fflush(stdout) != 0) {
        fprintf(stderr, "FAIL: fflush(stdout) failed after full buffering\n");
        return 1;
    }

    if (fprintf(stderr, "stderr-immediate\n") < 0) {
        return 1;
    }

    if (fprintf(stderr, "fixture_stdio_globals: PASS\n") < 0) {
        return 1;
    }
    return 0;
}
