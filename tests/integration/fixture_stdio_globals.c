/* fixture_stdio_globals.c — exported stdin/stdout/stderr sanity under LD_PRELOAD
 * Exit 0 = PASS, nonzero = FAIL with diagnostic to stderr.
 */
#include <stdio.h>
#include <string.h>

extern FILE *_IO_2_1_stdin_;
extern FILE *_IO_2_1_stdout_;
extern FILE *_IO_2_1_stderr_;

int main(void) {
    char user_buf[128];

    if (stdin == NULL || stdout == NULL || stderr == NULL) {
        fprintf(stderr, "FAIL: standard stream globals must be non-null\n");
        return 1;
    }
    if (_IO_2_1_stdin_ == NULL || _IO_2_1_stdout_ == NULL || _IO_2_1_stderr_ == NULL) {
        fprintf(stderr, "FAIL: _IO_2_1_* aliases must be non-null\n");
        return 1;
    }
    if (stdin != _IO_2_1_stdin_ || stdout != _IO_2_1_stdout_ || stderr != _IO_2_1_stderr_) {
        fprintf(stderr, "FAIL: stdio globals must match _IO_2_1_* aliases\n");
        return 1;
    }

    if (setvbuf(_IO_2_1_stdout_, user_buf, _IOFBF, sizeof(user_buf)) != 0) {
        fprintf(stderr, "FAIL: setvbuf(_IO_2_1_stdout_,_IOFBF,user_buf) failed\n");
        return 1;
    }
    if (fprintf(stdout, "stdout-buffered\n") < 0) {
        fprintf(stderr, "FAIL: fprintf(stdout,...) failed in full-buffered mode\n");
        return 1;
    }
    if (fflush(_IO_2_1_stdout_) != 0) {
        fprintf(stderr, "FAIL: fflush(_IO_2_1_stdout_) failed after full buffering\n");
        return 1;
    }

    if (fprintf(_IO_2_1_stderr_, "stderr-immediate\n") < 0) {
        return 1;
    }

    if (fprintf(stderr, "fixture_stdio_globals: PASS\n") < 0) {
        return 1;
    }
    return 0;
}
