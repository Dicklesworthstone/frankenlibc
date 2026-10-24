/* fixture_stdio_globals.c — exported stdin/stdout/stderr sanity under LD_PRELOAD
 * Exit 0 = PASS, nonzero = FAIL with diagnostic to stderr.
 */
#define _GNU_SOURCE 1
#include <dlfcn.h>
#include <errno.h>
#include <fcntl.h>
#include <link.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

/* These are FILE objects, NOT FILE * variables.  A preload implementation
 * may supply its own FILE storage without interposing these glibc internals. */
extern FILE _IO_2_1_stdin_;
extern FILE _IO_2_1_stdout_;
extern FILE _IO_2_1_stderr_;

static int same_file(const char *left, const char *right) {
    struct stat a, b;
    return stat(left, &a) == 0 && stat(right, &b) == 0 &&
           a.st_dev == b.st_dev && a.st_ino == b.st_ino;
}

static int check_provider(void) {
    const char *expected = getenv("FRANKENLIBC_STDIO_EXPECT_PROVIDER");
    if (expected == NULL || expected[0] == '\0') {
        fprintf(stderr, "FAIL: missing expected stdio provider\n");
        return 1;
    }
    const char *symbols[] = {
        "fileno", "setvbuf", "fprintf", "fflush", "fmemopen", "fclose",
        "printf", "puts", "getchar", "fgetc", "ungetc", "feof", "ferror",
        "clearerr", "stdin", "stdout", "stderr"
    };
    for (size_t i = 0; i < sizeof(symbols) / sizeof(symbols[0]); ++i) {
        void *symbol = dlsym(RTLD_DEFAULT, symbols[i]);
        Dl_info info;
        /* Data symbols can be copy-relocated into this executable. Verify
         * their definitions through the explicitly opened provider below. */
        if (i < 14 && (symbol == NULL || dladdr(symbol, &info) == 0 ||
                       !same_file(info.dli_fname, expected))) {
            fprintf(stderr, "FAIL: wrong stdio provider for %s\n", symbols[i]);
            return 1;
        }
    }
    void *handle = dlopen(expected, RTLD_LAZY | RTLD_NOLOAD);
    if (handle == NULL) {
        fprintf(stderr, "FAIL: expected provider is not loaded\n");
        return 1;
    }
    FILE **visible_cells[] = {&stdin, &stdout, &stderr};
    for (size_t i = 0; i < 3; ++i) {
        FILE **cell = (FILE **)dlsym(handle, symbols[14 + i]);
        Dl_info info;
        const ElfW(Sym) *entry = NULL;
        /* With R_*_COPY, the provider's original cell is superseded by the
         * executable's cell. Its stale initial value is not a contract. */
        if (cell == NULL || dladdr1(cell, &info, (void **)&entry, RTLD_DL_SYMENT) == 0 ||
            entry == NULL || entry->st_size != sizeof(FILE *) ||
            !same_file(info.dli_fname, expected) ||
            dlsym(RTLD_DEFAULT, symbols[14 + i]) != visible_cells[i]) {
            fprintf(stderr, "FAIL: wrong provider/global pointer cell for %s\n",
                    symbols[14 + i]);
            dlclose(handle);
            return 1;
        }
    }
    const char *objects[] = {"_IO_2_1_stdin_", "_IO_2_1_stdout_", "_IO_2_1_stderr_"};
    for (size_t i = 0; i < 3; ++i) {
        void *object = dlsym(handle, objects[i]);
        Dl_info info;
        const ElfW(Sym) *entry = NULL;
        if (object != NULL &&
            (dladdr1(object, &info, (void **)&entry, RTLD_DL_SYMENT) == 0 ||
             entry == NULL || entry->st_size < sizeof(FILE))) {
            fprintf(stderr, "FAIL: %s must be a FILE object, not a pointer cell\n", objects[i]);
            dlclose(handle);
            return 1;
        }
    }
    dlclose(handle);
    return 0;
}

static int check_redirected_globals(void) {
    char input[] = "rd\n";
    char output[128] = {0}, errors[128] = {0};
    FILE *in = fmemopen(input, sizeof(input) - 1, "r");
    FILE *out = fmemopen(output, sizeof(output), "w");
    FILE *err = fmemopen(errors, sizeof(errors), "w");
    if (in == NULL || out == NULL || err == NULL) {
        fprintf(stderr, "FAIL: fmemopen for redirected globals\n");
        if (in != NULL) fclose(in);
        if (out != NULL) fclose(out);
        if (err != NULL) fclose(err);
        return 1;
    }
    FILE *saved_in = stdin, *saved_out = stdout, *saved_err = stderr;
    stdin = in;
    stdout = out;
    stderr = err;
    int failed = printf("redirect:%d\n", 7) != 11;
    failed |= puts("puts") < 0;
    failed |= fprintf(stderr, "redirect-error\n") != 15;
    failed |= getchar() != 'r';
    failed |= ungetc('r', stdin) != 'r';
    failed |= fgetc(stdin) != 'r';
    failed |= getchar() != 'd';
    failed |= getchar() != '\n';
    failed |= getchar() != EOF || !feof(stdin) || ferror(stdin);
    clearerr(stdin);
    failed |= feof(stdin) != 0 || ferror(stdin) != 0;
    failed |= fflush(stdout) != 0 || fflush(stderr) != 0;
    stdin = saved_in;
    stdout = saved_out;
    stderr = saved_err;
    failed |= fclose(in) != 0;
    failed |= fclose(out) != 0;
    failed |= fclose(err) != 0;
    failed |= strcmp(output, "redirect:7\nputs\n") != 0;
    failed |= strcmp(errors, "redirect-error\n") != 0;
    if (failed) fprintf(stderr, "FAIL: redirected globals/output/input/status\n");
    return failed;
}

static int check_buffering(FILE *stream, int fd, int immediate) {
    int fds[2];
    if (pipe2(fds, O_NONBLOCK | O_CLOEXEC) != 0) return 1;
    int saved = dup(fd);
    if (saved < 0) {
        close(fds[0]);
        close(fds[1]);
        return 1;
    }
    int failed = dup2(fds[1], fd) < 0;
    if (!failed) {
        char bytes[16] = {0};
        failed |= fprintf(stream, "probe") != 5;
        ssize_t count = read(fds[0], bytes, sizeof(bytes));
        if (immediate) {
            failed |= count != 5 || memcmp(bytes, "probe", 5) != 0;
        } else {
            failed |= count != -1 || errno != EAGAIN;
        }
        failed |= fflush(stream) != 0;
        if (!immediate) {
            count = read(fds[0], bytes, sizeof(bytes));
            failed |= count != 5 || memcmp(bytes, "probe", 5) != 0;
        }
    }
    failed |= dup2(saved, fd) < 0;
    close(saved);
    close(fds[0]);
    close(fds[1]);
    if (failed) fprintf(stderr, "FAIL: buffering/flush for standard fd %d\n", fd);
    return failed;
}

int main(void) {
    /* The caller-provided buffer must outlive the stream, including exit. */
    static char user_buf[128];

    if (check_provider() != 0) return 1;

    if (stdin == NULL || stdout == NULL || stderr == NULL) {
        fprintf(stderr, "FAIL: standard stream globals must be non-null\n");
        return 1;
    }
    FILE *streams[] = {stdin, stdout, stderr};
    for (int fd = 0; fd < 3; ++fd) {
        if (fileno(streams[fd]) != fd || streams[fd]->_fileno != fd ||
            ((unsigned int)streams[fd]->_flags & 0xffff0000U) != 0xfbad0000U) {
            fprintf(stderr, "FAIL: standard stream %d is not a real FILE\n", fd);
            return 1;
        }
    }
    /* Correctly declared host objects have distinct addresses from the public
     * pointer cells. Do not require native storage to equal host storage. */
    if ((void *)&stdin == (void *)&_IO_2_1_stdin_ ||
        (void *)&stdout == (void *)&_IO_2_1_stdout_ ||
        (void *)&stderr == (void *)&_IO_2_1_stderr_) return 1;

    if (setvbuf(stdout, user_buf, _IOFBF, sizeof(user_buf)) != 0) {
        fprintf(stderr, "FAIL: setvbuf(stdout,_IOFBF,user_buf) failed\n");
        return 1;
    }
    if (fprintf(stdout, "stdout-buffered\n") != 16) {
        fprintf(stderr, "FAIL: fprintf(stdout,...) failed in full-buffered mode\n");
        return 1;
    }
    if (fflush(stdout) != 0) {
        fprintf(stderr, "FAIL: fflush(stdout) failed after full buffering\n");
        return 1;
    }

    if (fprintf(stderr, "stderr-immediate\n") != 17) {
        return 1;
    }

    if (check_buffering(stdout, STDOUT_FILENO, 0) != 0 ||
        check_buffering(stderr, STDERR_FILENO, 1) != 0) return 1;
    if (check_redirected_globals() != 0) return 1;
    if (fprintf(stdout, "fixture_stdio_globals: PASS\n") < 0 || fflush(stdout) != 0) {
        return 1;
    }
    return 0;
}
