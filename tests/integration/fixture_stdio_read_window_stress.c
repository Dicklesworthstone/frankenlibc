/* C-ABI regression for bd-ygc3li. Compile with -O2 so getc_unlocked is inline.
 * gcc -std=c11 -O2 -Wall -Wextra -Werror -pthread fixture_stdio_read_window_stress.c \
 *     -ldl -o fixture_stdio_read_window_stress
 * Baseline: ./fixture_stdio_read_window_stress
 * Candidate: FRANKENLIBC_MODE=strict LD_PRELOAD=.../libfrankenlibc_abi.so \
 *     ./fixture_stdio_read_window_stress --require-frankenlibc
 * Repeat candidate with FRANKENLIBC_MODE=hardened. A timeout is a failure.
 * No external service or filesystem fixture is required.
 */
#define _GNU_SOURCE
#include <dlfcn.h>
#include <errno.h>
#include <pthread.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

static unsigned checks;
#define CHECK(expr) do { \
    ++checks; \
    if (!(expr)) { \
        fprintf(stderr, "check %u, line %d: %s (errno=%d)\n", checks, __LINE__, #expr, errno); \
        exit(1); \
    } \
} while (0)

/* The glibc representation contracts used by gnulib, without its build system. */
static size_t visible(FILE *f) {
    size_t n = f->_IO_read_ptr == f->_IO_read_end ? 0 :
        (size_t)(f->_IO_read_end - f->_IO_read_ptr);
    if (f->_flags & 0x100) {
        if (f->_IO_save_base != f->_IO_save_end)
            n += (size_t)(f->_IO_save_end - f->_IO_save_base);
    }
    return n;
}

static unsigned char byte_at(size_t i) {
    return i % 31 == 30 ? '\n' : (unsigned char)('a' + i % 26);
}

static void file_case(void) {
    FILE *f = tmpfile();
    CHECK(f != NULL);
    CHECK(setvbuf(f, NULL, _IOFBF, 4096) == 0);
    unsigned char data[20000];
    for (size_t i = 0; i < sizeof data; ++i) data[i] = byte_at(i);
    CHECK(fwrite(data, 1, sizeof data, f) == sizeof data);
    CHECK(fseek(f, 0, SEEK_SET) == 0);
    CHECK(getc_unlocked(f) == data[0]);
    CHECK(visible(f) >= 16);
    size_t pos = 1;
    /* gnulib freadptrinc: advance the exported cursor without a libc call. */
    CHECK(memcmp(f->_IO_read_ptr, data + pos, 7) == 0);
    f->_IO_read_ptr += 7;
    pos += 7;
    CHECK(ftell(f) == (long)pos);
    CHECK(ftell(f) == (long)pos); /* reconciliation must not run twice */
    unsigned char out[5];
    CHECK(fread(out, 1, sizeof out, f) == sizeof out);
    CHECK(memcmp(out, data + pos, sizeof out) == 0);
    pos += sizeof out;
    /* Take a locked position snapshot before inspecting the header. A raw
     * fread fast path may legitimately withdraw its window until the next
     * locked operation republishes it; do not mistake that for lost data. */
    fpos_t before_pushback;
    CHECK(fgetpos(f, &before_pushback) == 0);
    size_t before = visible(f);
    CHECK(before > 0);
    CHECK(ungetc('Z', f) == 'Z');
    CHECK(visible(f) == before + 1);
    CHECK(ungetc('Y', f) == 'Y');
    CHECK(visible(f) == before + 2);
    CHECK(getc_unlocked(f) == 'Y');
    CHECK(getc_unlocked(f) == 'Z');
    CHECK(ftell(f) == (long)pos);
    fpos_t mark;
    CHECK(fgetpos(f, &mark) == 0);
    char line[80];
    CHECK(fgets(line, sizeof line, f) != NULL);
    size_t n = strlen(line);
    CHECK(n > 0 && line[n - 1] == '\n');
    CHECK(memcmp(line, data + pos, n) == 0);
    CHECK(fsetpos(f, &mark) == 0);
    CHECK(getc_unlocked(f) == data[pos++]);
    CHECK(fseek(f, 3, SEEK_CUR) == 0);
    pos += 3;
    CHECK(getc_unlocked(f) == data[pos++]);
    CHECK(fflush(f) == 0);
    CHECK(ftell(f) == (long)pos);
    CHECK(getc_unlocked(f) == data[pos++]);
    /* Mixed inline and normal calls cross multiple refill boundaries. */
    while (pos < sizeof data) {
        int c = pos % 17 == 0 ? fgetc(f) : getc_unlocked(f);
        CHECK(c == data[pos++]);
    }
    CHECK(getc_unlocked(f) == EOF);
    CHECK(feof(f) != 0 && !ferror(f));
    CHECK(ungetc('Q', f) == 'Q');
    CHECK(!feof(f));
    CHECK(getc_unlocked(f) == 'Q');
    CHECK(getc_unlocked(f) == EOF);
    clearerr(f);
    CHECK(!feof(f) && !ferror(f));
    CHECK(fseek(f, 4, SEEK_SET) == 0);
    CHECK(fputc('!', f) == '!');
    CHECK(fseek(f, 4, SEEK_SET) == 0);
    CHECK(getc_unlocked(f) == '!');
    CHECK(fclose(f) == 0);
}

static void pipe_case(void) {
    int fd[2];
    CHECK(pipe(fd) == 0);
    const char text[] = "0123456789abcdefghijklmnopqrstuv\n";
    CHECK(write(fd[1], text, sizeof text - 1) == (ssize_t)(sizeof text - 1));
    CHECK(close(fd[1]) == 0);
    FILE *f = fdopen(fd[0], "r");
    CHECK(f != NULL);
    CHECK(getc_unlocked(f) == '0');
    CHECK(visible(f) >= 8);
    f->_IO_read_ptr += 7;
    char tail[64];
    CHECK(fgets(tail, sizeof tail, f) == tail);
    CHECK(strcmp(tail, text + 8) == 0); /* cannot recover via lseek on a pipe */
    CHECK(fclose(f) == 0);
}

static void *thread_marker(void *unused) { return unused; }

int main(int argc, char **argv) {
    if (argc > 2 || (argc == 2 && strcmp(argv[1], "--require-frankenlibc"))) return 2;
    if (argc == 2) {
        const char *symbols[] = {"fgetc", "fread", "ftell", "ungetc"};
        for (size_t i = 0; i < sizeof symbols / sizeof symbols[0]; ++i) {
            void *p = dlsym(RTLD_DEFAULT, symbols[i]);
            Dl_info info;
            CHECK(p != NULL && dladdr(p, &info) && info.dli_fname != NULL);
            CHECK(strstr(info.dli_fname, "frankenlibc") != NULL);
        }
    }
    file_case(); /* exercises the process-single-threaded cache branch */
    pipe_case();
    pthread_t thread;
    CHECK(pthread_create(&thread, NULL, thread_marker, NULL) == 0);
    CHECK(pthread_join(thread, NULL) == 0);
    file_case(); /* exercises the cell-cache branch after threads have existed */
    pipe_case();
    printf("stdio-read-window-stress: %u checks passed\n", checks);
    return 0;
}
