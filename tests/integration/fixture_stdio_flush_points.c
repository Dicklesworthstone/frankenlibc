// Where a fully buffered stream flushes, made observable: a child's stdout and
// stderr share one pipe, so each unbuffered stderr marker lands exactly at the
// point stdout had flushed to.
//
// glibc sizes a stream buffer as BUFSIZ or the fd's smaller st_blksize (4096
// for a pipe, 1024 for /proc), and on overflow tops the buffer up, flushes it,
// writes whole blocks of the rest directly and buffers the tail. fl used 8192
// everywhere and flushed old buffer + the whole new chunk, so ImageMagick's
// `compare --help` put its error line in a different place than under glibc.
#define _GNU_SOURCE
#include <fcntl.h>
#include <stdio.h>
#include <stdio_ext.h>
#include <string.h>
#include <sys/wait.h>
#include <unistd.h>

static void child(void) {
    static char chunk[12000];
    const size_t sizes[] = {1000, 3000, 297, 5000, 4096, 10, 9000, 1, 4095, 12000};
    for (size_t i = 0; i < sizeof sizes / sizeof *sizes; i++) {
        memset(chunk, 'a' + (int)(i % 26), sizes[i]);
        fwrite(chunk, 1, sizes[i], stdout);
        fprintf(stderr, "<E%zu>", i);
    }
    printf("tail");
    fputs("<END>", stderr);
}

int main(void) {
    int p[2];
    if (pipe(p) != 0) return 1;
    fflush(stdout);
    pid_t pid = fork();
    if (pid == 0) {
        dup2(p[1], 1);
        dup2(p[1], 2);
        close(p[0]);
        close(p[1]);
        child();
        return 0;
    }
    close(p[1]);
    // Summarize the stream: runs of stdout bytes as <count x letter>, markers verbatim.
    char buf[4096];
    char run_ch = 0;
    long run = 0;
    ssize_t n;
    while ((n = read(p[0], buf, sizeof buf)) > 0) {
        for (ssize_t i = 0; i < n; i++) {
            char c = buf[i];
            if (c >= 'a' && c <= 'z' && (c == run_ch || run == 0)) {
                run_ch = c;
                run++;
                continue;
            }
            if (run) {
                printf("[%ld %c]", run, run_ch);
                run = 0;
            }
            if (c >= 'a' && c <= 'z') {
                run_ch = c;
                run = 1;
            } else {
                putchar(c);
            }
        }
    }
    if (run) printf("[%ld %c]", run, run_ch);
    putchar('\n');
    waitpid(pid, NULL, 0);

    int q[2];
    if (pipe(q) != 0) return 1;
    FILE *f = fdopen(q[1], "w");
    fputc('x', f);
    printf("pipe stream buffer: %zu\n", __fbufsize(f));
    fclose(f);
    close(q[0]);
    f = fopen("/dev/null", "w");
    fputc('x', f);
    printf("/dev/null stream buffer: %zu\n", __fbufsize(f));
    fclose(f);
    f = fopen("/proc/self/status", "r");
    fgetc(f);
    printf("/proc stream buffer: %zu\n", __fbufsize(f));
    fclose(f);
    return 0;
}
