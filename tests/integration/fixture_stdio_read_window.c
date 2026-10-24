/* The glibc read window [_IO_read_ptr, _IO_read_end): <stdio.h> inlines
 * getc_unlocked as `ptr < end ? *ptr++ : __uflow(fp)`, and gnulib's
 * freadahead/freadptr/freadseek read and advance these fields directly. fl
 * kept the window empty, so gnulib saw no buffered input (test-freadahead,
 * test-freadptr, test-freadptr2 failed in coreutils/findutils) and every
 * inlined getc was a __uflow call. Bytes consumed through the window must be
 * accounted before any libc call on the stream: mixing inline reads with
 * fgetc/fread/ungetc/ftell/fseek/fgets must not duplicate or skip bytes.
 * Output matches glibc.
 */
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

/* gnulib freadahead (glibc branch) */
static size_t ahead(FILE *fp) {
    if (fp->_IO_write_ptr > fp->_IO_write_base)
        return 0;
    return (size_t)(fp->_IO_read_end - fp->_IO_read_ptr);
}

int main(void) {
    char path[] = "/tmp/fl_read_window_XXXXXX";
    int fd = mkstemp(path);
    if (fd < 0)
        return 1;
    for (int i = 0; i < 5000; i++) {
        char c = (char)('a' + i % 26);
        if (write(fd, &c, 1) != 1)
            return 1;
    }
    close(fd);

    FILE *f = fopen(path, "r");
    int a = getc_unlocked(f), b = getc_unlocked(f);
    printf("inline: %c%c ahead>0=%d\n", a, b, ahead(f) > 0);
    printf("fgetc: %c ftell=%ld\n", fgetc(f), ftell(f));
    for (int i = 0; i < 10; i++)
        (void)getc_unlocked(f);
    printf("after 10 inline: ftell=%ld next=%c\n", ftell(f), fgetc(f));
    char buf[8] = {0};
    printf("fread=%zu [%s] ftell=%ld\n", fread(buf, 1, 5, f), buf, ftell(f));
    ungetc('#', f);
    printf("after ungetc: inline=%c inline=%c ftell=%ld\n", getc_unlocked(f), getc_unlocked(f), ftell(f));
    /* freadseek: skip 7 bytes by advancing _IO_read_ptr in place */
    if (ahead(f) >= 7)
        f->_IO_read_ptr += 7;
    else
        fseek(f, 7, SEEK_CUR);
    printf("after ptr+=7: ftell=%ld fgetc=%c\n", ftell(f), fgetc(f));
    fseek(f, 4090, SEEK_SET);
    int n = 0, c, last = 0;
    while ((c = getc_unlocked(f)) != EOF) {
        n++;
        last = c;
    }
    printf("tail: %d bytes last=%c eof=%d ftell=%ld\n", n, last, feof(f), ftell(f));
    rewind(f);
    char line[16];
    (void)getc_unlocked(f);
    printf("fgets after inline: [%s]\n", fgets(line, 6, f));
    long sum = 0;
    rewind(f);
    while ((c = getc_unlocked(f)) != EOF)
        sum += c;
    printf("sum=%ld\n", sum);
    fclose(f);

    /* a pipe: no seeking, the window is the only buffer */
    FILE *p = popen("printf 'hello pipe\\n'", "r");
    int h = getc_unlocked(p);
    printf("pipe: %c ahead=%zu rest=", h, ahead(p));
    while ((c = getc_unlocked(p)) != EOF)
        putchar(c);
    pclose(p);

    /* a closed std stream must not expose its freed buffer */
    FILE *in = freopen(path, "r", stdin);
    printf("stdin: %c", getc_unlocked(in));
    fclose(stdin);
    printf(" after fclose ahead=%zu\n", ahead(stdin));
    unlink(path);
    return 0;
}
