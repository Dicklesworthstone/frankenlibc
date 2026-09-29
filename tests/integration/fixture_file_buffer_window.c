// Code that reaches into glibc's FILE buffer window, as {fmt} 11 does for
// fmt::print on glibc (btop, spdlog users): unless _IO_UNBUFFERED is set, it
// forces buffer setup with `putc_unlocked(0, f); --f->_IO_write_ptr;`, formats
// straight into [_IO_write_ptr, _IO_buf_end), then advances _IO_write_ptr.
//
// fl's FILE handles keep that window empty (every inline macro falls through
// to __overflow/__uflow into fl's stdio), so the forced setup left
// _IO_write_ptr at -1 and btop died with SIGSEGV writing through it. A FILE
// with no visible buffer now says so with _IO_UNBUFFERED, and this caller
// takes the fwrite path. The inline getc/putc_unlocked macros must keep
// working through the empty window as before.
#define _GNU_SOURCE
#include <stdio.h>
#include <string.h>

#define IO_UNBUFFERED 0x0002

// fmt 11's glibc print path, transcribed to C.
static void fmt_style_print(FILE *f, const char *text) {
    size_t len = strlen(text);
    if (f->_flags & IO_UNBUFFERED) {
        fwrite(text, 1, len, f);
        return;
    }
    flockfile(f);
    if (f->_IO_write_ptr >= f->_IO_write_end) {
        putc_unlocked(0, f);
        --f->_IO_write_ptr;
    }
    while (len > 0) {
        size_t room = (size_t)(f->_IO_buf_end - f->_IO_write_ptr);
        size_t n = len < room ? len : room;
        memcpy(f->_IO_write_ptr, text, n);
        f->_IO_write_ptr += n;
        text += n;
        len -= n;
        if (len > 0) fflush_unlocked(f);
    }
    funlockfile(f);
}

int main(void) {
    fmt_style_print(stdout, "fmt-style print to stdout\n");
    for (int i = 0; i < 3; i++) fmt_style_print(stdout, "  repeated line\n");

    FILE *f = tmpfile();
    fmt_style_print(f, "into a file stream\n");
    for (const char *p = "via putc_unlocked\n"; *p; p++) putc_unlocked(*p, f);
    rewind(f);
    int c;
    printf("file contents:\n");
    while ((c = getc_unlocked(f)) != EOF) putchar_unlocked(c);
    fclose(f);

    char big[5000];
    memset(big, 'x', sizeof big - 2);
    big[sizeof big - 2] = '\n';
    big[sizeof big - 1] = 0;
    fmt_style_print(stdout, big);
    printf("done\n");
    return 0;
}
