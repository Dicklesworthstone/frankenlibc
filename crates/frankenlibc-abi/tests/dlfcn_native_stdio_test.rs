#![cfg(all(target_os = "linux", target_arch = "x86_64"))]

use std::ffi::{CStr, CString, c_char, c_int, c_void};
use std::os::unix::ffi::OsStrExt;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use frankenlibc_abi::{
    dlfcn_abi as dl, isoc_abi as isoc, malloc_abi as allocation, stdio_abi as stdio,
};
use frankenlibc_core::elf::ElfLoader;
#[path = "common/dlsym_oracle.rs"]
mod dlsym_oracle;

type Open = unsafe extern "C" fn(*const c_char, c_int) -> *mut c_void;
type Sym = unsafe extern "C" fn(*mut c_void, *const c_char) -> *mut c_void;
type Close = unsafe extern "C" fn(*mut c_void) -> c_int;
type Frontend = unsafe extern "C" fn(usize, c_int, *const c_char) -> *mut c_void;
type OnePath = unsafe extern "C" fn(*const c_char) -> c_int;

const SOURCE: &str = r#"#define _GNU_SOURCE
#include <stdio.h>
#include <dlfcn.h>
#include <fcntl.h>
#include <unistd.h>
#include <errno.h>
#include <stddef.h>
#include <stdint.h>

#define EXPECT(x, n) do { if (!(x)) return (n); } while (0)
#define FRONTENDS(X) \
 X(fopen) X(fdopen) X(freopen) X(fclose) X(fread) X(fwrite) \
 X(fgetc) X(fputc) X(fgets) X(fputs) X(ungetc) X(fseek) X(ftell) X(rewind) \
 X(feof) X(ferror) X(clearerr) X(fflush) X(setbuf) X(setvbuf) X(fileno) \
 X(flockfile) X(ftrylockfile) X(funlockfile) \
 X(fopen64) X(freopen64) X(fseeko) X(ftello) X(fseeko64) X(ftello64) \
 X(fgetpos) X(fsetpos) X(fgetpos64) X(fsetpos64)
#define NAME(n) #n,
static const char *const names[] = { FRONTENDS(NAME) };
#define ADDRESS(n) (void *)(uintptr_t)&n,
static void *const addresses[] = { FRONTENDS(ADDRESS) };
size_t stream_frontend_count(void) { return sizeof addresses / sizeof addresses[0]; }
void *stream_frontend(size_t index, int dynamic, const char *version) {
    if (index >= stream_frontend_count()) return 0;
    if (!dynamic) return addresses[index];
    void *result = version ? dlvsym(RTLD_DEFAULT, names[index], version)
                           : dlsym(RTLD_DEFAULT, names[index]);
    __asm__ __volatile__("" : "+r"(result));
    return result;
}
int stream_roundtrip(const char *path) {
    FILE *s = fopen(path, "w+"); EXPECT(s, 1);
    char buffer[128]; EXPECT(setvbuf(s, buffer, _IOFBF, sizeof buffer) == 0, 2);
    EXPECT(fwrite("ab\0cd\n", 2, 3, s) == 3, 3);
    EXPECT(ftell(s) == 6, 4); EXPECT(fflush(s) == 0, 5);
    char data[16] = {0};
    int fd = open(path, O_RDONLY); EXPECT(fd >= 0, 6);
    EXPECT(read(fd, data, sizeof data) == 6, 7); EXPECT(close(fd) == 0, 8);
    EXPECT(data[0]=='a' && data[2]==0 && data[5]=='\n', 9);
    EXPECT(fseek(s, 0, SEEK_SET)==0, 10);
    EXPECT(fread(data, 4, 2, s)==1, 11); EXPECT(feof(s)!=0 && ferror(s)==0, 12);
    clearerr(s); EXPECT(feof(s)==0 && ferror(s)==0, 13);
    rewind(s); EXPECT(ftell(s)==0, 14);
    EXPECT(fgetc(s)=='a', 15); EXPECT(ungetc('Z',s)=='Z' && fgetc(s)=='Z', 16);
    EXPECT(fseek(s,0,SEEK_END)==0 && fputc('!',s)=='!', 17);
    EXPECT(fclose(s)==0, 18);
    return 0;
}
int stream_reopen(const char *first, const char *second) {
    FILE *s=fopen(first,"w+"); EXPECT(s,1);
    setbuf(s,0); EXPECT(fputs("old",s)>=0,2);
    EXPECT(freopen(second,"w+",s)==s,3);
    EXPECT(fputs("new\n",s)>=0 && fflush(s)==0,4);
    rewind(s); char data[8]={0}; EXPECT(fgets(data,sizeof data,s)==data,5);
    EXPECT(data[0]=='n' && data[3]=='\n' && data[4]==0,6);
    EXPECT(fclose(s)==0,7);
    s=fopen(second,"a+"); EXPECT(s,8);
    EXPECT(fseek(s,0,SEEK_SET)==0 && fputc('+',s)=='+',9);
    EXPECT(fclose(s)==0,10);
    return 0;
}
int stream_fd_ownership(const char *path) {
    int fd=open(path,O_CREAT|O_TRUNC|O_RDWR,0600); EXPECT(fd>=0,1);
    FILE *s=fdopen(fd,"w+"); EXPECT(s,2); EXPECT(fileno(s)==fd,3);
    EXPECT(fputs("descriptor",s)>=0 && fflush(s)==0,4);
    EXPECT(fclose(s)==0,5);
    errno=0; char c; EXPECT(read(fd,&c,1)==-1 && errno==EBADF,6);
    fd=open(path,O_RDONLY); EXPECT(fd>=0,7);
    errno=0; EXPECT(fdopen(fd,"w")==0 && errno==EINVAL,8);
    EXPECT(read(fd,&c,1)==1 && c=='d',9); EXPECT(close(fd)==0,10);
    return 0;
}
int stream_errors(const char *path) {
    FILE *s=fopen(path,"w+"); EXPECT(s,1);
    EXPECT(fputs("one\ntwo\n",s)>=0 && fclose(s)==0,2);
    s=fopen(path,"r"); EXPECT(s,3);
    char data[16]; EXPECT(fgets(data,sizeof data,s)==data && data[0]=='o',4);
    EXPECT(fgets(data,sizeof data,s)==data && data[0]=='t',5);
    EXPECT(fgetc(s)==EOF && feof(s)!=0,6);
    clearerr(s); EXPECT(!feof(s) && !ferror(s),7);
    errno=0; EXPECT(fputc('x',s)==EOF && ferror(s)!=0 && errno==EBADF,8);
    clearerr(s); EXPECT(!ferror(s),9);
    rewind(s); EXPECT(fgetc(s)=='o' && !feof(s),10);
    EXPECT(fclose(s)==0,11);
    return 0;
}
void *stream_open_shared(const char *path) { return fopen(path,"w+"); }
int stream_write_locked(void *ptr, int byte, size_t lines) {
    FILE *s=ptr; char data[8];
    for (size_t i=0;i<sizeof data-1;++i) data[i]=(char)byte;
    data[7]='\n';
    for(size_t i=0;i<lines;++i) {
        flockfile(s);
        int lock=ftrylockfile(s);
        if(lock!=0) { funlockfile(s); return 1; }
        size_t n=fwrite(data,1,sizeof data,s);
        funlockfile(s); funlockfile(s);
        if(n!=sizeof data) return 2;
    }
    return 0;
}
int stream_close_shared(void *ptr) { return fclose(ptr); }
int stream_large_offsets(const char *path) {
    const off64_t offset = ((off64_t)5 << 30) + 7;
    FILE *s = fopen64(path, "w+"); EXPECT(s, 1);
    EXPECT(fseeko64(s, offset, SEEK_SET) == 0, 2);
    EXPECT(ftello64(s) == offset && ftello(s) == offset, 3);
    fpos_t start; EXPECT(fgetpos(s, &start) == 0, 4);
    EXPECT(fputs("large", s) >= 0 && fflush(s) == 0, 5);
    fpos64_t end; EXPECT(fgetpos64(s, &end) == 0, 6);
    EXPECT(ftello64(s) == offset + 5, 7);
    EXPECT(fsetpos(s, &start) == 0 && fgetc(s) == 'l', 8);
    EXPECT(fsetpos64(s, &end) == 0 && fputc('!', s) == '!', 9);
    EXPECT(fflush(s) == 0 && ftello64(s) == offset + 6, 10);
    errno = 0;
    EXPECT(fseeko64(s, -1, SEEK_SET) == -1 && errno == EINVAL, 11);
    EXPECT(ftello64(s) == offset + 6, 12);
    EXPECT(freopen64(path, "r", s) == s, 13);
    EXPECT(fseeko(s, offset - 1, SEEK_SET) == 0, 14);
    EXPECT(fgetc(s) == 0, 15);
    char bytes[6]; EXPECT(fread(bytes, 1, sizeof bytes, s) == sizeof bytes, 16);
    EXPECT(bytes[0] == 'l' && bytes[4] == 'e' && bytes[5] == '!', 17);
    EXPECT(ftello(s) == offset + 6 && fgetc(s) == EOF && feof(s), 18);
    EXPECT(fclose(s) == 0, 19);
    return 0;
}

#ifdef EXTENDED_STREAMS
#define EXTENDED_FRONTENDS(X) \
 X(fopencookie) X(tmpfile) X(tmpfile64) X(popen) X(pclose) \
 X(getc) X(putc) X(getchar) X(putchar) \
 X(getc_unlocked) X(putc_unlocked) X(fgetc_unlocked) X(fputc_unlocked) \
 X(getchar_unlocked) X(putchar_unlocked) X(fread_unlocked) X(fwrite_unlocked) \
 X(fgets_unlocked) X(fputs_unlocked) X(fflush_unlocked) X(feof_unlocked) \
 X(ferror_unlocked) X(clearerr_unlocked) X(fileno_unlocked)
static const char *const extended_names[] = { EXTENDED_FRONTENDS(NAME) };
static void *const extended_addresses[] = { EXTENDED_FRONTENDS(ADDRESS) };
size_t extended_frontend_count(void) {
    return sizeof extended_addresses / sizeof extended_addresses[0];
}
void *extended_frontend(size_t index, int dynamic, const char *version) {
    if (index >= extended_frontend_count()) return 0;
    if (!dynamic) return extended_addresses[index];
    void *result = version ? dlvsym(RTLD_DEFAULT, extended_names[index], version)
                           : dlsym(RTLD_DEFAULT, extended_names[index]);
    __asm__ __volatile__("" : "+r"(result));
    return result;
}

/* Call exported functions even when glibc headers offer FILE-field inlines. */
extern int exported_getc_unlocked(FILE *) __asm__("getc_unlocked");
extern int exported_fputc_unlocked(int, FILE *) __asm__("fputc_unlocked");
extern size_t exported_fread_unlocked(void *, size_t, size_t, FILE *)
    __asm__("fread_unlocked");
extern size_t exported_fwrite_unlocked(const void *, size_t, size_t, FILE *)
    __asm__("fwrite_unlocked");
extern int exported_fflush_unlocked(FILE *) __asm__("fflush_unlocked");
extern int exported_feof_unlocked(FILE *) __asm__("feof_unlocked");
extern int exported_ferror_unlocked(FILE *) __asm__("ferror_unlocked");
extern void exported_clearerr_unlocked(FILE *) __asm__("clearerr_unlocked");
extern int exported_fileno_unlocked(FILE *) __asm__("fileno_unlocked");

int stream_temporary_unlocked(int large) {
    FILE *s = large ? tmpfile64() : tmpfile(); EXPECT(s, 1);
    int fd = exported_fileno_unlocked(s); EXPECT(fd >= 0 && fileno(s) == fd, 2);
    flockfile(s);
    EXPECT(exported_fwrite_unlocked("ab\0cd\n", 2, 3, s) == 3, 3);
    EXPECT(exported_fputc_unlocked('!', s) == '!', 4);
    EXPECT(exported_fflush_unlocked(s) == 0 && ftell(s) == 7, 5);
    EXPECT(fseek(s, 0, SEEK_SET) == 0 && exported_getc_unlocked(s) == 'a', 6);
    char bytes[8] = {0};
    EXPECT(exported_fread_unlocked(bytes, 2, 4, s) == 3, 7);
    EXPECT(bytes[0] == 'b' && bytes[1] == 0 && bytes[2] == 'c' &&
           bytes[3] == 'd' && bytes[4] == '\n' && bytes[5] == '!', 8);
    EXPECT(exported_feof_unlocked(s) && feof(s) && !exported_ferror_unlocked(s), 9);
    exported_clearerr_unlocked(s);
    EXPECT(!feof(s) && !ferror(s), 10);
    funlockfile(s);
    EXPECT(fclose(s) == 0, 11);
    errno = 0; EXPECT(fcntl(fd, F_GETFD) == -1 && errno == EBADF, 12);
    return 0;
}

struct StreamCookie { size_t position; unsigned reads, closes; int fail; };
static ssize_t stream_cookie_read(void *opaque, char *buffer, size_t length) {
    struct StreamCookie *cookie = opaque;
    static const char bytes[] = "cookie\n";
    ++cookie->reads;
    if (cookie->fail) { errno = EIO; return -1; }
    size_t remaining = sizeof bytes - 1 - cookie->position;
    if (length > remaining) length = remaining;
    if (length > 2) length = 2;
    for (size_t i = 0; i < length; ++i) buffer[i] = bytes[cookie->position + i];
    cookie->position += length;
    return (ssize_t)length;
}
static int stream_cookie_close(void *opaque) {
    struct StreamCookie *cookie = opaque;
    ++cookie->closes;
    return 0;
}
int stream_cookie_unlocked(void) {
    struct StreamCookie cookie = {0};
    cookie_io_functions_t functions = {
        .read = stream_cookie_read, .close = stream_cookie_close
    };
    FILE *s = fopencookie(&cookie, "r", functions); EXPECT(s, 1);
    EXPECT(exported_getc_unlocked(s) == 'c', 2);
    char bytes[6]; EXPECT(exported_fread_unlocked(bytes, 1, sizeof bytes, s) == 6, 3);
    EXPECT(bytes[0] == 'o' && bytes[1] == 'o' && bytes[2] == 'k' &&
           bytes[3] == 'i' && bytes[4] == 'e' && bytes[5] == '\n', 4);
    EXPECT(fgetc(s) == EOF && exported_feof_unlocked(s), 5);
    exported_clearerr_unlocked(s);
    cookie.fail = 1; errno = 0;
    EXPECT(exported_getc_unlocked(s) == EOF && errno == EIO, 6);
    EXPECT(exported_ferror_unlocked(s) && ferror(s) && !feof(s), 7);
    exported_clearerr_unlocked(s); EXPECT(!ferror(s) && !feof(s), 8);
    errno = 0; EXPECT(exported_fileno_unlocked(s) == -1 && errno == EBADF, 9);
    EXPECT(fclose(s) == 0 && cookie.closes == 1 && cookie.reads >= 5, 10);
    return 0;
}

int stream_process_unlocked(void) {
    FILE *s = popen("printf 'pipe-data'; exit 7", "re"); EXPECT(s, 1);
    int fd = exported_fileno_unlocked(s); EXPECT(fd >= 0, 2);
    int flags = fcntl(fd, F_GETFD); EXPECT(flags >= 0 && (flags & FD_CLOEXEC), 3);
    char bytes[16] = {0};
    EXPECT(exported_fread_unlocked(bytes, 1, sizeof bytes, s) == 9, 4);
    static const char expected[] = "pipe-data";
    for (size_t i = 0; i < sizeof expected - 1; ++i) EXPECT(bytes[i] == expected[i], 5);
    EXPECT(exported_feof_unlocked(s) && !exported_ferror_unlocked(s), 6);
    EXPECT(pclose(s) == (7 << 8), 7);
    errno = 0; EXPECT(fcntl(fd, F_GETFD) == -1 && errno == EBADF, 8);
    errno = 0; EXPECT(popen("exit 0", "r+") == 0 && errno == EINVAL, 9);
    return 0;
}
#endif

#ifdef SCAN_INPUT
#include <stdarg.h>
#include <stdlib.h>
#include <string.h>

/* Explicit assembler names prevent the host headers from silently changing
   the legacy/C99/C23 contract selected by each test. */
#define DECLARE_SCANNERS(P, S) \
 extern int P##scanf(const char *, ...) __asm__(S "scanf"); \
 extern int P##fscanf(FILE *, const char *, ...) __asm__(S "fscanf"); \
 extern int P##sscanf(const char *, const char *, ...) __asm__(S "sscanf"); \
 extern int P##vscanf(const char *, va_list) __asm__(S "vscanf"); \
 extern int P##vfscanf(FILE *, const char *, va_list) __asm__(S "vfscanf"); \
 extern int P##vsscanf(const char *, const char *, va_list) __asm__(S "vsscanf")
DECLARE_SCANNERS(legacy_, "");
DECLARE_SCANNERS(c99_, "__isoc99_");
DECLARE_SCANNERS(c23_, "__isoc23_");

#define SCAN_FRONTENDS(X) \
 X(legacy_scanf, "scanf") X(legacy_fscanf, "fscanf") X(legacy_sscanf, "sscanf") \
 X(legacy_vscanf, "vscanf") X(legacy_vfscanf, "vfscanf") X(legacy_vsscanf, "vsscanf") \
 X(c99_scanf, "__isoc99_scanf") X(c99_fscanf, "__isoc99_fscanf") \
 X(c99_sscanf, "__isoc99_sscanf") X(c99_vscanf, "__isoc99_vscanf") \
 X(c99_vfscanf, "__isoc99_vfscanf") X(c99_vsscanf, "__isoc99_vsscanf") \
 X(c23_scanf, "__isoc23_scanf") X(c23_fscanf, "__isoc23_fscanf") \
 X(c23_sscanf, "__isoc23_sscanf") X(c23_vscanf, "__isoc23_vscanf") \
 X(c23_vfscanf, "__isoc23_vfscanf") X(c23_vsscanf, "__isoc23_vsscanf")
#define SCAN_NAME(F, N) N,
static const char *const scan_names[] = { SCAN_FRONTENDS(SCAN_NAME) };
#define SCAN_ADDRESS(F, N) (void *)(uintptr_t)&F,
static void *const scan_addresses[] = { SCAN_FRONTENDS(SCAN_ADDRESS) };
size_t scan_frontend_count(void) { return sizeof scan_addresses / sizeof scan_addresses[0]; }
void *scan_frontend(size_t index, int dynamic, const char *version) {
    if (index >= scan_frontend_count()) return 0;
    if (!dynamic) return scan_addresses[index];
    void *result = version ? dlvsym(RTLD_DEFAULT, scan_names[index], version)
                           : dlsym(RTLD_DEFAULT, scan_names[index]);
    __asm__ __volatile__("" : "+r"(result));
    return result;
}

/* Genuine C va_list forwarding, including more pointer destinations than
   fit in the integer argument registers. No Rust reconstruction of va_list. */
#define VSCAN_ADAPTERS(P) \
 static int P##string_v(const char *input, const char *format, ...) { \
    va_list ap; va_start(ap, format); \
    int result = P##vsscanf(input, format, ap); va_end(ap); return result; \
 } \
 static int P##file_v(FILE *stream, const char *format, ...) { \
    va_list ap; va_start(ap, format); \
    int result = P##vfscanf(stream, format, ap); va_end(ap); return result; \
 } \
 static int P##input_v(const char *format, ...) { \
    va_list ap; va_start(ap, format); \
    int result = P##vscanf(format, ap); va_end(ap); return result; \
 }
VSCAN_ADAPTERS(legacy_)
VSCAN_ADAPTERS(c99_)
VSCAN_ADAPTERS(c23_)

typedef int (*StringScan)(const char *, const char *, ...);
typedef int (*FileScan)(FILE *, const char *, ...);
typedef int (*InputScan)(const char *, ...);
static StringScan const string_scanners[] = {
    legacy_sscanf, legacy_string_v, c99_sscanf, c99_string_v, c23_sscanf, c23_string_v
};
static FileScan const file_scanners[] = {
    legacy_fscanf, legacy_file_v, c99_fscanf, c99_file_v, c23_fscanf, c23_file_v
};
static InputScan const input_scanners[] = {
    legacy_scanf, legacy_input_v, c99_scanf, c99_input_v, c23_scanf, c23_input_v
};

static FILE *scan_memory(void *data, size_t length) {
    /* An unversioned -nostdlib import can bind glibc's pre-2.22 compatibility
       fmemopen. Select the modern contract the native runtime supplies. */
    typedef FILE *(*MemoryOpen)(void *, size_t, const char *);
    MemoryOpen open = (MemoryOpen)dlvsym(RTLD_DEFAULT, "fmemopen", "GLIBC_2.22");
    return open ? open(data, length, "r") : 0;
}

int scan_values(unsigned route) {
    EXPECT(route < 6, 1);
    int a = 0, consumed = -1;
    unsigned b = 0; long c = 0; unsigned long long d = 0;
    short e = 0; unsigned char f = 0; double g = 0; char word[4] = {0};
    int count = string_scanners[route]("17 23 31 47 59 61 2.5 xyz!",
        "%d %u %ld %llu %hd %hhu %lf %3s%n",
        &a, &b, &c, &d, &e, &f, &g, word, &consumed);
    EXPECT(count == 8 && consumed == 25, 2);
    EXPECT(a == 17 && b == 23 && c == 31 && d == 47 && e == 59 && f == 61, 3);
    EXPECT(g == 2.5 && strcmp(word, "xyz") == 0, 4);
    a = 917; consumed = -1;
    EXPECT(string_scanners[route]("?", "%d%n", &a, &consumed) == 0, 5);
    EXPECT(a == 917 && consumed == -1, 6);
    EXPECT(string_scanners[route]("", "%d", &a) == EOF && a == 917, 7);
    EXPECT(string_scanners[route]("7 99 11", "%d %*d %ld%n", &a, &c, &consumed) == 2, 8);
    EXPECT(a == 7 && c == 11 && consumed == 7, 9);
    if (route >= 4) {
        EXPECT(string_scanners[route]("0b101!", "%i%n", &a, &consumed) == 1, 10);
        EXPECT(a == 5 && consumed == 5, 11);
    }
    return 0;
}

/* These expectations were observed through the exact GNU symbol for each
   route. A new glibc version does not change legacy/C99 %i into C23 %i. */
int scan_dialects(unsigned route, int kind) {
    EXPECT(route < 6 && kind >= 0 && kind <= 2, 1);
    struct Case {
        const char *text, *string_format, *stream_format;
        int legacy_value, c23_value, legacy_count, c23_count;
    };
    static const struct Case cases[] = {
        {"0b101!", "%i%n%c", "%i%n", 0, 5, 1, 5},
        {"-0B101!", "%i%n%c", "%i%n", 0, -5, 2, 6},
        {"+0b101!", "%i%n%c", "%i%n", 0, 5, 2, 6},
        {"0b!", "%i%n%c", "%i%n", 0, 0, 1, 2},
        {"0b2!", "%i%n%c", "%i%n", 0, 0, 1, 2},
        {"0b", "%i%n%c", "%i%n", 0, 0, 1, 2},
        {"0b101!", "%1i%n%c", "%1i%n", 0, 0, 1, 1},
        {"0b101!", "%2i%n%c", "%2i%n", 0, 0, 1, 2},
        {"0b101!", "%3i%n%c", "%3i%n", 0, 1, 1, 3},
        {"-0b1!", "%3i%n%c", "%3i%n", 0, 0, 2, 3},
        {"-0b1!", "%4i%n%c", "%4i%n", 0, -1, 2, 4},
        {"0x!", "%i%n%c", "%i%n", 0, 0, 2, 2},
        {"0x", "%i%n%c", "%i%n", 0, 0, 2, 2},
        {"-0X!", "%i%n%c", "%i%n", 0, 0, 3, 3},
        {"0x1!", "%1i%n%c", "%1i%n", 0, 0, 1, 1},
        {"0x1!", "%2i%n%c", "%2i%n", 0, 0, 2, 2},
        {"09!", "%i%n%c", "%i%n", 0, 0, 1, 1},
        {"123!", "%i%n%c", "%i%n", 123, 123, 3, 3}
    };
    for (size_t i = 0; i < sizeof cases / sizeof cases[0]; ++i) {
        const struct Case *c = &cases[i];
        int value = 917, consumed = -1, result, tail;
        int wanted_value = route >= 4 ? c->c23_value : c->legacy_value;
        int wanted_count = route >= 4 ? c->c23_count : c->legacy_count;
        int wanted_tail = c->text[wanted_count] ? c->text[wanted_count] : EOF;
        if (kind == 0) {
            char next = '?';
            result = string_scanners[route](c->text, c->string_format,
                                            &value, &consumed, &next);
            EXPECT(result == (wanted_tail == EOF ? 1 : 2), 100 + (int)i);
            tail = next == '?' && wanted_tail == EOF ? EOF : (unsigned char)next;
        } else {
            FILE *s = scan_memory((void *)c->text, strlen(c->text));
            EXPECT(s, 200 + (int)i);
            if (kind == 1) {
                result = file_scanners[route](s, c->stream_format, &value, &consumed);
            } else {
                FILE *saved = stdin; stdin = s;
                result = input_scanners[route](c->stream_format, &value, &consumed);
                stdin = saved;
            }
            EXPECT(result == 1 && ftello(s) == wanted_count, 300 + (int)i);
            tail = fgetc(s);
            EXPECT(fclose(s) == 0, 400 + (int)i);
        }
        EXPECT(value == wanted_value && consumed == wanted_count, 500 + (int)i);
        EXPECT(tail == wanted_tail, 600 + (int)i);
    }
    int consumed = -1; char tail = '?';
    EXPECT(string_scanners[route]("0b101!", "%*i%n%c", &consumed, &tail) == 1, 701);
    EXPECT(consumed == (route >= 4 ? 5 : 1) && tail == (route >= 4 ? '!' : 'b'), 702);
    unsigned hex = 917; consumed = -1; tail = '?';
    EXPECT(string_scanners[route]("0x!", "%x%n%c", &hex, &consumed, &tail) == 2, 703);
    EXPECT(hex == 0 && consumed == 2 && tail == '!', 704);
    return 0;
}

int scan_streams(const char *path, unsigned route) {
    EXPECT(route < 6, 1);
    FILE *s = fopen(path, "w+"); EXPECT(s, 2);
    EXPECT(fputs("17 23 tail!", s) >= 0 && fseeko(s, 0, SEEK_SET) == 0, 3);
    int a = 0, consumed = -1; unsigned b = 0;
    EXPECT(file_scanners[route](s, "%d %u%n", &a, &b, &consumed) == 2, 4);
    EXPECT(a == 17 && b == 23 && consumed == 5 && ftello(s) == 5, 5);
    EXPECT(fgetc(s) == ' ', 6);
    a = 917;
    EXPECT(file_scanners[route](s, "%d", &a) == 0 && a == 917 && !feof(s), 7);
    char word[5] = {0};
    EXPECT(file_scanners[route](s, "%4[a-z]%n", word, &consumed) == 1, 8);
    EXPECT(strcmp(word, "tail") == 0 && consumed == 4 && ftello(s) == 10, 9);
    EXPECT(fgetc(s) == '!' && fgetc(s) == EOF && feof(s) && !ferror(s), 10);
    EXPECT(file_scanners[route](s, "%d", &a) == EOF && a == 917, 11);
    EXPECT(fclose(s) == 0, 12);

    char memory[] = "31 word!";
    s = scan_memory(memory, sizeof memory - 1); EXPECT(s, 13);
    EXPECT(file_scanners[route](s, "%d %4[a-z]%n", &a, word, &consumed) == 2, 14);
    EXPECT(a == 31 && strcmp(word, "word") == 0 && consumed == 7 && ftello(s) == 7, 15);
    EXPECT(fgetc(s) == '!' && fgetc(s) == EOF && feof(s), 16);
    EXPECT(fclose(s) == 0, 17);

    char empty = 0;
    s = scan_memory(&empty, 0); EXPECT(s, 18);
    EXPECT(file_scanners[route](s, "%d", &a) == EOF && feof(s) && !ferror(s), 19);
    EXPECT(fclose(s) == 0, 20);
    return 0;
}

int scan_standard_input(unsigned route) {
    EXPECT(route < 6, 1);
    char text[] = "41 59!";
    FILE *s = scan_memory(text, sizeof text - 1); EXPECT(s, 2);
    FILE *saved = stdin;
    stdin = s;
    int a = 0, consumed = -1; unsigned b = 0;
    int result = input_scanners[route]("%d %u%n", &a, &b, &consumed);
    stdin = saved;
    int tail = fgetc(s);
    int closed = fclose(s);
    EXPECT(result == 2 && a == 41 && b == 59 && consumed == 5, 3);
    EXPECT(tail == '!' && closed == 0, 4);
    return 0;
}

char *scan_allocate(unsigned route, int stream) {
    if (route >= 6) return 0;
    char *word = 0; int consumed = -1, result;
    char input[] = "allocated tail";
    if (stream) {
        FILE *s = scan_memory(input, sizeof input - 1);
        if (!s) return 0;
        result = file_scanners[route](s, "%ms%n", &word, &consumed);
        if (fclose(s)) { free(word); return 0; }
    } else {
        result = string_scanners[route](input, "%ms%n", &word, &consumed);
    }
    if (result != 1 || consumed != 9) { free(word); return 0; }
    return word;
}
void scan_release(void *pointer) { free(pointer); }
#endif

#ifdef LIFECYCLE_PATH
static int init_result;
__attribute__((constructor)) static void initialize(void) {
    FILE *s=fopen(LIFECYCLE_PATH,"w");
    if(!s) {init_result=1;return;}
    int a=fputs("init\n",s); int b=fclose(s); init_result=a<0||b!=0;
}
int stream_init_result(void) { return init_result; }
__attribute__((destructor)) static void finalize(void) {
    FILE *s=fopen(LIFECYCLE_PATH,"a");
    if(s) { fputs("fini\n",s); fclose(s); }
}
#endif
#ifdef BAD_IMPORT
extern void missing_native_stream_import(void);
void stream_bad_import(void) { missing_native_stream_import(); }
#endif
#ifdef LOCAL_OVERRIDE
int fputs(const char *text, FILE *stream) { (void)text; (void)stream; return 917; }
#endif
"#;

fn frontends() -> Vec<(&'static str, *const ())> {
    vec![
        ("fopen", stdio::fopen as *const ()),
        ("fdopen", stdio::fdopen as *const ()),
        ("freopen", stdio::freopen as *const ()),
        ("fclose", stdio::fclose as *const ()),
        ("fread", stdio::fread as *const ()),
        ("fwrite", stdio::fwrite as *const ()),
        ("fgetc", stdio::fgetc as *const ()),
        ("fputc", stdio::fputc as *const ()),
        ("fgets", stdio::fgets as *const ()),
        ("fputs", stdio::fputs as *const ()),
        ("ungetc", stdio::ungetc as *const ()),
        ("fseek", stdio::fseek as *const ()),
        ("ftell", stdio::ftell as *const ()),
        ("rewind", stdio::rewind as *const ()),
        ("feof", stdio::feof as *const ()),
        ("ferror", stdio::ferror as *const ()),
        ("clearerr", stdio::clearerr as *const ()),
        ("fflush", stdio::fflush as *const ()),
        ("setbuf", stdio::setbuf as *const ()),
        ("setvbuf", stdio::setvbuf as *const ()),
        ("fileno", stdio::fileno as *const ()),
        ("flockfile", stdio::flockfile as *const ()),
        ("ftrylockfile", stdio::ftrylockfile as *const ()),
        ("funlockfile", stdio::funlockfile as *const ()),
        ("fopen64", stdio::fopen64 as *const ()),
        ("freopen64", stdio::freopen64 as *const ()),
        ("fseeko", stdio::fseeko as *const ()),
        ("ftello", stdio::ftello as *const ()),
        ("fseeko64", stdio::fseeko64 as *const ()),
        ("ftello64", stdio::ftello64 as *const ()),
        ("fgetpos", stdio::fgetpos as *const ()),
        ("fsetpos", stdio::fsetpos as *const ()),
        ("fgetpos64", stdio::fgetpos64 as *const ()),
        ("fsetpos64", stdio::fsetpos64 as *const ()),
    ]
}

fn extended_frontends() -> Vec<(&'static CStr, *const ())> {
    vec![
        (c"fopencookie", stdio::fopencookie as *const ()),
        (c"tmpfile", stdio::tmpfile as *const ()),
        (c"tmpfile64", stdio::tmpfile64 as *const ()),
        (c"popen", stdio::popen as *const ()),
        (c"pclose", stdio::pclose as *const ()),
        (c"getc", stdio::getc as *const ()),
        (c"putc", stdio::putc as *const ()),
        (c"getchar", stdio::getchar as *const ()),
        (c"putchar", stdio::putchar as *const ()),
        (c"getc_unlocked", stdio::getc_unlocked as *const ()),
        (c"putc_unlocked", stdio::putc_unlocked as *const ()),
        (c"fgetc_unlocked", stdio::fgetc_unlocked as *const ()),
        (c"fputc_unlocked", stdio::fputc_unlocked as *const ()),
        (c"getchar_unlocked", stdio::getchar_unlocked as *const ()),
        (c"putchar_unlocked", stdio::putchar_unlocked as *const ()),
        (c"fread_unlocked", stdio::fread_unlocked as *const ()),
        (c"fwrite_unlocked", stdio::fwrite_unlocked as *const ()),
        (c"fgets_unlocked", stdio::fgets_unlocked as *const ()),
        (c"fputs_unlocked", stdio::fputs_unlocked as *const ()),
        (c"fflush_unlocked", stdio::fflush_unlocked as *const ()),
        (c"feof_unlocked", stdio::feof_unlocked as *const ()),
        (c"ferror_unlocked", stdio::ferror_unlocked as *const ()),
        (c"clearerr_unlocked", stdio::clearerr_unlocked as *const ()),
        (c"fileno_unlocked", stdio::fileno_unlocked as *const ()),
    ]
}

fn scan_frontends() -> Vec<(&'static CStr, *const (), &'static CStr)> {
    let base = c"GLIBC_2.2.5";
    let c99 = c"GLIBC_2.7";
    let c23 = c"GLIBC_2.38";
    vec![
        (c"scanf", stdio::scanf as *const (), base),
        (c"fscanf", stdio::fscanf as *const (), base),
        (c"sscanf", stdio::sscanf as *const (), base),
        (c"vscanf", stdio::vscanf as *const (), base),
        (c"vfscanf", stdio::vfscanf as *const (), base),
        (c"vsscanf", stdio::vsscanf as *const (), base),
        (c"__isoc99_scanf", stdio::__isoc99_scanf as *const (), c99),
        (c"__isoc99_fscanf", stdio::__isoc99_fscanf as *const (), c99),
        (c"__isoc99_sscanf", stdio::__isoc99_sscanf as *const (), c99),
        (c"__isoc99_vscanf", stdio::__isoc99_vscanf as *const (), c99),
        (
            c"__isoc99_vfscanf",
            stdio::__isoc99_vfscanf as *const (),
            c99,
        ),
        (
            c"__isoc99_vsscanf",
            stdio::__isoc99_vsscanf as *const (),
            c99,
        ),
        (c"__isoc23_scanf", isoc::__isoc23_scanf as *const (), c23),
        (c"__isoc23_fscanf", isoc::__isoc23_fscanf as *const (), c23),
        (c"__isoc23_sscanf", isoc::__isoc23_sscanf as *const (), c23),
        (c"__isoc23_vscanf", isoc::__isoc23_vscanf as *const (), c23),
        (
            c"__isoc23_vfscanf",
            isoc::__isoc23_vfscanf as *const (),
            c23,
        ),
        (
            c"__isoc23_vsscanf",
            isoc::__isoc23_vsscanf as *const (),
            c23,
        ),
    ]
}

#[derive(Clone, Copy)]
struct Api {
    open: Open,
    sym: Sym,
    close: Close,
    native: bool,
}
impl Api {
    fn new(native: bool) -> Self {
        if native {
            Self {
                open: dl::dlopen,
                sym: dl::dlsym,
                close: dl::dlclose,
                native,
            }
        } else {
            unsafe {
                Self {
                    open: dlsym_oracle::host_fn(c"dlopen", dl::dlopen as *const ()),
                    sym: dlsym_oracle::host_fn(c"dlsym", dl::dlsym as *const ()),
                    close: dlsym_oracle::host_fn(c"dlclose", dl::dlclose as *const ()),
                    native,
                }
            }
        }
    }
    fn open(self, path: &Path, flags: c_int) -> *mut c_void {
        let name = CString::new(path.as_os_str().as_bytes()).unwrap();
        let handle = unsafe { (self.open)(name.as_ptr(), flags | libc::RTLD_NOW) };
        if self.native && !dl::native_dso_handle_for_tests(handle) {
            report_native_load_failure(path);
        }
        assert!(!handle.is_null(), "dlopen {name:?}");
        if self.native {
            assert!(
                dl::native_dso_handle_for_tests(handle),
                "host fallback: {name:?}"
            );
        }
        handle
    }
    fn symbol(self, handle: *mut c_void, name: &CStr) -> *mut c_void {
        let value = unsafe { (self.sym)(handle, name.as_ptr()) };
        assert!(!value.is_null(), "dlsym {name:?}");
        value
    }
    fn close(self, handle: *mut c_void) {
        assert_eq!(unsafe { (self.close)(handle) }, 0);
    }
    fn loaded(self, path: &Path) -> bool {
        let path = CString::new(path.as_os_str().as_bytes()).unwrap();
        let handle = unsafe { (self.open)(path.as_ptr(), libc::RTLD_NOW | libc::RTLD_NOLOAD) };
        if handle.is_null() {
            false
        } else {
            self.close(handle);
            true
        }
    }
}

// Emit the rejected fixture's bounded ELF metadata in the failing test log,
// including when native rejection was hidden by a disallowed host fallback.
fn report_native_load_failure(path: &Path) {
    // SAFETY: dlerror returns this thread's terminated message, valid until
    // another loader error call. Read it before spawning the diagnostic tool.
    let error = unsafe { dl::dlerror() };
    if error.is_null() {
        eprintln!("native load failure {path:?}: dlerror unavailable");
    } else {
        let message = unsafe { CStr::from_ptr(error) };
        eprintln!("native load failure {path:?}: {message:?}");
    }
    match Command::new("readelf")
        .args(["-lW", "-x", ".eh_frame_hdr", "-x", ".eh_frame"])
        .arg(path)
        .output()
    {
        Ok(output) => eprintln!(
            "native load fixture {path:?}: readelf status={}\n{}\n{}",
            output.status,
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        ),
        Err(error) => eprintln!("native load fixture {path:?}: readelf failed: {error}"),
    }
}

struct Fixture {
    dir: PathBuf,
    library: PathBuf,
}
impl Fixture {
    fn new(extra: &[&str]) -> Self {
        let dir = std::env::temp_dir().join(format!(
            "frankenlibc-stream-{}-{}",
            std::process::id(),
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir(&dir).unwrap();
        let library = dir.join("libstream.so");
        let source = dir.join("stream.c");
        std::fs::write(&source, SOURCE).unwrap();
        let mut command = Command::new("gcc");
        command
            .args([
                "-shared",
                "-fPIC",
                "-nostdlib",
                "-O2",
                "-fno-builtin",
                "-fno-optimize-sibling-calls",
                "-U_FORTIFY_SOURCE",
                "-D_FORTIFY_SOURCE=0",
                "-Wall",
                "-Wextra",
                "-Werror",
                "-Wl,--hash-style=both",
            ])
            .arg(format!(
                "-DLIFECYCLE_PATH=\"{}\"",
                dir.join("lifecycle.txt").display()
            ))
            .args(extra)
            .arg(&source)
            .arg("-o")
            .arg(&library);
        let output = command.output().expect("gcc is required");
        assert!(
            output.status.success(),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
        let object = ElfLoader::new(0)
            .parse(&std::fs::read(&library).unwrap())
            .unwrap();
        assert!(
            object.needed_libraries.is_empty(),
            "host dependencies are forbidden"
        );
        // Verify the generated DSO really imports the selected stream API.
        for name in [
            "fopen",
            "fclose",
            "fread",
            "fwrite",
            "fdopen",
            "flockfile",
            "fflush",
        ] {
            assert!(
                object
                    .undefined_symbols()
                    .any(|(_, symbol)| object.symbol_name(symbol) == Some(name)),
                "compiler elided import {name}"
            );
        }
        if extra.contains(&"-DEXTENDED_STREAMS") {
            for (name, _) in extended_frontends() {
                let name = name.to_str().unwrap();
                assert!(
                    object
                        .undefined_symbols()
                        .any(|(_, symbol)| object.symbol_name(symbol) == Some(name)),
                    "compiler elided extended stream import {name}"
                );
            }
        }
        if extra.contains(&"-DSCAN_INPUT") {
            for (name, _, _) in scan_frontends() {
                let name = name.to_str().unwrap();
                assert!(
                    object
                        .undefined_symbols()
                        .any(|(_, symbol)| object.symbol_name(symbol) == Some(name)),
                    "compiler elided scanner import {name}"
                );
            }
        }
        Self { dir, library }
    }
    fn path(&self, name: &str) -> CString {
        CString::new(self.dir.join(name).as_os_str().as_bytes()).unwrap()
    }
}

fn check_frontend(
    api: Api,
    query: Frontend,
    index: usize,
    name: &CStr,
    expected: *const (),
    version: &CStr,
) {
    // Resolve the incumbent independently; a host-loaded fixture must bind to
    // this exact provider, and a native fixture must bind to the Rust frontend.
    let host = unsafe { dlsym_oracle::host_addr_versioned(name, version, expected) };
    let direct = unsafe { query(index, 0, std::ptr::null()) };
    assert_eq!(
        direct,
        if api.native {
            expected.cast_mut().cast()
        } else {
            host
        },
        "{name:?}: wrong provider"
    );
    assert_eq!(
        direct,
        unsafe { query(index, 1, std::ptr::null()) },
        "{name:?}: direct/dynamic mismatch"
    );
    assert_eq!(
        direct,
        unsafe { query(index, 1, version.as_ptr()) },
        "{name:?}: versioned mismatch"
    );
    for unsupported in [
        c"GLIBC_2.2.5",
        c"GLIBC_2.7",
        c"GLIBC_2.38",
        c"GLIBC_PRIVATE",
        c"GLIBC_9.99",
    ] {
        if unsupported != version {
            assert!(
                unsafe { query(index, 1, unsupported.as_ptr()) }.is_null(),
                "{name:?}: accepted unsupported version {unsupported:?}"
            );
        }
    }
}

fn check_scan_frontends(api: Api, handle: *mut c_void) {
    let count: unsafe extern "C" fn() -> usize =
        unsafe { std::mem::transmute(api.symbol(handle, c"scan_frontend_count")) };
    let query: Frontend = unsafe { std::mem::transmute(api.symbol(handle, c"scan_frontend")) };
    assert_eq!(unsafe { count() }, scan_frontends().len());
    for (index, (name, expected, version)) in scan_frontends().into_iter().enumerate() {
        check_frontend(api, query, index, name, expected, version);
    }
}

fn isolated(name: &str, native_only: bool, scenario: fn(Api)) {
    if let Ok(mode) = std::env::var("FRANKENLIBC_STREAM_CHILD") {
        assert!(mode == "host" || mode == "native");
        scenario(Api::new(mode == "native"));
        return;
    }
    for mode in if native_only {
        &["native"][..]
    } else {
        &["host", "native"][..]
    } {
        let mut child = Command::new(std::env::current_exe().unwrap())
            .args(["--exact", name, "--nocapture"])
            .env("FRANKENLIBC_STREAM_CHILD", mode)
            .spawn()
            .unwrap();
        let start = Instant::now();
        loop {
            if let Some(status) = child.try_wait().unwrap() {
                assert!(status.success(), "{name}: {mode}: {status}");
                break;
            }
            if start.elapsed() > Duration::from_secs(45) {
                child.kill().unwrap();
                child.wait().unwrap();
                panic!("{name}: {mode}: timeout");
            }
            std::thread::sleep(Duration::from_millis(10));
        }
    }
}

#[test]
fn stream_imports_and_dynamic_lookup_share_all_frontends() {
    isolated(
        "stream_imports_and_dynamic_lookup_share_all_frontends",
        false,
        |api| {
            for options in [&[][..], &["-fno-plt"][..]] {
                let f = Fixture::new(options);
                let h = api.open(&f.library, 0);
                let count: unsafe extern "C" fn() -> usize =
                    unsafe { std::mem::transmute(api.symbol(h, c"stream_frontend_count")) };
                let query: Frontend =
                    unsafe { std::mem::transmute(api.symbol(h, c"stream_frontend")) };
                assert_eq!(unsafe { count() }, frontends().len());
                for (index, (name, expected)) in frontends().into_iter().enumerate() {
                    let direct = unsafe { query(index, 0, std::ptr::null()) };
                    let dynamic = unsafe { query(index, 1, std::ptr::null()) };
                    let versioned = unsafe { query(index, 1, c"GLIBC_2.2.5".as_ptr()) };
                    assert_eq!(direct, dynamic, "{name}: direct/dynamic mismatch");
                    assert_eq!(direct, versioned, "{name}: versioned mismatch");
                    if api.native {
                        assert_eq!(
                            direct.cast_const().cast::<()>(),
                            expected,
                            "{name}: wrong Rust frontend"
                        );
                    }
                    assert!(unsafe { query(index, 1, c"GLIBC_PRIVATE".as_ptr()) }.is_null());
                }
                api.close(h);
            }
        },
    );
}

#[test]
fn stream_extended_frontends_bind_native_providers() {
    isolated(
        "stream_extended_frontends_bind_native_providers",
        false,
        |api| {
            for options in [
                &["-DEXTENDED_STREAMS"][..],
                &["-DEXTENDED_STREAMS", "-fno-plt"][..],
            ] {
                let fixture = Fixture::new(options);
                let handle = api.open(&fixture.library, 0);
                // SAFETY: these fixture exports have the exact C declarations above.
                let count: unsafe extern "C" fn() -> usize =
                    unsafe { std::mem::transmute(api.symbol(handle, c"extended_frontend_count")) };
                let query: Frontend =
                    unsafe { std::mem::transmute(api.symbol(handle, c"extended_frontend")) };
                assert_eq!(unsafe { count() }, extended_frontends().len());
                for (index, (name, expected)) in extended_frontends().into_iter().enumerate() {
                    check_frontend(api, query, index, name, expected, c"GLIBC_2.2.5");
                }
                api.close(handle);
            }
        },
    );
}

#[test]
fn stream_extended_streams_share_file_state() {
    isolated("stream_extended_streams_share_file_state", false, |api| {
        let fixture = Fixture::new(&["-DEXTENDED_STREAMS", "-fno-plt"]);
        let handle = api.open(&fixture.library, 0);
        // SAFETY: fixture functions keep their FILE/cookie objects alive through
        // each operation and close all streams before the DSO is unloaded.
        let temporary: unsafe extern "C" fn(c_int) -> c_int =
            unsafe { std::mem::transmute(api.symbol(handle, c"stream_temporary_unlocked")) };
        for large in [0, 1] {
            assert_eq!(unsafe { temporary(large) }, 0, "tmpfile variant {large}");
        }
        for name in [c"stream_cookie_unlocked", c"stream_process_unlocked"] {
            let call: unsafe extern "C" fn() -> c_int =
                unsafe { std::mem::transmute(api.symbol(handle, name)) };
            assert_eq!(unsafe { call() }, 0, "{name:?}");
        }
        api.close(handle);
    });
}

fn one_path(api: Api, symbol: &CStr, expected: Option<&[u8]>) {
    let f = Fixture::new(&[]);
    let h = api.open(&f.library, 0);
    let call: OnePath = unsafe { std::mem::transmute(api.symbol(h, symbol)) };
    assert_eq!(unsafe { call(f.path("output").as_ptr()) }, 0, "{symbol:?}");
    if let Some(expected) = expected {
        assert_eq!(std::fs::read(f.dir.join("output")).unwrap(), expected);
    }
    api.close(h);
}
#[test]
fn stream_binary_roundtrip_and_flush_visibility() {
    isolated(
        "stream_binary_roundtrip_and_flush_visibility",
        false,
        |api| one_path(api, c"stream_roundtrip", Some(b"ab\0cd\n!")),
    );
}

#[test]
fn stream_large_file_seeks_preserve_positions_and_sparse_bytes() {
    isolated(
        "stream_large_file_seeks_preserve_positions_and_sparse_bytes",
        false,
        |api| {
            use std::io::{Read, Seek, SeekFrom};

            let fixture = Fixture::new(&["-fno-plt"]);
            let handle = api.open(&fixture.library, 0);
            let query: Frontend =
                unsafe { std::mem::transmute(api.symbol(handle, c"stream_frontend")) };
            for (index, (name, expected)) in frontends().into_iter().enumerate() {
                let name = CString::new(name).unwrap();
                check_frontend(api, query, index, &name, expected, c"GLIBC_2.2.5");
            }
            let call: OnePath =
                unsafe { std::mem::transmute(api.symbol(handle, c"stream_large_offsets")) };
            assert_eq!(unsafe { call(fixture.path("sparse").as_ptr()) }, 0);
            let mut file = std::fs::File::open(fixture.dir.join("sparse")).unwrap();
            let offset = (5_u64 << 30) + 7;
            assert_eq!(file.metadata().unwrap().len(), offset + 6);
            file.seek(SeekFrom::Start(offset - 1)).unwrap();
            let mut bytes = [0; 7];
            file.read_exact(&mut bytes).unwrap();
            assert_eq!(&bytes, b"\0large!");
            api.close(handle);
        },
    );
}

#[test]
fn stream_scanning_aliases_preserve_variadic_values_and_versions() {
    isolated(
        "stream_scanning_aliases_preserve_variadic_values_and_versions",
        false,
        |api| {
            for options in [&["-DSCAN_INPUT"][..], &["-DSCAN_INPUT", "-fno-plt"][..]] {
                let fixture = Fixture::new(options);
                let handle = api.open(&fixture.library, 0);
                check_scan_frontends(api, handle);
                let call: unsafe extern "C" fn(u32) -> c_int =
                    unsafe { std::mem::transmute(api.symbol(handle, c"scan_values")) };
                for route in 0..6 {
                    assert_eq!(unsafe { call(route) }, 0, "scanner route {route}");
                }
                api.close(handle);
            }
        },
    );
}

#[test]
fn stream_scanning_dialects_preserve_prefix_counts_and_unread_input() {
    isolated(
        "stream_scanning_dialects_preserve_prefix_counts_and_unread_input",
        false,
        |api| {
            for options in [&["-DSCAN_INPUT"][..], &["-DSCAN_INPUT", "-fno-plt"][..]] {
                let fixture = Fixture::new(options);
                let handle = api.open(&fixture.library, 0);
                check_scan_frontends(api, handle);
                let call: unsafe extern "C" fn(u32, c_int) -> c_int =
                    unsafe { std::mem::transmute(api.symbol(handle, c"scan_dialects")) };
                for route in 0..6 {
                    for kind in 0..3 {
                        assert_eq!(
                            unsafe { call(route, kind) },
                            0,
                            "scanner route {route}, input kind {kind}"
                        );
                    }
                }
                api.close(handle);
            }
        },
    );
}

#[test]
fn stream_scanning_preserves_leftovers_offsets_and_failure_state() {
    isolated(
        "stream_scanning_preserves_leftovers_offsets_and_failure_state",
        false,
        |api| {
            let fixture = Fixture::new(&["-DSCAN_INPUT"]);
            let handle = api.open(&fixture.library, 0);
            check_scan_frontends(api, handle);
            let call: unsafe extern "C" fn(*const c_char, u32) -> c_int =
                unsafe { std::mem::transmute(api.symbol(handle, c"scan_streams")) };
            for route in 0..6 {
                assert_eq!(
                    unsafe { call(fixture.path("records").as_ptr(), route) },
                    0,
                    "scanner route {route}"
                );
                assert_eq!(
                    std::fs::read(fixture.dir.join("records")).unwrap(),
                    b"17 23 tail!"
                );
            }
            api.close(handle);
        },
    );
}

#[test]
fn stream_scanning_owns_allocations_and_honors_redirected_stdin() {
    isolated(
        "stream_scanning_owns_allocations_and_honors_redirected_stdin",
        false,
        |api| {
            let fixture = Fixture::new(&["-DSCAN_INPUT", "-fno-plt"]);
            let handle = api.open(&fixture.library, 0);
            check_scan_frontends(api, handle);
            let input: unsafe extern "C" fn(u32) -> c_int =
                unsafe { std::mem::transmute(api.symbol(handle, c"scan_standard_input")) };
            let allocate: unsafe extern "C" fn(u32, c_int) -> *mut c_char =
                unsafe { std::mem::transmute(api.symbol(handle, c"scan_allocate")) };
            let release: unsafe extern "C" fn(*mut c_void) =
                unsafe { std::mem::transmute(api.symbol(handle, c"scan_release")) };
            for route in 0..6 {
                assert_eq!(unsafe { input(route) }, 0, "stdin scanner route {route}");
                for stream in 0..2 {
                    let pointer = unsafe { allocate(route, stream) };
                    assert!(
                        !pointer.is_null(),
                        "allocation route {route}, stream={stream}"
                    );
                    assert_eq!(unsafe { CStr::from_ptr(pointer) }.to_bytes(), b"allocated");
                    if api.native {
                        assert!(
                            allocation::known_remaining_for_tests(pointer as usize)
                                .is_some_and(|remaining| remaining >= 10),
                            "scanner allocation escaped native ownership"
                        );
                    }
                    unsafe { release(pointer.cast()) };
                }
            }
            api.close(handle);
        },
    );
}

#[test]
fn stream_descriptor_transfer_and_failed_fdopen_ownership() {
    isolated(
        "stream_descriptor_transfer_and_failed_fdopen_ownership",
        false,
        |api| one_path(api, c"stream_fd_ownership", Some(b"descriptor")),
    );
}
#[test]
fn stream_eof_error_and_rewind_state() {
    isolated("stream_eof_error_and_rewind_state", false, |api| {
        one_path(api, c"stream_errors", Some(b"one\ntwo\n"))
    });
}
#[test]
fn stream_freopen_and_append_preserve_file_protocol() {
    isolated(
        "stream_freopen_and_append_preserve_file_protocol",
        false,
        |api| {
            let f = Fixture::new(&[]);
            let h = api.open(&f.library, 0);
            let call: unsafe extern "C" fn(*const c_char, *const c_char) -> c_int =
                unsafe { std::mem::transmute(api.symbol(h, c"stream_reopen")) };
            assert_eq!(
                unsafe { call(f.path("first").as_ptr(), f.path("second").as_ptr()) },
                0
            );
            assert_eq!(std::fs::read(f.dir.join("first")).unwrap(), b"old");
            assert_eq!(std::fs::read(f.dir.join("second")).unwrap(), b"new\n+");
            api.close(h);
        },
    );
}
#[test]
fn stream_recursive_locks_serialize_concurrent_records() {
    isolated(
        "stream_recursive_locks_serialize_concurrent_records",
        false,
        |api| {
            let f = Fixture::new(&[]);
            let h = api.open(&f.library, 0);
            let open: unsafe extern "C" fn(*const c_char) -> *mut c_void =
                unsafe { std::mem::transmute(api.symbol(h, c"stream_open_shared")) };
            let write: unsafe extern "C" fn(*mut c_void, c_int, usize) -> c_int =
                unsafe { std::mem::transmute(api.symbol(h, c"stream_write_locked")) };
            let close: unsafe extern "C" fn(*mut c_void) -> c_int =
                unsafe { std::mem::transmute(api.symbol(h, c"stream_close_shared")) };
            let stream = unsafe { open(f.path("records").as_ptr()) } as usize;
            assert_ne!(stream, 0);
            let workers = b"ABCD".map(|byte| {
                std::thread::spawn(move || {
                    assert_eq!(
                        unsafe { write(stream as *mut c_void, byte as c_int, 200) },
                        0
                    );
                })
            });
            for worker in workers {
                worker.join().unwrap();
            }
            assert_eq!(unsafe { close(stream as *mut c_void) }, 0);
            let bytes = std::fs::read(f.dir.join("records")).unwrap();
            assert_eq!(bytes.len(), 4 * 200 * 8);
            let mut counts = [0usize; 4];
            for line in bytes.as_chunks::<8>().0 {
                assert_eq!(line[7], b'\n');
                assert!((b'A'..=b'D').contains(&line[0]));
                assert!(line[..7].iter().all(|byte| *byte == line[0]));
                counts[(line[0] - b'A') as usize] += 1;
            }
            assert_eq!(counts, [200; 4]);
            api.close(h);
        },
    );
}
#[test]
fn stream_constructors_and_finalizers_use_runtime_streams() {
    isolated(
        "stream_constructors_and_finalizers_use_runtime_streams",
        false,
        |api| {
            let f = Fixture::new(&[]);
            let h = api.open(&f.library, 0);
            let init: unsafe extern "C" fn() -> c_int =
                unsafe { std::mem::transmute(api.symbol(h, c"stream_init_result")) };
            assert_eq!(unsafe { init() }, 0);
            assert_eq!(
                std::fs::read(f.dir.join("lifecycle.txt")).unwrap(),
                b"init\n"
            );
            api.close(h);
            assert_eq!(
                std::fs::read(f.dir.join("lifecycle.txt")).unwrap(),
                b"init\nfini\n"
            );
            assert!(!api.loaded(&f.library));
        },
    );
}
#[test]
fn stream_missing_strong_import_rolls_back_before_constructor_io() {
    isolated(
        "stream_missing_strong_import_rolls_back_before_constructor_io",
        false,
        |api| {
            let f = Fixture::new(&["-DBAD_IMPORT"]);
            let name = CString::new(f.library.as_os_str().as_bytes()).unwrap();
            assert!(unsafe { (api.open)(name.as_ptr(), libc::RTLD_NOW) }.is_null());
            assert!(!f.dir.join("lifecycle.txt").exists());
            assert!(!api.loaded(&f.library));
            // Refusal did not poison the native/host stream registry for the next load.
            one_path(api, c"stream_roundtrip", Some(b"ab\0cd\n!"));
        },
    );
}
#[test]
fn stream_native_overrides_precede_runtime_and_retain_provider() {
    isolated(
        "stream_native_overrides_precede_runtime_and_retain_provider",
        true,
        |api| {
            let provider = Fixture::new(&["-DLOCAL_OVERRIDE"]);
            let p = api.open(&provider.library, libc::RTLD_GLOBAL);
            let expected = api.symbol(p, c"fputs");
            let consumer = Fixture::new(&[]);
            let c = api.open(&consumer.library, 0);
            let query: Frontend = unsafe { std::mem::transmute(api.symbol(c, c"stream_frontend")) };
            let index = frontends()
                .iter()
                .position(|(name, _)| *name == "fputs")
                .unwrap();
            assert_eq!(unsafe { query(index, 0, std::ptr::null()) }, expected);
            assert_eq!(unsafe { query(index, 1, std::ptr::null()) }, expected);
            api.close(p);
            assert!(api.loaded(&provider.library));
            let own = Fixture::new(&["-DLOCAL_OVERRIDE"]);
            let d = api.open(&own.library, libc::RTLD_DEEPBIND);
            let own_expected = api.symbol(d, c"fputs");
            assert_ne!(own_expected, expected);
            let own_query: Frontend =
                unsafe { std::mem::transmute(api.symbol(d, c"stream_frontend")) };
            assert_eq!(
                unsafe { own_query(index, 0, std::ptr::null()) },
                own_expected
            );
            assert_eq!(
                unsafe { own_query(index, 1, std::ptr::null()) },
                own_expected
            );
            api.close(d);
            api.close(c);
            assert!(!api.loaded(&provider.library));
        },
    );
}
