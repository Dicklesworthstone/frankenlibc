#define _GNU_SOURCE
#include <dlfcn.h>
#include <errno.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>

/* Each invocation is a fresh LD_PRELOAD process. No access to a test hook is
 * required, and provider rejection happens before any fault injection. Build
 * with -fno-builtin: the operations must enter the exported libc functions.
 * Invalid accesses deliberately exercise the hardened contract, not ISO C. */
enum { CAPACITY = 64, COPY_SIZE = 8, HEADER_SIZE = 24 };

static void *(*allocate_bytes)(size_t);
static void (*release_bytes)(void *);
static void *(*copy_bytes)(void *, const void *, size_t);
static void *(*move_bytes)(void *, const void *, size_t);
static void *(*fill_bytes)(void *, int, size_t);
static size_t (*string_length)(const char *);
static size_t (*bounded_length)(const char *, size_t);

static int same_file(const char *left, const char *right) {
    struct stat a, b;
    return left && right && stat(left, &a) == 0 && stat(right, &b) == 0 &&
           a.st_dev == b.st_dev && a.st_ino == b.st_ino;
}

static void *required_symbol(const char *name, const char *library) {
    void *address = dlsym(RTLD_DEFAULT, name);
    Dl_info info;
    if (!address || !dladdr(address, &info) || !same_file(library, info.dli_fname)) {
        fprintf(stderr, "provider rejection: %s is not from %s\n", name, library);
        exit(2);
    }
    return address;
}

static void store_pattern(volatile unsigned char *p, size_t n, unsigned char byte) {
    for (size_t i = 0; i < n; ++i) p[i] = byte;
}

static int matches(const volatile unsigned char *p, size_t n, unsigned char byte) {
    for (size_t i = 0; i < n; ++i) if (p[i] != byte) return 0;
    return 1;
}

int main(int argc, char **argv) {
    if (argc != 4) {
        fprintf(stderr, "usage: %s LIBRARY OPERATION valid|header|canary|end|quarantine\n", argv[0]);
        return 2;
    }
    const char *library = argv[1], *operation = argv[2], *fault = argv[3];
    int valid = strcmp(fault, "valid") == 0;
    int header = strcmp(fault, "header") == 0;
    int canary = strcmp(fault, "canary") == 0;
    int end = strcmp(fault, "end") == 0;
    int quarantine = strcmp(fault, "quarantine") == 0;
    int copying = strcmp(operation, "memcpy-dst") == 0 || strcmp(operation, "memcpy-src") == 0;
    int moving = strcmp(operation, "memmove-dst") == 0 || strcmp(operation, "memmove-src") == 0;
    int filling = strcmp(operation, "memset") == 0;
    int length = strcmp(operation, "strlen") == 0;
    int bounded = strcmp(operation, "strnlen") == 0;
    int source = strcmp(operation, "memcpy-src") == 0 || strcmp(operation, "memmove-src") == 0;
    if (!(valid || header || canary || end || quarantine) ||
        !(copying || moving || filling || length || bounded) ||
        (quarantine && !(source || length || bounded)) ||
        (end && !(copying || moving || filling))) {
        fprintf(stderr, "unsupported probe combination\n");
        return 2;
    }
    const char *mode = getenv("FRANKENLIBC_MODE");
    if (!valid && (!mode || strcmp(mode, "hardened") != 0)) {
        fprintf(stderr, "fault injection requires explicit hardened mode\n");
        return 2;
    }
    allocate_bytes = required_symbol("malloc", library);
    release_bytes = required_symbol("free", library);
    copy_bytes = required_symbol("memcpy", library);
    move_bytes = required_symbol("memmove", library);
    fill_bytes = required_symbol("memset", library);
    string_length = required_symbol("strlen", library);
    bounded_length = required_symbol("strnlen", library);

    unsigned char *p = allocate_bytes(CAPACITY);
    if (!p) { perror("malloc"); return 2; }
    store_pattern(p, CAPACITY, 0x35);
    p[CAPACITY - 1] = 0;
    unsigned char input[COPY_SIZE], output[COPY_SIZE];
    store_pattern(input, COPY_SIZE, 0xC7);
    store_pattern(output, COPY_SIZE, 0x6B);

    /* Do not warm the allocation's validation cache before corrupting it. */
    volatile unsigned char *metadata = NULL;
    unsigned char saved = 0, tail[COPY_SIZE];
    if (header || canary) {
        metadata = header ? p - HEADER_SIZE : p + CAPACITY;
        saved = *metadata;
        *metadata = (unsigned char)(saved ^ 1);
    }
    if (end) for (size_t i = 0; i < COPY_SIZE; ++i) tail[i] = ((volatile unsigned char *)p)[CAPACITY + i];
    unsigned char *access = end ? p + CAPACITY : p;
    if (quarantine) release_bytes(p);

    int ok = 1;
    if (length || bounded) {
        size_t actual = length ? string_length((const char *)access) : bounded_length((const char *)access, 32);
        size_t expected = valid ? (length ? CAPACITY - 1 : 32) : 0;
        ok = actual == expected;
    } else {
        void *destination = source ? output : access;
        const void *origin = source ? access : input;
        void *result = filling ? fill_bytes(destination, 0xC7, COPY_SIZE) :
                       copying ? copy_bytes(destination, origin, COPY_SIZE) :
                                 move_bytes(destination, origin, COPY_SIZE);
        ok = result == destination;
        if (source) ok = ok && matches(output, COPY_SIZE, valid ? 0x35 : 0x6B);
        else if (!end) ok = ok && matches(p, COPY_SIZE, valid ? 0xC7 : 0x35);
    }
    if (end) {
        for (size_t i = 0; i < COPY_SIZE; ++i) {
            ok = ok && ((volatile unsigned char *)p)[CAPACITY + i] == tail[i];
            ((volatile unsigned char *)p)[CAPACITY + i] = tail[i];
        }
    }
    if (metadata) *metadata = saved;
    if (!quarantine) release_bytes(p);
    printf("operation=%s fault=%s result=%s\n", operation, fault, ok ? "pass" : "FAIL");
    return ok ? 0 : 1;
}
