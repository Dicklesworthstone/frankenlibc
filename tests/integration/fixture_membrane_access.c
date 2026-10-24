#define _GNU_SOURCE
#include <dlfcn.h>
#include <errno.h>
#include <gnu/libc-version.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <time.h>

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
static int (*compare_bytes)(const void *, const void *, size_t);
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

static void bind_symbols(const char *library) {
    allocate_bytes = required_symbol("malloc", library);
    release_bytes = required_symbol("free", library);
    copy_bytes = required_symbol("memcpy", library);
    move_bytes = required_symbol("memmove", library);
    fill_bytes = required_symbol("memset", library);
    compare_bytes = required_symbol("memcmp", library);
    string_length = required_symbol("strlen", library);
    bounded_length = required_symbol("strnlen", library);
}

static void print_json_string(const char *text) {
    putchar('"');
    for (const unsigned char *p = (const unsigned char *)text; *p; ++p) {
        if (*p == '"' || *p == '\\') putchar('\\');
        if (*p < 0x20) printf("\\u%04x", (unsigned)*p);
        else putchar(*p);
    }
    putchar('"');
}

/* Valid warmed calls only. Fault probes below remain fresh/cold processes.
 * Every length is reported separately; a mixed-length average cannot hide a
 * short-call budget miss. Both heap allocation and operations use one provider. */
static int benchmark(const char *library, const char *operation,
                     const char *length_arg, const char *iterations_arg) {
    char *end;
    errno = 0;
    unsigned long n = strtoul(length_arg, &end, 10);
    if (errno || end == length_arg || *end || n >= CAPACITY || *length_arg == '-') return 2;
    errno = 0;
    unsigned long iterations = strtoul(iterations_arg, &end, 10);
    if (errno || end == iterations_arg || *end || !iterations || iterations > 100000000 ||
        *iterations_arg == '-') return 2;
    int length = strcmp(operation, "strlen-stack") == 0 || strcmp(operation, "strlen-heap") == 0;
    int compare = strcmp(operation, "memcmp-stack") == 0 || strcmp(operation, "memcmp-heap") == 0;
    int heap = strcmp(operation, "strlen-heap") == 0 || strcmp(operation, "memcmp-heap") == 0;
    if (!(length || compare)) return 2;
    Dl_info info;
    if (strcmp(library, "host") == 0) {
        if (!dladdr(dlsym(RTLD_DEFAULT, "malloc"), &info) ||
            !strstr(info.dli_fname, "libc.so.6")) {
            fprintf(stderr, "provider rejection: host malloc is not GNU libc\n");
            return 2;
        }
        library = info.dli_fname;
    }
    bind_symbols(library);
    unsigned char stack_left[CAPACITY], stack_right[CAPACITY];
    unsigned char *left = heap ? allocate_bytes(CAPACITY) : stack_left;
    unsigned char *right = heap ? allocate_bytes(CAPACITY) : stack_right;
    if (!left || !right) { perror("benchmark malloc"); return 2; }
    store_pattern(left, CAPACITY, 0x35);
    store_pattern(right, CAPACITY, 0x35);
    left[n] = right[n] = 0;
    if (compare && n) right[n - 1] = 0x36;
    /* Resolve dispatch and warm validation before the timed interval. */
    if (length) (void)string_length((const char *)left);
    else (void)compare_bytes(left, right, n);
    struct timespec start, finish;
    if (clock_gettime(CLOCK_MONOTONIC, &start)) { perror("clock_gettime"); return 2; }
    uint64_t checksum = 0;
    if (length) {
        for (unsigned long i = 0; i < iterations; ++i)
            checksum += string_length((const char *)left);
    } else {
        for (unsigned long i = 0; i < iterations; ++i) {
            int result = (i & 1) ? compare_bytes(right, left, n) : compare_bytes(left, right, n);
            checksum += result > 0;
        }
    }
    if (clock_gettime(CLOCK_MONOTONIC, &finish)) { perror("clock_gettime"); return 2; }
    int64_t elapsed = (int64_t)(finish.tv_sec - start.tv_sec) * 1000000000 +
                      finish.tv_nsec - start.tv_nsec;
    uint64_t expected = length ? (uint64_t)n * iterations : (n ? iterations / 2 : 0);
    if (heap) { release_bytes(left); release_bytes(right); }
    if (checksum != expected || elapsed <= 0) {
        fprintf(stderr, "benchmark result mismatch or nonpositive clock interval\n");
        return 1;
    }
    printf("{\"operation\":\"%s\",\"length\":%lu,\"iterations\":%lu,"
           "\"elapsed_ns\":%lld,\"checksum\":%llu,\"provider\":",
           operation, n, iterations, (long long)elapsed, (unsigned long long)checksum);
    print_json_string(library);
    printf(",\"glibc_version\":\"%s\"}\n", gnu_get_libc_version());
    return 0;
}

int main(int argc, char **argv) {
    if (argc == 6 && strcmp(argv[2], "benchmark") == 0)
        return benchmark(argv[1], argv[3], argv[4], argv[5]);
    if (argc != 4) {
        fprintf(stderr, "usage: %s LIBRARY OPERATION valid|header|canary|end|quarantine\n", argv[0]);
        fprintf(stderr, "       %s LIBRARY|host benchmark strlen-stack|strlen-heap|memcmp-stack|memcmp-heap LENGTH ITERATIONS\n", argv[0]);
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
    int comparing = strcmp(operation, "memcmp-lhs") == 0 || strcmp(operation, "memcmp-rhs") == 0;
    int compare_rhs = strcmp(operation, "memcmp-rhs") == 0;
    int length = strcmp(operation, "strlen") == 0;
    int bounded = strcmp(operation, "strnlen") == 0;
    int source = strcmp(operation, "memcpy-src") == 0 || strcmp(operation, "memmove-src") == 0;
    if (!(valid || header || canary || end || quarantine) ||
        !(copying || moving || filling || comparing || length || bounded) ||
        (quarantine && !(source || comparing || length || bounded)) ||
        (end && !(copying || moving || filling || comparing))) {
        fprintf(stderr, "unsupported probe combination\n");
        return 2;
    }
    const char *mode = getenv("FRANKENLIBC_MODE");
    if (!valid && (!mode || strcmp(mode, "hardened") != 0)) {
        fprintf(stderr, "fault injection requires explicit hardened mode\n");
        return 2;
    }
    bind_symbols(library);

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
    } else if (comparing) {
        const void *left = compare_rhs ? input : access;
        const void *right = compare_rhs ? access : input;
        int result = compare_bytes(left, right, COPY_SIZE);
        /* Valid operands differ in the first byte (0x35 versus 0xC7).
         * A denied/clamped-to-zero operand must instead yield the safe default,
         * in either position, without reading corrupt or quarantined storage. */
        ok = valid ? (compare_rhs ? result > 0 : result < 0) : result == 0;
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
