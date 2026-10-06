/* Clean-room ABI regression probe. Pass --host or the rebuilt ABI .so path.
 * Symbols are pinned to their owning DSO: a missing FrankenLibC export must
 * fail, not silently turn this into a test of a dependency's host libc.
 */
#define _GNU_SOURCE
#include <arpa/inet.h>
#include <dlfcn.h>
#include <errno.h>
#include <limits.h>
#include <netdb.h>
#include <pthread.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

typedef struct hostent *(*reverse_fn)(const void *, socklen_t, int);
typedef int (*reverse_r_fn)(const void *, socklen_t, int, struct hostent *,
                            char *, size_t, struct hostent **, int *);
struct api { reverse_fn reverse; reverse_r_fn reverse_r; };
static unsigned long calls;
static int candidate;

static void require(int condition, const char *message) {
    if (!condition) {
        fprintf(stderr, "FAIL: %s (after %lu ABI calls)\n", message, calls);
        exit(1);
    }
}

static void *symbol(void *handle, const char *name, const char *owner) {
    dlerror();
    void *p = dlsym(handle, name);
    const char *error = dlerror();
    if (!p || error) {
        fprintf(stderr, "missing %s: %s\n", name, error ? error : "null symbol");
        exit(1);
    }
    if (owner) {
        Dl_info info;
        struct stat expected, actual;
        require(dladdr(p, &info) != 0, "dladdr(symbol)");
        require(stat(owner, &expected) == 0 && stat(info.dli_fname, &actual) == 0,
                "stat symbol owner");
        require(expected.st_dev == actual.st_dev && expected.st_ino == actual.st_ino,
                "symbol resolved outside the requested FrankenLibC DSO");
    }
    return p;
}

static void address_bytes(const char *text, int family, unsigned char out[16]) {
    memset(out, 0, 16);
    require(inet_pton(family, text, out) == 1, "parse fixture address");
}

static int contains(const void *base, size_t capacity, const void *p, size_t size) {
    uintptr_t start = (uintptr_t)base, address = (uintptr_t)p;
    return address >= start && address - start <= capacity &&
           size <= capacity - (address - start);
}

static void check_result(const struct hostent *h, const unsigned char *address,
                         int family, const char *name, char *buf, size_t capacity) {
    size_t width = family == AF_INET6 ? 16 : 4;
    require(h != NULL, "reverse lookup returned no hostent");
    require(h->h_addrtype == family && h->h_length == (int)width,
            "hostent retains the original family and address width");
    require(h->h_name && h->h_addr_list && h->h_aliases, "complete hostent pointer tables");
    if (buf) {
        require(contains(buf, capacity, h->h_name, 1), "name lives in caller buffer");
        require(strnlen(h->h_name, capacity - ((uintptr_t)h->h_name - (uintptr_t)buf)) <
                capacity - ((uintptr_t)h->h_name - (uintptr_t)buf), "name is bounded and terminated");
        require(contains(buf, capacity, h->h_addr_list, 2 * sizeof(char *)),
                "address pointer table lives in caller buffer");
        require(contains(buf, capacity, h->h_aliases, sizeof(char *)),
                "alias pointer table lives in caller buffer");
        if (candidate) {
            require((uintptr_t)h->h_addr_list % _Alignof(char *) == 0,
                    "address pointer table is aligned");
            require((uintptr_t)h->h_aliases % _Alignof(char *) == 0,
                    "alias pointer table is aligned");
        }
    }
    /* Some host implementations use unaligned pointer tables when given an
     * unaligned char buffer. Read the oracle safely; require alignment from
     * FrankenLibC's explicitly aligned hostent writer. */
    char *first, *second;
    memcpy(&first, h->h_addr_list, sizeof first);
    memcpy(&second, (const char *)h->h_addr_list + sizeof first, sizeof second);
    require(first != NULL && second == NULL,
            "exactly one reverse address with a null terminator");
    if (buf) require(contains(buf, capacity, first, width),
                     "address bytes live in caller buffer");
    if (candidate) require((uintptr_t)first % _Alignof(struct in6_addr) == 0,
                           "returned address storage is aligned");
    require(memcmp(first, address, width) == 0, "exact original address bytes");
    if (name) require(strcmp(h->h_name, name) == 0, "canonical fixture hostname");
}

static void check_canaries(const unsigned char *arena, size_t size,
                           size_t offset, size_t capacity) {
    for (size_t i = 0; i < offset; ++i)
        require(arena[i] == 0xa5, "no write before caller buffer");
    for (size_t i = offset + capacity; i < size; ++i)
        require(arena[i] == 0xa5, "no write after caller buffer");
}

static void exercise(struct api api, const char *text, int family, const char *name) {
    unsigned char address[16];
    address_bytes(text, family, address);
    socklen_t width = family == AF_INET6 ? 16 : 4;
    ++calls;
    struct hostent *h = api.reverse(address, width, family);
    check_result(h, address, family, name, NULL, 0);

    /* Includes unaligned input and every possible pointer-table alignment. */
    unsigned char input[17];
    memcpy(input + 1, address, width);
    for (size_t alignment = 0; alignment < sizeof(void *); ++alignment) {
        unsigned char arena[560];
        memset(arena, 0xa5, sizeof arena);
        size_t offset = 8 + alignment;
        char *buf = (char *)arena + offset;
        struct hostent result_storage, *result = (void *)(uintptr_t)1;
        int host_error = 73;
        ++calls;
        int rc = api.reverse_r(input + 1, width, family, &result_storage,
                               buf, 512, &result, &host_error);
        require(rc == 0 && result == &result_storage, "reentrant reverse lookup succeeds");
        check_result(result, address, family, name, buf, 512);
        check_canaries(arena, sizeof arena, offset, 512);
    }

    /* Test the complete small-buffer boundary, not only an oversized happy path. */
    unsigned successes = 0, ranges = 0;
    for (size_t capacity = 0; capacity <= 256; ++capacity) {
        unsigned char arena[304];
        memset(arena, 0xa5, sizeof arena);
        const size_t offset = 9;
        char *buf = (char *)arena + offset;
        struct hostent result_storage, *result = (void *)(uintptr_t)1;
        int host_error = 73;
        ++calls;
        int rc = api.reverse_r(address, width, family, &result_storage,
                               buf, capacity, &result, &host_error);
        require(rc == ERANGE || rc == 0, "small buffer returns ERANGE or success");
        if (rc == ERANGE) {
            ++ranges;
            require(result == NULL, "ERANGE clears the result pointer");
        } else {
            ++successes;
            require(result == &result_storage, "successful reentrant result ownership");
            check_result(result, address, family, name, buf, capacity);
        }
        check_canaries(arena, sizeof arena, offset, capacity);
    }
    require(ranges > 0 && successes > 0, "small-buffer sweep crosses the success boundary");
}

struct worker { struct api api; unsigned char address[16]; const char *name; };
static void *other_thread(void *arg) {
    struct worker *worker = arg;
    struct hostent *h = worker->api.reverse(worker->address, 16, AF_INET6);
    check_result(h, worker->address, AF_INET6, worker->name, NULL, 0);
    return NULL;
}

static void tls_isolation(struct api api, int host) {
    unsigned char main_address[16];
    address_bytes(host ? "::1" : "2001:db8::42", AF_INET6, main_address);
    ++calls;
    struct hostent *main_result = api.reverse(main_address, 16, AF_INET6);
    const char *main_name = host ? NULL : "expanded-six";
    check_result(main_result, main_address, AF_INET6, main_name, NULL, 0);
    struct worker worker = { .api = api, .name = host ? NULL : "mapped-four" };
    address_bytes(host ? "::ffff:127.0.0.1" : "::ffff:192.0.2.17", AF_INET6, worker.address);
    pthread_t thread;
    ++calls;
    require(pthread_create(&thread, NULL, other_thread, &worker) == 0, "start TLS isolation thread");
    require(pthread_join(thread, NULL) == 0, "join TLS isolation thread");
    check_result(main_result, main_address, AF_INET6, main_name, NULL, 0);
}

static void fixture(void) {
    char directory[] = "/tmp/frankenlibc-reverse-ipv6-XXXXXX";
    require(mkdtemp(directory) != NULL, "create isolated fixture directory");
    char path[PATH_MAX];
    require(snprintf(path, sizeof path, "%s/hosts", directory) > 0, "hosts fixture path");
    FILE *file = fopen(path, "w");
    require(file != NULL, "open hosts fixture");
    require(fputs("::1 loopback-six\n"
                  "2001:0DB8:0000:0000:0000:0000:0000:0042 expanded-six alias-six\n"
                  "192.0.2.17 mapped-four\n", file) >= 0, "write hosts fixture");
    require(fclose(file) == 0, "close hosts fixture");
    require(setenv("FRANKENLIBC_HOSTS_PATH", path, 1) == 0, "select hosts fixture");
    printf("fixture=%s\n", path);
}

int main(int argc, char **argv) {
    require(argc == 2, "usage: native_reverse_ipv6 --host|/path/to/libfrankenlibc_abi.so");
    int host = strcmp(argv[1], "--host") == 0;
    candidate = !host;
    if (!host) fixture();
    void *handle = dlopen(host ? "libc.so.6" : argv[1], RTLD_NOW | RTLD_LOCAL);
    if (!handle) { fprintf(stderr, "dlopen: %s\n", dlerror()); return 1; }
    const char *owner = host ? NULL : argv[1];
    struct api api = {
        .reverse = (reverse_fn)symbol(handle, "gethostbyaddr", owner),
        .reverse_r = (reverse_r_fn)symbol(handle, "gethostbyaddr_r", owner),
    };
    exercise(api, "::1", AF_INET6, host ? NULL : "loopback-six");
    exercise(api, host ? "::ffff:127.0.0.1" : "::ffff:192.0.2.17",
             AF_INET6, host ? NULL : "mapped-four");
    if (!host) {
        exercise(api, "2001:db8::42", AF_INET6, "expanded-six");
        exercise(api, "192.0.2.17", AF_INET, "mapped-four");
        unsigned char address[16] = {0};
        char buf[512];
        struct hostent storage, *result = (void *)(uintptr_t)1;
        int host_error = 0;
        ++calls;
        require(api.reverse_r(address, 15, AF_INET6, &storage, buf, sizeof buf,
                              &result, &host_error) == EINVAL, "short IPv6 input is rejected");
        require(result == NULL && host_error == NO_RECOVERY, "invalid-input result/error contract");
        ++calls;
        require(api.reverse_r(NULL, 16, AF_INET6, &storage, buf, sizeof buf,
                              &result, &host_error) == EINVAL, "null IPv6 input is rejected");
    }
    /* glibc documents the nonreentrant calls as MT-unsafe; TLS isolation is
     * FrankenLibC's stronger implementation contract, not a host requirement. */
    if (!host) tls_isolation(api, 0);
    printf("PASS: %lu reverse-lookup ABI calls (%s)\n", calls, host ? "host oracle" : "candidate");
    return 0;
}
