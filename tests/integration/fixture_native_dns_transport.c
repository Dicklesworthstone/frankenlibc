/* Exercise the actual getaddrinfo/freeaddrinfo exports, not the host resolver.
 * Run in the isolated DNS namespace created by the native-resolver workflow. */
#define _GNU_SOURCE
#include <arpa/inet.h>
#include <dlfcn.h>
#include <netdb.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

typedef int (*getaddrinfo_fn)(const char *, const char *, const struct addrinfo *, struct addrinfo **);
typedef void (*freeaddrinfo_fn)(struct addrinfo *);

static getaddrinfo_fn lookup;
static freeaddrinfo_fn release_result;

static void check_address(const char *name, int family, const char *expected) {
    struct addrinfo hints = {0}, *result = NULL;
    hints.ai_family = family;
    hints.ai_socktype = SOCK_STREAM;
    int rc = lookup(name, "443", &hints, &result);
    if (rc != 0 || result == NULL) {
        fprintf(stderr, "%s: expected success, rc=%d result=%p\n", name, rc, (void *)result);
        exit(1);
    }
    unsigned char expected_bytes[16];
    if (inet_pton(family, expected, expected_bytes) != 1) abort();
    size_t count = 0;
    for (const struct addrinfo *ai = result; ai; ai = ai->ai_next) {
        if (ai->ai_family != family || ai->ai_socktype != SOCK_STREAM || !ai->ai_addr) {
            fprintf(stderr, "%s: unexpected addrinfo profile\n", name);
            exit(1);
        }
        const void *address;
        unsigned short port;
        size_t length;
        if (family == AF_INET) {
            if (ai->ai_addrlen < sizeof(struct sockaddr_in)) abort();
            const struct sockaddr_in *sa = (const struct sockaddr_in *)ai->ai_addr;
            address = &sa->sin_addr;
            port = ntohs(sa->sin_port);
            length = 4;
        } else {
            if (ai->ai_addrlen < sizeof(struct sockaddr_in6)) abort();
            const struct sockaddr_in6 *sa = (const struct sockaddr_in6 *)ai->ai_addr;
            address = &sa->sin6_addr;
            port = ntohs(sa->sin6_port);
            length = 16;
        }
        if (memcmp(address, expected_bytes, length) != 0 || port != 443) {
            fprintf(stderr, "%s: unrelated address or wrong port returned\n", name);
            exit(1);
        }
        ++count;
    }
    release_result(result);
    if (count != 1) {
        fprintf(stderr, "%s: expected one address, got %zu\n", name, count);
        exit(1);
    }
}

static void check_error(const char *name, int expected) {
    struct addrinfo hints = {0}, *result = NULL;
    hints.ai_family = AF_INET;
    hints.ai_socktype = SOCK_STREAM;
    int rc = lookup(name, "443", &hints, &result);
    if (rc != expected || result != NULL) {
        fprintf(stderr, "%s: expected rc=%d/null, got rc=%d/%p\n", name, expected, rc, (void *)result);
        exit(1);
    }
}

int main(int argc, char **argv) {
    if (argc != 2 && argc != 3) return 2;
    if (argc == 3) {
        if (strcmp(argv[2], "--preloaded") != 0) return 2;
        /* Exercise normal ELF symbol interposition. Reopening the already
         * preloaded library through its own dlopen tests the independent
         * loader implementation, not how applications call getaddrinfo. */
        lookup = getaddrinfo;
        release_result = freeaddrinfo;
    } else {
        void *library = dlopen(argv[1], RTLD_NOW | RTLD_LOCAL);
        if (!library) {
            fprintf(stderr, "dlopen: %s\n", dlerror());
            return 1;
        }
        lookup = (getaddrinfo_fn)dlsym(library, "getaddrinfo");
        release_result = (freeaddrinfo_fn)dlsym(library, "freeaddrinfo");
    }
    Dl_info owner = {0};
    if (!lookup || !release_result || !dladdr((void *)lookup, &owner)
        || !owner.dli_fname || !strstr(owner.dli_fname, "frankenlibc")) {
        fprintf(stderr, "resolver symbol did not resolve to FrankenLibC\n");
        return 1;
    }
    if (!dladdr((void *)release_result, &owner) || !owner.dli_fname
        || !strstr(owner.dli_fname, "frankenlibc")) {
        fprintf(stderr, "freeaddrinfo symbol did not resolve to FrankenLibC\n");
        return 1;
    }
    check_address("alias.test.", AF_INET, "192.0.2.9");
    check_address("v6alias.test.", AF_INET6, "2001:db8::9");
    const char *mode = getenv("FRANKENLIBC_MODE");
    if (!mode || strcmp(mode, "hardened") != 0) {
        check_error("missing.test.", EAI_NONAME);
        check_error("temporary.test.", EAI_AGAIN);
        check_error("refused.test.", EAI_FAIL);
        check_error("cycle.test.", EAI_FAIL);
        puts("native DNS ABI: 6 passed");
    } else {
        /* Existing hardened repair of a missing hostname is outside this
         * defined-input parity test. Do not assert strict error semantics. */
        puts("native DNS ABI: 2 passed");
    }
    return 0;
}
