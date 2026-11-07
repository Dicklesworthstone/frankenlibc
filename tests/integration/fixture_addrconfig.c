/* Compare deployed getaddrinfo results across controlled network namespaces.
 * Sort stdout externally to ignore address ordering while retaining duplicates.
 * An optional argument pins both resolver symbols to that shared object's inode.
 */
#define _GNU_SOURCE
#include <arpa/inet.h>
#include <dlfcn.h>
#include <inttypes.h>
#include <netdb.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>

typedef int (*resolve_fn)(const char *, const char *, const struct addrinfo *,
                          struct addrinfo **);
typedef void (*release_fn)(struct addrinfo *);

static int provider_matches(void *symbol, const char *name, const char *expected) {
    Dl_info info;
    struct stat actual, wanted;
    if (symbol == NULL || dladdr(symbol, &info) == 0 || info.dli_fname == NULL ||
        stat(info.dli_fname, &actual) != 0) {
        fprintf(stderr, "cannot identify provider of %s\n", name);
        return 0;
    }
    if (expected != NULL &&
        (stat(expected, &wanted) != 0 || actual.st_dev != wanted.st_dev ||
         actual.st_ino != wanted.st_ino)) {
        fprintf(stderr, "%s provider is %s, expected %s\n", name,
                info.dli_fname, expected);
        return 0;
    }
    return 1;
}

static int run_case(unsigned id, const char *node, int family, int flags,
                    int null_hints, resolve_fn resolve, release_fn release) {
    struct addrinfo hints = {0}, *result = NULL;
    hints.ai_family = family;
    hints.ai_flags = flags;
    int rc = resolve(node, "80", null_hints ? NULL : &hints, &result);
    size_t count = 0;
    if ((rc == 0) != (result != NULL)) {
        fprintf(stderr, "case %u: inconsistent result pointer and rc=%d\n", id, rc);
        return 1;
    }
    for (const struct addrinfo *entry = result; entry != NULL;
         entry = entry->ai_next) {
        unsigned char raw[16];
        size_t width;
        unsigned port;
        uint32_t scope = 0;
        if (++count > 1024 || entry->ai_addr == NULL) {
            fprintf(stderr, "case %u: invalid or cyclic address chain\n", id);
            return 1;
        }
        if (entry->ai_family == AF_INET &&
            entry->ai_addrlen == sizeof(struct sockaddr_in)) {
            struct sockaddr_in address;
            memcpy(&address, entry->ai_addr, sizeof(address));
            if (address.sin_family != AF_INET) {
                fprintf(stderr, "case %u: inconsistent IPv4 family\n", id);
                return 1;
            }
            width = sizeof(address.sin_addr);
            memcpy(raw, &address.sin_addr, width);
            port = ntohs(address.sin_port);
        } else if (entry->ai_family == AF_INET6 &&
                   entry->ai_addrlen == sizeof(struct sockaddr_in6)) {
            struct sockaddr_in6 address;
            memcpy(&address, entry->ai_addr, sizeof(address));
            if (address.sin6_family != AF_INET6) {
                fprintf(stderr, "case %u: inconsistent IPv6 family\n", id);
                return 1;
            }
            width = sizeof(address.sin6_addr);
            memcpy(raw, &address.sin6_addr, width);
            port = ntohs(address.sin6_port);
            scope = address.sin6_scope_id;
        } else {
            fprintf(stderr, "case %u: unsupported address family or length\n", id);
            return 1;
        }
        printf("case=%02u address family=%d flags=%d socktype=%d protocol=%d "
               "port=%u scope=%" PRIu32 " raw=", id, entry->ai_family,
               entry->ai_flags, entry->ai_socktype, entry->ai_protocol, port, scope);
        for (size_t i = 0; i < width; ++i)
            printf("%02x", (unsigned)raw[i]);
        putchar('\n');
    }
    printf("case=%02u result node=%s family=%d flags=%d null_hints=%d rc=%d "
           "count=%zu\n", id, node == NULL ? "NULL" : node, family, flags,
           null_hints, rc, count);
    if (result != NULL)
        release(result);
    return 0;
}

int main(int argc, char **argv) {
    if (argc > 2) {
        fprintf(stderr, "usage: %s [expected-provider.so]\n", argv[0]);
        return 2;
    }
    const char *expected = argc == 2 ? argv[1] : NULL;
    void *resolve_symbol = dlsym(RTLD_DEFAULT, "getaddrinfo");
    void *release_symbol = dlsym(RTLD_DEFAULT, "freeaddrinfo");
    if (!provider_matches(resolve_symbol, "getaddrinfo", expected) ||
        !provider_matches(release_symbol, "freeaddrinfo", expected))
        return 1;
    resolve_fn resolve = (resolve_fn)resolve_symbol;
    release_fn release = (release_fn)release_symbol;
    const char *nodes[] = {"127.0.0.1", "192.0.2.9", "::1", "2001:db8::9",
                           "::ffff:192.0.2.9", "fe80::1%1", NULL};
    const int families[] = {AF_UNSPEC, AF_INET, AF_INET6};
    const int flags[] = {0, AI_ADDRCONFIG, AI_ADDRCONFIG | AI_V4MAPPED,
                         AI_ADDRCONFIG | AI_V4MAPPED | AI_ALL};
    unsigned count = 0;
    for (size_t n = 0; n < sizeof(nodes) / sizeof(nodes[0]); ++n) {
        for (size_t f = 0; f < sizeof(families) / sizeof(families[0]); ++f) {
            for (size_t a = 0; a < sizeof(flags) / sizeof(flags[0]); ++a) {
                if (run_case(count++, nodes[n], families[f], flags[a], 0,
                             resolve, release) != 0)
                    return 1;
            }
        }
        if (run_case(count++, nodes[n], AF_UNSPEC, 0, 1, resolve, release) != 0)
            return 1;
    }
    if (count != 91) {
        fprintf(stderr, "unexpected case count: %u\n", count);
        return 1;
    }
    printf("addrconfig: %u cases\n", count);
    return ferror(stdout) ? 1 : 0;
}
