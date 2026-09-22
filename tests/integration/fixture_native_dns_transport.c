/* Actual release C exports: forward/reverse DNS, files, services and bounds. */
#define _GNU_SOURCE
#include <arpa/inet.h>
#include <dlfcn.h>
#include <netdb.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

typedef int (*getaddrinfo_fn)(const char *, const char *, const struct addrinfo *, struct addrinfo **);
typedef void (*freeaddrinfo_fn)(struct addrinfo *);
typedef int (*getnameinfo_fn)(const struct sockaddr *, socklen_t, char *, socklen_t, char *, socklen_t, int);
static getaddrinfo_fn lookup;
static freeaddrinfo_fn release_result;
static getnameinfo_fn reverse_lookup;
static unsigned passed;

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
        if (ai->ai_family != family || ai->ai_socktype != SOCK_STREAM || !ai->ai_addr) abort();
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
            fprintf(stderr, "%s: unrelated address or wrong port\n", name);
            exit(1);
        }
        ++count;
    }
    release_result(result);
    if (count != 1) abort();
    ++passed;
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
    ++passed;
}

static socklen_t make_address(const char *text, unsigned port, struct sockaddr_storage *storage) {
    memset(storage, 0, sizeof(*storage));
    if (strchr(text, ':')) {
        struct sockaddr_in6 *sa = (struct sockaddr_in6 *)storage;
        sa->sin6_family = AF_INET6;
        sa->sin6_port = htons(port);
        if (inet_pton(AF_INET6, text, &sa->sin6_addr) != 1) abort();
        return sizeof(*sa);
    }
    struct sockaddr_in *sa = (struct sockaddr_in *)storage;
    sa->sin_family = AF_INET;
    sa->sin_port = htons(port);
    if (inet_pton(AF_INET, text, &sa->sin_addr) != 1) abort();
    return sizeof(*sa);
}

static void check_reverse(const char *address, unsigned port, int flags,
                          unsigned host_cap, unsigned serv_cap, int expected_rc,
                          const char *expected_host, const char *expected_serv) {
    struct sockaddr_storage sa;
    socklen_t length = make_address(address, port, &sa);
    char host[1025], service[128];
    memset(host, 0x5a, sizeof(host));
    memset(service, 0x5a, sizeof(service));
    if (host_cap >= sizeof(host) || serv_cap >= sizeof(service)) abort();
    int rc = reverse_lookup((const struct sockaddr *)&sa, length,
                            host_cap ? host : NULL, host_cap,
                            serv_cap ? service : NULL, serv_cap, flags);
    if (rc != expected_rc || (!rc && expected_host && strcmp(host, expected_host))
        || (!rc && expected_serv && strcmp(service, expected_serv))) {
        fprintf(stderr, "reverse %s flags=%x: expected rc=%d [%s/%s], got rc=%d [%.80s/%.80s]\n",
                address, flags, expected_rc, expected_host ? expected_host : "omitted",
                expected_serv ? expected_serv : "omitted", rc, host, service);
        exit(1);
    }
    for (size_t i = host_cap; i < sizeof(host); ++i) if (host[i] != 0x5a) abort();
    for (size_t i = serv_cap; i < sizeof(service); ++i) if (service[i] != 0x5a) abort();
    ++passed;
}

static void check_input_contract(void) {
    struct sockaddr_storage sa;
    socklen_t length = make_address("192.0.2.250", 4443, &sa);
    char host[128];
    /* These addresses are deliberately absent from the DNS fixture: validation,
     * numeric-only and omitted-output calls must never send a DNS packet. */
    for (socklen_t n = 0; n < length; ++n) {
        memset(host, 0x5a, sizeof(host));
        int rc = reverse_lookup((const struct sockaddr *)&sa, n, host, sizeof(host), NULL, 0,
                                NI_NUMERICHOST | NI_NUMERICSERV);
        if (rc != EAI_FAMILY || host[0] != 0x5a) abort();
    }
    ++passed;
    unsigned char unaligned[sizeof(sa) + 1];
    memcpy(unaligned + 1, &sa, sizeof(sa));
    if (reverse_lookup((const struct sockaddr *)(unaligned + 1), length, host, sizeof(host), NULL, 0,
                       NI_NUMERICHOST | NI_NUMERICSERV) || strcmp(host, "192.0.2.250")) abort();
    ++passed;
    if (reverse_lookup((const struct sockaddr *)&sa, length, NULL, 0, NULL, 0, 0) != 0) abort();
    if (reverse_lookup((const struct sockaddr *)&sa, length, NULL, 0, NULL, 0, NI_NAMEREQD) != EAI_NONAME) abort();
    ++passed;
}

static void check_named_resolution(int tcp_only) {
    const int required = NI_NAMEREQD | NI_NUMERICSERV;
    check_reverse("192.0.2.9", 4443, required, 128, 32, 0, "peer.local.test", "4443");
    check_reverse("2001:db8::9", 4443, required, 128, 32, 0, "v6-peer.local.test", "4443");
    check_reverse("::ffff:192.0.2.9", 4443, required, 128, 32, 0, "peer.local.test", "4443");
    check_reverse("192.0.2.9", 4443, required | NI_NOFQDN, 128, 0, 0, "peer", NULL);
    check_reverse("192.0.2.10", 4443, required | NI_NOFQDN, 128, 0, 0, "peer.foreign.test", NULL);
    check_reverse("192.0.2.200", 4443, 0, 128, 32, 0, "files-v4.local.test", "franken-stream");
    check_reverse("2001:db8::200", 4443, NI_NAMEREQD | NI_DGRAM, 128, 32, 0,
                  "files-v6.local.test", "franken-datagram");
    check_reverse("192.0.2.200", 4443, NI_NAMEREQD | NI_NOFQDN, 128, 0, 0, "files-v4", NULL);
    check_reverse("192.0.2.200", 4443, NI_NUMERICHOST | NI_NUMERICSERV, 128, 32, 0, "192.0.2.200", "4443");
    check_reverse("192.0.2.250", 4443, NI_NUMERICHOST, 128, 32, 0, "192.0.2.250", "franken-stream");
    check_reverse("192.0.2.250", 4443, NI_NAMEREQD | NI_DGRAM, 0, 32, 0, NULL, "franken-datagram");
    check_reverse("192.0.2.250", 65534, NI_NUMERICHOST, 0, 32, 0, NULL, "65534");
    check_reverse("192.0.2.250", 4443, required | NI_NUMERICHOST, 128, 32, EAI_NONAME, NULL, NULL);
    check_reverse("192.0.2.250", 4443, 0x800000, 128, 32, EAI_BADFLAGS, NULL, NULL);
    check_reverse("192.0.2.201", 4443, NI_NUMERICSERV, 128, 0, 0, "192.0.2.201", NULL);
    check_reverse("192.0.2.201", 4443, required, 128, 0, EAI_NONAME, NULL, NULL);
    check_reverse("192.0.2.202", 4443, required, 128, 0, EAI_AGAIN, NULL, NULL);
    check_reverse("192.0.2.202", 4443, NI_NUMERICSERV, 128, 0, EAI_AGAIN, NULL, NULL);
    check_reverse("192.0.2.203", 4443, required, 128, 0, tcp_only ? EAI_NONAME : EAI_AGAIN, NULL, NULL);
    check_reverse("192.0.2.204", 4443, required, 128, 0, EAI_NONAME, NULL, NULL);
    check_reverse("192.0.2.205", 4443, required, 128, 0, EAI_NONAME, NULL, NULL);
    check_reverse("192.0.2.200", 4443, required, 4, 0, EAI_OVERFLOW, NULL, NULL);
    check_reverse("192.0.2.250", 4443, NI_NUMERICHOST, 0, 4, EAI_OVERFLOW, NULL, NULL);
    check_reverse("192.0.2.200", 4443, required, sizeof("files-v4.local.test"), 0, 0, "files-v4.local.test", NULL);
    check_input_contract();
}

static void check_provider(void *symbol, const char *name) {
    Dl_info owner = {0};
    if (!symbol || !dladdr(symbol, &owner) || !owner.dli_fname || !strstr(owner.dli_fname, "frankenlibc")) {
        fprintf(stderr, "%s symbol did not resolve to FrankenLibC\n", name);
        exit(1);
    }
}

int main(int argc, char **argv) {
    if (argc != 2 && argc != 3) return 2;
    if (argc == 3) {
        if (strcmp(argv[2], "--preloaded")) return 2;
        lookup = getaddrinfo;
        release_result = freeaddrinfo;
        reverse_lookup = getnameinfo;
    } else {
        void *library = dlopen(argv[1], RTLD_NOW | RTLD_LOCAL);
        if (!library) { fprintf(stderr, "dlopen: %s\n", dlerror()); return 1; }
        lookup = (getaddrinfo_fn)dlsym(library, "getaddrinfo");
        release_result = (freeaddrinfo_fn)dlsym(library, "freeaddrinfo");
        reverse_lookup = (getnameinfo_fn)dlsym(library, "getnameinfo");
    }
    check_provider((void *)lookup, "getaddrinfo");
    check_provider((void *)release_result, "freeaddrinfo");
    check_provider((void *)reverse_lookup, "getnameinfo");
    int tcp_only = getenv("FRANKENLIBC_TEST_TCP_ONLY") != NULL;
    check_address("alias.test.", AF_INET, "192.0.2.9");
    check_address("v6alias.test.", AF_INET6, "2001:db8::9");
    const char *mode = getenv("FRANKENLIBC_MODE");
    if (!mode || strcmp(mode, "hardened")) {
        check_error("missing.test.", EAI_NONAME);
        /* Captured against glibc 2.41 with identical controlled UDP/TCP peers. */
        check_error("temporary.test.", tcp_only ? EAI_NONAME : EAI_AGAIN);
        check_error("refused.test.", tcp_only ? EAI_NONAME : EAI_AGAIN);
        check_error("cycle.test.", EAI_FAIL);
    }
    /* Defined reverse-lookup contracts are identical in strict and hardened. */
    check_named_resolution(tcp_only);
    printf("native DNS ABI: %u passed\n", passed);
    return 0;
}
