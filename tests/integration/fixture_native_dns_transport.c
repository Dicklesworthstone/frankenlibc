/* Actual release C exports: forward/reverse DNS, files, services and bounds. */
#define _GNU_SOURCE
#include <arpa/inet.h>
#include <dlfcn.h>
#include <locale.h>
#include <netdb.h>
#include <net/if.h>
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

/* Compare address multisets, not RFC 6724 ordering (a separate resolver
 * capability). Check every node's ABI fields, scope, profile and ownership of
 * the sole canonical name, including the three-profile allocation path. */
static void check_forward(const char *name, int family, int flags, int expected_rc,
                          const char *first, const char *second, const char *canonical,
                          unsigned scope, int socktype) {
    struct addrinfo hints = {0}, *result = NULL;
    hints.ai_family = family;
    hints.ai_socktype = socktype;
    hints.ai_flags = flags;
    int rc = lookup(name, "443", &hints, &result);
    if (rc != expected_rc || (rc ? result != NULL : result == NULL)) {
        fprintf(stderr, "forward %s family=%d flags=%x: rc=%d expected=%d result=%p\n",
                name, family, flags, rc, expected_rc, (void *)result);
        exit(1);
    }
    if (rc) { ++passed; return; }
    const char *expected[2] = {first, second};
    unsigned seen[2] = {0, 0}, profiles[2] = {0, 0}, count = 0;
    for (const struct addrinfo *ai = result; ai; ai = ai->ai_next) {
        if (++count > 6 || !ai->ai_addr) abort();
        if (count == 1 && canonical) {
            if (!ai->ai_canonname || strcmp(ai->ai_canonname, canonical)) {
                fprintf(stderr, "%s: canonical=%s expected=%s\n", name,
                        ai->ai_canonname ? ai->ai_canonname : "NULL", canonical);
                exit(1);
            }
        } else if (ai->ai_canonname) abort();
        unsigned slot;
        for (slot = 0; slot < 2 && expected[slot]; ++slot) {
            int af = strchr(expected[slot], ':') ? AF_INET6 : AF_INET;
            unsigned char bytes[16];
            if (inet_pton(af, expected[slot], bytes) != 1) abort();
            if (ai->ai_family != af) continue;
            if (af == AF_INET6) {
                if (ai->ai_addrlen != sizeof(struct sockaddr_in6)) abort();
                const struct sockaddr_in6 *sa = (const struct sockaddr_in6 *)ai->ai_addr;
                if (sa->sin6_family != af || ntohs(sa->sin6_port) != 443
                    || sa->sin6_scope_id != scope || sa->sin6_flowinfo) abort();
                if (memcmp(bytes, &sa->sin6_addr, 16)) continue;
            } else {
                if (ai->ai_addrlen != sizeof(struct sockaddr_in)) abort();
                const struct sockaddr_in *sa = (const struct sockaddr_in *)ai->ai_addr;
                if (sa->sin_family != af || ntohs(sa->sin_port) != 443) abort();
                if (memcmp(bytes, &sa->sin_addr, 4)) continue;
            }
            break;
        }
        if (slot == 2 || !expected[slot]) {
            fprintf(stderr, "%s: unexpected address/family\n", name);
            exit(1);
        }
        unsigned profile;
        if (ai->ai_socktype == SOCK_STREAM && ai->ai_protocol == IPPROTO_TCP) profile = 1;
        else if (!socktype && ai->ai_socktype == SOCK_DGRAM && ai->ai_protocol == IPPROTO_UDP) profile = 2;
        else if (!socktype && ai->ai_socktype == SOCK_RAW && ai->ai_protocol == 0) profile = 4;
        else abort();
        if (profiles[slot] & profile) abort();
        profiles[slot] |= profile;
        ++seen[slot];
    }
    release_result(result);
    unsigned per_address = socktype ? 1 : 3;
    if (seen[0] != per_address || seen[1] != (second ? per_address : 0)) abort();
    ++passed;
}

static void check_forward_resolution(void) {
    const int numeric = AI_NUMERICHOST | AI_NUMERICSERV;
    const int mapped = AI_V4MAPPED | AI_CANONNAME;
    const int all = mapped | AI_ALL;
    unsigned lo = if_nametoindex("lo");
    if (!lo) abort();
    check_forward("192.0.2.7", AF_INET6, numeric | mapped, 0,
                  "::ffff:192.0.2.7", NULL, "192.0.2.7", 0, SOCK_STREAM);
    check_forward("192.0.2.7", AF_INET6, numeric | AI_ALL, EAI_ADDRFAMILY,
                  NULL, NULL, NULL, 0, SOCK_STREAM);
    check_forward("192.0.2.7", AF_UNSPEC, numeric | all, 0,
                  "192.0.2.7", NULL, "192.0.2.7", 0, SOCK_STREAM);
    const char *bsd[] = {"127.1", "0x7f000001", "0177.0.0.1", "2130706433"};
    for (unsigned i = 0; i < sizeof(bsd)/sizeof(bsd[0]); ++i) {
        check_forward(bsd[i], AF_INET6, numeric | mapped, 0,
                      "::ffff:127.0.0.1", NULL, bsd[i], 0, SOCK_STREAM);
    }
    check_forward("::ffff:192.0.2.7%2", AF_INET, numeric | AI_CANONNAME, 0,
                  "192.0.2.7", NULL, "::ffff:192.0.2.7%2", 0, SOCK_STREAM);
    check_forward("fe80::1%lo", AF_INET6, numeric | AI_CANONNAME, 0,
                  "fe80::1", NULL, "fe80::1%lo", lo, SOCK_STREAM);
    check_forward("ff01::1%lo", AF_INET6, numeric, 0,
                  "ff01::1", NULL, NULL, lo, SOCK_STREAM);
    check_forward("2001:db8::1%4294967295", AF_INET6, numeric, 0,
                  "2001:db8::1", NULL, NULL, 4294967295U, SOCK_STREAM);
    check_forward("fe80::1%0", AF_INET6, numeric, 0,
                  "fe80::1", NULL, NULL, 0, SOCK_STREAM);
    const char *invalid[] = {"fe80::1%", "fe80::1%-1", "fe80::1%+1",
        "fe80::1%4294967296", "fe80::1%unknown-fixture", "2001:db8::1%lo",
        "127.1 ", "4294967296", "::ffff:192.0.2.7%bad", "\xff"};
    for (unsigned i = 0; i < sizeof(invalid)/sizeof(invalid[0]); ++i) {
        check_forward(invalid[i], AF_INET6, numeric | mapped, EAI_NONAME,
                      NULL, NULL, NULL, 0, SOCK_STREAM);
    }
    check_forward("\xff", AF_INET6, 0, EAI_NONAME, NULL, NULL, NULL, 0, SOCK_STREAM);
    check_forward("::1%bad", AF_INET, numeric, EAI_ADDRFAMILY, NULL, NULL, NULL, 0, SOCK_STREAM);

    check_forward("alias-files", AF_INET6, mapped, 0,
                  "::ffff:192.0.2.200", NULL, "files-v4.local.test", 0, SOCK_STREAM);
    check_forward("dual-files", AF_INET6, mapped, 0,
                  "2001:db8::220", NULL, "dual-v6.local.test", 0, SOCK_STREAM);
    check_forward("dual-files", AF_INET6, all, 0,
                  "::ffff:192.0.2.220", "2001:db8::220", "dual-v6.local.test", 0, SOCK_STREAM);
    check_forward("dual-files", AF_INET6, AI_ALL | AI_CANONNAME, 0,
                  "2001:db8::220", NULL, "dual-v6.local.test", 0, SOCK_STREAM);
    check_forward("alias-files", AF_INET, AI_CANONNAME, 0,
                  "192.0.2.200", NULL, "files-v4.local.test", 0, 0);
    check_forward("loopback-files", AF_INET6, all, 0,
                  "::1", "::ffff:127.0.0.1", "loopback-v6.local.test", 0, SOCK_STREAM);

    check_forward("v4only.test.", AF_INET6, mapped, 0,
                  "::ffff:192.0.2.17", NULL, "v4only.test", 0, SOCK_STREAM);
    check_forward("dual.test.", AF_INET6, mapped, 0,
                  "2001:db8::17", NULL, "dual.test", 0, SOCK_STREAM);
    check_forward("all.test.", AF_INET6, all, 0,
                  "2001:db8::17", "::ffff:192.0.2.17", "all.test", 0, 0);
    check_forward("failure6.test.", AF_INET6, mapped, 0,
                  "::ffff:192.0.2.17", NULL, "failure6.test", 0, SOCK_STREAM);
    check_forward("failure4.test.", AF_INET6, all, 0,
                  "2001:db8::17", NULL, "failure4.test", 0, SOCK_STREAM);
    check_forward("search-only", AF_INET6, mapped, 0,
                  "2001:db8::17", NULL, "search-only.second.test", 0, SOCK_STREAM);
    check_forward("search-all", AF_INET6, all, 0,
                  "2001:db8::17", "::ffff:192.0.2.17", "search-all.second.test", 0, SOCK_STREAM);
    check_forward("searched-alias", AF_INET6, mapped, 0,
                  "2001:db8::17", NULL, "search-edge.test", 0, SOCK_STREAM);
    check_forward("no-address.test.", AF_INET6, all, EAI_NONAME,
                  NULL, NULL, NULL, 0, SOCK_STREAM);
}

static void check_address(const char *name, int family, const char *expected, const char *canonical) {
    struct addrinfo hints = {0}, *result = NULL;
    hints.ai_family = family;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_flags = AI_CANONNAME;
    int rc = lookup(name, "443", &hints, &result);
    if (rc != 0 || result == NULL) {
        fprintf(stderr, "%s: expected success, rc=%d result=%p\n", name, rc, (void *)result);
        exit(1);
    }
    unsigned char expected_bytes[16];
    if (inet_pton(family, expected, expected_bytes) != 1) abort();
    size_t count = 0;
    for (const struct addrinfo *ai = result; ai; ai = ai->ai_next) {
        if (count == 0) {
            if (!ai->ai_canonname || strcmp(ai->ai_canonname, canonical)) abort();
        } else if (ai->ai_canonname) abort();
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
    /* DNS can encode binary labels that must not be exposed as hostnames.
     * The root PTR is legal; an invalid first target is not rescued by a
     * later valid PTR. Captured against glibc 2.41 over both transports. */
    for (int want_name = 0; want_name <= 1; ++want_name) {
        int flags = NI_NUMERICSERV | (want_name ? NI_NAMEREQD : 0);
        check_reverse("192.0.2.206", 4443, flags, 128, 0, 0, ".", NULL);
        check_reverse("192.0.2.207", 4443, flags, 128, 0, want_name ? EAI_NONAME : 0, "192.0.2.207", NULL);
        check_reverse("192.0.2.208", 4443, flags, 128, 0, want_name ? EAI_NONAME : 0, "192.0.2.208", NULL);
        check_reverse("192.0.2.209", 4443, flags, 128, 0, 0, "_service.Host-.test", NULL);
        check_reverse("192.0.2.210", 4443, flags, 128, 0, want_name ? EAI_NONAME : 0, "192.0.2.210", NULL);
        check_reverse("192.0.2.211", 4443, flags, 128, 0, 0, "valid.test", NULL);
    }
    check_input_contract();
}

static void check_provider(void *symbol, const char *name) {
    Dl_info owner = {0};
    if (!symbol || !dladdr(symbol, &owner) || !owner.dli_fname || !strstr(owner.dli_fname, "frankenlibc")) {
        fprintf(stderr, "%s symbol did not resolve to FrankenLibC\n", name);
        exit(1);
    }
}


/* The same fixture can compare IDN input/output against an independently resolved
 * GNU provider without running a DNS server. CI supplies private files-only
 * NSS fixtures, so no host network or host configuration is involved. */
struct idn_provider {
    getaddrinfo_fn forward;
    freeaddrinfo_fn release;
    getnameinfo_fn reverse;
    locale_t (*make_locale)(int, const char *, locale_t);
    locale_t (*select_locale)(locale_t);
    void (*free_locale)(locale_t);
    int (*encode)(const char *, char **);
    void (*free_encoded)(void *);
};

static struct idn_provider idn_provider(const char *path) {
    void *handle = dlopen(path, RTLD_NOW | RTLD_LOCAL);
    if (!handle) { fprintf(stderr, "IDN dlopen: %s\n", dlerror()); exit(1); }
    struct idn_provider provider = {
        (getaddrinfo_fn)dlsym(handle, "getaddrinfo"),
        (freeaddrinfo_fn)dlsym(handle, "freeaddrinfo"),
        (getnameinfo_fn)dlsym(handle, "getnameinfo"),
        (locale_t (*)(int, const char *, locale_t))dlsym(handle, "newlocale"),
        (locale_t (*)(locale_t))dlsym(handle, "uselocale"),
        (void (*)(locale_t))dlsym(handle, "freelocale"),
        (int (*)(const char *, char **))dlsym(handle, "__idna_to_dns_encoding"),
        (void (*)(void *))dlsym(handle, "free"),
    };
    void *symbols[] = {(void *)provider.forward, (void *)provider.release,
        (void *)provider.reverse, (void *)provider.make_locale,
        (void *)provider.select_locale, (void *)provider.free_locale,
        (void *)provider.encode, (void *)provider.free_encoded};
    Dl_info first = {0};
    if (!symbols[0] || !dladdr(symbols[0], &first)) abort();
    for (size_t i = 0; i < sizeof(symbols)/sizeof(symbols[0]); ++i) {
        Dl_info owner = {0};
        if (!symbols[i] || !dladdr(symbols[i], &owner) || owner.dli_fbase != first.dli_fbase) {
            fprintf(stderr, "IDN provider has a missing or foreign symbol: %s\n", path);
            exit(1);
        }
    }
    return provider;
}

struct idn_forward_observation {
    int has_name;
    char name[1025];
};

static struct idn_forward_observation idn_forward(
    struct idn_provider provider, const char *query, int flags, unsigned last) {
    struct idn_forward_observation observed = {0};
    struct addrinfo hints = {0}, *result = NULL;
    hints.ai_family = AF_INET;
    hints.ai_flags = flags;
    int code = provider.forward(query, "443", &hints, &result);
    if (code || !result) {
        fprintf(stderr, "IDN forward %s flags=%x: %d\n", query, flags, code);
        exit(1);
    }
    unsigned count = 0, profiles = 0;
    const unsigned char expected[4] = {192, 0, 2, (unsigned char)last};
    for (struct addrinfo *node = result; node; node = node->ai_next) {
        if (++count > 3 || node->ai_family != AF_INET || !node->ai_addr
            || node->ai_addrlen != sizeof(struct sockaddr_in)) abort();
        const struct sockaddr_in *address = (const struct sockaddr_in *)node->ai_addr;
        if (address->sin_family != AF_INET || ntohs(address->sin_port) != 443
            || memcmp(&address->sin_addr, expected, 4)) abort();
        unsigned profile;
        if (node->ai_socktype == SOCK_STREAM && node->ai_protocol == IPPROTO_TCP) profile = 1;
        else if (node->ai_socktype == SOCK_DGRAM && node->ai_protocol == IPPROTO_UDP) profile = 2;
        else if (node->ai_socktype == SOCK_RAW && node->ai_protocol == 0) profile = 4;
        else abort();
        if (profiles & profile) abort();
        profiles |= profile;
        if (count == 1 && (flags & AI_CANONNAME)) {
            if (!node->ai_canonname
                || strnlen(node->ai_canonname, sizeof(observed.name)) >= sizeof(observed.name)) abort();
            observed.has_name = 1;
            strcpy(observed.name, node->ai_canonname);
        } else if (node->ai_canonname) abort();
    }
    provider.release(result);
    if (count != 3 || profiles != 7) abort();
    return observed;
}

static void idn_forward_pair(struct idn_provider host, struct idn_provider candidate,
                             const char *query, int flags, unsigned last,
                             const char *expected) {
    struct idn_forward_observation oracle = idn_forward(host, query, flags, last);
    struct idn_forward_observation actual = idn_forward(candidate, query, flags, last);
    if (oracle.has_name != actual.has_name || strcmp(oracle.name, actual.name)
        || (expected && strcmp(oracle.name, expected))) {
        fprintf(stderr, "IDN canonical %s flags=%x: host=[%s] candidate=[%s]\n",
                query, flags, oracle.name, actual.name);
        exit(1);
    }
    ++passed;
}

static void idn_encoding_pair(struct idn_provider host, struct idn_provider candidate,
                              const char *input, int expected_code, const char *expected) {
    char *oracle = NULL, *actual = NULL;
    int host_code = host.encode(input, &oracle);
    int actual_code = candidate.encode(input, &actual);
    if (host_code != expected_code || actual_code != host_code
        || (!host_code && (!oracle || !actual || strcmp(oracle, actual)
                          || (expected && strcmp(oracle, expected))))) {
        fprintf(stderr, "IDN encode [%s]: host=%d [%s] candidate=%d [%s]\n",
                input, host_code, oracle ? oracle : "<null>",
                actual_code, actual ? actual : "<null>");
        exit(1);
    }
    if (oracle) host.free_encoded(oracle);
    if (actual) candidate.free_encoded(actual);
    ++passed;
}

static void idn_forward_error_pair(struct idn_provider host, struct idn_provider candidate,
                                   const char *input, int flags, int family, int socktype,
                                   const char *service, int expected_code) {
    struct addrinfo hints = {0}, *oracle = NULL, *actual = NULL;
    hints.ai_flags = flags;
    hints.ai_family = family;
    hints.ai_socktype = socktype;
    int host_code = host.forward(input, service, &hints, &oracle);
    int actual_code = candidate.forward(input, service, &hints, &actual);
    if (host_code != expected_code || actual_code != host_code || oracle || actual) {
        fprintf(stderr, "IDN lookup [%s] flags=%x family=%d socktype=%d: host=%d candidate=%d expected=%d\n",
                input, flags, family, socktype, host_code, actual_code, expected_code);
        exit(1);
    }
    ++passed;
}

static void check_idn_input(struct idn_provider host, struct idn_provider candidate, int utf8) {
    const struct { const char *input, *encoded; } valid[] = {
        {"BÜCHER.test", "xn--bcher-kva.test"},
        {"bu\xcc\x88""cher.test", "xn--bcher-kva.test"},
        {"例え。テスト", "xn--r8jz45g.xn--zckzah"},
        {"例え．テスト", "xn--r8jz45g.xn--zckzah"},
        {"例え｡テスト", "xn--r8jz45g.xn--zckzah"},
        {"faß.test", "xn--fa-hia.test"},
        {"ẞ.test", "xn--zca.test"},
        {"Σςσ.test", "xn--3xabb.test"},
        {"Ⅳ.test", "iv.test"},
        {"Ｆｏｏ.test", "foo.test"},
        {"ü.AsCii.TeST", "xn--tda.ascii.test"},
        {"ü_foo.test", "xn--_foo-zra.test"},
        {"a·b.test", "xn--ab-0ea.test"},
        {"l·l.test", "xn--ll-0ea.test"},
        {"123.א.test", "123.xn--4db.test"},
        {"1a.א.test", "1a.xn--4db.test"},
        {"_srv.א.test", "_srv.xn--4db.test"},
        {"क्\xe2\x80\x8d""ष.test", "xn--11b2ezcw70k.test"},
        {"نامه\xe2\x80\x8c""ای.test", "xn--mgba3gch31f060k.test"},
        {"ü..test", "xn--tda..test"},
        {"ü.test..", "xn--tda.test.."},
        {"ü.\xc2\xad.test", "xn--tda..test"},
        {"ü.a b.test", "xn--tda.a b.test"},
        {"＄.test", "$.test"},
        {"ü.xn--bcher-kva.test", "xn--tda.xn--bcher-kva.test"},
    };
    const char *ascii[] = {"", "AsCii.CaSe", "xn--bad_.test", "xn--", "a\\b"};
    for (size_t i = 0; i < sizeof(ascii)/sizeof(ascii[0]); ++i)
        idn_encoding_pair(host, candidate, ascii[i], 0, ascii[i]);
    for (size_t i = 0; i < sizeof(valid)/sizeof(valid[0]); ++i)
        idn_encoding_pair(host, candidate, valid[i].input,
                          utf8 ? 0 : EAI_IDN_ENCODE, utf8 ? valid[i].encoded : NULL);
    const char *invalid[] = {
        "😀.test", "☃.test", "\xcd\xb8.test", "\xcc\x88""a.test",
        "ü-.test", "-ü.test", "ab--ü.test", "ü.ab--cd.test",
        "ü.-ascii.test", "ü.ascii-.test", "a\xe2\x80\x8d""b.test",
        "a\xe2\x80\x8c""b.test", "אa.test", "ü!.test", "ü.a\\foo.test",
        "ü.xn--bad_.test", "ü.xn--hello-.test",
        "\xff.test", "\xc0\xaf.test", "\xed\xa0\x80.test", "\xf8\x88\x80\x80\x80.test",
    };
    for (size_t i = 0; i < sizeof(invalid)/sizeof(invalid[0]); ++i)
        idn_encoding_pair(host, candidate, invalid[i], EAI_IDN_ENCODE, NULL);

    const struct { const char *input, *encoded, *decoded; unsigned last; } lookups[] = {
        {"bücher.test", "xn--bcher-kva.test", "bücher.test", 241},
        {"BÜCHER.test", "xn--bcher-kva.test", "bücher.test", 241},
        {"bu\xcc\x88""cher.test", "xn--bcher-kva.test", "bücher.test", 241},
        {"例え。テスト", "xn--r8jz45g.xn--zckzah", "例え.テスト", 242},
        {"例え．テスト", "xn--r8jz45g.xn--zckzah", "例え.テスト", 242},
        {"例え｡テスト", "xn--r8jz45g.xn--zckzah", "例え.テスト", 242},
    };
    for (size_t i = 0; i < sizeof(lookups)/sizeof(lookups[0]); ++i) {
        int flags[] = {AI_IDN | AI_CANONNAME, AI_IDN | AI_CANONNAME | AI_CANONIDN,
                       AI_IDN | AI_CANONIDN, AI_IDN | AI_CANONNAME | 0x300};
        const char *names[] = {lookups[i].encoded, lookups[i].decoded, "", lookups[i].encoded};
        for (size_t j = 0; j < sizeof(flags)/sizeof(flags[0]); ++j) {
            if (utf8)
                idn_forward_pair(host, candidate, lookups[i].input, flags[j],
                                 lookups[i].last, names[j]);
            else
                idn_forward_error_pair(host, candidate, lookups[i].input, flags[j],
                                       AF_INET, 0, "443", EAI_IDN_ENCODE);
        }
    }
    // Conversion errors precede AI_NUMERICHOST, but follow the ordinary
    // family, socket type and numeric-service validation, as measured in GNU.
    const char *errors[] = {"\xff.test", "😀.test", "אa.test", "a\xe2\x80\x8d""b.test"};
    for (size_t i = 0; i < sizeof(errors)/sizeof(errors[0]); ++i) {
        int flags = AI_IDN | AI_NUMERICHOST;
        for (int obsolete = 0; obsolete <= 0x300; obsolete += 0x100)
            idn_forward_error_pair(host, candidate, errors[i], flags | obsolete,
                                   AF_INET, 0, "443", EAI_IDN_ENCODE);
        idn_forward_error_pair(host, candidate, errors[i], flags, AF_UNIX, 0, "443", EAI_FAMILY);
        idn_forward_error_pair(host, candidate, errors[i], flags, AF_INET, 999, "443", EAI_SOCKTYPE);
        idn_forward_error_pair(host, candidate, errors[i], flags | AI_NUMERICSERV,
                               AF_INET, 0, "http", EAI_NONAME);
    }
    idn_forward_error_pair(host, candidate, "bücher.test", AI_CANONNAME | AI_CANONIDN,
                           AF_INET, 0, "443", EAI_NONAME);
    idn_forward_error_pair(host, candidate, "bücher.test", AI_IDN | AI_NUMERICHOST,
                           AF_INET, 0, "443", utf8 ? EAI_NONAME : EAI_IDN_ENCODE);

    char length_case[400];
    memset(length_case, 'u', 55);
    strcpy(length_case + 55, "ü.test");
    idn_encoding_pair(host, candidate, length_case, utf8 ? 0 : EAI_IDN_ENCODE, NULL);
    memset(length_case, 'u', 56);
    strcpy(length_case + 56, "ü.test");
    idn_encoding_pair(host, candidate, length_case, EAI_IDN_ENCODE, NULL);
    strcpy(length_case, "ü.");
    size_t length = strlen(length_case);
    for (unsigned i = 0; i < 122; ++i) {
        length_case[length++] = 'a';
        length_case[length++] = '.';
    }
    strcpy(length_case + length, "a");
    idn_encoding_pair(host, candidate, length_case, utf8 ? 0 : EAI_IDN_ENCODE, NULL);
    strcpy(length_case + length, "a.");
    idn_encoding_pair(host, candidate, length_case, utf8 ? 0 : EAI_IDN_ENCODE, NULL);
    strcpy(length_case + length, "aa");
    idn_encoding_pair(host, candidate, length_case, EAI_IDN_ENCODE, NULL);
    strcpy(length_case + length, "aa.");
    idn_encoding_pair(host, candidate, length_case, EAI_IDN_ENCODE, NULL);
}

static int idn_reverse(struct idn_provider provider, unsigned last, int flags,
                       unsigned capacity, char output[1025]) {
    struct sockaddr_in address = {0};
    const unsigned char bytes[4] = {192, 0, 2, (unsigned char)last};
    address.sin_family = AF_INET;
    memcpy(&address.sin_addr, bytes, sizeof(bytes));
    memset(output, 0x5a, 1025);
    int code = provider.reverse((const struct sockaddr *)&address, sizeof(address),
                                output, capacity, NULL, 0, flags | NI_NUMERICSERV);
    if (capacity > 1024) abort();
    for (size_t i = capacity; i < 1025; ++i) if (output[i] != 0x5a) abort();
    if (!code && !memchr(output, 0, capacity)) abort();
    return code;
}

static void idn_reverse_pair(struct idn_provider host, struct idn_provider candidate,
                             unsigned last, int flags, const char *expected) {
    char oracle[1025], actual[1025];
    int host_code = idn_reverse(host, last, flags, 1024, oracle);
    int actual_code = idn_reverse(candidate, last, flags, 1024, actual);
    if (host_code || actual_code || strcmp(oracle, actual)
        || (expected && strcmp(oracle, expected))) {
        fprintf(stderr, "IDN reverse .%u flags=%x: host=%d [%.80s] candidate=%d [%.80s]\n",
                last, flags, host_code, oracle, actual_code, actual);
        exit(1);
    }
    ++passed;
    size_t length = strlen(oracle);
    if (!length) abort();
    host_code = idn_reverse(host, last, flags, (unsigned)length + 1, oracle);
    actual_code = idn_reverse(candidate, last, flags, (unsigned)length + 1, actual);
    if (host_code || actual_code || strcmp(oracle, actual)) abort();
    ++passed;
    host_code = idn_reverse(host, last, flags, (unsigned)length, oracle);
    actual_code = idn_reverse(candidate, last, flags, (unsigned)length, actual);
    if (host_code != EAI_OVERFLOW || actual_code != EAI_OVERFLOW) {
        fprintf(stderr, "IDN reverse capacity .%u flags=%x capacity=%zu: host=%d candidate=%d\n",
                last, flags, length, host_code, actual_code);
        abort();
    }
    ++passed;
}

static int check_idn_resolution(const char *path) {
    struct idn_provider host = idn_provider("libc.so.6");
    struct idn_provider candidate = idn_provider(path);
    if (host.forward == candidate.forward || host.reverse == candidate.reverse
        || host.make_locale == candidate.make_locale) {
        fprintf(stderr, "IDN oracle collapsed into the candidate provider\n");
        return 1;
    }
    const struct {
        const char *query, *encoded, *decoded;
        unsigned last;
    } cases[] = {
        {"idn-latin", "xn--bcher-kva.test", "b\xc3\xbc""cher.test", 241},
        {"idn-japanese", "xn--r8jz45g.xn--zckzah",
            "\xe4\xbe\x8b\xe3\x81\x88.\xe3\x83\x86\xe3\x82\xb9\xe3\x83\x88", 242},
        {"idn-case", "XN--bcher-kva.CaSe", "b\xc3\xbc""cher.CaSe", 243},
        {"idn-malformed", "xn--bad_.test", "\xc2\x83\xc2\x83\xc2\x81.test", 244},
        {"idn-partial", "xn--bcher-kva.xn--bad_",
            "b\xc3\xbc""cher.\xc2\x83\xc2\x83\xc2\x81", 245},
        {"idn-ascii", "ordinary.CaSe", "ordinary.CaSe", 246},
        {"idn-incomplete", "xn--0.test", "xn--0.test", 247},
        {"idn-empty", "xn--", "xn--", 248},
        {"idn-partial-incomplete", "xn--bcher-kva.xn--0", "xn--bcher-kva.xn--0", 249},
        {"idn-basic", "xn--hello-.test", "xn--hello-.test", 250},
        {"idn-literal-underscore", "xn--bad_-a.test", "\xc2\x80""bad_.test", 251},
    };
    const char *locales[] = {"C", "C.UTF-8"};
    for (size_t locale = 0; locale < sizeof(locales)/sizeof(locales[0]); ++locale) {
        locale_t host_locale = host.make_locale(LC_CTYPE_MASK, locales[locale], (locale_t)0);
        locale_t candidate_locale = candidate.make_locale(LC_CTYPE_MASK, locales[locale], (locale_t)0);
        if (!host_locale || !candidate_locale) abort();
        locale_t host_previous = host.select_locale(host_locale);
        locale_t candidate_previous = candidate.select_locale(candidate_locale);
        if (!host_previous || !candidate_previous) abort();
        check_idn_input(host, candidate, locale != 0);
        for (size_t i = 0; i < sizeof(cases)/sizeof(cases[0]); ++i) {
            const char *expected = locale ? cases[i].decoded : cases[i].encoded;
            idn_forward_pair(host, candidate, cases[i].query, AI_CANONNAME,
                             cases[i].last, cases[i].encoded);
            idn_forward_pair(host, candidate, cases[i].query, AI_CANONNAME | AI_CANONIDN,
                             cases[i].last, expected);
            idn_forward_pair(host, candidate, cases[i].query, AI_CANONIDN,
                             cases[i].last, "");
            idn_reverse_pair(host, candidate, cases[i].last, NI_NAMEREQD, cases[i].encoded);
            idn_reverse_pair(host, candidate, cases[i].last, NI_NAMEREQD | NI_IDN, expected);
        }
        idn_reverse_pair(host, candidate, 241, NI_NUMERICHOST | NI_IDN, "192.0.2.241");
        candidate.select_locale(candidate_previous);
        host.select_locale(host_previous);
        candidate.free_locale(candidate_locale);
        host.free_locale(host_locale);
    }
    printf("native IDN ABI: %u passed\n", passed);
    return 0;
}

int main(int argc, char **argv) {
    if (argc == 3 && !strcmp(argv[2], "--idn-only")) return check_idn_resolution(argv[1]);
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
    check_address("alias.test.", AF_INET, "192.0.2.9", "edge.test");
    check_address("v6alias.test.", AF_INET6, "2001:db8::9", "v6edge.test");
    {
        check_error("missing.test.", EAI_NONAME);
        /* Captured against glibc 2.41 with identical controlled UDP/TCP peers. */
        check_error("temporary.test.", tcp_only ? EAI_NONAME : EAI_AGAIN);
        check_error("refused.test.", tcp_only ? EAI_NONAME : EAI_AGAIN);
        check_error("cycle.test.", EAI_FAIL);
    }
    /* Defined reverse-lookup contracts are identical in strict and hardened. */
    check_named_resolution(tcp_only);
    check_forward_resolution();
    printf("native DNS ABI: %u passed\n", passed);
    return 0;
}
