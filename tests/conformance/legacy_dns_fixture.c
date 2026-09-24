/* Deterministic legacy DNS integration fixture: loopback only, no /etc writes.
 * cc -std=c11 -Wall -Wextra -Werror legacy_dns_fixture.c -lresolv -ldl -o fixture
 * ./fixture forward|reverse [absolute path to candidate shared library]
 * An explicit candidate uses dlsym + dladdr, never an unnoticed host fallback.
 */
#define _GNU_SOURCE
#include <arpa/inet.h>
#include <dlfcn.h>
#include <errno.h>
#include <netdb.h>
#include <resolv.h>
#include <signal.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

static pid_t server_pid = -1;
static unsigned checks;
static struct hostent *(*lookup_name)(const char *) = gethostbyname;
static int (*lookup_name_r)(const char *, struct hostent *, char *, size_t,
                             struct hostent **, int *) = gethostbyname_r;
static struct hostent *(*lookup_addr)(const void *, socklen_t, int) = gethostbyaddr;
static int (*lookup_addr_r)(const void *, socklen_t, int, struct hostent *, char *,
                             size_t, struct hostent **, int *) = gethostbyaddr_r;
static int *(*host_errno_location)(void) = __h_errno_location;
static void cleanup(void) {
    if (server_pid > 0) {
        (void)kill(server_pid, SIGTERM);
        while (waitpid(server_pid, NULL, 0) < 0 && errno == EINTR) {}
        server_pid = -1;
    }
}
static void check(bool ok, const char *what) {
    ++checks;
    if (!ok) {
        fprintf(stderr, "FAIL: %s (errno=%d, h_errno=%d)\n", what, errno,
                *host_errno_location());
        exit(1);
    }
}
static void put16(unsigned char *out, size_t *n, unsigned value) {
    out[(*n)++] = (unsigned char)(value >> 8);
    out[(*n)++] = (unsigned char)value;
}
static void name(unsigned char *out, size_t *n, const char *text) {
    while (*text) {
        const char *dot = strchr(text, '.');
        size_t len = dot ? (size_t)(dot - text) : strlen(text);
        out[(*n)++] = (unsigned char)len;
        memcpy(out + *n, text, len);
        *n += len;
        if (!dot) break;
        text = dot + 1;
    }
    out[(*n)++] = 0;
}
static void rr_prefix(unsigned char *out, size_t *n, const char *owner,
                      unsigned type, unsigned length) {
    if (owner) name(out, n, owner);
    else { out[(*n)++] = 0xc0; out[(*n)++] = 0x0c; }
    put16(out, n, type);
    put16(out, n, 1);
    put16(out, n, 0);
    put16(out, n, 30);
    put16(out, n, length);
}
static void serve(int fd) {
    alarm(30);
    for (;;) {
        unsigned char in[512], out[1024], target[256];
        struct sockaddr_storage peer;
        socklen_t peerlen = sizeof(peer);
        ssize_t got = recvfrom(fd, in, sizeof(in), 0,
                               (struct sockaddr *)&peer, &peerlen);
        if (got < 0) { if (errno == EINTR) continue; _exit(2); }
        if (got < 17) continue;
        char host[256]; size_t p = 12, h = 0;
        while (p < (size_t)got && in[p]) {
            size_t len = in[p++];
            if (len > 63 || p + len > (size_t)got || h + len + 1 >= sizeof(host)) break;
            if (h) host[h++] = '.';
            memcpy(host + h, in + p, len); h += len; p += len;
        }
        if (p >= (size_t)got || in[p] != 0 || p + 5 > (size_t)got) continue;
        host[h] = 0;
        ++p;
        unsigned type = ((unsigned)in[p] << 8) | in[p + 1];
        size_t end = p + 4, n = end, target_len = 0;
        memcpy(out, in, end);
        out[2] = 0x81; out[3] = 0x80;
        out[6] = out[7] = out[8] = out[9] = out[10] = out[11] = 0;
        if (!strncmp(host, "missing.", 8) || !strncmp(host, "99.2.0.192.", 11)) {
            out[3] |= 3;
        } else if (!strncmp(host, "temporary.", 10) || !strncmp(host, "98.2.0.192.", 11)) {
            out[3] |= 2;
        } else if (type == 1) {
            name(target, &target_len, "canonical.legacy.test");
            out[7] = 3;
            rr_prefix(out, &n, NULL, 5, (unsigned)target_len);
            memcpy(out + n, target, target_len); n += target_len;
            for (unsigned suffix = 40; suffix <= 41; ++suffix) {
                rr_prefix(out, &n, "canonical.legacy.test", 1, 4);
                out[n++] = 192; out[n++] = 0; out[n++] = 2; out[n++] = (unsigned char)suffix;
            }
        } else if (type == 12) {
            name(target, &target_len, "reverse.legacy.test");
            out[7] = 1;
            rr_prefix(out, &n, NULL, 12, (unsigned)target_len);
            memcpy(out + n, target, target_len); n += target_len;
        }
        (void)sendto(fd, out, n, 0, (struct sockaddr *)&peer, peerlen);
    }
}
static void configure(void) {
    int fd = socket(AF_INET, SOCK_DGRAM | SOCK_CLOEXEC, 0);
    check(fd >= 0, "create fixture socket");
    struct sockaddr_in sa = { .sin_family = AF_INET, .sin_port = htons(53) };
    check(inet_pton(AF_INET, "127.0.0.244", &sa.sin_addr) == 1, "fixture address");
    check(bind(fd, (struct sockaddr *)&sa, sizeof(sa)) == 0,
          "bind loopback DNS fixture (requires permission for port 53)");
    server_pid = fork();
    check(server_pid >= 0, "start DNS fixture");
    if (server_pid == 0) serve(fd);
    close(fd);
    check(atexit(cleanup) == 0, "register server cleanup");
    char config[] = "/tmp/frankenlibc-legacy-resolv-XXXXXX";
    int conf = mkstemp(config);
    check(conf >= 0, "create resolver fixture configuration");
    static const char contents[] = "nameserver 127.0.0.244\noptions timeout:1 attempts:1\n";
    check(write(conf, contents, sizeof(contents) - 1) == (ssize_t)(sizeof(contents) - 1),
          "write resolver fixture configuration");
    check(close(conf) == 0, "close resolver fixture configuration");
    check(setenv("FRANKENLIBC_RESOLV_CONF", config, 1) == 0, "select native DNS fixture");
    char hosts[] = "/tmp/frankenlibc-legacy-hosts-XXXXXX";
    int hostfd = mkstemp(hosts);
    check(hostfd >= 0 && close(hostfd) == 0, "create empty hosts fixture");
    check(setenv("FRANKENLIBC_HOSTS_PATH", hosts, 1) == 0, "select empty hosts fixture");
    check(res_init() == 0, "initialize independent host resolver");
    _res.nscount = 1;
    _res.nsaddr_list[0] = sa;
    _res.retrans = 1;
    _res.retry = 1;
    _res.options &= ~(RES_ROTATE | RES_USEVC);
    alarm(20);
}
static void *candidate_symbol(void *handle, const char *symbol, const struct stat *expected) {
    dlerror();
    void *address = dlsym(handle, symbol);
    const char *error = dlerror();
    if (error) fprintf(stderr, "dlsym(%s): %s\n", symbol, error);
    check(error == NULL && address != NULL, "candidate exports required symbol");
    Dl_info info;
    struct stat actual;
    check(dladdr(address, &info) != 0 && info.dli_fname != NULL &&
          stat(info.dli_fname, &actual) == 0 && actual.st_dev == expected->st_dev &&
          actual.st_ino == expected->st_ino, "symbol belongs to candidate, not host libc");
    return address;
}
static void select_candidate(const char *path) {
    struct stat expected;
    check(stat(path, &expected) == 0, "candidate shared library exists");
    void *handle = dlopen(path, RTLD_NOW | RTLD_LOCAL);
    if (!handle) fprintf(stderr, "dlopen: %s\n", dlerror());
    check(handle != NULL, "load candidate shared library");
    lookup_name = candidate_symbol(handle, "gethostbyname", &expected);
    lookup_name_r = candidate_symbol(handle, "gethostbyname_r", &expected);
    lookup_addr = candidate_symbol(handle, "gethostbyaddr", &expected);
    lookup_addr_r = candidate_symbol(handle, "gethostbyaddr_r", &expected);
    host_errno_location = candidate_symbol(handle, "__h_errno_location", &expected);
    /* Retain the handle: returned hostent pointers refer to candidate TLS. */
}
static void check_forward(struct hostent *entry) {
    check(entry != NULL, "forward lookup found DNS-only host");
    check(entry->h_addrtype == AF_INET && entry->h_length == 4, "IPv4 hostent shape");
    check(strcmp(entry->h_name, "canonical.legacy.test") == 0, "canonical CNAME owner");
    check(entry->h_addr_list && entry->h_addr_list[0] && entry->h_addr_list[1] &&
          !entry->h_addr_list[2], "retain all DNS addresses");
    const unsigned char first[] = {192, 0, 2, 40}, second[] = {192, 0, 2, 41};
    check(memcmp(entry->h_addr_list[0], first, 4) == 0 &&
          memcmp(entry->h_addr_list[1], second, 4) == 0, "network-byte-order addresses");
}
int main(int argc, char **argv) {
    if (argc < 2 || argc > 3 ||
        (strcmp(argv[1], "forward") != 0 && strcmp(argv[1], "reverse") != 0)) {
        fprintf(stderr, "usage: %s forward|reverse [candidate.so]\n", argv[0]);
        return 2;
    }
    bool reverse = strcmp(argv[1], "reverse") == 0;
    configure();
    if (argc == 3) select_candidate(argv[2]);
    struct hostent storage, *result = NULL;
    char buf[4096];
    int herr = 77, rc;
    if (!reverse) {
        check_forward(lookup_name("alias.legacy.test."));
        rc = lookup_name_r("alias.legacy.test.", &storage, buf, sizeof(buf), &result, &herr);
        check(rc == 0 && result == &storage, "reentrant forward success");
        check_forward(result);
        result = (struct hostent *)(uintptr_t)1;
        rc = lookup_name_r("alias.legacy.test.", &storage, buf, 1, &result, &herr);
        check(rc == ERANGE && result == NULL, "small forward buffer is retryable");
        check(lookup_name("missing.legacy.test.") == NULL && *host_errno_location() == HOST_NOT_FOUND,
              "missing host never becomes localhost");
        result = (struct hostent *)(uintptr_t)1;
        rc = lookup_name_r("missing.legacy.test.", &storage, buf, sizeof(buf), &result, &herr);
        check(rc == 0 && result == NULL && herr == HOST_NOT_FOUND, "reentrant definitive negative");
        check(lookup_name("temporary.legacy.test.") == NULL && *host_errno_location() == TRY_AGAIN,
              "temporary DNS failure remains temporary");
        result = (struct hostent *)(uintptr_t)1;
        rc = lookup_name_r("temporary.legacy.test.", &storage, buf, sizeof(buf), &result, &herr);
        check(rc == EAGAIN && result == NULL && herr == TRY_AGAIN, "reentrant temporary forward failure");
    } else {
        struct in_addr ip;
        check(inet_pton(AF_INET, "192.0.2.40", &ip) == 1, "reverse fixture address");
        struct hostent *entry = lookup_addr(&ip, sizeof(ip), AF_INET);
        check(entry != NULL && strcmp(entry->h_name, "reverse.legacy.test") == 0,
              "PTR lookup resolves address absent from hosts");
        check(entry->h_addr_list[0] && !entry->h_addr_list[1] &&
              memcmp(entry->h_addr_list[0], &ip, sizeof(ip)) == 0, "reverse retains input address");
        rc = lookup_addr_r(&ip, sizeof(ip), AF_INET, &storage, buf, sizeof(buf), &result, &herr);
        check(rc == 0 && result == &storage && strcmp(result->h_name, "reverse.legacy.test") == 0,
              "reentrant PTR success");
        result = (struct hostent *)(uintptr_t)1;
        rc = lookup_addr_r(&ip, sizeof(ip), AF_INET, &storage, buf, 1, &result, &herr);
        check(rc == ERANGE && result == NULL, "small reverse buffer is retryable");
        check(inet_pton(AF_INET, "192.0.2.99", &ip) == 1, "negative reverse fixture address");
        check(lookup_addr(&ip, sizeof(ip), AF_INET) == NULL && *host_errno_location() == HOST_NOT_FOUND,
              "negative PTR remains missing");
        result = (struct hostent *)(uintptr_t)1;
        rc = lookup_addr_r(&ip, sizeof(ip), AF_INET, &storage, buf, sizeof(buf), &result, &herr);
        check(rc == 0 && result == NULL && herr == HOST_NOT_FOUND, "reentrant negative PTR");
        check(inet_pton(AF_INET, "192.0.2.98", &ip) == 1, "temporary reverse fixture address");
        check(lookup_addr(&ip, sizeof(ip), AF_INET) == NULL && *host_errno_location() == TRY_AGAIN,
              "temporary PTR failure remains temporary");
        result = (struct hostent *)(uintptr_t)1;
        rc = lookup_addr_r(&ip, sizeof(ip), AF_INET, &storage, buf, sizeof(buf), &result, &herr);
        check(rc == 0 && result == NULL && herr == TRY_AGAIN, "reentrant temporary reverse failure");
    }
    alarm(0);
    printf("PASS: %u checks (%s, %s, %s)\n", checks, argv[1],
           argc == 3 ? "candidate" : "host", getenv("FRANKENLIBC_MODE") ? getenv("FRANKENLIBC_MODE") : "default");
    return 0;
}
