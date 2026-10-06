#define _GNU_SOURCE
#include <arpa/inet.h>
#include <dlfcn.h>
#include <errno.h>
#include <fcntl.h>
#include <netdb.h>
#include <poll.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/random.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

/* No public DNS, host configuration changes, preload, or probabilistic ID
 * assertions. Each query runs in a fresh child with its own empty /dev.
 * Resolve symbols before chroot; pin every function to the requested DSO. */
static int (*lookup)(const char *, const char *, const struct addrinfo *, struct addrinfo **);
static void (*release)(struct addrinfo *);
static int (*reverse_lookup)(const struct sockaddr *, socklen_t, char *, socklen_t, char *, socklen_t, int);
static const char canonical[] = "kernel-entropy.test";
static const char alias[] = "alias.kernel-entropy.test";
static const unsigned char ipv4[4] = {192, 0, 2, 61};
static unsigned char ipv6[16];
static void *owner;

#define CHECK(c) do { if (!(c)) { fprintf(stderr, "line %d: %s (errno=%d)\n", __LINE__, #c, errno); exit(1); } } while (0)

static void *symbol(void *handle, const char *name, int host) {
    void *p = dlsym(handle, name);
    Dl_info info = {0};
    CHECK(p != NULL && dladdr(p, &info) != 0);
    if (!owner) {
        owner = info.dli_fbase;
        if (host) CHECK(strstr(info.dli_fname, "libc.so") != NULL);

    }
    CHECK(info.dli_fbase == owner);
    return p;
}

static long long now_ms(void) {
    struct timespec ts;
    CHECK(clock_gettime(CLOCK_MONOTONIC, &ts) == 0);
    return (long long)ts.tv_sec * 1000 + ts.tv_nsec / 1000000;
}

static void store_file(const char *root, const char *name, const char *text) {
    char path[1024];
    CHECK(snprintf(path, sizeof path, "%s/etc/%s", root, name) > 0);
    FILE *f = fopen(path, "w");
    CHECK(f != NULL && fputs(text, f) >= 0 && fclose(f) == 0);
}

static size_t encode_name(unsigned char *dst, size_t capacity, const char *name) {
    size_t used = 0;
    while (*name) {
        const char *dot = strchr(name, '.');
        size_t n = dot ? (size_t)(dot - name) : strlen(name);
        CHECK(n > 0 && n <= 63 && used + n + 2 <= capacity);
        dst[used++] = (unsigned char)n;
        memcpy(dst + used, name, n); used += n;
        name += n;
        if (*name == '.') name++;
    }
    dst[used++] = 0;
    return used;
}

static size_t reply_to(const unsigned char *q, size_t length, unsigned char *out,
                       unsigned *questions, unsigned *aliases, unsigned *ptrs) {
    CHECK(length >= 17 && q[4] == 0 && q[5] == 1);
    char name[256]; size_t p = 12, used = 0;
    while (p < length && q[p]) {
        unsigned n = q[p++];
        CHECK(n <= 63 && p + n < length && used + n + 1 < sizeof name);
        if (used) name[used++] = '.';
        memcpy(name + used, q + p, n); used += n; p += n;
    }
    CHECK(p < length && p + 5 <= length);
    p++; name[used] = 0;
    unsigned kind = (unsigned)q[p] * 256 + q[p + 1];
    CHECK(q[p + 2] == 0 && q[p + 3] == 1);
    p += 4;
    memcpy(out, q, p); out[2] = 0x81; out[3] = 0x80;
    out[6] = 0; out[7] = 1; memset(out + 8, 0, 4);
    unsigned char data[256]; size_t bytes;
    unsigned answer_kind = kind;
    (*questions)++;
    if (!strcmp(name, alias)) {
        CHECK(kind == 1 || kind == 28);
        answer_kind = 5;
        bytes = encode_name(data, sizeof data, canonical);
        (*aliases)++;
    } else if (kind == 12) {
        CHECK(strstr(name, ".in-addr.arpa") != NULL || strstr(name, ".ip6.arpa") != NULL);
        bytes = encode_name(data, sizeof data, canonical);
        (*ptrs)++;
    } else {
        CHECK(!strcmp(name, canonical) && (kind == 1 || kind == 28));
        bytes = kind == 1 ? 4 : 16;
        memcpy(data, kind == 1 ? ipv4 : ipv6, bytes);
    }
    const unsigned char rr[] = {0xc0, 12, 0, 0, 0, 1, 0, 0, 0, 60, 0, 0};
    memcpy(out + p, rr, sizeof rr);
    out[p + 3] = (unsigned char)answer_kind;
    out[p + 10] = (unsigned char)(bytes >> 8); out[p + 11] = (unsigned char)bytes;
    p += sizeof rr; memcpy(out + p, data, bytes); p += bytes;
    if (answer_kind == 5) {
        out[7] = 2;
        p += encode_name(out + p, 4096 - p, canonical);
        const unsigned char fixed[] = {0, 0, 0, 1, 0, 0, 0, 60, 0, 0};
        memcpy(out + p, fixed, sizeof fixed);
        bytes = kind == 1 ? 4 : 16;
        out[p + 1] = (unsigned char)kind;
        out[p + 9] = (unsigned char)bytes;
        p += sizeof fixed;
        memcpy(out + p, kind == 1 ? ipv4 : ipv6, bytes); p += bytes;
    }
    return p;
}

static void transfer(int fd, void *buffer, size_t length, int writing) {
    unsigned char *p = buffer;
    while (length) {
        ssize_t n = writing ? write(fd, p, length) : read(fd, p, length);
        if (n < 0 && errno == EINTR) continue;
        CHECK(n > 0 && (size_t)n <= length);
        p += n; length -= (size_t)n;
    }
}

static void client(const char *root, int case_number) {
    alarm(8);
    CHECK(chroot(root) == 0 && chdir("/") == 0);
    errno = 0;
    CHECK(access("/dev/urandom", F_OK) == -1 && errno == ENOENT);
    unsigned char entropy[2];
    CHECK(getrandom(entropy, sizeof entropy, GRND_NONBLOCK) == (ssize_t)sizeof entropy);
    int family = case_number % 2 ? AF_INET6 : AF_INET;
    if (case_number < 4) {
        struct addrinfo hints = {0}, *result = NULL;
        hints.ai_family = family; hints.ai_socktype = SOCK_STREAM; hints.ai_flags = AI_CANONNAME;
        int rc = lookup(case_number < 2 ? canonical : alias, NULL, &hints, &result);
        CHECK(rc == 0 && result != NULL && result->ai_family == family);
        CHECK(result->ai_canonname != NULL && !strcmp(result->ai_canonname, canonical));
        if (family == AF_INET) {
            CHECK(result->ai_addrlen >= sizeof(struct sockaddr_in));
            CHECK(!memcmp(&((struct sockaddr_in *)result->ai_addr)->sin_addr, ipv4, 4));
        } else {
            CHECK(result->ai_addrlen >= sizeof(struct sockaddr_in6));
            CHECK(!memcmp(&((struct sockaddr_in6 *)result->ai_addr)->sin6_addr, ipv6, 16));
        }
        release(result);
    } else {
        struct sockaddr_storage address = {0};
        socklen_t size;
        if (family == AF_INET) {
            struct sockaddr_in *a = (void *)&address;
            a->sin_family = AF_INET; memcpy(&a->sin_addr, ipv4, 4); size = sizeof *a;
        } else {
            struct sockaddr_in6 *a = (void *)&address;
            a->sin6_family = AF_INET6; memcpy(&a->sin6_addr, ipv6, 16); size = sizeof *a;
        }
        char name[256] = {0};
        CHECK(reverse_lookup((void *)&address, size, name, sizeof name, NULL, 0, NI_NAMEREQD) == 0);
        CHECK(!strcmp(name, canonical));
    }
    _exit(0);
}

static void run_case(int udp, int tcp, const char *root, int index, int use_tcp) {
    pid_t pid = fork(); CHECK(pid >= 0);
    if (!pid) { close(udp); close(tcp); client(root, index); }
    long long deadline = now_ms() + 9000;
    int status = 0; unsigned questions = 0, aliases = 0, ptrs = 0;
    for (;;) {
        pid_t done = waitpid(pid, &status, WNOHANG);
        CHECK(done >= 0);
        if (done == pid) break;
        if (now_ms() >= deadline) { kill(pid, SIGKILL); waitpid(pid, &status, 0); CHECK(!"DNS child exceeded deadline"); }
        struct pollfd fds[2] = {{udp, POLLIN, 0}, {tcp, POLLIN, 0}};
        int ready = poll(fds, 2, 30);
        if (ready < 0 && errno == EINTR) continue;
        CHECK(ready >= 0);
        unsigned char query[4096], response[4096];
        if (fds[0].revents & POLLIN) {
            CHECK(!use_tcp);
            struct sockaddr_storage peer; socklen_t len = sizeof peer;
            ssize_t n = recvfrom(udp, query, sizeof query, 0, (void *)&peer, &len);
            CHECK(n > 0);
            size_t count = reply_to(query, (size_t)n, response, &questions, &aliases, &ptrs);
            CHECK(sendto(udp, response, count, 0, (void *)&peer, len) == (ssize_t)count);
        }
        if (fds[1].revents & POLLIN) {
            CHECK(use_tcp);
            int fd = accept(tcp, NULL, NULL); CHECK(fd >= 0);
            struct timeval timeout = {2, 0};
            CHECK(setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof timeout) == 0);
            CHECK(setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &timeout, sizeof timeout) == 0);
            unsigned char prefix[2]; transfer(fd, prefix, 2, 0);
            size_t n = (size_t)prefix[0] * 256 + prefix[1]; CHECK(n <= sizeof query);
            transfer(fd, query, n, 0);
            size_t count = reply_to(query, n, response, &questions, &aliases, &ptrs);
            prefix[0] = (unsigned char)(count >> 8); prefix[1] = (unsigned char)count;
            transfer(fd, prefix, 2, 1); transfer(fd, response, count, 1); close(fd);
        }
    }
    CHECK(WIFEXITED(status) && WEXITSTATUS(status) == 0);
    CHECK(questions > 0);
    if (index == 2 || index == 3) CHECK(aliases == 1 && questions == 1);
    if (index >= 4) CHECK(ptrs == 1);
    printf("%s case %d: real DNS exchange without /dev/urandom passed\n", use_tcp ? "TCP" : "UDP", index);
}

int main(int argc, char **argv) {
    CHECK(argc == 2);
    CHECK(setvbuf(stdout, NULL, _IONBF, 0) == 0);
    CHECK(geteuid() == 0); /* Run with sudo; lack of privilege must not look green. */
    int host = !strcmp(argv[1], "--host");
    void *handle = dlopen(host ? "libc.so.6" : argv[1], RTLD_NOW | RTLD_LOCAL);
    CHECK(handle != NULL);
    lookup = symbol(handle, "getaddrinfo", host);
    release = symbol(handle, "freeaddrinfo", host);
    reverse_lookup = symbol(handle, "getnameinfo", host);
    if (!host) {
        Dl_info info = {0}; struct stat expected, actual;
        CHECK(dladdr((void *)lookup, &info));
        CHECK(stat(argv[1], &expected) == 0 && stat(info.dli_fname, &actual) == 0);
        CHECK(expected.st_dev == actual.st_dev && expected.st_ino == actual.st_ino);
    }
    CHECK(inet_pton(AF_INET6, "2001:db8::61", ipv6) == 1);
    int udp = socket(AF_INET, SOCK_DGRAM, 0), tcp = socket(AF_INET, SOCK_STREAM, 0);
    CHECK(udp >= 0 && tcp >= 0);
    struct sockaddr_in server = {.sin_family = AF_INET, .sin_port = htons(53)};
    char server_text[64]; int bound = 0;
    for (unsigned n = 1; n < 250; n++) {
        snprintf(server_text, sizeof server_text, "127.213.%u.%u", (unsigned)getpid() % 250 + 1, n);
        CHECK(inet_pton(AF_INET, server_text, &server.sin_addr) == 1);
        if (bind(udp, (void *)&server, sizeof server) == 0) { bound = 1; break; }
        CHECK(errno == EADDRINUSE);
    }
    CHECK(bound && bind(tcp, (void *)&server, sizeof server) == 0 && listen(tcp, 8) == 0);
    char root[] = "/tmp/frankenlibc-dns-entropy-XXXXXX"; CHECK(mkdtemp(root));
    char path[1024]; snprintf(path, sizeof path, "%s/etc", root); CHECK(mkdir(path, 0700) == 0);
    CHECK(unsetenv("LOCALDOMAIN") == 0 && unsetenv("RES_OPTIONS") == 0 && unsetenv("HOSTALIASES") == 0);
    store_file(root, "hosts", ""); store_file(root, "nsswitch.conf", "hosts: files dns\n");
    for (int tcp_mode = 0; tcp_mode < 2; tcp_mode++) {
        char conf[256]; snprintf(conf, sizeof conf, "nameserver %s\noptions timeout:1 attempts:1%s\n", server_text, tcp_mode ? " use-vc" : "");
        store_file(root, "resolv.conf", conf);
        for (int index = 0; index < 6; index++) run_case(udp, tcp, root, index, tcp_mode);
    }
    close(udp); close(tcp);
    for (unsigned i = 0; i < 3; i++) {
        const char *files[] = {"hosts", "nsswitch.conf", "resolv.conf"};
        snprintf(path, sizeof path, "%s/etc/%s", root, files[i]); CHECK(unlink(path) == 0);
    }
    snprintf(path, sizeof path, "%s/etc", root); CHECK(rmdir(path) == 0 && rmdir(root) == 0);
    CHECK(dlclose(handle) == 0);
    printf("12 %s kernel-entropy DNS cases passed\n", host ? "host-glibc" : "candidate");
    return 0;
}
