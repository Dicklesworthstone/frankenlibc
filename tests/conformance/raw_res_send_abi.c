/* Exercise the actual exported raw-send ABI in a private resolver filesystem.
 * Run as root in a fresh network namespace with loopback enabled. Each case
 * forks before calling the resolver, then chroots to its own /etc/resolv.conf;
 * neither the host's resolver configuration nor external DNS is used.
 * cc -std=c11 -O2 -Wall -Wextra -Werror raw_res_send_abi.c -ldl -pthread -o probe
 * sudo unshare -n sh -c 'ip link set lo up; exec "$@"' sh ./probe --host|/abs/candidate.so
 */
#define _GNU_SOURCE
#include <arpa/inet.h>
#include <assert.h>
#include <dlfcn.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <poll.h>
#include <pthread.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

typedef int (*send_fn)(const unsigned char *, int, unsigned char *, int);
static const unsigned char query[] = {
    0x32,0x10,1,0,0,1,0,0,0,0,0,0,3,'r','a','w',4,'t','e','s','t',0,0,1,0,1
};
struct test_case {
    const char *name;
    int tcp, fallback, forge, alias, negative, trust_ad, response_ad, capacity, no_reply;
};
struct result { int rc, error; unsigned char output[514]; };
struct server {
    int udp, tcp;
    const struct test_case *test;
    unsigned calls;
    unsigned char answer[64];
    size_t answer_len;
};
static void exact_read(int fd, void *out, size_t len) {
    unsigned char *p = out;
    while (len) {
        ssize_t n = read(fd, p, len);
        if (n < 0 && errno == EINTR) continue;
        assert(n > 0);
        p += n; len -= (size_t)n;
    }
}
static void exact_write(int fd, const void *in, size_t len) {
    const unsigned char *p = in;
    while (len) {
        ssize_t n = write(fd, p, len);
        if (n < 0 && errno == EINTR) continue;
        assert(n > 0);
        p += n; len -= (size_t)n;
    }
}
static void timeout_socket(int fd) {
    struct timeval timeout = {.tv_sec = 4};
    assert(setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout)) == 0);
    assert(setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &timeout, sizeof(timeout)) == 0);
}
static int listener(int type) {
    int fd = socket(AF_INET, type, 0);
    assert(fd >= 0);
    int one = 1;
    assert(setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one)) == 0);
    struct sockaddr_in addr = {.sin_family = AF_INET, .sin_port = htons(53)};
    assert(inet_pton(AF_INET, "127.23.45.67", &addr.sin_addr) == 1);
    assert(bind(fd, (struct sockaddr *)&addr, sizeof(addr)) == 0);
    if (type == SOCK_STREAM) assert(listen(fd, 4) == 0);
    timeout_socket(fd);
    return fd;
}
static void *respond(void *opaque) {
    struct server *s = opaque;
    const struct test_case *t = s->test;
    struct pollfd fds[2] = {{.fd=s->udp,.events=POLLIN},{.fd=s->tcp,.events=POLLIN}};
    int ready = poll(fds, 2, t->capacity < 12 ? 300 : 4000);
    if (t->capacity < 12) { assert(ready == 0); return NULL; }
    assert(ready > 0);
    unsigned char buffer[512];
    if (!t->tcp) {
        assert(fds[0].revents & POLLIN);
        struct sockaddr_in peer;
        socklen_t len = sizeof(peer);
        ssize_t n = recvfrom(s->udp, buffer, sizeof(buffer), 0, (struct sockaddr *)&peer, &len);
        assert(n == (ssize_t)sizeof(query) && memcmp(buffer, query, sizeof(query)) == 0);
        s->calls++;
        if (t->no_reply) return NULL;
        if (t->forge) {
            unsigned char forged[64];
            memcpy(forged, s->answer, s->answer_len);
            forged[s->answer_len - 1] = 99;
            int rogue = socket(AF_INET, SOCK_DGRAM, 0);
            assert(rogue >= 0);
            assert(sendto(rogue, forged, s->answer_len, 0, (struct sockaddr *)&peer, len) == (ssize_t)s->answer_len);
            assert(close(rogue) == 0);
            // Same ID, wrong question from the correct endpoint.
            forged[13] ^= 1;
            assert(sendto(s->udp, forged, s->answer_len, 0, (struct sockaddr *)&peer, len) == (ssize_t)s->answer_len);
        }
        if (t->fallback) {
            unsigned char truncated[sizeof(query)];
            memcpy(truncated, query, sizeof(query));
            truncated[2] = 0x83; truncated[3] = 0x80;
            assert(sendto(s->udp, truncated, sizeof(truncated), 0, (struct sockaddr *)&peer, len) == (ssize_t)sizeof(truncated));
            fds[0].fd = -1; fds[1].revents = 0;
            assert(poll(fds, 2, 4000) == 1 && (fds[1].revents & POLLIN));
        } else {
            assert(sendto(s->udp, s->answer, s->answer_len, 0, (struct sockaddr *)&peer, len) == (ssize_t)s->answer_len);
            return NULL;
        }
    } else assert(fds[1].revents & POLLIN);
    int stream = accept(s->tcp, NULL, NULL);
    assert(stream >= 0);
    timeout_socket(stream);
    unsigned char prefix[2];
    exact_read(stream, prefix, 2);
    size_t n = (size_t)prefix[0] * 256 + prefix[1];
    assert(n == sizeof(query));
    exact_read(stream, buffer, n);
    assert(memcmp(buffer, query, sizeof(query)) == 0);
    s->calls++;
    prefix[0] = 0; prefix[1] = (unsigned char)s->answer_len;
    // Deliberate fragmentation covers partial length prefixes and payload I/O.
    exact_write(stream, prefix, 1); exact_write(stream, prefix + 1, 1);
    for (size_t i = 0; i < s->answer_len; ++i) exact_write(stream, s->answer + i, 1);
    assert(close(stream) == 0);
    return NULL;
}
static void run_case(send_fn send_message, const struct test_case *t) {
    char root[] = "/tmp/frankenlibc-raw-abi-XXXXXX";
    assert(mkdtemp(root));
    char path[PATH_MAX];
    assert(snprintf(path, sizeof(path), "%s/etc", root) > 0);
    assert(mkdir(path, 0700) == 0);
    assert(snprintf(path, sizeof(path), "%s/etc/resolv.conf", root) > 0);
    FILE *conf = fopen(path, "w");
    assert(conf);
    assert(fprintf(conf, "nameserver 127.23.45.67\noptions timeout:1 attempts:1%s%s\n",
                   t->tcp ? " use-vc" : "", t->trust_ad ? " trust-ad" : "") > 0);
    assert(fclose(conf) == 0);
    struct server s = {.udp=listener(SOCK_DGRAM), .tcp=listener(SOCK_STREAM), .test=t};
    memcpy(s.answer, query, sizeof(query));
    s.answer[2] = 0x81; s.answer[3] = (unsigned char)(0x80 | (t->response_ad ? 0x20 : 0) | (t->negative ? 3 : 0));
    s.answer_len = sizeof(query);
    if (!t->negative) {
        const unsigned char rr[] = {0xc0,12,0,1,0,1,0,0,0,60,0,4,192,0,2,7};
        s.answer[7] = 1;
        memcpy(s.answer + s.answer_len, rr, sizeof(rr)); s.answer_len += sizeof(rr);
    }
    int results[2];
    assert(pipe(results) == 0);
    pid_t child = fork();
    assert(child >= 0);
    if (child == 0) {
        close(results[0]); close(s.udp); close(s.tcp);
        alarm(6);
        assert(chroot(root) == 0 && chdir("/") == 0);
        struct result result;
        memset(&result, 0, sizeof(result));
        memset(result.output, 0xa5, sizeof(result.output));
        unsigned char *output = result.output + 1;
        const unsigned char *input = query;
        if (t->alias) { memcpy(output, query, sizeof(query)); input = output; }
        errno = 0;
        result.rc = send_message(input, sizeof(query), output, t->capacity);
        result.error = errno;
        exact_write(results[1], &result, sizeof(result));
        _exit(0);
    }
    assert(close(results[1]) == 0);
    pthread_t worker;
    assert(pthread_create(&worker, NULL, respond, &s) == 0);
    struct pollfd p = {.fd=results[0], .events=POLLIN};
    assert(poll(&p, 1, 7000) > 0 && (p.revents & POLLIN));
    struct result result;
    exact_read(results[0], &result, sizeof(result));
    assert(close(results[0]) == 0);
    int status;
    assert(waitpid(child, &status, 0) == child && WIFEXITED(status) && WEXITSTATUS(status) == 0);
    assert(pthread_join(worker, NULL) == 0);
    assert(close(s.udp) == 0 && close(s.tcp) == 0);
    assert(result.output[0] == 0xa5 && result.output[t->capacity + 1] == 0xa5);
    if (t->capacity < 12 || t->no_reply) {
        assert(result.rc == -1 && result.error == (t->no_reply ? ETIMEDOUT : EINVAL));
        for (size_t i = 0; i < sizeof(result.output); ++i) assert(result.output[i] == 0xa5);
        assert(s.calls == (unsigned)t->no_reply);
    } else {
        size_t copied = (size_t)t->capacity < s.answer_len ? (size_t)t->capacity : s.answer_len;
        assert(result.rc == (int)((t->tcp || t->fallback) ? s.answer_len : copied));
        if (!t->trust_ad) s.answer[3] &= (unsigned char)~0x20;
        if ((t->tcp || t->fallback) && copied < s.answer_len) s.answer[2] |= 2;
        if (memcmp(result.output + 1, s.answer, copied) != 0) {
            fprintf(stderr, "%s rc=%d errno=%d copied=%zu expected:", t->name, result.rc, result.error, copied);
            for (size_t i=0; i<copied; ++i) fprintf(stderr, " %02x", s.answer[i]);
            fputs("\nobserved:", stderr);
            for (size_t i=0; i<copied; ++i) fprintf(stderr, " %02x", result.output[i+1]);
            fputc('\n', stderr);
        }
        assert(memcmp(result.output + 1, s.answer, copied) == 0);
        for (size_t i = copied + 1; i < sizeof(result.output); ++i) assert(result.output[i] == 0xa5);
        assert(s.calls == (t->fallback ? 2u : 1u));
    }
    printf("PASS: %s\n", t->name);
}
int main(int argc, char **argv) {
    if (argc != 2 || geteuid() != 0) {
        fputs("Requires root in an isolated network namespace; pass --host or an absolute DSO path\n", stderr);
        return 2;
    }
    int host = strcmp(argv[1], "--host") == 0;
    void *library = dlopen(host ? "libc.so.6" : argv[1], RTLD_NOW | RTLD_LOCAL);
    assert(library);
    void *symbol = dlsym(library, "__res_send");
    if (!symbol && host) symbol = dlsym(library, "res_send");
    assert(symbol);
    Dl_info owner;
    assert(dladdr(symbol, &owner) && owner.dli_fname);
    if (host) assert(strstr(owner.dli_fname, "libc.so") || strstr(owner.dli_fname, "libresolv.so"));
    else {
        struct stat expected, actual;
        assert(stat(argv[1], &expected) == 0 && stat(owner.dli_fname, &actual) == 0);
        assert(expected.st_dev == actual.st_dev && expected.st_ino == actual.st_ino);
    }
    printf("SYMBOL_OWNER: %s\n", owner.dli_fname);
    send_fn send_message;
    _Static_assert(sizeof(send_message) == sizeof(symbol), "function pointer ABI");
    memcpy(&send_message, &symbol, sizeof(send_message));
    const struct test_case cases[] = {
        {.name="udp", .capacity=128},
        {.name="udp-short-copy", .capacity=12},
        {.name="tcp", .tcp=1, .capacity=128},
        {.name="tcp-full-frame-length", .tcp=1, .capacity=12},
        {.name="udp-tcp-fallback", .fallback=1, .capacity=128},
        {.name="fallback-full-frame-length", .fallback=1, .capacity=12},
        {.name="forged-peer-and-question", .forge=1, .capacity=128},
        {.name="overlapping-message-and-answer", .alias=1, .capacity=128},
        {.name="raw-nxdomain", .negative=1, .capacity=128},
        // AD is tested on full replies, separately from truncation. Host glibc
        // preserves AD on a short-question UDP receive; native send clears it.
        {.name="untrusted-ad-cleared", .response_ad=1, .capacity=128},
        {.name="explicit-ad-trust", .trust_ad=1, .response_ad=1, .capacity=128},
        {.name="header-short-no-network", .capacity=11},
        {.name="bounded-timeout", .capacity=128, .no_reply=1},
    };
    for (size_t i = 0; i < sizeof(cases)/sizeof(cases[0]); ++i) run_case(send_message, &cases[i]);
    printf("13 exported raw-send cases passed (%s)\n", host ? "host" : "candidate");
    return 0;
}
