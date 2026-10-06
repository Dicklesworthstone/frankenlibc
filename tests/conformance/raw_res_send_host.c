/* Host-glibc reference probe, NOT validation of the Rust candidate.
 * Only loopback sockets created by this process are contacted.
 * cc -std=c11 -O2 -Wall -Wextra -Werror raw_res_send_host.c -pthread -lresolv -ldl -o probe
 */
#define _GNU_SOURCE
#include <arpa/inet.h>
#include <assert.h>
#include <dlfcn.h>
#include <errno.h>
#include <netinet/in.h>
#include <poll.h>
#include <pthread.h>
#include <resolv.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <unistd.h>

static const unsigned char query[] = {
    0x32,0x10,0x01,0x00,0,1,0,0,0,0,0,0,
    4,'t','e','s','t',7,'i','n','v','a','l','i','d',0,0,1,0,1
};
enum mode { UDP, TCP, FALLBACK };
struct endpoint {
    int datagram, listener;
    enum mode mode;
    unsigned packets;
    struct sockaddr_in address;
};

static void timeouts(int fd) {
    struct timeval t = {.tv_sec = 3};
    assert(setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &t, sizeof(t)) == 0);
    assert(setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &t, sizeof(t)) == 0);
}
static struct endpoint endpoint(enum mode mode) {
    struct endpoint e = {.datagram = -1, .listener = -1, .mode = mode};
    e.address.sin_family = AF_INET;
    e.address.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    int fd = socket(AF_INET, mode == UDP ? SOCK_DGRAM : SOCK_STREAM, 0);
    assert(fd >= 0);
    assert(bind(fd, (struct sockaddr *)&e.address, sizeof(e.address)) == 0);
    socklen_t len = sizeof(e.address);
    assert(getsockname(fd, (struct sockaddr *)&e.address, &len) == 0);
    timeouts(fd);
    if (mode == UDP) {
        e.datagram = fd;
    } else {
        e.listener = fd;
        assert(listen(fd, 1) == 0);
        if (mode == FALLBACK) {
            e.datagram = socket(AF_INET, SOCK_DGRAM, 0);
            assert(e.datagram >= 0);
            assert(bind(e.datagram, (struct sockaddr *)&e.address, sizeof(e.address)) == 0);
            timeouts(e.datagram);
        }
    }
    return e;
}
static size_t answer(unsigned char *out) {
    memcpy(out, query, sizeof(query));
    out[2] = 0x81; out[3] = 0x80; out[7] = 1;
    const unsigned char rr[] = {0xc0,12,0,1,0,1,0,0,0,60,0,4,192,0,2,7};
    memcpy(out + sizeof(query), rr, sizeof(rr));
    return sizeof(query) + sizeof(rr);
}
static void read_all(int fd, unsigned char *out, size_t n) {
    while (n != 0) {
        ssize_t got = read(fd, out, n);
        if (got == -1 && errno == EINTR) continue;
        assert(got > 0);
        out += got; n -= (size_t)got;
    }
}
static void write_all(int fd, const unsigned char *bytes, size_t n) {
    while (n != 0) {
        ssize_t done = write(fd, bytes, n);
        if (done == -1 && errno == EINTR) continue;
        assert(done > 0);
        bytes += done; n -= (size_t)done;
    }
}
static void *serve(void *opaque) {
    struct endpoint *e = opaque;
    unsigned char packet[512], response[512];
    size_t response_length = answer(response);
    if (e->mode != TCP) {
        struct sockaddr_in peer;
        socklen_t size = sizeof(peer);
        ssize_t got = recvfrom(e->datagram, packet, sizeof(packet), 0,
                               (struct sockaddr *)&peer, &size);
        assert(got == (ssize_t)sizeof(query));
        assert(memcmp(packet, query, sizeof(query)) == 0);
        e->packets++;
        if (e->mode == FALLBACK) {
            response[2] |= 2;
            response_length = sizeof(query) + 1; /* A cut-off RR with TC. */
        }
        assert(sendto(e->datagram, response, response_length, 0,
                       (struct sockaddr *)&peer, size) == (ssize_t)response_length);
    }
    if (e->mode != UDP) {
        struct pollfd pollfd = {.fd = e->listener, .events = POLLIN};
        assert(poll(&pollfd, 1, 3000) == 1);
        int fd = accept(e->listener, NULL, NULL);
        assert(fd >= 0);
        timeouts(fd);
        unsigned char prefix[2];
        read_all(fd, prefix, 2);
        size_t size = (size_t)prefix[0] * 256 + prefix[1];
        assert(size == sizeof(query));
        read_all(fd, packet, size);
        assert(memcmp(packet, query, size) == 0);
        e->packets++;
        response_length = answer(response);
        prefix[0] = (unsigned char)(response_length >> 8);
        prefix[1] = (unsigned char)response_length;
        write_all(fd, prefix, 1);
        write_all(fd, prefix + 1, 1);
        for (size_t i = 0; i < response_length; i += 3) {
            size_t chunk = response_length - i;
            if (chunk > 3) chunk = 3;
            write_all(fd, response + i, chunk);
        }
        assert(close(fd) == 0);
    }
    return NULL;
}
static void run_case(enum mode mode, size_t capacity) {
    struct endpoint e = endpoint(mode);
    struct __res_state state;
    memset(&state, 0, sizeof(state));
    assert(res_ninit(&state) == 0);
    state.nscount = 1;
    state.nsaddr_list[0] = e.address;
    state.retrans = 1;
    state.retry = 1;
    state.options = RES_INIT | RES_RECURSE | (mode == TCP ? RES_USEVC : 0);
    unsigned char output[514], expected[512];
    memset(output, 0xa5, sizeof(output));
    pthread_t worker;
    int valid = capacity >= 12;
    if (valid) assert(pthread_create(&worker, NULL, serve, &e) == 0);
    errno = 0;
    int result = res_nsend(&state, query, sizeof(query), output + 1, (int)capacity);
    int saved_errno = errno;
    if (!valid) {
        assert(result == -1 && saved_errno == EINVAL);
        for (size_t i = 0; i < sizeof(output); i++) assert(output[i] == 0xa5);
        struct pollfd p = {
            .fd = mode == TCP ? e.listener : e.datagram, .events = POLLIN
        };
        assert(poll(&p, 1, 0) == 0);
    } else {
        assert(pthread_join(worker, NULL) == 0);
        assert(e.packets == (mode == FALLBACK ? 2u : 1u));
        size_t length = answer(expected);
        size_t copied = capacity < length ? capacity : length;
        assert(result == (int)(mode == UDP ? copied : length));
        if (mode != UDP && copied < length) expected[2] |= 2;
        assert(memcmp(output + 1, expected, copied) == 0);
        assert(output[0] == 0xa5);
        for (size_t i = copied + 1; i < sizeof(output); i++) assert(output[i] == 0xa5);
    }
    res_nclose(&state);
    if (e.datagram >= 0) assert(close(e.datagram) == 0);
    if (e.listener >= 0) assert(close(e.listener) == 0);
    printf("PASS host-glibc mode=%d capacity=%zu return=%d errno=%d packets=%u\n",
           mode, capacity, result, saved_errno, e.packets);
}
int main(void) {
    Dl_info owner;
    assert(dladdr((void *)res_nsend, &owner) != 0);
    const char *name = strrchr(owner.dli_fname, '/');
    name = name == NULL ? owner.dli_fname : name + 1;
    assert(strcmp(name, "libc.so.6") == 0 || strcmp(name, "libresolv.so.2") == 0);
    printf("Reference function owner: %s\n", owner.dli_fname);
    const size_t capacities[] = {0, 1, 11, 12, 15, 512};
    for (int mode = UDP; mode <= FALLBACK; mode++)
        for (size_t i = 0; i < sizeof(capacities)/sizeof(capacities[0]); i++)
            run_case((enum mode)mode, capacities[i]);
    puts("18 host-glibc raw-send cases passed; Rust candidate not tested");
    return 0;
}
