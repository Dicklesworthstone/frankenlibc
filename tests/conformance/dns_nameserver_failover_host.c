/* Host-glibc oracle for DNS nameserver failover, not a FrankenLibC test.
 * Uses isolated resolver state and loopback-only ephemeral UDP endpoints.
 * Build: cc -std=c11 -Wall -Wextra -Werror -O2
 *   tests/conformance/dns_nameserver_failover_host.c -lresolv -pthread -o /tmp/dns-failover
 * Run: timeout 20 /tmp/dns-failover
 * Optional probe instrumentation: -fsanitize=address,undefined -g
 */
#define _GNU_SOURCE
#include <arpa/inet.h>
#include <arpa/nameser.h>
#include <assert.h>
#include <errno.h>
#include <netdb.h>
#include <pthread.h>
#include <resolv.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

struct responder { int fd; int type; int negative; unsigned calls; };
static int bound_socket(struct sockaddr_in *address) {
    int fd = socket(AF_INET, SOCK_DGRAM, 0);
    assert(fd >= 0);
    *address = (struct sockaddr_in){.sin_family = AF_INET,
        .sin_addr.s_addr = htonl(INADDR_LOOPBACK)};
    assert(bind(fd, (const struct sockaddr *)address, sizeof(*address)) == 0);
    socklen_t size = sizeof(*address);
    assert(getsockname(fd, (struct sockaddr *)address, &size) == 0);
    struct timeval timeout = {.tv_sec = 3};
    assert(setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout)) == 0);
    return fd;
}
static void *respond(void *opaque) {
    struct responder *r = opaque;
    uint8_t packet[1024];
    struct sockaddr_storage peer;
    socklen_t peerlen = sizeof(peer);
    ssize_t length = recvfrom(r->fd, packet, sizeof(packet) - 28, 0,
                              (struct sockaddr *)&peer, &peerlen);
    assert(length >= 17);
    assert(packet[length - 4] == 0 && packet[length - 3] == r->type);
    r->calls++;
    packet[2] = 0x81;
    packet[3] = r->negative ? 0x83 : 0x80;
    memset(packet + 6, 0, 6);
    if (!r->negative) {
        packet[7] = 1;
        uint8_t header[] = {0xc0, 12, 0, 0, 0, 1, 0, 0, 0, 60, 0, 0};
        header[3] = (uint8_t)r->type;
        size_t width = r->type == ns_t_a ? 4 : 16;
        header[11] = (uint8_t)width;
        memcpy(packet + length, header, sizeof(header)); length += sizeof(header);
        const uint8_t v4[4] = {192, 0, 2, 7};
        const uint8_t v6[16] = {0x20, 1, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 7};
        memcpy(packet + length, width == 4 ? v4 : v6, width); length += (ssize_t)width;
    }
    assert(sendto(r->fd, packet, (size_t)length, 0,
                  (const struct sockaddr *)&peer, peerlen) == length);
    return NULL;
}
static void run_case(int type, int negative) {
    struct sockaddr_in dead, alive;
    int reservation = bound_socket(&dead);
    int fd = bound_socket(&alive);
    assert(close(reservation) == 0);
    // Verify the primary endpoint really refuses UDP, rather than silently timing out.
    int probe = socket(AF_INET, SOCK_DGRAM, 0);
    assert(probe >= 0);
    assert(connect(probe, (const struct sockaddr *)&dead, sizeof(dead)) == 0);
    struct timeval timeout = {.tv_sec = 1};
    assert(setsockopt(probe, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout)) == 0);
    assert(send(probe, "x", 1, 0) == 1);
    char byte;
    assert(recv(probe, &byte, 1, 0) == -1 && errno == ECONNREFUSED);
    assert(close(probe) == 0);
    struct responder r = {.fd = fd, .type = type, .negative = negative};
    pthread_t worker;
    assert(pthread_create(&worker, NULL, respond, &r) == 0);
    struct __res_state state;
    memset(&state, 0, sizeof(state));
    assert(res_ninit(&state) == 0);
    state.nscount = 2;
    state.nsaddr_list[0] = dead;
    state.nsaddr_list[1] = alive;
    state.retrans = 1;
    state.retry = 2;
    state.options &= ~(RES_ROTATE | RES_USEVC);
    uint8_t reply[1024];
    int length = res_nquery(&state, "failover.test.", ns_c_in, type, reply, sizeof(reply));
    if (negative) {
        assert(length == -1 && state.res_h_errno == HOST_NOT_FOUND);
    } else {
        assert(length > 0);
        ns_msg message;
        ns_rr rr;
        assert(ns_initparse(reply, length, &message) == 0);
        assert(ns_parserr(&message, ns_s_an, 0, &rr) == 0);
        assert((int)ns_rr_type(rr) == type && ns_rr_class(rr) == ns_c_in);
        assert(ns_rr_rdlen(rr) == (type == ns_t_a ? 4 : 16));
    }
    res_nclose(&state);
    assert(pthread_join(worker, NULL) == 0);
    assert(r.calls == 1);
    assert(close(fd) == 0);
    printf("PASS: refused primary -> fallback type=%d negative=%d\n", type, negative);
}
int main(void) {
    run_case(ns_t_a, 0);
    run_case(ns_t_aaaa, 0);
    run_case(ns_t_a, 1);
    run_case(ns_t_aaaa, 1);
    puts("4 host-glibc nameserver failover cases passed");
}
