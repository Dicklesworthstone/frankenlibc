/* Global resolver ABI conformance. Loopback only; no external DNS or root.
 * cc -std=c11 -O2 -Wall -Wextra -Werror global_resolver_abi.c -pthread -ldl -lresolv -o global-resolver
 * timeout 90 ./global-resolver --host   (or absolute candidate shared library)
 */
#define _GNU_SOURCE
#include <arpa/inet.h>
#include <arpa/nameser.h>
#include <assert.h>
#include <dlfcn.h>
#include <errno.h>
#include <netdb.h>
#include <pthread.h>
#include <resolv.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <unistd.h>

static res_state (*state_ptr)(void);
static int (*initialize)(void);
static void (*state_close)(res_state);
static int (*build)(int,const char*,int,int,const unsigned char*,int,const unsigned char*,unsigned char*,int);
static int (*send_raw)(const unsigned char*,int,unsigned char*,int);
static int (*query)(const char*,int,int,unsigned char*,int);
static int (*search)(const char*,int,int,unsigned char*,int);
static int (*querydomain)(const char*,const char*,int,int,unsigned char*,int);
static int *(*host_error)(void);
static unsigned passed;

static void *symbol(void *handle, const char *name, const char *candidate) {
    void *p = dlsym(handle, name);
    if (!p) { fprintf(stderr, "missing %s: %s\n", name, dlerror()); abort(); }
    Dl_info info;
    assert(dladdr(p, &info));
    if (candidate) {
        struct stat expected, actual;
        assert(stat(candidate, &expected) == 0);
        assert(stat(info.dli_fname, &actual) == 0);
        assert(expected.st_dev == actual.st_dev && expected.st_ino == actual.st_ino);
    } else {
        assert(strstr(info.dli_fname, "libc.so") || strstr(info.dli_fname, "libresolv.so"));
    }
    return p;
}
static void pass(const char *label) { ++passed; printf("PASS: %s\n", label); }
static void deadlines(int fd) {
    struct timeval timeout = {.tv_sec = 4};
    assert(setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout)) == 0);
    assert(setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &timeout, sizeof(timeout)) == 0);
}
static int bind_socket(struct sockaddr_in *address, int tcp, int reuse_address) {
    int fd = socket(AF_INET, tcp ? SOCK_STREAM : SOCK_DGRAM, 0);
    assert(fd >= 0);
    if (!reuse_address) {
        *address = (struct sockaddr_in){.sin_family = AF_INET,
            .sin_addr.s_addr = htonl(INADDR_LOOPBACK)};
    }
    assert(bind(fd, (void *)address, sizeof(*address)) == 0);
    socklen_t length = sizeof(*address);
    assert(getsockname(fd, (void *)address, &length) == 0);
    deadlines(fd);
    if (tcp) assert(listen(fd, 2) == 0);
    return fd;
}
static void read_all(int fd, void *p, size_t length) {
    unsigned char *bytes = p;
    while (length) {
        ssize_t n = read(fd, bytes, length);
        assert(n > 0); bytes += n; length -= (size_t)n;
    }
}
static void write_all(int fd, const void *p, size_t length) {
    const unsigned char *bytes = p;
    while (length) {
        ssize_t n = write(fd, bytes, length);
        assert(n > 0); bytes += n; length -= (size_t)n;
    }
}
static void configure(struct sockaddr_in address, unsigned long options) {
    res_state state = state_ptr();
    assert(state == state_ptr());
    if (state->options & RES_INIT) state_close(state);
    memset(state, 0, sizeof(*state));
    state->options = RES_INIT | RES_RECURSE | RES_DEFNAMES | RES_DNSRCH | options;
    state->retrans = 1; state->retry = 1; state->ndots = 1;
    state->nscount = 1; state->nsaddr_list[0] = address; state->_vcsock = -1;
}
struct server {
    int udp, tcp, transport, count, marker, kind, class_, edns, forged;
    const char *names[3];
    unsigned codes[3];
};
static void *serve(void *opaque) {
    struct server *server = opaque;
    for (int index = 0; index < server->count; ++index) {
        unsigned char request[2048], reply[2048];
        struct sockaddr_in peer; socklen_t plen = sizeof(peer);
        size_t length; int connection = -1;
        if (server->transport == 1) {
            connection = accept(server->tcp, NULL, NULL); assert(connection >= 0);
            deadlines(connection);
            unsigned char prefix[2]; read_all(connection, prefix, 2);
            length = ((size_t)prefix[0] << 8) | prefix[1];
            assert(length >= 17 && length < sizeof(request));
            read_all(connection, request, length);
        } else {
            ssize_t n = recvfrom(server->udp, request, sizeof(request), 0, (void *)&peer, &plen);
            assert(n >= 17); length = (size_t)n;
        }
        assert(request[4] == 0 && request[5] == 1);
        size_t end = 12;
        while (end < length && request[end]) {
            assert(request[end] <= 63); end += 1 + request[end];
        }
        end += 5; assert(end <= length);
        char owner[1025]; assert(dn_expand(request, request + length, request + 12, owner, sizeof(owner)) > 0);
        assert(strcmp(owner, server->names[index]) == 0);
        assert(request[end - 4] == 0 && request[end - 3] == server->kind);
        assert(request[end - 2] == 0 && request[end - 1] == server->class_);
        if (server->edns) {
            assert(length == end + 11 && request[11] == 1);
            assert(request[end] == 0 && request[end + 1] == 0 && request[end + 2] == 41);
            assert((request[end + 7] & 0x80) == (server->edns == 2 ? 0x80 : 0));
        } else assert(length == end && request[11] == 0);
        memcpy(reply, request, end);
        reply[2] |= 0x80; reply[3] = 0xa0 | server->codes[index];
        memset(reply + 6, 0, 6);
        size_t response_length = end;
        if (server->codes[index] == 0 && server->marker) {
            reply[7] = 1;
            unsigned char rr[] = {0xc0,12,0,(unsigned char)server->kind,0,(unsigned char)server->class_,0,0,0,60,0,4,192,0,2,(unsigned char)server->marker};
            if (server->kind == ns_t_txt) memcpy(rr + 12, "\3ok!", 4);
            memcpy(reply + response_length, rr, sizeof(rr)); response_length += sizeof(rr);
        }
        if (server->transport == 2) {
            unsigned char truncated[2048]; memcpy(truncated, reply, end);
            truncated[2] |= 2; memset(truncated + 6, 0, 6);
            assert(sendto(server->udp, truncated, end, 0, (void *)&peer, plen) == (ssize_t)end);
            connection = accept(server->tcp, NULL, NULL); assert(connection >= 0); deadlines(connection);
            unsigned char prefix[2], repeated[2048]; read_all(connection, prefix, 2);
            size_t tcp_length = ((size_t)prefix[0] << 8) | prefix[1]; assert(tcp_length == length);
            read_all(connection, repeated, tcp_length); assert(memcmp(repeated, request, length) == 0);
        }
        if (connection >= 0) {
            unsigned char prefix[] = {(unsigned char)(response_length >> 8), (unsigned char)response_length};
            write_all(connection, prefix, 1); usleep(1000); write_all(connection, prefix + 1, 1);
            for (size_t offset = 0; offset < response_length; offset += 7) {
                size_t size = response_length - offset; if (size > 7) size = 7;
                write_all(connection, reply + offset, size);
            }
            assert(close(connection) == 0);
        } else {
            if (server->forged) {
                unsigned char wrong[2048]; memcpy(wrong, reply, response_length);
                wrong[response_length - 1] = 99;
                int rogue = socket(AF_INET, SOCK_DGRAM, 0); assert(rogue >= 0);
                assert(sendto(rogue, wrong, response_length, 0, (void *)&peer, plen) == (ssize_t)response_length);
                assert(close(rogue) == 0);
                wrong[13] ^= 1;
                assert(sendto(server->udp, wrong, response_length, 0, (void *)&peer, plen) == (ssize_t)response_length);
            }
            ssize_t written = sendto(server->udp, reply, response_length, 0, (void *)&peer, plen);
            if (written != (ssize_t)response_length) { fprintf(stderr, "send fd=%d size=%zu plen=%u family=%d port=%u: %s\n", server->udp, response_length, (unsigned)plen, peer.sin_family, ntohs(peer.sin_port), strerror(errno)); abort(); }
        }
    }
    return NULL;
}
static void network_case(int operation, int transport, int edns, int code, int marker,
                         int class_, int capacity, int trust, int forged) {
    struct sockaddr_in address;
    struct server server = {.udp = -1, .tcp = -1, .transport = transport, .count = 1,
        .marker = marker, .kind = class_ == ns_c_chaos ? ns_t_txt : ns_t_a,
        .class_ = class_, .edns = edns, .forged = forged,
        .names = {operation == 2 ? "host.suffix.test" : operation == 3 ? "host.first.test" : "example.test"},
        .codes = {(unsigned)code}};
    if (transport == 1) server.tcp = bind_socket(&address, 1, 0);
    else {
        server.udp = bind_socket(&address, 0, 0);
        if (transport == 2) server.tcp = bind_socket(&address, 1, 1);
    }
    configure(address, (transport == 1 ? RES_USEVC : 0) | (trust ? RES_TRUSTAD : 0)
        | (edns == 2 ? RES_USE_DNSSEC : edns ? RES_USE_EDNS0 : 0));
    res_state state = state_ptr();
    if (operation == 3) {
        state->dnsrch[0] = "first.test"; state->dnsrch[1] = "second.test";
        server.count = 2; server.codes[0] = ns_r_nxdomain; server.names[1] = "host.second.test";
    }
    pthread_t worker; assert(pthread_create(&worker, NULL, serve, &server) == 0);
    unsigned char storage[2050]; memset(storage, 0xa5, sizeof(storage));
    unsigned char *out = storage + 1;
    unsigned char before[sizeof(storage)]; memcpy(before, storage, sizeof(storage));
    int n;
    state->res_h_errno = 99; *host_error() = 99;
    if (operation == 1) {
        int length = build(0, "example.test", class_, server.kind, NULL, 0, NULL, out, 1024);
        assert(length > 0);
        memcpy(before, storage, sizeof(storage));
        // glibc overwrites an aliased request with the truncated UDP reply
        // before TCP retry. Test aliasing for direct UDP/TCP, and preserve
        // the request separately for the reference fallback contract.
        unsigned char request[1024]; memcpy(request, out, (size_t)length);
        n = send_raw(transport == 2 ? request : out, length, out, capacity);
    } else if (operation == 2) n = querydomain("host", "suffix.test", class_, server.kind, out, capacity);
    else if (operation == 3) n = search("host", class_, server.kind, out, capacity);
    else n = query("example.test", class_, server.kind, out, capacity);
    if (operation == 1 || marker) assert(n > 0);
    else {
        assert(n == -1);
        assert(*host_error() == (code == ns_r_nxdomain ? HOST_NOT_FOUND : NO_DATA));
        assert(state->res_h_errno == *host_error());
    }
    assert(storage[0] == 0xa5);
    assert(memcmp(storage + capacity + 1, before + capacity + 1, sizeof(storage) - (size_t)capacity - 1) == 0);
    assert(out[2] & 0x80);
    if (transport && capacity == 12) { assert(n > capacity); assert(out[2] & 2); }
    else if (marker && operation != 3) assert(out[n - 1] == (class_ == ns_c_chaos ? '!' : marker));
    assert((out[3] & 0x20) == (trust ? 0x20 : 0));
    if (operation != 1 && operation != 3 && marker) assert(*host_error() == 99);
    assert(pthread_join(worker, NULL) == 0);
    if (server.udp >= 0) assert(close(server.udp) == 0);
    if (server.tcp >= 0) assert(close(server.tcp) == 0);
    state_close(state);
    pass(operation == 3 ? "global search uses public suffix list" : operation == 2 ? "global querydomain honors public endpoint" :
         operation == 1 ? "global raw send uses public state and shared buffer" : "global query transport, options, class and result contract");
}
static void initialization_cases(void) {
    res_state state = state_ptr();
    if (state->options & RES_INIT) state_close(state);
    memset(state, 0, sizeof(*state));
    assert(setenv("LOCALDOMAIN", "one.test", 1) == 0);
    assert(setenv("RES_OPTIONS", "timeout:2 attempts:3 ndots:4 edns0 trust-ad", 1) == 0);
    unsigned char out[512];
    assert(build(0, "example.test", 1, 1, NULL, 0, NULL, out, sizeof(out)) == 30);
    assert(state == state_ptr() && (state->options & RES_INIT));
    assert(state->retrans == 2 && state->retry == 3 && state->ndots == 4);
    assert((state->options & (RES_USE_EDNS0 | RES_TRUSTAD)) == (RES_USE_EDNS0 | RES_TRUSTAD));
    assert(strcmp(state->dnsrch[0], "one.test") == 0); pass("legacy mkquery lazily initializes the public state");
    state->options = RES_INIT | RES_USEVC;
    assert(setenv("LOCALDOMAIN", "two.test three.test", 1) == 0);
    assert(setenv("RES_OPTIONS", "timeout:1 attempts:2 ndots:2", 1) == 0);
    assert(initialize() == 0); assert(state == state_ptr());
    assert((state->options & (RES_RECURSE | RES_USEVC)) == RES_USEVC);
    assert(state->retrans == 1 && state->retry == 2 && state->ndots == 2);
    assert(strcmp(state->dnsrch[0], "two.test") == 0 && strcmp(state->dnsrch[1], "three.test") == 0);
    pass("res_init reloads configuration without replacing stable state or established options");
    for (int flags = 0; flags < 4; ++flags) {
        state->options = RES_INIT | (flags & 1 ? RES_RECURSE : 0) | (flags & 2 ? RES_TRUSTAD : 0);
        assert(build(0, "example.test", ns_c_chaos, ns_t_txt, NULL, 0, NULL, out, sizeof(out)) == 30);
        assert((((unsigned)out[2] << 8) | out[3]) == (unsigned)((flags & 1 ? 0x100 : 0) | (flags & 2 ? 0x20 : 0)));
        assert(out[27] == ns_t_txt && out[29] == ns_c_chaos);
        pass("global mkquery observes mutable RD/AD flags and non-IN class");
    }
    assert(build(ns_o_notify, "example.test", 1, ns_t_soa, (const unsigned char *)"edge.test", 0, NULL, out, sizeof(out)) == 47);
    assert(out[11] == 1); pass("global NOTIFY uses native completion-record builder");
    state_close(state); assert(unsetenv("LOCALDOMAIN") == 0); assert(unsetenv("RES_OPTIONS") == 0);
}
struct client { struct sockaddr_in address; int marker; pthread_barrier_t *barrier; res_state pointer; };
static void *client(void *opaque) {
    struct client *client = opaque;
    configure(client->address, 0); client->pointer = state_ptr();
    int rc = pthread_barrier_wait(client->barrier); assert(rc == 0 || rc == PTHREAD_BARRIER_SERIAL_THREAD);
    unsigned char out[512]; int n = query("example.test", 1, 1, out, sizeof(out));
    assert(n > 0 && out[n - 1] == client->marker);
    rc = pthread_barrier_wait(client->barrier); assert(rc == 0 || rc == PTHREAD_BARRIER_SERIAL_THREAD);
    state_close(state_ptr()); return NULL;
}
static void thread_case(void) {
    struct server servers[2] = {
        {.tcp=-1,.count=1,.marker=11,.kind=1,.class_=1,.names={"example.test"}},
        {.tcp=-1,.count=1,.marker=22,.kind=1,.class_=1,.names={"example.test"}}
    };
    pthread_barrier_t barrier; assert(pthread_barrier_init(&barrier, NULL, 3) == 0);
    struct client clients[2] = {{.marker=11,.barrier=&barrier},{.marker=22,.barrier=&barrier}};
    pthread_t listeners[2], workers[2];
    for (int i=0;i<2;++i) {
        servers[i].udp = bind_socket(&clients[i].address, 0, 0);
        assert(pthread_create(&listeners[i], NULL, serve, &servers[i]) == 0);
        assert(pthread_create(&workers[i], NULL, client, &clients[i]) == 0);
    }
    int rc = pthread_barrier_wait(&barrier); assert(rc == 0 || rc == PTHREAD_BARRIER_SERIAL_THREAD);
    assert(clients[0].pointer != clients[1].pointer && clients[0].pointer != state_ptr() && clients[1].pointer != state_ptr());
    rc = pthread_barrier_wait(&barrier); assert(rc == 0 || rc == PTHREAD_BARRIER_SERIAL_THREAD);
    for (int i=0;i<2;++i) { assert(pthread_join(workers[i], NULL) == 0); assert(pthread_join(listeners[i], NULL) == 0); assert(close(servers[i].udp) == 0); }
    assert(pthread_barrier_destroy(&barrier) == 0); pass("simultaneous global callers retain separate TLS endpoints");
}
int main(int argc, char **argv) {
    assert(argc == 2); const char *candidate = strcmp(argv[1], "--host") ? argv[1] : NULL;
    void *handle = dlopen(candidate ? candidate : "libc.so.6", RTLD_NOW | RTLD_LOCAL); assert(handle);
    state_ptr = symbol(handle,"__res_state",candidate); initialize = symbol(handle,"__res_init",candidate);
    state_close = symbol(handle,"__res_nclose",candidate); build = symbol(handle,"res_mkquery",candidate);
    send_raw = symbol(handle,"res_send",candidate); query = symbol(handle,"res_query",candidate);
    search = symbol(handle,"res_search",candidate); querydomain = symbol(handle,"res_querydomain",candidate);
    host_error = symbol(handle,"__h_errno_location",candidate);
    initialization_cases();
    for (int transport=0;transport<3;++transport) {
        network_case(0,transport,0,0,42,1,512,0,0);
        network_case(1,transport,0,0,42,1,transport?12:512,0,0);
    }
    network_case(0,0,0,0,42,ns_c_chaos,512,0,0);
    network_case(0,0,0,ns_r_nxdomain,0,1,512,0,0);
    network_case(0,0,0,0,0,1,512,0,0);
    network_case(0,0,0,0,42,1,512,1,0);
    network_case(0,0,0,0,42,1,512,0,1);
    for (int edns=1;edns<=2;++edns) network_case(0,2,edns,0,42,1,512,0,0);
    network_case(2,0,0,0,42,1,512,0,0);
    network_case(3,0,0,0,42,1,512,0,0);
    thread_case();
    printf("%u %s global resolver cases passed\n", passed, candidate ? "candidate" : "host-glibc");
    return 0;
}
