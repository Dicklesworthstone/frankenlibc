/* A dependency-free DSO: every imported runtime function must bind natively. */
#define _GNU_SOURCE
#include <dlfcn.h>
#include <errno.h>
#include <stddef.h>
#include <stdint.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <unistd.h>

#define CHECK(test) do { if (!(test)) return __LINE__; } while (0)

int socket_stream_protocol(void) {
    int ends[2];
    CHECK(socketpair(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0, ends) == 0);
    int kind = 0, enabled = 1;
    socklen_t length = sizeof(kind);
    CHECK(getsockopt(ends[0], SOL_SOCKET, SO_TYPE, &kind, &length) == 0);
    CHECK(kind == SOCK_STREAM && length == sizeof(kind));
    CHECK(setsockopt(ends[0], SOL_SOCKET, SO_KEEPALIVE, &enabled, sizeof(enabled)) == 0);
    struct sockaddr_un address;
    length = sizeof(address);
    CHECK(getsockname(ends[0], (struct sockaddr *)&address, &length) == 0);
    CHECK(address.sun_family == AF_UNIX);
    length = sizeof(address);
    CHECK(getpeername(ends[0], (struct sockaddr *)&address, &length) == 0);
    CHECK(address.sun_family == AF_UNIX);
    CHECK(send(ends[0], "hello", 5, MSG_NOSIGNAL) == 5);
    char data[6] = {0, 0, 0, 0, 0, 99};
    CHECK(recv(ends[1], data, 5, MSG_WAITALL) == 5);
    CHECK(data[0] == 'h' && data[4] == 'o' && data[5] == 99);
    CHECK(shutdown(ends[0], SHUT_WR) == 0);
    CHECK(recv(ends[1], data, 1, 0) == 0);
    CHECK(close(ends[0]) == 0 && close(ends[1]) == 0);
    errno = 0; data[0] = 42;
    CHECK(recv(-1, data, 1, MSG_DONTWAIT) == -1 && errno == EBADF);
    CHECK(data[0] == 42);
    return 0;
}

int socket_datagram_protocol(void) {
    int ends[2];
    CHECK(socketpair(AF_UNIX, SOCK_DGRAM | SOCK_NONBLOCK | SOCK_CLOEXEC, 0, ends) == 0);
    CHECK(sendto(ends[0], "one", 3, 0, 0, 0) == 3);
    char data[4] = {0, 0, 0, 77};
    CHECK(recvfrom(ends[1], data, 3, 0, 0, 0) == 3);
    CHECK(data[0] == 'o' && data[2] == 'e' && data[3] == 77);
    struct iovec out[2] = {{(void *)"ab", 2}, {(void *)"cd", 2}};
    struct msghdr message = {0};
    message.msg_iov = out; message.msg_iovlen = 2;
    CHECK(sendmsg(ends[0], &message, 0) == 4);
    char left[3] = {0, 0, 88}, right[3] = {0, 0, 99};
    struct iovec in[2] = {{left, 2}, {right, 2}};
    message.msg_iov = in;
    CHECK(recvmsg(ends[1], &message, 0) == 4);
    CHECK(left[0] == 'a' && left[1] == 'b' && left[2] == 88);
    CHECK(right[0] == 'c' && right[1] == 'd' && right[2] == 99);
    CHECK((message.msg_flags & MSG_TRUNC) == 0);

    struct mmsghdr batch[2] = {0};
    struct iovec vectors[2] = {{(void *)"A", 1}, {(void *)"B", 1}};
    for (unsigned i = 0; i < 2; ++i) {
        batch[i].msg_hdr.msg_iov = &vectors[i];
        batch[i].msg_hdr.msg_iovlen = 1;
    }
    CHECK(sendmmsg(ends[0], batch, 2, 0) == 2);
    CHECK(batch[0].msg_len == 1 && batch[1].msg_len == 1);
    char bytes[2] = {0, 0};
    for (unsigned i = 0; i < 2; ++i) {
        vectors[i].iov_base = &bytes[i];
        batch[i].msg_len = 0;
    }
    CHECK(recvmmsg(ends[1], batch, 2, MSG_DONTWAIT, 0) == 2);
    CHECK(batch[0].msg_len == 1 && batch[1].msg_len == 1);
    CHECK(bytes[0] == 'A' && bytes[1] == 'B');
    errno = 0; data[0] = 42;
    CHECK(recv(ends[1], data, 1, MSG_DONTWAIT) == -1 && errno == EAGAIN);
    CHECK(data[0] == 42);
    CHECK(close(ends[0]) == 0 && close(ends[1]) == 0);
    return 0;
}

int socket_listener_protocol(uint64_t nonce) {
    struct sockaddr_un address = {0};
    address.sun_family = AF_UNIX;
    /* An abstract address needs no filesystem cleanup or global fixed port. */
    for (unsigned i = 0; i < sizeof(nonce); ++i)
        address.sun_path[i + 1] = (char)(nonce >> (8 * i));
    socklen_t size = offsetof(struct sockaddr_un, sun_path) + 1 + sizeof(nonce);
    int server = socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0);
    CHECK(server >= 0);
    CHECK(bind(server, (struct sockaddr *)&address, size) == 0);
    CHECK(listen(server, 2) == 0);
    for (unsigned round = 0; round < 2; ++round) {
        int client = socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0);
        CHECK(client >= 0);
        CHECK(connect(client, (struct sockaddr *)&address, size) == 0);
        int peer = round ? accept(server, 0, 0)
                         : accept4(server, 0, 0, SOCK_NONBLOCK | SOCK_CLOEXEC);
        CHECK(peer >= 0);
        CHECK(send(client, "S", 1, MSG_NOSIGNAL) == 1);
        char byte = 0;
        CHECK(recv(peer, &byte, 1, 0) == 1 && byte == 'S');
        CHECK(close(peer) == 0 && close(client) == 0);
    }
    CHECK(close(server) == 0);
    return 0;
}

void *socket_function(unsigned index) {
    switch (index) {
        case 0: return (void *)socket;
        case 1: return (void *)socketpair;
        case 2: return (void *)bind;
        case 3: return (void *)listen;
        case 4: return (void *)connect;
        case 5: return (void *)accept;
        case 6: return (void *)accept4;
        case 7: return (void *)shutdown;
        case 8: return (void *)getsockname;
        case 9: return (void *)getpeername;
        case 10: return (void *)getsockopt;
        case 11: return (void *)setsockopt;
        case 12: return (void *)send;
        case 13: return (void *)recv;
        case 14: return (void *)sendto;
        case 15: return (void *)recvfrom;
        case 16: return (void *)sendmsg;
        case 17: return (void *)recvmsg;
        case 18: return (void *)sendmmsg;
        case 19: return (void *)recvmmsg;
        default: return 0;
    }
}

void *socket_dynamic(const char *name, const char *version, int *error) {
    dlerror();
    void *result = version ? dlvsym(RTLD_DEFAULT, name, version)
                           : dlsym(RTLD_DEFAULT, name);
    *error = dlerror() != 0;
    /* Preserve a return PC in this DSO for the caller-relative lookup bridge. */
    __asm__ __volatile__("" : "+r"(result));
    return result;
}
