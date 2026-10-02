/* socket()/socketpair() across address families and types.
 *
 * fl's strict mode (the default) refused every family but UNIX, INET,
 * INET6 and NETLINK (and every type but STREAM, DGRAM, RAW, SEQPACKET)
 * with its own allow-list, before the kernel was asked: AF_PACKET, AF_ALG,
 * AF_VSOCK, AF_CAN ... all failed with EAFNOSUPPORT (CPython test_socket's
 * VSOCK tests). Output is compared byte-for-byte with glibc; only the
 * result class and errno are printed, so kernel support decides both.
 */
#include <errno.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

#ifndef AF_VSOCK
#define AF_VSOCK 40
#endif
#ifndef AF_XDP
#define AF_XDP 44
#endif

int main(void) {
    struct {
        const char *name;
        int domain;
    } families[] = {
        {"AF_UNSPEC", AF_UNSPEC}, {"AF_UNIX", AF_UNIX},       {"AF_INET", AF_INET},
        {"AF_INET6", AF_INET6},   {"AF_NETLINK", AF_NETLINK}, {"AF_PACKET", AF_PACKET},
        {"AF_ALG", AF_ALG},       {"AF_VSOCK", AF_VSOCK},     {"AF_CAN", AF_CAN},
        {"AF_TIPC", AF_TIPC},     {"AF_XDP", AF_XDP},         {"AF_KEY", AF_KEY},
        {"AF_MAX+5", AF_MAX + 5}, {"-1", -1},
    };
    struct {
        const char *name;
        int type;
    } types[] = {
        {"STREAM", SOCK_STREAM}, {"DGRAM", SOCK_DGRAM}, {"SEQPACKET", SOCK_SEQPACKET},
        {"RDM", SOCK_RDM},       {"RAW", SOCK_RAW},     {"DCCP", 6},
        {"PACKET", SOCK_PACKET}, {"99", 99},
    };
    for (size_t f = 0; f < sizeof families / sizeof *families; f++) {
        for (size_t t = 0; t < sizeof types / sizeof *types; t++) {
            errno = 0;
            int fd = socket(families[f].domain, types[t].type | SOCK_CLOEXEC, 0);
            int e = errno;
            printf("socket(%s, %s) = %s", families[f].name, types[t].name, fd >= 0 ? "fd" : "-1");
            if (fd < 0)
                printf(" errno=%s", strerror(e));
            else
                close(fd);
            int sv[2];
            errno = 0;
            int r = socketpair(families[f].domain, types[t].type, 0, sv);
            e = errno;
            printf("; socketpair = %d", r);
            if (r < 0)
                printf(" errno=%s", strerror(e));
            else {
                close(sv[0]);
                close(sv[1]);
            }
            putchar('\n');
        }
    }
    return 0;
}
