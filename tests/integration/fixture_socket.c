/* fixture_socket.c — socket syscall semantics smoke fixture (bd-15n.2)
 * Exit 0 = PASS, nonzero = FAIL with diagnostics.
 */
#include <errno.h>
#include <netinet/in.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>

static int test_socket_and_getsockopt(void) {
    int fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0) {
        fprintf(stderr, "FAIL: socket(AF_INET, SOCK_STREAM, 0) errno=%d\n", errno);
        return 1;
    }

    int so_type = -1;
    socklen_t len = sizeof(so_type);
    if (getsockopt(fd, SOL_SOCKET, SO_TYPE, &so_type, &len) != 0) {
        fprintf(stderr, "FAIL: getsockopt(SO_TYPE) errno=%d\n", errno);
        close(fd);
        return 1;
    }
    if (so_type != SOCK_STREAM) {
        fprintf(stderr, "FAIL: SO_TYPE=%d expected=%d\n", so_type, SOCK_STREAM);
        close(fd);
        return 1;
    }

    close(fd);
    return 0;
}

static int test_invalid_fd_errors(void) {
    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = htons(12345);
    addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);

    if (bind(-1, (struct sockaddr *)&addr, sizeof(addr)) != -1 || errno != EBADF) {
        fprintf(stderr, "FAIL: bind(-1,...) expected EBADF got errno=%d\n", errno);
        return 1;
    }

    if (send(-1, "x", 1, 0) != -1 || errno != EBADF) {
        fprintf(stderr, "FAIL: send(-1,...) expected EBADF got errno=%d\n", errno);
        return 1;
    }

    char ch;
    if (recv(-1, &ch, 1, 0) != -1 || errno != EBADF) {
        fprintf(stderr, "FAIL: recv(-1,...) expected EBADF got errno=%d\n", errno);
        return 1;
    }

    if (shutdown(-1, SHUT_RDWR) != -1 || errno != EBADF) {
        fprintf(stderr, "FAIL: shutdown(-1,...) expected EBADF got errno=%d\n", errno);
        return 1;
    }

    return 0;
}

int main(void) {
    int fails = 0;
    fails += test_socket_and_getsockopt();
    fails += test_invalid_fd_errors();

    if (fails) {
        fprintf(stderr, "fixture_socket: %d FAILED\n", fails);
        return 1;
    }
    printf("fixture_socket: PASS (2 tests)\n");
    return 0;
}
