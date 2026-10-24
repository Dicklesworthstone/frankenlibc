/* No libc dependency: sockets, waits and timers must share one native runtime. */
#define _GNU_SOURCE
#include <dlfcn.h>
#include <errno.h>
#include <poll.h>
#include <signal.h>
#include <stdint.h>
#include <sys/epoll.h>
#include <sys/eventfd.h>
#include <sys/select.h>
#include <sys/socket.h>
#include <sys/timerfd.h>
#include <unistd.h>

#define CHECK(test) do { if (!(test)) return __LINE__; } while (0)

int event_readiness_protocol(void) {
    int fd = eventfd(0, EFD_CLOEXEC | EFD_NONBLOCK);
    CHECK(fd >= 0 && fd < FD_SETSIZE);
    struct pollfd watch = {fd, POLLIN, 99};
    CHECK(poll(&watch, 1, 0) == 0 && watch.revents == 0);
    uint64_t value = 7;
    CHECK(write(fd, &value, sizeof(value)) == sizeof(value));
    value = 5;
    CHECK(write(fd, &value, sizeof(value)) == sizeof(value));
    CHECK(poll(&watch, 1, 0) == 1 && (watch.revents & POLLIN));
    const struct timespec zero = {0, 0};
    const sigset_t mask = {0};
    CHECK(ppoll(&watch, 1, &zero, &mask) == 1 && (watch.revents & POLLIN));
    fd_set ready;
    FD_ZERO(&ready); FD_SET(fd, &ready);
    struct timeval timeout = {0, 0};
    CHECK(select(fd + 1, &ready, 0, 0, &timeout) == 1 && FD_ISSET(fd, &ready));
    FD_ZERO(&ready); FD_SET(fd, &ready);
    CHECK(pselect(fd + 1, &ready, 0, 0, &zero, &mask) == 1 && FD_ISSET(fd, &ready));
    value = 0;
    CHECK(read(fd, &value, sizeof(value)) == sizeof(value) && value == 12);
    CHECK(poll(&watch, 1, 0) == 0 && watch.revents == 0);
    errno = 0; value = 91;
    CHECK(read(fd, &value, sizeof(value)) == -1 && errno == EAGAIN && value == 91);
    CHECK(close(fd) == 0);
    watch.fd = -1; watch.revents = 99;
    CHECK(poll(&watch, 1, 0) == 0 && watch.revents == 0);

    fd = eventfd(2, EFD_SEMAPHORE | EFD_NONBLOCK | EFD_CLOEXEC);
    CHECK(fd >= 0);
    CHECK(read(fd, &value, sizeof(value)) == sizeof(value) && value == 1);
    CHECK(read(fd, &value, sizeof(value)) == sizeof(value) && value == 1);
    errno = 0;
    CHECK(read(fd, &value, sizeof(value)) == -1 && errno == EAGAIN);
    CHECK(close(fd) == 0);
    return 0;
}

int event_epoll_socket_protocol(void) {
    int old = epoll_create(1); CHECK(old >= 0 && close(old) == 0);
    errno = 0; CHECK(epoll_create(0) == -1 && errno == EINVAL);
    int ep = epoll_create1(EPOLL_CLOEXEC); CHECK(ep >= 0);
    int ends[2];
    CHECK(socketpair(AF_UNIX, SOCK_STREAM | SOCK_NONBLOCK | SOCK_CLOEXEC, 0, ends) == 0);
    const uint64_t token = UINT64_C(0xabcdef0123456789);
    struct epoll_event interest = {.events = EPOLLIN | EPOLLONESHOT, .data.u64 = token};
    struct epoll_event output[2] = {0};
    CHECK(epoll_ctl(ep, EPOLL_CTL_ADD, ends[1], &interest) == 0);
    CHECK(epoll_wait(ep, output, 2, 0) == 0);
    CHECK(send(ends[0], "X", 1, MSG_NOSIGNAL) == 1);
    CHECK(epoll_wait(ep, output, 2, 1000) == 1);
    CHECK((output[0].events & EPOLLIN) && output[0].data.u64 == token);
    /* One-shot readiness must not repeat until explicitly rearmed. */
    CHECK(epoll_wait(ep, output, 2, 0) == 0);
    interest.data.u64 = token + 1;
    CHECK(epoll_ctl(ep, EPOLL_CTL_MOD, ends[1], &interest) == 0);
    const sigset_t mask = {0};
    CHECK(epoll_pwait(ep, output, 2, 1000, &mask) == 1);
    CHECK((output[0].events & EPOLLIN) && output[0].data.u64 == token + 1);
    char byte = 0;
    CHECK(recv(ends[1], &byte, 1, 0) == 1 && byte == 'X');
    CHECK(epoll_ctl(ep, EPOLL_CTL_DEL, ends[1], 0) == 0);
    CHECK(send(ends[0], "Y", 1, MSG_NOSIGNAL) == 1);
    CHECK(epoll_pwait(ep, output, 2, 0, &mask) == 0);
    errno = 0;
    CHECK(epoll_wait(-1, output, 2, 0) == -1 && errno == EBADF);
    CHECK(close(ends[0]) == 0 && close(ends[1]) == 0 && close(ep) == 0);
    return 0;
}

int event_timer_protocol(void) {
    int fd = timerfd_create(CLOCK_MONOTONIC, TFD_NONBLOCK | TFD_CLOEXEC);
    CHECK(fd >= 0);
    struct itimerspec setting = {{0, 0}, {1, 0}};
    struct itimerspec old = {{99, 99}, {99, 99}};
    /* A nonzero absolute deadline in the past avoids scheduler-sensitive sleeps. */
    CHECK(timerfd_settime(fd, TFD_TIMER_ABSTIME, &setting, &old) == 0);
    CHECK(old.it_value.tv_sec == 0 && old.it_value.tv_nsec == 0);
    CHECK(old.it_interval.tv_sec == 0 && old.it_interval.tv_nsec == 0);
    struct pollfd watch = {fd, POLLIN, 0};
    CHECK(poll(&watch, 1, 1000) == 1 && (watch.revents & POLLIN));
    uint64_t count = 0;
    CHECK(read(fd, &count, sizeof(count)) == sizeof(count) && count == 1);
    CHECK(timerfd_gettime(fd, &old) == 0);
    CHECK(old.it_value.tv_sec == 0 && old.it_value.tv_nsec == 0);
    setting.it_value.tv_sec = 0;
    CHECK(timerfd_settime(fd, 0, &setting, 0) == 0);
    CHECK(poll(&watch, 1, 0) == 0);
    errno = 0; count = 91;
    CHECK(read(fd, &count, sizeof(count)) == -1 && errno == EAGAIN && count == 91);
    CHECK(close(fd) == 0);
    return 0;
}

void *event_function(unsigned index) {
    switch (index) {
        case 0: return (void *)poll;
        case 1: return (void *)ppoll;
        case 2: return (void *)select;
        case 3: return (void *)pselect;
        case 4: return (void *)epoll_create;
        case 5: return (void *)epoll_create1;
        case 6: return (void *)epoll_ctl;
        case 7: return (void *)epoll_wait;
        case 8: return (void *)epoll_pwait;
        case 9: return (void *)eventfd;
        case 10: return (void *)timerfd_create;
        case 11: return (void *)timerfd_settime;
        case 12: return (void *)timerfd_gettime;
        default: return 0;
    }
}

void *event_dynamic(const char *name, const char *version, int *error) {
    dlerror();
    void *result = version ? dlvsym(RTLD_DEFAULT, name, version)
                           : dlsym(RTLD_DEFAULT, name);
    *error = dlerror() != 0;
    __asm__ __volatile__("" : "+r"(result));
    return result;
}
