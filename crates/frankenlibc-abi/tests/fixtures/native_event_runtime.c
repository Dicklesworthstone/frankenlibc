/* No libc dependency: sockets, waits and timers must share one native runtime. */
#define _GNU_SOURCE
#include <dlfcn.h>
#include <errno.h>
#include <poll.h>
#include <signal.h>
#include <stdatomic.h>
#include <stdint.h>
#include <string.h>
#include <sys/epoll.h>
#include <sys/eventfd.h>
#include <sys/select.h>
#include <sys/signalfd.h>
#include <sys/socket.h>
#include <sys/timerfd.h>
#include <unistd.h>

#define CHECK(test) do { if (!(test)) return __LINE__; } while (0)

/* This historical entry remains exported even when modern feature-test
   macros hide its declaration. Its ABI is the ordinary BSD signal ABI. */
extern void (*bsd_signal(int, void (*)(int)))(int);

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

int event_signal_sets_protocol(void) {
    sigset_t empty, first, second, combined, full;
    CHECK(sigemptyset(&empty) == 0 && sigisemptyset(&empty) == 1);
    first = empty;
    second = empty;
    CHECK(sigaddset(&first, SIGUSR1) == 0 && sigaddset(&second, SIGUSR2) == 0);
    CHECK(sigorset(&combined, &first, &second) == 0);
    CHECK(sigismember(&combined, SIGUSR1) == 1 && sigismember(&combined, SIGUSR2) == 1);
    CHECK(sigandset(&combined, &combined, &first) == 0);
    CHECK(sigismember(&combined, SIGUSR1) == 1 && sigismember(&combined, SIGUSR2) == 0);
    CHECK(sigdelset(&combined, SIGUSR1) == 0 && sigisemptyset(&combined) == 1);
    CHECK(sigfillset(&full) == 0);
    CHECK(sigismember(&full, SIGUSR1) == 1 && sigismember(&full, SIGUSR2) == 1);
    CHECK(SIGRTMIN > 0 && SIGRTMIN <= SIGRTMAX && sigismember(&full, SIGRTMAX) == 1);
    errno = 0;
    CHECK(sigaddset(&empty, 0) == -1 && errno == EINVAL);
    CHECK(sigisemptyset(&empty) == 1);
    errno = 0;
    CHECK(sigdelset(&first, SIGRTMAX + 1) == -1 && errno == EINVAL);
    CHECK(sigismember(&first, SIGUSR1) == 1);
    const char *name = sigabbrev_np(SIGUSR1);
    CHECK(name && name[0] == 'U' && name[1] == 'S' && name[2] == 'R' && name[3] == '1' && name[4] == 0);
    CHECK(sigdescr_np(SIGUSR1) && sigabbrev_np(0) == 0 && sigdescr_np(0) == 0);
    CHECK(raise(0) == 0 && kill(getpid(), 0) == 0 && tgkill(getpid(), gettid(), 0) == 0);
    errno = 0;
    CHECK(killpg(-1, 0) == -1 && errno == EINVAL);
    return 0;
}

int event_signal_wait_protocol(void) {
    sigset_t selected, original, pending;
    CHECK(sigemptyset(&selected) == 0 && sigaddset(&selected, SIGUSR2) == 0);
    CHECK(sigprocmask(SIG_BLOCK, &selected, &original) == 0);
    CHECK(raise(SIGUSR2) == 0);
    CHECK(sigpending(&pending) == 0 && sigismember(&pending, SIGUSR2) == 1);
    siginfo_t info = {0};
    const struct timespec zero = {0, 0};
    CHECK(sigtimedwait(&selected, &info, &zero) == SIGUSR2);
    CHECK(info.si_signo == SIGUSR2 && info.si_pid == getpid());
    CHECK(sigpending(&pending) == 0 && sigismember(&pending, SIGUSR2) == 0);
    errno = 0;
    CHECK(sigtimedwait(&selected, &info, &zero) == -1 && errno == EAGAIN);
    CHECK(raise(SIGUSR2) == 0 && sigwaitinfo(&selected, &info) == SIGUSR2);
    CHECK(info.si_signo == SIGUSR2 && info.si_pid == getpid());
    CHECK(raise(SIGUSR2) == 0);
    int received = -1;
    errno = 1234;
    CHECK(sigwait(&selected, &received) == 0 && received == SIGUSR2 && errno == 1234);

    /* The signal stays on this thread, so another test-harness thread cannot
       consume it. signalfd must share the selected signal mask and IO domain. */
    int fd = signalfd(-1, &selected, SFD_NONBLOCK | SFD_CLOEXEC);
    CHECK(fd >= 0 && raise(SIGUSR2) == 0);
    struct pollfd watch = {fd, POLLIN, 0};
    CHECK(poll(&watch, 1, 1000) == 1 && (watch.revents & POLLIN));
    struct signalfd_siginfo record = {0};
    CHECK(read(fd, &record, sizeof(record)) == sizeof(record));
    CHECK(record.ssi_signo == SIGUSR2 && record.ssi_pid == (unsigned)getpid());
    errno = 0;
    CHECK(read(fd, &record, sizeof(record)) == -1 && errno == EAGAIN);
    CHECK(close(fd) == 0);
    CHECK(sigprocmask(SIG_SETMASK, &original, 0) == 0);
    return 0;
}

_Static_assert(ATOMIC_INT_LOCK_FREE == 2, "signal fixture needs lock-free atomics");
static _Atomic int signal_seen;
static _Atomic int signal_code;
static _Atomic int signal_value;
static _Atomic int signal_pid;
static _Atomic int signal_on_stack;
static unsigned char signal_stack[65536] __attribute__((aligned(16)));

static void event_signal_handler(int number, siginfo_t *info, void *context) {
    unsigned char marker;
    uintptr_t stack_address = (uintptr_t)&marker;
    (void)context;
    atomic_store_explicit(&signal_code, info ? info->si_code : 0, memory_order_relaxed);
    atomic_store_explicit(&signal_value, info ? info->si_value.sival_int : 0, memory_order_relaxed);
    atomic_store_explicit(&signal_pid, info ? info->si_pid : 0, memory_order_relaxed);
    atomic_store_explicit(&signal_on_stack,
        stack_address >= (uintptr_t)signal_stack &&
        stack_address < (uintptr_t)signal_stack + sizeof(signal_stack), memory_order_relaxed);
    if (number == SIGUSR1) atomic_fetch_add_explicit(&signal_seen, 1, memory_order_release);
}

static void event_simple_handler(int number) {
    if (number == SIGUSR1) atomic_fetch_add_explicit(&signal_seen, 1, memory_order_release);
}

/* Exercising this obsolete API is intentional; all other warnings remain
   errors for the fixture, including ABI declarations and conversions. */
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wdeprecated-declarations"
int event_signal_handler_protocol(void) {
    sigset_t selected, original, suspend_mask;
    CHECK(sigemptyset(&selected) == 0 && sigaddset(&selected, SIGUSR1) == 0);
    CHECK(sigprocmask(SIG_UNBLOCK, &selected, &original) == 0);
    stack_t previous_stack, alternate = {signal_stack, 0, sizeof(signal_stack)};
    CHECK(sigaltstack(&alternate, &previous_stack) == 0);
    struct sigaction original_action, action = {0}, observed;
    action.sa_sigaction = event_signal_handler;
    action.sa_flags = SA_SIGINFO | SA_ONSTACK | SA_RESTART;
    CHECK(sigemptyset(&action.sa_mask) == 0);
    CHECK(sigaction(SIGUSR1, &action, &original_action) == 0);
    atomic_store_explicit(&signal_seen, 0, memory_order_release);
    CHECK(raise(SIGUSR1) == 0);
    CHECK(atomic_load_explicit(&signal_seen, memory_order_acquire) == 1);
    CHECK(atomic_load_explicit(&signal_on_stack, memory_order_relaxed) == 1);

    union sigval value = {.sival_int = 0x123456};
    CHECK(sigqueue(getpid(), SIGUSR1, value) == 0);
    /* The runner blocks SIGUSR1 before exec; this protocol is the only thread
       to unblock it. Queue delivery must finish on this thread before the
       plugin can restore its action and later be unmapped. */
    for (unsigned attempt = 0; atomic_load_explicit(&signal_seen, memory_order_acquire) < 2 && attempt < 2000; ++attempt)
        (void)poll(0, 0, 1);
    CHECK(atomic_load_explicit(&signal_seen, memory_order_acquire) == 2);
    CHECK(atomic_load_explicit(&signal_code, memory_order_relaxed) == SI_QUEUE);
    CHECK(atomic_load_explicit(&signal_value, memory_order_relaxed) == value.sival_int);
    CHECK(atomic_load_explicit(&signal_pid, memory_order_relaxed) == getpid());

    CHECK(sigprocmask(SIG_BLOCK, &selected, &suspend_mask) == 0);
    CHECK(raise(SIGUSR1) == 0 && atomic_load_explicit(&signal_seen, memory_order_acquire) == 2);
    CHECK(sigdelset(&suspend_mask, SIGUSR1) == 0);
    errno = 0;
    CHECK(sigsuspend(&suspend_mask) == -1 && errno == EINTR);
    CHECK(atomic_load_explicit(&signal_seen, memory_order_acquire) == 3);
    CHECK(sigprocmask(SIG_UNBLOCK, &selected, 0) == 0);

    CHECK(siginterrupt(SIGUSR1, 1) == 0);
    CHECK(sigaction(SIGUSR1, 0, &observed) == 0 && !(observed.sa_flags & SA_RESTART));
    CHECK(siginterrupt(SIGUSR1, 0) == 0);
    CHECK(sigaction(SIGUSR1, 0, &observed) == 0 && (observed.sa_flags & SA_RESTART));
    CHECK(signal(SIGUSR1, event_simple_handler) != SIG_ERR && raise(SIGUSR1) == 0);
    CHECK(atomic_load_explicit(&signal_seen, memory_order_acquire) == 4);
    CHECK(bsd_signal(SIGUSR1, event_simple_handler) == event_simple_handler);
    CHECK(raise(SIGUSR1) == 0 && atomic_load_explicit(&signal_seen, memory_order_acquire) == 5);
    /* Restore every callback before dlclose can retire its defining mapping. */
    CHECK(sigaction(SIGUSR1, &original_action, 0) == 0);
    CHECK(sigaltstack(&previous_stack, 0) == 0);
    CHECK(sigprocmask(SIG_SETMASK, &original, 0) == 0);
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
        case 13: return (void *)signal;
        case 14: return (void *)raise;
        case 15: return (void *)kill;
        case 16: return (void *)killpg;
        case 17: return (void *)sigemptyset;
        case 18: return (void *)sigfillset;
        case 19: return (void *)sigaddset;
        case 20: return (void *)sigdelset;
        case 21: return (void *)sigismember;
        case 22: return (void *)sigandset;
        case 23: return (void *)sigorset;
        case 24: return (void *)sigisemptyset;
        case 25: return (void *)sigprocmask;
        case 26: return (void *)sigpending;
        case 27: return (void *)sigsuspend;
        case 28: return (void *)sigaction;
        case 29: return (void *)sigaltstack;
        case 30: return (void *)siginterrupt;
        case 31: return (void *)sigwait;
        case 32: return (void *)sigqueue;
        case 33: return (void *)sigwaitinfo;
        case 34: return (void *)sigtimedwait;
        case 35: return (void *)pause;
        case 36: return (void *)sigabbrev_np;
        case 37: return (void *)sigdescr_np;
        case 38: return (void *)signalfd;
        case 39: return (void *)tgkill;
        case 40: return (void *)__libc_current_sigrtmin;
        case 41: return (void *)__libc_current_sigrtmax;
        case 42: return (void *)bsd_signal;
        default: return 0;
    }
}
#pragma GCC diagnostic pop

void *event_dynamic(const char *name, const char *version, int *error) {
    dlerror();
    void *result = version ? dlvsym(RTLD_DEFAULT, name, version)
                           : dlsym(RTLD_DEFAULT, name);
    *error = dlerror() != 0;
    __asm__ __volatile__("" : "+r"(result));
    return result;
}
