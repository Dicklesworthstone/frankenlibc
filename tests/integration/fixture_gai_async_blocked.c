/* Real, controlled DNS over loopback. The runner supplies private resolver and
 * NSS configuration paths. No kernel filters or system configuration changes. */
#define main gai_basic_fixture_main
#include "fixture_gai_async.c"
#undef main
#include <poll.h>
#include <dirent.h>

static atomic_int stopped, released, blocked_count, interrupt_wait;
static pthread_t controller_thread, interrupted_thread;
static volatile sig_atomic_t signal_count;
static char blocked_names[20][96];
static int server_fd;
static int successful_reply;

struct packet {
    unsigned char data[512];
    size_t size;
    struct sockaddr_in peer;
    socklen_t peer_size;
};

static void reply_dns(struct packet *p) {
    CHECK(p->size >= 17 && p->data[4] == 0 && p->data[5] == 1);
    size_t end = 12;
    while (end < p->size && p->data[end]) {
        unsigned length = p->data[end];
        CHECK(length <= 63 && end + length + 1 < p->size);
        end += length + 1;
    }
    CHECK(end + 5 <= p->size);
    unsigned type = ((unsigned)p->data[end + 1] << 8) | p->data[end + 2];
    end += 5;
    CHECK(type == 1 || type == 28);
    unsigned char response[560];
    memcpy(response, p->data, end);
    response[2] = 0x81; response[3] = successful_reply ? 0x80 : 0x83;
    memset(response + 6, 0, 6);
    if (successful_reply) {
        response[7] = 1;
        const unsigned char answer[] = {0xc0, 0x0c, 0, (unsigned char)type,
                                       0, 1, 0, 0, 0, 10, 0, type == 1 ? 4 : 16};
        memcpy(response + end, answer, sizeof(answer)); end += sizeof(answer);
        size_t bytes = type == 1 ? 4 : 16;
        memset(response + end, 0, bytes);
        if (type == 1) { response[end] = 127; response[end + 3] = 7; }
        else response[end + 15] = 1;
        end += bytes;
    }
    CHECK(sendto(server_fd, response, end, 0, (struct sockaddr *)&p->peer, p->peer_size) == (ssize_t)end);
}

static void *control_dns(void *unused) {
    (void)unused;
    struct packet held[64];
    int count = 0;
    while (!atomic_load_explicit(&stopped, memory_order_acquire)) {
        if (atomic_load_explicit(&interrupt_wait, memory_order_acquire))
            CHECK(pthread_kill(interrupted_thread, SIGUSR1) == 0);
        if (atomic_load_explicit(&released, memory_order_acquire)) {
            while (count) reply_dns(&held[--count]);
        }
        struct pollfd pfd = {.fd = server_fd, .events = POLLIN};
        int rc = poll(&pfd, 1, 2);
        if (rc < 0 && errno == EINTR) continue;
        CHECK(rc >= 0);
        if (!rc) continue;
        CHECK(count < 64);
        struct packet *p = &held[count];
        p->peer_size = sizeof(p->peer);
        ssize_t size = recvfrom(server_fd, p->data, sizeof(p->data), 0,
                                (struct sockaddr *)&p->peer, &p->peer_size);
        CHECK(size > 0); p->size = (size_t)size;
        ++count;
        atomic_fetch_add_explicit(&blocked_count, 1, memory_order_release);
    }
    return NULL;
}

static void install_blocking_controller(void) {
    CHECK(getenv("FRANKENLIBC_RESOLV_CONF") && getenv("FRANKENLIBC_NSSWITCH_CONF"));
    server_fd = socket(AF_INET, SOCK_DGRAM | SOCK_CLOEXEC, 0);
    CHECK(server_fd >= 0);
    struct sockaddr_in address = {.sin_family = AF_INET, .sin_port = htons(53)};
    CHECK(inet_pton(AF_INET, "127.0.0.77", &address.sin_addr) == 1);
    CHECK(bind(server_fd, (struct sockaddr *)&address, sizeof(address)) == 0);
    interrupted_thread = pthread_self();
    CHECK(pthread_create(&controller_thread, NULL, control_dns, NULL) == 0);
}

static void await_blocked(int expected) {
    for (int i = 0; atomic_load_explicit(&blocked_count, memory_order_acquire) < expected; ++i) {
        CHECK(i < 4000);
        pause_ms(1);
    }
}

static double seconds(void) {
    struct timespec now;
    CHECK(clock_gettime(CLOCK_MONOTONIC, &now) == 0);
    return (double)now.tv_sec + (double)now.tv_nsec / 1e9;
}

static void finish_controller(struct gaicb *requests, int count) {
    atomic_store_explicit(&released, 1, memory_order_release);
    for (int i = 0; i < count; ++i) {
        wait_cb(&requests[i]);
        CHECK(gai_error(&requests[i]) == (successful_reply ? 0 : EAI_NONAME));
        if (successful_reply) {
            int family = requests[i].ar_request->ai_family;
            verify(&requests[i], family, family == AF_INET ? "127.0.0.7" : "::1");
            freeaddrinfo(requests[i].ar_result);
        }
    }
    atomic_store_explicit(&stopped, 1, memory_order_release);
    CHECK(pthread_join(controller_thread, NULL) == 0);
    CHECK(close(server_fd) == 0);
}

static void blocked_requests(struct gaicb *requests, struct addrinfo *h, int count) {
    *h = hint(AF_INET); h->ai_flags = AI_NUMERICSERV;
    struct gaicb *list[20];
    CHECK(count <= 20);
    for (int i = 0; i < count; ++i) {
        CHECK(snprintf(blocked_names[i], sizeof(blocked_names[i]),
                       "blocked-%d.gai-contract.invalid", i) > 0);
        init(&requests[i], blocked_names[i], h); list[i] = &requests[i];
    }
    CHECK(getaddrinfo_a(GAI_NOWAIT, list, count, NULL) == 0);
    await_blocked(count);
    for (int i = 0; i < count; ++i) CHECK(gai_error(&requests[i]) == EAI_INPROGRESS);
}

static void on_signal(int signo) { (void)signo; ++signal_count; }

static void waiting_contract(const char *scenario) {
    install_blocking_controller();
    struct gaicb request, done = {0};
    struct addrinfo h;
    blocked_requests(&request, &h, 1);
    CHECK(gai_cancel(&request) == EAI_NOTCANCELED);
    const struct gaicb *list[] = {&request, &done};
    const struct timespec timeout = {0, 50000000};
    errno = E2BIG;
    if (strcmp(scenario, "blocked-signal")) {
        double start = seconds();
        CHECK(gai_suspend(list, !strcmp(scenario, "mixed-pending") ? 2 : 1, &timeout) == EAI_AGAIN);
        double elapsed = seconds() - start;
        CHECK(elapsed >= 0.03 && elapsed < 1.5 && errno == E2BIG);
    } else {
        struct sigaction action = {0}; action.sa_handler = on_signal;
        sigemptyset(&action.sa_mask);
        CHECK(sigaction(SIGUSR1, &action, NULL) == 0);
        atomic_store_explicit(&interrupt_wait, 1, memory_order_release);
        int rc = gai_suspend(list, 1, NULL);
        atomic_store_explicit(&interrupt_wait, 0, memory_order_release);
        CHECK(rc == EAI_INTR && signal_count > 0);
    }
    CHECK(gai_error(&request) == EAI_INPROGRESS);
    finish_controller(&request, 1);
}

static void queued_contract(const char *scenario) {
    struct sigevent event = {0}; sigset_t mask;
    event.sigev_notify = SIGEV_SIGNAL; event.sigev_signo = SIGRTMIN + 4;
    event.sigev_value.sival_int = 173;
    sigemptyset(&mask); sigaddset(&mask, event.sigev_signo);
    CHECK(pthread_sigmask(SIG_BLOCK, &mask, NULL) == 0);
    install_blocking_controller();
    struct gaicb blockers[20]; struct addrinfo blocking_hint, numeric_hint = hint(AF_INET);
    blocked_requests(blockers, &blocking_hint, 20);
    struct gaicb next, other;
    init(&next, "127.0.0.9", &numeric_hint); init(&other, "127.0.0.10", &numeric_hint);
    struct gaicb *list[] = {&next, &other};
    CHECK(getaddrinfo_a(GAI_NOWAIT, list, 2, &event) == 0);
    CHECK(gai_error(&next) == EAI_INPROGRESS && gai_error(&other) == EAI_INPROGRESS);
    CHECK(gai_cancel(&next) == EAI_CANCELED);
    CHECK(gai_error(&next) == EAI_CANCELED && gai_error(&other) == EAI_INPROGRESS);
    if (!strcmp(scenario, "cancel-all")) CHECK(gai_cancel(NULL) == EAI_NOTCANCELED);
    else CHECK(gai_cancel(&other) == EAI_CANCELED);
    CHECK(gai_error(&other) == EAI_CANCELED && gai_cancel(&next) == EAI_ALLDONE);
    struct timespec timeout = {2, 0}, zero = {0, 0}; siginfo_t information;
    CHECK(sigtimedwait(&mask, &information, &timeout) == event.sigev_signo);
    CHECK(information.si_code == SI_ASYNCNL && information.si_value.sival_int == 173);
    CHECK(sigtimedwait(&mask, &information, &zero) == -1 && errno == EAGAIN);
    for (int i = 0; i < 20; ++i) CHECK(gai_error(&blockers[i]) == EAI_INPROGRESS);
    finish_controller(blockers, 20);
}

static void retirement_contract(const char *scenario) {
    install_blocking_controller();
    struct gaicb blockers[20]; struct addrinfo blocking_hint, numeric_hint = hint(AF_INET);
    blocked_requests(blockers, &blocking_hint, 20);
    size_t page_size = (size_t)sysconf(_SC_PAGESIZE);
    void *page = mmap(NULL, page_size, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    CHECK(page != MAP_FAILED);
    struct gaicb *request = page, *list[] = {request};
    int rounds = !strcmp(scenario, "cancel-reuse") ? 128 : 1;
    for (int i = 0; i < rounds; ++i) {
        init(request, "127.0.0.11", &numeric_hint);
        CHECK(getaddrinfo_a(GAI_NOWAIT, list, 1, NULL) == 0);
        CHECK(gai_cancel(request) == EAI_CANCELED && gai_error(request) == EAI_CANCELED);
    }
    CHECK(mprotect(page, page_size, PROT_NONE) == 0);
    finish_controller(blockers, 20);
    CHECK(munmap(page, page_size) == 0);
}

static atomic_int waiter_ready, waiter_go, waiter_cleanup;
static struct gaicb *waiter_request;
static void wait_cleanup(void *unused) { (void)unused; atomic_fetch_add(&waiter_cleanup, 1); }
static void *cancelable_wait(void *arg) {
    int mode = *(int *)arg;
    pthread_cleanup_push(wait_cleanup, NULL);
    atomic_store_explicit(&waiter_ready, 1, memory_order_release);
    while (!atomic_load_explicit(&waiter_go, memory_order_acquire)) sched_yield();
    if (mode == 2) {
        struct gaicb *list[] = {waiter_request}; (void)getaddrinfo_a(GAI_WAIT, list, 1, NULL);
    } else {
        const struct gaicb *list[] = {waiter_request}; (void)gai_suspend(list, 1, NULL);
    }
    pthread_cleanup_pop(0);
    return (void *)(uintptr_t)7;
}

static void cancellation_contract(const char *scenario) {
    install_blocking_controller();
    struct gaicb request; struct addrinfo h;
    int mode = !strcmp(scenario, "wait-cancel") ? 2 : 1;
    if (mode == 1) blocked_requests(&request, &h, 1);
    else {
        h = hint(AF_INET); h.ai_flags = AI_NUMERICSERV;
        init(&request, "blocked.gai-contract.invalid", &h);
    }
    waiter_request = &request;
    pthread_t waiter; CHECK(pthread_create(&waiter, NULL, cancelable_wait, &mode) == 0);
    while (!atomic_load_explicit(&waiter_ready, memory_order_acquire)) pause_ms(1);
    if (!strcmp(scenario, "suspend-pending-cancel")) {
        CHECK(pthread_cancel(waiter) == 0);
        atomic_store_explicit(&waiter_go, 1, memory_order_release);
    } else {
        atomic_store_explicit(&waiter_go, 1, memory_order_release);
        if (mode == 2) await_blocked(1); else pause_ms(20);
        CHECK(pthread_cancel(waiter) == 0);
    }
    struct timespec deadline; CHECK(clock_gettime(CLOCK_REALTIME, &deadline) == 0); deadline.tv_sec += 2;
    void *result = NULL; CHECK(pthread_timedjoin_np(waiter, &result, &deadline) == 0);
    CHECK(result == PTHREAD_CANCELED && atomic_load(&waiter_cleanup) == 1);
    CHECK(gai_error(&request) == EAI_INPROGRESS);
    numeric(GAI_WAIT, AF_INET);
    finish_controller(&request, 1);
}

static void dns_success(int family) {
    successful_reply = 1;
    install_blocking_controller();
    struct addrinfo h = hint(family); h.ai_flags = AI_NUMERICSERV;
    struct gaicb request; init(&request, "answer.gai-contract.invalid", &h);
    struct gaicb *list[] = {&request};
    CHECK(getaddrinfo_a(GAI_NOWAIT, list, 1, NULL) == 0);
    await_blocked(1); CHECK(gai_error(&request) == EAI_INPROGRESS);
    finish_controller(&request, 1);
}


/* Implementation ownership promise: unlike the caller-owned gaicb output,
 * all name, service, hint, and list input storage is snapshotted at admission.
 * Keep the output alive while making the input page inaccessible. */
static void input_snapshot(void) {
    install_blocking_controller();
    struct gaicb blockers[20]; struct addrinfo blocking_hint;
    blocked_requests(blockers, &blocking_hint, 20);
    size_t size = (size_t)sysconf(_SC_PAGESIZE);
    unsigned char *page = mmap(NULL, size, PROT_READ | PROT_WRITE,
                               MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    CHECK(page != MAP_FAILED && size > 512);
    struct addrinfo *h = (struct addrinfo *)page;
    *h = hint(AF_INET);
    char *name = (char *)page + 128, *service = (char *)page + 192;
    strcpy(name, "127.0.0.7"); strcpy(service, "43127");
    struct gaicb output = {.ar_name = name, .ar_service = service, .ar_request = h};
    struct gaicb **list = (struct gaicb **)(page + 256);
    list[0] = &output;
    CHECK(getaddrinfo_a(GAI_NOWAIT, list, 1, NULL) == 0);
    CHECK(gai_error(&output) == EAI_INPROGRESS);
    CHECK(mprotect(page, size, PROT_NONE) == 0);
    atomic_store_explicit(&released, 1, memory_order_release);
    wait_cb(&output);
    verify(&output, AF_INET, "127.0.0.7");
    freeaddrinfo(output.ar_result);
    finish_controller(blockers, 20);
    CHECK(munmap(page, size) == 0);
}

static int thread_count(void) {
    DIR *directory = opendir("/proc/self/task"); CHECK(directory);
    int count = 0;
    struct dirent *entry;
    while ((entry = readdir(directory))) if (entry->d_name[0] != '.') ++count;
    CHECK(closedir(directory) == 0);
    return count;
}

static void worker_lifetime(void) {
    int initial = thread_count();
    install_blocking_controller();
    struct gaicb blockers[20]; struct addrinfo blocking_hint, h = hint(AF_INET);
    blocked_requests(blockers, &blocking_hint, 20);
    CHECK(thread_count() == initial + 21); /* bounded I/O plus DNS controller */
    enum { BACKLOG = 128 };
    struct gaicb backlog[BACKLOG]; struct gaicb *list[BACKLOG];
    for (int i = 0; i < BACKLOG; ++i) {
        init(&backlog[i], "127.0.0.7", &h); list[i] = &backlog[i];
    }
    CHECK(getaddrinfo_a(GAI_NOWAIT, list, BACKLOG, NULL) == 0);
    CHECK(thread_count() == initial + 21); /* queued work never spawns more */
    for (int i = 0; i < BACKLOG; ++i) {
        CHECK(gai_error(&backlog[i]) == EAI_INPROGRESS);
        CHECK(gai_cancel(&backlog[i]) == EAI_CANCELED);
        CHECK(gai_error(&backlog[i]) == EAI_CANCELED);
    }
    finish_controller(blockers, 20);
    for (int i = 0; thread_count() != initial; ++i) { CHECK(i < 4000); pause_ms(1); }
    numeric(GAI_WAIT, AF_INET6); /* a fully retired pool starts again */
    for (int i = 0; thread_count() != initial; ++i) { CHECK(i < 4000); pause_ms(1); }
}

static atomic_int batch_canceled_notice;
static struct gaicb *canceled_batch;
static void canceled_callback(union sigval value) {
    CHECK(value.sival_int == 181);
    for (int i = 0; i < 2; ++i) CHECK(gai_error(&canceled_batch[i]) == EAI_CANCELED);
    free(canceled_batch);
    atomic_store_explicit(&batch_canceled_notice, 1, memory_order_release);
    pthread_exit(NULL);
}

static void canceled_callback_lifetime(void) {
    install_blocking_controller();
    struct gaicb blockers[20]; struct addrinfo blocking_hint, h = hint(AF_INET);
    blocked_requests(blockers, &blocking_hint, 20);
    canceled_batch = calloc(2, sizeof(*canceled_batch)); CHECK(canceled_batch);
    init(&canceled_batch[0], "127.0.0.7", &h);
    init(&canceled_batch[1], "127.0.0.8", &h);
    struct gaicb *list[] = {&canceled_batch[0], &canceled_batch[1]};
    struct sigevent event = {0};
    event.sigev_notify = SIGEV_THREAD; event.sigev_notify_function = canceled_callback;
    event.sigev_value.sival_int = 181;
    CHECK(getaddrinfo_a(GAI_NOWAIT, list, 2, &event) == 0);
    CHECK(gai_cancel(list[0]) == EAI_CANCELED);
    CHECK(gai_cancel(list[1]) == EAI_CANCELED);
    for (int i = 0; !atomic_load_explicit(&batch_canceled_notice, memory_order_acquire); ++i) {
        CHECK(i < 3000); pause_ms(1);
    }
    /* Callback completed before any of the 20 blocked resolver workers could
     * run again. Never inspect the freed requests after cancellation returns. */
    finish_controller(blockers, 20);
}

int main(int argc, char **argv) {
    CHECK(argc == 2); alarm(15);
    provider(getaddrinfo_a); provider(gai_suspend); provider(gai_error);
    provider(gai_cancel); provider(getaddrinfo); provider(freeaddrinfo);
    const char *scenario = argv[1];
    if (!strcmp(scenario, "blocked-timeout") || !strcmp(scenario, "mixed-pending") ||
        !strcmp(scenario, "blocked-signal")) waiting_contract(scenario);
    else if (!strcmp(scenario, "cancel-one") || !strcmp(scenario, "cancel-all")) queued_contract(scenario);
    else if (!strcmp(scenario, "cancel-retire") || !strcmp(scenario, "cancel-reuse")) retirement_contract(scenario);
    else if (!strcmp(scenario, "wait-cancel") || !strcmp(scenario, "suspend-cancel") ||
             !strcmp(scenario, "suspend-pending-cancel")) cancellation_contract(scenario);
    else if (!strcmp(scenario, "dns-v4")) dns_success(AF_INET);
    else if (!strcmp(scenario, "dns-v6")) dns_success(AF_INET6);
    else if (!strcmp(scenario, "input-snapshot")) input_snapshot();
    else if (!strcmp(scenario, "worker-lifetime")) worker_lifetime();
    else if (!strcmp(scenario, "cancel-callback")) canceled_callback_lifetime();
    else CHECK(0 && "unknown blocked scenario");
    printf("PASS %s\n", scenario); return 0;
}
