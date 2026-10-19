/* Reuse the provider checks, bounded waits, and syscall observation helpers.
 * Each executable invocation still owns a fresh process and all request storage. */
#define main queue_contract_main
#include "fixture_aio_queue.c"
#undef main

static atomic_int go;
static int race_fd;
static int race_writer;
static struct aiocb *race_cb;
static int decisions[8];

static void *cancel_racer(void *arg) {
    size_t index = (size_t)(uintptr_t)arg;
    while (!atomic_load_explicit(&go, memory_order_acquire)) sched_yield();
    decisions[index] = aio_cancel(race_fd, race_cb);
    return NULL;
}

static void *write_racer(void *unused) {
    (void)unused;
    while (!atomic_load_explicit(&go, memory_order_acquire)) sched_yield();
    check(write(race_writer, "xy", 2) == 2, "race releases active and queued reads");
    return NULL;
}

static void race_case(int complete) {
    for (int iteration = 0; iteration != 32; ++iteration) {
        int pipes[2]; check(pipe(pipes) == 0, "race pipe");
        char bytes[2] = {0}; struct aiocb first, second;
        init(&first, pipes[0], &bytes[0], 1);
        init(&second, pipes[0], &bytes[1], 1);
        atomic_store(&notified, 0); atomic_store(&go, 0);
        callback_kind = 0; thread_notice(&second.aio_sigevent);
        check(aio_read(&first) == 0, "submit active race read");
        await_syscall(pipes[0], SYS_read);
        check(aio_read(&second) == 0, "submit queued race read");
        race_fd = pipes[0]; race_writer = pipes[1]; race_cb = &second;
        pthread_t threads[8];
        int count = complete ? 2 : 8;
        for (int i = 0; i != count; ++i)
            check(pthread_create(&threads[i], NULL, complete && i == 1 ? write_racer : cancel_racer,
                                 (void *)(uintptr_t)i) == 0, "create race participant");
        atomic_store_explicit(&go, 1, memory_order_release);
        for (int i = 0; i != count; ++i) check(pthread_join(threads[i], NULL) == 0, "join race participant");
        await_notice();
        if (complete) {
            check(decisions[0] == AIO_CANCELED || decisions[0] == AIO_NOTCANCELED || decisions[0] == AIO_ALLDONE,
                  "completion race returns a valid state");
            wait_done(&first); wait_done(&second);
            check(aio_error(&first) == 0 && aio_return(&first) == 1 && bytes[0] == 'x', "first race read");
            int error = aio_error(&second);
            if (decisions[0] == AIO_CANCELED) check(error == ECANCELED, "cancel winner owns final status");
            else check(error == 0, "started/completed request is not falsely canceled");
            check(fcntl(pipes[0], F_SETFL, O_NONBLOCK) == 0, "inspect remaining race bytes");
            char remainder = 0;
            if (error == ECANCELED) {
                check(aio_return(&second) == -1 && read(pipes[0], &remainder, 1) == 1 && remainder == 'y',
                      "canceled operation consumes no input");
            } else {
                check(aio_return(&second) == 1 && bytes[1] == 'y', "completion winner consumes exactly one byte");
                check(read(pipes[0], &remainder, 1) == -1 && errno == EAGAIN, "no extra input remains");
            }
            close(pipes[0]); close(pipes[1]);
        } else {
            int winners = 0;
            for (int i = 0; i != count; ++i) {
                check(decisions[i] == AIO_CANCELED || decisions[i] == AIO_ALLDONE, "queued cancellation race result");
                winners += decisions[i] == AIO_CANCELED;
            }
            check(winners == 1 && aio_error(&second) == ECANCELED && aio_return(&second) == -1,
                  "one cancellation owner and one completion notification");
            unblock_read(pipes, &first);
        }
    }
}

static void retire_case(void) {
    for (int iteration = 0; iteration != 32; ++iteration) {
        int pipes[2]; check(pipe(pipes) == 0, "retire pipe");
        char first_byte = 0; struct aiocb first;
        init(&first, pipes[0], &first_byte, 1);
        check(aio_read(&first) == 0, "submit retirement predecessor");
        await_syscall(pipes[0], SYS_read);
        size_t page = (size_t)sysconf(_SC_PAGESIZE);
        unsigned char *memory = mmap(NULL, page * 2, PROT_READ | PROT_WRITE,
                                     MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
        check(memory != MAP_FAILED && sizeof(struct aiocb) <= page, "allocate request pages");
        struct aiocb *cb = (struct aiocb *)memory;
        init(cb, pipes[0], memory + page, 1);
        atomic_store(&notified, 0); callback_kind = 0;
        thread_notice(&cb->aio_sigevent);
        check(aio_read(cb) == 0 && aio_cancel(pipes[0], cb) == AIO_CANCELED, "cancel before page retirement");
        check(aio_error(cb) == ECANCELED && aio_return(cb) == -1, "retirement final result");
        check(mprotect(memory, page * 2, PROT_NONE) == 0, "protect entire aiocb and buffer immediately");
        await_notice();
        unblock_read(pipes, &first);
        check(munmap(memory, page * 2) == 0, "release retired pages");
    }
}

int main(int argc, char **argv) {
    check(argc == 2, "one race case required"); alarm(10);
    provider((void *)aio_read); provider((void *)aio_cancel);
    provider((void *)aio_error); provider((void *)aio_return);
    provider((void *)aio_suspend);
    if (!strcmp(argv[1], "cancel-contended")) race_case(0);
    else if (!strcmp(argv[1], "cancel-complete-race")) race_case(1);
    else if (!strcmp(argv[1], "cancel-retire")) retire_case();
    else check(0, "known race case");
    alarm(0); printf("PASS %s\n", argv[1]); return 0;
}
