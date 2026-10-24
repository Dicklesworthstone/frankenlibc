#define _GNU_SOURCE
#include <aio.h>
#include <dirent.h>
#include <dlfcn.h>
#include <errno.h>
#include <fcntl.h>
#include <pthread.h>
#include <signal.h>
#include <stdatomic.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <time.h>
#include <unistd.h>

static atomic_int notified;
static struct aiocb *callback_cb;
static struct aiocb *batch_members;
static int callback_fd;
static int callback_kind;
static char callback_buffer;

static void check(int ok, const char *message) {
    if (!ok) { fprintf(stderr, "FAIL: %s (errno=%d)\n", message, errno); _Exit(1); }
}

static void pause_ms(long ms) {
    struct timespec delay = {ms / 1000, (ms % 1000) * 1000000};
    while (nanosleep(&delay, &delay) && errno == EINTR) {}
}

static void init(struct aiocb *cb, int fd, void *buffer, size_t length) {
    memset(cb, 0, sizeof(*cb));
    cb->aio_fildes = fd;
    cb->aio_buf = buffer;
    cb->aio_nbytes = length;
    cb->aio_sigevent.sigev_notify = SIGEV_NONE;
}

static void wait_done(struct aiocb *cb) {
    const struct aiocb *list[] = {cb};
    const struct timespec timeout = {2, 0};
    while (aio_error(cb) == EINPROGRESS)
        check(aio_suspend(list, 1, &timeout) == 0 || errno == EINTR, "bounded AIO completion");
}

static void await_notice(void) {
    for (int i = 0; i != 2000 && !atomic_load_explicit(&notified, memory_order_acquire); ++i)
        pause_ms(1);
    check(atomic_load_explicit(&notified, memory_order_acquire) == 1, "exactly one notification");
}

/* Observe the actual blocking syscall, rather than assume a sleep made the
 * first worker run. This makes queued/running cancellation checks deterministic
 * without hooks in the implementation. Linux /proc is part of this fixture. */
static void await_syscall(int fd, long syscall_number) {
    for (int attempt = 0; attempt != 2000; ++attempt) {
        DIR *tasks = opendir("/proc/self/task");
        check(tasks != NULL, "open thread syscall inventory");
        struct dirent *entry;
        int found = 0;
        while ((entry = readdir(tasks)) != NULL) {
            if (entry->d_name[0] == '.') continue;
            char path[384], line[512];
            snprintf(path, sizeof(path), "/proc/self/task/%s/syscall", entry->d_name);
            FILE *stream = fopen(path, "r");
            if (!stream) continue;
            if (fgets(line, sizeof(line), stream)) {
                long number = -1;
                unsigned long argument = 0;
                if (sscanf(line, "%ld %lx", &number, &argument) == 2 &&
                    number == syscall_number && argument == (unsigned long)fd) found = 1;
            }
            fclose(stream);
        }
        closedir(tasks);
        if (found) return;
        pause_ms(1);
    }
    check(0, "first request must enter its blocking kernel syscall");
}

static void provider(void *symbol) {
    const char *path = getenv("FRANKENLIBC_TEST_LIBRARY");
    if (!path) return;
    Dl_info info;
    struct stat actual, expected;
    check(dladdr(symbol, &info) && stat(info.dli_fname, &actual) == 0 && stat(path, &expected) == 0,
          "locate AIO provider");
    check(actual.st_dev == expected.st_dev && actual.st_ino == expected.st_ino,
          "AIO symbol must bind to candidate library");
}

static void callback(union sigval value) {
    check(value.sival_int == 91, "callback value");
    if (callback_kind == 1) {
        check(aio_error(callback_cb) == ECANCELED && aio_return(callback_cb) == -1,
              "canceled callback observes final result");
        free((void *)callback_cb->aio_buf);
        free(callback_cb);
    } else if (callback_kind == 2) {
        for (int i = 0; i != 2; ++i)
            check(aio_error(&batch_members[i]) == ECANCELED && aio_return(&batch_members[i]) == -1,
                  "canceled list member status");
        free(batch_members);
    } else if (callback_kind == 3) {
        /* Completion must release the fd queue before entering user code. */
        struct aiocb next;
        init(&next, callback_fd, &callback_buffer, 1);
        check(aio_read(&next) == 0, "callback resubmits on its own descriptor");
        wait_done(&next);
        check(aio_error(&next) == 0 && aio_return(&next) == 1 && callback_buffer == 'y',
              "callback can wait for same-descriptor progress");
    }
    atomic_fetch_add_explicit(&notified, 1, memory_order_release);
}

static void thread_notice(struct sigevent *event) {
    memset(event, 0, sizeof(*event));
    event->sigev_notify = SIGEV_THREAD;
    event->sigev_notify_function = callback;
    event->sigev_value.sival_int = 91;
}

static void unblock_read(int *pipes, struct aiocb *cb) {
    check(write(pipes[1], "x", 1) == 1, "release active read");
    wait_done(cb);
    check(aio_error(cb) == 0 && aio_return(cb) == 1, "active read completes normally");
    check(aio_cancel(pipes[0], NULL) == AIO_ALLDONE, "descriptor drained");
    close(pipes[0]); close(pipes[1]);
}

static void cancellation(const char *kind) {
    int pipes[2];
    check(pipe(pipes) == 0, "pipe");
    char first_byte = 0, second_byte = 0, third_byte = 0;
    struct aiocb first, second, third;
    init(&first, pipes[0], &first_byte, 1);
    check(aio_read(&first) == 0, "submit active read");
    await_syscall(pipes[0], SYS_read);
    check(aio_cancel(pipes[0], &first) == AIO_NOTCANCELED, "running syscall is not canceled");
    check(aio_error(&first) == EINPROGRESS, "running status unchanged");
    init(&second, pipes[0], &second_byte, 1);
    init(&third, pipes[0], &third_byte, 1);

    if (!strcmp(kind, "cancel-thread")) {
        callback_cb = calloc(1, sizeof(*callback_cb));
        check(callback_cb != NULL, "callback aiocb");
        void *buffer = malloc(1); check(buffer != NULL, "callback buffer");
        init(callback_cb, pipes[0], buffer, 1);
        callback_kind = 1;
        thread_notice(&callback_cb->aio_sigevent);
        check(aio_read(callback_cb) == 0, "submit callback read");
        /* The callback may free the aiocb before this call even returns. */
        check(aio_cancel(pipes[0], callback_cb) == AIO_CANCELED, "cancel callback read");
        await_notice();
    } else if (!strcmp(kind, "cancel-batch")) {
        batch_members = calloc(2, sizeof(*batch_members));
        check(batch_members != NULL, "batch aiocbs");
        init(&batch_members[0], pipes[0], &second_byte, 1);
        init(&batch_members[1], pipes[0], &third_byte, 1);
        batch_members[0].aio_lio_opcode = batch_members[1].aio_lio_opcode = LIO_READ;
        struct aiocb *list[] = {&batch_members[0], &batch_members[1]};
        struct sigevent event;
        callback_kind = 2;
        thread_notice(&event);
        check(lio_listio(LIO_NOWAIT, list, 2, &event) == 0, "submit batch");
        check(aio_cancel(pipes[0], NULL) == AIO_NOTCANCELED, "cancel queued batch, preserve active read");
        await_notice(); // must NOT wait for unrelated active first request
    } else if (!strcmp(kind, "cancel-reuse")) {
        int ready_pipe[2]; check(pipe(ready_pipe) == 0, "reuse pipe");
        for (int i = 0; i != 32; ++i) {
            init(&second, pipes[0], &second_byte, 1);
            check(aio_read(&second) == 0, "submit request to cancel and reuse");
            check(aio_cancel(pipes[0], &second) == AIO_CANCELED, "cancel before reuse");
            check(aio_return(&second) == -1, "reap before reuse");
            init(&second, ready_pipe[0], &second_byte, 1);
            check(write(ready_pipe[1], "r", 1) == 1 && aio_read(&second) == 0, "reuse exact aiocb address");
            wait_done(&second);
            check(aio_error(&second) == 0 && aio_return(&second) == 1 && second_byte == 'r',
                  "old cancellation worker cannot overwrite new submission");
        }
        close(ready_pipe[0]); close(ready_pipe[1]);
    } else if (!strcmp(kind, "cancel-signal")) {
        const int signo = SIGRTMIN + 3;
        sigset_t mask; sigemptyset(&mask); sigaddset(&mask, signo);
        check(pthread_sigmask(SIG_BLOCK, &mask, NULL) == 0, "block completion signal");
        second.aio_sigevent.sigev_notify = SIGEV_SIGNAL;
        second.aio_sigevent.sigev_signo = signo;
        second.aio_sigevent.sigev_value.sival_int = 72;
        check(aio_read(&second) == 0 && aio_cancel(pipes[0], &second) == AIO_CANCELED, "cancel signal request");
        siginfo_t info; const struct timespec timeout = {2, 0}, zero = {0, 0};
        check(sigtimedwait(&mask, &info, &timeout) == signo, "cancellation sends normal notification");
        check(info.si_code == SI_ASYNCIO && info.si_value.sival_int == 72, "cancellation signal payload");
        check(aio_error(&second) == ECANCELED && aio_return(&second) == -1, "signal after result publication");
        check(sigtimedwait(&mask, &info, &zero) == -1 && errno == EAGAIN, "no duplicate completion signal");
    } else {
        check(aio_read(&second) == 0 && aio_read(&third) == 0, "submit queued reads");
        if (!strcmp(kind, "cancel-all")) {
            check(aio_cancel(pipes[0], NULL) == AIO_NOTCANCELED, "mixed running/queued cancel-all result");
            check(aio_error(&third) == ECANCELED && aio_return(&third) == -1, "cancel-all reaches every queued request");
        } else {
            check(aio_cancel(pipes[0], &second) == AIO_CANCELED, "cancel one queued request");
            check(aio_error(&third) == EINPROGRESS, "other queued request survives cancel-one");
            check(aio_cancel(pipes[0], &third) == AIO_CANCELED, "cancel remaining queued request");
        }
        check(aio_error(&second) == ECANCELED && aio_return(&second) == -1, "synchronous canceled result");
        check(aio_cancel(pipes[0], &second) == AIO_ALLDONE, "repeat cancellation sees completed request");
    }
    unblock_read(pipes, &first);
}

static void barrier(const char *kind) {
    int pipes[2]; check(pipe2(pipes, O_NONBLOCK) == 0, "nonblocking pipe");
    char fill[4096]; memset(fill, 'f', sizeof(fill));
    size_t capacity = 0;
    ssize_t written;
    while ((written = write(pipes[1], fill, sizeof(fill))) > 0) capacity += (size_t)written;
    check(errno == EAGAIN && capacity >= sizeof(fill), "fill pipe");
    check(fcntl(pipes[1], F_SETFL, 0) == 0, "make writer blocking");
    struct aiocb write_cb, sync_cb, independent;
    char byte = 'z';
    init(&write_cb, pipes[1], &byte, 1);
    check(aio_write(&write_cb) == 0, "submit blocked write");
    await_syscall(pipes[1], SYS_write);
    init(&sync_cb, pipes[1], NULL, 0);
    check(aio_fsync(O_SYNC, &sync_cb) == 0, "submit fsync behind blocked write");
    pause_ms(20);
    check(aio_error(&sync_cb) == EINPROGRESS, "fsync cannot overtake earlier pending write");
    if (!strcmp(kind, "cancel-fsync")) {
        check(aio_cancel(pipes[1], &sync_cb) == AIO_CANCELED, "queued fsync is cancelable");
        check(aio_error(&sync_cb) == ECANCELED && aio_return(&sync_cb) == -1, "canceled fsync status");
    }
    int other[2]; check(pipe(other) == 0, "independent pipe");
    init(&independent, other[1], &byte, 1);
    check(aio_write(&independent) == 0, "submit independent write"); wait_done(&independent);
    check(aio_error(&independent) == 0 && aio_return(&independent) == 1,
          "blocked descriptor cannot stall unrelated descriptors");
    close(other[0]); close(other[1]);
    check(read(pipes[0], fill, sizeof(fill)) == sizeof(fill), "make room for blocked write");
    wait_done(&write_cb);
    check(aio_error(&write_cb) == 0 && aio_return(&write_cb) == 1, "earlier write completes");
    wait_done(&sync_cb);
    check(aio_error(&sync_cb) == (!strcmp(kind, "cancel-fsync") ? ECANCELED : EINVAL),
          "fsync completes or remains canceled after predecessor");
    if (strcmp(kind, "cancel-fsync")) check(aio_return(&sync_cb) == -1, "pipe fsync fails normally");
    close(pipes[0]); close(pipes[1]);
}

static void file_sync(int operation) {
    char path[] = "/tmp/frankenlibc-aio-queue-XXXXXX";
    int fd = mkstemp(path); check(fd >= 0, "temporary file"); unlink(path);
    enum {COUNT = 24, SIZE = 1024};
    char buffers[COUNT][SIZE];
    struct aiocb writes[COUNT], sync_cb;
    for (int i = 0; i != COUNT; ++i) {
        memset(buffers[i], 'a' + i, SIZE);
        init(&writes[i], fd, buffers[i], SIZE);
        writes[i].aio_offset = (off_t)i * SIZE;
        check(aio_write(&writes[i]) == 0, "submit file write");
    }
    init(&sync_cb, fd, NULL, 0);
    check(aio_fsync(operation, &sync_cb) == 0, "submit file durability barrier");
    wait_done(&sync_cb);
    check(aio_error(&sync_cb) == 0 && aio_return(&sync_cb) == 0, "successful file fsync");
    for (int i = 0; i != COUNT; ++i) {
        check(aio_error(&writes[i]) == 0 && aio_return(&writes[i]) == SIZE, "all earlier writes complete at fsync completion");
        char actual[SIZE];
        check(pread(fd, actual, SIZE, (off_t)i * SIZE) == SIZE && !memcmp(actual, buffers[i], SIZE), "durable file contents");
    }
    check(aio_cancel(fd, NULL) == AIO_ALLDONE, "empty file queue"); close(fd);
}

static void callback_progress(void) {
    int pipes[2]; check(pipe(pipes) == 0, "callback pipe");
    char byte; struct aiocb cb;
    init(&cb, pipes[0], &byte, 1);
    callback_kind = 3; callback_fd = pipes[0];
    thread_notice(&cb.aio_sigevent);
    check(write(pipes[1], "xy", 2) == 2 && aio_read(&cb) == 0, "submit callback first read");
    await_notice(); wait_done(&cb);
    check(aio_error(&cb) == 0 && aio_return(&cb) == 1 && byte == 'x', "callback initial request");
    close(pipes[0]); close(pipes[1]);
}

static void fifo(void) {
    int pipes[2]; check(pipe(pipes) == 0, "ordered pipe");
    struct aiocb requests[16]; char bytes[16] = {0};
    for (int i = 0; i != 16; ++i) {
        init(&requests[i], pipes[0], &bytes[i], 1);
        check(aio_read(&requests[i]) == 0, "enqueue ordered read");
        if (!i) await_syscall(pipes[0], SYS_read);
    }
    check(write(pipes[1], "abcdefghijklmnop", 16) == 16, "release ordered reads");
    for (int i = 0; i != 16; ++i) {
        wait_done(&requests[i]);
        check(aio_error(&requests[i]) == 0 && aio_return(&requests[i]) == 1 && bytes[i] == 'a' + i,
              "same-descriptor FIFO submission order");
    }
    close(pipes[0]); close(pipes[1]);
}

int main(int argc, char **argv) {
    check(argc == 2, "one case required"); alarm(10);
    provider((void *)aio_read); provider((void *)aio_write); provider((void *)aio_cancel);
    provider((void *)aio_error); provider((void *)aio_return); provider((void *)aio_fsync);
    provider((void *)aio_suspend); provider((void *)lio_listio);
    const char *kind = argv[1];
    if (!strcmp(kind, "empty")) {
        errno = 0;
        check(aio_cancel(-1, NULL) == -1 && errno == EBADF, "cancel invalid descriptor");
        int fd = open("/dev/null", O_RDWR); check(fd >= 0, "open empty descriptor");
        check(aio_cancel(fd, NULL) == AIO_ALLDONE, "cancel valid empty descriptor"); close(fd);
    } else if (!strcmp(kind, "fsync-barrier") || !strcmp(kind, "cancel-fsync")) barrier(kind);
    else if (!strcmp(kind, "file-fsync")) file_sync(O_SYNC);
    else if (!strcmp(kind, "file-fdatasync")) file_sync(O_DSYNC);
    else if (!strcmp(kind, "callback-progress")) callback_progress();
    else if (!strcmp(kind, "fifo")) fifo();
    else if (!strcmp(kind, "cancel-one") || !strcmp(kind, "cancel-all") || !strcmp(kind, "cancel-thread") ||
             !strcmp(kind, "cancel-batch") || !strcmp(kind, "cancel-reuse") || !strcmp(kind, "cancel-signal")) cancellation(kind);
    else check(0, "known case");
    alarm(0); printf("PASS %s\n", kind); return 0;
}
