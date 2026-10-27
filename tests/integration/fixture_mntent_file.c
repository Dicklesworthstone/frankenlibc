/* Mount-table operations must share the public FILE lifecycle.  Run this
 * exact fixture against live GNU and the deployed candidate in both modes. */
#define _GNU_SOURCE
#include <dlfcn.h>
#include <errno.h>
#include <fcntl.h>
#include <mntent.h>
#include <pthread.h>
#include <signal.h>
#include <stdatomic.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <time.h>
#include <unistd.h>
#include <wchar.h>

#define CHECK(test) do { if (!(test)) { \
    fprintf(stderr, "mntent-file:%s:%d:%s:errno=%d\n", case_name, __LINE__, #test, errno); \
    exit(1); \
} } while (0)

static const char *case_name;
static const char first[] = "dev /one ext4 rw 1 2\n";
static const char second[] = "next /two tmpfs ro 3 4\n";

static void check_provider(const char *expected) {
    const char *symbols[] = {"setmntent", "endmntent", "getmntent", "getmntent_r",
                            "addmntent", "fopen", "fclose", "fmemopen", "fgets"};
    struct stat want, actual;
    CHECK(stat(expected, &want) == 0);
    for (size_t i = 0; i < sizeof(symbols) / sizeof(symbols[0]); ++i) {
        Dl_info info;
        void *p = dlsym(RTLD_DEFAULT, symbols[i]);
        CHECK(p != NULL && dladdr(p, &info) != 0);
        if (stat(info.dli_fname, &actual) != 0 || actual.st_dev != want.st_dev ||
            actual.st_ino != want.st_ino) {
            fprintf(stderr, "mntent-file:provider-mismatch:%s\n", symbols[i]);
            exit(86);
        }
    }
}

static void write_all(int fd, const void *p, size_t n) {
    const char *bytes = p;
    while (n) {
        ssize_t sent = syscall(SYS_write, fd, bytes, n);
        CHECK(sent > 0);
        bytes += sent;
        n -= (size_t) sent;
    }
}

static FILE *open_fixture(char *path, const char *mode, int mount_api) {
    strcpy(path, "/tmp/frankenlibc-mntent-file-XXXXXX");
    int fd = mkstemp(path);
    CHECK(fd >= 0);
    write_all(fd, first, sizeof(first) - 1);
    write_all(fd, second, sizeof(second) - 1);
    CHECK(close(fd) == 0);
    FILE *f = mount_api ? setmntent(path, mode) : fopen(path, mode);
    CHECK(f != NULL);
    CHECK(unlink(path) == 0);
    return f;
}

static void expect_entry(FILE *f, const char *name, const char *dir, int freq, int pass) {
    struct mntent result;
    char buf[256];
    CHECK(getmntent_r(f, &result, buf, sizeof(buf)) == &result);
    CHECK(strcmp(result.mnt_fsname, name) == 0);
    CHECK(strcmp(result.mnt_dir, dir) == 0);
    CHECK(result.mnt_freq == freq && result.mnt_passno == pass);
}

static void file_lifecycle(int mount_api) {
    char path[80];
    FILE *f = open_fixture(path, "r", mount_api);
    int fd = fileno(f);
    CHECK(fd >= 0);
    if (mount_api) CHECK((fcntl(fd, F_GETFD) & FD_CLOEXEC) != 0);
    CHECK(fwide(f, 0) == 0);
    CHECK(setvbuf(f, NULL, _IOFBF, 256) == 0);
    expect_entry(f, "dev", "/one", 1, 2);
    CHECK(fwide(f, 0) < 0 && ftell(f) == (long) sizeof(first) - 1);
    char line[256];
    CHECK(fgets(line, sizeof(line), f) == line && strcmp(line, second) == 0);
    CHECK(getmntent(f) == NULL && feof(f) && !ferror(f));
    rewind(f);
    CHECK(!feof(f));
    CHECK(fgetc(f) == 'd' && ungetc('d', f) == 'd');
    expect_entry(f, "dev", "/one", 1, 2);
    CHECK(endmntent(f) == 1);
    errno = 0;
    CHECK(fcntl(fd, F_GETFD) == -1 && errno == EBADF);
    CHECK(endmntent(NULL) == 1);
}

static void memory_input(int foreign) {
    char input[] = " \t# ignored\n\n/dev/a\\040b /mount\\134dir ext4 rw,tag=hello\\011x 12 4\n"
                   "single\nlast /z t rw -9 8";
    FILE *f;
    void *host = NULL;
    if (foreign) {
        host = dlopen("libc.so.6", RTLD_NOW | RTLD_LOCAL);
        CHECK(host != NULL);
        FILE *(*make)(void *, size_t, const char *) =
            (FILE *(*)(void *, size_t, const char *)) dlsym(host, "fmemopen");
        CHECK(make != NULL);
        f = make(input, sizeof(input) - 1, "r");
    } else {
        f = fmemopen(input, sizeof(input) - 1, "r");
    }
    CHECK(f != NULL);
    struct mntent result;
    char buf[256];
    CHECK(getmntent_r(f, &result, buf, sizeof(buf)) == &result);
    CHECK(strcmp(result.mnt_fsname, "/dev/a b") == 0);
    CHECK(strcmp(result.mnt_dir, "/mount\\dir") == 0);
    CHECK(strcmp(result.mnt_opts, "rw,tag=hello\tx") == 0);
    CHECK(result.mnt_freq == 12 && result.mnt_passno == 4);
    expect_entry(f, "single", "", 0, 0);
    expect_entry(f, "last", "/z", -9, 8);
    CHECK(getmntent(f) == NULL && feof(f));
    CHECK(endmntent(f) == 1);
    if (host) CHECK(dlclose(host) == 0);
}

static void truncated_input(void) {
    char input[] = "abcdefghijklmnop /lost type opts 9 7\nnext /ok t rw 2 3\n";
    FILE *f = fmemopen(input, sizeof(input) - 1, "r");
    CHECK(f != NULL);
    struct { unsigned char before; char buf[8]; unsigned char after; } guarded;
    memset(&guarded, 0xa5, sizeof(guarded));
    struct mntent entry = {0};
    CHECK(getmntent_r(f, &entry, guarded.buf, sizeof(guarded.buf)) == &entry);
    CHECK(guarded.before == 0xa5 && guarded.after == 0xa5);
    CHECK(strcmp(entry.mnt_fsname, "abcdefg") == 0);
    CHECK(!*entry.mnt_dir && !*entry.mnt_type && !*entry.mnt_opts);
    expect_entry(f, "next", "/ok", 2, 3);
    CHECK(endmntent(f) == 1);
    f = fmemopen(input, sizeof(input) - 1, "r");
    CHECK(f != NULL);
    char tiny[2];
    CHECK(getmntent_r(f, &entry, tiny, sizeof(tiny)) == &entry);
    CHECK(strcmp(entry.mnt_fsname, "a") == 0 && !*entry.mnt_dir && !*entry.mnt_opts);
    expect_entry(f, "next", "/ok", 2, 3);
    CHECK(endmntent(f) == 1);
}

static struct mntent addition(void) {
    struct mntent m = {"new device", "/new\tpath", "test", "rw,tag=\\value\n", 7, -2};
    return m;
}

static void append_file(int mount_api) {
    char path[80];
    FILE *f = open_fixture(path, "r+", mount_api);
    CHECK(fgetc(f) == 'd'); /* read-ahead must be reconciled before append. */
    struct mntent m = addition();
    CHECK(addmntent(f, &m) == 0);
    CHECK(fflush(f) == 0);
    rewind(f);
    expect_entry(f, "dev", "/one", 1, 2);
    expect_entry(f, "next", "/two", 3, 4);
    expect_entry(f, "new device", "/new\tpath", 7, -2);
    CHECK(getmntent(f) == NULL && !ferror(f));
    CHECK(endmntent(f) == 1);
}

static void append_memory(void) {
    char *text = NULL;
    size_t size = 0;
    FILE *f = open_memstream(&text, &size);
    CHECK(f != NULL);
    CHECK(fputs(first, f) >= 0);
    CHECK(fseek(f, 0, SEEK_SET) == 0);
    struct mntent m = addition();
    CHECK(addmntent(f, &m) == 0);
    CHECK(endmntent(f) == 1);
    const char expected[] = "dev /one ext4 rw 1 2\n"
        "new\\040device /new\\011path test rw,tag=\\134value\\012 7 -2\n";
    CHECK(size == sizeof(expected) - 1 && strcmp(text, expected) == 0);
    free(text);
}

struct cookie { const char *text; size_t length, pos; int calls, closed; };

static ssize_t cookie_read(void *opaque, char *buf, size_t n) {
    struct cookie *c = opaque;
    c->calls++;
    if (n > 3) n = 3; /* Split escape sequences and delimiters across reads. */
    if (n > c->length - c->pos) n = c->length - c->pos;
    memcpy(buf, c->text + c->pos, n);
    c->pos += n;
    return (ssize_t) n;
}

static int cookie_close(void *opaque) {
    struct cookie *c = opaque;
    c->closed++;
    return 0;
}

static void cookie_input(void) {
    const char text[] = "# comment\na\\040b /x t rw 1 2\nnext /y t ro 3 4\n";
    struct cookie c = {text, sizeof(text) - 1, 0, 0, 0};
    cookie_io_functions_t io = {.read = cookie_read, .close = cookie_close};
    FILE *f = fopencookie(&c, "r", io);
    CHECK(f != NULL);
    expect_entry(f, "a b", "/x", 1, 2);
    expect_entry(f, "next", "/y", 3, 4);
    CHECK(getmntent(f) == NULL && feof(f) && c.calls > 10);
    CHECK(endmntent(f) == 1 && c.closed == 1);
}

static void non_utf8_path(void) {
    char path[100];
    snprintf(path, sizeof(path), "/tmp/frankenlibc-mntent-%ld-\xff", (long) getpid());
    int fd = open(path, O_CREAT | O_EXCL | O_WRONLY, 0600);
    CHECK(fd >= 0);
    write_all(fd, first, sizeof(first) - 1);
    CHECK(close(fd) == 0);
    FILE *f = setmntent(path, "r");
    CHECK(f != NULL);
    CHECK(unlink(path) == 0);
    expect_entry(f, "dev", "/one", 1, 2);
    CHECK(endmntent(f) == 1);
}

static void error_paths(void) {
    errno = 0;
    CHECK(setmntent("/frankenlibc-no-such-directory/mtab", "r") == NULL && errno == ENOENT);
    errno = 0;
    CHECK(setmntent("/dev/null", "invalid") == NULL && errno == EINVAL);
    FILE *f = setmntent("/", "r");
    CHECK(f != NULL);
    struct mntent m;
    char buf[128];
    errno = 0;
    CHECK(getmntent_r(f, &m, buf, sizeof(buf)) == NULL && errno == EISDIR);
    CHECK(ferror(f) && !feof(f));
    clearerr(f);
    CHECK(!ferror(f));
    CHECK(endmntent(f) == 1);
    char path[80];
    f = open_fixture(path, "r", 1);
    m = addition();
    errno = 0;
    CHECK(addmntent(f, &m) == 1 && errno == EBADF && ferror(f));
    CHECK(endmntent(f) == 1);
    f = setmntent("/dev/null", "r");
    CHECK(f != NULL);
    int fd = fileno(f);
    CHECK(close(fd) == 0);
    errno = 0;
    CHECK(endmntent(f) == 1 && errno == EBADF);
}

static void append_pipe(void) {
    int p[2];
    CHECK(pipe(p) == 0);
    CHECK(fcntl(p[0], F_SETFL, O_NONBLOCK) == 0);
    FILE *f = fdopen(p[1], "w");
    CHECK(f != NULL);
    struct mntent m = addition();
    errno = 0;
    CHECK(addmntent(f, &m) == 1 && errno == ESPIPE);
    char b;
    errno = 0;
    CHECK(read(p[0], &b, 1) == -1 && errno == EAGAIN);
    CHECK(endmntent(f) == 1 && close(p[0]) == 0);
}

static atomic_int seen[200], total;
static void *parallel_reader(void *opaque) {
    FILE *f = opaque;
    struct mntent m;
    char buf[128];
    for (;;) {
        /* GNU mount readers use unlocked stdio internally.  A caller sharing
         * one FILE must serialize the complete record operation explicitly. */
        flockfile(f);
        struct mntent *entry = getmntent_r(f, &m, buf, sizeof(buf));
        funlockfile(f);
        if (!entry) break;
        CHECK(!strcmp(m.mnt_type, "tmpfs") && !strcmp(m.mnt_opts, "rw"));
        CHECK(m.mnt_freq >= 0 && m.mnt_freq < 200);
        CHECK(atomic_fetch_add(&seen[m.mnt_freq], 1) == 0);
        atomic_fetch_add(&total, 1);
    }
    CHECK(!ferror(f));
    return NULL;
}

static void concurrent_readers(void) {
    FILE *f = tmpfile();
    CHECK(f != NULL);
    for (int i = 0; i < 200; ++i) CHECK(fprintf(f, "device%d /%d tmpfs rw %d 0\n", i, i, i) > 0);
    rewind(f);
    pthread_t threads[4];
    for (int i = 0; i < 4; ++i) CHECK(pthread_create(&threads[i], NULL, parallel_reader, f) == 0);
    for (int i = 0; i < 4; ++i) CHECK(pthread_join(threads[i], NULL) == 0);
    CHECK(atomic_load(&total) == 200);
    CHECK(endmntent(f) == 1);
}

struct cancel_state { FILE *f; int output, mount_reader; atomic_int started, returned, cleaned; };
static void cleaned(void *opaque) {
    struct cancel_state *s = opaque;
    atomic_fetch_add(&s->cleaned, 1);
}
static void *cancel_worker(void *opaque) {
    struct cancel_state *s = opaque;
    pthread_cleanup_push(cleaned, s);
    atomic_store(&s->started, 1);
    if (s->output) {
        CHECK(fputc('x', s->f) == 'x');
    } else if (s->mount_reader) {
        struct mntent m;
        char buf[128];
        CHECK(getmntent_r(s->f, &m, buf, sizeof(buf)) == &m);
        CHECK(!strcmp(m.mnt_fsname, "dev"));
    } else {
        char buf[128];
        CHECK(fgets(buf, sizeof(buf), s->f) == buf && !strcmp(buf, first));
    }
    atomic_store(&s->returned, 1);
    pthread_testcancel();
    pthread_cleanup_pop(0);
    return NULL;
}

static void cancellation(int suppress, int mount_op, int output, int fdopen_c) {
    int p[2];
    CHECK(pipe(p) == 0);
    if (output) {
        CHECK(fcntl(p[1], F_SETFL, O_NONBLOCK) == 0);
        char bytes[4096];
        memset(bytes, 'a', sizeof(bytes));
        while (write(p[1], bytes, sizeof(bytes)) > 0) {}
        CHECK(errno == EAGAIN);
        CHECK(fcntl(p[1], F_SETFL, 0) == 0);
    }
    FILE *f;
    if (suppress) {
        char path[80];
        snprintf(path, sizeof(path), "/proc/self/fd/%d", p[output ? 1 : 0]);
        f = mount_op ? setmntent(path, "r") : fopen(path, output ? "wc" : "rc");
        CHECK(f != NULL);
    } else {
        f = fdopen(p[0], fdopen_c ? "rc" : "r");
        CHECK(f != NULL);
    }
    if (output) CHECK(setvbuf(f, NULL, _IONBF, 0) == 0);
    struct cancel_state state = {.f = f, .output = output, .mount_reader = mount_op};
    pthread_t t;
    CHECK(pthread_create(&t, NULL, cancel_worker, &state) == 0);
    while (!atomic_load(&state.started)) sched_yield();
    usleep(30000);
    CHECK(pthread_cancel(t) == 0);
    if (suppress) {
        usleep(30000);
        CHECK(!atomic_load(&state.returned) && !atomic_load(&state.cleaned));
        if (output) {
            char bytes[4096];
            CHECK(syscall(SYS_read, p[0], bytes, sizeof(bytes)) == (ssize_t) sizeof(bytes));
        } else {
            write_all(p[1], first, sizeof(first) - 1);
        }
    }
    struct timespec deadline;
    CHECK(clock_gettime(CLOCK_REALTIME, &deadline) == 0);
    deadline.tv_sec += 3;
    void *result = NULL;
    CHECK(pthread_timedjoin_np(t, &result, &deadline) == 0);
    CHECK(result == PTHREAD_CANCELED && atomic_load(&state.cleaned) == 1);
    CHECK(atomic_load(&state.returned) == suppress);
    CHECK(ftrylockfile(f) == 0);
    funlockfile(f);
    CHECK(fclose(f) == 0);
    if (suppress) CHECK(close(p[output ? 1 : 0]) == 0);
    CHECK(close(p[output ? 0 : 1]) == 0);
}

int main(int argc, char **argv) {
    if (argc == 2 && !strcmp(argv[1], "--provider")) {
        Dl_info info;
        if (!dladdr(dlsym(RTLD_DEFAULT, "setmntent"), &info)) return 1;
        puts(info.dli_fname);
        return 0;
    }
    if (argc != 3) return 2;
    case_name = argv[1];
    alarm(8);
    check_provider(argv[2]);
    if (!strcmp(case_name, "setmntent-file")) file_lifecycle(1);
    else if (!strcmp(case_name, "fopen-input")) file_lifecycle(0);
    else if (!strcmp(case_name, "memory-input")) memory_input(0);
    else if (!strcmp(case_name, "host-file")) memory_input(1);
    else if (!strcmp(case_name, "truncated-input")) truncated_input();
    else if (!strcmp(case_name, "append-update")) append_file(1);
    else if (!strcmp(case_name, "append-fopen")) append_file(0);
    else if (!strcmp(case_name, "append-memory")) append_memory();
    else if (!strcmp(case_name, "cookie-input")) cookie_input();
    else if (!strcmp(case_name, "non-utf8-path")) non_utf8_path();
    else if (!strcmp(case_name, "error-paths")) error_paths();
    else if (!strcmp(case_name, "append-pipe")) append_pipe();
    else if (!strcmp(case_name, "concurrent-readers")) concurrent_readers();
    else if (!strcmp(case_name, "cancel-ordinary")) cancellation(0, 1, 0, 0);
    else if (!strcmp(case_name, "cancel-setmntent")) cancellation(1, 1, 0, 0);
    else if (!strcmp(case_name, "fopen-c-read")) cancellation(1, 0, 0, 0);
    else if (!strcmp(case_name, "fopen-c-write")) cancellation(1, 0, 1, 0);
    else if (!strcmp(case_name, "fdopen-c-ignored")) cancellation(0, 0, 0, 1);
    else return 2;
    printf("mntent-file:%s:PASS\n", case_name);
    return 0;
}
