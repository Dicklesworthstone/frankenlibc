/* fixture_nss.c — NSS/resolver lookup smoke fixture (bd-x2sq)
 * Exit 0 = PASS, nonzero = FAIL with diagnostics.
 */
#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
#include <dirent.h>
#include <dlfcn.h>
#include <errno.h>
#include <fcntl.h>
#include <grp.h>
#include <netdb.h>
#include <pthread.h>
#include <pwd.h>
#include <signal.h>
#include <stdatomic.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

typedef int (*identity_name_fn)(const char *, void *, char *, size_t, int *);
typedef int (*identity_id_fn)(unsigned int, void *, char *, size_t, int *);
typedef int (*identity_next_fn)(void *, char *, size_t, int *);
typedef int (*identity_start_fn)(int);
typedef int (*identity_end_fn)(void);

struct identity_ops {
    identity_name_fn name;
    identity_id_fn id;
    identity_next_fn next;
    identity_start_fn start;
    identity_end_fn end;
};

struct identity_result {
    union { struct passwd pw; struct group gr; } record;
    char buffer[65537];
    int status, err, saved_errno;
};

static void *identity_symbol(void *handle, const char *name,
                             const struct stat *expected) {
    void *symbol = dlsym(handle, name);
    Dl_info info;
    struct stat actual;
    if (!symbol || !dladdr(symbol, &info) || !info.dli_fname ||
        stat(info.dli_fname, &actual) || actual.st_dev != expected->st_dev ||
        actual.st_ino != expected->st_ino) {
        fprintf(stderr, "FAIL: identity provider mismatch for %s\n", name);
        return NULL;
    }
    return symbol;
}

static int identity_bind(void *handle, const struct stat *expected, int group,
                         struct identity_ops *ops) {
    ops->name = (identity_name_fn)identity_symbol(handle,
        group ? "_nss_files_getgrnam_r" : "_nss_files_getpwnam_r", expected);
    ops->id = (identity_id_fn)identity_symbol(handle,
        group ? "_nss_files_getgrgid_r" : "_nss_files_getpwuid_r", expected);
    ops->next = (identity_next_fn)identity_symbol(handle,
        group ? "_nss_files_getgrent_r" : "_nss_files_getpwent_r", expected);
    ops->start = (identity_start_fn)identity_symbol(handle,
        group ? "_nss_files_setgrent" : "_nss_files_setpwent", expected);
    ops->end = (identity_end_fn)identity_symbol(handle,
        group ? "_nss_files_endgrent" : "_nss_files_endpwent", expected);
    return ops->name && ops->id && ops->next && ops->start && ops->end;
}

static int identity_string_equal(const char *a, const char *b) {
    return (!a || !b) ? a == b : strcmp(a, b) == 0;
}

static int identity_records_equal(int group, const struct identity_result *a,
                                   const struct identity_result *b) {
    if (!group) {
        const struct passwd *x = &a->record.pw, *y = &b->record.pw;
        return x->pw_uid == y->pw_uid && x->pw_gid == y->pw_gid &&
            identity_string_equal(x->pw_name, y->pw_name) &&
            identity_string_equal(x->pw_passwd, y->pw_passwd) &&
            identity_string_equal(x->pw_gecos, y->pw_gecos) &&
            identity_string_equal(x->pw_dir, y->pw_dir) &&
            identity_string_equal(x->pw_shell, y->pw_shell);
    }
    const struct group *x = &a->record.gr, *y = &b->record.gr;
    if (x->gr_gid != y->gr_gid || !identity_string_equal(x->gr_name, y->gr_name) ||
        !identity_string_equal(x->gr_passwd, y->gr_passwd) ||
        !x->gr_mem || !y->gr_mem) return 0;
    for (size_t i = 0; i < 65536; ++i) {
        if (!identity_string_equal(x->gr_mem[i], y->gr_mem[i])) return 0;
        if (!x->gr_mem[i]) return 1;
    }
    return 0;
}

static void identity_call(const struct identity_ops *ops, int kind,
                          const char *name, unsigned int id, size_t capacity,
                          size_t offset, struct identity_result *out) {
    memset(&out->record, 0, sizeof(out->record));
    memset(out->buffer, 0xa5, sizeof(out->buffer));
    out->err = 717;
    errno = 718;
    if (kind == 0)
        out->status = ops->name(name, &out->record, out->buffer + offset,
                                capacity, &out->err);
    else if (kind == 1)
        out->status = ops->id(id, &out->record, out->buffer + offset,
                              capacity, &out->err);
    else
        out->status = ops->next(&out->record, out->buffer + offset,
                                capacity, &out->err);
    out->saved_errno = errno;
}

static int identity_pair(const struct identity_ops *host,
                         const struct identity_ops *candidate, int group,
                         int kind, const char *name, unsigned int id,
                         size_t capacity, size_t offset,
                         struct identity_result *a, struct identity_result *b,
                         unsigned int *observations) {
    identity_call(host, kind, name, id, capacity, offset, a);
    identity_call(candidate, kind, name, id, capacity, offset, b);
    ++*observations;
    if (a->status != b->status || a->err != b->err ||
        a->saved_errno != b->saved_errno ||
        (a->status == 1 && !identity_records_equal(group, a, b))) {
        fprintf(stderr, "FAIL: files %s kind=%d capacity=%zu offset=%zu "
                "host=(%d,%d,%d) candidate=(%d,%d,%d)\n",
                group ? "group" : "passwd", kind, capacity, offset,
                a->status, a->err, a->saved_errno,
                b->status, b->err, b->saved_errno);
        return 1;
    }
    for (size_t i = 0; i < sizeof(b->buffer); ++i) {
        if ((i < offset || i >= offset + capacity) &&
            (unsigned char)b->buffer[i] != 0xa5) {
            fprintf(stderr, "FAIL: files identity wrote outside caller buffer\n");
            return 1;
        }
    }
    return 0;
}

/* Compare actual exported providers from two distinct ELF objects. No system
 * identity files are changed. Fixture-path and missing-file cases are covered
 * separately by pwd_abi_test.rs and grp_abi_test.rs. */
static int test_files_provider(const char *candidate_path) {
    void *host_handle = dlopen("libc.so.6", RTLD_NOW | RTLD_LOCAL);
    void *candidate_handle = dlopen(candidate_path, RTLD_NOW | RTLD_LOCAL);
    struct stat host_stat, candidate_stat;
    Dl_info host_info;
    if (!host_handle || !candidate_handle ||
        !dladdr(dlsym(host_handle, "getpid"), &host_info) ||
        stat(host_info.dli_fname, &host_stat) || stat(candidate_path, &candidate_stat) ||
        (host_stat.st_dev == candidate_stat.st_dev && host_stat.st_ino == candidate_stat.st_ino)) {
        fprintf(stderr, "FAIL: distinct identity providers required: %s\n", dlerror());
        return 42;
    }
    unsigned int observations = 0;
    for (int group = 0; group < 2; ++group) {
        struct identity_ops host, candidate;
        if (!identity_bind(host_handle, &host_stat, group, &host) ||
            !identity_bind(candidate_handle, &candidate_stat, group, &candidate) ||
            host.name == candidate.name || host.id == candidate.id || host.next == candidate.next)
            return 42;
        if (host.start(0) != 1 || candidate.start(0) != 1) return 1;
        struct identity_result a, b, lookup_a, lookup_b;
        unsigned int records = 0;
        for (; records < 4096; ++records) {
            if (identity_pair(&host, &candidate, group, 2, NULL, 0, 65536, 0,
                              &a, &b, &observations)) return 1;
            if (a.status == 0) break;
            if (a.status != 1) return 1;
            const char *name = group ? a.record.gr.gr_name : a.record.pw.pw_name;
            unsigned int id = group ? a.record.gr.gr_gid : a.record.pw.pw_uid;
            for (int kind = 0; kind < 2; ++kind) {
                if (identity_pair(&host, &candidate, group, kind, name, id, 65536, 0,
                                  &lookup_a, &lookup_b, &observations)) return 1;
                if (identity_pair(&host, &candidate, group, kind, name, id, 1, 1,
                                  &lookup_a, &lookup_b, &observations)) return 1;
            }
        }
        if (!records || records == 4096) return 1;
        for (int kind = 0; kind < 2; ++kind) {
            const size_t capacities[] = {0, 1, 31, 32, 63, 128, 65536};
            for (size_t i = 0; i < sizeof(capacities) / sizeof(capacities[0]); ++i)
                if (identity_pair(&host, &candidate, group, kind,
                    "frankenlibc_no_such_identity_5e87bb9", UINT32_MAX,
                    capacities[i], 1, &a, &b, &observations)) return 1;
        }
        if (host.start(1) != 1 || candidate.start(1) != 1) return 1;
        if (identity_pair(&host, &candidate, group, 2, NULL, 0, 1, 0,
                          &a, &b, &observations) || a.status != -2) return 1;
        if (identity_pair(&host, &candidate, group, 2, NULL, 0, 65536, 0,
                          &a, &b, &observations) || a.status != 1) return 1;
        if (host.end() != 1 || candidate.end() != 1) return 1;
        if (identity_pair(&host, &candidate, group, 2, NULL, 0, 65536, 0,
                          &a, &b, &observations) || a.status != 1) return 1;
        if (host.end() != 1 || candidate.end() != 1) return 1;
    }
    printf("fixture_nss: files provider PASS (%u differential observations)\n", observations);
    dlclose(candidate_handle);
    dlclose(host_handle);
    return 0;
}

struct hosts_tuple {
    struct hosts_tuple *next;
    char *name;
    int family;
    uint32_t addr[4];
    uint32_t scopeid;
};

typedef int (*hosts_name4_fn)(const char *, struct hosts_tuple **,
                              char *, size_t, int *, int *, int32_t *);

struct hosts_result {
    struct hosts_tuple supplied, *head;
    char buffer[65537];
    int status, err, herr, saved_errno;
    int32_t ttl;
};

static void hosts_call(hosts_name4_fn fn, const char *name, size_t capacity,
                       size_t offset, int supply_head, struct hosts_result *out) {
    memset(&out->supplied, 0, sizeof(out->supplied));
    memset(out->buffer, 0xa5, sizeof(out->buffer));
    out->head = supply_head ? &out->supplied : NULL;
    out->err = 777;
    out->herr = 778;
    out->ttl = 779;
    errno = 780;
    out->status = fn(name, &out->head, out->buffer + offset, capacity,
                      &out->err, &out->herr, &out->ttl);
    out->saved_errno = errno;
}

static int hosts_pair(hosts_name4_fn host, hosts_name4_fn candidate,
                       const char *name, size_t capacity, size_t offset,
                       int supply_head, int expected_status, unsigned int expected_count,
                       unsigned int *observations) {
    struct hosts_result a, b;
    hosts_call(host, name, capacity, offset, supply_head, &a);
    hosts_call(candidate, name, capacity, offset, supply_head, &b);
    ++*observations;
    if (a.status != expected_status || a.status != b.status || a.err != b.err || a.herr != b.herr ||
        a.ttl != b.ttl || a.saved_errno != b.saved_errno) {
        fprintf(stderr, "FAIL: hosts name=%s capacity=%zu offset=%zu supplied=%d "
                "host=(%d,%d,%d,%d,%d) candidate=(%d,%d,%d,%d,%d)\n",
                name, capacity, offset, supply_head,
                a.status, a.err, a.herr, a.ttl, a.saved_errno,
                b.status, b.err, b.herr, b.ttl, b.saved_errno);
        return 1;
    }
    for (size_t i = 0; i < sizeof(b.buffer); ++i) {
        if ((i < offset || i >= offset + capacity) &&
            (unsigned char)b.buffer[i] != 0xa5) {
            fprintf(stderr, "FAIL: hosts wrote outside caller buffer\n");
            return 1;
        }
    }
    if (a.status != 1) return 0;
    if (supply_head && (a.head != &a.supplied || b.head != &b.supplied)) {
        fprintf(stderr, "FAIL: hosts replaced the caller-supplied head\n");
        return 1;
    }
    const struct hosts_tuple *x = a.head, *y = b.head;
    unsigned int count = 0;
    for (; x && y && count < 4096; ++count, x = x->next, y = y->next) {
        size_t width = x->family == AF_INET ? 4 : 16;
        if (x->family != y->family || x->scopeid != y->scopeid ||
            !identity_string_equal(x->name, y->name) ||
            memcmp(x->addr, y->addr, width)) {
            fprintf(stderr, "FAIL: hosts tuple mismatch at row %u for %s\n", count, name);
            return 1;
        }
        if (y != &b.supplied &&
            ((uintptr_t)y < (uintptr_t)(b.buffer + offset) ||
             (uintptr_t)y + sizeof(*y) > (uintptr_t)(b.buffer + offset + capacity) ||
             (uintptr_t)y % _Alignof(struct hosts_tuple))) {
            fprintf(stderr, "FAIL: hosts tuple outside/alignment of caller storage\n");
            return 1;
        }
    }
    if (x || y || count != expected_count) {
        fprintf(stderr, "FAIL: hosts %s expected %u complete rows, compared %u\n",
                name, expected_count, count);
        return 1;
    }
    return 0;
}

/* Use a private /etc/hosts bind mount for deterministic IPv6-only, mixed-family,
 * and >64-row cases. Both real ELF providers read the same file. The explicit
 * count makes an empty fixture or missing symbol fail, never pass vacuously. */
static int test_hosts_provider(const char *candidate_path, const char *name,
                                unsigned int expected_count) {
    void *host_handle = dlopen("libc.so.6", RTLD_NOW | RTLD_LOCAL);
    void *candidate_handle = dlopen(candidate_path, RTLD_NOW | RTLD_LOCAL);
    struct stat host_stat, candidate_stat;
    Dl_info host_info;
    if (!expected_count || expected_count > 4096 || !host_handle || !candidate_handle ||
        !dladdr(dlsym(host_handle, "getpid"), &host_info) ||
        stat(host_info.dli_fname, &host_stat) || stat(candidate_path, &candidate_stat) ||
        (host_stat.st_dev == candidate_stat.st_dev && host_stat.st_ino == candidate_stat.st_ino)) {
        fprintf(stderr, "FAIL: distinct hosts providers and a nonempty fixture required\n");
        return 42;
    }
    hosts_name4_fn host = (hosts_name4_fn)identity_symbol(host_handle,
        "_nss_files_gethostbyname4_r", &host_stat);
    hosts_name4_fn candidate = (hosts_name4_fn)identity_symbol(candidate_handle,
        "_nss_files_gethostbyname4_r", &candidate_stat);
    if (!host || !candidate || host == candidate) return 42;
    /* GNU initializes /etc/host.conf (including multi) through public lookup. */
    struct hostent *(*host_lookup)(const char *) =
        (struct hostent *(*)(const char *))identity_symbol(host_handle,
            "gethostbyname", &host_stat);
    if (!host_lookup) return 42;
    (void)host_lookup(name);
    unsigned int observations = 0;
    for (size_t offset = 0; offset < 2; ++offset) {
        for (int supplied = 0; supplied < 2; ++supplied) {
            if (hosts_pair(host, candidate, name, 1, offset, supplied,
                           -2, expected_count, &observations) ||
                hosts_pair(host, candidate, name, 65536, offset, supplied,
                           1, expected_count, &observations) ||
                hosts_pair(host, candidate, "frankenlibc_missing_host_5e87bb9",
                           65536, offset, supplied, 0, 0, &observations)) return 1;
        }
    }
    printf("fixture_nss: hosts provider PASS (%u differential observations, %u rows)\n",
           observations, expected_count);
    dlclose(candidate_handle);
    dlclose(host_handle);
    return 0;
}

static int test_getpwnam_root(void) {
    struct passwd *pw = getpwnam("root");
    if (pw == NULL) {
        fprintf(stderr, "FAIL: getpwnam(root) returned NULL errno=%d\n", errno);
        return 1;
    }
    if (pw->pw_name == NULL || strcmp(pw->pw_name, "root") != 0) {
        fprintf(stderr, "FAIL: getpwnam(root) returned unexpected name\n");
        return 1;
    }
    return 0;
}

static int test_getpwuid_zero(void) {
    struct passwd *pw = getpwuid(0);
    if (pw == NULL) {
        fprintf(stderr, "FAIL: getpwuid(0) returned NULL errno=%d\n", errno);
        return 1;
    }
    if (pw->pw_name == NULL || pw->pw_name[0] == '\0') {
        fprintf(stderr, "FAIL: getpwuid(0) returned empty name\n");
        return 1;
    }
    return 0;
}

static int test_getpwnam_missing(void) {
    errno = 0;
    struct passwd *pw = getpwnam("frankenlibc_missing_user_xyz");
    if (pw != NULL) {
        fprintf(stderr, "FAIL: getpwnam(missing) expected NULL\n");
        return 1;
    }
    return 0;
}

static int test_getgrnam_root(void) {
    struct group *gr = getgrnam("root");
    if (gr == NULL) {
        fprintf(stderr, "FAIL: getgrnam(root) returned NULL errno=%d\n", errno);
        return 1;
    }
    if (gr->gr_name == NULL || strcmp(gr->gr_name, "root") != 0) {
        fprintf(stderr, "FAIL: getgrnam(root) returned unexpected name\n");
        return 1;
    }
    return 0;
}

static int test_getgrgid_zero(void) {
    struct group *gr = getgrgid(0);
    if (gr == NULL) {
        fprintf(stderr, "FAIL: getgrgid(0) returned NULL errno=%d\n", errno);
        return 1;
    }
    if (gr->gr_name == NULL || gr->gr_name[0] == '\0') {
        fprintf(stderr, "FAIL: getgrgid(0) returned empty group name\n");
        return 1;
    }
    return 0;
}

static int test_getgrnam_missing(void) {
    errno = 0;
    struct group *gr = getgrnam("frankenlibc_missing_group_xyz");
    if (gr != NULL) {
        fprintf(stderr, "FAIL: getgrnam(missing) expected NULL\n");
        return 1;
    }
    return 0;
}

static int test_passwd_group_enumeration_controls(void) {
    setpwent();
    struct passwd *pw = getpwent();
    endpwent();
    if (pw == NULL) {
        fprintf(stderr, "FAIL: getpwent() returned NULL after setpwent()\n");
        return 1;
    }

    setgrent();
    struct group *gr = getgrent();
    endgrent();
    if (gr == NULL) {
        fprintf(stderr, "FAIL: getgrent() returned NULL after setgrent()\n");
        return 1;
    }

    return 0;
}

static int test_getaddrinfo_localhost(void) {
    struct addrinfo hints;
    memset(&hints, 0, sizeof(hints));
    hints.ai_socktype = SOCK_STREAM;

    struct addrinfo *res = NULL;
    int rc = getaddrinfo("localhost", "80", &hints, &res);
    if (rc != 0) {
        fprintf(stderr, "FAIL: getaddrinfo(localhost,80) rc=%d (%s)\n", rc, gai_strerror(rc));
        return 1;
    }
    if (res == NULL) {
        fprintf(stderr, "FAIL: getaddrinfo(localhost,80) returned NULL list\n");
        return 1;
    }

    int family = res->ai_family;
    freeaddrinfo(res);

    if (!(family == AF_INET || family == AF_INET6)) {
        fprintf(stderr, "FAIL: getaddrinfo(localhost,80) family=%d\n", family);
        return 1;
    }
    return 0;
}

static int test_getaddrinfo_default_hints(void) {
    struct addrinfo *res = NULL;
    int rc = getaddrinfo("127.0.0.1", "80", NULL, &res);
    if (rc != 0 || res == NULL) {
        fprintf(stderr, "FAIL: getaddrinfo default hints rc=%d\n", rc);
        return 1;
    }
    int count = 0;
    int transports = 0;
    for (const struct addrinfo *entry = res; entry; entry = entry->ai_next) {
        if (entry->ai_flags != (AI_V4MAPPED | AI_ADDRCONFIG) ||
            entry->ai_family != AF_INET) {
            fprintf(stderr, "FAIL: default hints flags=%d family=%d\n",
                    entry->ai_flags, entry->ai_family);
            freeaddrinfo(res);
            return 1;
        }
        if (entry->ai_socktype == SOCK_STREAM && entry->ai_protocol == IPPROTO_TCP)
            transports |= 1;
        if (entry->ai_socktype == SOCK_DGRAM && entry->ai_protocol == IPPROTO_UDP)
            transports |= 2;
        if (entry->ai_socktype == SOCK_RAW && entry->ai_protocol == 0)
            transports |= 4;
        ++count;
    }
    freeaddrinfo(res);
    if (count != 3 || transports != 7) {
        fprintf(stderr, "FAIL: default hints count=%d transports=%d\n", count, transports);
        return 1;
    }
    return 0;
}

struct password_lock_ops {
    int (*lock)(void);
    int (*unlock)(void);
};

static volatile sig_atomic_t password_lock_signals;

static void password_lock_signal_handler(int signal_number) {
    (void)signal_number;
    ++password_lock_signals;
}

static double password_lock_now(void) {
    struct timespec now;
    if (clock_gettime(CLOCK_MONOTONIC, &now)) return -1;
    return (double)now.tv_sec + (double)now.tv_nsec / 1000000000.0;
}

static void password_lock_pause(unsigned int milliseconds) {
    struct timespec delay = {
        .tv_sec = milliseconds / 1000,
        .tv_nsec = (long)(milliseconds % 1000) * 1000000
    };
    while (nanosleep(&delay, &delay) && errno == EINTR) {}
}

static int password_lock_wait(pid_t child) {
    int status;
    pid_t result;
    do { result = waitpid(child, &status, 0); } while (result < 0 && errno == EINTR);
    return result == child && WIFEXITED(status) && WEXITSTATUS(status) == 0;
}

static int password_lock_try_range(int fd) {
    struct flock lock = {
        .l_type = F_WRLCK, .l_whence = SEEK_SET, .l_start = 4096, .l_len = 1
    };
    return fcntl(fd, F_SETLK, &lock);
}

/* The child never inherits its parent's POSIX record lock. Closing the child's
 * copy of the provider's descriptor must leave the parent's lock in force. */
static int password_lock_fork_probe(const struct password_lock_ops *ops,
                                    int inherited_handle, int expect_busy) {
    pid_t child = fork();
    if (child < 0) return 0;
    if (!child) {
        struct sigaction deadline = {0};
        deadline.sa_handler = SIG_DFL;
        sigemptyset(&deadline.sa_mask);
        if (sigaction(SIGALRM, &deadline, NULL)) _exit(10);
        sigset_t timeout_mask;
        sigemptyset(&timeout_mask);
        sigaddset(&timeout_mask, SIGALRM);
        if (sigprocmask(SIG_UNBLOCK, &timeout_mask, NULL)) _exit(10);
        alarm(3);
        if (inherited_handle) {
            errno = 821;
            if (ops->lock() != -1 || errno != 821) _exit(11);
            if (ops->unlock() != 0 || errno != 821) _exit(12);
            if (ops->unlock() != -1 || errno != 821) _exit(13);
        }
        int fd = open("/etc/.pwd.lock", O_WRONLY | O_CLOEXEC);
        if (fd < 0) _exit(14);
        int rc = password_lock_try_range(fd);
        int busy = rc == -1 && (errno == EAGAIN || errno == EACCES);
        close(fd);
        _exit(expect_busy ? (busy ? 0 : 15) : (rc == 0 ? 0 : 16));
    }
    return password_lock_wait(child);
}

/* Observe the provider's descriptor without opening/closing the lock inode in
 * this process: closing ANY descriptor for it would drop a POSIX record lock. */
static int password_lock_find_fd(void) {
    struct stat expected, actual;
    if (stat("/etc/.pwd.lock", &expected)) return -1;
    DIR *directory = opendir("/proc/self/fd");
    if (!directory) return -1;
    int result = -1;
    struct dirent *entry;
    while ((entry = readdir(directory))) {
        char *end;
        long value = strtol(entry->d_name, &end, 10);
        if (*end || value < 0 || value > INT32_MAX) continue;
        if (!fstat((int)value, &actual) && actual.st_dev == expected.st_dev &&
            actual.st_ino == expected.st_ino) {
            result = (int)value;
            break;
        }
    }
    closedir(directory);
    return result;
}

struct password_lock_holder {
    pid_t pid;
    int release_fd;
    int automatic;
};

/* A separate process owns the kernel lock. A zero hold duration waits for the
 * parent to release it; nonzero durations can deliver SIGUSR1 during the wait. */
static int password_lock_start_holder(struct password_lock_holder *holder,
                                      unsigned int hold_ms, int send_signal) {
    int ready[2], release[2];
    if (pipe(ready)) return 0;
    if (pipe(release)) { close(ready[0]); close(ready[1]); return 0; }
    pid_t parent = getpid();
    pid_t child = fork();
    if (child < 0) {
        close(ready[0]); close(ready[1]); close(release[0]); close(release[1]);
        return 0;
    }
    if (!child) {
        close(ready[0]); close(release[1]);
        int fd = open("/etc/.pwd.lock", O_WRONLY | O_CLOEXEC);
        if (fd < 0 || password_lock_try_range(fd)) _exit(21);
        if (write(ready[1], "R", 1) != 1) _exit(22);
        close(ready[1]);
        if (send_signal) {
            password_lock_pause(100);
            if (kill(parent, SIGUSR1)) _exit(23);
        }
        if (hold_ms) {
            password_lock_pause(hold_ms - (send_signal ? 100 : 0));
        } else {
            char byte;
            ssize_t n;
            do { n = read(release[0], &byte, 1); } while (n < 0 && errno == EINTR);
            if (n != 1) _exit(24);
        }
        close(fd);
        _exit(0);
    }
    close(ready[1]); close(release[0]);
    char byte;
    ssize_t n;
    do { n = read(ready[0], &byte, 1); } while (n < 0 && errno == EINTR);
    close(ready[0]);
    if (n != 1 || byte != 'R') {
        close(release[1]);
        password_lock_wait(child);
        return 0;
    }
    *holder = (struct password_lock_holder){child, release[1], hold_ms != 0};
    return 1;
}

static int password_lock_finish_holder(struct password_lock_holder *holder) {
    int released = 1;
    if (!holder->automatic) released = write(holder->release_fd, "R", 1) == 1;
    close(holder->release_fd);
    return password_lock_wait(holder->pid) && released;
}

struct password_lock_thread {
    const struct password_lock_ops *ops;
    int unlock, result, saved_errno;
    atomic_int done;
};

static void *password_lock_thread_call(void *argument) {
    struct password_lock_thread *call = argument;
    errno = 829;
    call->result = call->unlock ? call->ops->unlock() : call->ops->lock();
    call->saved_errno = errno;
    atomic_store_explicit(&call->done, 1, memory_order_release);
    return NULL;
}

static int password_lock_same_action(const struct sigaction *a,
                                     const struct sigaction *b) {
    if (a->sa_handler != b->sa_handler || a->sa_flags != b->sa_flags ||
        a->sa_restorer != b->sa_restorer) return 0;
    for (int signal_number = 1; signal_number <= 64; ++signal_number)
        if (sigismember(&a->sa_mask, signal_number) !=
            sigismember(&b->sa_mask, signal_number)) return 0;
    return 1;
}

#define PASSWORD_CHECK(condition, description) do { \
    if (!(condition)) { \
        fprintf(stderr, "FAIL: password lock %s (errno=%d)\n", description, errno); \
        return 1; \
    } \
} while (0)

/* Run inside a private /etc bind mount, for example bwrap --unshare-user
 * --unshare-pid --ro-bind / / --bind "$scratch_etc" /etc --proc /proc --
 * fixture_nss --password-lock-provider "$provider" "$scratch_etc".
 * The directory-identity check prevents an accidental ordinary host run. */
static int test_password_lock_provider(const char *provider_path,
                                       const char *expected_etc,
                                       int exercise_fork_gate) {
    struct stat expected_directory, actual_directory, provider, lock_file;
    PASSWORD_CHECK(strcmp(expected_etc, "/etc") != 0 &&
        !stat(expected_etc, &expected_directory) && !stat("/etc", &actual_directory) &&
        expected_directory.st_dev == actual_directory.st_dev &&
        expected_directory.st_ino == actual_directory.st_ino, "requires private /etc");
    void *handle = dlopen(provider_path, RTLD_NOW | RTLD_LOCAL);
    PASSWORD_CHECK(handle && !stat(provider_path, &provider), "open provider");
    struct password_lock_ops ops = {
        (int (*)(void))identity_symbol(handle, "lckpwdf", &provider),
        (int (*)(void))identity_symbol(handle, "ulckpwdf", &provider)
    };
    PASSWORD_CHECK(ops.lock && ops.unlock, "exported provider identity");
    mode_t old_umask = umask(077);
    errno = 811;
    PASSWORD_CHECK(ops.unlock() == -1 && errno == 811, "unowned unlock");

    struct sigaction alarm_action = {0}, old_alarm, installed_alarm, observed_alarm;
    alarm_action.sa_handler = password_lock_signal_handler;
    alarm_action.sa_flags = SA_RESTART;
    sigemptyset(&alarm_action.sa_mask);
    sigaddset(&alarm_action.sa_mask, SIGUSR2);
    PASSWORD_CHECK(!sigaction(SIGALRM, &alarm_action, &old_alarm) &&
        !sigaction(SIGALRM, NULL, &installed_alarm), "install alarm sentinel");
    sigset_t mask, original_mask, observed_mask;
    sigemptyset(&mask); sigaddset(&mask, SIGALRM); sigaddset(&mask, SIGUSR2);
    PASSWORD_CHECK(!pthread_sigmask(SIG_BLOCK, &mask, &original_mask), "block alarm");
    alarm(5);
    errno = 812;
    PASSWORD_CHECK(ops.lock() == 0 && errno == 812, "acquire and preserve errno");
    PASSWORD_CHECK(alarm(0) == 0, "cancel prior alarm");
    PASSWORD_CHECK(!sigaction(SIGALRM, NULL, &observed_alarm) &&
        password_lock_same_action(&installed_alarm, &observed_alarm), "restore alarm action");
    PASSWORD_CHECK(!pthread_sigmask(SIG_SETMASK, NULL, &observed_mask) &&
        sigismember(&observed_mask, SIGALRM) == 1 &&
        sigismember(&observed_mask, SIGUSR2) == 1, "restore blocked signal mask");
    PASSWORD_CHECK(!stat("/etc/.pwd.lock", &lock_file) &&
        S_ISREG(lock_file.st_mode) && (lock_file.st_mode & 0777) == 0600, "create mode600");
    int descriptor = password_lock_find_fd();
    int descriptor_flags = descriptor >= 0 ? fcntl(descriptor, F_GETFD) : -1;
    PASSWORD_CHECK(descriptor_flags >= 0 && (descriptor_flags & FD_CLOEXEC), "close-on-exec");
    errno = 813;
    PASSWORD_CHECK(ops.lock() == -1 && errno == 813, "duplicate acquisition");
    PASSWORD_CHECK(password_lock_fork_probe(&ops, 1, 1), "fork handle and parent exclusion");
    errno = 814;
    PASSWORD_CHECK(ops.unlock() == 0 && errno == 814, "release and preserve errno");
    PASSWORD_CHECK(password_lock_fork_probe(&ops, 0, 0), "release kernel lock");
    PASSWORD_CHECK(!pthread_sigmask(SIG_SETMASK, &original_mask, NULL), "restore test mask");

    if (geteuid() != 0) {
        PASSWORD_CHECK(!chmod("/etc/.pwd.lock", 0400), "set read-only lock fixture");
        int denied = ops.lock(), denied_errno = errno;
        PASSWORD_CHECK(!chmod("/etc/.pwd.lock", 0600), "restore lock fixture permissions");
        PASSWORD_CHECK(denied == -1 && denied_errno == EACCES, "propagate open permission error");
        errno = 815;
        PASSWORD_CHECK(ops.unlock() == -1 && errno == 815, "failed open has no ownership");
    }

    struct sigaction user_action = {0}, old_user;
    user_action.sa_handler = password_lock_signal_handler;
    sigemptyset(&user_action.sa_mask);
    PASSWORD_CHECK(!sigaction(SIGUSR1, &user_action, &old_user), "install interrupt handler");
    sigemptyset(&mask); sigaddset(&mask, SIGUSR1);
    sigset_t before_user_mask;
    PASSWORD_CHECK(!pthread_sigmask(SIG_UNBLOCK, &mask, &before_user_mask), "unblock interrupt");
    for (int restart = 0; restart < 2; ++restart) {
        user_action.sa_flags = restart ? SA_RESTART : 0;
        PASSWORD_CHECK(!sigaction(SIGUSR1, &user_action, NULL), "set restart behavior");
        struct password_lock_holder holder;
        PASSWORD_CHECK(password_lock_start_holder(&holder, 400, 1), "start signal holder");
        password_lock_signals = 0;
        errno = 816;
        double started = password_lock_now();
        int rc = ops.lock(), saved_errno = errno;
        double elapsed = password_lock_now() - started;
        int holder_ok = password_lock_finish_holder(&holder);
        PASSWORD_CHECK(holder_ok && password_lock_signals == 1, "deliver signal during wait");
        if (restart) {
            PASSWORD_CHECK(rc == 0 && saved_errno == 816 && elapsed >= 0.25,
                "SA_RESTART waits for owner release");
            PASSWORD_CHECK(ops.unlock() == 0, "release restarted acquisition");
        } else {
            PASSWORD_CHECK(rc == -1 && saved_errno == EINTR && elapsed < 0.35,
                "nonrestart signal interrupts wait");
            errno = 817;
            PASSWORD_CHECK(ops.unlock() == -1 && errno == 817, "interrupt clears ownership");
        }
    }
    PASSWORD_CHECK(!sigaction(SIGUSR1, &old_user, NULL) &&
        !pthread_sigmask(SIG_SETMASK, &before_user_mask, NULL), "restore interrupt state");

    struct password_lock_holder holder;
    PASSWORD_CHECK(password_lock_start_holder(&holder, 0, 0), "start threaded holder");
    struct password_lock_thread acquire = {.ops = &ops}, release = {.ops = &ops, .unlock = 1};
    pthread_t acquiring, releasing;
    PASSWORD_CHECK(!pthread_create(&acquiring, NULL, password_lock_thread_call, &acquire),
        "start acquisition thread");
    double ready_deadline = password_lock_now() + 5.0;
    while (password_lock_find_fd() < 0 && password_lock_now() < ready_deadline)
        password_lock_pause(1);
    PASSWORD_CHECK(password_lock_find_fd() >= 0, "publish waiting descriptor");
    errno = 818;
    double duplicate_start = password_lock_now();
    PASSWORD_CHECK(ops.lock() == -1 && errno == 818 &&
        password_lock_now() - duplicate_start < 0.2, "reject concurrent duplicate promptly");
    /* GNU's internal mutex can remain inherited from a vanished parent thread.
     * The extra mode tests FrankenLibC's process-aware gate separately from the
     * host-compatible behavioral contract exercised by the ordinary mode. */
    if (exercise_fork_gate)
        PASSWORD_CHECK(password_lock_fork_probe(&ops, 1, 1), "fork while operation gate is held");
    PASSWORD_CHECK(!pthread_create(&releasing, NULL, password_lock_thread_call, &release),
        "start release thread");
    password_lock_pause(50);
    int release_waited = !atomic_load_explicit(&release.done, memory_order_acquire);
    PASSWORD_CHECK(password_lock_finish_holder(&holder), "release threaded holder");
    PASSWORD_CHECK(!pthread_join(acquiring, NULL) && !pthread_join(releasing, NULL),
        "join lock threads");
    PASSWORD_CHECK(release_waited && acquire.result == 0 && release.result == 0 &&
        acquire.saved_errno == 829 && release.saved_errno == 829, "serialize concurrent unlock");
    PASSWORD_CHECK(password_lock_fork_probe(&ops, 0, 0), "threaded release drops lock");

    PASSWORD_CHECK(password_lock_start_holder(&holder, 0, 0), "start timeout holder");
    sigemptyset(&mask); sigaddset(&mask, SIGALRM);
    PASSWORD_CHECK(!pthread_sigmask(SIG_BLOCK, &mask, &original_mask), "block alarm before timeout");
    sig_atomic_t previous_signals = password_lock_signals;
    errno = 819;
    double started = password_lock_now();
    int rc = ops.lock(), saved_errno = errno;
    double elapsed = password_lock_now() - started;
    PASSWORD_CHECK(password_lock_finish_holder(&holder), "release timeout holder");
    PASSWORD_CHECK(rc == -1 && saved_errno == EINTR && elapsed >= 14.0 && elapsed < 20.0,
        "15-second alarm timeout");
    PASSWORD_CHECK(password_lock_signals == previous_signals,
        "temporary timeout does not call application handler");
    PASSWORD_CHECK(!sigaction(SIGALRM, NULL, &observed_alarm) &&
        password_lock_same_action(&installed_alarm, &observed_alarm), "restore handler after timeout");
    PASSWORD_CHECK(!pthread_sigmask(SIG_SETMASK, NULL, &observed_mask) &&
        sigismember(&observed_mask, SIGALRM) == 1, "restore mask after timeout");
    PASSWORD_CHECK(!pthread_sigmask(SIG_SETMASK, &original_mask, NULL), "restore timeout test mask");
    PASSWORD_CHECK(alarm(0) == 0, "no alarm remains after timeout");
    errno = 820;
    PASSWORD_CHECK(ops.unlock() == -1 && errno == 820, "timeout clears ownership");
    PASSWORD_CHECK(ops.lock() == 0 && ops.unlock() == 0, "retry after timeout");
    PASSWORD_CHECK(!sigaction(SIGALRM, &old_alarm, NULL), "restore original alarm handler");
    umask(old_umask);
    dlclose(handle);
    printf("fixture_nss: password lock provider PASS (timeout %.3fs)\n", elapsed);
    return 0;
}

#undef PASSWORD_CHECK

int main(int argc, char **argv) {
    if (argc == 4 && strcmp(argv[1], "--password-lock-provider") == 0)
        return test_password_lock_provider(argv[2], argv[3], 0);
    if (argc == 4 && strcmp(argv[1], "--password-lock-fork-provider") == 0)
        return test_password_lock_provider(argv[2], argv[3], 1);
    if (argc == 3 && strcmp(argv[1], "--files-provider") == 0)
        return test_files_provider(argv[2]);
    if (argc == 5 && strcmp(argv[1], "--hosts-provider") == 0)
        return test_hosts_provider(argv[2], argv[3], (unsigned int)strtoul(argv[4], NULL, 10));
    if (argc != 1) return 2;
    int fails = 0;

    fails += test_getpwnam_root();
    fails += test_getpwuid_zero();
    fails += test_getpwnam_missing();
    fails += test_getgrnam_root();
    fails += test_getgrgid_zero();
    fails += test_getgrnam_missing();
    fails += test_passwd_group_enumeration_controls();
    fails += test_getaddrinfo_localhost();
    fails += test_getaddrinfo_default_hints();

    if (fails) {
        fprintf(stderr, "fixture_nss: %d FAILED\n", fails);
        return 1;
    }

    printf("fixture_nss: PASS (9 tests)\n");
    return 0;
}
