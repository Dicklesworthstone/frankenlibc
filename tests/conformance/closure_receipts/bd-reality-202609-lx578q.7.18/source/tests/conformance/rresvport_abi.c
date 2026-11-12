/* Reserved-port ABI conformance. Requires CAP_NET_BIND_SERVICE and unused
 * TCP ports 512, 1022 and 1023. Each case runs in its own child; kernel bind
 * denial and descriptor limits affect that child only. No network traffic.
 * cc -std=c11 -O2 -Wall -Wextra -Werror rresvport_abi.c -ldl -o rresvport-abi
 * rresvport-abi (--host|CANDIDATE) EXPECTED_PROVIDER [--linked]
 * --linked checks the executable's versioned C relocations under LD_PRELOAD.
 */
#define _GNU_SOURCE
#include <arpa/inet.h>
#include <dirent.h>
#include <dlfcn.h>
#include <errno.h>
#include <linux/filter.h>
#include <linux/seccomp.h>
#include <netdb.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/prctl.h>
#include <sys/resource.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/wait.h>
#include <unistd.h>

#ifdef NDEBUG
#error "The reserved-port oracle requires active checks"
#endif

static int (*reserve_port)(int *);
static int (*reserve_family)(int *, sa_family_t);
static int *(*error_location)(void);
static int corrupt_port;

static void reject(const char *reason) {
    fprintf(stderr, "FAIL: %s\n", reason);
    exit(42);
}

static void pin(void *symbol, const char *name, const char *expected_path) {
    Dl_info info;
    struct stat expected, actual;
    if (!symbol || !dladdr(symbol, &info) ||
        stat(expected_path, &expected) || stat(info.dli_fname, &actual) ||
        expected.st_dev != actual.st_dev || expected.st_ino != actual.st_ino)
        reject("provider_mismatch");
    printf("PROVIDER: %s %s\n", name, info.dli_fname);
}

static int descriptors(void) {
    DIR *dir = opendir("/proc/self/fd");
    if (!dir) reject("descriptor_count_unavailable");
    int count = 0;
    struct dirent *entry;
    while ((entry = readdir(dir)))
        if (strcmp(entry->d_name, ".") && strcmp(entry->d_name, "..")) ++count;
    if (closedir(dir)) reject("descriptor_count_close");
    return count;
}

static int occupy(int family, int port) {
    int fd = socket(family, SOCK_STREAM, 0);
    if (fd < 0) reject("blocker_socket_precondition");
    struct sockaddr_storage address = {0};
    socklen_t size;
    if (family == AF_INET) {
        struct sockaddr_in *a = (void *)&address;
        a->sin_family = AF_INET;
        a->sin_port = htons((unsigned short)port);
        size = sizeof(*a);
    } else {
        struct sockaddr_in6 *a = (void *)&address;
        a->sin6_family = AF_INET6;
        a->sin6_port = htons((unsigned short)port);
        size = sizeof(*a);
    }
    if (bind(fd, (void *)&address, size)) reject("blocker_bind_precondition");
    return fd;
}

static void deny_bind(void) {
    /* Fault injection only, not a general sandbox: bind returns EACCES. */
    struct sock_filter filter[] = {
        BPF_STMT(BPF_LD | BPF_W | BPF_ABS, offsetof(struct seccomp_data, nr)),
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, SYS_bind, 0, 1),
        BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ERRNO | EACCES),
        BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW)
    };
    struct sock_fprog program = {
        .len = sizeof(filter) / sizeof(filter[0]), .filter = filter
    };
    if (prctl(PR_SET_NO_NEW_PRIVS, 1UL, 0UL, 0UL, 0UL) ||
        prctl(PR_SET_SECCOMP, (unsigned long)SECCOMP_MODE_FILTER,
            (unsigned long)&program, 0UL, 0UL))
        reject("bind_denial_precondition");
}

struct test_case {
    const char *name;
    int family, seed, expected_port, blockers, expected_errno, fd_limit, deny, legacy;
};

static const struct test_case cases[] = {
    {"legacy-negative", AF_INET, -1, 512, 0, 0, 0, 0, 1},
    {"legacy-zero", AF_INET, 0, 512, 0, 0, 0, 0, 1},
    {"legacy-low", AF_INET, 511, 512, 0, 0, 0, 0, 1},
    {"legacy-floor", AF_INET, 512, 512, 0, 0, 0, 0, 1},
    {"legacy-high", AF_INET, 1024, 1023, 0, 0, 0, 0, 1},
    {"legacy-wide", AF_INET, 65536, 1023, 0, 0, 0, 0, 1},
    {"legacy-wrap", AF_INET, 512, 1023, 1, 0, 0, 0, 1},
    {"legacy-two-collisions", AF_INET, 512, 1022, 2, 0, 0, 0, 1},
    {"legacy-bind-denied", AF_INET, 512, -1, 0, EACCES, 0, 1, 1},
    {"legacy-no-descriptors", AF_INET, 512, -1, 0, EMFILE, 1, 0, 1},
    {"inet-negative", AF_INET, -1, 512, 0, 0, 0, 0, 0},
    {"inet-zero", AF_INET, 0, 512, 0, 0, 0, 0, 0},
    {"inet-low", AF_INET, 511, 512, 0, 0, 0, 0, 0},
    {"inet-floor", AF_INET, 512, 512, 0, 0, 0, 0, 0},
    {"inet-high", AF_INET, 1024, 1023, 0, 0, 0, 0, 0},
    {"inet-wide", AF_INET, 65536, 1023, 0, 0, 0, 0, 0},
    {"inet-wrap", AF_INET, 512, 1023, 1, 0, 0, 0, 0},
    {"inet-two-collisions", AF_INET, 512, 1022, 2, 0, 0, 0, 0},
    {"inet-bind-denied", AF_INET, 512, -1, 0, EACCES, 0, 1, 0},
    {"inet-no-descriptors", AF_INET, 512, -1, 0, EMFILE, 1, 0, 0},
    {"inet6-floor", AF_INET6, 512, 512, 0, 0, 0, 0, 0},
    {"inet6-wrap", AF_INET6, 512, 1023, 1, 0, 0, 0, 0},
    {"inet6-two-collisions", AF_INET6, 512, 1022, 2, 0, 0, 0, 0},
    {"inet6-bind-denied", AF_INET6, 512, -1, 0, EACCES, 0, 1, 0},
    {"inet6-no-descriptors", AF_INET6, 512, -1, 0, EMFILE, 1, 0, 0},
    {"unspecified-family", AF_UNSPEC, 512, -1, 0, EAFNOSUPPORT, 0, 0, 0},
    {"unix-family", AF_UNIX, 512, -1, 0, EAFNOSUPPORT, 0, 0, 0},
    {"unix-family-no-descriptors", AF_UNIX, 512, -1, 0, EAFNOSUPPORT, 1, 0, 0}
};

static void exercise(const struct test_case *test) {
    int blocked[2] = {-1, -1};
    if (test->blockers) blocked[0] = occupy(test->family, 512);
    if (test->blockers > 1) blocked[1] = occupy(test->family, 1023);
    int before = descriptors();
    struct rlimit saved;
    if (test->fd_limit) {
        if (getrlimit(RLIMIT_NOFILE, &saved)) reject("getrlimit_precondition");
        struct rlimit limited = saved;
        limited.rlim_cur = 0;
        if (setrlimit(RLIMIT_NOFILE, &limited)) reject("setrlimit_precondition");
    }
    if (test->deny) deny_bind();
    int port = test->seed;
    *error_location() = 0;
    int fd = test->legacy ? reserve_port(&port) :
        reserve_family(&port, (sa_family_t)test->family);
    int error = *error_location();
    if (test->fd_limit && setrlimit(RLIMIT_NOFILE, &saved))
        reject("restore_descriptor_limit");
    printf("RESULT: %s fd=%d seed=%d port=%d errno=%d\n",
        test->name, fd, test->seed, port, error);
    if (test->expected_errno) {
        if (fd != -1 || error != test->expected_errno) reject("errno_contract_mismatch");
    } else {
        struct sockaddr_storage address = {0};
        socklen_t size = sizeof(address);
        if (fd < 0 || getsockname(fd, (void *)&address, &size))
            reject("bound_socket_missing");
        int actual_port = ntohs(((struct sockaddr_in *)&address)->sin_port);
        if (corrupt_port) ++actual_port;
        if (address.ss_family != test->family || port != test->expected_port || port != actual_port)
            reject("port_result_mismatch");
        int type = 0;
        size = sizeof(type);
        if (getsockopt(fd, SOL_SOCKET, SO_TYPE, &type, &size) || type != SOCK_STREAM)
            reject("socket_type_mismatch");
    }
    if (fd >= 0 && close(fd)) reject("returned_socket_close");
    if (descriptors() != before) reject("descriptor_leak");
    for (int index = 0; index < test->blockers; ++index)
        if (close(blocked[index])) reject("blocker_close");
}

int main(int argc, char **argv) {
    if (argc < 3 || argc > 4) reject("usage");
    int host = !strcmp(argv[1], "--host");
    int linked = argc == 4 && !strcmp(argv[3], "--linked");
    if (argc == 4 && !linked) reject("unknown_lookup");
    void *library = dlopen(host ? "libc.so.6" : argv[1], RTLD_NOW | RTLD_LOCAL);
    if (!library) reject("provider_load");
    if (linked) {
        reserve_port = rresvport;
        reserve_family = rresvport_af;
        error_location = __errno_location;
    } else if (host) {
        reserve_port = (void *)dlvsym(library, "rresvport", "GLIBC_2.2.5");
        reserve_family = (void *)dlvsym(library, "rresvport_af", "GLIBC_2.2.5");
        error_location = (void *)dlvsym(library, "__errno_location", "GLIBC_2.2.5");
    } else {
        reserve_port = (void *)dlsym(library, "rresvport");
        reserve_family = (void *)dlsym(library, "rresvport_af");
        error_location = (void *)dlsym(library, "__errno_location");
    }
    pin((void *)reserve_port, "rresvport", argv[2]);
    pin((void *)reserve_family, "rresvport_af", argv[2]);
    pin((void *)error_location, "__errno_location", argv[2]);
    printf("LOOKUP: %s\n", linked ? "versioned-C-relocations" : host ? "GLIBC_2.2.5" : "native-default");
    const char *control = getenv("FLC_RRESVPORT_CONTROL");
    int omit_result = control && !strcmp(control, "missing_result");
    corrupt_port = control && !strcmp(control, "corrupt_port");
    if (control && !omit_result && !corrupt_port) reject("unknown_control");
    unsigned passed = 0;
    for (size_t index = 0; index < sizeof(cases) / sizeof(cases[0]); ++index) {
        if (fflush(NULL)) reject("flush_before_fork");
        pid_t child = fork();
        if (child < 0) reject("case_fork");
        if (!child) {
            exercise(&cases[index]);
            if (fflush(NULL)) reject("flush_child");
            _exit(0);
        }
        int status;
        if (waitpid(child, &status, 0) != child || !WIFEXITED(status) || WEXITSTATUS(status))
            reject("case_failed");
        if (omit_result) {
            omit_result = 0;
            printf("CONTROL: withheld result: %s\n", cases[index].name);
        } else {
            ++passed;
            printf("PASS: %s\n", cases[index].name);
        }
    }
    if (passed != 28) reject("missing_case_result");
    printf("28 %s reserved-port cases passed\n", host ? "host-glibc" : "candidate");
    return 0;
}
