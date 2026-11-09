/* fixture_nss.c — NSS/resolver lookup smoke fixture (bd-x2sq)
 * Exit 0 = PASS, nonzero = FAIL with diagnostics.
 */
#define _GNU_SOURCE
#include <dlfcn.h>
#include <errno.h>
#include <grp.h>
#include <netdb.h>
#include <pwd.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>

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

int main(int argc, char **argv) {
    if (argc == 3 && strcmp(argv[1], "--files-provider") == 0)
        return test_files_provider(argv[2]);
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
