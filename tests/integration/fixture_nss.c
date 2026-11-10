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
#include <gshadow.h>
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

typedef int (*hosts_public_next_fn)(struct hostent *, char *, size_t,
                                     struct hostent **, int *);
typedef struct hostent *(*hosts_static_next_fn)(void);
typedef void (*hosts_public_start_fn)(int);
typedef void (*hosts_public_end_fn)(void);
typedef int (*hosts_files_next_fn)(struct hostent *, char *, size_t, int *, int *);

struct hosts_enumeration_ops {
    hosts_public_next_fn next;
    hosts_static_next_fn next_static;
    hosts_public_start_fn start;
    hosts_public_end_fn end;
    hosts_files_next_fn files_next;
    identity_start_fn files_start;
    identity_end_fn files_end;
};

struct hosts_enumeration_result {
    struct hostent entry, *result;
    char buffer[65537];
    int status, err, herr, saved_errno;
};

struct hosts_enumeration_observations {
    unsigned int count, max_aliases;
    size_t max_name;
};

static int hosts_enumeration_bind(void *handle, const struct stat *owner,
                                   struct hosts_enumeration_ops *ops) {
    ops->next = (hosts_public_next_fn)identity_symbol(handle, "gethostent_r", owner);
    ops->next_static = (hosts_static_next_fn)identity_symbol(handle, "gethostent", owner);
    ops->start = (hosts_public_start_fn)identity_symbol(handle, "sethostent", owner);
    ops->end = (hosts_public_end_fn)identity_symbol(handle, "endhostent", owner);
    ops->files_next = (hosts_files_next_fn)identity_symbol(handle, "_nss_files_gethostent_r", owner);
    ops->files_start = (identity_start_fn)identity_symbol(handle, "_nss_files_sethostent", owner);
    ops->files_end = (identity_end_fn)identity_symbol(handle, "_nss_files_endhostent", owner);
    return ops->next && ops->next_static && ops->start && ops->end &&
        ops->files_next && ops->files_start && ops->files_end;
}

static int hosts_span_owned(const char *buffer, size_t capacity,
                            const void *pointer, size_t length) {
    uintptr_t base = (uintptr_t)buffer, address = (uintptr_t)pointer;
    return pointer && address >= base && length <= capacity &&
        address - base <= capacity - length;
}

static int hosts_string_owned(const char *buffer, size_t capacity, const char *text) {
    return hosts_span_owned(buffer, capacity, text, 1) &&
        memchr(text, 0, capacity - ((uintptr_t)text - (uintptr_t)buffer)) != NULL;
}

static char *hosts_list_at(const void *list, unsigned int index) {
    char *value;
    memcpy(&value, (const char *)list + index * sizeof(value), sizeof(value));
    return value;
}

/* A reentrant answer must not borrow a parser allocation or publish unaligned
 * native pointer tables. GNU may leave h_addr_list unaligned for buffer+1, so
 * read the oracle's pointer slots as bytes and check native alignment separately. */
static int hosts_record_owned(const struct hostent *entry, const char *buffer,
                              size_t capacity) {
    if (!hosts_string_owned(buffer, capacity, entry->h_name) ||
        (entry->h_addrtype != AF_INET && entry->h_addrtype != AF_INET6) ||
        entry->h_length != (entry->h_addrtype == AF_INET ? 4 : 16)) return 0;
    for (int addresses = 0; addresses < 2; ++addresses) {
        char **list = addresses ? entry->h_addr_list : entry->h_aliases;
        if (!list) return 0;
        unsigned int index = 0;
        for (; index < 4096; ++index) {
            if (!hosts_span_owned(buffer, capacity,
                    (const char *)list + index * sizeof(*list), sizeof(*list))) return 0;
            char *value = hosts_list_at(list, index);
            if (!value) break;
            if (addresses) {
                if (!hosts_span_owned(buffer, capacity, value, (size_t)entry->h_length)) return 0;
            } else if (!hosts_string_owned(buffer, capacity, value)) return 0;
        }
        if (index == 4096 || (addresses && !index)) return 0;
    }
    return 1;
}

static int hosts_records_equal(const struct hostent *a, const struct hostent *b,
                                struct hosts_enumeration_observations *observations) {
    if (!a || !b || (uintptr_t)b % _Alignof(struct hostent) ||
        !a->h_name || !b->h_name || !a->h_aliases || !b->h_aliases ||
        !a->h_addr_list || !b->h_addr_list ||
        a->h_addrtype != b->h_addrtype || a->h_length != b->h_length ||
        (a->h_length != 4 && a->h_length != 16) ||
        strcmp(a->h_name, b->h_name)) return 0;
    unsigned int aliases = 0;
    for (; aliases < 4096; ++aliases) {
        char *x = hosts_list_at(a->h_aliases, aliases), *y = hosts_list_at(b->h_aliases, aliases);
        if (!x || !y) {
            if (x != y) return 0;
            break;
        }
        if (strcmp(x, y)) return 0;
    }
    if (aliases == 4096) return 0;
    unsigned int addresses = 0;
    for (; addresses < 4096; ++addresses) {
        char *x = hosts_list_at(a->h_addr_list, addresses), *y = hosts_list_at(b->h_addr_list, addresses);
        if (!x || !y) {
            if (x != y) return 0;
            break;
        }
        if (memcmp(x, y, (size_t)a->h_length)) return 0;
    }
    if (!addresses || addresses == 4096) return 0;
    if (aliases > observations->max_aliases) observations->max_aliases = aliases;
    size_t length = strlen(a->h_name);
    if (length > observations->max_name) observations->max_name = length;
    return 1;
}

static void hosts_enumeration_call(const struct hosts_enumeration_ops *ops,
                                   int files, size_t capacity, size_t offset,
                                   struct hosts_enumeration_result *out) {
    memset(&out->entry, 0, sizeof(out->entry));
    memset(out->buffer, 0xa5, sizeof(out->buffer));
    out->result = NULL;
    out->err = 777;
    out->herr = 778;
    errno = 780;
    if (files) {
        out->status = ops->files_next(&out->entry, out->buffer + offset,
                                      capacity, &out->err, &out->herr);
        if (out->status == 1) out->result = &out->entry;
    } else {
        out->status = ops->next(&out->entry, out->buffer + offset,
                                capacity, &out->result, &out->herr);
    }
    out->saved_errno = errno;
}

static int hosts_enumeration_pair(const struct hosts_enumeration_ops *host,
                                  const struct hosts_enumeration_ops *candidate,
                                  int files, size_t capacity, size_t offset,
                                  int expected, struct hosts_enumeration_observations *observations) {
    struct hosts_enumeration_result a, b;
    hosts_enumeration_call(host, files, capacity, offset, &a);
    hosts_enumeration_call(candidate, files, capacity, offset, &b);
    ++observations->count;
    int found = files ? expected == 1 : expected == 0;
    /* The public API can change errno while initializing resolver policy, even
     * on success or EOF. Its ERANGE errno and all NSS-provider slots are observable. */
    if (a.status != expected || b.status != a.status || a.err != b.err || a.herr != b.herr ||
        ((files || expected == ERANGE) && a.saved_errno != b.saved_errno) ||
        (found ? a.result != &a.entry || b.result != &b.entry : a.result || b.result)) {
        fprintf(stderr, "FAIL: hosts enumeration files=%d capacity=%zu offset=%zu "
                "expected=%d host=(%d,%d,%d,%d) candidate=(%d,%d,%d,%d)\n",
                files, capacity, offset, expected, a.status, a.err, a.herr, a.saved_errno,
                b.status, b.err, b.herr, b.saved_errno);
        return 1;
    }
    for (size_t index = 0; index < sizeof(b.buffer); ++index) {
        if ((index < offset || index >= offset + capacity) &&
            ((unsigned char)a.buffer[index] != 0xa5 || (unsigned char)b.buffer[index] != 0xa5)) {
            fprintf(stderr, "FAIL: hosts enumeration wrote outside caller storage\n");
            return 1;
        }
    }
    if (found && (!hosts_record_owned(&a.entry, a.buffer + offset, capacity) ||
                  !hosts_record_owned(&b.entry, b.buffer + offset, capacity) ||
                  (uintptr_t)b.entry.h_aliases % _Alignof(char *) ||
                  (uintptr_t)b.entry.h_addr_list % _Alignof(char *) ||
                  !hosts_records_equal(&a.entry, &b.entry, observations))) {
        fprintf(stderr, "FAIL: hosts enumeration record or caller storage mismatch (files=%d)\n", files);
        return 1;
    }
    return 0;
}

static int hosts_enumeration_control(const struct hosts_enumeration_ops *host,
                                     const struct hosts_enumeration_ops *candidate,
                                     int files, int closing, int stayopen,
                                     struct hosts_enumeration_observations *observations) {
    const struct hosts_enumeration_ops *providers[] = {host, candidate};
    for (size_t index = 0; index < 2; ++index) {
        const struct hosts_enumeration_ops *ops = providers[index];
        errno = 780;
        int status = 1;
        if (files) status = closing ? ops->files_end() : ops->files_start(stayopen);
        else if (closing) ops->end();
        else ops->start(stayopen);
        if (status != 1 || (files && errno != 780)) {
            fprintf(stderr, "FAIL: hosts enumeration control files=%d closing=%d provider=%zu\n",
                    files, closing, index);
            return 1;
        }
    }
    ++observations->count;
    return 0;
}

static int test_hosts_enumeration_provider(const char *candidate_path,
                                          unsigned int expected_records) {
    void *host_handle = dlopen("libc.so.6", RTLD_NOW | RTLD_LOCAL);
    void *candidate_handle = dlopen(candidate_path, RTLD_NOW | RTLD_LOCAL);
    struct stat host_stat, candidate_stat;
    Dl_info host_info;
    if (!expected_records || expected_records > 4096 || !host_handle || !candidate_handle ||
        !dladdr(dlsym(host_handle, "getpid"), &host_info) ||
        stat(host_info.dli_fname, &host_stat) || stat(candidate_path, &candidate_stat) ||
        (host_stat.st_dev == candidate_stat.st_dev && host_stat.st_ino == candidate_stat.st_ino)) {
        fprintf(stderr, "FAIL: distinct hosts enumeration providers and fixture rows required\n");
        return 42;
    }
    struct hosts_enumeration_ops host, candidate;
    if (!hosts_enumeration_bind(host_handle, &host_stat, &host) ||
        !hosts_enumeration_bind(candidate_handle, &candidate_stat, &candidate) ||
        host.next == candidate.next || host.next_static == candidate.next_static ||
        host.files_next == candidate.files_next) return 42;
    struct hosts_enumeration_observations observations = {0, 0, 0};
    for (int files = 0; files < 2; ++files) {
        int success = files ? 1 : 0, exhausted = files ? 0 : ENOENT, retry = files ? -2 : ERANGE;
        for (size_t offset = 0; offset < 2; ++offset) {
            if (hosts_enumeration_control(&host, &candidate, files, 0, 0, &observations)) return 1;
            for (int attempt = 0; attempt < 2; ++attempt)
                if (hosts_enumeration_pair(&host, &candidate, files, 1, offset, retry, &observations)) return 1;
            for (unsigned int row = 0; row < expected_records; ++row)
                if (hosts_enumeration_pair(&host, &candidate, files, 65536, offset, success, &observations)) return 1;
            if (hosts_enumeration_pair(&host, &candidate, files, 65536, offset, exhausted, &observations) ||
                hosts_enumeration_pair(&host, &candidate, files, 1, offset, retry, &observations) ||
                hosts_enumeration_pair(&host, &candidate, files, 65536, offset, exhausted, &observations) ||
                hosts_enumeration_control(&host, &candidate, files, 0, 1, &observations) ||
                hosts_enumeration_pair(&host, &candidate, files, 65536, offset, success, &observations) ||
                hosts_enumeration_control(&host, &candidate, files, 1, 0, &observations) ||
                hosts_enumeration_pair(&host, &candidate, files, 65536, offset, success, &observations) ||
                hosts_enumeration_control(&host, &candidate, files, 1, 0, &observations)) return 1;
        }
        /* The final fixture row has a 4096-byte name and 80 aliases. Retry it
         * after a buffer that passes fixed-header validation but cannot hold the row. */
        if (hosts_enumeration_control(&host, &candidate, files, 0, 0, &observations)) return 1;
        for (unsigned int row = 1; row < expected_records; ++row)
            if (hosts_enumeration_pair(&host, &candidate, files, 65536, 1, success, &observations)) return 1;
        for (int attempt = 0; attempt < 2; ++attempt)
            if (hosts_enumeration_pair(&host, &candidate, files, 1024, 1, retry, &observations)) return 1;
        if (hosts_enumeration_pair(&host, &candidate, files, 65536, 1, success, &observations) ||
            hosts_enumeration_pair(&host, &candidate, files, 65536, 1, exhausted, &observations) ||
            hosts_enumeration_control(&host, &candidate, files, 1, 0, &observations)) return 1;
    }
    if (hosts_enumeration_control(&host, &candidate, 0, 0, 0, &observations)) return 1;
    for (unsigned int row = 0; row <= expected_records; ++row) {
        struct hostent *a = host.next_static(), *b = candidate.next_static();
        ++observations.count;
        if ((row == expected_records && (a || b)) ||
            (row != expected_records && !hosts_records_equal(a, b, &observations))) {
            fprintf(stderr, "FAIL: nonreentrant hosts enumeration row %u\n", row);
            return 1;
        }
    }
    if (hosts_enumeration_control(&host, &candidate, 0, 1, 0, &observations)) return 1;
    if (observations.max_aliases != 80 || observations.max_name != 4096) {
        fprintf(stderr, "FAIL: hosts enumeration long-record fixture absent or truncated\n");
        return 1;
    }
    printf("fixture_nss: hosts enumeration provider PASS (%u differential observations, "
           "%u records, %u aliases, %zu-byte name)\n", observations.count, expected_records,
           observations.max_aliases, observations.max_name);
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


/* gshadow contracts and live GNU comparisons. All database rows used by this
 * mode must come from a private /etc/gshadow mounted by the caller. */
struct gshadow_ops {
    struct sgrp *(*string)(const char *);
    int (*string_r)(const char *, struct sgrp *, char *, size_t, struct sgrp **);
    struct sgrp *(*name)(const char *);
    int (*name_r)(const char *, struct sgrp *, char *, size_t, struct sgrp **);
    struct sgrp *(*next)(void);
    int (*next_r)(struct sgrp *, char *, size_t, struct sgrp **);
    struct sgrp *(*stream)(FILE *);
    int (*stream_r)(FILE *, struct sgrp *, char *, size_t, struct sgrp **);
    void (*start)(void);
    void (*end)(void);
    int (*files_name)(const char *, struct sgrp *, char *, size_t, int *);
    int (*files_next)(struct sgrp *, char *, size_t, int *);
    int (*files_start)(int);
    int (*files_end)(void);
    FILE *(*memory)(void *, size_t, const char *);
    FILE *(*descriptor)(int, const char *);
    FILE *(*cookie)(void *, const char *, cookie_io_functions_t);
    int (*close)(FILE *);
    long (*tell)(FILE *);
    int (*eof)(FILE *);
    int (*error)(FILE *);
};

static int gshadow_bind(void *handle, const struct stat *expected,
                        struct gshadow_ops *ops) {
#define GSHADOW_BIND(member, symbol) do { \
    ops->member = (__typeof__(ops->member))identity_symbol(handle, symbol, expected); \
    if (!ops->member) return 0; \
} while (0)
    GSHADOW_BIND(string, "sgetsgent");
    GSHADOW_BIND(string_r, "sgetsgent_r");
    GSHADOW_BIND(name, "getsgnam");
    GSHADOW_BIND(name_r, "getsgnam_r");
    GSHADOW_BIND(next, "getsgent");
    GSHADOW_BIND(next_r, "getsgent_r");
    GSHADOW_BIND(stream, "fgetsgent");
    GSHADOW_BIND(stream_r, "fgetsgent_r");
    GSHADOW_BIND(start, "setsgent");
    GSHADOW_BIND(end, "endsgent");
    GSHADOW_BIND(files_name, "_nss_files_getsgnam_r");
    GSHADOW_BIND(files_next, "_nss_files_getsgent_r");
    GSHADOW_BIND(files_start, "_nss_files_setsgent");
    GSHADOW_BIND(files_end, "_nss_files_endsgent");
    GSHADOW_BIND(memory, "fmemopen");
    GSHADOW_BIND(descriptor, "fdopen");
    GSHADOW_BIND(cookie, "fopencookie");
    GSHADOW_BIND(close, "fclose");
    GSHADOW_BIND(tell, "ftell");
    GSHADOW_BIND(eof, "feof");
    GSHADOW_BIND(error, "ferror");
#undef GSHADOW_BIND
    return 1;
}

enum gshadow_call_kind {
    GSHADOW_STRING, GSHADOW_NAME, GSHADOW_NEXT, GSHADOW_STREAM,
    GSHADOW_FILES_NAME, GSHADOW_FILES_NEXT
};

struct gshadow_result {
    struct sgrp record;
    struct sgrp *result;
    _Alignas(void *) char buffer[65552];
    size_t offset, capacity;
    int rc, error, saved_errno;
};

static void gshadow_call(const struct gshadow_ops *ops, enum gshadow_call_kind kind,
                         const void *subject, size_t capacity, size_t offset,
                         struct gshadow_result *out) {
    memset(&out->record, 0, sizeof(out->record));
    memset(out->buffer, 0xa5, sizeof(out->buffer));
    out->result = (struct sgrp *)(uintptr_t)1;
    out->offset = offset;
    out->capacity = capacity;
    out->error = 731;
    errno = 733;
    char *buffer = out->buffer + offset;
    switch (kind) {
        case GSHADOW_STRING:
            out->rc = ops->string_r(subject, &out->record, buffer, capacity, &out->result);
            break;
        case GSHADOW_NAME:
            out->rc = ops->name_r(subject, &out->record, buffer, capacity, &out->result);
            break;
        case GSHADOW_NEXT:
            out->rc = ops->next_r(&out->record, buffer, capacity, &out->result);
            break;
        case GSHADOW_STREAM:
            out->rc = ops->stream_r((FILE *)subject, &out->record, buffer, capacity,
                                    &out->result);
            break;
        case GSHADOW_FILES_NAME:
            out->rc = ops->files_name(subject, &out->record, buffer, capacity, &out->error);
            out->result = out->rc == 1 ? &out->record : NULL;
            break;
        case GSHADOW_FILES_NEXT:
            out->rc = ops->files_next(&out->record, buffer, capacity, &out->error);
            out->result = out->rc == 1 ? &out->record : NULL;
            break;
        default:
            abort();
    }
    out->saved_errno = errno;
}

static int gshadow_string_inside(const char *text, uintptr_t begin, uintptr_t end) {
    if (!text) return 1;
    uintptr_t address = (uintptr_t)text;
    return address >= begin && address < end &&
        memchr(text, 0, (size_t)(end - address)) != NULL;
}

static int gshadow_list_inside(char *const *list, uintptr_t begin, uintptr_t end) {
    uintptr_t address = (uintptr_t)list;
    if (!list || address % _Alignof(char *) || address < begin || address > end)
        return 0;
    while (end - address >= sizeof(char *)) {
        char *text;
        memcpy(&text, (const void *)address, sizeof(text));
        if (!text) return 1;
        if (!gshadow_string_inside(text, begin, end)) return 0;
        address += sizeof(char *);
    }
    return 0;
}

static int gshadow_output_valid(const struct gshadow_result *out) {
    for (size_t i = 0; i < sizeof(out->buffer); ++i) {
        if ((i < out->offset || i >= out->offset + out->capacity) &&
            (unsigned char)out->buffer[i] != 0xa5)
            return 0;
    }
    if (!out->result) return 1;
    if (out->result == (struct sgrp *)(uintptr_t)1) return out->rc != 0;
    if (out->result != &out->record) return 0;
    uintptr_t begin = (uintptr_t)(out->buffer + out->offset);
    uintptr_t end = begin + out->capacity;
    return gshadow_string_inside(out->record.sg_namp, begin, end) &&
        gshadow_string_inside(out->record.sg_passwd, begin, end) &&
        gshadow_list_inside(out->record.sg_adm, begin, end) &&
        gshadow_list_inside(out->record.sg_mem, begin, end);
}

static int gshadow_list_equal(char *const *a, char *const *b) {
    if (!a || !b) return a == b;
    for (size_t i = 0; i < 4096; ++i) {
        if (!identity_string_equal(a[i], b[i])) return 0;
        if (!a[i]) return 1;
    }
    return 0;
}

static int gshadow_record_equal(const struct sgrp *a, const struct sgrp *b) {
    if (!a || !b) return a == b;
    return identity_string_equal(a->sg_namp, b->sg_namp) &&
        identity_string_equal(a->sg_passwd, b->sg_passwd) &&
        gshadow_list_equal(a->sg_adm, b->sg_adm) &&
        gshadow_list_equal(a->sg_mem, b->sg_mem);
}

static int gshadow_pair(const struct gshadow_ops *host, const struct gshadow_ops *candidate,
                         enum gshadow_call_kind kind, const void *host_subject,
                         const void *candidate_subject, size_t capacity, size_t offset,
                         struct gshadow_result *a, struct gshadow_result *b,
                         unsigned int *observations) {
    gshadow_call(host, kind, host_subject, capacity, offset, a);
    gshadow_call(candidate, kind, candidate_subject, capacity, offset, b);
    ++*observations;
    if (!gshadow_output_valid(a) || !gshadow_output_valid(b) ||
        a->rc != b->rc || a->error != b->error || a->saved_errno != b->saved_errno ||
        (a->result == (struct sgrp *)(uintptr_t)1) !=
            (b->result == (struct sgrp *)(uintptr_t)1) ||
        ((a->result != (struct sgrp *)(uintptr_t)1) &&
            !gshadow_record_equal(a->result, b->result))) {
        fprintf(stderr, "FAIL: gshadow kind=%d capacity=%zu offset=%zu "
                "host=(%d,%d,%d) candidate=(%d,%d,%d)\n",
                kind, capacity, offset, a->rc, a->error, a->saved_errno,
                b->rc, b->error, b->saved_errno);
        return 0;
    }
    return 1;
}

static int gshadow_static_pair(const struct gshadow_ops *host,
                               const struct gshadow_ops *candidate, int kind,
                               const void *a_subject, const void *b_subject,
                               unsigned int *observations) {
    errno = 739;
    struct sgrp *a = kind == 0 ? host->string(a_subject) :
        kind == 1 ? host->name(a_subject) :
        kind == 2 ? host->next() : host->stream((FILE *)a_subject);
    int a_errno = errno;
    errno = 739;
    struct sgrp *b = kind == 0 ? candidate->string(b_subject) :
        kind == 1 ? candidate->name(b_subject) :
        kind == 2 ? candidate->next() : candidate->stream((FILE *)b_subject);
    int b_errno = errno;
    ++*observations;
    /* errno after a successful nonreentrant lookup can reflect internal
     * buffer growth. Compare it when reporting failure, where it is useful. */
    if (((!a || !b) && a_errno != b_errno) || !gshadow_record_equal(a, b)) {
        fprintf(stderr, "FAIL: gshadow static kind=%d host_errno=%d candidate_errno=%d\n",
                kind, a_errno, b_errno);
        return -1;
    }
    return a != NULL;
}

static char *gshadow_long_line(void) {
    char *line = malloc(32768);
    if (!line) return NULL;
    size_t used = (size_t)snprintf(line, 32768, "frankenlibc-gshadow-long:!:");
    for (int field = 0; field < 2; ++field) {
        for (unsigned int i = 0; i < 80; ++i) {
            int written = snprintf(line + used, 32768 - used,
                "%s%s-%03u-abcdefghijklmnopqrstuvwxyz",
                i ? "," : "", field ? "member" : "administrator", i);
            if (written < 0 || (size_t)written >= 32768 - used) {
                free(line);
                return NULL;
            }
            used += (size_t)written;
        }
        line[used++] = field ? '\n' : ':';
        line[used] = 0;
    }
    return line;
}

static int gshadow_full_record(const struct sgrp *record, const char *name,
                              size_t admins, size_t members) {
    if (!record || !record->sg_namp || strcmp(record->sg_namp, name) ||
        !record->sg_passwd || strcmp(record->sg_passwd, "!") ||
        !record->sg_adm || !record->sg_mem)
        return 0;
    for (size_t i = 0; i < admins; ++i) if (!record->sg_adm[i]) return 0;
    for (size_t i = 0; i < members; ++i) if (!record->sg_mem[i]) return 0;
    return !record->sg_adm[admins] && !record->sg_mem[members];
}

/* This mode is an independent positive control. It accepts one explicitly
 * identified provider, including GNU libc, and never claims a differential. */
static int test_gshadow_contract_provider(const char *path) {
    void *handle = dlopen(path, RTLD_NOW | RTLD_LOCAL);
    struct stat expected;
    struct gshadow_ops ops;
    if (!handle || stat(path, &expected) || !gshadow_bind(handle, &expected, &ops))
        return 42;
    const char *line = "frankenlibc-gshadow-first:!:alice,bob:carol,dave\n";
    struct gshadow_result result;
    unsigned int observations = 0;
    for (size_t offset = 0; offset < _Alignof(char *); ++offset) {
        gshadow_call(&ops, GSHADOW_STRING, line, 65536, offset, &result);
        if (result.rc || !gshadow_output_valid(&result) ||
            !gshadow_full_record(result.result, "frankenlibc-gshadow-first", 2, 2)) {
            fprintf(stderr, "FAIL: gshadow caller-result contract offset=%zu rc=%d identity=%d\n",
                    offset, result.rc, result.result == &result.record);
            return 1;
        }
        ++observations;
    }
    gshadow_call(&ops, GSHADOW_STRING, line, 1, 1, &result);
    if (result.rc != ERANGE || result.result != (struct sgrp *)(uintptr_t)1 ||
        !gshadow_output_valid(&result)) return 1;
    ++observations;
    char *long_line = gshadow_long_line();
    if (!long_line || strlen(long_line) <= 4096) return 1;
    gshadow_call(&ops, GSHADOW_STRING, long_line, 65536, 1, &result);
    if (result.rc || !gshadow_output_valid(&result) ||
        !gshadow_full_record(result.result, "frankenlibc-gshadow-long", 80, 80) ||
        !gshadow_full_record(ops.string(long_line), "frankenlibc-gshadow-long", 80, 80))
        return 1;
    observations += 2;
    for (int reentrant = 0; reentrant < 2; ++reentrant) {
        FILE *stream = ops.memory(long_line, strlen(long_line), "r");
        if (!stream) return 1;
        struct sgrp *record;
        if (reentrant) {
            gshadow_call(&ops, GSHADOW_STREAM, stream, 65536, 1, &result);
            if (result.rc || !gshadow_output_valid(&result)) return 1;
            record = result.result;
        } else {
            record = ops.stream(stream);
        }
        if (!gshadow_full_record(record, "frankenlibc-gshadow-long", 80, 80)) return 1;
        if (ops.close(stream)) return 1;
        ++observations;
    }
    free(long_line);
    dlclose(handle);
    printf("fixture_nss: gshadow contract PASS (%u independent observations)\n", observations);
    return 0;
}

static int gshadow_memory_comparison(const struct gshadow_ops *host,
                                     const struct gshadow_ops *candidate,
                                     const struct gshadow_ops *constructor,
                                     const char *content, unsigned int rows,
                                     int reentrant, int retry,
                                     unsigned int *observations) {
    FILE *a_stream = host->memory((void *)content, strlen(content), "r");
    FILE *b_stream = constructor->memory((void *)content, strlen(content), "r");
    if (!a_stream || !b_stream) return 0;
    struct gshadow_result a, b;
    if (retry) {
        if (!gshadow_pair(host, candidate, GSHADOW_STREAM, a_stream, b_stream,
                          16, 1, &a, &b, observations) || a.rc != ERANGE ||
            host->tell(a_stream) != constructor->tell(b_stream))
            return 0;
    }
    unsigned int read_rows = 0;
    for (; read_rows <= rows; ++read_rows) {
        int present;
        if (reentrant) {
            if (!gshadow_pair(host, candidate, GSHADOW_STREAM, a_stream, b_stream,
                              65536, read_rows % _Alignof(char *), &a, &b, observations))
                return 0;
            present = a.result != NULL;
        } else {
            present = gshadow_static_pair(host, candidate, 3, a_stream, b_stream, observations);
            if (present < 0) return 0;
        }
        if (host->tell(a_stream) != constructor->tell(b_stream) ||
            !!host->eof(a_stream) != !!constructor->eof(b_stream) ||
            !!host->error(a_stream) != !!constructor->error(b_stream))
            return 0;
        if (!present) break;
    }
    int close_a = host->close(a_stream);
    int close_b = constructor->close(b_stream);
    return read_rows == rows && !close_a && !close_b;
}

static ssize_t gshadow_error_read(void *cookie, char *buffer, size_t length) {
    (void)buffer;
    (void)length;
    ++*(unsigned int *)cookie;
    errno = EIO;
    return -1;
}


struct gshadow_partial_input {
    const char *text;
    size_t offset;
    unsigned int reads;
};

static ssize_t gshadow_partial_read(void *cookie, char *buffer, size_t length) {
    struct gshadow_partial_input *input = cookie;
    ++input->reads;
    size_t remaining = strlen(input->text) - input->offset;
    if (!remaining) {
        errno = EIO;
        return -1;
    }
    if (length > remaining) length = remaining;
    memcpy(buffer, input->text + input->offset, length);
    input->offset += length;
    return (ssize_t)length;
}

static int gshadow_pipe_and_error_comparison(const struct gshadow_ops *host,
                                             const struct gshadow_ops *candidate,
                                             const struct gshadow_ops *constructor,
                                             unsigned int *observations) {
    const char content[] = "team:!:a,b:m,n\nlast:*::m\n";
    for (int reentrant = 0; reentrant < 2; ++reentrant) {
        int a_pipe[2], b_pipe[2];
        if (pipe(a_pipe) || pipe(b_pipe) ||
            write(a_pipe[1], content, sizeof(content) - 1) != (ssize_t)sizeof(content) - 1 ||
            write(b_pipe[1], content, sizeof(content) - 1) != (ssize_t)sizeof(content) - 1 ||
            close(a_pipe[1]) || close(b_pipe[1]))
            return 0;
        FILE *a_stream = host->descriptor(a_pipe[0], "r");
        FILE *b_stream = constructor->descriptor(b_pipe[0], "r");
        if (!a_stream || !b_stream) return 0;
        struct gshadow_result a, b;
        for (int call = 0; call < (reentrant ? 3 : 2); ++call) {
            if (reentrant) {
                if (!gshadow_pair(host, candidate, GSHADOW_STREAM, a_stream, b_stream,
                                  65536, 1, &a, &b, observations))
                    return 0;
                if ((call < 2) != (a.result != NULL)) return 0;
            } else if (gshadow_static_pair(host, candidate, 3, a_stream, b_stream,
                                           observations) != 0) {
                return 0;
            }
            if (!!host->eof(a_stream) != !!constructor->eof(b_stream) ||
                !!host->error(a_stream) != !!constructor->error(b_stream))
                return 0;
        }
        if (host->close(a_stream) || constructor->close(b_stream)) return 0;
    }

    unsigned int a_reads = 0, b_reads = 0;
    cookie_io_functions_t functions = {.read = gshadow_error_read};
    FILE *a_stream = host->cookie(&a_reads, "r", functions);
    FILE *b_stream = constructor->cookie(&b_reads, "r", functions);
    if (!a_stream || !b_stream) return 0;
    struct gshadow_result a, b;
    if (!gshadow_pair(host, candidate, GSHADOW_STREAM, a_stream, b_stream,
                      65536, 1, &a, &b, observations) ||
        a.result || !a_reads || !b_reads ||
        !!host->error(a_stream) != !!constructor->error(b_stream))
        return 0;
    if (host->close(a_stream) || constructor->close(b_stream)) return 0;

    /* getdelim can report positive bytes and ferror together. Such a partial
     * physical record is an error, while a complete newline-terminated record
     * must succeed before a later callback failure has been observed. */
    for (int newline = 0; newline < 2; ++newline) {
        const char *text = newline ? "team:!:a:m\n" : "team:!:a:m";
        struct gshadow_partial_input a_input = {.text = text};
        struct gshadow_partial_input b_input = {.text = text};
        functions.read = gshadow_partial_read;
        a_stream = host->cookie(&a_input, "r", functions);
        b_stream = constructor->cookie(&b_input, "r", functions);
        if (!a_stream || !b_stream) return 0;
        if (!gshadow_pair(host, candidate, GSHADOW_STREAM, a_stream, b_stream,
                          65536, 1, &a, &b, observations) ||
            (newline ? (a.rc != 0 || !a.result) : (a.rc != EIO || a.result)) ||
            !a_input.reads || !b_input.reads ||
            !!host->error(a_stream) != !newline ||
            !!host->error(a_stream) != !!constructor->error(b_stream))
            return 0;
        if (host->close(a_stream) || constructor->close(b_stream)) return 0;
    }
    return 1;
}

static int test_gshadow_provider(const char *candidate_path, unsigned int expected_rows) {
    void *host_handle = dlopen("libc.so.6", RTLD_NOW | RTLD_LOCAL);
    void *candidate_handle = dlopen(candidate_path, RTLD_NOW | RTLD_LOCAL);
    struct stat host_stat, candidate_stat;
    Dl_info host_info;
    struct gshadow_ops host, candidate;
    if (!expected_rows || !host_handle || !candidate_handle ||
        !dladdr(dlsym(host_handle, "getpid"), &host_info) ||
        stat(host_info.dli_fname, &host_stat) || stat(candidate_path, &candidate_stat) ||
        (host_stat.st_dev == candidate_stat.st_dev && host_stat.st_ino == candidate_stat.st_ino) ||
        !gshadow_bind(host_handle, &host_stat, &host) ||
        !gshadow_bind(candidate_handle, &candidate_stat, &candidate) ||
        host.string_r == candidate.string_r || host.stream_r == candidate.stream_r ||
        host.name_r == candidate.name_r || host.files_next == candidate.files_next) {
        fprintf(stderr, "FAIL: distinct gshadow providers required\n");
        return 42;
    }
    unsigned int observations = 0;
    struct gshadow_result a, b;
    const char *strings[] = {
        "frankenlibc-gshadow-first:!:alice,bob:carol,dave\n",
        "empty:::", "", "only-name", "# string comment", ":!:admin:member",
        "  spaced:!:alice,bob:carol,dave", "commas:!:,alice,,bob,:carol,,dave,",
        "tail:!:alice:carol:extra"
    };
    for (size_t line = 0; line < sizeof(strings) / sizeof(strings[0]); ++line) {
        for (size_t offset = 0; offset < _Alignof(char *); ++offset) {
            if (!gshadow_pair(&host, &candidate, GSHADOW_STRING, strings[line], strings[line],
                              65536, offset, &a, &b, &observations))
                return 1;
        }
        if (gshadow_static_pair(&host, &candidate, 0, strings[line], strings[line],
                                 &observations) != 1)
            return 1;
    }
    /* A whole line that does not fit differs from a line whose pointer arrays
     * do not fit. Compare both, including the result-slot sentinel. */
    const size_t capacities[] = {1, 8, 16, 32, 64, 71, 72, 79, 80};
    for (size_t offset = 0; offset < _Alignof(char *); ++offset) {
        for (size_t i = 0; i < sizeof(capacities) / sizeof(capacities[0]); ++i) {
            if (!gshadow_pair(&host, &candidate, GSHADOW_STRING,
                              "team:!:a,b:m,n", "team:!:a,b:m,n",
                              capacities[i], offset, &a, &b, &observations))
                return 1;
        }
    }
    char *long_line = gshadow_long_line();
    if (!long_line || strlen(long_line) <= 4096 ||
        !gshadow_pair(&host, &candidate, GSHADOW_STRING, long_line, long_line,
                      65536, 1, &a, &b, &observations) ||
        !gshadow_full_record(a.result, "frankenlibc-gshadow-long", 80, 80) ||
        gshadow_static_pair(&host, &candidate, 0, long_line, long_line, &observations) != 1)
        return 1;

    size_t stream_size = strlen(long_line) + 256;
    char *content = malloc(stream_size);
    if (!content) return 1;
    int written = snprintf(content, stream_size, "%s\n# skipped file comment\n"
        "  frankenlibc-gshadow-first:!:alice,bob:carol,dave\n"
        "frankenlibc-gshadow-last:!::last-member\n", long_line);
    if (written < 0 || (size_t)written >= stream_size) return 1;
    for (int native_file = 0; native_file < 2; ++native_file) {
        const struct gshadow_ops *constructor = native_file ? &candidate : &host;
        for (int reentrant = 0; reentrant < 2; ++reentrant) {
            if (!gshadow_memory_comparison(&host, &candidate, constructor, content,
                                           3, reentrant, reentrant, &observations))
                return 1;
        }
        if (!gshadow_pipe_and_error_comparison(&host, &candidate, constructor, &observations))
            return 1;
    }
    free(content);
    free(long_line);

    /* The required marker prevents accidentally enumerating a system password
     * database when the caller forgot to mount the private fixtures. */
    const char *names[] = {"frankenlibc-gshadow-first", "frankenlibc-gshadow-long",
                           "frankenlibc-gshadow-deliberately-absent"};
    if (!gshadow_pair(&host, &candidate, GSHADOW_NAME, names[0], names[0],
                      65536, 1, &a, &b, &observations) || !a.result)
        return 1;
    for (size_t name = 0; name < sizeof(names) / sizeof(names[0]); ++name) {
        for (int files = 0; files < 2; ++files) {
            enum gshadow_call_kind kind = files ? GSHADOW_FILES_NAME : GSHADOW_NAME;
            for (int small = 0; small < 2; ++small) {
                if (!gshadow_pair(&host, &candidate, kind, names[name], names[name],
                                  small ? 16 : 65536, 1, &a, &b, &observations))
                    return 1;
            }
        }
        if (gshadow_static_pair(&host, &candidate, 1, names[name], names[name],
                                 &observations) != (name != 2))
            return 1;
    }

    for (int files = 0; files < 2; ++files) {
        if (files) {
            if (host.files_start(0) != 1 || candidate.files_start(0) != 1) return 1;
        } else {
            host.start();
            candidate.start();
        }
        enum gshadow_call_kind kind = files ? GSHADOW_FILES_NEXT : GSHADOW_NEXT;
        if (!gshadow_pair(&host, &candidate, kind, NULL, NULL,
                          16, 1, &a, &b, &observations) || a.result)
            return 1;
        unsigned int rows = 0;
        int saw_long = 0;
        for (; rows <= expected_rows; ++rows) {
            if (!gshadow_pair(&host, &candidate, kind, NULL, NULL, 65536,
                              rows % _Alignof(char *), &a, &b, &observations))
                return 1;
            if (!a.result) break;
            if (gshadow_full_record(a.result, "frankenlibc-gshadow-long", 80, 80))
                saw_long = 1;
        }
        if (rows != expected_rows || !saw_long) return 1;
        if (files) {
            if (host.files_end() != 1 || candidate.files_end() != 1) return 1;
        } else {
            host.end();
            candidate.end();
        }
        /* Closing the enumeration must allow the next call to reopen at row1. */
        if (!gshadow_pair(&host, &candidate, kind, NULL, NULL,
                          65536, 1, &a, &b, &observations) || !a.result ||
            !a.result->sg_namp || strcmp(a.result->sg_namp, names[0]))
            return 1;
    }
    host.start();
    candidate.start();
    unsigned int rows = 0;
    for (; rows <= expected_rows; ++rows) {
        int present = gshadow_static_pair(&host, &candidate, 2, NULL, NULL, &observations);
        if (present < 0) return 1;
        if (!present) break;
    }
    if (rows != expected_rows) return 1;
    host.end();
    candidate.end();
    dlclose(candidate_handle);
    dlclose(host_handle);
    printf("fixture_nss: gshadow provider PASS (%u differential observations, %u database rows)\n",
           observations, expected_rows);
    return 0;
}

/* RPC database contracts. Run this same identity-checked provider probe once
 * against GNU libc and once against the candidate, inside a private /etc. */
struct rpc_database_ops {
    int (*name)(const char *, struct rpcent *, char *, size_t, struct rpcent **);
    int (*number)(int, struct rpcent *, char *, size_t, struct rpcent **);
    int (*next)(struct rpcent *, char *, size_t, struct rpcent **);
    struct rpcent *(*name_static)(const char *);
    struct rpcent *(*number_static)(int);
    struct rpcent *(*next_static)(void);
    void (*start)(int);
    void (*end)(void);
    identity_name_fn files_name;
    int (*files_number)(int, void *, char *, size_t, int *);
    identity_next_fn files_next;
    identity_start_fn files_start;
    identity_end_fn files_end;
};

static int rpc_database_bind(void *handle, const struct stat *expected,
                              struct rpc_database_ops *ops) {
#define RPC_BIND(member, symbol) do { \
    ops->member = (__typeof__(ops->member))identity_symbol(handle, symbol, expected); \
    if (!ops->member) return 0; \
} while (0)
    RPC_BIND(name, "getrpcbyname_r");
    RPC_BIND(number, "getrpcbynumber_r");
    RPC_BIND(next, "getrpcent_r");
    RPC_BIND(name_static, "getrpcbyname");
    RPC_BIND(number_static, "getrpcbynumber");
    RPC_BIND(next_static, "getrpcent");
    RPC_BIND(start, "setrpcent");
    RPC_BIND(end, "endrpcent");
    RPC_BIND(files_name, "_nss_files_getrpcbyname_r");
    RPC_BIND(files_number, "_nss_files_getrpcbynumber_r");
    RPC_BIND(files_next, "_nss_files_getrpcent_r");
    RPC_BIND(files_start, "_nss_files_setrpcent");
    RPC_BIND(files_end, "_nss_files_endrpcent");
#undef RPC_BIND
    return 1;
}

struct rpc_database_result {
    struct rpcent record;
    struct rpcent *result;
    char buffer[65538];
    int rc, error, saved_errno;
};

static void rpc_database_call(const struct rpc_database_ops *ops, int kind,
                              const char *name, int number, size_t capacity,
                              struct rpc_database_result *out) {
    memset(out, 0, sizeof(*out));
    memset(out->buffer, 0xa5, sizeof(out->buffer));
    out->error = 99;
    errno = 77;
    char *buffer = out->buffer + 1; /* exercise an unaligned caller buffer */
    switch (kind) {
        case 0: out->rc = ops->next(&out->record, buffer, capacity, &out->result); break;
        case 1: out->rc = ops->files_next(&out->record, buffer, capacity, &out->error); break;
        case 2: out->rc = ops->name(name, &out->record, buffer, capacity, &out->result); break;
        case 3: out->rc = ops->files_name(name, &out->record, buffer, capacity, &out->error); break;
        case 4: out->rc = ops->number(number, &out->record, buffer, capacity, &out->result); break;
        case 5: out->rc = ops->files_number(number, &out->record, buffer, capacity, &out->error); break;
        default: abort();
    }
    out->saved_errno = errno;
    if (kind & 1) out->result = out->rc == 1 ? &out->record : NULL;
}

static int rpc_database_owned(const struct rpc_database_result *out, size_t capacity) {
    for (size_t i = 0; i < sizeof(out->buffer); ++i)
        if ((i == 0 || i >= capacity + 1) && (unsigned char)out->buffer[i] != 0xa5)
            return 0;
    if (!out->result) return 1;
    uintptr_t begin = (uintptr_t)(out->buffer + 1), end = begin + capacity;
    return out->result == &out->record && out->record.r_name &&
        gshadow_string_inside(out->record.r_name, begin, end) &&
        gshadow_list_inside(out->record.r_aliases, begin, end);
}

static int rpc_database_record(const struct rpcent *entry, int row) {
    if (!entry || !entry->r_name || !entry->r_aliases ||
        entry->r_number != 700001 + row) return 0;
    if (row == 0) {
        return identity_string_equal(entry->r_name, "frankenlibc-rpc-first") &&
            identity_string_equal(entry->r_aliases[0], "FirstAlias") &&
            identity_string_equal(entry->r_aliases[1], "first-alt") &&
            entry->r_aliases[2] == NULL;
    }
    if (row == 2) {
        return identity_string_equal(entry->r_name, "frankenlibc-rpc-last") &&
            identity_string_equal(entry->r_aliases[0], "LastAlias") &&
            entry->r_aliases[1] == NULL;
    }
    const char *prefix = "frankenlibc-rpc-long-";
    size_t prefix_len = strlen(prefix);
    if (strlen(entry->r_name) != 4096 || strncmp(entry->r_name, prefix, prefix_len))
        return 0;
    for (size_t i = prefix_len; i < 4096; ++i)
        if (entry->r_name[i] != 'q') return 0;
    for (unsigned int i = 0; i < 96; ++i) {
        char expected[80];
        snprintf(expected, sizeof(expected), "Alias%03u-xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx", i);
        if (!identity_string_equal(entry->r_aliases[i], expected)) return 0;
    }
    return entry->r_aliases[96] == NULL;
}

static int rpc_database_expect(const struct rpc_database_ops *ops, int kind,
                               const char *name, int number, size_t capacity,
                               int rc, int error, int saved_errno, int row,
                               unsigned int *observations) {
    struct rpc_database_result out;
    rpc_database_call(ops, kind, name, number, capacity, &out);
    ++*observations;
    if (out.rc != rc || out.error != error || out.saved_errno != saved_errno ||
        !rpc_database_owned(&out, capacity) ||
        (row < 0 ? out.result != NULL : !rpc_database_record(out.result, row))) {
        fprintf(stderr, "FAIL: RPC kind=%d capacity=%zu row=%d "
                "expected=(%d,%d,%d) actual=(%d,%d,%d)\n",
                kind, capacity, row, rc, error, saved_errno,
                out.rc, out.error, out.saved_errno);
        return 0;
    }
    return 1;
}

static int test_rpc_database_provider(const char *path, const char *source_kind) {
    void *handle = dlopen(path, RTLD_NOW | RTLD_LOCAL);
    struct stat expected;
    struct rpc_database_ops ops;
    if (!handle || stat(path, &expected) || !rpc_database_bind(handle, &expected, &ops))
        return 42;
    unsigned int observations = 0;
    if (!strcmp(source_kind, "missing") || !strcmp(source_kind, "directory")) {
        int missing = !strcmp(source_kind, "missing");
        int error = missing ? ENOENT : EISDIR;
        errno = 77;
        int status = ops.files_start(0);
        if (status != (missing ? -1 : 1) || errno != (missing ? ENOENT : 77))
            return 1;
        for (int kind = 0; kind < 6; ++kind) {
            int rc = kind == 0 ? ENOENT : (kind & 1) ? -1 : error;
            int expected_error = (kind & 1) && !missing ? error : 99;
            int expected_errno = kind <= 1 && missing ? 77 : error;
            if (!rpc_database_expect(&ops, kind, "frankenlibc-rpc-first", 700001,
                    65536, rc, expected_error, expected_errno, -1, &observations))
                return 1;
        }
    } else if (!strcmp(source_kind, "records")) {
        for (int files = 0; files < 2; ++files) {
            if (files) {
                if (ops.files_start(1) != 1) return 1;
            } else ops.start(1);
            int success = files ? 1 : 0, retry = files ? -2 : ERANGE;
            if (!rpc_database_expect(&ops, files, NULL, 0, 1,
                    retry, files ? ERANGE : 99, files ? 77 : ERANGE, -1, &observations))
                return 1;
            if (!rpc_database_expect(&ops, files, NULL, 0, 65536,
                    success, 99, 77, 0, &observations))
                return 1;
            for (int attempt = 0; attempt < 2; ++attempt)
                if (!rpc_database_expect(&ops, files, NULL, 0, 1024,
                        retry, files ? ERANGE : 99, ERANGE, -1, &observations))
                    return 1;
            for (int row = 1; row <= 2; ++row)
                if (!rpc_database_expect(&ops, files, NULL, 0, 65536,
                        success, 99, 77, row, &observations))
                    return 1;
            if (!rpc_database_expect(&ops, files, NULL, 0, 65536,
                    files ? 0 : ENOENT, 99, 77, -1, &observations))
                return 1;
            if (!rpc_database_expect(&ops, files, NULL, 0, 1,
                    retry, files ? ERANGE : 99, files ? 77 : ERANGE, -1, &observations))
                return 1;
            if (files) {
                if (ops.files_end() != 1) return 1;
            } else ops.end();
            if (!rpc_database_expect(&ops, files, NULL, 0, 65536,
                    success, 99, 77, 0, &observations))
                return 1;
        }

        const char *alias = "Alias095-xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx";
        for (int files = 0; files < 2; ++files) {
            int success = files ? 1 : 0, normal_errno = files ? 77 : 0;
            if (!rpc_database_expect(&ops, 2 + files, alias, 0, 65536,
                    success, 99, normal_errno, 1, &observations) ||
                !rpc_database_expect(&ops, 4 + files, NULL, 700002, 65536,
                    success, 99, normal_errno, 1, &observations) ||
                !rpc_database_expect(&ops, 2 + files, "FRANKENLIBC-RPC-FIRST", 0, 65536,
                    0, 99, normal_errno, -1, &observations) ||
                !rpc_database_expect(&ops, 2 + files, "firstalias", 0, 65536,
                    0, 99, normal_errno, -1, &observations) ||
                !rpc_database_expect(&ops, 4 + files, NULL, 799999, 65536,
                    0, 99, normal_errno, -1, &observations))
                return 1;
        }
        if (!rpc_database_record(ops.name_static(alias), 1) ||
            !rpc_database_record(ops.number_static(700002), 1)) return 1;
        observations += 2;
        ops.start(0);
        for (int row = 0; row <= 2; ++row) {
            if (!rpc_database_record(ops.next_static(), row)) return 1;
            ++observations;
        }
        if (ops.next_static()) return 1;
        ++observations;
    } else {
        return 2;
    }
    ops.end();
    if (ops.files_end() != 1) return 1;
    printf("fixture_nss: RPC provider PASS (%u contract observations, %s)\n",
           observations, source_kind);
    dlclose(handle);
    return 0;
}


int main(int argc, char **argv) {
    if (argc == 4 && strcmp(argv[1], "--rpc-provider") == 0)
        return test_rpc_database_provider(argv[2], argv[3]);

    if (argc == 3 && strcmp(argv[1], "--gshadow-contract-provider") == 0)
        return test_gshadow_contract_provider(argv[2]);
    if (argc == 4 && strcmp(argv[1], "--gshadow-provider") == 0)
        return test_gshadow_provider(argv[2], (unsigned int)strtoul(argv[3], NULL, 10));

    if (argc == 4 && strcmp(argv[1], "--password-lock-provider") == 0)
        return test_password_lock_provider(argv[2], argv[3], 0);
    if (argc == 4 && strcmp(argv[1], "--password-lock-fork-provider") == 0)
        return test_password_lock_provider(argv[2], argv[3], 1);
    if (argc == 3 && strcmp(argv[1], "--files-provider") == 0)
        return test_files_provider(argv[2]);
    if (argc == 5 && strcmp(argv[1], "--hosts-provider") == 0)
        return test_hosts_provider(argv[2], argv[3], (unsigned int)strtoul(argv[4], NULL, 10));
    if (argc == 4 && strcmp(argv[1], "--hosts-enumeration-provider") == 0)
        return test_hosts_enumeration_provider(argv[2], (unsigned int)strtoul(argv[3], NULL, 10));
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
