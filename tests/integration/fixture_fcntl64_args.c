// fcntl's optional third argument through fcntl64 -- what every program built
// with _FILE_OFFSET_BITS=64 calls (the smoke battery compiles this one so).
//
// fl's fcntl64 read that argument from the va_list STRUCTURE instead of the
// argument list, so every command that takes one got 0x3000000010: F_SETLK
// failed with EFAULT (sqlite3 on any on-disk database: "disk I/O error"),
// F_SETFL/F_SETFD set garbage, F_DUPFD returned the wrong descriptor.
#define _GNU_SOURCE
#define _FILE_OFFSET_BITS 64
#include <dlfcn.h>
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <locale.h>
#include <stdint.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/sysmacros.h>
#include <sys/wait.h>
#include <unistd.h>

/* One protocol is compiled into both the native plugin and the deployed C
   executable. The caller supplies an independent live GNU/kernel oracle. */
extern int narrow_stat(const char *, struct stat *) __asm__("stat");
extern int narrow_fstat(int, struct stat *) __asm__("fstat");
extern int narrow_lstat(const char *, struct stat *) __asm__("lstat");
extern int narrow_fstatat(int, const char *, struct stat *, int) __asm__("fstatat");
_Static_assert(sizeof(struct stat) == sizeof(struct stat64), "ELF64 stat layout");

void *flc_metadata_function(unsigned index) {
    switch (index) {
        case 0: return (void *)narrow_stat;
        case 1: return (void *)narrow_fstat;
        case 2: return (void *)narrow_lstat;
        case 3: return (void *)narrow_fstatat;
        case 4: return (void *)stat64;
        case 5: return (void *)fstat64;
        case 6: return (void *)lstat64;
        case 7: return (void *)fstatat64;
        case 8: return (void *)statx;
        default: return NULL;
    }
}

static int metadata_call(unsigned index, int directory, int fd,
                         const char *path, struct stat *out, int flags) {
    if (index < 4) {
        switch (index) {
            case 0: return narrow_stat(path, out);
            case 1: return narrow_fstat(fd, out);
            case 2: return narrow_lstat(path, out);
            default: return narrow_fstatat(directory, path, out, flags);
        }
    }
    struct stat64 large;
    memcpy(&large, out, sizeof large);
    int result;
    switch (index) {
        case 4: result = stat64(path, &large); break;
        case 5: result = fstat64(fd, &large); break;
        case 6: result = lstat64(path, &large); break;
        default: result = fstatat64(directory, path, &large, flags); break;
    }
    memcpy(out, &large, sizeof *out);
    return result;
}

static int metadata_equal(const struct stat *a, const struct stat *b) {
    return a->st_dev == b->st_dev && a->st_ino == b->st_ino &&
        a->st_mode == b->st_mode && a->st_nlink == b->st_nlink &&
        a->st_uid == b->st_uid && a->st_gid == b->st_gid &&
        a->st_rdev == b->st_rdev && a->st_size == b->st_size &&
        a->st_blksize == b->st_blksize && a->st_blocks == b->st_blocks &&
        a->st_atim.tv_sec == b->st_atim.tv_sec && a->st_atim.tv_nsec == b->st_atim.tv_nsec &&
        a->st_mtim.tv_sec == b->st_mtim.tv_sec && a->st_mtim.tv_nsec == b->st_mtim.tv_nsec &&
        a->st_ctim.tv_sec == b->st_ctim.tv_sec && a->st_ctim.tv_nsec == b->st_ctim.tv_nsec;
}

typedef int (*metadata_reference)(int, const char *, struct stat *, int);

/* Keep both real ELF64 names despite large-file redirection. The explicit
   declarations also let this conformance probe call the obsolete _r ABI. */
extern struct dirent *directory_readdir(DIR *) __asm__("readdir");
extern int directory_readdir_r(DIR *, struct dirent *, struct dirent **) __asm__("readdir_r");
extern int directory_readdir64_r(DIR *, struct dirent64 *, struct dirent64 **) __asm__("readdir64_r");
_Static_assert(sizeof(struct dirent) == sizeof(struct dirent64), "ELF64 dirent layout");

void *flc_directory_function(unsigned index) {
    switch (index) {
        case 0: return (void *)opendir;
        case 1: return (void *)fdopendir;
        case 2: return (void *)directory_readdir;
        case 3: return (void *)readdir64;
        case 4: return (void *)directory_readdir_r;
        case 5: return (void *)directory_readdir64_r;
        case 6: return (void *)closedir;
        case 7: return (void *)dirfd;
        case 8: return (void *)rewinddir;
        case 9: return (void *)telldir;
        case 10: return (void *)seekdir;
        default: return NULL;
    }
}

struct directory_api {
    DIR *(*open)(const char *);
    DIR *(*fdopen)(int);
    struct dirent *(*read)(DIR *);
    struct dirent64 *(*read64)(DIR *);
    int (*read_r)(DIR *, struct dirent *, struct dirent **);
    int (*read64_r)(DIR *, struct dirent64 *, struct dirent64 **);
    int (*close)(DIR *);
    int (*fd)(DIR *);
    void (*rewind)(DIR *);
    long (*tell)(DIR *);
    void (*seek)(DIR *, long);
};

static void *directory_address(void *const *functions, unsigned index) {
    return functions ? functions[index] : flc_directory_function(index);
}

/* Copy only the returned record, never bytes beyond a GNU variable-sized
   dirent. Reentrant calls use caller-owned complete records. */
static int directory_next(struct directory_api *api, DIR *dir, unsigned variant,
                           struct dirent *out, int *slot) {
    memset(out, 0, sizeof *out);
    *slot = 1234;
    if (variant < 2) {
        const void *entry;
        unsigned short length;
        if (variant == 0) {
            struct dirent *p = api->read(dir);
            if (!p) return *slot == 1234 ? 0 : -1;
            entry = p; length = p->d_reclen;
        } else {
            struct dirent64 *p = api->read64(dir);
            if (!p) return *slot == 1234 ? 0 : -1;
            entry = p; length = p->d_reclen;
        }
        if (length < offsetof(struct dirent, d_name) + 1 || length > sizeof *out) return -1;
        memcpy(out, entry, length);
    } else if (variant == 2) {
        struct dirent *result = NULL;
        memset(out, 0xA5, sizeof *out);
        int r = api->read_r(dir, out, &result);
        if (r || *slot != 1234 || (result && result != out)) return -1;
        if (!result) return 0;
        if (out->d_reclen < 20 || out->d_reclen > sizeof *out) return -1;
        for (size_t i = out->d_reclen; i < sizeof *out; i++)
            if (((unsigned char *)out)[i] != 0xA5) return -1;
    } else {
        struct dirent64 entry = {0}, *result = NULL;
        memset(&entry, 0xA5, sizeof entry);
        int r = api->read64_r(dir, &entry, &result);
        if (r || *slot != 1234 || (result && result != &entry)) return -1;
        if (!result) return 0;
        if (entry.d_reclen < 20 || entry.d_reclen > sizeof entry) return -1;
        for (size_t i = entry.d_reclen; i < sizeof entry; i++)
            if (((unsigned char *)&entry)[i] != 0xA5) return -1;
        memcpy(out, &entry, sizeof *out);
    }
    return 1;
}

static int directory_name_index(const char *name) {
    const char *fixed[] = {".", "..", "alpha", "beta", "gamma", "sub", "link"};
    for (unsigned i = 0; i < sizeof fixed / sizeof *fixed; i++)
        if (strcmp(name, fixed[i]) == 0) return (int)i;
    if (strlen(name) == 255) {
        for (unsigned i = 0; i < 255; i++) if (name[i] != 'n') return -1;
        return 7;
    }
    if (strlen(name) == 7 && memcmp(name, "item", 4) == 0 &&
        name[4] >= '0' && name[4] <= '1' && name[5] >= '0' && name[5] <= '9' &&
        name[6] >= '0' && name[6] <= '9')
        return 8 + 100 * (name[4] - '0') + 10 * (name[5] - '0') + name[6] - '0';
    return -1;
}

static int directory_walk(struct directory_api *api, DIR *dir, unsigned variant,
                           int *slot, metadata_reference reference) {
    unsigned char seen[208] = {0};
    unsigned count = 0;
    struct dirent entry;
    int status;
    while ((status = directory_next(api, dir, variant, &entry, slot)) == 1) {
        size_t length = strnlen(entry.d_name, sizeof entry.d_name);
        size_t expected = (20 + length + 7) & ~(size_t)7;
        /* GNU _r removes final padding if it exceeds the maximum name slot. */
        size_t limit = offsetof(struct dirent, d_name) + 256;
        if (variant >= 2 && expected > limit) expected = limit;
        if (length == sizeof entry.d_name || entry.d_reclen != expected) return __LINE__;
        int index = directory_name_index(entry.d_name);
        if (index < 0 || index >= 208 || seen[index]++) return __LINE__;
        struct stat st;
        if (reference(api->fd(dir), entry.d_name, &st, AT_SYMLINK_NOFOLLOW) != 0 || entry.d_ino != st.st_ino)
            return __LINE__;
        unsigned type = S_ISDIR(st.st_mode) ? DT_DIR : S_ISLNK(st.st_mode) ? DT_LNK : DT_REG;
        if (entry.d_type != DT_UNKNOWN && entry.d_type != type) return __LINE__;
        count++;
    }
    if (status != 0 || count != 208) return __LINE__;
    return 0;
}

#define DIRECTORY_CHECK(condition) do { if (!(condition)) { result = __LINE__; goto done; } } while (0)
/* Thirteen fixed groups: four walks, independent-stream storage, seek/EOF,
   rewind, fd ownership, O_PATH/non-directory/badfd/missing/regular errors. */
int flc_directory_case(unsigned which, const char *directory, const char *file, const char *missing,
                        void *const *functions, int *(*error_slot)(void), metadata_reference reference) {
    struct directory_api api;
    api.open = (__typeof__(api.open))directory_address(functions, 0);
    api.fdopen = (__typeof__(api.fdopen))directory_address(functions, 1);
    api.read = (__typeof__(api.read))directory_address(functions, 2);
    api.read64 = (__typeof__(api.read64))directory_address(functions, 3);
    api.read_r = (__typeof__(api.read_r))directory_address(functions, 4);
    api.read64_r = (__typeof__(api.read64_r))directory_address(functions, 5);
    api.close = (__typeof__(api.close))directory_address(functions, 6);
    api.fd = (__typeof__(api.fd))directory_address(functions, 7);
    api.rewind = (__typeof__(api.rewind))directory_address(functions, 8);
    api.tell = (__typeof__(api.tell))directory_address(functions, 9);
    api.seek = (__typeof__(api.seek))directory_address(functions, 10);
    DIR *a = NULL, *b = NULL;
    int fd = -1, result = 0, *slot = error_slot();
    if (which < 4 || which == 6) {
        a = api.open(directory); DIRECTORY_CHECK(a != NULL);
        DIRECTORY_CHECK(directory_walk(&api, a, which < 4 ? which : 0, slot, reference) == 0);
        if (which == 6) {
            api.rewind(a); DIRECTORY_CHECK(api.tell(a) == 0);
            DIRECTORY_CHECK(directory_walk(&api, a, 0, slot, reference) == 0);
        }
    } else if (which == 4) {
        a = api.open(directory); b = api.open(directory); DIRECTORY_CHECK(a && b);
        struct dirent *saved = NULL;
        for (unsigned i = 0; i < 208; i++) {
            saved = api.read(a); DIRECTORY_CHECK(saved != NULL);
            if (strcmp(saved->d_name, "alpha") == 0) break;
        }
        DIRECTORY_CHECK(strcmp(saved->d_name, "alpha") == 0);
        ino_t ino = saved->d_ino; off_t offset = saved->d_off;
        unsigned short length = saved->d_reclen; unsigned char type = saved->d_type;
        struct dirent *other;
        do { other = api.read(b); DIRECTORY_CHECK(other != NULL); } while (strcmp(other->d_name, "beta"));
        DIRECTORY_CHECK(strcmp(saved->d_name, "alpha") == 0 && saved->d_ino == ino &&
                        saved->d_off == offset && saved->d_reclen == length && saved->d_type == type);
        api.rewind(b);
        struct dirent entry;
        DIRECTORY_CHECK(directory_next(&api, b, 1, &entry, slot) == 1);
        DIRECTORY_CHECK(directory_next(&api, b, 2, &entry, slot) == 1);
        DIRECTORY_CHECK(directory_next(&api, b, 3, &entry, slot) == 1);
        DIRECTORY_CHECK(api.close(b) == 0); b = NULL;
        DIRECTORY_CHECK(strcmp(saved->d_name, "alpha") == 0 && saved->d_ino == ino &&
                        saved->d_off == offset && saved->d_reclen == length && saved->d_type == type);
    } else if (which == 5) {
        a = api.open(directory); DIRECTORY_CHECK(a != NULL);
        struct dirent entry, expected;
        for (unsigned i = 0; i < 3; i++) DIRECTORY_CHECK(directory_next(&api, a, 0, &entry, slot) == 1);
        long cookie = api.tell(a); DIRECTORY_CHECK(cookie != -1);
        DIRECTORY_CHECK(directory_next(&api, a, 0, &expected, slot) == 1);
        api.seek(a, cookie);
        DIRECTORY_CHECK(directory_next(&api, a, 0, &entry, slot) == 1 &&
                        strcmp(entry.d_name, expected.d_name) == 0 && entry.d_ino == expected.d_ino);
        int next;
        while ((next = directory_next(&api, a, 0, &entry, slot)) == 1) { }
        DIRECTORY_CHECK(next == 0);
        api.seek(a, cookie);
        DIRECTORY_CHECK(directory_next(&api, a, 0, &entry, slot) == 1 &&
                        strcmp(entry.d_name, expected.d_name) == 0 && entry.d_ino == expected.d_ino);
    } else if (which >= 7 && which <= 9) {
        fd = open(which == 9 ? file : directory, (which == 8 ? O_PATH : O_RDONLY) | (which == 9 ? 0 : O_DIRECTORY));
        DIRECTORY_CHECK(fd >= 0 && fcntl(fd, F_GETFD) == 0);
        *slot = 1234; a = api.fdopen(fd); int error = *slot;
        if (a) { int owned = fd; fd = -1; DIRECTORY_CHECK(api.fd(a) == owned); }
        if (which == 7) {
            DIRECTORY_CHECK(a != NULL); int owned = api.fd(a);
            DIRECTORY_CHECK(fcntl(owned, F_GETFD) == FD_CLOEXEC);
            DIRECTORY_CHECK(directory_walk(&api, a, 0, slot, reference) == 0);
            DIRECTORY_CHECK(api.close(a) == 0); a = NULL;
            DIRECTORY_CHECK(fcntl(owned, F_GETFD) == -1);
        } else {
            DIRECTORY_CHECK(a == NULL && error == (which == 8 ? EBADF : ENOTDIR));
            DIRECTORY_CHECK(fcntl(fd, F_GETFD) == 0);
        }
    } else if (which == 10) {
        *slot = 1234; a = api.fdopen(-1); DIRECTORY_CHECK(a == NULL && *slot == EBADF);
    } else if (which == 11 || which == 12) {
        *slot = 1234; a = api.open(which == 11 ? missing : file);
        DIRECTORY_CHECK(a == NULL && *slot == (which == 11 ? ENOENT : ENOTDIR));
    } else result = 2;
done:
    if (b && api.close(b) != 0) result = result ? result : __LINE__;
    if (a && api.close(a) != 0) result = result ? result : __LINE__;
    if (fd >= 0 && close(fd) != 0) result = result ? result : __LINE__;
    return result;
}
#undef DIRECTORY_CHECK

extern int scan_narrow(const char *, struct dirent ***, int (*)(const struct dirent *),
                       int (*)(const struct dirent **, const struct dirent **)) __asm__("scandir");
extern int scan_at_narrow(int, const char *, struct dirent ***, int (*)(const struct dirent *),
                          int (*)(const struct dirent **, const struct dirent **)) __asm__("scandirat");
extern int scan_alpha(const struct dirent **, const struct dirent **) __asm__("alphasort");
extern int scan_version(const struct dirent **, const struct dirent **) __asm__("versionsort");

void *flc_scan_function(unsigned index) {
    switch (index) {
        case 0: return (void *)scan_narrow;
        case 1: return (void *)scandir64;
        case 2: return (void *)scan_at_narrow;
        case 3: return (void *)scandirat64;
        case 4: return (void *)scan_alpha;
        case 5: return (void *)alphasort64;
        case 6: return (void *)scan_version;
        case 7: return (void *)versionsort64;
        default: return NULL;
    }
}

typedef int (*scan_select)(const struct dirent *);
typedef int (*scan_compare)(const struct dirent **, const struct dirent **);
typedef int (*scan_name_compare)(const char *, const char *);
static void *scan_address(void *const *functions, unsigned index) {
    return functions ? functions[index] : flc_scan_function(index);
}
static int scan_invoke(void *function, unsigned variant, int fd, const char *path,
                        struct dirent ***list, scan_select select, scan_compare compare) {
    if (variant < 2)
        return ((int (*)(const char *, struct dirent ***, scan_select, scan_compare))function)(path, list, select, compare);
    return ((int (*)(int, const char *, struct dirent ***, scan_select, scan_compare))function)(fd, path, list, select, compare);
}
static void scan_release(struct dirent **list, int count, void (*release)(void *)) {
    if (list && count >= 0) {
        for (int i = 0; i < count; i++) release(list[i]);
        release(list);
    }
}
static int scan_index(const char *name) {
    int index = directory_name_index(name);
    if (index >= 0) return index;
    const char *extra[] = {"file2", "file10", "file1", "file01", "file001"};
    for (unsigned i = 0; i < 5; i++) if (!strcmp(name, extra[i])) return 208 + (int)i;
    return -1;
}
/* Observer state is process-local; these protocols run serially in isolated
   children. Reentry below invokes the scan ABI directly, without a new observer. */
static struct {
    unsigned group, calls, comparisons;
    int *slot, mismatch;
    int (*inject)(int);
    void *function;
    const char *path;
    void (*release)(void *);
} scan_observer;
static int scan_filter(const struct dirent *entry) {
    unsigned call = ++scan_observer.calls;
    if (scan_observer.group >= 9 && scan_observer.group <= 11 && call == 3) {
        const int errors[] = {EIO, EINTR, EACCES};
        if (!scan_observer.inject || scan_observer.inject(errors[scan_observer.group - 9]))
            scan_observer.mismatch = 1;
    }
    if (scan_observer.group == 5 && call == 1) {
        struct dirent **nested = NULL;
        int n = scan_invoke(scan_observer.function, 0, -1, scan_observer.path, &nested, NULL, NULL);
        if (n != 213) scan_observer.mismatch = 1;
        scan_release(nested, n, scan_observer.release);
    }
    *scan_observer.slot = EAGAIN;
    if (scan_observer.group == 4) return 0;
    if (scan_observer.group == 3) {
        int index = scan_index(entry->d_name);
        return index >= 8 && index < 208 && (index - 8) % 2 == 0;
    }
    return 1;
}
static int scan_descending(const struct dirent **a, const struct dirent **b) {
    scan_observer.comparisons++;
    *scan_observer.slot = EDOM;
    return strcmp((*b)->d_name, (*a)->d_name);
}
static int scan_fd_count(void) {
    int count = 0;
    for (int fd = 0; fd < 4096; fd++) if (fcntl(fd, F_GETFD) >= 0) count++;
    return count;
}

/* 12 groups per variant, plus relative badfd for the two at variants.
   7 positive + 5 error groups; all returned allocations use their provider. */
int flc_scan_case(unsigned group, unsigned variant, const char *directory, const char *missing,
                   const char *file, void *const *functions, int *(*error_slot)(void),
                   void (*release)(void *), metadata_reference reference,
                   scan_name_compare alphabetical, scan_name_compare version,
                   int (*inject)(int)) {
    if (variant > 3 || group > 12 || (group == 12 && variant < 2)) return 2;
    int before = scan_fd_count(), result = 0;
    int fd = open(directory, O_RDONLY | O_DIRECTORY);
    if (fd < 0) return __LINE__;
    scan_observer.group = group; scan_observer.calls = scan_observer.comparisons = 0;
    scan_observer.slot = error_slot(); scan_observer.mismatch = 0;
    scan_observer.inject = inject; scan_observer.function = scan_address(functions, 0);
    scan_observer.path = directory; scan_observer.release = release;
    scan_compare compare = group == 1 ? (scan_compare)scan_address(functions, 4 + variant % 2) :
                           group == 2 ? (scan_compare)scan_address(functions, 6 + variant % 2) :
                           group == 5 ? scan_descending : NULL;
    const char *path = variant < 2 || group == 8 ? directory : ".";
    if (group == 6) path = variant < 2 ? missing : "missing";
    if (group == 7) path = variant < 2 ? file : "alpha";
    struct dirent **sentinel = (struct dirent **)(uintptr_t)1, **list = sentinel;
    *scan_observer.slot = 1234;
    int n = scan_invoke(scan_address(functions, variant), variant,
                        group == 8 || group == 12 ? -1 : fd, path, &list, scan_filter, compare);
    int error = *scan_observer.slot;
    int expected_error = group == 6 ? ENOENT : group == 7 ? ENOTDIR : group == 12 ? EBADF :
                         group == 9 ? EIO : group == 10 ? EINTR : group == 11 ? EACCES : 0;
    if (expected_error) {
        if (n != -1 || error != expected_error || list != sentinel) result = __LINE__;
        if (group >= 9 && group <= 11 && scan_observer.calls < 3) result = __LINE__;
    } else {
        int expected_count = group == 3 ? 100 : group == 4 ? 0 : 213;
        unsigned char seen[213] = {0};
        if (n != expected_count || error != 1234 || scan_observer.calls != 213) result = __LINE__;
        if (n > 0 && (!list || list == sentinel)) result = __LINE__;
        if (!result) for (int i = 0; i < n; i++) {
            struct dirent *entry = list[i];
            size_t length = strnlen(entry->d_name, sizeof entry->d_name);
            int index = length == sizeof entry->d_name ? -1 : scan_index(entry->d_name);
            if (index < 0 || index >= 213 || seen[index]++ ||
                (group == 3 && !(index >= 8 && index < 208 && (index - 8) % 2 == 0))) { result = __LINE__; break; }
            struct stat st;
            if (reference(fd, entry->d_name, &st, AT_SYMLINK_NOFOLLOW) || st.st_ino != entry->d_ino) { result = __LINE__; break; }
            unsigned type = S_ISDIR(st.st_mode) ? DT_DIR : S_ISLNK(st.st_mode) ? DT_LNK : DT_REG;
            if (entry->d_type != DT_UNKNOWN && entry->d_type != type) { result = __LINE__; break; }
            if (i && compare) {
                int order = (group == 2 ? version : alphabetical)(list[i - 1]->d_name, entry->d_name);
                if ((group == 5 && order < 0) || (group != 5 && order > 0)) { result = __LINE__; break; }
            }
        }
        if (group == 5 && !scan_observer.comparisons) result = __LINE__;
    }
    if (scan_observer.mismatch) result = __LINE__;
    if (n >= 0 && list != sentinel) scan_release(list, n, release);
    if (close(fd) != 0 || scan_fd_count() != before) result = __LINE__;
    return result;
}

int flc_scan_comparators(void *const *functions, scan_name_compare alphabetical,
                          scan_name_compare version) {
    const char *pairs[][2] = {{"file9", "file10"}, {"file10", "file9"}, {"a", "a"},
        {"img2", "img2"}, {"v1.9", "v1.10"}, {"abc", "abd"}, {"", "x"}, {"file001", "file1"}};
    for (unsigned which = 0; which < 4; which++) for (unsigned i = 0; i < 8; i++) {
        struct dirent a = {0}, b = {0};
        strcpy(a.d_name, pairs[i][0]); strcpy(b.d_name, pairs[i][1]);
        const struct dirent *pa = &a, *pb = &b;
        int observed = ((scan_compare)scan_address(functions, 4 + which))(&pa, &pb);
        int expected = (which < 2 ? alphabetical : version)(pairs[i][0], pairs[i][1]);
        if ((observed > 0) - (observed < 0) != (expected > 0) - (expected < 0)) return __LINE__;
    }
    return 0;
}

static int metadata_matches(const struct stat *out, const char *path,
                             metadata_reference reference, const struct stat *initial) {
    struct stat expected;
    if (reference(AT_FDCWD, path, &expected, AT_SYMLINK_NOFOLLOW) != 0) return 0;
    /* Traversal may update atime. Every other original field is invariant;
       the implementation must not mutate metadata and then report its change. */
    struct stat stable = *initial;
    stable.st_atim = expected.st_atim;
    return metadata_equal(out, &expected) && metadata_equal(&expected, &stable);
}

#define META_CHECK(condition) do { if (!(condition)) return __LINE__; } while (0)
int flc_metadata_protocol(const char *directory, const char *file, const char *link, const char *missing,
                          metadata_reference reference, unsigned counts[2]) {
    counts[0] = counts[1] = 0;
    struct stat expected[3];
    const char *reference_paths[] = {file, link, directory};
    for (unsigned i = 0; i < 3; i++)
        META_CHECK(reference(AT_FDCWD, reference_paths[i], &expected[i], AT_SYMLINK_NOFOLLOW) == 0);
    int fd = open(file, O_RDONLY), dir = open(directory, O_RDONLY | O_DIRECTORY);
    META_CHECK(fd >= 0 && dir >= 0);
    META_CHECK(expected[0].st_size > INT32_MAX && S_ISREG(expected[0].st_mode));
    META_CHECK(S_ISLNK(expected[1].st_mode) && S_ISDIR(expected[2].st_mode));
    META_CHECK(lseek(fd, 17, SEEK_SET) == 17);
    for (unsigned api = 0; api < 8; api++) {
        unsigned family = api % 4;
        for (unsigned item = 0; item < 3; item++) {
            const char *path = item == 0 ? file : item == 1 ? link : directory;
            int which = item == 1 && family == 2 ? 1 : item == 2 && family != 1 ? 2 : 0;
            struct stat out = {0};
            errno = 1234;
            META_CHECK(metadata_call(api, AT_FDCWD, fd, path, &out, 0) == 0);
            META_CHECK(errno == 1234);
            META_CHECK(metadata_matches(&out, reference_paths[which], reference, &expected[which]));
            counts[0]++;
        }
        struct stat out, untouched;
        memset(&untouched, 0xA5, sizeof untouched);
        out = untouched;
        errno = 0;
        const char *absent = family == 0 || family == 2 ? missing : "missing";
        META_CHECK(metadata_call(api, -1, -1, absent, &out, 0) == -1);
        META_CHECK(errno == (family == 1 || family == 3 ? EBADF : ENOENT));
        META_CHECK(memcmp(&out, &untouched, sizeof out) == 0);
        counts[1]++;
        if (family == 3) {
            errno = 1234;
            META_CHECK(metadata_call(api, dir, fd, "data", &out, 0) == 0);
            META_CHECK(errno == 1234);
            META_CHECK(metadata_matches(&out, file, reference, &expected[0]));
            counts[0]++;
            META_CHECK(metadata_call(api, dir, fd, "link", &out, AT_SYMLINK_NOFOLLOW) == 0);
            META_CHECK(metadata_matches(&out, link, reference, &expected[1])); counts[0]++;
            META_CHECK(metadata_call(api, fd, fd, "", &out, AT_EMPTY_PATH) == 0);
            META_CHECK(metadata_matches(&out, file, reference, &expected[0])); counts[0]++;
            out = untouched; errno = 0;
            META_CHECK(metadata_call(api, dir, fd, "data", &out, INT_MIN) == -1 && errno == EINVAL);
            META_CHECK(memcmp(&out, &untouched, sizeof out) == 0); counts[1]++;
        }
    }
    struct statx extended, untouched;
    for (unsigned item = 0; item < 4; item++) {
        const char *path = item == 0 ? "data" : item == 1 ? "link" : item == 2 ? "" : ".";
        int which = item == 1 ? 1 : item == 3 ? 2 : 0;
        int base = item == 2 ? fd : dir;
        int flags = item == 2 ? AT_EMPTY_PATH : AT_SYMLINK_NOFOLLOW;
        memset(&extended, 0, sizeof extended); errno = 1234;
        META_CHECK(statx(base, path, flags, STATX_BASIC_STATS, &extended) == 0 && errno == 1234);
        META_CHECK((extended.stx_mask & STATX_BASIC_STATS) == STATX_BASIC_STATS);
        struct stat current;
        META_CHECK(reference(AT_FDCWD, reference_paths[which], &current, AT_SYMLINK_NOFOLLOW) == 0);
        struct stat stable = expected[which];
        stable.st_atim = current.st_atim;
        META_CHECK(metadata_equal(&current, &stable));
        const struct stat *want = &current;
        META_CHECK(extended.stx_ino == want->st_ino && extended.stx_size == (uint64_t)want->st_size);
        META_CHECK(extended.stx_mode == want->st_mode && extended.stx_nlink == want->st_nlink);
        META_CHECK(extended.stx_uid == want->st_uid && extended.stx_gid == want->st_gid);
        META_CHECK(extended.stx_blksize == want->st_blksize && extended.stx_blocks == (uint64_t)want->st_blocks);
        META_CHECK(extended.stx_dev_major == major(want->st_dev) && extended.stx_dev_minor == minor(want->st_dev));
        META_CHECK(extended.stx_rdev_major == major(want->st_rdev) && extended.stx_rdev_minor == minor(want->st_rdev));
        META_CHECK(extended.stx_atime.tv_sec == want->st_atim.tv_sec && extended.stx_atime.tv_nsec == want->st_atim.tv_nsec);
        META_CHECK(extended.stx_mtime.tv_sec == want->st_mtim.tv_sec && extended.stx_mtime.tv_nsec == want->st_mtim.tv_nsec);
        META_CHECK(extended.stx_ctime.tv_sec == want->st_ctim.tv_sec && extended.stx_ctime.tv_nsec == want->st_ctim.tv_nsec);
        counts[0]++;
    }
    memset(&untouched, 0xA5, sizeof untouched);
    const int bases[] = {-1, dir, dir};
    const char *paths[] = {"data", "missing", "data"};
    const int flags[] = {0, 0, INT_MIN};
    const int errors[] = {EBADF, ENOENT, EINVAL};
    for (unsigned item = 0; item < 3; item++) {
        extended = untouched; errno = 0;
        META_CHECK(statx(bases[item], paths[item], flags[item], STATX_BASIC_STATS, &extended) == -1);
        META_CHECK(errno == errors[item] && memcmp(&extended, &untouched, sizeof extended) == 0);
        counts[1]++;
    }
    META_CHECK(lseek(fd, 0, SEEK_CUR) == 17);
    META_CHECK(close(fd) == 0 && close(dir) == 0);
    META_CHECK(counts[0] == 34 && counts[1] == 13);
    return 0;
}
#undef META_CHECK

extern char *__getcwd_chk(char *, size_t, size_t);
extern ssize_t __readlink_chk(const char *, char *, size_t, size_t);
extern ssize_t __readlinkat_chk(int, const char *, char *, size_t, size_t);

void *flc_path_function(unsigned index) {
    switch (index) {
        case 0: return (void *)creat64;
        case 1: return (void *)access;
        case 2: return (void *)faccessat;
        case 3: return (void *)getcwd;
        case 4: return (void *)chdir;
        case 5: return (void *)fchdir;
        case 6: return (void *)readlink;
        case 7: return (void *)readlinkat;
        case 8: return (void *)free;
        case 9: return (void *)__getcwd_chk;
        case 10: return (void *)__readlink_chk;
        case 11: return (void *)__readlinkat_chk;
        default: return NULL;
    }
}

/* Restore through the independent caller even if the implementation under
   test fails. Tests run in a child because cwd is process-wide. */
typedef int (*path_restore)(int);
#define PATH_CHECK(condition) do { if (!(condition)) { result = __LINE__; goto done; } } while (0)
int flc_path_protocol(const char *directory, const char *file, const char *link,
                      const char *missing, const char *created, int deep,
                      const char *deep_name, int repairs, path_restore restore,
                      unsigned counts[3]) {
    int result = 0, saved = open(".", O_RDONLY | O_DIRECTORY);
    int dir = open(directory, O_RDONLY | O_DIRECTORY), fd = open(file, O_RDONLY);
    counts[0] = counts[1] = counts[2] = 0;
    char bytes[8192], guard[8192];
    memset(guard, 0xA5, sizeof guard);
    PATH_CHECK(saved >= 0 && dir >= 0 && fd >= 0);
    PATH_CHECK(chdir(directory) == 0); counts[0]++;
    size_t length = strlen(directory);
    memcpy(bytes, guard, sizeof bytes);
    PATH_CHECK(getcwd(bytes, sizeof bytes) == bytes && strcmp(bytes, directory) == 0);
    PATH_CHECK(memcmp(bytes + length + 1, guard + length + 1, sizeof bytes - length - 1) == 0); counts[0]++;
    PATH_CHECK(getcwd(bytes, length + 1) == bytes && strcmp(bytes, directory) == 0); counts[0]++;
    PATH_CHECK(__getcwd_chk(bytes, sizeof bytes, sizeof bytes) == bytes && strcmp(bytes, directory) == 0); counts[0]++;
    for (unsigned i = 0; i < 2; i++) {
        char *allocated = getcwd(NULL, i ? sizeof bytes : 0);
        int correct = allocated && strcmp(allocated, directory) == 0;
        free(allocated); PATH_CHECK(correct); counts[0]++;
    }
    errno = 0; PATH_CHECK(getcwd(bytes, 0) == NULL && errno == EINVAL); counts[1]++;
    memcpy(bytes, guard, sizeof bytes); errno = 0;
    PATH_CHECK(getcwd(bytes, 1) == NULL && errno == ERANGE && memcmp(bytes, guard, sizeof bytes) == 0); counts[1]++;
    errno = 0; PATH_CHECK(getcwd(NULL, 1) == NULL && errno == ERANGE); counts[1]++;
    PATH_CHECK(fchdir(saved) == 0); counts[0]++;
    PATH_CHECK(fchdir(dir) == 0); counts[0]++;
    errno = 0; PATH_CHECK(chdir(file) == -1 && errno == ENOTDIR); counts[1]++;
    errno = 0; PATH_CHECK(chdir(missing) == -1 && errno == ENOENT); counts[1]++;
    errno = 0; PATH_CHECK(fchdir(fd) == -1 && errno == ENOTDIR); counts[1]++;
    errno = 0; PATH_CHECK(fchdir(-1) == -1 && errno == EBADF); counts[1]++;
    PATH_CHECK(getcwd(bytes, sizeof bytes) == bytes && strcmp(bytes, directory) == 0);
    const int modes[] = {F_OK, R_OK, W_OK};
    for (unsigned i = 0; i < 3; i++) { PATH_CHECK(access(file, modes[i]) == 0); counts[0]++; }
    errno = 0; PATH_CHECK(access(file, X_OK) == -1 && errno == EACCES); counts[1]++;
    errno = 0; PATH_CHECK(access(missing, F_OK) == -1 && errno == ENOENT); counts[1]++;
    errno = 0;
    if (repairs) { PATH_CHECK(access(file, INT_MIN) == 0); counts[2]++; }
    else { PATH_CHECK(access(file, INT_MIN) == -1 && errno == EINVAL); counts[1]++; }
    const int flags[] = {0, AT_EACCESS, AT_SYMLINK_NOFOLLOW};
    for (unsigned i = 0; i < 3; i++) for (unsigned j = 0; j < 3; j++) {
        PATH_CHECK(faccessat(dir, "data", modes[i], flags[j]) == 0); counts[0]++;
    }
    PATH_CHECK(faccessat(dir, "link", X_OK, AT_SYMLINK_NOFOLLOW) == 0); counts[0]++;
    errno = 0; PATH_CHECK(faccessat(-1, "data", F_OK, 0) == -1 && errno == EBADF); counts[1]++;
    errno = 0; PATH_CHECK(faccessat(dir, "missing", F_OK, 0) == -1 && errno == ENOENT); counts[1]++;
    errno = 0; PATH_CHECK(faccessat(dir, "data", F_OK, INT_MIN) == -1 && errno == EINVAL); counts[1]++;
    errno = 0; PATH_CHECK(faccessat(dir, "data", INT_MIN, 0) == -1 && errno == EINVAL); counts[1]++;
    const size_t sizes[] = {1, 4, 32};
    for (unsigned api = 0; api < 2; api++) {
        for (unsigned i = 0; i < 3; i++) {
            memcpy(bytes, guard, sizeof bytes); errno = 1234;
            ssize_t n = api ? readlinkat(dir, "link", bytes, sizes[i]) : readlink(link, bytes, sizes[i]);
            size_t want = sizes[i] < 4 ? sizes[i] : 4;
            PATH_CHECK(n == (ssize_t)want && errno == 1234 && memcmp(bytes, "data", want) == 0);
            PATH_CHECK(memcmp(bytes + want, guard + want, sizeof bytes - want) == 0); counts[0]++;
        }
        const char *paths[] = {api ? "link" : link, api ? "data" : file, api ? "missing" : missing};
        const int errors[] = {EINVAL, EINVAL, ENOENT};
        for (unsigned i = 0; i < 3; i++) {
            memcpy(bytes, guard, sizeof bytes); errno = 0;
            ssize_t n = api ? readlinkat(dir, paths[i], bytes, i ? sizeof bytes : 0)
                            : readlink(paths[i], bytes, i ? sizeof bytes : 0);
            PATH_CHECK(n == -1 && errno == errors[i] && memcmp(bytes, guard, sizeof bytes) == 0); counts[1]++;
        }
    }
    errno = 0; PATH_CHECK(readlinkat(-1, "link", bytes, sizeof bytes) == -1 && errno == EBADF); counts[1]++;
    for (unsigned api = 0; api < 2; api++) {
        memcpy(bytes, guard, sizeof bytes);
        ssize_t n = api ? __readlinkat_chk(dir, "link", bytes, 4, sizeof bytes)
                        : __readlink_chk(link, bytes, 4, sizeof bytes);
        PATH_CHECK(n == 4 && memcmp(bytes, "data", 4) == 0);
        PATH_CHECK(memcmp(bytes + 4, guard + 4, sizeof bytes - 4) == 0); counts[0]++;
    }
    int out = creat64(created, 0600); PATH_CHECK(out >= 0);
    PATH_CHECK(write(out, "new", 3) == 3 && close(out) == 0);
    out = open(created, O_RDONLY); PATH_CHECK(out >= 0);
    ssize_t n = read(out, bytes, sizeof bytes);
    int closed = close(out);
    PATH_CHECK(n == 3 && memcmp(bytes, "new", 3) == 0 && closed == 0); counts[0]++;
    PATH_CHECK(fchdir(deep) == 0); counts[0]++;
    length = strlen(deep_name); PATH_CHECK(length > PATH_MAX && length + 1 < sizeof bytes);
    PATH_CHECK(getcwd(bytes, sizeof bytes) == bytes && strcmp(bytes, deep_name) == 0); counts[0]++;
    for (unsigned i = 0; i < 2; i++) {
        char *allocated = getcwd(NULL, i ? sizeof bytes : 0);
        int correct = allocated && strcmp(allocated, deep_name) == 0;
        free(allocated); PATH_CHECK(correct); counts[0]++;
    }
    errno = 0; PATH_CHECK(getcwd(bytes, 1) == NULL && errno == ERANGE); counts[1]++;
    PATH_CHECK(counts[0] == 34 && counts[1] == (repairs ? 21u : 22u) && counts[2] == (unsigned)repairs);
done:
    if (saved >= 0) {
        if (restore(saved) != 0) result = __LINE__;
        close(saved);
    }
    if (dir >= 0) close(dir);
    if (fd >= 0) close(fd);
    return result;
}
#undef PATH_CHECK

#ifndef FLC_STAT_PLUGIN
#include <linux/filter.h>
#include <linux/seccomp.h>
#include <stddef.h>
#include <sched.h>
#include <sys/mount.h>
#include <sys/prctl.h>

static int path_kernel_restore(int fd) { return (int)syscall(SYS_fchdir, fd); }

/* Fault injection into one selected syscall in one child. Other errors must
   never be hidden by a fallback. This is not a security sandbox. */
static int path_filter(int number, int error) {
    struct sock_filter code[] = {
        BPF_STMT(BPF_LD | BPF_W | BPF_ABS, offsetof(struct seccomp_data, nr)),
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, (unsigned)number, 0, 1),
        BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ERRNO | (unsigned)error),
        BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW)
    };
    struct sock_fprog program = {(unsigned short)(sizeof code / sizeof *code), code};
    return prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) || prctl(PR_SET_SECCOMP, SECCOMP_MODE_FILTER, &program);
}

typedef int (*scan_case_function)(unsigned, unsigned, const char *, const char *, const char *,
    void *const *, int *(*)(void), void (*)(void *), metadata_reference,
    scan_name_compare, scan_name_compare, int (*)(int));
static int scan_inject(int error) { return path_filter(SYS_getdents64, error); }

int flc_scan_child(scan_case_function run, unsigned group, unsigned variant,
                    const char *directory, const char *missing, const char *file,
                    void *const *functions, int *(*error_slot)(void), void (*release)(void *),
                    metadata_reference reference, scan_name_compare alphabetical,
                    scan_name_compare version) {
    int pipefd[2];
    if (pipe(pipefd) != 0) return __LINE__;
    pid_t pid = fork();
    if (pid == 0) {
        close(pipefd[0]);
        int result = run(group, variant, directory, missing, file, functions,
                         error_slot, release, reference, alphabetical, version, scan_inject);
        ssize_t sent = write(pipefd[1], &result, sizeof result);
        close(pipefd[1]);
        _exit(sent == sizeof result ? 0 : 3);
    }
    close(pipefd[1]);
    if (pid < 0) { close(pipefd[0]); return __LINE__; }
    int result = -1, status = 0;
    ssize_t received = read(pipefd[0], &result, sizeof result);
    close(pipefd[0]);
    if (waitpid(pid, &status, 0) != pid || !WIFEXITED(status) || WEXITSTATUS(status) ||
        received != sizeof result) return __LINE__;
    return result;
}

static int scan_provider(void) {
    struct stat expected, actual;
    const char *pin = getenv("FLC_SCAN_EXPECT_PROVIDER");
    if (!pin || syscall(SYS_newfstatat, AT_FDCWD, pin, &expected, 0)) return 42;
    for (unsigned i = 0; i < 10; i++) {
        Dl_info info;
        void *function = i < 8 ? flc_scan_function(i) : i == 8 ? (void *)free : (void *)__errno_location;
        if (!dladdr(function, &info) || !info.dli_fname ||
            syscall(SYS_newfstatat, AT_FDCWD, info.dli_fname, &actual, 0) ||
            actual.st_dev != expected.st_dev || actual.st_ino != expected.st_ino) return 42;
    }
    return 0;
}

/* The candidate's comparator must not also serve as its name-order oracle. */
static void *scan_oracles(scan_name_compare *alphabetical, scan_name_compare *version) {
    const char *pin = getenv("FLC_SCAN_ORACLE_PROVIDER");
    struct stat expected, actual;
    if (!pin || syscall(SYS_newfstatat, AT_FDCWD, pin, &expected, 0)) return NULL;
    void *host = dlopen("libc.so.6", RTLD_NOW | RTLD_LOCAL);
    if (!host) return NULL;
    void *functions[] = {dlsym(host, "strcoll"), dlsym(host, "strverscmp"), dlsym(host, "setlocale")};
    for (unsigned i = 0; i < 3; i++) {
        Dl_info info;
        if (!functions[i] || !dladdr(functions[i], &info) || !info.dli_fname ||
            syscall(SYS_newfstatat, AT_FDCWD, info.dli_fname, &actual, 0) ||
            actual.st_dev != expected.st_dev || actual.st_ino != expected.st_ino) {
            dlclose(host); return NULL;
        }
    }
    if (!((char *(*)(int, const char *))functions[2])(LC_ALL, "C")) { dlclose(host); return NULL; }
    *alphabetical = (scan_name_compare)functions[0];
    *version = (scan_name_compare)functions[1];
    return host;
}

static int path_provider(void) {
    struct stat provider, actual;
    const char *pin = getenv("FLC_PATH_EXPECT_PROVIDER");
    if (!pin || syscall(SYS_newfstatat, AT_FDCWD, pin, &provider, 0) != 0) return 42;
    for (unsigned i = 0; i < 13; i++) {
        Dl_info info;
        void *symbol = i == 12 ? (void *)__errno_location : flc_path_function(i);
        if (!dladdr(symbol, &info) || !info.dli_fname ||
            syscall(SYS_newfstatat, AT_FDCWD, info.dli_fname, &actual, 0) != 0 ||
            provider.st_dev != actual.st_dev || provider.st_ino != actual.st_ino) return 42;
    }
    return 0;
}

static int path_edges(const char *jail, const char *file, const char *missing) {
    struct edge { int setup, result, error; };
    int failures = 0;
    char *warm = getcwd(NULL, 0);
    if (!warm) return 2;
    free(warm);
    for (unsigned i = 0; i < 6; i++) {
        int ends[2];
        if (pipe(ends) != 0) return 2;
        pid_t child = fork();
        if (child < 0) { close(ends[0]); close(ends[1]); return 2; }
        if (child == 0) {
            close(ends[0]);
            struct edge out = {0, 0, 0};
            if (i < 3) {
                out.setup = chroot(jail);
                if (!out.setup) {
                    char bytes[8192]; errno = 0;
                    char *answer = getcwd(i == 0 ? bytes : NULL, i == 1 ? 0 : sizeof bytes);
                    out.error = errno; out.result = answer != NULL;
                    if (i != 0) free(answer);
                }
            } else {
                out.setup = path_filter(SYS_faccessat2, i == 5 ? EACCES : ENOSYS);
                if (!out.setup) {
                    errno = 0;
                    out.result = faccessat(AT_FDCWD, i == 4 ? missing : file, F_OK, 0);
                    out.error = errno;
                }
            }
            ssize_t sent = write(ends[1], &out, sizeof out);
            _exit(sent == sizeof out ? 0 : 2);
        }
        close(ends[1]);
        struct edge out = {0, 0, 0};
        ssize_t received = read(ends[0], &out, sizeof out);
        close(ends[0]);
        int status = 0;
        if (waitpid(child, &status, 0) != child || received != sizeof out ||
            !WIFEXITED(status) || WEXITSTATUS(status) != 0 || out.setup) return 2;
        int correct = i < 3 ? out.result == 0 && out.error == ENOENT
                    : i == 3 ? out.result == 0
                    : out.result == -1 && out.error == (i == 4 ? ENOENT : EACCES);
        printf("path edge %u: result=%d error=%d correct=%d\n", i, out.result, out.error, correct);
        failures += !correct;
    }
    return failures ? 1 : 0;
}

typedef char *(*cwd_function)(char *, size_t);
typedef void (*cwd_free)(void *);
typedef int *(*cwd_errno)(void);
struct cwd_observation {
    int status, setup, success, error, raw_error, guards_ok, fd_delta;
    int same_device, different_inode;
    size_t length;
    char path[8192];
};

static int cwd_fd_count(void) {
    int count = 0;
    for (int fd = 0; fd < 4096; fd++) count += syscall(SYS_fcntl, fd, F_GETFD) >= 0;
    return count;
}

/* Run actual filesystem/syscall operations in a child, so neither cwd nor
   mount propagation can escape into the test runner. Policies: normal,
   getdents64 EACCES/EIO/EINTR, EOF, and a same-device bind mount. */
int flc_cwd_observe(cwd_function cwd, cwd_free release, cwd_errno error_slot,
                    const char *source, const char *target, const char *component,
                    int deep, int policy, int form, struct cwd_observation *out) {
    if (deep < 0 || deep >= 4096 || policy < 0 || policy > 5 || form < 0 || form > 2) return 2;
    char *warm = cwd(NULL, 0);
    if (!warm) return 2;
    release(warm);
    int ends[2];
    if (pipe(ends) != 0) return 2;
    pid_t child = fork();
    if (child < 0) { close(ends[0]); close(ends[1]); return 2; }
    if (child == 0) {
        close(ends[0]);
        struct cwd_observation result = {0};
        if (policy == 5) {
            struct stat src, dst;
            if (syscall(SYS_newfstatat, AT_FDCWD, source, &src, 0) != 0 ||
                syscall(SYS_newfstatat, AT_FDCWD, target, &dst, 0) != 0) {
                result.setup = 1; goto send;
            }
            result.same_device = src.st_dev == dst.st_dev;
            result.different_inode = src.st_ino != dst.st_ino;
            if (unshare(CLONE_NEWNS) != 0 ||
                mount(NULL, "/", NULL, MS_REC | MS_PRIVATE, NULL) != 0 ||
                mount(source, target, NULL, MS_BIND, NULL) != 0) {
                result.setup = 2; goto send;
            }
            int fd = open(target, O_RDONLY | O_DIRECTORY | O_CLOEXEC);
            if (fd < 0) { result.setup = 3; goto send; }
            for (unsigned i = 0; i < 24; i++) {
                int next = openat(fd, component, O_RDONLY | O_DIRECTORY | O_CLOEXEC);
                close(fd);
                if (next < 0) { result.setup = 4; goto send; }
                fd = next;
            }
            int changed = fchdir(fd);
            close(fd);
            if (changed != 0) { result.setup = 5; goto send; }
        } else if (fchdir(deep) != 0) {
            result.setup = 6; goto send;
        }
        char kernel_path[8192];
        errno = 0;
        long raw = syscall(SYS_getcwd, kernel_path, sizeof kernel_path);
        result.raw_error = raw < 0 ? errno : 0;
        if (result.raw_error != ENAMETOOLONG) { result.setup = 7; goto send; }
        if (policy >= 1 && policy <= 4) {
            const int errors[] = {EACCES, EIO, EINTR, 0};
            if (path_filter(SYS_getdents64, errors[policy - 1]) != 0) {
                result.setup = 8; goto send;
            }
        }
        struct { unsigned char left[32]; char bytes[8192]; unsigned char right[32]; } guarded;
        memset(&guarded, 0xA5, sizeof guarded);
        int before = cwd_fd_count();
        int *slot = error_slot();
        *slot = 1234;
        char *answer = cwd(form == 0 ? guarded.bytes : NULL, form == 1 ? 0 : sizeof guarded.bytes);
        result.error = *slot;
        result.success = answer != NULL;
        if (answer) {
            result.length = strnlen(answer, sizeof result.path);
            if (result.length < sizeof result.path) memcpy(result.path, answer, result.length + 1);
        }
        if (form != 0) release(answer);
        result.fd_delta = cwd_fd_count() - before;
        result.guards_ok = 1;
        for (unsigned i = 0; i < 32; i++)
            result.guards_ok &= guarded.left[i] == 0xA5 && guarded.right[i] == 0xA5;
send:;
        size_t sent = 0;
        while (sent < sizeof result) {
            ssize_t n = write(ends[1], (char *)&result + sent, sizeof result - sent);
            if (n < 0 && errno == EINTR) continue;
            if (n <= 0) _exit(2);
            sent += (size_t)n;
        }
        _exit(0);
    }
    close(ends[1]);
    size_t received = 0;
    while (received < sizeof *out) {
        ssize_t n = read(ends[0], (char *)out + received, sizeof *out - received);
        if (n < 0 && errno == EINTR) continue;
        if (n <= 0) break;
        received += (size_t)n;
    }
    close(ends[0]);
    int status = 0;
    pid_t waited;
    do { waited = waitpid(child, &status, 0); } while (waited < 0 && errno == EINTR);
    if (waited != child || received != sizeof *out) return 2;
    out->status = status;
    return 0;
}

static int cwd_review(const char *source, const char *target, const char *component, int deep) {
    const char *pin = getenv("FLC_CWD_EXPECT_PROVIDER");
    struct stat expected, actual;
    if (!pin || syscall(SYS_newfstatat, AT_FDCWD, pin, &expected, 0) != 0) return 42;
    const void *functions[] = {(const void *)getcwd, (const void *)free, (const void *)__errno_location};
    for (unsigned i = 0; i < sizeof functions / sizeof *functions; i++) {
        Dl_info info;
        if (!dladdr(functions[i], &info) || !info.dli_fname ||
            syscall(SYS_newfstatat, AT_FDCWD, info.dli_fname, &actual, 0) != 0 ||
            actual.st_dev != expected.st_dev || actual.st_ino != expected.st_ino) return 42;
    }
    const int errors[] = {0, EACCES, EIO, EINTR, ENOENT, 0};
    unsigned successes = 0, failures = 0, mismatches = 0;
    for (int policy = 0; policy < 6; policy++) {
        char pathname[8192];
        int used = snprintf(pathname, sizeof pathname, "%s", policy == 5 ? target : source);
        if (used < 0 || used >= (int)sizeof pathname) return 2;
        size_t length = (size_t)used, part = strlen(component);
        for (unsigned i = 0; i < 24; i++) {
            if (length + part + 2 > sizeof pathname) return 2;
            pathname[length++] = '/';
            memcpy(pathname + length, component, part + 1);
            length += part;
        }
        for (int form = 0; form < 3; form++) {
            struct cwd_observation out = {0};
            int r = flc_cwd_observe(getcwd, free, __errno_location, source, target,
                                    component, deep, policy, form, &out);
            int valid = r == 0 && out.status == 0 && out.setup == 0 &&
                        out.raw_error == ENAMETOOLONG && out.guards_ok && out.fd_delta == 0;
            if (errors[policy]) {
                failures++;
                valid &= !out.success && out.error == errors[policy];
            } else {
                successes++;
                valid &= out.success && out.length == length && strcmp(out.path, pathname) == 0;
            }
            if (policy == 5) valid &= out.same_device && out.different_inode;
            mismatches += !valid;
            printf("cwd case policy=%d form=%d valid=%d setup=%d status=%d success=%d errno=%d raw=%d guards=%d fds=%d length=%zu\n",
                   policy, form, valid, out.setup, out.status, out.success, out.error,
                   out.raw_error, out.guards_ok, out.fd_delta, out.length);
        }
    }
    printf("cwd review: successes=%u errors=%u mismatches=%u\n", successes, failures, mismatches);
    return mismatches ? 1 : 0;
}

static int metadata_kernel_reference(int dir, const char *path, struct stat *out, int flags) {
    return (int)syscall(SYS_newfstatat, dir, path, out, flags);
}

static const char *err(int r) { return r < 0 ? strerrorname_np(errno) : "ok"; }

/* Keep both real GNU symbol imports despite the large-file redirect. */
extern int narrow_lockf(int, int, off_t) __asm__("lockf");
typedef int (*lock_function)(int, int, off_t);
extern int narrow_posix_fallocate(int, off_t, off_t) __asm__("posix_fallocate");
typedef int (*allocate_function)(int, off_t, off_t);

#define CHECK(condition) do { if (!(condition)) { \
    fprintf(stderr, "fd contract failed at line %d\n", __LINE__); return 1; \
} } while (0)

static int check_lock_provider(void) {
    const char *expected = getenv("FLC_LOCKF_EXPECT_PROVIDER");
    if (!expected) return 0;
    struct stat want, got;
    if (stat(expected, &want) != 0) return 42;
    const void *symbols[] = {(const void *)narrow_lockf, (const void *)lockf,
                             (const void *)narrow_posix_fallocate, (const void *)posix_fallocate,
                             (const void *)__errno_location};
    for (size_t i = 0; i < sizeof symbols / sizeof *symbols; i++) {
        Dl_info info;
        if (!dladdr(symbols[i], &info) || !info.dli_fname ||
            stat(info.dli_fname, &got) != 0 || got.st_dev != want.st_dev ||
            got.st_ino != want.st_ino) {
            fprintf(stderr, "lockf provider mismatch\n");
            return 42;
        }
    }
    return 0;
}

static int clear_locks(int fd) {
    struct flock lock = {.l_type = F_UNLCK, .l_whence = SEEK_SET};
    return fcntl(fd, F_SETLK, &lock);
}

static int lockf_contract(void) {
    char path[] = "/tmp/fl_lockf_retained_XXXXXX";
    int fd = mkstemp(path), ends[2];
    CHECK(fd >= 0 && write(fd, "0123456789abcdef", 16) == 16);
    int ro = open(path, O_RDONLY);
    CHECK(ro >= 0 && pipe(ends) == 0 && write(ends[1], "q", 1) == 1);
    int closed = dup(ends[0]);
    CHECK(closed >= 0 && close(closed) == 0);
    int descriptors[] = {fd, ro, ends[0], ends[1], -1, closed};
    int commands[] = {-1, F_ULOCK, F_LOCK, F_TLOCK, F_TEST, 4, INT_MIN, INT_MAX};
    off_t lengths[] = {-3, 0, 4};
    lock_function functions[] = {narrow_lockf, lockf};
    size_t cases = 0;
    for (size_t a = 0; a < 2; a++) {
        for (size_t d = 0; d < 6; d++) {
            for (size_t c = 0; c < 8; c++) {
                for (size_t l = 0; l < 3; l++) {
                    CHECK(clear_locks(fd) == 0 && lseek(fd, 7, SEEK_SET) == 7);
                    CHECK(lseek(ro, 7, SEEK_SET) == 7);
                    errno = 0;
                    int rc = functions[a](descriptors[d], commands[c], lengths[l]);
                    int error = rc < 0 ? errno : 0;
                    printf("lockf/%zu fd=%zu cmd=%d len=%lld rc=%d errno=%s pos=%lld/%lld\n",
                           a, d, commands[c], (long long)lengths[l], rc,
                           error ? strerrorname_np(error) : "ok",
                           (long long)lseek(fd, 0, SEEK_CUR), (long long)lseek(ro, 0, SEEK_CUR));
                    cases++;
                }
            }
        }
    }
    CHECK(cases == 288 && clear_locks(fd) == 0);

    size_t conflicts = 0;
    for (int exclusive = 0; exclusive < 2; exclusive++) {
        int ready[2], release[2];
        CHECK(pipe(ready) == 0 && pipe(release) == 0);
        pid_t child = fork();
        CHECK(child >= 0);
        if (child == 0) {
            close(ready[0]); close(release[1]);
            struct flock lock = {.l_type = exclusive ? F_WRLCK : F_RDLCK,
                                 .l_whence = SEEK_SET, .l_start = 7, .l_len = 4};
            if (fcntl(fd, F_SETLK, &lock) != 0 || write(ready[1], "r", 1) != 1) _exit(2);
            char byte;
            if (read(release[0], &byte, 1) != 0) _exit(3);
            _exit(0);
        }
        close(ready[1]); close(release[0]);
        char byte;
        CHECK(read(ready[0], &byte, 1) == 1 && byte == 'r');
        for (size_t a = 0; a < 2; a++) {
            for (int test = 0; test < 2; test++) {
                int cmd = test ? F_TEST : F_TLOCK;
                CHECK(lseek(fd, 7, SEEK_SET) == 7);
                errno = 0;
                int rc = functions[a](fd, cmd, 4), error = rc < 0 ? errno : 0;
                printf("lockf/%zu holder=%s cmd=%d rc=%d errno=%s\n", a,
                       exclusive ? "write" : "read", cmd, rc,
                       error ? strerrorname_np(error) : "ok");
                CHECK((rc == 0) == (!exclusive && test));
                CHECK(lseek(fd, 0, SEEK_CUR) == 7);
                conflicts++;
            }
        }
        close(release[1]); close(ready[0]);
        int status;
        CHECK(waitpid(child, &status, 0) == child && WIFEXITED(status) && WEXITSTATUS(status) == 0);
    }
    CHECK(conflicts == 8);

    size_t ranges = 0;
    for (size_t a = 0; a < 2; a++) {
        for (size_t l = 0; l < 3; l++) {
            CHECK(clear_locks(fd) == 0 && lseek(fd, 7, SEEK_SET) == 7);
            CHECK(functions[a](fd, F_TLOCK, lengths[l]) == 0);
            int reply[2];
            CHECK(pipe(reply) == 0);
            pid_t child = fork();
            CHECK(child >= 0);
            if (child == 0) {
                close(reply[0]);
                struct flock query = {.l_type = F_WRLCK, .l_whence = SEEK_SET};
                if (fcntl(fd, F_GETLK, &query) != 0 ||
                    write(reply[1], &query, sizeof query) != (ssize_t)sizeof query) _exit(4);
                _exit(0);
            }
            close(reply[1]);
            struct flock query;
            CHECK(read(reply[0], &query, sizeof query) == (ssize_t)sizeof query);
            close(reply[0]);
            int status;
            CHECK(waitpid(child, &status, 0) == child && WIFEXITED(status) && WEXITSTATUS(status) == 0);
            off_t start = lengths[l] < 0 ? 7 + lengths[l] : 7;
            off_t size = lengths[l] < 0 ? -lengths[l] : lengths[l];
            CHECK(query.l_type == F_WRLCK && query.l_start == start && query.l_len == size && query.l_pid == getpid());
            CHECK(lseek(fd, 0, SEEK_CUR) == 7);
            printf("lockf/%zu range=%lld/%lld holder_is_parent=1\n", a, (long long)start, (long long)size);
            ranges++;
        }
    }
    char bytes[16], byte;
    struct stat metadata;
    CHECK(ranges == 6 && clear_locks(fd) == 0);
    CHECK(pread(fd, bytes, sizeof bytes, 0) == (ssize_t)sizeof bytes && memcmp(bytes, "0123456789abcdef", sizeof bytes) == 0);
    CHECK(fstat(fd, &metadata) == 0 && metadata.st_size == (off_t)sizeof bytes);
    CHECK(read(ends[0], &byte, 1) == 1 && byte == 'q');
    CHECK(close(fd) == 0 && close(ro) == 0 && close(ends[0]) == 0 && close(ends[1]) == 0);
    printf("lockf contract: %zu descriptor cases, %zu conflicts, %zu ranges passed\n", cases, conflicts, ranges);
    /* Retain both uniquely named test inputs for diagnosis. */
    return 0;
}

static int allocation_contract(void) {
    char path[] = "/tmp/fl_posix_alloc_retained_XXXXXX";
    const char seed[] = "0123456789abcdef";
    int fd = mkstemp(path), ends[2];
    CHECK(fd >= 0);
    int ro = open(path, O_RDONLY), append = open(path, O_WRONLY | O_APPEND);
    int directory = open("/tmp", O_RDONLY | O_DIRECTORY);
    CHECK(ro >= 0 && append >= 0 && directory >= 0 && pipe(ends) == 0);
    CHECK(write(ends[1], "q", 1) == 1);
    int closed = dup(directory);
    CHECK(closed >= 0 && close(closed) == 0);
    int descriptors[] = {fd, ro, append, ends[0], ends[1], directory, -1, closed};
    off_t offsets[] = {-1, 0, 7, 31, INT64_MIN};
    off_t lengths[] = {-1, 0, 1, 4, INT64_MIN};
    allocate_function functions[] = {narrow_posix_fallocate, posix_fallocate};
    size_t cases = 0, successes = 0;
    for (size_t a = 0; a < 2; a++) {
        for (size_t d = 0; d < 8; d++) {
            for (size_t o = 0; o < 5; o++) {
                for (size_t l = 0; l < 5; l++) {
                    CHECK(ftruncate(fd, 16) == 0 && pwrite(fd, seed, 16, 0) == 16);
                    CHECK(lseek(fd, 3, SEEK_SET) == 3 && lseek(ro, 3, SEEK_SET) == 3 && lseek(append, 3, SEEK_SET) == 3);
                    errno = 0x3bad;
                    int rc = functions[a](descriptors[d], offsets[o], lengths[l]);
                    int error = errno;
                    CHECK(rc >= 0 && error == 0x3bad);
                    struct stat metadata;
                    CHECK(fstat(fd, &metadata) == 0 && metadata.st_size >= 16 && metadata.st_size <= 35);
                    unsigned char bytes[35];
                    ssize_t count = pread(fd, bytes, sizeof bytes, 0);
                    CHECK(count == metadata.st_size && memcmp(bytes, seed, 16) == 0);
                    for (ssize_t i = 16; i < count; i++) CHECK(bytes[i] == 0);
                    off_t expected = 16;
                    if (rc == 0) {
                        CHECK(offsets[o] >= 0 && lengths[l] > 0);
                        off_t end = offsets[o] + lengths[l];
                        if (end > expected) expected = end;
                        successes++;
                    }
                    CHECK(metadata.st_size == expected);
                    CHECK(lseek(fd, 0, SEEK_CUR) == 3 && lseek(ro, 0, SEEK_CUR) == 3 && lseek(append, 0, SEEK_CUR) == 3);
                    printf("posix allocation/%zu fd=%zu off=%lld len=%lld rc=%d errno=%d size=%lld data=",
                           a, d, (long long)offsets[o], (long long)lengths[l], rc, error, (long long)metadata.st_size);
                    for (ssize_t i = 0; i < count; i++) printf("%02x", bytes[i]);
                    putchar('\n');
                    cases++;
                }
            }
        }
    }
    CHECK(cases == 400 && successes == 24);
    CHECK(narrow_posix_fallocate(-1, -1, -1) == EBADF);
    CHECK(posix_fallocate(-1, -1, -1) == EBADF);
    char byte;
    CHECK(read(ends[0], &byte, 1) == 1 && byte == 'q');
    CHECK(close(fd) == 0 && close(ro) == 0 && close(append) == 0 && close(directory) == 0);
    CHECK(close(ends[0]) == 0 && close(ends[1]) == 0);
    printf("posix allocation contract: %zu cases, %zu successes passed\n", cases, successes);
    return 0;
}

int main(int argc, char **argv) {
    if (argc == 6 && strcmp(argv[1], "--scan-case") == 0) {
        int provider = scan_provider();
        if (provider) return provider;
        scan_name_compare alphabetical, version;
        void *oracle = scan_oracles(&alphabetical, &version);
        if (!oracle) return 43;
        char missing[PATH_MAX];
        if (snprintf(missing, sizeof missing, "%s/missing", argv[4]) >= (int)sizeof missing) return 2;
        int result = flc_scan_child(flc_scan_case, (unsigned)strtoul(argv[2], NULL, 10),
            (unsigned)strtoul(argv[3], NULL, 10), argv[4], missing, argv[5], NULL,
            __errno_location, free, metadata_kernel_reference, alphabetical, version);
        if (dlclose(oracle)) return 44;
        printf("scan group=%s variant=%s line=%d\n", argv[2], argv[3], result);
        return result ? 1 : 0;
    }
    if (argc == 2 && strcmp(argv[1], "--scan-comparators") == 0) {
        int provider = scan_provider();
        if (provider) return provider;
        scan_name_compare alphabetical, version;
        void *oracle = scan_oracles(&alphabetical, &version);
        if (!oracle) return 43;
        int result = flc_scan_comparators(NULL, alphabetical, version);
        if (dlclose(oracle)) return 44;
        printf("scan comparators=32 line=%d\n", result);
        return result ? 1 : 0;
    }
    if (argc == 5 && strcmp(argv[1], "--directory-case") == 0) {
        const char *pin = getenv("FLC_DIRECTORY_EXPECT_PROVIDER");
        struct stat expected, actual;
        if (!pin || syscall(SYS_newfstatat, AT_FDCWD, pin, &expected, 0) != 0) return 42;
        for (unsigned i = 0; i < 12; i++) {
            Dl_info info;
            void *function = i < 11 ? flc_directory_function(i) : (void *)__errno_location;
            if (!dladdr(function, &info) || !info.dli_fname ||
                syscall(SYS_newfstatat, AT_FDCWD, info.dli_fname, &actual, 0) != 0 ||
                actual.st_dev != expected.st_dev || actual.st_ino != expected.st_ino) return 42;
        }
        char missing[PATH_MAX];
        if (snprintf(missing, sizeof missing, "%s/missing", argv[3]) >= (int)sizeof missing) return 2;
        int result = flc_directory_case((unsigned)strtoul(argv[2], NULL, 10), argv[3], argv[4],
                                        missing, NULL, __errno_location, metadata_kernel_reference);
        printf("directory case=%s line=%d\n", argv[2], result);
        return result ? 1 : 0;
    }
    if (argc == 6 && strcmp(argv[1], "--cwd-review") == 0)
        return cwd_review(argv[2], argv[3], argv[4], atoi(argv[5]));
    if (argc == 4 && strcmp(argv[1], "--path-overflow") == 0) {
        int provider = path_provider();
        if (provider) return provider;
        char bytes[4];
        size_t requested = (size_t)strtoul(argv[3], NULL, 10);
        ssize_t returned;
        switch (atoi(argv[2])) {
            case 0: returned = __getcwd_chk(bytes, requested, sizeof bytes) != NULL; break;
            case 1: returned = __readlink_chk("/proc/self/exe", bytes, requested, sizeof bytes); break;
            case 2: returned = __readlinkat_chk(AT_FDCWD, "/proc/self/exe", bytes, requested, sizeof bytes); break;
            default: return 2;
        }
        fprintf(stderr, "checked operation unexpectedly returned: %zd\n", returned);
        return 43; /* A checked overflow must never return. */
    }
    if (argc == 5 && strcmp(argv[1], "--path-edges") == 0) {
        int provider = path_provider();
        return provider ? provider : path_edges(argv[2], argv[3], argv[4]);
    }
    if (argc == 8 && strcmp(argv[1], "--paths") == 0) {
        int provider = path_provider();
        if (provider) return provider;
        char missing[PATH_MAX];
        if (snprintf(missing, sizeof missing, "%s/missing", argv[2]) >= (int)sizeof missing) return 2;
        unsigned counts[3];
        const char *repairs = getenv("FLC_PATH_REPAIRS");
        int result = flc_path_protocol(argv[2], argv[3], argv[4], missing, argv[7],
                                       atoi(argv[5]), argv[6], repairs && strcmp(repairs, "1") == 0,
                                       path_kernel_restore, counts);
        printf("pathname protocol: line=%d success=%u errors=%u repairs=%u\n", result, counts[0], counts[1], counts[2]);
        return result ? 1 : 0;
    }
    if (argc == 5 && strcmp(argv[1], "--metadata") == 0) {
        struct stat provider, actual;
        const char *pin = getenv("FLC_STAT_EXPECT_PROVIDER");
        if (!pin || syscall(SYS_newfstatat, AT_FDCWD, pin, &provider, 0) != 0) return 42;
        for (unsigned i = 0; i < 10; i++) {
            Dl_info info;
            void *symbol = i == 9 ? (void *)__errno_location : flc_metadata_function(i);
            if (!dladdr(symbol, &info) || !info.dli_fname ||
                syscall(SYS_newfstatat, AT_FDCWD, info.dli_fname, &actual, 0) != 0 ||
                provider.st_dev != actual.st_dev || provider.st_ino != actual.st_ino) return 42;
        }
        unsigned counts[2];
        char missing[PATH_MAX];
        if (snprintf(missing, sizeof missing, "%s/missing", argv[2]) >= (int)sizeof missing) return 2;
        int result = flc_metadata_protocol(argv[2], argv[3], argv[4], missing, metadata_kernel_reference, counts);
        printf("metadata protocol: line=%d success=%u errors=%u\n", result, counts[0], counts[1]);
        return result ? 1 : 0;
    }
    int provider = check_lock_provider();
    if (provider) return provider;
    char path[] = "/tmp/fl_fcntl64_XXXXXX";
    int fd = mkstemp(path);
    if (write(fd, "0123456789", 10) != 10) return 1;

    int r = fcntl(fd, F_SETFL, O_NONBLOCK | O_APPEND);
    int fl = fcntl(fd, F_GETFL);
    printf("F_SETFL %s, F_GETFL nonblock=%d append=%d\n", err(r), !!(fl & O_NONBLOCK), !!(fl & O_APPEND));

    r = fcntl(fd, F_SETFD, FD_CLOEXEC);
    printf("F_SETFD %s, F_GETFD cloexec=%d\n", err(r), fcntl(fd, F_GETFD) & FD_CLOEXEC);

    int d = fcntl(fd, F_DUPFD, 40);
    int dc = fcntl(fd, F_DUPFD_CLOEXEC, 50);
    printf("F_DUPFD >= 40: %d, F_DUPFD_CLOEXEC >= 50: %d cloexec=%d\n", d, dc, fcntl(dc, F_GETFD) & FD_CLOEXEC);

    struct flock lk = {.l_type = F_WRLCK, .l_whence = SEEK_SET, .l_start = 2, .l_len = 3};
    r = fcntl(fd, F_SETLK, &lk);
    printf("F_SETLK write lock bytes 2..4: %s\n", err(r));
    fflush(stdout);
    pid_t pid = fork();
    if (pid == 0) {
        int cfd = open(path, O_RDWR);
        struct flock probe = {.l_type = F_WRLCK, .l_whence = SEEK_SET, .l_start = 0, .l_len = 10};
        int g = fcntl(cfd, F_GETLK, &probe);
        printf("child F_GETLK %s: type=%s start=%lld len=%lld holder_is_parent=%d\n", err(g),
               probe.l_type == F_WRLCK ? "F_WRLCK" : probe.l_type == F_UNLCK ? "F_UNLCK" : "?",
               (long long)probe.l_start, (long long)probe.l_len, probe.l_pid == getppid());
        struct flock try = {.l_type = F_RDLCK, .l_whence = SEEK_SET, .l_start = 3, .l_len = 1};
        errno = 0;
        int t = fcntl(cfd, F_SETLK, &try);
        printf("child F_SETLK conflicting read lock: %s\n", t < 0 ? strerrorname_np(errno) : "granted");
        struct flock free_range = {.l_type = F_RDLCK, .l_whence = SEEK_SET, .l_start = 6, .l_len = 2};
        printf("child F_SETLK non-overlapping read lock: %s\n", err(fcntl(cfd, F_SETLK, &free_range)));
        fflush(stdout);
        _exit(0);
    }
    waitpid(pid, NULL, 0);
    lk.l_type = F_UNLCK;
    printf("F_SETLK unlock: %s\n", err(fcntl(fd, F_SETLK, &lk)));

    struct flock ofd = {.l_type = F_WRLCK, .l_whence = SEEK_SET, .l_start = 0, .l_len = 1};
    printf("F_OFD_SETLK: %s\n", err(fcntl(fd, F_OFD_SETLK, &ofd)));
    printf("F_SETPIPE_SZ on a file: %s\n", err(fcntl(fd, F_SETPIPE_SZ, 65536)));
    int p[2];
    CHECK(pipe(p) == 0);
    printf("F_SETPIPE_SZ on a pipe: %d, F_GETPIPE_SZ: %d\n", fcntl(p[0], F_SETPIPE_SZ, 131072), fcntl(p[0], F_GETPIPE_SZ));
    printf("bad fd: %s\n", err(fcntl(999, F_SETFL, 0)));
    CHECK(lockf_contract() == 0);
    return allocation_contract();
}
#endif
