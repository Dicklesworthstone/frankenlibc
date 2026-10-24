#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
#include <dlfcn.h>
#include <errno.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#ifdef __cplusplus
#define STATIC_ASSERT static_assert
#else
#define STATIC_ASSERT _Static_assert
#endif
STATIC_ASSERT(sizeof(uid_t) == 4 && sizeof(gid_t) == 4, "Linux uid/gid ABI");
#define CHECK(x) do { if (!(x)) { fprintf(stderr, "FAIL %d: %s\n", __LINE__, #x); exit(1); } } while (0)

typedef int (*User)(const char *, uid_t *, gid_t *, int *, gid_t *);
typedef int (*Host)(const char *, char *, int);
typedef int (*Key)(const char *, char *);
static User user;
static Host host;
static Key public_key;
static int *(*error_slot)(void);
static void *(*allocate)(size_t);
static void (*release)(void *);
static const char *candidate;
static void *provider;
static int gnu;
static unsigned rows;

static void *symbol(const char *name) {
    void *p;
    const char *forced = getenv("RPC_IDENTITY_FORCE_HOST");
    if (forced && !strcmp(forced, name)) {
        void *libc_handle = dlopen("libc.so.6", RTLD_NOW | RTLD_LOCAL);
        CHECK(libc_handle);
        p = dlvsym(libc_handle, name, "GLIBC_2.2.5");
    } else p = gnu ? dlvsym(provider, name, "GLIBC_2.2.5") : dlsym(provider, name);
    CHECK(p);
    if (candidate) {
        Dl_info info;
        struct stat wanted, actual;
        if (!dladdr(p, &info) || !info.dli_fname || stat(candidate, &wanted) ||
            stat(info.dli_fname, &actual) || wanted.st_dev != actual.st_dev ||
            wanted.st_ino != actual.st_ino) {
            fputs("WRONG RPC IDENTITY PROVIDER\n", stderr);
            exit(113);
        }
    }
    return p;
}

typedef struct Outputs {
    uid_t uid;
    uint32_t uid_guard;
    gid_t gid;
    uint32_t gid_guard;
    int count;
    uint32_t count_guard;
    gid_t groups[65536];
    uint32_t tail;
} Outputs;

static void init_output(Outputs *out) {
    memset(out, 0xa5, sizeof(*out));
    out->uid = 19; out->gid = 23; out->count = 29;
}

static void check_guards(const Outputs *out) {
    CHECK(out->uid_guard == UINT32_C(0xa5a5a5a5));
    CHECK(out->gid_guard == UINT32_C(0xa5a5a5a5));
    CHECK(out->count_guard == UINT32_C(0xa5a5a5a5));
    CHECK(out->tail == UINT32_C(0xa5a5a5a5));
}

static void user_case(const char *name, int success, uid_t uid, gid_t gid,
                      int count, const gid_t *groups) {
    Outputs out;
    init_output(&out);
    char mutable_name[256];
    CHECK(strlen(name) < sizeof(mutable_name));
    strcpy(mutable_name, name);
    *error_slot() = 37;
    int result = user(mutable_name, &out.uid, &out.gid, &out.count, out.groups);
    int error = *error_slot();
    if (getenv("RPC_IDENTITY_CHECK_USER_ERRNO")) CHECK(error == EKEYREJECTED);
    CHECK(result == success);
    check_guards(&out);
    if (success) {
        CHECK(out.uid == uid && out.gid == gid && out.count == count);
        for (int i = 0; i < count; i++) CHECK(out.groups[i] == groups[i]);
    } else CHECK(out.uid == 19 && out.gid == 23 && out.count == 29);
    for (unsigned i = success ? (unsigned)count : 0; i < 65536; i++)
        CHECK(out.groups[i] == UINT32_C(0xa5a5a5a5));
    printf("user %s %d %u %u %d errno=%d", name, result, out.uid, out.gid, out.count, error);
    if (success) for (int i = 0; i < count; i++) printf(" %u", out.groups[i]);
    putchar('\n');
    rows++;
}

static void key_case(const char *name, int success, const char *expected) {
    unsigned char output[51];
    memset(output, 0xa5, sizeof(output));
    *error_slot() = 37;
    int result = public_key(name, (char *)output + 1);
    int error = *error_slot();
    CHECK(result == success && output[0] == 0xa5 && output[50] == 0xa5);
    if (success) {
        CHECK(strlen(expected) == 48 && !memcmp(output + 1, expected, 48));
        CHECK(output[49] == 0);
    } else for (unsigned i = 1; i < 50; i++) CHECK(output[i] == 0xa5);
    printf("key %s %d errno=%d", name, result, error);
    for (unsigned i = 1; i < 50; i++) printf(" %02x", output[i]);
    putchar('\n');
    rows++;
}

static void host_case(int length) {
    unsigned char output[258];
    memset(output, 0xa5, sizeof(output));
    char name[] = "unix.gateway@franken.invalid";
    *error_slot() = 37;
    int result = host(name, (char *)output + 1, length);
    int error = *error_slot();
    CHECK(result == 1 && output[0] == 0xa5 && output[257] == 0xa5);
    for (int i = 0; i < length; i++) CHECK(output[1 + i] == (i < 10 ? "node.local"[i] : 0));
    for (int i = length; i < 256; i++) CHECK(output[1 + i] == 0xa5);
    printf("host %d %d errno=%d", length, result, error);
    for (unsigned i = 1; i < 257; i++) printf(" %02x", output[i]);
    putchar('\n');
    rows++;
}

static void files(void) {
    const gid_t two[] = {17, 88}, root_group[] = {9}, maximum[] = {UINT32_MAX};
    gid_t many[40];
    for (unsigned i = 0; i < 40; i++) many[i] = i + 1;
    user_case("unix.555@franken.invalid", 1, 1000, 42, 2, two);
    user_case("unix.77@franken.invalid", 1, 2000, 43, 0, NULL);
    user_case("unix.41@franken.invalid", 1, 0, 7, 1, root_group);
    user_case("unix.4294967295@franken.invalid", 1, UINT32_MAX, UINT32_MAX, 1, maximum);
    user_case("unix.40@franken.invalid", 1, 3000, 44, 40, many);
    const int lengths[] = {0, 1, 4, 9, 10, 11, 12, 256};
    for (unsigned i = 0; i < sizeof(lengths) / sizeof(lengths[0]); i++) host_case(lengths[i]);
    key_case("unix.555@franken.invalid", 1, "0123456789abcdef0123456789ABCDEF0123456789abcdef");
    key_case("nobody", 1, "ABCDEF0123456789abcdef0123456789ABCDEF0123456789");
    CHECK(rows == 15);
}

static void native_failures(void) {
    const char *names[] = {"unix.555@unmapped.invalid", "unix.overflow@franken.invalid",
        "unix.negative@franken.invalid", "unix.badgroup@franken.invalid"};
    for (unsigned i = 0; i < sizeof(names) / sizeof(names[0]); i++)
        user_case(names[i], 0, 0, 0, 0, NULL);
    key_case("unix.555@unmapped.invalid", 0, NULL);
    key_case("malformed", 0, NULL);
    unsigned char output[258];
    memset(output, 0xa5, sizeof(output));
    CHECK(host("unix.gateway@unmapped.invalid", (char *)output + 1, 256) == 0);
    for (unsigned i = 0; i < sizeof(output); i++) CHECK(output[i] == 0xa5);
    rows++;
    CHECK(rows == 7);
}

static void bounds(void) {
    Outputs out;
    init_output(&out);
    gid_t *groups = (gid_t *)allocate(sizeof(gid_t));
    CHECK(groups); *groups = 123;
    CHECK(user("unix.555@franken.invalid", &out.uid, &out.gid, &out.count, groups) == 0);
    CHECK(out.uid == 19 && out.gid == 23 && out.count == 29 && *groups == 123);
    check_guards(&out); release(groups); rows++;
    char *key = (char *)allocate(48);
    CHECK(key); memset(key, 0x5a, 48);
    CHECK(public_key("unix.555@franken.invalid", key) == 0);
    for (unsigned i = 0; i < 48; i++) CHECK(key[i] == 0x5a);
    release(key); rows++;
    char *name = (char *)allocate(4);
    CHECK(name); memset(name, 0x5a, 4);
    CHECK(host("unix.gateway@franken.invalid", name, 8) == 0);
    for (unsigned i = 0; i < 4; i++) CHECK(name[i] == 0x5a);
    release(name); rows++;
    CHECK(user("unix.555@franken.invalid", &out.uid, &out.gid, &out.count, NULL) == 0);
    CHECK(out.uid == 19 && out.gid == 23 && out.count == 29); rows++;
    CHECK(user("unix.77@franken.invalid", &out.uid, &out.gid, &out.count, NULL) == 1);
    CHECK(out.uid == 2000 && out.gid == 43 && out.count == 0); rows++;
    CHECK(rows == 5);
}

int main(int argc, char **argv) {
    CHECK(argc == 8);
    /* provider, library, isolated-root, mode, module-directory, sources, result */
    const char *mode = argv[4];
    gnu = !strcmp(argv[1], "glibc");
    candidate = !strcmp(argv[1], "candidate") ? argv[2] : NULL;
    provider = dlopen(candidate ? candidate : (gnu ? "libc.so.6" : "libtirpc.so.3"), RTLD_NOW | RTLD_LOCAL);
    CHECK(provider);
    user = (User)symbol("netname2user");
    public_key = (Key)symbol("getpublickey");
    host = (Host)symbol("netname2host");
    error_slot = (int *(*)(void))dlsym(provider, "__errno_location");
    CHECK(error_slot);
    unsigned (*counts[2])(unsigned) = {NULL, NULL};
    if (!strncmp(mode, "module", 6)) {
        const char *names[2] = {"rpcid_first", "rpcid_second"};
        if (!strcmp(argv[6], "default")) { names[0] = "nis"; names[1] = "nisplus"; }
        for (unsigned i = 0; i < 2; i++) {
            char path[4096];
            CHECK(snprintf(path, sizeof(path), "%s/libnss_%s.so.2", argv[5], names[i]) > 0);
            void *module = dlopen(path, RTLD_NOW | RTLD_LOCAL);
            CHECK(module);
            counts[i] = (unsigned (*)(unsigned))dlsym(module, "rpc_identity_calls");
            CHECK(counts[i]);
        }
        if (gnu && strcmp(argv[6], "default")) {
            int (*configure)(const char *, const char *) = (int (*)(const char *, const char *))dlsym(provider, "__nss_configure_lookup");
            CHECK(configure && configure("publickey", argv[6]) == 0);
        }
    }
    if (!strcmp(mode, "bounds")) {
        CHECK(candidate);
        allocate = (void *(*)(size_t))symbol("malloc");
        release = (void (*)(void *))symbol("free");
    }
    /* Only this test process enters this root. No bind mounts or host /etc edits. */
    CHECK(chroot(argv[3]) == 0 && chdir("/") == 0);
    if (!strcmp(mode, "files")) files();
    else if (!strcmp(mode, "native")) native_failures();
    else if (!strcmp(mode, "bounds")) bounds();
    else if (!strcmp(mode, "module-bad-count")) {
        user_case("unix.555@franken.invalid", 0, 0, 0, 0, NULL);
        CHECK(counts[0](0) == 1 && counts[1](0) == 0);
    }
    else if (!strcmp(mode, "module-bad-key")) {
        key_case("unix.555@franken.invalid", 0, NULL);
        CHECK(counts[0](1) == 1 && counts[1](1) == 0);
    }
    else if (!strcmp(mode, "module")) {
        int selected = atoi(argv[7]);
        const gid_t first[] = {17, 88}, second[] = {29, 93};
        user_case("unix.555@franken.invalid", selected != 0, selected == 1 ? 1001 : 2002,
                  selected == 1 ? 42 : 84, 2, selected == 1 ? first : second);
        key_case("unix.555@franken.invalid", selected != 0,
                 selected == 1 ? "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa" :
                                 "BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB");
        printf("calls %u %u %u %u\n", counts[0](0), counts[1](0), counts[0](1), counts[1](1));
        CHECK(rows == 2);
    } else CHECK(0);
    printf("ROWS %u\n", rows);
    return 0;
}
