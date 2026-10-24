/* Clean-room DNS parser ABI regressions. No network traffic is generated.
 * Build with a C compiler; pass --host or the freshly built FrankenLibC DSO.
 */
#define _GNU_SOURCE
#include <arpa/nameser.h>
#include <dlfcn.h>
#include <errno.h>
#include <limits.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>

typedef int (*init_fn)(const unsigned char *, int, ns_msg *);
typedef int (*parse_fn)(ns_msg *, ns_sect, int, ns_rr *);
typedef int *(*errno_fn)(void);
struct api { init_fn init; parse_fn parse; errno_fn error; };
struct packet {
    unsigned char bytes[65536];
    size_t size;
    size_t starts[4];
    size_t ends[4][2048];
    int counts[4];
};
static unsigned long calls;
static int candidate;

static void require(int condition, const char *message) {
    if (!condition) {
        fprintf(stderr, "FAIL: %s (after %lu ABI calls)\n", message, calls);
        exit(1);
    }
}

static void *symbol(void *handle, const char *name, const char *owner) {
    dlerror();
    void *p = dlsym(handle, name);
    const char *error = dlerror();
    if (!p || error) {
        fprintf(stderr, "missing %s: %s\n", name, error ? error : "null symbol");
        exit(1);
    }
    if (owner) {
        Dl_info info;
        struct stat expected, actual;
        require(dladdr(p, &info) != 0, "dladdr(symbol)");
        require(stat(owner, &expected) == 0 && stat(info.dli_fname, &actual) == 0,
                "stat symbol owner");
        require(expected.st_dev == actual.st_dev && expected.st_ino == actual.st_ino,
                "symbol resolved outside the requested FrankenLibC DSO");
    }
    return p;
}

static void byte(struct packet *packet, unsigned value) {
    require(packet->size < sizeof packet->bytes, "fixture capacity");
    packet->bytes[packet->size++] = (unsigned char)value;
}
static void u16(struct packet *packet, unsigned value) {
    byte(packet, value >> 8); byte(packet, value);
}
static void fixture(struct packet *packet, unsigned answers) {
    memset(packet, 0, sizeof *packet);
    require(answers > 0 && answers <= 2048, "fixture answer count");
    u16(packet, 0x1234); u16(packet, 0x8180);
    u16(packet, 1); u16(packet, answers); u16(packet, 1); u16(packet, 1);
    packet->counts[0] = 1; packet->counts[1] = (int)answers;
    packet->counts[2] = 1; packet->counts[3] = 1;
    packet->starts[0] = packet->size;
    const unsigned char name[] = {3,'w','w','w',7,'e','x','a','m','p','l','e',0};
    for (size_t i = 0; i < sizeof name; ++i) byte(packet, name[i]);
    u16(packet, ns_t_a); u16(packet, ns_c_in);
    packet->ends[0][0] = packet->size;
    for (int section = 1; section < 4; ++section) {
        packet->starts[section] = packet->size;
        for (int index = 0; index < packet->counts[section]; ++index) {
            u16(packet, 0xc00c); /* owner compressed to the question */
            unsigned type = section == 1 ? ns_t_a : section == 2 ? ns_t_ns : ns_t_aaaa;
            unsigned width = section == 1 ? 4 : section == 2 ? 2 : 16;
            u16(packet, type); u16(packet, ns_c_in);
            u16(packet, 0); u16(packet, 60 + (unsigned)index);
            u16(packet, width);
            if (section == 2) {
                u16(packet, 0xc00c);
            } else {
                for (unsigned i = 0; i < width; ++i) byte(packet, (unsigned)index + i + 1);
            }
            packet->ends[section][index] = packet->size;
        }
    }
}

static void initialize(struct api api, struct packet *packet, ns_msg *handle) {
    memset(handle, 0xa5, sizeof *handle);
    *api.error() = 0;
    ++calls;
    require(api.init(packet->bytes, (int)packet->size, handle) == 0, "initialize valid DNS frame");
    require(handle->_msg == packet->bytes && handle->_eom == packet->bytes + packet->size,
            "message bounds");
    require(handle->_id == 0x1234 && handle->_flags == 0x8180, "DNS header fields");
    require(handle->_sect == ns_s_max && handle->_rrnum == -1 && handle->_msg_ptr == NULL,
            "initial cursor has no selected section");
    for (int section = 0; section < 4; ++section) {
        require(handle->_counts[section] == packet->counts[section], "section record count");
        require(handle->_sections[section] == packet->bytes + packet->starts[section],
                "section start pointer");
    }
}

static void record(struct api api, struct packet *packet, ns_msg *handle,
                   int section, int request, int expected_index) {
    ns_rr result;
    memset(&result, 0xa5, sizeof result);
    *api.error() = 0;
    ++calls;
    require(api.parse(handle, (ns_sect)section, request, &result) == 0, "parse expected record");
    require(strcmp(result.name, "www.example") == 0, "expanded compressed owner name");
    unsigned expected_type = section <= 1 ? ns_t_a : section == 2 ? ns_t_ns : ns_t_aaaa;
    require(result.type == expected_type && result.rr_class == ns_c_in, "RR type and class");
    if (section == 0) {
        require(result.ttl == 0 && result.rdlength == 0 && result.rdata == NULL,
                "question has no resource-record payload");
    } else {
        size_t width = section == 1 ? 4 : section == 2 ? 2 : 16;
        require(result.ttl == 60U + (unsigned)expected_index && result.rdlength == width,
                "RR TTL and payload width");
        require(result.rdata == packet->bytes + packet->ends[section][expected_index] - width,
                "rdata points into the caller's message");
        if (section != 2)
            require(result.rdata[0] == (unsigned char)(expected_index + 1), "selected payload");
    }
    require(handle->_sect == (ns_sect)section && handle->_rrnum == expected_index + 1,
            "cursor identifies the NEXT record, not the last record");
    require(handle->_msg_ptr == packet->bytes + packet->ends[section][expected_index],
            "cursor byte pointer advances past the full record");
}

static void reject_index(struct api api, ns_msg *handle, int section, int index) {
    ns_rr result;
    *api.error() = 0;
    ++calls;
    require(api.parse(handle, (ns_sect)section, index, &result) == -1, "reject invalid/exhausted index");
    require(*api.error() == ENODEV, "invalid/exhausted index reports ENODEV");
}

static void mixed_iteration(struct api api) {
    struct packet packet;
    ns_msg handle;
    fixture(&packet, 3);
    initialize(api, &packet, &handle);
    record(api, &packet, &handle, 0, -1, 0);
    reject_index(api, &handle, 0, -1);
    record(api, &packet, &handle, 1, -1, 0);
    record(api, &packet, &handle, 1, -1, 1);
    record(api, &packet, &handle, 1, 0, 0); /* backward seek */
    record(api, &packet, &handle, 1, -1, 1);
    record(api, &packet, &handle, 1, 2, 2);
    reject_index(api, &handle, 1, -1);
    record(api, &packet, &handle, 2, -1, 0);
    reject_index(api, &handle, 2, -1);
    record(api, &packet, &handle, 3, -1, 0);
    reject_index(api, &handle, 3, -1);
    record(api, &packet, &handle, 1, -1, 0); /* section switch restarts it */
    record(api, &packet, &handle, 1, 2, 2); /* skip forward */
    reject_index(api, &handle, 1, 65536);
    reject_index(api, &handle, 1, INT_MAX);
    reject_index(api, &handle, 1, -2);
    reject_index(api, &handle, 1, INT_MIN);
    reject_index(api, &handle, 4, 0);
    reject_index(api, &handle, -1, 0);
    record(api, &packet, &handle, 1, 0, 0); /* recovery after rejected calls */
}

static void framing(struct api api) {
    struct packet packet;
    ns_msg handle;
    fixture(&packet, 3);
    for (size_t length = 0; length < packet.size; ++length) {
        *api.error() = 0;
        ++calls;
        require(api.init(packet.bytes, (int)length, &handle) == -1, "reject every truncated frame prefix");
        require(*api.error() == EMSGSIZE, "truncated frame reports EMSGSIZE");
    }
    packet.bytes[packet.size] = 0;
    *api.error() = 0;
    ++calls;
    require(api.init(packet.bytes, (int)packet.size + 1, &handle) == -1, "reject trailing bytes");
    require(*api.error() == EMSGSIZE, "trailing bytes report EMSGSIZE");

    /* A compression cycle can be skipped structurally, but cannot be expanded. */
    size_t owner = packet.starts[1];
    packet.bytes[owner] = (unsigned char)(0xc0 | (owner >> 8));
    packet.bytes[owner + 1] = (unsigned char)owner;
    initialize(api, &packet, &handle);
    ns_rr result, untouched;
    memset(&result, 0xa5, sizeof result);
    memcpy(&untouched, &result, sizeof result);
    *api.error() = 0;
    ++calls;
    require(api.parse(&handle, ns_s_an, 0, &result) == -1, "reject cyclic compressed owner");
    require(*api.error() == EMSGSIZE, "malformed owner reports EMSGSIZE");
    if (candidate) require(memcmp(&result, &untouched, sizeof result) == 0,
                           "malformed record does not publish a partial result");

    fixture(&packet, 3);
    initialize(api, &packet, &handle);
    /* Corruption after initialization must still be caught by ns_parserr. */
    packet.bytes[packet.starts[1] + 10] = 0xff;
    packet.bytes[packet.starts[1] + 11] = 0xff;
    *api.error() = 0;
    ++calls;
    require(api.parse(&handle, ns_s_an, 0, &result) == -1, "reject payload overrun after initialization");
    require(*api.error() == EMSGSIZE, "payload overrun reports EMSGSIZE");
}

static void empty_sections(struct api api) {
    unsigned char empty[12] = {0};
    ns_msg handle;
    ++calls;
    require(api.init(empty, sizeof empty, &handle) == 0, "empty DNS message");
    for (int section = 0; section < 4; ++section) {
        require(handle._sections[section] == NULL, "empty sections have null start pointers");
        reject_index(api, &handle, section, -1);
    }
}

static void long_iteration(struct api api) {
    struct packet packet;
    ns_msg handle;
    fixture(&packet, 2048);
    initialize(api, &packet, &handle);
    for (int index = 0; index < 2048; ++index)
        record(api, &packet, &handle, 1, -1, index);
    reject_index(api, &handle, 1, -1);
    /* Ascending explicit indices must maintain the same incremental cursor. */
    for (int index = 0; index < 2048; ++index)
        record(api, &packet, &handle, 1, index, index);
}

int main(int argc, char **argv) {
    require(argc == 2, "usage: native_dns_cursor --host|/path/to/libfrankenlibc_abi.so");
    int host = strcmp(argv[1], "--host") == 0;
    candidate = !host;
    void *handle = dlopen(host ? "libresolv.so.2" : argv[1], RTLD_NOW | RTLD_LOCAL);
    if (!handle) { fprintf(stderr, "dlopen: %s\n", dlerror()); return 1; }
    const char *owner = host ? NULL : argv[1];
    struct api api = {
        .init = (init_fn)symbol(handle, "ns_initparse", owner),
        .parse = (parse_fn)symbol(handle, "ns_parserr", owner),
        .error = (errno_fn)symbol(handle, "__errno_location", owner),
    };
    mixed_iteration(api);
    framing(api);
    empty_sections(api);
    long_iteration(api);
    printf("PASS: %lu DNS parser ABI calls (%s)\n", calls, host ? "host oracle" : "candidate");
    return 0;
}
