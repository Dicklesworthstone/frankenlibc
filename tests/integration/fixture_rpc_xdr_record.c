#define _GNU_SOURCE
#include <arpa/inet.h>
#include <dlfcn.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <unistd.h>

/* GNU's LP64 XDR prefix, independent of libtirpc headers and libraries. */
typedef struct Xdr Xdr;
typedef struct {
    int (*getlong)(Xdr *, long *);
    int (*putlong)(Xdr *, const long *);
    int (*getbytes)(Xdr *, char *, unsigned);
    int (*putbytes)(Xdr *, const char *, unsigned);
    unsigned (*getpos)(const Xdr *);
    int (*setpos)(Xdr *, unsigned);
    int32_t *(*inline_bytes)(Xdr *, unsigned);
    void (*destroy)(Xdr *);
    int (*getint32)(Xdr *, int32_t *);
    int (*putint32)(Xdr *, const int32_t *);
} Ops;
struct Xdr {
    int op;
    const Ops *ops;
    char *public_data;
    void *private_data;
    char *base;
    unsigned handy;
};
_Static_assert(sizeof(Xdr) == 48 && offsetof(Xdr, ops) == 8, "GNU LP64 XDR");
typedef int (*Io)(void *, void *, int);
static void (*create)(Xdr *, unsigned, unsigned, void *, Io, Io);
static int (*skip)(Xdr *);
static int (*eof)(Xdr *);
static int (*end)(Xdr *, int);

#define CHECK(x) do { if (!(x)) { fprintf(stderr, "FAIL %s:%d: %s errno=%d\n", __func__, __LINE__, #x, errno); exit(1); } } while (0)
static void wrong_provider(void) {
    static const char text[] = "WRONG XDR RECORD PROVIDER\n";
    if (write(2, text, sizeof(text)-1) != (ssize_t)(sizeof(text)-1)) _Exit(114);
    _Exit(113);
}
static void provider(void *pointer) {
    const char *candidate = getenv("FRANKENLIBC_TEST_LIBRARY");
    if (candidate) {
        Dl_info info;
        struct stat a, b;
        if (!pointer || !dladdr(pointer, &info) || !info.dli_fname
            || stat(candidate, &a) || stat(info.dli_fname, &b)
            || a.st_dev != b.st_dev || a.st_ino != b.st_ino) wrong_provider();
    } else CHECK(pointer != NULL);
}
static void *symbol(const char *name) {
    void *p;
    if (getenv("FRANKENLIBC_TEST_LIBRARY") && !getenv("RPC_TEST_FORCE_HOST"))
        p = dlsym(RTLD_DEFAULT, name);
    else {
        void *lib = dlopen("libc.so.6", RTLD_NOW | RTLD_LOCAL);
        CHECK(lib);
        p = dlvsym(lib, name, "GLIBC_2.2.5");
    }
    provider(p);
    return p;
}
static void pin_ops(const Xdr *x) {
    provider((void *)x->ops->getlong);
    provider((void *)x->ops->putlong);
    provider((void *)x->ops->getbytes);
    provider((void *)x->ops->putbytes);
    provider((void *)x->ops->getpos);
    provider((void *)x->ops->setpos);
    provider((void *)x->ops->inline_bytes);
    provider((void *)x->ops->destroy);
}

typedef struct {
    unsigned char input[16384], output[16384];
    size_t input_size, cursor, output_size, chunk;
    unsigned reads, writes, requests[256], write_sizes[256];
    int fail_read, write_result, fd;
} Channel;
static Channel *file_channel;
static int read_bytes(void *handle, void *buffer, int count) {
    Channel *c = handle;
    CHECK(count > 0 && c->reads < 256);
    c->requests[c->reads++] = (unsigned)count;
    if (c->fail_read && c->reads >= (unsigned)c->fail_read) { errno = EIO; return -1; }
    size_t n = c->input_size - c->cursor;
    if (n > (size_t)count) n = (size_t)count;
    if (c->chunk && n > c->chunk) n = c->chunk;
    if (!n) { errno = ENODATA; return -1; }
    memcpy(buffer, c->input + c->cursor, n);
    c->cursor += n;
    return (int)n;
}
static int write_bytes(void *handle, void *buffer, int count) {
    Channel *c = handle;
    CHECK(count > 0 && c->writes < 256);
    CHECK(c->output_size + (size_t)count <= sizeof(c->output));
    c->write_sizes[c->writes++] = (unsigned)count;
    memcpy(c->output + c->output_size, buffer, (size_t)count);
    c->output_size += (size_t)count;
    if (c->write_result) {
        errno = EIO;
        if (c->write_result == 1) return -1;
        if (c->write_result == 2) return 0;
        if (c->write_result == 3) return count - 1;
        return count + 1;
    }
    return count;
}
static int fd_read(void *handle, void *buffer, int count) {
    Channel *c = file_channel;
    CHECK(c && (int)(intptr_t)handle == c->fd && c->reads < 256 && count > 0);
    c->requests[c->reads++] = (unsigned)count;
    if (c->chunk && (size_t)count > c->chunk) count = (int)c->chunk;
    ssize_t n = read(c->fd, buffer, (size_t)count);
    return n == 0 ? -1 : (int)n;
}
static int fd_write(void *handle, void *buffer, int count) {
    Channel *c = file_channel;
    CHECK(c && (int)(intptr_t)handle == c->fd && c->writes < 256 && count > 0);
    c->write_sizes[c->writes++] = (unsigned)count;
    return (int)write(c->fd, buffer, (size_t)count);
}
static Xdr stream(Channel *c, unsigned size, int op) {
    Xdr x;
    memset(&x, 0, sizeof(x));
    x.op = op;
    create(&x, size, size, c, read_bytes, write_bytes);
    CHECK(x.ops && x.private_data);
    pin_ops(&x);
    return x;
}
static void word(unsigned char *p, uint32_t value) {
    value = htonl(value);
    memcpy(p, &value, 4);
}
static uint32_t load_word(const unsigned char *p) {
    uint32_t value;
    memcpy(&value, p, 4);
    return ntohl(value);
}
static void fragment(Channel *c, const void *data, size_t size, int last) {
    CHECK(c->input_size + size + 4 <= sizeof(c->input));
    word(c->input + c->input_size, (uint32_t)size | (last ? 0x80000000u : 0));
    if (size) memcpy(c->input + c->input_size + 4, data, size);
    c->input_size += size + 4;
}
static void record_word(Channel *c, uint32_t value) {
    unsigned char bytes[4];
    word(bytes, value);
    fragment(c, bytes, sizeof(bytes), 1);
}
static void put(Xdr *x, uint32_t value) {
    long word_value = (long)value;
    CHECK(x->ops->putlong(x, &word_value) == 1);
}
static void get(Xdr *x, uint32_t expected) {
    long value = 0;
    CHECK(x->ops->getlong(x, &value) == 1);
    CHECK(value == (long)(int32_t)expected);
}

static void create_case(void) {
    Channel c = {0};
    record_word(&c, 42);
    Xdr x = {0};
    x.op = 1; x.public_data = (char *)(uintptr_t)0x1234;
    x.base = (char *)(uintptr_t)0x2345; x.handy = 0x3456;
    create(&x, 0, 0, &c, read_bytes, write_bytes);
    CHECK(x.ops && x.private_data);
    pin_ops(&x);
    CHECK(x.op == 1 && x.public_data == (char *)(uintptr_t)0x1234);
    CHECK(x.base == (char *)(uintptr_t)0x2345 && x.handy == 0x3456);
    long value = 77;
    CHECK(x.ops->getlong(&x, &value) == 0 && value == 77 && c.reads == 0);
    CHECK(eof(&x) == 1 && c.reads == 0);
    CHECK(skip(&x) == 1 && c.reads == 0);
    get(&x, 42);
    CHECK(c.reads == 1 && c.requests[0] == 4000);
    x.ops->destroy(&x);
    CHECK(c.writes == 0);
}

static void fragments_case(size_t chunk) {
    Channel c = {0}; c.chunk = chunk;
    const unsigned char value[] = {0x11,0x22,0x33,0x44};
    fragment(&c, value, 1, 0);
    fragment(&c, value+1, 2, 0);
    fragment(&c, value+3, 1, 1);
    fragment(&c, NULL, 0, 1);
    record_word(&c, 0xaabbccdd);
    Xdr x = stream(&c, 100, 1);
    CHECK(skip(&x) == 1 && c.reads == 0);
    get(&x, 0x11223344);
    long sentinel = 91;
    CHECK(x.ops->getlong(&x, &sentinel) == 0 && sentinel == 91);
    CHECK(skip(&x) == 1);
    CHECK(x.ops->getlong(&x, &sentinel) == 0 && sentinel == 91);
    CHECK(skip(&x) == 1);
    get(&x, 0xaabbccdd);
    CHECK(eof(&x) == 1);
    x.ops->destroy(&x);
}

static void zero_fragment_case(void) {
    Channel c = {0};
    fragment(&c, NULL, 0, 0); record_word(&c, 42);
    Xdr x = stream(&c, 100, 1);
    CHECK(skip(&x) == 1);
    long sentinel = 77;
    CHECK(x.ops->getlong(&x, &sentinel) == 0 && sentinel == 77);
    get(&x, 42);
    CHECK(eof(&x) == 1);
    x.ops->destroy(&x);
}

static void navigation_case(void) {
    Channel c = {0};
    unsigned char values[12];
    word(values, 10); word(values+4, 20); word(values+8, 30);
    fragment(&c, values, 5, 0); fragment(&c, values+5, 7, 1);
    record_word(&c, 40); record_word(&c, 50);
    Xdr x = stream(&c, 100, 1);
    CHECK(skip(&x) == 1); get(&x, 10);
    CHECK(skip(&x) == 1); get(&x, 40);
    unsigned before = c.reads;
    CHECK(eof(&x) == 0 && c.reads == before);
    CHECK(skip(&x) == 1); get(&x, 50);
    CHECK(eof(&x) == 1 && c.reads == before);
    CHECK(eof(&x) == 1 && c.reads == before);
    x.ops->destroy(&x);
}

static void eof_consumes_case(void) {
    Channel c = {0};
    unsigned char bytes[12];
    word(bytes, 1); word(bytes+4, 2); word(bytes+8, 3);
    fragment(&c, bytes, 2, 0); fragment(&c, bytes+2, 10, 1);
    record_word(&c, 99);
    Xdr x = stream(&c, 100, 1);
    CHECK(skip(&x) == 1); get(&x, 1);
    CHECK(eof(&x) == 0);
    long sentinel = 77;
    CHECK(x.ops->getlong(&x, &sentinel) == 0 && sentinel == 77);
    CHECK(skip(&x) == 1); get(&x, 99);
    CHECK(eof(&x) == 1);
    x.ops->destroy(&x);
}

static void boundary_case(void) {
    Channel c = {0};
    record_word(&c, 0x12345678); record_word(&c, 0x87654321);
    Xdr x = stream(&c, 100, 1);
    CHECK(skip(&x) == 1);
    unsigned char bytes[12]; memset(bytes, 0xa5, sizeof(bytes));
    CHECK(x.ops->getbytes(&x, (char *)bytes+2, 8) == 0);
    CHECK(load_word(bytes+2) == 0x12345678);
    CHECK(bytes[0] == 0xa5 && bytes[1] == 0xa5);
    for (unsigned i=6; i<sizeof(bytes); i++) CHECK(bytes[i] == 0xa5);
    CHECK(skip(&x) == 1); get(&x, 0x87654321);
    x.ops->destroy(&x);
}

static void read_error_case(int body) {
    Channel c = {0}; c.chunk = body ? 5 : 2; c.fail_read = 2;
    record_word(&c, 42);
    Xdr x = stream(&c, 100, 1);
    CHECK(skip(&x) == 1);
    long sentinel = 77; errno = 0;
    CHECK(x.ops->getlong(&x, &sentinel) == 0 && sentinel == 77 && errno == EIO);
    CHECK(c.reads == 2);
    x.ops->destroy(&x);
}

static void read_error_retry_case(void) {
    Channel c = {0}; c.chunk = 2; c.fail_read = 2;
    record_word(&c, 42);
    Xdr x = stream(&c, 100, 1);
    CHECK(skip(&x) == 1);
    long sentinel = 77;
    CHECK(x.ops->getlong(&x, &sentinel) == 0 && sentinel == 77 && c.reads == 2);
    /* A failed partial marker has consumed bytes; GNU does not replay them. */
    c.fail_read = 0;
    CHECK(x.ops->getlong(&x, &sentinel) == 0 && sentinel == 77);
    CHECK(c.cursor == c.input_size && c.reads == 6 && errno == ENODATA);
    x.ops->destroy(&x);
}

static void batch_case(int abandon) {
    Channel c = {0};
    Xdr x = stream(&c, 100, 0);
    put(&x, 42); CHECK(end(&x, 0) == 1 && c.writes == 0);
    CHECK(end(&x, 0) == 1 && c.writes == 0);
    if (abandon) { x.ops->destroy(&x); CHECK(c.writes == 0); return; }
    put(&x, 85); CHECK(end(&x, 1) == 1 && c.writes == 1);
    CHECK(c.output_size == 20 && c.write_sizes[0] == 20);
    const uint32_t expected[] = {0x80000004,42,0x80000000,0x80000004,85};
    for (unsigned i=0; i<5; i++) CHECK(load_word(c.output+4*i) == expected[i]);
    x.ops->destroy(&x);
    CHECK(c.writes == 1);
}

static void output_fragments_case(unsigned size, size_t length) {
    Channel c = {0};
    unsigned char payload[1024];
    CHECK(length <= sizeof(payload));
    for (size_t i=0; i<length; i++) payload[i] = (unsigned char)(i*17+3);
    Xdr x = stream(&c, size, 0);
    CHECK(x.ops->putbytes(&x, (char *)payload, (unsigned)length) == 1);
    unsigned normalized = size < 100 ? 4000 : (size+3) & ~3u;
    unsigned before = c.writes;
    CHECK(end(&x, 0) == 1);
    if (length + 8 < normalized) {
        CHECK(before == 0 && c.writes == 0);
        CHECK(end(&x, 1) == 1);
        CHECK(c.output_size == length + 8);
        CHECK(load_word(c.output) == (0x80000000u | (uint32_t)length));
        CHECK(memcmp(c.output+4, payload, length) == 0);
        CHECK(load_word(c.output+4+length) == 0x80000000u);
    } else {
        CHECK(c.writes > 0);
        size_t pos = 0, data = 0;
        for (unsigned i=0; i<c.writes; i++) {
            uint32_t marker = load_word(c.output+pos);
            size_t fragment_size = marker & 0x7fffffffu;
            CHECK(fragment_size + 4 == c.write_sizes[i]);
            CHECK(fragment_size <= normalized-4 && data + fragment_size <= length);
            CHECK((marker >> 31) == (i+1 == c.writes));
            CHECK(memcmp(c.output+pos+4, payload+data, fragment_size) == 0);
            data += fragment_size; pos += 4+fragment_size;
        }
        CHECK(data == length && pos == c.output_size);
    }
    x.ops->destroy(&x);
}

static void sizes_case(void) {
    const unsigned sizes[] = {0,1,99,100,101,102,103,104};
    for (unsigned i=0; i<sizeof(sizes)/sizeof(sizes[0]); i++) {
        output_fragments_case(sizes[i], 92);
        output_fragments_case(sizes[i], 96);
        output_fragments_case(sizes[i], 300);
        Channel c = {0}; record_word(&c, 42);
        Xdr x = stream(&c, sizes[i], 1);
        CHECK(skip(&x) == 1); get(&x, 42);
        CHECK(c.requests[0] == (sizes[i] < 100 ? 4000 : (sizes[i]+3)&~3u));
        x.ops->destroy(&x);
    }
}

static void odd_batch_case(void) {
    Channel c = {0};
    Xdr x = stream(&c, 100, 0);
    CHECK(x.ops->putbytes(&x, "abc", 3) == 1);
    CHECK(end(&x, 0) == 1 && c.writes == 0);
    put(&x, 42); CHECK(end(&x, 0) == 1 && c.writes == 0);
    unsigned char payload[97];
    for (unsigned i=0; i<sizeof(payload); i++) payload[i] = (unsigned char)i;
    CHECK(x.ops->putbytes(&x, (char *)payload, sizeof(payload)) == 1);
    CHECK(c.writes == 1 && c.write_sizes[0] == 100);
    CHECK(end(&x, 0) == 1 && c.writes == 2 && c.write_sizes[1] == 20);
    CHECK(c.output_size == 120);
    CHECK(load_word(c.output) == 0x80000003u && memcmp(c.output+4, "abc", 3) == 0);
    CHECK(load_word(c.output+7) == 0x80000004u && load_word(c.output+11) == 42);
    CHECK(load_word(c.output+15) == 81 && memcmp(c.output+19, payload, 81) == 0);
    CHECK(load_word(c.output+100) == 0x80000010u && memcmp(c.output+104, payload+81, 16) == 0);
    x.ops->destroy(&x);
}

static void write_error_case(void) {
    for (int result=1; result<=4; result++) {
        Channel c = {0}; c.write_result = result;
        Xdr x = stream(&c, 100, 0);
        put(&x, 42); errno = 0;
        CHECK(end(&x, 1) == 0 && c.writes == 1 && errno == EIO);
        CHECK(c.write_sizes[0] == 8 && load_word(c.output) == 0x80000004u);
        x.ops->destroy(&x); CHECK(c.writes == 1);
    }
}

static void inline_case(void) {
    Channel c = {0};
    Xdr x = stream(&c, 100, 0);
    int32_t *p = x.ops->inline_bytes(&x, 12);
    CHECK(p && (uintptr_t)p % 4 == 0);
    const uint32_t values[] = {1,0x88776655,3};
    for (unsigned i=0; i<3; i++) word((unsigned char *)p+4*i, values[i]);
    CHECK(x.ops->inline_bytes(&x, 100) == NULL);
    CHECK(end(&x, 1) == 1 && c.output_size == 16);
    CHECK(load_word(c.output) == 0x8000000c);
    x.ops->destroy(&x);
    memcpy(c.input, c.output, c.output_size); c.input_size = c.output_size;
    x = stream(&c, 100, 1);
    CHECK(skip(&x) == 1);
    CHECK(x.ops->inline_bytes(&x, 4) == NULL && c.reads == 0);
    get(&x, 1);
    CHECK(x.ops->inline_bytes(&x, 12) == NULL);
    p = x.ops->inline_bytes(&x, 8);
    CHECK(p && (uintptr_t)p % 4 == 0);
    CHECK(load_word((unsigned char *)p) == values[1]);
    CHECK(load_word((unsigned char *)p+4) == values[2]);
    long sentinel = 77;
    CHECK(x.ops->getlong(&x, &sentinel) == 0 && sentinel == 77);
    x.ops->destroy(&x);
}

static void position_case(int decode) {
    Channel c = {0}; c.fd = memfd_create("xdrrec-fixture", MFD_CLOEXEC); CHECK(c.fd >= 0);
    file_channel = &c;
    Xdr x = {0}; x.op = decode;
    if (decode) {
        unsigned char payload[16];
        for (unsigned i=0; i<4; i++) word(payload+4*i, 10*(i+1));
        fragment(&c, payload, 16, 1); record_word(&c, 50);
        CHECK(write(c.fd, c.input, c.input_size) == (ssize_t)c.input_size);
        CHECK(lseek(c.fd, 0, SEEK_SET) == 0);
    }
    create(&x, 100, 100, (void *)(intptr_t)c.fd, fd_read, fd_write);
    CHECK(x.ops && x.private_data); pin_ops(&x);
    if (decode) {
        CHECK(x.ops->getpos(&x) == 0); CHECK(skip(&x) == 1);
        get(&x, 10); unsigned saved = x.ops->getpos(&x); CHECK(saved == 8);
        get(&x, 20); CHECK(x.ops->getpos(&x) == 12);
        CHECK(x.ops->setpos(&x, saved) == 1); get(&x, 20);
        /* GNU's observable legacy adjustment leaves no fragment bytes here. */
        long value = 77;
        CHECK(x.ops->getlong(&x, &value) == 0 && value == 77);
        CHECK(x.ops->setpos(&x, 0) == 0);
    } else {
        CHECK(x.ops->getpos(&x) == 4);
        unsigned slot = x.ops->getpos(&x); put(&x, 0);
        put(&x, 0x12345678); put(&x, 0xabcdef01);
        unsigned finish = x.ops->getpos(&x); CHECK(finish == 16);
        CHECK(x.ops->setpos(&x, slot) == 1); put(&x, 8);
        CHECK(x.ops->setpos(&x, finish) == 1);
        CHECK(x.ops->setpos(&x, 0) == 0 && x.ops->setpos(&x, 100) == 0);
        CHECK(end(&x, 1) == 1 && x.ops->getpos(&x) == 20);
        unsigned char bytes[16]; CHECK(pread(c.fd, bytes, sizeof(bytes), 0) == 16);
        CHECK(load_word(bytes) == 0x8000000c && load_word(bytes+4) == 8);
        CHECK(load_word(bytes+8) == 0x12345678 && load_word(bytes+12) == 0xabcdef01);
    }
    unsigned reads = c.reads, writes = c.writes;
    x.ops->destroy(&x);
    CHECK(fcntl(c.fd, F_GETFD) >= 0 && reads == c.reads && writes == c.writes);
    CHECK(close(c.fd) == 0); file_channel = NULL;
}

static void socket_case(void) {
    int pair[2]; CHECK(socketpair(AF_UNIX, SOCK_STREAM|SOCK_CLOEXEC, 0, pair) == 0);
    Channel c = {0}; c.fd = pair[0]; c.chunk = 1; file_channel = &c;
    record_word(&c, 0x12345678); record_word(&c, 0xabcdef01);
    CHECK(write(pair[1], c.input, c.input_size) == (ssize_t)c.input_size);
    CHECK(shutdown(pair[1], SHUT_WR) == 0);
    Xdr x = {0}; x.op = 1;
    create(&x, 100, 100, (void *)(intptr_t)c.fd, fd_read, fd_write);
    CHECK(x.ops && x.private_data); pin_ops(&x);
    errno = 0; CHECK(x.ops->getpos(&x) == UINT_MAX && errno == ESPIPE);
    CHECK(x.ops->setpos(&x, 0) == 0);
    CHECK(skip(&x) == 1); get(&x, 0x12345678);
    CHECK(skip(&x) == 1); get(&x, 0xabcdef01);
    CHECK(c.reads == 16 && eof(&x) == 1);
    x.ops->destroy(&x);
    CHECK(fcntl(pair[0], F_GETFD) >= 0);
    CHECK(close(pair[0]) == 0 && close(pair[1]) == 0); file_channel = NULL;
}

static int invalid_read(void *handle, void *buffer, int count) {
    (void)buffer;
    Channel *c = handle; c->reads++;
    CHECK(c->reads == 1);
    return c->fail_read ? count+1 : 0;
}
static void native_boundary_case(void) {
    CHECK(getenv("FRANKENLIBC_TEST_LIBRARY"));
    for (int bad_count=0; bad_count<2; bad_count++) {
        Channel c = {0}; c.fail_read = bad_count;
        Xdr x = {0}; x.op = 1;
        create(&x, 100, 100, &c, invalid_read, write_bytes);
        CHECK(x.ops && x.private_data); pin_ops(&x); CHECK(skip(&x) == 1);
        long value = 77;
        CHECK(x.ops->getlong(&x, &value) == 0 && value == 77 && c.reads == 1);
        x.ops->destroy(&x);
    }
    Xdr x; memset(&x, 0xa5, sizeof(x)); Xdr original = x;
    errno = 0;
    create(&x, UINT_MAX, 100, NULL, read_bytes, write_bytes);
    CHECK(errno == ENOMEM && memcmp(&x, &original, sizeof(x)) == 0);
    errno = 0;
    create(&x, 100, 0x80000000u, NULL, read_bytes, write_bytes);
    CHECK(errno == ENOMEM && memcmp(&x, &original, sizeof(x)) == 0);
    Channel c = {0}; c.fd = memfd_create("xdrrec-invalid-position", MFD_CLOEXEC); CHECK(c.fd >= 0);
    file_channel = &c;
    memset(&x, 0, sizeof(x));
    create(&x, 100, 100, (void *)(intptr_t)c.fd, fd_read, fd_write);
    CHECK(x.ops && x.private_data); pin_ops(&x);
    /* Unlike returned payload positions, these point inside a wire marker. */
    for (unsigned pos=0; pos<4; pos++) CHECK(x.ops->setpos(&x, pos) == 0);
    put(&x, 42); CHECK(end(&x, 1) == 1);
    unsigned char bytes[8]; CHECK(pread(c.fd, bytes, sizeof(bytes), 0) == 8);
    CHECK(load_word(bytes) == 0x80000004u && load_word(bytes+4) == 42);
    x.ops->destroy(&x); CHECK(close(c.fd) == 0); file_channel = NULL;
}

int main(int argc, char **argv) {
    CHECK(argc == 2);
    alarm(8);
    create = symbol("xdrrec_create"); skip = symbol("xdrrec_skiprecord");
    eof = symbol("xdrrec_eof"); end = symbol("xdrrec_endofrecord");
    if (getenv("RPC_TEST_FORCE_HOST_OPS")) {
        void *host = dlopen("libc.so.6", RTLD_NOW | RTLD_LOCAL);
        CHECK(host);
        create = dlvsym(host, "xdrrec_create", "GLIBC_2.2.5");
        CHECK(create);
    }
    const char *name = argv[1];
    if (!strcmp(name,"create")) create_case();
    else if (!strcmp(name,"split-1")) fragments_case(1);
    else if (!strcmp(name,"split-2")) fragments_case(2);
    else if (!strcmp(name,"split-3")) fragments_case(3);
    else if (!strcmp(name,"split-5")) fragments_case(5);
    else if (!strcmp(name,"coalesced")) fragments_case(100);
    else if (!strcmp(name,"zero-nonterminal")) zero_fragment_case();
    else if (!strcmp(name,"navigation")) navigation_case();
    else if (!strcmp(name,"eof-consumes")) eof_consumes_case();
    else if (!strcmp(name,"record-boundary")) boundary_case();
    else if (!strcmp(name,"read-error-marker")) read_error_case(0);
    else if (!strcmp(name,"read-error-body")) read_error_case(1);
    else if (!strcmp(name,"read-error-retry")) read_error_retry_case();
    else if (!strcmp(name,"batch")) batch_case(0);
    else if (!strcmp(name,"destroy-deferred")) batch_case(1);
    else if (!strcmp(name,"output-fragments")) output_fragments_case(100,300);
    else if (!strcmp(name,"buffer-sizes")) sizes_case();
    else if (!strcmp(name,"odd-batch")) odd_batch_case();
    else if (!strcmp(name,"write-errors")) write_error_case();
    else if (!strcmp(name,"inline")) inline_case();
    else if (!strcmp(name,"position-encode")) position_case(0);
    else if (!strcmp(name,"position-decode")) position_case(1);
    else if (!strcmp(name,"socket")) socket_case();
    else if (!strcmp(name,"native-boundaries")) native_boundary_case();
    else CHECK(0);
    printf("PASS %s\n", name);
    return 0;
}
