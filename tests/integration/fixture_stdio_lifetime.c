#define _GNU_SOURCE 1
#include <dlfcn.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

/* Refer directly to all four objects so the non-PIC build exercises actual
 * executable COPY relocations, including chain-head updates after startup. */
extern FILE *_IO_list_all;

static void fail(const char *message) {
    ssize_t written = write(STDERR_FILENO, message, strlen(message));
    _exit(written < 0 ? 2 : 1);
}

#define STRINGIFY_INNER(value) #value
#define STRINGIFY(value) STRINGIFY_INNER(value)
#define CHECK(condition) do { \
    if (!(condition)) fail("stdio-lifetime:" STRINGIFY(__LINE__) ": " #condition "\n"); \
} while (0)

struct native_api {
    int (*print)(const char *, ...);
    int (*fprint)(FILE *, const char *, ...);
    int (*get_char)(void);
    FILE *(*open_memory)(char **, size_t *);
    FILE *(*open_fixed)(void *, size_t, const char *);
    size_t (*write_bytes)(const void *, size_t, size_t, FILE *);
    int (*flush)(FILE *);
    int (*close)(FILE *);
    void (*release)(void *);
    void *(*head)(void);
    FILE **cells[3];
    FILE **list;
};

static void *symbol(void *handle, const char *name, void *base) {
    void *address = dlsym(handle, name);
    Dl_info info;
    CHECK(address && dladdr(address, &info) != 0 && info.dli_fbase == base);
    return address;
}

static struct native_api native_api(void *handle) {
    struct native_api api;
    void *head = dlsym(handle, "_IO_list_all_get");
    Dl_info info;
    CHECK(head && dladdr(head, &info) != 0);
    void *base = info.dli_fbase;
    api.head = head;
    api.print = symbol(handle, "printf", base);
    api.fprint = symbol(handle, "fprintf", base);
    api.get_char = symbol(handle, "getchar", base);
    api.open_memory = symbol(handle, "open_memstream", base);
    api.open_fixed = symbol(handle, "fmemopen", base);
    api.write_bytes = symbol(handle, "fwrite", base);
    api.flush = symbol(handle, "fflush", base);
    api.close = symbol(handle, "fclose", base);
    api.release = symbol(handle, "free", base);
    api.cells[0] = dlsym(handle, "stdin");
    api.cells[1] = dlsym(handle, "stdout");
    api.cells[2] = dlsym(handle, "stderr");
    api.list = dlsym(handle, "_IO_list_all");
    CHECK(api.list);
    for (unsigned i = 0; i < 3; ++i) {
        CHECK(api.cells[i] && *api.cells[i]);
        /* Real FILE objects are required, not the internal sentinel IDs. */
        CHECK(((*api.cells[i])->_flags & 0xffff0000u) == 0xfbad0000u);
        CHECK((*api.cells[i])->_fileno == (int)i);
    }
    CHECK(*api.list && api.head() == *api.list);
    return api;
}

static void check_head(const struct native_api *api, FILE *head, int preload) {
    CHECK(*api->list == head && api->head() == head);
    if (preload) {
        FILE **visible = dlsym(RTLD_DEFAULT, "_IO_list_all");
        CHECK(visible && *visible == head && _IO_list_all == head);
    }
}

static void exercise_native(struct native_api *api, int preload) {
    FILE *initial = *api->list;
    char *first_bytes = NULL, *second_bytes = NULL;
    size_t first_len = 0, second_len = 0;
    FILE *first = api->open_memory(&first_bytes, &first_len);
    CHECK(first);
    check_head(api, first, preload);
    FILE *second = api->open_memory(&second_bytes, &second_len);
    CHECK(second);
    check_head(api, second, preload);

    FILE **output_cell = preload ? &stdout : api->cells[1];
    FILE *old_output = *output_cell;
    *output_cell = first;
    CHECK(api->print("native:%d", 17) == 9);
    *output_cell = old_output;
    CHECK(api->write_bytes("second", 1, 6, second) == 6);

    /* Remove a non-head, then the head. The COPY cell must follow each change. */
    CHECK(api->close(first) == 0);
    check_head(api, second, preload);
    CHECK(first_len == 9 && memcmp(first_bytes, "native:17", 10) == 0);
    api->release(first_bytes);
    CHECK(api->close(second) == 0);
    check_head(api, initial, preload);
    CHECK(second_len == 6 && memcmp(second_bytes, "second", 7) == 0);
    api->release(second_bytes);

    char input_bytes[] = "Z";
    FILE *input = api->open_fixed(input_bytes, 1, "r");
    CHECK(input);
    check_head(api, input, preload);
    FILE **input_cell = preload ? &stdin : api->cells[0];
    FILE *old_input = *input_cell;
    *input_cell = input;
    CHECK(api->get_char() == 'Z');
    *input_cell = old_input;
    CHECK(api->close(input) == 0);
    check_head(api, initial, preload);

    char *error_bytes = NULL;
    size_t error_len = 0;
    FILE *error = api->open_memory(&error_bytes, &error_len);
    CHECK(error);
    FILE **error_cell = preload ? &stderr : api->cells[2];
    FILE *old_error = *error_cell;
    *error_cell = error;
    CHECK(api->fprint(*error_cell, "native-error:%d", 19) == 15);
    *error_cell = old_error;
    CHECK(api->close(error) == 0);
    check_head(api, initial, preload);
    CHECK(error_len == 15 && memcmp(error_bytes, "native-error:19", 16) == 0);
    api->release(error_bytes);
}

/* fflush(NULL) explicitly requests every output stream, including host-owned
 * streams. Test that contract separately from preservation during dlclose. */
static void check_flush_all(int (*flush)(FILE *)) {
    FILE *host = tmpfile();
    CHECK(host);
    char buffering[128];
    CHECK(setvbuf(host, buffering, _IOFBF, sizeof buffering) == 0);
    const char pending[] = "explicit-flush";
    for (size_t i = 0; i < sizeof pending - 1; ++i) CHECK(fputc(pending[i], host) != EOF);
    int fd = fileno(host);
    CHECK(lseek(fd, 0, SEEK_CUR) == 0);
    CHECK(flush(NULL) == 0);
    CHECK(lseek(fd, 0, SEEK_CUR) == (off_t)(sizeof pending - 1));
    CHECK(fseek(host, 0, SEEK_SET) == 0);
    char readback[sizeof pending] = {0};
    CHECK(fread(readback, 1, sizeof pending - 1, host) == sizeof pending - 1);
    CHECK(memcmp(readback, pending, sizeof pending) == 0);
    CHECK(fclose(host) == 0);
}

static void check_host(FILE ***cells, FILE **values, FILE **saved) {
    for (unsigned i = 0; i < 4; ++i) CHECK(*cells[i] == values[i]);
    CHECK(stdin == saved[0] && stdout == saved[1] && stderr == saved[2]);
    CHECK(_IO_list_all == values[3]);
}

static void local_lifetime(const char *library) {
    FILE *host = tmpfile();
    CHECK(host);
    char buffering[128];
    CHECK(setvbuf(host, buffering, _IOFBF, sizeof buffering) == 0);
    const char pending[] = "host-pending";
    for (size_t i = 0; i < sizeof pending - 1; ++i) CHECK(fputc(pending[i], host) != EOF);
    int fd = fileno(host);
    CHECK(lseek(fd, 0, SEEK_CUR) == 0);
    const char *names[] = { "stdin", "stdout", "stderr", "_IO_list_all" };
    FILE **cells[4], *values[4], *saved[] = { stdin, stdout, stderr };
    for (unsigned i = 0; i < 4; ++i) {
        cells[i] = dlsym(RTLD_DEFAULT, names[i]);
        CHECK(cells[i]);
        values[i] = *cells[i];
    }
    for (unsigned cycle = 0; cycle < 3; ++cycle) {
        void *handle = dlopen(library, RTLD_NOW | RTLD_LOCAL);
        CHECK(handle);
        check_host(cells, values, saved);
        struct native_api api = native_api(handle);
        exercise_native(&api, 0);
        check_host(cells, values, saved);
        CHECK(lseek(fd, 0, SEEK_CUR) == 0);
        CHECK(dlclose(handle) == 0);
        check_host(cells, values, saved);
    }
    CHECK(fflush(NULL) == 0);
    CHECK(lseek(fd, 0, SEEK_CUR) == (off_t)(sizeof pending - 1));
    CHECK(fseek(host, 0, SEEK_SET) == 0);
    char readback[sizeof pending] = {0};
    CHECK(fread(readback, 1, sizeof pending - 1, host) == sizeof pending - 1);
    CHECK(memcmp(readback, pending, sizeof pending) == 0);

    /* A separate load proves that the native NULL-stream flush reaches a
     * buffered host FILE, without confusing it with implicit lifetime effects. */
    void *handle = dlopen(library, RTLD_NOW | RTLD_LOCAL);
    CHECK(handle);
    struct native_api api = native_api(handle);
    check_flush_all(api.flush);
    CHECK(dlclose(handle) == 0);
    check_host(cells, values, saved);
    CHECK(fclose(host) == 0);
}

static void preload_lifetime(const char *library) {
    /* These direct reads precede any ABI call: constructor COPY publication
     * cannot wait for a later printf/fflush to initialize the visible cells. */
    CHECK(stdin && stdout && stderr && _IO_list_all);
    CHECK((stdin->_flags & 0xffff0000u) == 0xfbad0000u && stdin->_fileno == 0);
    CHECK((stdout->_flags & 0xffff0000u) == 0xfbad0000u && stdout->_fileno == 1);
    CHECK((stderr->_flags & 0xffff0000u) == 0xfbad0000u && stderr->_fileno == 2);
    void *handle = dlopen(library, RTLD_NOW | RTLD_NOLOAD);
    CHECK(handle);
    struct native_api api = native_api(handle);
    CHECK(stdin == *api.cells[0] && stdout == *api.cells[1] && stderr == *api.cells[2]);
    check_head(&api, *api.list, 1);
    exercise_native(&api, 1);
    CHECK(api.flush(NULL) == 0);
    CHECK(dlclose(handle) == 0);
}

int main(int argc, char **argv) {
    CHECK(argc == 3);
    alarm(15);
    if (strcmp(argv[2], "local") == 0) local_lifetime(argv[1]);
    else if (strcmp(argv[2], "preload") == 0) preload_lifetime(argv[1]);
    else if (strcmp(argv[2], "host-flush") == 0) check_flush_all(fflush);
    else fail("stdio-lifetime: unknown deployment\n");
    CHECK(printf("stdio-lifetime:%s:PASS\n", argv[2]) > 0);
    CHECK(fprintf(stderr, "stdio-lifetime:%s:stderr-alive\n", argv[2]) > 0);
    CHECK(fflush(NULL) == 0);
    return 0;
}
