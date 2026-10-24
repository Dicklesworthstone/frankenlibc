/* Host-glibc oracle only; never claim this validates FrankenLibC.
 * Build: cc -std=c11 -O2 -Wall -Wextra -Werror
 *   tests/conformance/native_candidate_search_host.c -ldl -o /tmp/candidate-host
 * Run: python3 -S tests/conformance/native_candidate_search_host.py /tmp/candidate-host
 * Sanitizers: add -O1 -g -fsanitize=address,undefined -fno-omit-frame-pointer
 *   -fno-pie -no-pie. The driver removes LD_PRELOAD from each probe process.
 */
#define _GNU_SOURCE
#include <assert.h>
#include <dlfcn.h>
#include <stdio.h>
#include <string.h>
int main(int argc, char **argv) {
    assert(argc == 3 || argc == 4);
    int succeeds = strcmp(argv[2], "success") == 0;
    void *handle = dlopen(argv[1], RTLD_NOW | RTLD_LOCAL);
    if (!succeeds) {
        assert(handle == NULL);
        const char *error = dlerror();
        assert(error != NULL);
        printf("expected rejection: %s\n", error);
        return 0;
    }
    if (!handle) fprintf(stderr, "unexpected load error: %s\n", dlerror());
    assert(handle);
    void *symbol = dlsym(handle, "candidate_entry");
    assert(symbol);
    int (*entry)(void);
    _Static_assert(sizeof entry == sizeof symbol, "supported ELF64 function pointer");
    memcpy(&entry, &symbol, sizeof entry);
    assert(entry() == 74);
    if (argc == 4) {
        FILE *file = fopen(argv[1], "r+b");
        assert(file);
        assert(fseek(file, 4, SEEK_SET) == 0);
        assert(fputc(1, file) == 1);
        assert(fclose(file) == 0);
        void *again = dlopen(argv[1], RTLD_NOW | RTLD_LOCAL);
        assert(again == handle);
        assert(entry() == 74);
        assert(dlclose(again) == 0);
    }
    assert(dlclose(handle) == 0);
    puts("compatible library selected");
    return 0;
}
