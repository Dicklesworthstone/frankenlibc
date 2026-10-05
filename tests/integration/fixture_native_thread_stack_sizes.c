/* Check the actual C-ABI stack alignment with non-aligned pthread stack sizes.
 *
 * gcc -std=c11 -O2 -Wall -Wextra -Werror -pthread \
 *   tests/integration/fixture_native_thread_stack_sizes.c -ldl -o /tmp/native-stacks
 * /tmp/native-stacks
 * FRANKENLIBC_THREAD_NATIVE=1 FRANKENLIBC_MODE=strict \
 *   LD_PRELOAD=target/release/libfrankenlibc_abi.so /tmp/native-stacks --require-native
 * Repeat with FRANKENLIBC_MODE=hardened.
 *
 * The assembly entry point observes the incoming stack before a compiler prologue
 * can hide misalignment. It uses no libc or host TLS on the native child.
 */
#define _GNU_SOURCE
#include <dlfcn.h>
#include <inttypes.h>
#include <pthread.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#if defined(__x86_64__)
extern void *entry_alignment(void *arg);
__asm__(".text\n"
        ".p2align 4\n"
        ".globl entry_alignment\n"
        ".hidden entry_alignment\n"
        ".type entry_alignment, @function\n"
        "entry_alignment:\n"
        "endbr64\n"
        "mov %rsp, %rax\n"
        "and $15, %eax\n"
        "ret\n"
        ".size entry_alignment, .-entry_alignment\n");
#define EXPECTED_ALIGNMENT 8u
#elif defined(__aarch64__)
extern void *entry_alignment(void *arg);
__asm__(".text\n"
        ".p2align 4\n"
        ".globl entry_alignment\n"
        ".hidden entry_alignment\n"
        ".type entry_alignment, %function\n"
        "entry_alignment:\n"
        "hint #34\n"
        "mov x0, sp\n"
        "and x0, x0, #15\n"
        "ret\n"
        ".size entry_alignment, .-entry_alignment\n");
#define EXPECTED_ALIGNMENT 0u
#else
int main(void) {
    puts("SKIP: native stack fixture requires x86-64 or AArch64");
    return 77;
}
#endif

#if defined(__x86_64__) || defined(__aarch64__)
int main(int argc, char **argv) {
    if (argc > 2 || (argc == 2 && strcmp(argv[1], "--require-native") != 0)) {
        fprintf(stderr, "usage: %s [--require-native]\n", argv[0]);
        return 2;
    }
    if (argc == 2) {
        /* Do not count a missing/ignored preload as a native-runtime pass. */
        const char *native = getenv("FRANKENLIBC_THREAD_NATIVE");
        void *symbol = dlsym(RTLD_DEFAULT, "pthread_create");
        Dl_info provider;
        if (native == NULL || strcmp(native, "1") != 0 || symbol == NULL ||
            dladdr(symbol, &provider) == 0 || provider.dli_fname == NULL ||
            strstr(provider.dli_fname, "frankenlibc") == NULL) {
            fputs("native backend required: set FRANKENLIBC_THREAD_NATIVE=1 and "
                  "preload libfrankenlibc_abi.so\n", stderr);
            return 1;
        }
    }
    const size_t bases[] = {128u * 1024u, 256u * 1024u};
    unsigned checked = 0;
    for (size_t base = 0; base < sizeof(bases) / sizeof(bases[0]); ++base) {
        for (size_t residue = 0; residue < 16; ++residue) {
            const size_t size = bases[base] + residue;
            pthread_attr_t attr;
            int rc = pthread_attr_init(&attr);
            if (rc != 0) {
                fprintf(stderr, "attr_init: %d\n", rc);
                return 1;
            }
            rc = pthread_attr_setstacksize(&attr, size);
            if (rc != 0) {
                fprintf(stderr, "setstacksize(%zu): %d\n", size, rc);
                pthread_attr_destroy(&attr);
                return 1;
            }
            pthread_t thread;
            rc = pthread_create(&thread, &attr, entry_alignment, NULL);
            int destroy_rc = pthread_attr_destroy(&attr);
            if (rc != 0) {
                fprintf(stderr, "pthread_create(%zu): %d\n", size, rc);
                return 1;
            }
            void *value = NULL;
            rc = pthread_join(thread, &value);
            if (rc != 0 || destroy_rc != 0) {
                fprintf(stderr, "join/destroy(%zu): %d/%d\n", size, rc, destroy_rc);
                return 1;
            }
            if ((uintptr_t)value != EXPECTED_ALIGNMENT) {
                fprintf(stderr, "entry alignment(%zu): %" PRIuPTR " (expected %u)\n",
                        size, (uintptr_t)value, EXPECTED_ALIGNMENT);
                return 1;
            }
            ++checked;
        }
    }
    printf("thread-stack-sizes: %u passed (%s)\n", checked,
           argc == 2 ? "native requested" : "baseline");
    return 0;
}
#endif
