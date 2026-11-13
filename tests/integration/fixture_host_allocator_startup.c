/* FrankenLibC must initialize the real host heap before hosted workers can
 * reach hidden libc allocations. An executable-owned allocator keeps that
 * heap cold, and a raw program-break snapshot witnesses the actual allocation
 * without depending on private glibc arena offsets. Workers start in a
 * constructor and remain parked until main has checked the snapshot. */
#define _GNU_SOURCE
#include <dlfcn.h>
#include <errno.h>
#include <pthread.h>
#include <stdatomic.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/wait.h>
#include <unistd.h>

enum { WORKERS = 4 };
static _Alignas(64) unsigned char app_heap[64 * 1024 * 1024];
static atomic_size_t app_used;
static atomic_uint foreign_frees;
static uintptr_t creator_thread_pointer;
static atomic_int inspect_first_create;
static atomic_uintptr_t first_create_allocator_break;
static uintptr_t raw_program_break(void);

static int app_owns(const void *pointer) {
    uintptr_t address = (uintptr_t)pointer;
    return address >= (uintptr_t)app_heap &&
        address < (uintptr_t)app_heap + sizeof(app_heap);
}

static void *app_allocate(size_t length, size_t alignment) {
    /* The host start context is allocated by the creator before it calls
     * the real pthread_create. Observe that first interposed allocation too:
     * warming from a newly running worker would be too late. The warmup's
     * matched raw libc pair must never enter this application allocator. */
    if ((uintptr_t)__builtin_thread_pointer() == creator_thread_pointer &&
        atomic_load_explicit(&inspect_first_create, memory_order_relaxed)) {
        uintptr_t expected = 0;
        atomic_compare_exchange_strong_explicit(&first_create_allocator_break,
            &expected, raw_program_break(), memory_order_relaxed, memory_order_relaxed);
    }
    if (!length) length = 1;
    if (alignment < 16) alignment = 16;
    if ((alignment & (alignment - 1)) ||
        alignment > sizeof(app_heap) - 16 ||
        length > sizeof(app_heap) - alignment - 16) return NULL;
    size_t amount = length + alignment + 16;
    size_t offset = atomic_fetch_add_explicit(&app_used, amount, memory_order_relaxed);
    if (offset > sizeof(app_heap) - amount) return NULL;
    uintptr_t raw = (uintptr_t)(app_heap + offset + 16);
    unsigned char *result = (unsigned char *)
        ((raw + alignment - 1) & ~(uintptr_t)(alignment - 1));
    ((size_t *)result)[-1] = length;
    return result;
}

void *malloc(size_t length) { return app_allocate(length, 16); }

void free(void *pointer) {
    if (pointer && !app_owns(pointer))
        atomic_fetch_add_explicit(&foreign_frees, 1, memory_order_relaxed);
}

void *calloc(size_t count, size_t size) {
    if (size && count > SIZE_MAX / size) return NULL;
    size_t length = count * size;
    unsigned char *result = app_allocate(length, 16);
    if (result) for (size_t i = 0; i < length; ++i) result[i] = 0;
    return result;
}

void *realloc(void *pointer, size_t length) {
    if (pointer && !app_owns(pointer)) return NULL;
    unsigned char *result = app_allocate(length, 16);
    if (result && pointer) {
        size_t old = ((size_t *)pointer)[-1];
        for (size_t i = 0; i < old && i < length; ++i)
            result[i] = ((unsigned char *)pointer)[i];
    }
    return result;
}

int posix_memalign(void **out, size_t alignment, size_t length) {
    if (alignment < sizeof(void *) || (alignment & (alignment - 1))) return EINVAL;
    void *result = app_allocate(length, alignment);
    if (!result) return ENOMEM;
    *out = result;
    return 0;
}

void *memalign(size_t alignment, size_t length) {
    return app_allocate(length, alignment);
}

void *aligned_alloc(size_t alignment, size_t length) {
    return app_allocate(length, alignment);
}

/* No interposed syscall/errno/policy path may initialize the heap while taking
 * the preinit observation. Both supported targets use the Linux brk ABI. */
static uintptr_t raw_program_break(void) {
#if defined(__x86_64__)
    unsigned long result;
    __asm__ volatile("syscall" : "=a"(result) : "a"(SYS_brk), "D"(0UL)
                     : "rcx", "r11", "memory");
    return result;
#elif defined(__aarch64__)
    register unsigned long x0 __asm__("x0") = 0;
    register unsigned long x8 __asm__("x8") = SYS_brk;
    __asm__ volatile("svc 0" : "+r"(x0) : "r"(x8) : "memory", "cc");
    return x0;
#else
#error This fixture requires Linux x86-64 or AArch64.
#endif
}

static uintptr_t break_at_preinit, break_before_threads, break_after_threads;
static atomic_uintptr_t worker_thread_pointers[WORKERS];
static pthread_t workers[WORKERS];
static atomic_uint workers_ready;
static atomic_int release_workers;
static int creation_error;
static unsigned created_workers;
static unsigned char *retained_app_buffer;

static void preinit(void) { break_at_preinit = raw_program_break(); }
__attribute__((used, section(".preinit_array")))
static void (*preinit_slot)(void) = preinit;

static void *worker(void *argument) {
    size_t index = (size_t)(uintptr_t)argument;
    atomic_store_explicit(&worker_thread_pointers[index],
                          (uintptr_t)__builtin_thread_pointer(), memory_order_release);
    atomic_fetch_add_explicit(&workers_ready, 1, memory_order_release);
    while (!atomic_load_explicit(&release_workers, memory_order_acquire)) {}

    unsigned char *buffer = calloc(128, 1);
    if (!buffer || !app_owns(buffer)) return NULL;
    for (size_t i = 0; i < 128; ++i) {
        if (buffer[i] != 0) return NULL;
        buffer[i] = (unsigned char)(index + 17);
    }
    buffer = realloc(buffer, 256);
    if (!buffer || !app_owns(buffer)) return NULL;
    for (size_t i = 0; i < 128; ++i)
        if (buffer[i] != (unsigned char)(index + 17)) return NULL;
    return buffer;
}

__attribute__((constructor)) static void constructor_workers(void) {
    creator_thread_pointer = (uintptr_t)__builtin_thread_pointer();
    break_before_threads = raw_program_break();
    retained_app_buffer = malloc(128);
    if (!retained_app_buffer) {
        creation_error = ENOMEM;
        return;
    }
    for (size_t i = 0; i < 128; ++i) retained_app_buffer[i] = (unsigned char)i;
    for (size_t i = 0; i < WORKERS; ++i) {
        atomic_store_explicit(&inspect_first_create, i == 0, memory_order_relaxed);
        int result = pthread_create(&workers[i], NULL, worker, (void *)(uintptr_t)i);
        atomic_store_explicit(&inspect_first_create, 0, memory_order_relaxed);
        if (result) {
            creation_error = result;
            break;
        }
        ++created_workers;
    }
    break_after_threads = raw_program_break();
}

static void fail(const char *message, int code) {
    fprintf(stderr, "host-allocator-startup:%s\n", message);
    _Exit(code);
}

static int same_file(const char *first, const char *second) {
    struct stat a, b;
    return stat(first, &a) == 0 && stat(second, &b) == 0 &&
        a.st_dev == b.st_dev && a.st_ino == b.st_ino;
}

static const char *provider(void) {
    Dl_info info;
    void *address = dlsym(RTLD_DEFAULT, "pthread_create");
    if (!address || !dladdr(address, &info)) fail("provider-unavailable", 85);
    return info.dli_fname;
}

static void verify_provider(const char *expected) {
    static const char *names[] = {"pthread_create", "pthread_join", "fork"};
    for (size_t i = 0; i < sizeof(names) / sizeof(names[0]); ++i) {
        Dl_info info;
        void *address = dlsym(RTLD_DEFAULT, names[i]);
        if (!address || !dladdr(address, &info) || !same_file(info.dli_fname, expected))
            fail("provider-mismatch", 86);
    }
}

static void finish_workers(void) {
    atomic_store_explicit(&release_workers, 1, memory_order_release);
    for (size_t i = 0; i < WORKERS; ++i) {
        void *result = NULL;
        if (pthread_join(workers[i], &result) || !result || !app_owns(result))
            fail("worker-allocation-or-join", 90);
        for (size_t j = 0; j < 128; ++j)
            if (((unsigned char *)result)[j] != (unsigned char)(i + 17))
                fail("worker-buffer-changed", 90);
        free(result);
    }
    if (!app_owns(retained_app_buffer)) fail("application-allocator-bypassed", 91);
    for (size_t i = 0; i < 128; ++i)
        if (retained_app_buffer[i] != (unsigned char)i)
            fail("application-buffer-changed", 91);
    if (atomic_load_explicit(&foreign_frees, memory_order_relaxed))
        fail("host-pointer-reached-application-free", 91);
}

static void verify_child_thread(void) {
    pid_t child = fork();
    if (child < 0) fail("fork-failed", 92);
    if (child == 0) {
        pthread_t thread;
        void *result = NULL;
        uintptr_t child_creator = (uintptr_t)__builtin_thread_pointer();
        int error = pthread_create(&thread, NULL, worker, NULL);
        if (!error) error = pthread_join(thread, &result);
        if (error || !result || !app_owns(result) ||
            atomic_load_explicit(&worker_thread_pointers[0], memory_order_acquire) == child_creator ||
            atomic_load_explicit(&foreign_frees, memory_order_relaxed)) _Exit(1);
        _Exit(0);
    }
    int status = 0;
    if (waitpid(child, &status, 0) != child || !WIFEXITED(status) || WEXITSTATUS(status))
        fail("fork-child-hosted-thread", 92);
}

int main(int argc, char **argv) {
    if (creation_error || created_workers != WORKERS) fail("constructor-create-failed", 87);
    while (atomic_load_explicit(&workers_ready, memory_order_acquire) != WORKERS) {}
    for (size_t i = 0; i < WORKERS; ++i) {
        uintptr_t pointer = atomic_load_explicit(&worker_thread_pointers[i], memory_order_acquire);
        if (!pointer || pointer == creator_thread_pointer) fail("host-backend-mismatch", 89);
        for (size_t j = 0; j < i; ++j)
            if (pointer == atomic_load_explicit(&worker_thread_pointers[j], memory_order_acquire))
                fail("host-backend-mismatch", 89);
    }
    if (argc == 2 && strcmp(argv[1], "--provider") == 0) {
        const char *path = provider();
        finish_workers();
        puts(path);
        return 0;
    }
    if (argc != 3) fail("usage", 2);
    verify_provider(argv[1]);

    int require_prime = strcmp(argv[2], "reference") != 0;
    if (require_prime) {
        if (!break_at_preinit || break_after_threads <= break_at_preinit)
            fail("host-heap-remained-cold", 88);
        if (atomic_load_explicit(&first_create_allocator_break, memory_order_relaxed) <=
            break_at_preinit)
            fail("host-heap-cold-at-creator-allocation", 88);
        if (strcmp(argv[2], "startup") == 0) {
            if (break_before_threads <= break_at_preinit)
                fail("startup-did-not-prime-host-heap", 88);
        } else if (strcmp(argv[2], "constructor") == 0) {
            /* Delegated startup has not entered its main wrapper yet. The
             * executable-owned allocator suppresses hardened prewarming too,
             * so the first pthread_create must warm an actually cold heap. */
            if (break_before_threads != break_at_preinit)
                fail("constructor-did-not-enter-with-cold-host-heap", 88);
        } else {
            fail("unknown-initialization-case", 2);
        }
    }
    finish_workers();
    verify_child_thread();
    puts("host-allocator-startup:workers-and-application-allocator:PASS");
    if (require_prime) printf("host-allocator-startup:%s-prime:PASS\n", argv[2]);
    return 0;
}
