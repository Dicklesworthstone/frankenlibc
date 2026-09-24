#define _GNU_SOURCE
#include <dlfcn.h>
#include <errno.h>
#include <fcntl.h>
#include <pthread.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

/* Test the same POSIX contract against glibc and explicitly owned candidate
 * symbols. Shared mappings deliberately have different virtual addresses.
 * https://pubs.opengroup.org/onlinepubs/9699919799/functions/pthread_condattr_getpshared.html
 */
#define API(X) \
 X(pthread_mutexattr_init) X(pthread_mutexattr_destroy) \
 X(pthread_mutexattr_settype) X(pthread_mutexattr_setpshared) \
 X(pthread_mutex_init) X(pthread_mutex_destroy) X(pthread_mutex_lock) \
 X(pthread_mutex_unlock) X(pthread_mutex_trylock) X(pthread_mutex_timedlock) \
 X(pthread_mutex_clocklock) X(pthread_condattr_init) X(pthread_condattr_destroy) \
 X(pthread_condattr_setpshared) X(pthread_condattr_setclock) X(pthread_cond_init) \
 X(pthread_cond_destroy) X(pthread_cond_wait) X(pthread_cond_timedwait) \
 X(pthread_cond_clockwait) X(pthread_cond_signal) X(pthread_cond_broadcast)
#define DECLARE(name) static __typeof__(&name) call_##name;
API(DECLARE)
#undef DECLARE

struct shared { pthread_mutex_t mutex; pthread_cond_t cond; int ready, go, done, value; };
static pid_t children[4];
static int checks;
static void stop_children(void) {
    for (int i = 0; i < 4; i++) if (children[i] > 0) kill(children[i], SIGKILL);
    for (int i = 0; i < 4; i++) if (children[i] > 0) {
        while (waitpid(children[i], NULL, 0) < 0 && errno == EINTR) {}
        children[i] = 0;
    }
}
static void check(int yes, const char *what) {
    if (!yes) { fprintf(stderr, "FAIL: %s (errno=%d)\n", what, errno); stop_children(); exit(1); }
    checks++;
}
static struct timespec deadline(clockid_t clock, long ms) {
    struct timespec ts; check(clock_gettime(clock, &ts) == 0, "clock_gettime");
    ts.tv_sec += ms / 1000; ts.tv_nsec += (ms % 1000) * 1000000;
    if (ts.tv_nsec >= 1000000000) { ts.tv_sec++; ts.tv_nsec -= 1000000000; }
    return ts;
}
static void pause_ms(long ms) { struct timespec ts = {ms/1000, (ms%1000)*1000000}; nanosleep(&ts, NULL); }
static void child_context(void) { memset(children, 0, sizeof children); alarm(10); }
static void joined(int slot) {
    int status; pid_t rc;
    do { rc = waitpid(children[slot], &status, 0); } while (rc < 0 && errno == EINTR);
    children[slot] = 0;
    check(rc > 0 && WIFEXITED(status) && WEXITSTATUS(status) == 0, "child completed successfully");
}
static void wait_parked(pid_t pid) {
    char path[80], text[256]; snprintf(path, sizeof path, "/proc/%ld/wchan", (long)pid);
    for (int i = 0; i < 3000; i++) {
        int fd = open(path, O_RDONLY); ssize_t n = fd < 0 ? -1 : read(fd, text, sizeof text-1);
        if (fd >= 0) close(fd);
        if (n > 0) { text[n] = 0; if (strstr(text, "futex")) { checks++; return; } }
        pause_ms(1);
    }
    check(0, "child reached a kernel futex wait (not just an uncontended fast path)");
}
static struct shared *new_mapping(int *fd) {
    *fd = memfd_create("frankenlibc-shared-sync", MFD_CLOEXEC);
    check(*fd >= 0 && ftruncate(*fd, sizeof(struct shared)) == 0, "shared backing file");
    void *p = mmap(NULL, sizeof(struct shared), PROT_READ|PROT_WRITE, MAP_SHARED, *fd, 0);
    check(p != MAP_FAILED, "parent mapping"); return p;
}
static struct shared *remap(int fd, struct shared *old) {
    struct shared *p = mmap(NULL, sizeof *p, PROT_READ|PROT_WRITE, MAP_SHARED, fd, 0);
    check(p != MAP_FAILED && p != old, "child uses a distinct virtual address");
    check(munmap(old, sizeof *old) == 0, "remove inherited mapping"); return p;
}
static void init_mutex(struct shared *s, int kind) {
    pthread_mutexattr_t a;
    check(call_pthread_mutexattr_init(&a) == 0, "mutex attr init");
    check(call_pthread_mutexattr_setpshared(&a, PTHREAD_PROCESS_SHARED) == 0, "shared mutex attr");
    check(call_pthread_mutexattr_settype(&a, kind) == 0, "mutex type");
    check(call_pthread_mutex_init(&s->mutex, &a) == 0, "shared mutex init");
    check(call_pthread_mutexattr_destroy(&a) == 0, "mutex attr destroy");
}
static void mutex_case(int kind, int use_clock) {
    int fd, ready[2]; struct shared *s = new_mapping(&fd); init_mutex(s, kind);
    check(pipe(ready) == 0, "ready pipe");
    check(call_pthread_mutex_lock(&s->mutex) == 0, "parent mutex lock");
    if (kind == PTHREAD_MUTEX_RECURSIVE) check(call_pthread_mutex_lock(&s->mutex) == 0, "recursive parent lock");
    pid_t child = fork(); check(child >= 0, "fork mutex waiter");
    if (child == 0) {
        child_context(); close(ready[0]); s = remap(fd, s);
        check(call_pthread_mutex_trylock(&s->mutex) == EBUSY, "shared trylock contention");
        struct timespec ts = deadline(use_clock ? CLOCK_MONOTONIC : CLOCK_REALTIME, 40);
        int rc = use_clock ? call_pthread_mutex_clocklock(&s->mutex, CLOCK_MONOTONIC, &ts)
                           : call_pthread_mutex_timedlock(&s->mutex, &ts);
        check(rc == ETIMEDOUT, "shared timed mutex timeout");
        check(write(ready[1], "R", 1) == 1, "publish timed wait completion");
        check(call_pthread_mutex_lock(&s->mutex) == 0, "shared blocking acquisition");
        s->value = 73; check(call_pthread_mutex_unlock(&s->mutex) == 0, "child shared unlock"); _exit(0);
    }
    children[0] = child; close(ready[1]); char c;
    check(read(ready[0], &c, 1) == 1, "child completed timeout"); close(ready[0]);
    wait_parked(child);
    if (kind == PTHREAD_MUTEX_RECURSIVE) {
        check(call_pthread_mutex_unlock(&s->mutex) == 0, "recursive partial unlock");
        check(s->value == 0, "recursive mutex still owns protected state");
    }
    check(call_pthread_mutex_unlock(&s->mutex) == 0, "parent wakes shared waiter"); joined(0);
    check(call_pthread_mutex_lock(&s->mutex) == 0 && s->value == 73, "cross-process publication");
    check(call_pthread_mutex_unlock(&s->mutex) == 0, "parent final unlock");
    check(call_pthread_mutex_destroy(&s->mutex) == 0, "shared mutex destroy");
    munmap(s, sizeof *s); close(fd);
}
static void cond_case(clockid_t clock, int kind, int broadcast) {
    int fd; struct shared *s = new_mapping(&fd); init_mutex(s, kind);
    pthread_condattr_t a;
    check(call_pthread_condattr_init(&a) == 0, "cond attr init");
    check(call_pthread_condattr_setpshared(&a, PTHREAD_PROCESS_SHARED) == 0, "shared cond attr");
    check(call_pthread_condattr_setclock(&a, clock) == 0, "condition clock");
    check(call_pthread_cond_init(&s->cond, &a) == 0, "shared cond init");
    check(call_pthread_condattr_destroy(&a) == 0, "cond attr destroy");
    int count = broadcast ? 3 : 1;
    for (int i = 0; i < count; i++) {
        pid_t child = fork(); check(child >= 0, "fork condition waiter");
        if (child == 0) {
            child_context(); s = remap(fd, s);
            check(call_pthread_mutex_lock(&s->mutex) == 0, "waiter lock"); s->ready++;
            while (!s->go) {
                struct timespec ts = deadline(clock, 5000); int rc;
                if (i == 0) rc = call_pthread_cond_wait(&s->cond, &s->mutex);
                else if (i == 1) rc = call_pthread_cond_timedwait(&s->cond, &s->mutex, &ts);
                else {
                    clockid_t other = clock == CLOCK_REALTIME ? CLOCK_MONOTONIC : CLOCK_REALTIME;
                    ts = deadline(other, 5000); rc = call_pthread_cond_clockwait(&s->cond, &s->mutex, other, &ts);
                }
                check(rc == 0, "cross-process condition wake and relock");
            }
            s->done++; check(call_pthread_mutex_unlock(&s->mutex) == 0, "waiter final unlock"); _exit(0);
        }
        children[i] = child;
    }
    int all_ready = 0;
    for (int i = 0; i < 3000; i++) {
        check(call_pthread_mutex_lock(&s->mutex) == 0, "parent checks condition predicate");
        if (s->ready == count) { all_ready = 1; break; }
        check(call_pthread_mutex_unlock(&s->mutex) == 0, "parent releases predicate"); pause_ms(1);
    }
    check(all_ready, "all waiters registered");
    for (int i = 0; i < count; i++) wait_parked(children[i]);
    s->go = 1;
    check((broadcast ? call_pthread_cond_broadcast(&s->cond) : call_pthread_cond_signal(&s->cond)) == 0, "shared notification");
    /* Keep the mutex held so returning waiters must park on its futex too. */
    pause_ms(25); check(s->done == 0, "waiters cannot return without mutex ownership");
    check(call_pthread_mutex_unlock(&s->mutex) == 0, "parent releases relock waiters");
    for (int i = 0; i < count; i++) joined(i);
    check(call_pthread_mutex_lock(&s->mutex) == 0 && s->done == count, "all shared waiters completed");
    struct timespec ts = deadline(clock, 40);
    check(call_pthread_cond_timedwait(&s->cond, &s->mutex, &ts) == ETIMEDOUT, "shared condition timeout");
    check(call_pthread_mutex_unlock(&s->mutex) == 0, "timeout retained mutex ownership");
    check(call_pthread_cond_destroy(&s->cond) == 0, "shared condition destroy");
    check(call_pthread_mutex_destroy(&s->mutex) == 0, "condition mutex destroy"); munmap(s, sizeof *s); close(fd);
}
int main(int argc, char **argv) {
    check(argc == 2 || argc == 3, "usage: fixture mutex|cond [candidate.so]"); alarm(60); atexit(stop_children);
    void *h = argc == 3 ? dlopen(argv[2], RTLD_NOW|RTLD_LOCAL) : RTLD_DEFAULT;
    if (argc == 3 && !h) { fprintf(stderr, "dlopen: %s\n", dlerror()); return 1; }
    void *owner = NULL;
#define LOAD(name) do { \
    void *p = dlsym(h, #name); check(p != NULL, #name " resolved"); \
    *(void **)(&call_##name) = p; \
    if (argc == 3) { Dl_info info; check(dladdr(p, &info) != 0, #name " owner known"); \
        if (!owner) owner = info.dli_fbase; \
        check(info.dli_fbase == owner && strstr(info.dli_fname, "libfrankenlibc_abi") != NULL, #name " owned by candidate"); } \
} while (0);
    API(LOAD)
#undef LOAD
    if (!strcmp(argv[1], "mutex")) {
        int kinds[] = {PTHREAD_MUTEX_NORMAL, PTHREAD_MUTEX_RECURSIVE, PTHREAD_MUTEX_ERRORCHECK, PTHREAD_MUTEX_ADAPTIVE_NP};
        for (int i = 0; i < 4; i++) for (int clock = 0; clock < 2; clock++) mutex_case(kinds[i], clock);
    } else if (!strcmp(argv[1], "cond")) {
        for (int clock = 0; clock < 2; clock++) for (int broadcast = 0; broadcast < 2; broadcast++)
            cond_case(clock ? CLOCK_MONOTONIC : CLOCK_REALTIME, broadcast ? PTHREAD_MUTEX_ERRORCHECK : PTHREAD_MUTEX_RECURSIVE, broadcast);
    } else check(0, "unknown case");
    printf("PASS: shared %s (%s), %d parent assertions; all children passed\n", argv[1], argc == 3 ? "candidate" : "host", checks);
    return 0;
}
