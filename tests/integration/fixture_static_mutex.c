// Mutexes that were never passed to pthread_mutex_init, only statically
// initialized, must keep the kind their initializer names.
//
// glibc's recursive and errorcheck initializers are not all zero: they set
// __kind. A libc that adopts every uninitialized mutex as NORMAL deadlocks on
// the first nested lock of a static C++ std::recursive_mutex -- libLLVM's
// constructor does that, which hung perf at startup. Cases run from a
// constructor as well as from main, since that is where it bit.
#define _GNU_SOURCE
#include <errno.h>
#include <pthread.h>
#include <stdio.h>
#include <string.h>
#include <time.h>

static pthread_mutex_t ctor_recursive = PTHREAD_RECURSIVE_MUTEX_INITIALIZER_NP;
static pthread_mutex_t recursive = PTHREAD_RECURSIVE_MUTEX_INITIALIZER_NP;
static pthread_mutex_t errorcheck = PTHREAD_ERRORCHECK_MUTEX_INITIALIZER_NP;
static pthread_mutex_t adaptive = PTHREAD_ADAPTIVE_MUTEX_INITIALIZER_NP;
static pthread_mutex_t timed = PTHREAD_MUTEX_INITIALIZER;
static pthread_mutex_t timed_recursive = PTHREAD_RECURSIVE_MUTEX_INITIALIZER_NP;
static pthread_mutex_t unlock_first = PTHREAD_ERRORCHECK_MUTEX_INITIALIZER_NP;
static char ctor_report[128];

static const char *name(int rc) { return rc ? strerrorname_np(rc) : "0"; }

__attribute__((constructor)) static void early(void) {
    int a = pthread_mutex_lock(&ctor_recursive);
    int b = pthread_mutex_lock(&ctor_recursive);
    int c = pthread_mutex_unlock(&ctor_recursive);
    int d = pthread_mutex_unlock(&ctor_recursive);
    snprintf(ctor_report, sizeof ctor_report, "ctor recursive: lock=%s relock=%s unlock=%s unlock=%s",
             name(a), name(b), name(c), name(d));
}

static void *other_thread_trylock(void *arg) {
    return (void *)(long)pthread_mutex_trylock(arg);
}

static struct timespec in_ms(long ms) {
    struct timespec ts;
    clock_gettime(CLOCK_REALTIME, &ts);
    ts.tv_nsec += ms * 1000000;
    ts.tv_sec += ts.tv_nsec / 1000000000;
    ts.tv_nsec %= 1000000000;
    return ts;
}

int main(void) {
    puts(ctor_report);

    printf("recursive: lock=%s", name(pthread_mutex_lock(&recursive)));
    printf(" relock=%s", name(pthread_mutex_lock(&recursive)));
    printf(" trylock=%s", name(pthread_mutex_trylock(&recursive)));
    pthread_t t;
    void *other;
    pthread_create(&t, NULL, other_thread_trylock, &recursive);
    pthread_join(t, &other);
    printf(" other-thread trylock=%s", name((int)(long)other));
    printf(" unlock x3=%s", name(pthread_mutex_unlock(&recursive)));
    printf(",%s", name(pthread_mutex_unlock(&recursive)));
    printf(",%s", name(pthread_mutex_unlock(&recursive)));
    printf(" extra unlock=%s\n", name(pthread_mutex_unlock(&recursive)));

    printf("errorcheck: unlock-unowned=%s", name(pthread_mutex_unlock(&unlock_first)));
    printf(" lock=%s", name(pthread_mutex_lock(&errorcheck)));
    printf(" relock=%s", name(pthread_mutex_lock(&errorcheck)));
    printf(" unlock=%s", name(pthread_mutex_unlock(&errorcheck)));
    printf(" unlock again=%s\n", name(pthread_mutex_unlock(&errorcheck)));

    printf("adaptive: lock=%s", name(pthread_mutex_lock(&adaptive)));
    printf(" trylock=%s", name(pthread_mutex_trylock(&adaptive)));
    printf(" unlock=%s\n", name(pthread_mutex_unlock(&adaptive)));

    struct timespec soon = in_ms(20);
    printf("timed normal: timedlock=%s", name(pthread_mutex_timedlock(&timed, &soon)));
    pthread_create(&t, NULL, other_thread_trylock, &timed);
    pthread_join(t, &other);
    printf(" other-thread trylock=%s", name((int)(long)other));
    printf(" unlock=%s\n", name(pthread_mutex_unlock(&timed)));

    soon = in_ms(20);
    printf("timed recursive: timedlock=%s", name(pthread_mutex_timedlock(&timed_recursive, &soon)));
    printf(" timedlock again=%s", name(pthread_mutex_timedlock(&timed_recursive, &soon)));
    printf(" unlock=%s", name(pthread_mutex_unlock(&timed_recursive)));
    printf(",%s\n", name(pthread_mutex_unlock(&timed_recursive)));
    return 0;
}
