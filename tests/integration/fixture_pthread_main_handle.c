/* Calls another thread makes on the main thread's pthread_t (bd-5aw3u6),
 * compared line for line with host glibc by ld_preload_smoke.sh.
 *
 * fl names the main thread by its tid, and every call it forwarded with that
 * value -- to glibc (join, detach, tryjoin_np, timedjoin_np) or to its own
 * read of glibc's thread descriptor (get/setschedparam, setschedprio) --
 * dereferenced the tid as a pointer: SIGSEGV. */
#define _GNU_SOURCE
#include <errno.h>
#include <pthread.h>
#include <sched.h>
#include <signal.h>
#include <stdio.h>
#include <string.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

static pthread_t main_thread;

static void *worker(void *arg) {
    (void)arg;
    struct sched_param sp;
    int policy = -1;
    int r = pthread_getschedparam(main_thread, &policy, &sp);
    printf("getschedparam %d policy=%d prio=%d\n", r, policy, sp.sched_priority);
    printf("setschedparam %d\n", pthread_setschedparam(main_thread, policy, &sp));
    printf("setschedprio %d\n", pthread_setschedprio(main_thread, sp.sched_priority));
    printf("kill0 %d\n", pthread_kill(main_thread, 0));
    printf("tryjoin_np %d\n", pthread_tryjoin_np(main_thread, NULL));
    struct timespec ts;
    clock_gettime(CLOCK_REALTIME, &ts);
    ts.tv_nsec += 20 * 1000 * 1000;
    if (ts.tv_nsec >= 1000000000L) {
        ts.tv_sec++;
        ts.tv_nsec -= 1000000000L;
    }
    printf("timedjoin_np %d\n", pthread_timedjoin_np(main_thread, NULL, &ts));
    printf("detach %d\n", pthread_detach(main_thread));
    return NULL;
}

static int run(const char *who) {
    printf("%s\n", who);
    main_thread = pthread_self();
    pthread_t t;
    if (pthread_create(&t, NULL, worker, NULL) != 0) {
        return 1;
    }
    pthread_join(t, NULL);
    /* The main thread on itself: a join deadlocks. */
    printf("self join %d\n", pthread_join(pthread_self(), NULL) == EDEADLK);
    fflush(stdout);
    return 0;
}

int main(void) {
    if (run("process") != 0) {
        return 1;
    }
    /* A fork child's only thread is its main thread. */
    pid_t kid = fork();
    if (kid == 0) {
        _exit(run("fork child"));
    }
    int status = 0;
    waitpid(kid, &status, 0);
    printf("child status %d\n", status);
    return 0;
}
