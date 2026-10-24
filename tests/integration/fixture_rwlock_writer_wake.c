/* Writers contending on a pthread rwlock must never sleep on a free lock.
 *
 * fl's wrlock retried its CAS(0 -> -1), then waited on whatever value it
 * read next. When the holder released in between, that value was 0: the
 * writer went to sleep "until the lock stops being 0", after the unlock had
 * already woken everyone. A later unlock would rescue it, so it hangs only
 * when the lock then goes quiet -- as when the other threads finish. OpenSSL's
 * CRYPTO_THREAD_write_lock under 8 Python threads hung about one run in 30.
 *
 * Many short phases, each ending with every thread done, give that window
 * thousands of chances. A watchdog turns a hang into a failing exit; the
 * output is deterministic.
 */
#include <pthread.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/time.h>
#include <unistd.h>

#ifndef THREADS
#define THREADS 4
#endif
#ifndef PHASES
#define PHASES 4000
#endif
#ifndef WRITES
#define WRITES 4
#endif

static pthread_rwlock_t lock = PTHREAD_RWLOCK_INITIALIZER;
static long counter;

static void *worker(void *arg) {
    (void)arg;
    for (int i = 0; i < WRITES; i++) {
        pthread_rwlock_wrlock(&lock);
        counter++;
        pthread_rwlock_unlock(&lock);
    }
    return NULL;
}

static void tick(int sig) { (void)sig; }

/* Oversubscribe the CPUs: the race needs a writer preempted between its
 * failed CAS and its reload (it hung only while the box was loaded). */
static volatile int done;
static void *spinner(void *arg) {
    (void)arg;
    while (!done) {
    }
    return NULL;
}

int main(void) {
    /* A signal landing between a writer's failed CAS and its reload widens
     * the window from a few instructions to the handler's run time. */
    struct sigaction sa = {0};
    sa.sa_handler = tick;
    sa.sa_flags = SA_RESTART;
    sigaction(SIGPROF, &sa, NULL);
    struct itimerval every = {{0, 20}, {0, 20}};
    setitimer(ITIMER_PROF, &every, NULL);
    /* Watchdog: SIGALRM's default action kills the process on a hang. */
    alarm(60);
    long cpus = sysconf(_SC_NPROCESSORS_ONLN);
    int spinners = cpus > 0 && cpus < 64 ? (int)(2 * cpus) : 16;
    pthread_t spin[128];
    for (int s = 0; s < spinners; s++) {
        pthread_create(&spin[s], NULL, spinner, NULL);
    }
    for (int phase = 0; phase < PHASES; phase++) {
        pthread_t threads[THREADS];
        for (int t = 0; t < THREADS; t++) {
            if (pthread_create(&threads[t], NULL, worker, NULL) != 0) {
                return 1;
            }
        }
        for (int t = 0; t < THREADS; t++) {
            pthread_join(threads[t], NULL);
        }
    }
    done = 1;
    for (int s = 0; s < spinners; s++) {
        pthread_join(spin[s], NULL);
    }
    long expected = (long)PHASES * THREADS * WRITES;
    printf("rwlock writers: counter=%ld expected=%ld\n", counter, expected);
    return counter == expected ? 0 : 1;
}
