/* sem_post wakes a sem_timedwait waiter (thread and process) at once.
 *
 * sem_post skips FUTEX_WAKE when no waiter is registered in the sem_t, and
 * fl's sem_timedwait never registered: every timed waiter slept until its
 * deadline after a post. CPython's multiprocessing Barrier (timed SemLock
 * waits) stalled for its full timeouts and test_processes timed out.
 * Output is "promptly" (< 1 s) or "late", compared byte-for-byte with glibc.
 */
#define _GNU_SOURCE
#include <pthread.h>
#include <semaphore.h>
#include <stdio.h>
#include <sys/mman.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

static double now(void) {
    struct timespec t;
    clock_gettime(CLOCK_MONOTONIC, &t);
    return t.tv_sec + t.tv_nsec / 1e9;
}

static int timed_wait(sem_t *s) {
    struct timespec deadline;
    clock_gettime(CLOCK_REALTIME, &deadline);
    deadline.tv_sec += 5;
    return sem_timedwait(s, &deadline);
}

static sem_t thread_sem;
static double woke_after;

static void *waiter(void *arg) {
    (void)arg;
    double t0 = now();
    int r = timed_wait(&thread_sem);
    woke_after = r == 0 ? now() - t0 : 99;
    return NULL;
}

int main(void) {
    setvbuf(stdout, NULL, _IONBF, 0);
    sem_init(&thread_sem, 0, 0);
    pthread_t t;
    pthread_create(&t, NULL, waiter, NULL);
    usleep(100000);
    sem_post(&thread_sem);
    pthread_join(t, NULL);
    printf("thread waiter: %s\n", woke_after < 1.0 ? "promptly" : "late");

    sem_t *shared = mmap(NULL, sizeof(sem_t), PROT_READ | PROT_WRITE, MAP_SHARED | MAP_ANONYMOUS, -1, 0);
    sem_init(shared, 1, 0);
    pid_t pid = fork();
    if (pid == 0) {
        double t0 = now();
        int r = timed_wait(shared);
        _exit(r == 0 && now() - t0 < 1.0 ? 0 : 1);
    }
    usleep(100000);
    sem_post(shared);
    int status;
    waitpid(pid, &status, 0);
    printf("process waiter: %s\n", WEXITSTATUS(status) == 0 ? "promptly" : "late");
    return 0;
}
