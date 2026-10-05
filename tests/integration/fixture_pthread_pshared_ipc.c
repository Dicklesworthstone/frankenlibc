/* Process-shared rwlock, barrier and sem_t across fork()ed processes in a
 * MAP_SHARED mapping: blocking waits must be woken from another process,
 * which needs shared (non-FUTEX_PRIVATE) futexes. Output must match glibc
 * (bd-rc0923-epic-eeuy4f.15).
 */
#define _GNU_SOURCE
#include <pthread.h>
#include <semaphore.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

struct shm {
    pthread_rwlock_t rw;
    pthread_barrier_t bar;
    sem_t sem;
    sem_t done;
    volatile int counter;
    volatile int phase;
};

static long now_ms(void) {
    struct timespec t;
    clock_gettime(CLOCK_MONOTONIC, &t);
    return t.tv_sec * 1000 + t.tv_nsec / 1000000;
}

int main(void) {
    struct shm *s = mmap(NULL, sizeof *s, PROT_READ | PROT_WRITE, MAP_SHARED | MAP_ANONYMOUS, -1, 0);
    pthread_rwlockattr_t ra;
    pthread_rwlockattr_init(&ra);
    int r = pthread_rwlockattr_setpshared(&ra, PTHREAD_PROCESS_SHARED);
    printf("rwlockattr_setpshared=%d\n", r);
    printf("rwlock_init=%d\n", pthread_rwlock_init(&s->rw, &ra));
    pthread_barrierattr_t ba;
    pthread_barrierattr_init(&ba);
    printf("barrierattr_setpshared=%d\n", pthread_barrierattr_setpshared(&ba, PTHREAD_PROCESS_SHARED));
    printf("barrier_init=%d\n", pthread_barrier_init(&s->bar, &ba, 3));
    printf("sem_init=%d\n", sem_init(&s->sem, 1, 0));
    printf("sem_init done=%d\n", sem_init(&s->done, 1, 0));
    fflush(stdout);

    /* 1. writer lock held by parent blocks a child's rdlock until released. */
    pthread_rwlock_wrlock(&s->rw);
    pid_t c1 = fork();
    if (c1 == 0) {
        long t0 = now_ms();
        int rc = pthread_rwlock_rdlock(&s->rw);
        long waited = now_ms() - t0;
        int saw = s->phase;
        pthread_rwlock_unlock(&s->rw);
        _exit(rc == 0 && saw == 1 && waited >= 150 ? 0 : 10 + rc);
    }
    usleep(200000);
    s->phase = 1;
    pthread_rwlock_unlock(&s->rw);
    int st;
    waitpid(c1, &st, 0);
    printf("rwlock cross-process: %s\n", WIFEXITED(st) && WEXITSTATUS(st) == 0 ? "ok" : "FAIL");

    /* 2. sem_t: child posts, parent waits (blocking across processes). */
    pid_t c2 = fork();
    if (c2 == 0) {
        usleep(100000);
        for (int i = 0; i < 5; i++)
            sem_post(&s->sem);
        _exit(0);
    }
    int got = 0;
    for (int i = 0; i < 5; i++)
        got += sem_wait(&s->sem) == 0;
    waitpid(c2, &st, 0);
    int v = -1;
    sem_getvalue(&s->sem, &v);
    printf("sem cross-process: waits=%d value=%d\n", got, v);

    /* 3. barrier across 3 processes; exactly one PTHREAD_BARRIER_SERIAL_THREAD. */
    s->counter = 0;
    pid_t kids[2];
    for (int k = 0; k < 2; k++) {
        kids[k] = fork();
        if (kids[k] == 0) {
            usleep(50000 * (k + 1));
            int rc = pthread_barrier_wait(&s->bar);
            if (rc == PTHREAD_BARRIER_SERIAL_THREAD)
                __atomic_fetch_add(&s->counter, 1, __ATOMIC_SEQ_CST);
            sem_post(&s->done);
            _exit(rc == 0 || rc == PTHREAD_BARRIER_SERIAL_THREAD ? 0 : 1);
        }
    }
    int rc = pthread_barrier_wait(&s->bar);
    if (rc == PTHREAD_BARRIER_SERIAL_THREAD)
        __atomic_fetch_add(&s->counter, 1, __ATOMIC_SEQ_CST);
    int ok = rc == 0 || rc == PTHREAD_BARRIER_SERIAL_THREAD;
    for (int k = 0; k < 2; k++) {
        waitpid(kids[k], &st, 0);
        ok &= WIFEXITED(st) && WEXITSTATUS(st) == 0;
    }
    sem_wait(&s->done);
    sem_wait(&s->done);
    printf("barrier cross-process: %s serial=%d\n", ok ? "ok" : "FAIL", s->counter);

    /* 4. many readers across processes concurrently, writer excluded. */
    s->counter = 0;
    pid_t rd[4];
    for (int k = 0; k < 4; k++) {
        rd[k] = fork();
        if (rd[k] == 0) {
            for (int i = 0; i < 2000; i++) {
                pthread_rwlock_wrlock(&s->rw);
                int c = s->counter;
                s->counter = c + 1;
                pthread_rwlock_unlock(&s->rw);
            }
            _exit(0);
        }
    }
    for (int k = 0; k < 4; k++)
        waitpid(rd[k], &st, 0);
    printf("rwlock wrlock contention across 4 processes: counter=%d\n", s->counter);
    return 0;
}
