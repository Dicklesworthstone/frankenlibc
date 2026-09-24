// Process-shared, robust and priority-inheritance mutexes
// (bd-rc0923-epic-eeuy4f.15). Output must be byte-identical under host glibc
// and FrankenLibC.
#define _GNU_SOURCE
#include <errno.h>
#include <pthread.h>
#include <stdio.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

struct shared {
  pthread_mutex_t pshared;
  pthread_mutex_t robust;
  pthread_mutex_t robust_try;
  pthread_mutex_t robust_lost;
  pthread_mutex_t cv_mutex;
  pthread_cond_t cv;
  int ready;
};

static const char *name(int rc) {
  switch (rc) {
  case 0: return "0";
  case EBUSY: return "EBUSY";
  case EDEADLK: return "EDEADLK";
  case EPERM: return "EPERM";
  case EINVAL: return "EINVAL";
  case ETIMEDOUT: return "ETIMEDOUT";
  case EOWNERDEAD: return "EOWNERDEAD";
  case ENOTRECOVERABLE: return "ENOTRECOVERABLE";
  default: return strerror(rc);
  }
}

static int init_mutex(pthread_mutex_t *m, int type, int pshared, int robust, int protocol) {
  pthread_mutexattr_t a;
  pthread_mutexattr_init(&a);
  pthread_mutexattr_settype(&a, type);
  if (pshared) pthread_mutexattr_setpshared(&a, PTHREAD_PROCESS_SHARED);
  if (robust) pthread_mutexattr_setrobust(&a, PTHREAD_MUTEX_ROBUST);
  pthread_mutexattr_setprotocol(&a, protocol);
  int rc = pthread_mutex_init(m, &a);
  pthread_mutexattr_destroy(&a);
  return rc;
}

static void child_dies_holding(pthread_mutex_t *m) {
  pid_t p = fork();
  if (p == 0) {
    pthread_mutex_lock(m);
    _exit(0);
  }
  waitpid(p, NULL, 0);
}

static void *thread_dies_holding(void *m) {
  pthread_mutex_lock((pthread_mutex_t *)m);
  return NULL;
}

static pthread_mutex_t pi_mutex;
static long pi_counter;
static void *pi_worker(void *arg) {
  (void)arg;
  for (int i = 0; i < 20000; i++) {
    pthread_mutex_lock(&pi_mutex);
    pi_counter++;
    pthread_mutex_unlock(&pi_mutex);
  }
  return NULL;
}

static pthread_mutex_t robust_cv_mutex;
static pthread_cond_t robust_cv = PTHREAD_COND_INITIALIZER;
static int robust_cv_ready;
static void *robust_cv_signaller(void *arg) {
  (void)arg;
  usleep(50000);
  pthread_mutex_lock(&robust_cv_mutex);
  robust_cv_ready = 1;
  pthread_cond_signal(&robust_cv);
  pthread_mutex_unlock(&robust_cv_mutex);
  return NULL;
}

int main(void) {
  struct shared *sh = mmap(NULL, sizeof *sh, PROT_READ | PROT_WRITE,
                           MAP_SHARED | MAP_ANONYMOUS, -1, 0);
  if (sh == MAP_FAILED) return 1;

  // Process-shared mutex contended across fork.
  printf("pshared init=%s\n", name(init_mutex(&sh->pshared, PTHREAD_MUTEX_NORMAL, 1, 0, PTHREAD_PRIO_NONE)));
  pid_t p = fork();
  if (p == 0) {
    pthread_mutex_lock(&sh->pshared);
    usleep(200000);
    pthread_mutex_unlock(&sh->pshared);
    _exit(0);
  }
  usleep(50000);
  printf("pshared trylock while child holds=%s\n", name(pthread_mutex_trylock(&sh->pshared)));
  printf("pshared lock after child releases=%s\n", name(pthread_mutex_lock(&sh->pshared)));
  pthread_mutex_unlock(&sh->pshared);
  waitpid(p, NULL, 0);

  // Process-shared timed lock times out.
  pthread_mutex_lock(&sh->pshared);
  p = fork();
  if (p == 0) {
    struct timespec dl;
    clock_gettime(CLOCK_REALTIME, &dl);
    dl.tv_nsec += 50000000;
    if (dl.tv_nsec >= 1000000000) { dl.tv_sec++; dl.tv_nsec -= 1000000000; }
    _exit(pthread_mutex_timedlock(&sh->pshared, &dl) == ETIMEDOUT ? 0 : 1);
  }
  int st = 0;
  waitpid(p, &st, 0);
  pthread_mutex_unlock(&sh->pshared);
  printf("pshared timedlock in child: %s\n", WEXITSTATUS(st) == 0 ? "ETIMEDOUT" : "other");

  // Process-shared condition variable: parent waits, child signals.
  pthread_condattr_t ca;
  pthread_condattr_init(&ca);
  pthread_condattr_setpshared(&ca, PTHREAD_PROCESS_SHARED);
  printf("pshared cond init=%s\n", name(pthread_cond_init(&sh->cv, &ca)));
  pthread_condattr_destroy(&ca);
  init_mutex(&sh->cv_mutex, PTHREAD_MUTEX_NORMAL, 1, 0, PTHREAD_PRIO_NONE);
  p = fork();
  if (p == 0) {
    usleep(100000);
    pthread_mutex_lock(&sh->cv_mutex);
    sh->ready = 1;
    pthread_cond_signal(&sh->cv);
    pthread_mutex_unlock(&sh->cv_mutex);
    _exit(0);
  }
  pthread_mutex_lock(&sh->cv_mutex);
  int crc = 0;
  while (!sh->ready && crc == 0) crc = pthread_cond_wait(&sh->cv, &sh->cv_mutex);
  pthread_mutex_unlock(&sh->cv_mutex);
  waitpid(p, NULL, 0);
  printf("pshared cond wait woken by child: rc=%s ready=%d\n", name(crc), sh->ready);

  // Robust: owner process dies holding the lock.
  printf("robust init=%s\n", name(init_mutex(&sh->robust, PTHREAD_MUTEX_NORMAL, 1, 1, PTHREAD_PRIO_NONE)));
  child_dies_holding(&sh->robust);
  int rc = pthread_mutex_lock(&sh->robust);
  printf("lock after owner process died=%s\n", name(rc));
  printf("trylock by same owner=%s\n", name(pthread_mutex_trylock(&sh->robust)));
  printf("consistent=%s\n", name(pthread_mutex_consistent(&sh->robust)));
  printf("consistent again=%s\n", name(pthread_mutex_consistent(&sh->robust)));
  printf("unlock=%s\n", name(pthread_mutex_unlock(&sh->robust)));
  printf("unlock not owned=%s\n", name(pthread_mutex_unlock(&sh->robust)));
  printf("lock again=%s\n", name(pthread_mutex_lock(&sh->robust)));
  pthread_mutex_unlock(&sh->robust);

  // Robust trylock on a dead owner.
  init_mutex(&sh->robust_try, PTHREAD_MUTEX_ERRORCHECK, 1, 1, PTHREAD_PRIO_NONE);
  child_dies_holding(&sh->robust_try);
  printf("trylock after owner died=%s\n", name(pthread_mutex_trylock(&sh->robust_try)));
  pthread_mutex_consistent(&sh->robust_try);
  printf("errorcheck relock=%s\n", name(pthread_mutex_lock(&sh->robust_try)));
  pthread_mutex_unlock(&sh->robust_try);

  // Robust: unlock without consistent makes it unrecoverable.
  init_mutex(&sh->robust_lost, PTHREAD_MUTEX_NORMAL, 1, 1, PTHREAD_PRIO_NONE);
  child_dies_holding(&sh->robust_lost);
  printf("lost: lock=%s\n", name(pthread_mutex_lock(&sh->robust_lost)));
  printf("lost: unlock without consistent=%s\n", name(pthread_mutex_unlock(&sh->robust_lost)));
  printf("lost: lock=%s\n", name(pthread_mutex_lock(&sh->robust_lost)));
  printf("lost: trylock=%s\n", name(pthread_mutex_trylock(&sh->robust_lost)));

  // Robust (process-private): owner thread exits holding the lock.
  pthread_mutex_t thread_robust;
  init_mutex(&thread_robust, PTHREAD_MUTEX_RECURSIVE, 0, 1, PTHREAD_PRIO_NONE);
  pthread_t t;
  pthread_create(&t, NULL, thread_dies_holding, &thread_robust);
  pthread_join(t, NULL);
  printf("lock after owner thread exited=%s\n", name(pthread_mutex_lock(&thread_robust)));
  pthread_mutex_consistent(&thread_robust);
  printf("recursive relock=%s\n", name(pthread_mutex_lock(&thread_robust)));
  int u1 = pthread_mutex_unlock(&thread_robust);
  int u2 = pthread_mutex_unlock(&thread_robust);
  printf("unlock x2=%s,%s\n", name(u1), name(u2));

  // Condition variable wait on a robust mutex.
  init_mutex(&robust_cv_mutex, PTHREAD_MUTEX_NORMAL, 0, 1, PTHREAD_PRIO_NONE);
  pthread_create(&t, NULL, robust_cv_signaller, NULL);
  pthread_mutex_lock(&robust_cv_mutex);
  crc = 0;
  while (!robust_cv_ready && crc == 0) crc = pthread_cond_wait(&robust_cv, &robust_cv_mutex);
  int cu = pthread_mutex_unlock(&robust_cv_mutex);
  printf("cond_wait on robust mutex: rc=%s ready=%d unlock=%s\n", name(crc), robust_cv_ready, name(cu));
  pthread_join(t, NULL);

  // Priority inheritance: contention between threads, recursion.
  printf("PI init=%s\n", name(init_mutex(&pi_mutex, PTHREAD_MUTEX_NORMAL, 0, 0, PTHREAD_PRIO_INHERIT)));
  pthread_t w[4];
  for (int i = 0; i < 4; i++) pthread_create(&w[i], NULL, pi_worker, NULL);
  for (int i = 0; i < 4; i++) pthread_join(w[i], NULL);
  printf("PI counter=%ld\n", pi_counter);
  pthread_mutex_t pi_rec;
  init_mutex(&pi_rec, PTHREAD_MUTEX_RECURSIVE, 0, 0, PTHREAD_PRIO_INHERIT);
  int r1 = pthread_mutex_lock(&pi_rec);
  int r2 = pthread_mutex_lock(&pi_rec);
  int r3 = pthread_mutex_unlock(&pi_rec);
  int r4 = pthread_mutex_unlock(&pi_rec);
  int r5 = pthread_mutex_unlock(&pi_rec);
  printf("PI recursive lock/lock/unlock/unlock/unlock=%s,%s,%s,%s,%s\n", name(r1), name(r2),
         name(r3), name(r4), name(r5));
  pthread_mutex_t pi_err;
  init_mutex(&pi_err, PTHREAD_MUTEX_ERRORCHECK, 0, 0, PTHREAD_PRIO_INHERIT);
  int e1 = pthread_mutex_lock(&pi_err);
  int e2 = pthread_mutex_lock(&pi_err);
  int e3 = pthread_mutex_trylock(&pi_err);
  printf("PI errorcheck lock/relock/trylock=%s,%s,%s\n", name(e1), name(e2), name(e3));
  pthread_mutex_unlock(&pi_err);
  return 0;
}
