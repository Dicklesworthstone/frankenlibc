// Thread cancellation and cleanup handlers (bd-rc0923-epic-eeuy4f.24).
//
// Output must be byte-identical under host glibc and FrankenLibC:
//   - statically initialized condvars (PTHREAD_COND_INITIALIZER) work;
//   - pthread_exit and pthread_testcancel run pthread_cleanup_push handlers;
//   - pthread_cancel of a thread blocked in read, sleep, nanosleep, poll or
//     pthread_cond_wait completes, runs its cleanup handlers (cond_wait's with
//     the mutex re-acquired), and pthread_join reports PTHREAD_CANCELED;
//   - a thread with cancellation disabled is not cancelled while blocked.
#define _GNU_SOURCE
#include <errno.h>
#include <poll.h>
#include <pthread.h>
#include <stdio.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

static int pipefd[2];
static pthread_mutex_t lock = PTHREAD_MUTEX_INITIALIZER;
static pthread_cond_t cond = PTHREAD_COND_INITIALIZER;
static int ready;

static void cleanup(void *what) {
  printf("  cleanup: %s\n", (const char *)what);
  fflush(stdout);
}

static void unlock_cleanup(void *m) {
  // POSIX: a cancelled pthread_cond_wait re-acquires the mutex first.
  int rc = pthread_mutex_trylock((pthread_mutex_t *)m);
  printf("  cleanup: cond_wait (mutex already held=%s)\n", rc == EBUSY ? "yes" : "no");
  fflush(stdout);
  if (rc == 0) {
    pthread_mutex_unlock((pthread_mutex_t *)m);
  }
  pthread_mutex_unlock((pthread_mutex_t *)m);
}

static void *blocked_read(void *arg) {
  (void)arg;
  char c;
  pthread_cleanup_push(cleanup, "read");
  ssize_t n = read(pipefd[0], &c, 1);
  (void)n;
  pthread_cleanup_pop(0);
  return NULL;
}

static void *blocked_sleep(void *arg) {
  (void)arg;
  pthread_cleanup_push(cleanup, "sleep");
  sleep(100);
  pthread_cleanup_pop(0);
  return NULL;
}

static void *blocked_nanosleep(void *arg) {
  (void)arg;
  struct timespec ts = {100, 0};
  pthread_cleanup_push(cleanup, "nanosleep");
  nanosleep(&ts, NULL);
  pthread_cleanup_pop(0);
  return NULL;
}

static void *blocked_poll(void *arg) {
  (void)arg;
  struct pollfd p = {pipefd[0], POLLIN, 0};
  pthread_cleanup_push(cleanup, "poll");
  poll(&p, 1, 100000);
  pthread_cleanup_pop(0);
  return NULL;
}

static void *blocked_cond_wait(void *arg) {
  (void)arg;
  pthread_mutex_lock(&lock);
  pthread_cleanup_push(unlock_cleanup, &lock);
  while (!ready) {
    pthread_cond_wait(&cond, &lock);
  }
  pthread_cleanup_pop(1);
  return NULL;
}

static void *disabled_sleep(void *arg) {
  (void)arg;
  pthread_setcancelstate(PTHREAD_CANCEL_DISABLE, NULL);
  struct timespec ts = {0, 300000000};
  nanosleep(&ts, NULL);
  printf("  disabled thread finished its sleep\n");
  fflush(stdout);
  pthread_setcancelstate(PTHREAD_CANCEL_ENABLE, NULL);
  pthread_testcancel();
  printf("  not reached\n");
  return NULL;
}

static void *exits(void *arg) {
  (void)arg;
  pthread_cleanup_push(cleanup, "pthread_exit");
  pthread_exit((void *)42);
  pthread_cleanup_pop(0);
  return NULL;
}

static void *signalled(void *arg) {
  (void)arg;
  pthread_mutex_lock(&lock);
  while (!ready) {
    pthread_cond_wait(&cond, &lock);
  }
  pthread_mutex_unlock(&lock);
  return (void *)7;
}

static void cancel_case(const char *name, void *(*fn)(void *)) {
  pthread_t t;
  void *ret = NULL;
  printf("%s:\n", name);
  fflush(stdout);
  pthread_create(&t, NULL, fn, NULL);
  struct timespec settle = {0, 100000000};
  nanosleep(&settle, NULL);
  pthread_cancel(t);
  pthread_join(t, &ret);
  printf("  joined: %s\n", ret == PTHREAD_CANCELED ? "PTHREAD_CANCELED" : "returned");
  fflush(stdout);
}

int main(void) {
  if (pipe(pipefd) != 0) {
    return 1;
  }

  // Static condvar: wait + signal.
  pthread_t t;
  void *ret = NULL;
  pthread_create(&t, NULL, signalled, NULL);
  struct timespec settle = {0, 50000000};
  nanosleep(&settle, NULL);
  pthread_mutex_lock(&lock);
  ready = 1;
  int sig_rc = pthread_cond_signal(&cond);
  pthread_mutex_unlock(&lock);
  pthread_join(t, &ret);
  printf("static condvar: signal=%d joined=%ld\n", sig_rc, (long)ret);
  ready = 0;

  // Static condvar: timed wait times out.
  struct timespec deadline;
  clock_gettime(CLOCK_REALTIME, &deadline);
  deadline.tv_nsec += 20000000;
  if (deadline.tv_nsec >= 1000000000) {
    deadline.tv_sec += 1;
    deadline.tv_nsec -= 1000000000;
  }
  pthread_mutex_lock(&lock);
  int tw = pthread_cond_timedwait(&cond, &lock, &deadline);
  pthread_mutex_unlock(&lock);
  printf("static condvar timedwait: %s\n", tw == ETIMEDOUT ? "ETIMEDOUT" : strerror(tw));

  printf("pthread_exit:\n");
  pthread_create(&t, NULL, exits, NULL);
  pthread_join(t, &ret);
  printf("  joined: %ld\n", (long)ret);

  cancel_case("read", blocked_read);
  cancel_case("sleep", blocked_sleep);
  cancel_case("nanosleep", blocked_nanosleep);
  cancel_case("poll", blocked_poll);
  cancel_case("cond_wait", blocked_cond_wait);
  cancel_case("cancel disabled until testcancel", disabled_sleep);

  // The mutex is usable after a cancelled waiter's cleanup released it.
  printf("mutex after cancellations: trylock=%d\n", pthread_mutex_trylock(&lock));
  pthread_mutex_unlock(&lock);
  return 0;
}
