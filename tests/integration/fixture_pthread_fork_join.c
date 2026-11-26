// A fork survivor must retain a joinable native pthread lifecycle.
// The child starts a second thread, exits its original thread, and is kept
// alive by the joiner until the kernel clears the survivor's owned TID word.
// No formatted output or allocation is used by the application workers.
#define _GNU_SOURCE
#include <dlfcn.h>
#include <errno.h>
#include <limits.h>
#include <pthread.h>
#include <sched.h>
#include <signal.h>
#include <stdatomic.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

#define NATIVE_HANDLE_MAGIC UINT32_C(0x5448444c)
#define RETURN_VALUE ((void *)(uintptr_t)0x5a17)

typedef pid_t (*fork_fn)(void);
typedef int (*create_fn)(pthread_t *, const pthread_attr_t *, void *(*)(void *), void *);
typedef pthread_t (*self_fn)(void);
typedef int (*join_fn)(pthread_t, void **);
typedef int (*timed_join_fn)(pthread_t, void **, const struct timespec *);
typedef void (*thread_exit_fn)(void *);
typedef void (*process_exit_fn)(int);

static struct {
  fork_fn fork;
  create_fn create;
  self_fn self;
  join_fn join;
  timed_join_fn timed_join;
  thread_exit_fn exit_thread;
  process_exit_fn exit_process;
} calls;

struct scenario {
  int explicit_exit;
  int timed_join;
  int require_native;
  _Atomic int parent_done;
};

struct child_join {
  pthread_t survivor;
  int timed_join;
  int require_native;
  _Atomic int ready;
};

static _Noreturn void finish_process(int status) {
  calls.exit_process(status);
  __builtin_unreachable();
}

static int owns_native_handle(void) {
  uintptr_t self = (uintptr_t)calls.self();
  if (self <= UINT32_MAX) return 0;
  // In this provider-pinned native test, pthread_t names the owned handle.
  return __atomic_load_n((const uint32_t *)self, __ATOMIC_RELAXED) == NATIVE_HANDLE_MAGIC;
}

static void *join_survivor(void *opaque) {
  struct child_join *shared = opaque;
  pthread_t survivor = shared->survivor;
  int timed = shared->timed_join;
  int native = shared->require_native;
  struct timespec deadline;
  if (native && !owns_native_handle()) finish_process(41);
  if (clock_gettime(CLOCK_REALTIME, &deadline) != 0) finish_process(42);
  deadline.tv_sec += 4;
  // Copy every field before joining. Successful join reclaims the survivor's
  // stack, where shared lives, so this thread must never read shared again.
  atomic_store_explicit(&shared->ready, 1, memory_order_release);
  void *value = NULL;
  int rc = timed ? calls.timed_join(survivor, &value, &deadline)
                 : calls.join(survivor, &value);
  if (rc == ETIMEDOUT) finish_process(43);
  if (rc != 0) finish_process(44);
  if (value != RETURN_VALUE) finish_process(45);
  finish_process(0);
}

static void *finish_parent(struct scenario *input, uintptr_t status) {
  // Main must not join this worker until its child is reaped. Otherwise the
  // child could inherit a join claim owned by the vanished parent main.
  atomic_store_explicit(&input->parent_done, 1, memory_order_release);
  return (void *)status;
}

static void *forking_worker(void *opaque) {
  struct scenario *input = opaque;
  int explicit_exit = input->explicit_exit;
  int timed_join = input->timed_join;
  int require_native = input->require_native;
  if (require_native && !owns_native_handle()) return finish_parent(input, 31);
  pid_t child = calls.fork();
  if (child < 0) return finish_parent(input, 32);
  if (child > 0) {
    int status = 0;
    pid_t got;
    do { got = waitpid(child, &status, 0); } while (got < 0 && errno == EINTR);
    if (got != child) return finish_parent(input, 33);
    if (!WIFEXITED(status)) return finish_parent(input, 34);
    return finish_parent(input, (uintptr_t)WEXITSTATUS(status));
  }

  alarm(8);
  if (require_native && !owns_native_handle()) finish_process(35);
  struct child_join shared = {
    .survivor = calls.self(),
    .timed_join = timed_join,
    .require_native = require_native,
    .ready = 0
  };
  pthread_t joiner;
  if (calls.create(&joiner, NULL, join_survivor, &shared) != 0) finish_process(36);
  while (!atomic_load_explicit(&shared.ready, memory_order_acquire)) sched_yield();
  if (explicit_exit) {
    calls.exit_thread(RETURN_VALUE);
    finish_process(46); // pthread_exit must not return.
  }
  return RETURN_VALUE;
}

static int resolve_provider(void) {
  const char *expected = getenv("FRANKENLIBC_TEST_LIBRARY");
  int pinned = expected != NULL && *expected != '\0';
  struct stat wanted;
  if (pinned && stat(expected, &wanted) != 0) return -1;
  const char *names[] = {
    "fork", "pthread_create", "pthread_self", "pthread_join",
    "pthread_timedjoin_np", "pthread_exit", "_exit"
  };
  void *addresses[sizeof(names) / sizeof(names[0])];
  for (size_t i = 0; i < sizeof(names) / sizeof(names[0]); ++i) {
    addresses[i] = dlsym(RTLD_DEFAULT, names[i]);
    if (addresses[i] == NULL) {
      fprintf(stderr, "missing provider for %s\n", names[i]);
      return -1;
    }
    if (pinned) {
      Dl_info info;
      struct stat actual;
      if (dladdr(addresses[i], &info) == 0 || info.dli_fname == NULL ||
          stat(info.dli_fname, &actual) != 0 ||
          actual.st_dev != wanted.st_dev || actual.st_ino != wanted.st_ino) {
        fprintf(stderr, "wrong provider for %s\n", names[i]);
        return -1;
      }
    }
  }
  // Invoke exactly the addresses whose provider was checked. A linked PLT
  // relocation can carry a symbol version different from plain dlsym.
  calls.fork = (fork_fn)addresses[0];
  calls.create = (create_fn)addresses[1];
  calls.self = (self_fn)addresses[2];
  calls.join = (join_fn)addresses[3];
  calls.timed_join = (timed_join_fn)addresses[4];
  calls.exit_thread = (thread_exit_fn)addresses[5];
  calls.exit_process = (process_exit_fn)addresses[6];
  return 0;
}

int main(void) {
  if (resolve_provider() != 0) return 1;
  const char *library = getenv("FRANKENLIBC_TEST_LIBRARY");
  const char *native = getenv("FRANKENLIBC_THREAD_NATIVE");
  int require_native = library != NULL && *library != '\0';
  if (require_native && (native == NULL || strcmp(native, "1") != 0)) {
    fprintf(stderr, "candidate fork-survivor test requires FRANKENLIBC_THREAD_NATIVE=1\n");
    return 1;
  }
  signal(SIGALRM, SIG_DFL);
  alarm(30);
  unsigned passed = 0;
  for (int explicit_exit = 0; explicit_exit < 2; ++explicit_exit) {
    for (int timed_join = 0; timed_join < 2; ++timed_join) {
      struct scenario scenario = {explicit_exit, timed_join, require_native, 0};
      pthread_t worker;
      int rc = calls.create(&worker, NULL, forking_worker, &scenario);
      if (rc != 0) {
        fprintf(stderr, "fork worker create failed: %d\n", rc);
        return 1;
      }
      const struct timespec poll = {.tv_sec = 0, .tv_nsec = 1000000};
      while (!atomic_load_explicit(&scenario.parent_done, memory_order_acquire)) {
        (void)nanosleep(&poll, NULL);
      }
      void *result = NULL;
      rc = calls.join(worker, &result);
      if (rc != 0 || result != NULL) {
        fprintf(stderr, "fork survivor: exit=%d timed=%d join=%d child=%lu\n",
                explicit_exit, timed_join, rc, (unsigned long)(uintptr_t)result);
        return 1;
      }
      ++passed;
    }
  }
  alarm(0);
  printf("PASS fork survivor join: %u cases\n", passed);
  return passed == 4 ? 0 : 1;
}
