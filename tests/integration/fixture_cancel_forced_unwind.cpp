// C++ view of thread cancellation (bd-rc0923-epic-eeuy4f.24).
//
// glibc implements cancellation as a forced unwind: C++ destructors of every
// frame run, `catch (abi::__forced_unwind &)` observes it and must rethrow,
// and `catch (...)` that rethrows is equally legal. The unwind must also cross
// libc's own frames when the cancellation point is inside a callback that libc
// called (a qsort comparator; bd-rc0923-epic-eeuy4f.6). Output must be
// byte-identical under host glibc and FrankenLibC (strict and hardened).
#include <cxxabi.h>
#include <pthread.h>
#include <unistd.h>

#include <cstdio>
#include <cstdlib>
#include <ctime>

static int pipefd[2];

struct Noisy {
  const char *name;
  explicit Noisy(const char *n) : name(n) {}
  ~Noisy() {
    std::printf("  ~Noisy(%s)\n", name);
    std::fflush(stdout);
  }
};

static void blocked_in_read() {
  Noisy inner("inner frame");
  char c;
  ssize_t n = read(pipefd[0], &c, 1);
  (void)n;
  std::printf("  read returned (not cancelled)\n");
}

static void *catches_forced_unwind(void *) {
  Noisy outer("outer frame");
  try {
    blocked_in_read();
  } catch (abi::__forced_unwind &) {
    std::printf("  caught abi::__forced_unwind, rethrowing\n");
    std::fflush(stdout);
    throw;
  }
  return nullptr;
}

static void *catch_all_rethrows(void *) {
  Noisy outer("catch-all frame");
  try {
    std::timespec forever = {100, 0};
    nanosleep(&forever, nullptr);
  } catch (...) {
    std::printf("  catch (...) saw the unwind, rethrowing\n");
    std::fflush(stdout);
    throw;
  }
  return nullptr;
}

static int compar_blocks(const void *a, const void *b) {
  Noisy in_compar("comparator frame");
  char c;
  ssize_t n = read(pipefd[0], &c, 1);  // cancellation point inside a libc callback
  (void)n;
  return *static_cast<const int *>(a) - *static_cast<const int *>(b);
}

static void *cancelled_inside_qsort(void *) {
  Noisy outer("qsort caller frame");
  int values[] = {3, 1, 2};
  qsort(values, 3, sizeof values[0], compar_blocks);
  std::printf("  qsort returned (not cancelled)\n");
  return nullptr;
}

static void run(const char *name, void *(*fn)(void *)) {
  std::printf("%s:\n", name);
  std::fflush(stdout);
  pthread_t t;
  pthread_create(&t, nullptr, fn, nullptr);
  std::timespec settle = {0, 100000000};
  nanosleep(&settle, nullptr);
  pthread_cancel(t);
  void *ret = nullptr;
  pthread_join(t, &ret);
  std::printf("  joined: %s\n", ret == PTHREAD_CANCELED ? "PTHREAD_CANCELED" : "returned");
  std::fflush(stdout);
}

int main() {
  if (pipe(pipefd) != 0) {
    return 1;
  }
  run("read with abi::__forced_unwind handler", catches_forced_unwind);
  run("nanosleep with catch (...)", catch_all_rethrows);
  run("read inside a qsort comparator", cancelled_inside_qsort);
  return 0;
}
