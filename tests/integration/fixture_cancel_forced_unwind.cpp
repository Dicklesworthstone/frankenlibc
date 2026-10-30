// C++ view of thread cancellation (bd-rc0923-epic-eeuy4f.24).
//
// glibc implements cancellation as a forced unwind: C++ destructors of every
// frame run, `catch (abi::__forced_unwind &)` observes it and must rethrow,
// and `catch (...)` that rethrows is equally legal. The unwind must also cross
// libc's own frames when the cancellation point is inside a callback that libc
// called (a qsort comparator; bd-rc0923-epic-eeuy4f.6). Output must be
// byte-identical under host glibc and FrankenLibC (strict and hardened).
#include <cxxabi.h>
#include <dlfcn.h>
#include <fcntl.h>
#include <pthread.h>
#include <pwd.h>
#include <semaphore.h>
#include <sys/stat.h>
#include <unistd.h>

#include <atomic>
#include <cerrno>
#include <cstdio>
#include <cstdlib>
#include <cstring>
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

/* The optional native-state modes use explicit exit or a cooperatively
 * reached cancellation point. Remote interruption of blocking syscalls is a
 * separate native backend feature, so these probes isolate stack unwinding. */
extern "C" void frankenlibc_native_cleanup_frame(void (*)(void *), void (*)(void *), void *)
    __attribute__((weak));

struct NativeState {
  pthread_t thread{};
  bool cancel = false;
  bool catch_all = false;
  bool mixed = false;
  const char *point = nullptr;
  bool disabled = false;
  bool internal_io = false;
  bool internal_completed = false;
  bool operation_completed = false;
  sem_t semaphore{};
  void *eh_globals = nullptr;
  int events[16]{};
  int count = 0;
  std::atomic<int> ready{0};
  std::atomic<int> release{0};
};

static pthread_key_t native_key;
static NativeState native_states[2];

static void native_require(bool condition, const char *message) {
  if (!condition) {
    std::fprintf(stderr, "pthread-native-unwind: %s\n", message);
    std::_Exit(1);
  }
}

static void native_event(NativeState *state, int event) {
  native_require(state->count < 16, "event capacity");
  state->events[state->count++] = event;
}

struct NativeGuard {
  NativeState *state;
  int event;
  ~NativeGuard() { native_event(state, event); }
};

static void native_key_destructor(void *argument) {
  auto *state = static_cast<NativeState *>(argument);
  native_require(pthread_getspecific(native_key) == nullptr, "key cleared before destructor");
  native_event(state, 9);
}

static void native_cpp_cleanup(void *argument) {
  auto *state = static_cast<NativeState *>(argument);
  native_require(pthread_getspecific(native_key) == state, "cleanup precedes key destructor");
  native_event(state, 5);
}

static void native_c_cleanup(void *argument) {
  native_event(static_cast<NativeState *>(argument), 4);
}

static void native_inner(void *argument) {
  auto *state = static_cast<NativeState *>(argument);
  NativeGuard guard{state, 1};
  state->ready.store(1, std::memory_order_release);
  while (!state->release.load(std::memory_order_acquire)) {}
  if (state->cancel) {
    if (state->point) {
      if (state->disabled)
        native_require(pthread_setcancelstate(PTHREAD_CANCEL_DISABLE, nullptr) == 0,
                       "disable pending cancellation");
      if (state->internal_io) {
        native_require(getpwnam("root") != nullptr, "internal passwd lookup completes");
        state->internal_completed = true;
      }
      if (!std::strcmp(state->point, "read")) {
        char byte = 0;
        native_require(read(pipefd[0], &byte, 1) == 1 && byte == 'R', "read result");
      } else if (!std::strcmp(state->point, "write")) {
        native_require(write(pipefd[1], "W", 1) == 1, "write result");
      } else if (!std::strcmp(state->point, "nanosleep")) {
        const std::timespec zero = {0, 0};
        native_require(nanosleep(&zero, nullptr) == 0, "nanosleep result");
      } else if (!std::strcmp(state->point, "sem_wait")) {
        native_require(sem_wait(&state->semaphore) == 0, "ready semaphore result");
      } else {
        const std::timespec expired = {0, 0};
        native_require(sem_timedwait(&state->semaphore, &expired) == 0,
                       "ready timed semaphore result");
      }
      state->operation_completed = true;
      if (!state->disabled)
        std::_Exit(94); // A pending request must act before any syscall/token effect.
      native_require(pthread_setcancelstate(PTHREAD_CANCEL_ENABLE, nullptr) == 0,
                     "restore cancellation after disabled operation");
    }
    pthread_testcancel();
    std::_Exit(94);
  }
  pthread_exit(state);
}

static void native_inner_dispatch(NativeState *state) {
  if (state->mixed) {
    native_require(frankenlibc_native_cleanup_frame != nullptr, "C frame linked");
    frankenlibc_native_cleanup_frame(native_inner, native_c_cleanup, state);
  } else {
    native_inner(state);
  }
}

static void *native_worker(void *argument) {
  auto *state = static_cast<NativeState *>(argument);
  state->eh_globals = abi::__cxa_get_globals();
  native_require(pthread_setspecific(native_key, state) == 0, "setspecific");
  NativeGuard outer{state, 7};
  pthread_cleanup_push(native_cpp_cleanup, state);
  if (state->catch_all) {
    try {
      native_inner_dispatch(state);
    } catch (...) {
      native_event(state, 6);
      throw;
    }
  } else {
    try {
      native_inner_dispatch(state);
    } catch (abi::__forced_unwind &) {
      native_event(state, 6);
      throw;
    }
  }
  pthread_cleanup_pop(0);
  return nullptr;
}

static int native_provider(const char *expected) {
  const char *names[] = {"pthread_create", "pthread_join", "pthread_exit", "pthread_testcancel",
                         "read", "write", "nanosleep", "sem_wait", "sem_timedwait", "getpwnam"};
  struct stat wanted{};
  if (stat(expected, &wanted)) return 86;
  for (const char *name : names) {
    Dl_info info{};
    struct stat actual{};
    void *symbol = dlsym(RTLD_DEFAULT, name);
    if (!symbol || !dladdr(symbol, &info) || stat(info.dli_fname, &actual) ||
        actual.st_dev != wanted.st_dev || actual.st_ino != wanted.st_ino) {
      std::fprintf(stderr, "pthread-native-unwind:provider-mismatch:%s\n", name);
      return 86;
    }
  }
  return 0;
}

static int native_probe(const char *name, const char *provider) {
  int checked = native_provider(provider);
  if (checked) return checked;
  bool cancel = std::strstr(name, "cancel") != nullptr;
  bool mixed = std::strstr(name, "mixed") != nullptr;
  bool catch_all = std::strstr(name, "catch-all") != nullptr;
  bool disabled = std::strstr(name, "disabled") != nullptr;
  bool internal_io = std::strstr(name, "internal") != nullptr;
  const char *point = std::strstr(name, "-read") ? "read" :
                      std::strstr(name, "-write") ? "write" :
                      std::strstr(name, "-nanosleep") ? "nanosleep" :
                      std::strstr(name, "-sem-timed") ? "sem_timedwait" :
                      std::strstr(name, "-sem") ? "sem_wait" : nullptr;
  int count = std::strstr(name, "siblings") ? 2 : 1;
  alarm(12);
  if (point && (!std::strcmp(point, "read") || !std::strcmp(point, "write"))) {
    native_require(pipe(pipefd) == 0, "create observable pipe");
    native_require(fcntl(pipefd[0], F_SETFL, O_NONBLOCK) == 0, "nonblocking pipe inspection");
    if (!std::strcmp(point, "read"))
      native_require(write(pipefd[1], "R", 1) == 1, "seed readable pipe");
  }
  native_require(pthread_key_create(&native_key, native_key_destructor) == 0, "key_create");
  void *parent_globals = abi::__cxa_get_globals();
  for (int i = 0; i < count; ++i) {
    NativeState *state = &native_states[i];
    state->cancel = cancel;
    state->mixed = mixed;
    state->catch_all = catch_all;
    state->point = point;
    state->disabled = disabled;
    state->internal_io = internal_io;
    if (point && !std::strncmp(point, "sem_", 4))
      native_require(sem_init(&state->semaphore, 0, 1) == 0, "seed available semaphore");
    native_require(pthread_create(&state->thread, nullptr, native_worker, state) == 0, "create");
    while (!state->ready.load(std::memory_order_acquire)) {}
    native_require(state->eh_globals != parent_globals, "child exception state aliases parent");
    if (i) native_require(state->eh_globals != native_states[0].eh_globals,
                          "sibling exception states alias");
  }
  for (int i = 0; i < count; ++i) {
    NativeState *state = &native_states[i];
    if (cancel) native_require(pthread_cancel(state->thread) == 0, "cancel");
    state->release.store(1, std::memory_order_release);
    void *result = nullptr;
    native_require(pthread_join(state->thread, &result) == 0, "join");
    native_require(result == (cancel ? PTHREAD_CANCELED : static_cast<void *>(state)), "exit value");
    if (point) {
      native_require(state->operation_completed == disabled, "pending cancellation precedes operation");
      native_require(state->internal_completed == internal_io, "internal I/O is not a cancellation point");
      if (!std::strncmp(point, "sem_", 4)) {
        int tokens = -1;
        native_require(sem_getvalue(&state->semaphore, &tokens) == 0 && tokens == !disabled,
                       "canceled wait must preserve its available token");
        native_require(sem_destroy(&state->semaphore) == 0, "destroy semaphore");
      } else if (!std::strcmp(point, "read") || !std::strcmp(point, "write")) {
        char byte = 0;
        errno = 0;
        ssize_t amount = read(pipefd[0], &byte, 1);
        bool present = !std::strcmp(point, "read") ? !disabled : disabled;
        native_require(present ? amount == 1 && byte == (!std::strcmp(point, "read") ? 'R' : 'W')
                               : amount == -1 && errno == EAGAIN,
                       "pipe contents expose whether the canceled syscall ran");
      }
    }
    const int expected[] = {1, 4, 6, 5, 7, 9};
    native_require(state->count == (mixed ? 6 : 5), "all cleanup frames run exactly once");
    int index = 0;
    for (int event : expected) {
      if (!mixed && event == 4) continue;
      native_require(state->events[index++] == event, "C/C++/key cleanup order");
    }
    if (i + 1 < count) native_require(native_states[i + 1].count == 0, "sibling remains live");
  }
  native_require(pthread_key_delete(native_key) == 0, "key_delete");
  if (point && (!std::strcmp(point, "read") || !std::strcmp(point, "write"))) {
    native_require(close(pipefd[0]) == 0 && close(pipefd[1]) == 0, "close observed pipe");
  }
  std::printf("pthread-native-unwind:%s:PASS\n", name);
  return 0;
}

int main(int argc, char **argv) {
  if (argc == 3 && !std::strncmp(argv[1], "native-", 7)) {
    return native_probe(argv[1], argv[2]);
  }
  if (pipe(pipefd) != 0) {
    return 1;
  }
  run("read with abi::__forced_unwind handler", catches_forced_unwind);
  run("nanosleep with catch (...)", catch_all_rethrows);
  run("read inside a qsort comparator", cancelled_inside_qsort);
  return 0;
}
