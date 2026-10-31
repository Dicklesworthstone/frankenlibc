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
#include <sys/eventfd.h>
#include <sys/stat.h>
#include <sys/syscall.h>
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

static pthread_t native_join_target;
static int native_join_target_value;
static int native_join_sentinel;
static std::atomic<int> native_join_started{0};
using NativeJoin = int (*)(pthread_t, void **);
static NativeJoin native_alias_join;
static int native_event_fd = -1;
static constexpr eventfd_t native_event_sentinel = 0x1122334455667788ULL;

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
  eventfd_t event_value = native_event_sentinel;
  void *join_result = &native_join_sentinel;
  void *eh_globals = nullptr;
  int events[16]{};
  int count = 0;
  std::atomic<int> ready{0};
  std::atomic<int> release{0};
  std::atomic<pid_t> tid{0};
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

static void *native_join_target_worker(void *) {
  native_join_started.store(1, std::memory_order_release);
  return &native_join_target_value;
}

static int native_join_operation(NativeState *state) {
  const char *point = state->point;
  if (!std::strcmp(point, "join-alias"))
    return native_alias_join(native_join_target, &state->join_result);
  if (!std::strcmp(point, "tryjoin")) {
    int result;
    do {
      result = pthread_tryjoin_np(native_join_target, &state->join_result);
    } while (result == EBUSY);
    return result;
  }
  if (!std::strcmp(point, "join-timed-null"))
    return pthread_timedjoin_np(native_join_target, &state->join_result, nullptr);
  if (!std::strcmp(point, "join-clock-null"))
    return pthread_clockjoin_np(native_join_target, &state->join_result, CLOCK_MONOTONIC, nullptr);
  if (!std::strcmp(point, "join-timed") || !std::strncmp(point, "join-clock-", 11)) {
    clockid_t clock = !std::strcmp(point, "join-clock-mono") ? CLOCK_MONOTONIC : CLOCK_REALTIME;
    std::timespec deadline{};
    native_require(clock_gettime(clock, &deadline) == 0, "join deadline clock");
    deadline.tv_sec += 60;
    if (!std::strcmp(point, "join-timed"))
      return pthread_timedjoin_np(native_join_target, &state->join_result, &deadline);
    return pthread_clockjoin_np(native_join_target, &state->join_result, clock, &deadline);
  }
  return pthread_join(native_join_target, &state->join_result);
}

static void native_observe_event_wait(NativeState *state) {
  char path[96];
  std::snprintf(path, sizeof path, "/proc/self/task/%ld/syscall",
                static_cast<long>(state->tid.load(std::memory_order_acquire)));
  std::timespec start{};
  native_require(clock_gettime(CLOCK_MONOTONIC, &start) == 0, "blocking observation clock");
  for (;;) {
    int fd = open(path, O_RDONLY | O_CLOEXEC);
    native_require(fd >= 0, "open thread syscall observation");
    char line[256]{};
    ssize_t length = read(fd, line, sizeof line - 1);
    native_require(close(fd) == 0 && length > 0, "read thread syscall observation");
    long number = -1;
    unsigned long argument = 0;
    long expected = !std::strcmp(state->point, "eventfd-read") ? SYS_read : SYS_write;
    if (std::sscanf(line, "%ld %lx", &number, &argument) == 2 &&
        number == expected && argument == static_cast<unsigned long>(native_event_fd))
      return;
    std::timespec now{};
    native_require(clock_gettime(CLOCK_MONOTONIC, &now) == 0, "blocking observation clock");
    native_require(now.tv_sec - start.tv_sec < 3, "eventfd operation reached blocking syscall");
    const std::timespec pause = {0, 1000000};
    native_require(nanosleep(&pause, nullptr) == 0, "blocking observation pause");
  }
}

static void native_inner(void *argument) {
  auto *state = static_cast<NativeState *>(argument);
  NativeGuard guard{state, 1};
  state->tid.store(static_cast<pid_t>(syscall(SYS_gettid)), std::memory_order_release);
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
      if (!std::strcmp(state->point, "eventfd-read")) {
        native_require(eventfd_read(native_event_fd, &state->event_value) == 0 &&
                       state->event_value == 3, "eventfd read result");
      } else if (!std::strcmp(state->point, "eventfd-write")) {
        native_require(eventfd_write(native_event_fd, 5) == 0, "eventfd write result");
      } else if (!std::strcmp(state->point, "read")) {
        char byte = 0;
        native_require(read(pipefd[0], &byte, 1) == 1 && byte == 'R', "read result");
      } else if (!std::strcmp(state->point, "write")) {
        native_require(write(pipefd[1], "W", 1) == 1, "write result");
      } else if (!std::strcmp(state->point, "nanosleep")) {
        const std::timespec zero = {0, 0};
        native_require(nanosleep(&zero, nullptr) == 0, "nanosleep result");
      } else if (!std::strcmp(state->point, "sem_wait")) {
        native_require(sem_wait(&state->semaphore) == 0, "ready semaphore result");
      } else if (!std::strncmp(state->point, "join", 4) ||
                 !std::strcmp(state->point, "tryjoin")) {
        native_require(native_join_operation(state) == 0, "target join succeeds");
      } else {
        const std::timespec expired = {0, 0};
        native_require(sem_timedwait(&state->semaphore, &expired) == 0,
                       "ready timed semaphore result");
      }
      state->operation_completed = true;
      if (!state->disabled && std::strcmp(state->point, "tryjoin"))
        std::_Exit(94); // A pending request must act before any syscall/token effect.
      if (state->disabled)
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

static int native_provider(const char *expected, const char *name) {
  const char *names[] = {"pthread_create", "pthread_join", "pthread_exit", "pthread_testcancel",
                         "read", "write", "nanosleep", "sem_wait", "sem_timedwait", "getpwnam",
                         "eventfd", "eventfd_read", "eventfd_write",
                         "pthread_timedjoin_np", "pthread_clockjoin_np", "pthread_tryjoin_np",
                         std::strstr(name, "join-alias") ? "__pthread_join" : "pthread_join"};
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
  if (std::strstr(name, "join-alias"))
    native_alias_join = reinterpret_cast<NativeJoin>(dlsym(RTLD_DEFAULT, "__pthread_join"));
  return 0;
}

static int native_probe(const char *name, const char *provider) {
  int checked = native_provider(provider, name);
  if (checked) return checked;
  bool cancel = std::strstr(name, "cancel") != nullptr;
  bool mixed = std::strstr(name, "mixed") != nullptr;
  bool catch_all = std::strstr(name, "catch-all") != nullptr;
  bool disabled = std::strstr(name, "disabled") != nullptr;
  bool blocking_event = std::strstr(name, "blocked") != nullptr;
  bool internal_io = std::strstr(name, "internal") != nullptr;
  const char *point = std::strstr(name, "-eventfd-read") ? "eventfd-read" :
                      std::strstr(name, "-eventfd-write") ? "eventfd-write" :
                      std::strstr(name, "-read") ? "read" :
                      std::strstr(name, "-write") ? "write" :
                      std::strstr(name, "-nanosleep") ? "nanosleep" :
                      std::strstr(name, "-sem-timed") ? "sem_timedwait" :
                      std::strstr(name, "-sem") ? "sem_wait" :
                      std::strstr(name, "-join-alias") ? "join-alias" :
                      std::strstr(name, "-join-timed-null") ? "join-timed-null" :
                      std::strstr(name, "-join-timed") ? "join-timed" :
                      std::strstr(name, "-join-clock-real") ? "join-clock-real" :
                      std::strstr(name, "-join-clock-mono") ? "join-clock-mono" :
                      std::strstr(name, "-join-clock-null") ? "join-clock-null" :
                      std::strstr(name, "-join") ? "join" :
                      std::strstr(name, "-tryjoin") ? "tryjoin" : nullptr;
  bool joining = point && (!std::strncmp(point, "join", 4) || !std::strcmp(point, "tryjoin"));
  bool noncanceling = point && !std::strcmp(point, "tryjoin");
  bool event_io = point && !std::strncmp(point, "eventfd-", 8);
  int count = std::strstr(name, "siblings") ? 2 : 1;
  alarm(12);
  if (event_io) {
    native_event_fd = eventfd(blocking_event ? 0 : 3,
                             EFD_CLOEXEC | (blocking_event ? 0 : EFD_NONBLOCK));
    native_require(native_event_fd >= 0, "create observable event counter");
    if (blocking_event && !std::strcmp(point, "eventfd-write"))
      native_require(eventfd_write(native_event_fd, ~eventfd_t{0} - 1) == 0,
                     "saturate blocking event counter");
  }
  if (point && (!std::strcmp(point, "read") || !std::strcmp(point, "write"))) {
    native_require(pipe(pipefd) == 0, "create observable pipe");
    native_require(fcntl(pipefd[0], F_SETFL, O_NONBLOCK) == 0, "nonblocking pipe inspection");
    if (!std::strcmp(point, "read"))
      native_require(write(pipefd[1], "R", 1) == 1, "seed readable pipe");
  }
  // NSS may initialize through cancellation points on its first lookup. This
  // control concerns the subsequent internal file I/O, not provider loading.
  if (internal_io)
    native_require(getpwnam("root") != nullptr, "initialize passwd provider before cancellation");
  if (joining) {
    native_require(pthread_create(&native_join_target, nullptr, native_join_target_worker, nullptr) == 0,
                   "create joinable target");
    while (!native_join_started.load(std::memory_order_acquire)) {}
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
    if (cancel && !blocking_event)
      native_require(pthread_cancel(state->thread) == 0, "cancel");
    state->release.store(1, std::memory_order_release);
    if (blocking_event) {
      native_observe_event_wait(state);
      native_require(pthread_cancel(state->thread) == 0, "cancel blocked event I/O");
      if (disabled) {
        if (!std::strcmp(point, "eventfd-read")) {
          native_require(eventfd_write(native_event_fd, 3) == 0, "release disabled event read");
        } else {
          eventfd_t value = 0;
          native_require(eventfd_read(native_event_fd, &value) == 0 &&
                         value == ~eventfd_t{0} - 1, "release disabled event write");
        }
      }
    }
    void *result = nullptr;
    native_require(pthread_join(state->thread, &result) == 0, "join");
    native_require(result == (cancel ? PTHREAD_CANCELED : static_cast<void *>(state)), "exit value");
    if (point) {
      native_require(state->operation_completed == (disabled || noncanceling),
                     "pending cancellation precedes cancelable operation");
      native_require(state->internal_completed == internal_io, "internal I/O is not a cancellation point");
      if (event_io) {
        native_require(state->event_value ==
                       (disabled && !std::strcmp(point, "eventfd-read") ? 3 : native_event_sentinel),
                       "canceled event read preserves output slot");
        native_require(fcntl(native_event_fd, F_SETFL, O_NONBLOCK) == 0,
                       "nonblocking event counter inspection");
        eventfd_t expected = !std::strcmp(point, "eventfd-read") ?
                             (disabled || blocking_event ? 0 : 3) :
                             (disabled ? (blocking_event ? 5 : 8) :
                              (blocking_event ? ~eventfd_t{0} - 1 : 3));
        eventfd_t value = native_event_sentinel;
        errno = 0;
        int rc = eventfd_read(native_event_fd, &value);
        native_require(expected ? rc == 0 && value == expected :
                                  rc == -1 && errno == EAGAIN && value == native_event_sentinel,
                       "counter state exposes whether canceled event I/O ran");
      } else if (joining) {
        if (disabled || noncanceling) {
          native_require(state->join_result == &native_join_target_value,
                         "noncanceling control really consumes target result");
        } else {
          native_require(state->join_result == &native_join_sentinel,
                         "canceled join leaves result slot untouched");
          void *target_result = nullptr;
          native_require(pthread_join(native_join_target, &target_result) == 0 &&
                         target_result == &native_join_target_value,
                         "canceled join leaves target joinable by another thread");
        }
      } else if (!std::strncmp(point, "sem_", 4)) {
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
  if (event_io)
    native_require(close(native_event_fd) == 0, "close observed event counter");
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
