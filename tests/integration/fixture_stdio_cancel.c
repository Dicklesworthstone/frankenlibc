/* Native stdio read cancellation, compiled as both C and C++.
 *
 * Each invocation owns only anonymous pipes. A blocked case is cancelled only
 * after /proc confirms the worker is inside read(2) on the tested descriptor.
 * The cleanup handler reuses the same FILE, so a leaked stream lock cannot
 * masquerade as a successful join. C++ additionally checks both destructors and
 * the forced-unwind catch/rethrow path. No named files or production state are
 * changed.
 */
#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
#include <dlfcn.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <pthread.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <time.h>
#include <unistd.h>
#ifdef __cplusplus
#include <cxxabi.h>
#endif

struct read_case {
  const char *name;
  const char *phase;
  const char *path;
  FILE *stream;
  void *operation;
  int fd;
  int tid;
  int entered;
  int cleaned;
  int reused;
  int destructors;
  int forced;
  int result;
  char *line;
  size_t line_size;
};

static void fail(const char *message, int status) {
  (void)syscall(SYS_write, STDERR_FILENO, message, strlen(message));
  (void)syscall(SYS_write, STDERR_FILENO, "\n", 1);
  /* exit() can try to flush the stream whose broken lock this test detected. */
  (void)syscall(SYS_exit_group, status);
  __builtin_unreachable();
}

static int is_case(const struct read_case *test, const char *name) {
  return strcmp(test->name, name) == 0;
}

static void verify_provider(void *address) {
  const char *expected = getenv("FRANKENLIBC_TEST_LIBRARY");
  if (expected == NULL || *expected == '\0')
    return;
  Dl_info info;
  struct stat actual_stat, expected_stat;
  if (!address || !dladdr(address, &info) || !info.dli_fname ||
      stat(info.dli_fname, &actual_stat) != 0 ||
      stat(expected, &expected_stat) != 0 ||
      actual_stat.st_dev != expected_stat.st_dev ||
      actual_stat.st_ino != expected_stat.st_ino)
    fail("stdio cancellation: wrong symbol provider", 90);
}

static void *lookup(const char *name) {
  void *address = dlsym(RTLD_DEFAULT, name);
  /* __getline is a FrankenLibC reserved alias; GNU's public getline is its
   * independent behavior oracle, not a candidate-side fallback. */
  if (!address && strcmp(name, "__getline") == 0 &&
      getenv("FRANKENLIBC_TEST_LIBRARY") == NULL)
    address = dlsym(RTLD_DEFAULT, "getline");
  if (!address)
    fail("stdio cancellation: required symbol missing", 91);
  verify_provider(address);
  return address;
}

static void operate(struct read_case *test) {
  char bytes[16384];
  if (is_case(test, "fread") || is_case(test, "fread_unlocked") ||
      is_case(test, "fread-large")) {
    size_t count = is_case(test, "fread-large") &&
                           strcmp(test->phase, "buffered") != 0
                       ? sizeof(bytes)
                       : 1;
    size_t result = ((size_t (*)(void *, size_t, size_t, FILE *))test->operation)(
        bytes, 1, count, test->stream);
    test->result = result != 0 && bytes[0] == 'R';
  } else if (is_case(test, "__fread_chk") ||
             is_case(test, "__fread_unlocked_chk")) {
    size_t result =
        ((size_t (*)(void *, size_t, size_t, size_t, FILE *))test->operation)(
            bytes, sizeof(bytes), 1, 1, test->stream);
    test->result = result == 1 && bytes[0] == 'R';
  } else if (is_case(test, "fgets") || is_case(test, "fgets_unlocked")) {
    char *result = ((char *(*)(char *, int, FILE *))test->operation)(
        bytes, sizeof(bytes), test->stream);
    test->result = result == bytes && bytes[0] == 'R';
  } else if (is_case(test, "__fgets_chk") ||
             is_case(test, "__fgets_unlocked_chk")) {
    char *result =
        ((char *(*)(char *, size_t, int, FILE *))test->operation)(
            bytes, sizeof(bytes), sizeof(bytes), test->stream);
    test->result = result == bytes && bytes[0] == 'R';
  } else if (is_case(test, "getline") || is_case(test, "__getline")) {
    ssize_t result = ((ssize_t (*)(char **, size_t *, FILE *))test->operation)(
        &test->line, &test->line_size, test->stream);
    test->result = result == 2 && test->line[0] == 'R';
  } else if (is_case(test, "getdelim") || is_case(test, "__getdelim")) {
    ssize_t result =
        ((ssize_t (*)(char **, size_t *, int, FILE *))test->operation)(
            &test->line, &test->line_size, '\n', test->stream);
    test->result = result == 2 && test->line[0] == 'R';
  } else if (is_case(test, "macro-getc_unlocked")) {
    test->result = getc_unlocked(test->stream) == 'R';
  } else if (is_case(test, "macro-getchar_unlocked")) {
    test->result = getchar_unlocked() == 'R';
  } else if (is_case(test, "getchar") || is_case(test, "getchar_unlocked")) {
    test->result = ((int (*)(void))test->operation)() == 'R';
  } else {
    test->result = ((int (*)(FILE *))test->operation)(test->stream) == 'R';
  }
}

static void cleanup(void *argument) {
  struct read_case *test = (struct read_case *)argument;
  test->cleaned++;
  /* Both functions need the stream's normal state/lock after the interrupted
   * Rust frame has unwound. A successful ftrylockfile alone would check only
   * the separately managed explicit FILE lock. */
  test->reused = ungetc('Q', test->stream) == 'Q' && fgetc(test->stream) == 'Q';
}

#ifdef __cplusplus
struct destruction_count {
  struct read_case *test;
  explicit destruction_count(struct read_case *value) : test(value) {}
  ~destruction_count() { test->destructors++; }
};
#endif

static void *reader(void *argument) {
  struct read_case *test = (struct read_case *)argument;
  test->tid = (int)syscall(SYS_gettid);
  if (strcmp(test->path, "cold") != 0 && fgetc(test->stream) != 'W')
    fail("stdio cancellation: failed to prime stream", 92);
  if (strcmp(test->phase, "disabled") == 0 &&
      pthread_setcancelstate(PTHREAD_CANCEL_DISABLE, NULL) != 0)
    fail("stdio cancellation: cannot disable cancellation", 93);

  pthread_cleanup_push(cleanup, argument);
#ifdef __cplusplus
  {
    destruction_count outer(test);
    try {
      destruction_count inner(test);
#endif
      if ((strcmp(test->phase, "pending") == 0 ||
           strcmp(test->phase, "buffered") == 0) &&
          pthread_cancel(pthread_self()) != 0)
        fail("stdio cancellation: self-cancel failed", 94);
      __atomic_store_n(&test->entered, 1, __ATOMIC_RELEASE);
      operate(test);
#ifdef __cplusplus
    } catch (const __cxxabiv1::__forced_unwind &) {
      test->forced++;
      throw;
    }
  }
#endif
  pthread_cleanup_pop(0);
  return (void *)(uintptr_t)0x5354494f;
}

static struct timespec deadline(long milliseconds) {
  struct timespec now;
  if (clock_gettime(CLOCK_REALTIME, &now) != 0)
    fail("stdio cancellation: clock failed", 95);
  now.tv_sec += milliseconds / 1000;
  now.tv_nsec += (milliseconds % 1000) * 1000000;
  if (now.tv_nsec >= 1000000000) {
    now.tv_sec++;
    now.tv_nsec -= 1000000000;
  }
  return now;
}

static void wait_for_read(struct read_case *test) {
  for (int attempt = 0; attempt < 2000; attempt++) {
    if (__atomic_load_n(&test->entered, __ATOMIC_ACQUIRE)) {
      char pathname[96], data[256];
      snprintf(pathname, sizeof(pathname), "/proc/self/task/%d/syscall", test->tid);
      int descriptor = open(pathname, O_RDONLY | O_CLOEXEC);
      if (descriptor >= 0) {
        ssize_t count = read(descriptor, data, sizeof(data) - 1);
        close(descriptor);
        if (count > 0) {
          data[count] = '\0';
          long number;
          unsigned long descriptor_arg;
          if (sscanf(data, "%ld %lx", &number, &descriptor_arg) == 2 &&
              number == SYS_read && descriptor_arg == (unsigned long)test->fd)
            return;
        }
      }
    }
    struct timespec pause = {0, 1000000};
    nanosleep(&pause, NULL);
  }
  fail("stdio cancellation: worker never blocked in the expected read", 96);
}

int main(int argc, char **argv) {
  if (argc != 4)
    fail("usage: fixture SYMBOL blocked|pending|disabled|buffered cold|warm|unbuffered", 2);
  struct read_case test;
  memset(&test, 0, sizeof(test));
  test.name = argv[1];
  test.phase = argv[2];
  test.path = argv[3];
  if (strcmp(test.phase, "blocked") && strcmp(test.phase, "pending") &&
      strcmp(test.phase, "disabled") && strcmp(test.phase, "buffered"))
    fail("stdio cancellation: unknown phase", 2);
  if (strcmp(test.path, "cold") && strcmp(test.path, "warm") &&
      strcmp(test.path, "unbuffered"))
    fail("stdio cancellation: unknown path", 2);
  if (strcmp(test.phase, "buffered") == 0 && strcmp(test.path, "warm") != 0)
    fail("stdio cancellation: buffer-only control must use a warm stream", 2);

  const char *lookup_name = test.name;
  if (is_case(&test, "fread-large"))
    lookup_name = "fread";
  if (is_case(&test, "macro-getc_unlocked") ||
      is_case(&test, "macro-getchar_unlocked"))
    lookup_name = "__uflow";
  test.operation = lookup(lookup_name);
  verify_provider(dlsym(RTLD_DEFAULT, "fdopen"));
  verify_provider(dlsym(RTLD_DEFAULT, "fclose"));
  verify_provider(dlsym(RTLD_DEFAULT, "pthread_create"));

  int descriptors[2];
  if (pipe(descriptors) != 0)
    fail("stdio cancellation: pipe failed", 97);
  test.fd = descriptors[0];
  test.stream = fdopen(test.fd, "r");
  if (!test.stream)
    fail("stdio cancellation: fdopen failed", 97);
  if (strcmp(test.path, "unbuffered") == 0 &&
      setvbuf(test.stream, NULL, _IONBF, 0) != 0)
    fail("stdio cancellation: setvbuf failed", 97);
  FILE *saved_stdin = stdin;
  if (is_case(&test, "getchar") || is_case(&test, "getchar_unlocked") ||
      is_case(&test, "macro-getchar_unlocked"))
    stdin = test.stream;

  if (strcmp(test.path, "cold") != 0) {
    const char *initial = strcmp(test.phase, "buffered") == 0 ? "WR\n" : "W";
    size_t length = strlen(initial);
    if (write(descriptors[1], initial, length) != (ssize_t)length)
      fail("stdio cancellation: initial write failed", 98);
  }
  pthread_t thread;
  if (pthread_create(&thread, NULL, reader, &test) != 0)
    fail("stdio cancellation: thread creation failed", 99);
  void *result = NULL;
  if (strcmp(test.phase, "blocked") == 0 || strcmp(test.phase, "disabled") == 0) {
    wait_for_read(&test);
    if (pthread_cancel(thread) != 0)
      fail("stdio cancellation: cancel failed", 100);
    if (strcmp(test.phase, "disabled") == 0) {
      struct timespec short_deadline = deadline(30);
      if (pthread_timedjoin_np(thread, &result, &short_deadline) != ETIMEDOUT)
        fail("stdio cancellation: disabled request acted", 101);
      if (write(descriptors[1], "R\n", 2) != 2)
        fail("stdio cancellation: release write failed", 102);
      close(descriptors[1]);
      descriptors[1] = -1;
    }
  }
  struct timespec finish = deadline(2000);
  if (pthread_timedjoin_np(thread, &result, &finish) != 0)
    fail("stdio cancellation: join did not complete", 103);
  int expected_cancel = strcmp(test.phase, "pending") == 0 ||
                        strcmp(test.phase, "blocked") == 0;
  if (expected_cancel) {
    if (result != PTHREAD_CANCELED || test.cleaned != 1 || test.reused != 1)
      fail("stdio cancellation: cancellation or stream cleanup was lost", 104);
  } else if (result != (void *)(uintptr_t)0x5354494f || test.cleaned != 0 ||
             test.result != 1) {
    fail("stdio cancellation: valid read or non-cancel control failed", 105);
  }
#ifdef __cplusplus
  if (test.destructors != 2 || test.forced != expected_cancel)
    fail("stdio cancellation: C++ unwind was not preserved", 106);
#endif
  stdin = saved_stdin;
  free(test.line);
  if (fclose(test.stream) != 0)
    fail("stdio cancellation: stream could not be closed after the join", 107);
  if (descriptors[1] >= 0)
    close(descriptors[1]);
  printf("PASS %s %s %s\n", test.name, test.phase, test.path);
  return 0;
}
