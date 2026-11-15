/* Native stdio cancellation, compiled as both C and C++.
 *
 * Each invocation owns only anonymous pipes or socket pairs. A blocked case
 * is cancelled only after /proc confirms the worker is inside read(2),
 * write(2), or the admitted native socket polling loop on the tested
 * descriptor. Output transports start full unless the case explicitly
 * verifies a partially committed write or buffered flush.
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
#include <locale.h>
#include <poll.h>
#include <pthread.h>
#include <stdarg.h>
#include <stdint.h>
#include <stdio.h>
#include <stdio_ext.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <time.h>
#include <unistd.h>
#include <wchar.h>
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
  int output;
  int wide;
  int closed;
  int finished;
  char *memory;
  wchar_t *wide_memory;
  size_t memory_size;
  int socket_io;
  int expect_native;
  uintptr_t creator_tp;
  int creator_tid;
  pthread_t creator_thread;
  int recursive;
  int committed_prefix;
  size_t pending_after_cancel;
  char syscall_path[128];
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

static int named_in(const char *name, const char *const *names) {
  for (size_t i = 0; names[i] != NULL; i++)
    if (strcmp(name, names[i]) == 0)
      return 1;
  return 0;
}

static const char *const output_cases[] = {
    "fputc", "putc", "fputc_unlocked", "putc_unlocked", "putchar",
    "putchar_unlocked", "macro-putc_unlocked", "macro-putchar_unlocked",
    "fputs", "fputs_unlocked", "puts", "fwrite", "fwrite-large",
    "fwrite_unlocked", "fflush", "fflush_unlocked", "fclose", "putw",
    "fprintf", "printf", "vfprintf", "vprintf", "dprintf", "vdprintf",
    "__fprintf_chk", "__printf_chk", "__vfprintf_chk", "__vprintf_chk",
    "__dprintf_chk", "__vdprintf_chk", "__overflow", "_IO_putc", "_IO_puts",
    "_IO_fputs", "_IO_fwrite", "_IO_fflush", "_IO_fclose", "_IO_printf",
    "_IO_fprintf", "_IO_vfprintf", "fputwc", "putwc", "fputwc_unlocked",
    "putwc_unlocked", "putwchar", "putwchar_unlocked", "fputws",
    "fputws_unlocked", "fputws-large", "fwprintf", "wprintf", "vfwprintf",
    "vwprintf", "__fwprintf_chk", "__wprintf_chk", "__vfwprintf_chk",
    "__vwprintf_chk", "__woverflow", NULL};

static const char *const wide_cases[] = {
    "fgetwc", "getwc", "fgetwc_unlocked", "getwc_unlocked", "getwchar",
    "getwchar_unlocked", "fgetws", "fgetws_unlocked", "__fgetws_chk",
    "__fgetws_unlocked_chk", "fwscanf", "wscanf", "vfwscanf", "vwscanf",
    "__isoc99_fwscanf", "__isoc99_wscanf", "__isoc99_vfwscanf",
    "__isoc99_vwscanf", "__wuflow", "__wunderflow", "fputwc", "putwc",
    "fputwc_unlocked", "putwc_unlocked", "putwchar", "putwchar_unlocked",
    "fputws", "fputws_unlocked", "fputws-large", "fwprintf", "wprintf",
    "vfwprintf", "vwprintf", "__fwprintf_chk", "__wprintf_chk",
    "__vfwprintf_chk", "__vwprintf_chk", "__woverflow", NULL};

static const char *const standard_stream_cases[] = {
    "getchar", "getchar_unlocked", "macro-getchar_unlocked", "scanf",
    "vscanf", "__isoc99_scanf", "__isoc99_vscanf", "getwchar",
    "getwchar_unlocked", "wscanf", "vwscanf", "__isoc99_wscanf",
    "__isoc99_vwscanf", "putchar", "putchar_unlocked",
    "macro-putchar_unlocked", "puts", "_IO_puts", "printf", "vprintf",
    "__printf_chk", "__vprintf_chk", "_IO_printf", "putwchar",
    "putwchar_unlocked", "wprintf", "vwprintf", "__wprintf_chk",
    "__vwprintf_chk", NULL};

static int variadic_narrow(struct read_case *test, const char *format, ...) {
  va_list args;
  va_start(args, format);
  int result;
  if (is_case(test, "vprintf"))
    result = ((int (*)(const char *, va_list))test->operation)(format, args);
  else if (is_case(test, "__vprintf_chk"))
    result = ((int (*)(int, const char *, va_list))test->operation)(0, format, args);
  else if (is_case(test, "vdprintf"))
    result = ((int (*)(int, const char *, va_list))test->operation)(test->fd, format, args);
  else if (is_case(test, "__vdprintf_chk"))
    result = ((int (*)(int, int, const char *, va_list))test->operation)(test->fd, 0, format, args);
  else if (is_case(test, "__vfprintf_chk"))
    result = ((int (*)(FILE *, int, const char *, va_list))test->operation)(test->stream, 0, format, args);
  else if (is_case(test, "vscanf") || is_case(test, "__isoc99_vscanf"))
    result = ((int (*)(const char *, va_list))test->operation)(format, args);
  else
    result = ((int (*)(FILE *, const char *, va_list))test->operation)(test->stream, format, args);
  va_end(args);
  return result;
}

static int variadic_wide(struct read_case *test, const wchar_t *format, ...) {
  va_list args;
  va_start(args, format);
  int result;
  if (is_case(test, "vwprintf") || is_case(test, "vwscanf") ||
      is_case(test, "__isoc99_vwscanf"))
    result = ((int (*)(const wchar_t *, va_list))test->operation)(format, args);
  else if (is_case(test, "__vwprintf_chk"))
    result = ((int (*)(int, const wchar_t *, va_list))test->operation)(0, format, args);
  else if (is_case(test, "__vfwprintf_chk"))
    result = ((int (*)(FILE *, int, const wchar_t *, va_list))test->operation)(test->stream, 0, format, args);
  else
    result = ((int (*)(FILE *, const wchar_t *, va_list))test->operation)(test->stream, format, args);
  va_end(args);
  return result;
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
  /* Reserved aliases absent from this GNU dynamic symbol table use their
   * public GNU operation as the independent oracle. The candidate must always
   * export and provide the exact requested alias. */
  if (!address && strcmp(name, "__getline") == 0 &&
      getenv("FRANKENLIBC_TEST_LIBRARY") == NULL)
    address = dlsym(RTLD_DEFAULT, "getline");
  if (!address && strcmp(name, "_IO_vfscanf") == 0 &&
      getenv("FRANKENLIBC_TEST_LIBRARY") == NULL)
    address = dlsym(RTLD_DEFAULT, "vfscanf");
  if (!address)
    fail("stdio cancellation: required symbol missing", 91);
  verify_provider(address);
  return address;
}

static void operate(struct read_case *test) {
  char bytes[16384];
  wchar_t wide_bytes[4096];
  if (test->output) {
    int ch = strcmp(test->path, "line") == 0 ? '\n' : 'R';
    if (is_case(test, "fflush") || is_case(test, "fflush_unlocked") ||
        is_case(test, "_IO_fflush")) {
      test->result = ((int (*)(FILE *))test->operation)(test->stream) == 0;
    } else if (is_case(test, "fclose") || is_case(test, "_IO_fclose")) {
      test->result = ((int (*)(FILE *))test->operation)(test->stream) == 0;
      test->closed = 1;
    } else if (is_case(test, "fwrite") || is_case(test, "fwrite_unlocked") ||
               is_case(test, "fwrite-large") || is_case(test, "_IO_fwrite")) {
      size_t count = is_case(test, "fwrite-large") ? sizeof(bytes) : 2;
      for (size_t i = 0; i < count; i++)
        bytes[i] = strcmp(test->phase, "partial") == 0 ? (char)('!' + i % 90) : 'R';
      bytes[count - 1] = '\n';
      test->result = ((size_t (*)(const void *, size_t, size_t, FILE *))test->operation)(
                         bytes, 1, count, test->stream) == count;
    } else if (is_case(test, "fputs") || is_case(test, "fputs_unlocked") ||
               is_case(test, "_IO_fputs")) {
      test->result = ((int (*)(const char *, FILE *))test->operation)("R\n", test->stream) >= 0;
    } else if (is_case(test, "puts") || is_case(test, "_IO_puts")) {
      test->result = ((int (*)(const char *))test->operation)("R") >= 0;
    } else if (is_case(test, "fputws") || is_case(test, "fputws_unlocked") ||
               is_case(test, "fputws-large")) {
      for (size_t i = 0; i < sizeof(wide_bytes) / sizeof(wide_bytes[0]); i++)
        wide_bytes[i] = L'R';
      wide_bytes[4094] = L'\n';
      wide_bytes[4095] = L'\0';
      const wchar_t *value = is_case(test, "fputws-large") ? wide_bytes : L"R\n";
      test->result = ((int (*)(const wchar_t *, FILE *))test->operation)(value, test->stream) >= 0;
    } else if (is_case(test, "printf") || is_case(test, "_IO_printf")) {
      test->result = ((int (*)(const char *, ...))test->operation)("%s\n", "R") == 2;
    } else if (is_case(test, "fprintf") || is_case(test, "_IO_fprintf")) {
      test->result = ((int (*)(FILE *, const char *, ...))test->operation)(test->stream, "%s\n", "R") == 2;
    } else if (is_case(test, "dprintf")) {
      test->result = ((int (*)(int, const char *, ...))test->operation)(test->fd, "%s\n", "R") == 2;
    } else if (is_case(test, "__printf_chk")) {
      test->result = ((int (*)(int, const char *, ...))test->operation)(0, "%s\n", "R") == 2;
    } else if (is_case(test, "__fprintf_chk")) {
      test->result = ((int (*)(FILE *, int, const char *, ...))test->operation)(test->stream, 0, "%s\n", "R") == 2;
    } else if (is_case(test, "__dprintf_chk")) {
      test->result = ((int (*)(int, int, const char *, ...))test->operation)(test->fd, 0, "%s\n", "R") == 2;
    } else if (is_case(test, "vprintf") || is_case(test, "vfprintf") ||
               is_case(test, "vdprintf") || is_case(test, "_IO_vfprintf") ||
               is_case(test, "__vprintf_chk") || is_case(test, "__vfprintf_chk") ||
               is_case(test, "__vdprintf_chk")) {
      test->result = variadic_narrow(test, "%s\n", "R") == 2;
    } else if (is_case(test, "wprintf")) {
      test->result = ((int (*)(const wchar_t *, ...))test->operation)(L"%ls\n", L"R") == 2;
    } else if (is_case(test, "fwprintf")) {
      test->result = ((int (*)(FILE *, const wchar_t *, ...))test->operation)(test->stream, L"%ls\n", L"R") == 2;
    } else if (is_case(test, "__wprintf_chk")) {
      test->result = ((int (*)(int, const wchar_t *, ...))test->operation)(0, L"%ls\n", L"R") == 2;
    } else if (is_case(test, "__fwprintf_chk")) {
      test->result = ((int (*)(FILE *, int, const wchar_t *, ...))test->operation)(test->stream, 0, L"%ls\n", L"R") == 2;
    } else if (is_case(test, "vwprintf") || is_case(test, "vfwprintf") ||
               is_case(test, "__vwprintf_chk") || is_case(test, "__vfwprintf_chk")) {
      test->result = variadic_wide(test, L"%ls\n", L"R") == 2;
    } else if (is_case(test, "macro-putc_unlocked")) {
      test->result = putc_unlocked(ch, test->stream) == ch;
    } else if (is_case(test, "macro-putchar_unlocked")) {
      test->result = putchar_unlocked(ch) == ch;
    } else if (is_case(test, "putchar") || is_case(test, "putchar_unlocked")) {
      test->result = ((int (*)(int))test->operation)(ch) == ch;
    } else if (is_case(test, "putwchar") || is_case(test, "putwchar_unlocked")) {
      test->result = ((wint_t (*)(wchar_t))test->operation)((wchar_t)ch) == (wint_t)ch;
    } else if (is_case(test, "__overflow")) {
      test->result = ((int (*)(FILE *, int))test->operation)(test->stream, ch) == ch;
    } else if (is_case(test, "__woverflow")) {
      test->result = ((wint_t (*)(FILE *, wint_t))test->operation)(test->stream, (wint_t)ch) == (wint_t)ch;
    } else if (test->wide) {
      test->result = ((wint_t (*)(wchar_t, FILE *))test->operation)((wchar_t)ch, test->stream) == (wint_t)ch;
    } else if (is_case(test, "putw")) {
      test->result = ((int (*)(int, FILE *))test->operation)(0x52525252, test->stream) == 0;
    } else {
      test->result = ((int (*)(int, FILE *))test->operation)(ch, test->stream) == ch;
    }
  } else if (is_case(test, "fscanf") || is_case(test, "__isoc99_fscanf")) {
    test->result = ((int (*)(FILE *, const char *, ...))test->operation)(test->stream, "%c", bytes) == 1 && bytes[0] == 'R';
  } else if (is_case(test, "scanf") || is_case(test, "__isoc99_scanf")) {
    test->result = ((int (*)(const char *, ...))test->operation)("%c", bytes) == 1 && bytes[0] == 'R';
  } else if (is_case(test, "vfscanf") || is_case(test, "vscanf") ||
             is_case(test, "__isoc99_vfscanf") || is_case(test, "__isoc99_vscanf") ||
             is_case(test, "_IO_vfscanf") || is_case(test, "__vfscanf")) {
    test->result = variadic_narrow(test, "%c", bytes) == 1 && bytes[0] == 'R';
  } else if (is_case(test, "fwscanf") || is_case(test, "__isoc99_fwscanf")) {
    test->result = ((int (*)(FILE *, const wchar_t *, ...))test->operation)(test->stream, L"%lc", wide_bytes) == 1 && wide_bytes[0] == L'R';
  } else if (is_case(test, "wscanf") || is_case(test, "__isoc99_wscanf")) {
    test->result = ((int (*)(const wchar_t *, ...))test->operation)(L"%lc", wide_bytes) == 1 && wide_bytes[0] == L'R';
  } else if (is_case(test, "vfwscanf") || is_case(test, "vwscanf") ||
             is_case(test, "__isoc99_vfwscanf") || is_case(test, "__isoc99_vwscanf")) {
    test->result = variadic_wide(test, L"%lc", wide_bytes) == 1 && wide_bytes[0] == L'R';
  } else if (is_case(test, "fgetws") || is_case(test, "fgetws_unlocked")) {
    wchar_t *result = ((wchar_t *(*)(wchar_t *, int, FILE *))test->operation)(wide_bytes, 4096, test->stream);
    test->result = result == wide_bytes && wide_bytes[0] == L'R';
  } else if (is_case(test, "__fgetws_chk") || is_case(test, "__fgetws_unlocked_chk")) {
    wchar_t *result = ((wchar_t *(*)(wchar_t *, size_t, int, FILE *))test->operation)(wide_bytes, 4096, 4096, test->stream);
    test->result = result == wide_bytes && wide_bytes[0] == L'R';
  } else if (test->wide) {
    if (is_case(test, "getwchar") || is_case(test, "getwchar_unlocked"))
      test->result = ((wint_t (*)(void))test->operation)() == L'R';
    else
      test->result = ((wint_t (*)(FILE *))test->operation)(test->stream) == L'R';
  } else if (is_case(test, "fread") || is_case(test, "fread_unlocked") ||
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
  if (strcmp(test->phase, "partial-flush") == 0) {
    /* Keep the pending output intact: purging here would hide replay of bytes
     * that the native send adapter already reported as accepted. The parent
     * drains that prefix and completes the remaining flush after the join. */
    test->pending_after_cancel = __fpending(test->stream);
    test->reused = fileno(test->stream) == test->fd;
  } else if (test->output) {
    __fpurge(test->stream);
    clearerr(test->stream);
    test->reused = fileno(test->stream) == test->fd &&
                   setvbuf(test->stream, NULL, _IOFBF, 8192) == 0;
    if (test->reused)
      test->reused = test->wide ? fputwc(L'Q', test->stream) == L'Q'
                               : fputc('Q', test->stream) == 'Q';
  } else if (test->wide) {
    test->reused = ungetwc(L'Q', test->stream) == L'Q' && fgetwc(test->stream) == L'Q';
  } else {
    test->reused = ungetc('Q', test->stream) == 'Q' && fgetc(test->stream) == 'Q';
  }
  if (test->recursive) {
    /* The application owns two explicit locks. The interrupted libc operation
     * must release only its own lock before this handler runs. The joined
     * parent then verifies that exactly these two unlocks release the FILE. */
    funlockfile(test->stream);
    funlockfile(test->stream);
  }
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
  if (test->socket_io) {
    /* Native clone threads currently inherit the creator's thread pointer;
     * owned-tls-cache does not create an independent TCB. This checks backend
     * selection, not general native TLS safety. Keep the witness allocation-free. */
    if (test->tid == test->creator_tid ||
        pthread_equal(pthread_self(), test->creator_thread) ||
        (((uintptr_t)__builtin_thread_pointer() == test->creator_tp) != test->expect_native))
      fail("stdio cancellation: wrong thread backend", 89);
    memcpy(test->syscall_path, "/proc/", 6);
    ssize_t length = syscall(SYS_readlinkat, AT_FDCWD, "/proc/thread-self",
                             test->syscall_path + 6, sizeof(test->syscall_path) - 15);
    if (length <= 0 || (size_t)length >= sizeof(test->syscall_path) - 15)
      fail("stdio cancellation: thread observation unavailable", 96);
    memcpy(test->syscall_path + 6 + length, "/syscall", 9);
  }
  if (!test->output && strcmp(test->path, "cold") != 0) {
    int primed = test->wide ? fgetwc(test->stream) == L'W' : fgetc(test->stream) == 'W';
    if (!primed)
      fail("stdio cancellation: failed to prime stream", 92);
  }
  if (strcmp(test->phase, "disabled") == 0 &&
      pthread_setcancelstate(PTHREAD_CANCEL_DISABLE, NULL) != 0)
    fail("stdio cancellation: cannot disable cancellation", 93);

  if (test->recursive) {
    flockfile(test->stream);
    flockfile(test->stream);
  }

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
  if (test->recursive) {
    funlockfile(test->stream);
    funlockfile(test->stream);
  }
  __atomic_store_n(&test->finished, 1, __ATOMIC_RELEASE);
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

/* Do not format or allocate while an inherited-TLS native worker is running.
 * The kernel's proc view supplies the syscall and its arguments; read its
 * pointed-to pollfd through /proc/self/mem rather than trusting a test flag. */
static int syscall_arguments(const char *text, unsigned long long fields[7]) {
  for (int field = 0; field < 7; field++) {
    while (*text == ' ' || *text == '\t') text++;
    unsigned base = field == 0 ? 10 : 16;
    if (base == 16 && text[0] == '0' && text[1] == 'x') text += 2;
    int digits = 0;
    unsigned long long value = 0;
    for (;;) {
      unsigned digit = *text >= '0' && *text <= '9' ? (unsigned)(*text - '0') :
                       *text >= 'a' && *text <= 'f' ? (unsigned)(*text - 'a' + 10) : 16;
      if (digit >= base) break;
      if (value > (ULLONG_MAX - digit) / base) return 0;
      value = value * base + digit;
      digits++;
      text++;
    }
    if (!digits || (*text != ' ' && *text != '\t' && *text != '\n' && *text != 0)) return 0;
    fields[field] = value;
  }
  return 1;
}

static int same_socket(unsigned long long actual, int expected) {
  struct stat left, right;
  if (actual > INT_MAX || syscall(SYS_fstat, (int)actual, &left) != 0 ||
      syscall(SYS_fstat, expected, &right) != 0)
    return 0;
  return left.st_dev == right.st_dev && left.st_ino == right.st_ino &&
         (left.st_mode & S_IFMT) == S_IFSOCK && (right.st_mode & S_IFMT) == S_IFSOCK;
}

static void wait_for_socket(struct read_case *test) {
  int memory = (int)syscall(SYS_openat, AT_FDCWD, "/proc/self/mem", O_RDONLY | O_CLOEXEC, 0);
  if (memory < 0) fail("stdio cancellation: memory observation unavailable", 96);
  for (int attempt = 0; attempt < 2000; attempt++) {
    if (__atomic_load_n(&test->entered, __ATOMIC_ACQUIRE)) {
      char data[512];
      int fd = (int)syscall(SYS_openat, AT_FDCWD, test->syscall_path, O_RDONLY | O_CLOEXEC, 0);
      if (fd >= 0) {
        ssize_t size = syscall(SYS_read, fd, data, sizeof(data) - 1);
        (void)syscall(SYS_close, fd);
        if (size > 0) {
          data[size] = 0;
          unsigned long long fields[7];
          if (syscall_arguments(data, fields)) {
            int parked = fields[0] == (unsigned long long)(test->output ? SYS_write : SYS_read) &&
                         same_socket(fields[1], test->fd);
            if (test->expect_native && strcmp(test->phase, "disabled") != 0 &&
                fields[0] == SYS_ppoll && fields[2] == 1 && fields[3] != 0) {
              struct pollfd interest;
              struct timespec slice;
              parked = syscall(SYS_pread64, memory, &interest, sizeof(interest),
                                (off_t)fields[1]) == (ssize_t)sizeof(interest) &&
                       syscall(SYS_pread64, memory, &slice, sizeof(slice),
                                (off_t)fields[3]) == (ssize_t)sizeof(slice) &&
                       same_socket((unsigned long long)interest.fd, test->fd) &&
                       interest.events == (test->output ? POLLOUT : POLLIN) &&
                       slice.tv_sec == 0 && slice.tv_nsec > 0 && slice.tv_nsec <= 50000000;
            }
            if (parked) {
              (void)syscall(SYS_close, memory);
              return;
            }
          }
        }
      }
    }
    const struct timespec pause = {0, 1000000};
    (void)syscall(SYS_nanosleep, &pause, NULL);
  }
  (void)syscall(SYS_close, memory);
  fail("stdio cancellation: worker never blocked on the selected socket", 96);
}

static void wait_for_read(struct read_case *test) {
  if (test->socket_io) {
    wait_for_socket(test);
    return;
  }
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
              number == (test->output ? SYS_write : SYS_read) &&
              descriptor_arg == (unsigned long)test->fd)
            return;
        }
      }
    }
    struct timespec pause = {0, 1000000};
    nanosleep(&pause, NULL);
  }
  fail("stdio cancellation: worker never blocked in the expected syscall", 96);
}

static void fill_pipe(int fd) {
  char bytes[4096];
  memset(bytes, 'F', sizeof(bytes));
  int flags = fcntl(fd, F_GETFL);
  if (flags < 0 || fcntl(fd, F_SETFL, flags | O_NONBLOCK) != 0)
    fail("stdio cancellation: pipe fill setup failed", 108);
  while (syscall(SYS_write, fd, bytes, sizeof(bytes)) > 0) {}
  if (errno != EAGAIN || fcntl(fd, F_SETFL, flags) != 0)
    fail("stdio cancellation: pipe fill failed", 108);
}

static void drain_pipe(int fd) {
  char bytes[4096];
  int flags = fcntl(fd, F_GETFL);
  if (flags < 0 || fcntl(fd, F_SETFL, flags | O_NONBLOCK) != 0)
    fail("stdio cancellation: pipe drain setup failed", 108);
  ssize_t n;
  do { n = (ssize_t)syscall(SYS_read, fd, bytes, sizeof(bytes)); } while (n > 0);
  if ((n < 0 && errno != EAGAIN) || fcntl(fd, F_SETFL, flags) != 0)
    fail("stdio cancellation: pipe drain failed", 108);
}

static void fill_socket(int fd) {
  char bytes[4096];
  memset(bytes, 'F', sizeof(bytes));
  while (syscall(SYS_sendto, fd, bytes, sizeof(bytes), MSG_DONTWAIT | MSG_NOSIGNAL,
                 NULL, 0) > 0) {}
  if (errno != EAGAIN) fail("stdio cancellation: socket fill failed", 108);
}

static void drain_socket(int fd) {
  char bytes[4096];
  ssize_t n;
  do {
    n = syscall(SYS_recvfrom, fd, bytes, sizeof(bytes), MSG_DONTWAIT, NULL, NULL);
  } while (n > 0);
  if (n < 0 && errno != EAGAIN) fail("stdio cancellation: socket drain failed", 108);
}

static void verify_partial_output(const struct read_case *test, int peer) {
  char bytes[16384];
  size_t total = 0;
  for (;;) {
    ssize_t count = syscall(SYS_recvfrom, peer, bytes, sizeof(bytes), MSG_DONTWAIT, NULL, NULL);
    if (count < 0 && errno == EAGAIN) break;
    if (count <= 0) fail("stdio cancellation: partial output read failed", 111);
    for (ssize_t i = 0; i < count; i++)
      if (bytes[i] != (char)('!' + (total + (size_t)i) % 90))
        fail("stdio cancellation: committed prefix changed or replayed", 111);
    total += (size_t)count;
  }
  if (total != (size_t)test->committed_prefix || total == 0 || total >= sizeof(bytes))
    fail("stdio cancellation: committed prefix was lost or duplicated", 111);
}

static void verify_partial_flush(const struct read_case *test, int peer) {
  if (!test->expect_native) {
    /* GNU has one canceled blocking write: it cannot recover a partial count
     * that the kernel never returned. Retain the observation as a comparator,
     * not as an assertion that it implements native prefix accounting. */
    printf("GNU partial fflush: committed=%d pending=%zu\n",
           test->committed_prefix, test->pending_after_cancel);
    __fpurge(test->stream);
    drain_socket(peer);
    return;
  }
  if (test->pending_after_cancel != 16384U - (size_t)test->committed_prefix)
    fail("stdio cancellation: acknowledged flush prefix remained buffered", 112);
  char bytes[32768];
  size_t total = 0;
  for (int pass = 0; pass < 2; pass++) {
    for (;;) {
      ssize_t count = syscall(SYS_recvfrom, peer, bytes + total, sizeof(bytes) - total,
                              MSG_DONTWAIT, NULL, NULL);
      if (count < 0 && errno == EAGAIN) break;
      if (count <= 0) fail("stdio cancellation: partial flush drain failed", 112);
      total += (size_t)count;
      if (total >= sizeof(bytes)) fail("stdio cancellation: flush replay overflow", 112);
    }
    if (pass == 0) {
      if (total != (size_t)test->committed_prefix)
        fail("stdio cancellation: committed flush prefix changed", 112);
      int capacity = 65536;
      if (setsockopt(test->fd, SOL_SOCKET, SO_SNDBUF, &capacity, sizeof(capacity)) != 0 ||
          fflush(test->stream) != 0)
        fail("stdio cancellation: remaining flush failed", 112);
    }
  }
  if (total != 16384 || __fpending(test->stream) != 0)
    fail("stdio cancellation: resumed flush lost or duplicated bytes", 112);
  for (size_t i = 0; i < total; i++)
    if (bytes[i] != (char)('!' + i % 90))
      fail("stdio cancellation: resumed flush changed byte order", 112);
}

int main(int argc, char **argv) {
  if (argc != 4 && argc != 6)
    fail("usage: fixture SYMBOL PHASE PATH [socket host|native]", 2);
  struct read_case test;
  memset(&test, 0, sizeof(test));
  test.name = argv[1];
  test.phase = argv[2];
  test.path = argv[3];
  test.output = named_in(test.name, output_cases);
  test.wide = named_in(test.name, wide_cases);
  if (argc == 6) {
    if (strcmp(argv[4], "socket") || (strcmp(argv[5], "host") && strcmp(argv[5], "native")))
      fail("stdio cancellation: unknown transport or backend", 2);
    test.socket_io = 1;
    test.expect_native = strcmp(argv[5], "native") == 0;
    test.creator_tp = (uintptr_t)__builtin_thread_pointer();
    test.creator_tid = (int)syscall(SYS_gettid);
    test.creator_thread = pthread_self();
  }
  test.recursive = strcmp(test.path, "recursive") == 0;
  if (setlocale(LC_ALL, "C.UTF-8") == NULL)
    fail("stdio cancellation: UTF-8 locale unavailable", 2);
  if (strcmp(test.phase, "blocked") && strcmp(test.phase, "pending") &&
      strcmp(test.phase, "disabled") && strcmp(test.phase, "buffered") &&
      strcmp(test.phase, "partial") && strcmp(test.phase, "partial-flush"))
    fail("stdio cancellation: unknown phase", 2);
  if (strcmp(test.path, "cold") && strcmp(test.path, "warm") &&
      strcmp(test.path, "unbuffered") && strcmp(test.path, "line") &&
      strcmp(test.path, "memory") && strcmp(test.path, "partial") &&
      strcmp(test.path, "recursive"))
    fail("stdio cancellation: unknown path", 2);
  if (strcmp(test.phase, "buffered") == 0 && strcmp(test.path, "warm") != 0 &&
      strcmp(test.path, "memory") != 0)
    fail("stdio cancellation: buffer-only control must use a warm stream", 2);
  if (strcmp(test.phase, "partial") == 0 &&
      (!test.socket_io || !is_case(&test, "fwrite-large")))
    fail("stdio cancellation: partial transfer requires socket fwrite-large", 2);
  if (strcmp(test.phase, "partial-flush") == 0 &&
      (!test.socket_io || !is_case(&test, "fflush")))
    fail("stdio cancellation: partial flush requires socket fflush", 2);

  const char *lookup_name = test.name;
  if (is_case(&test, "fread-large"))
    lookup_name = "fread";
  if (is_case(&test, "fwrite-large"))
    lookup_name = "fwrite";
  if (is_case(&test, "fputws-large"))
    lookup_name = "fputws";
  if (is_case(&test, "macro-getc_unlocked") ||
      is_case(&test, "macro-getchar_unlocked"))
    lookup_name = "__uflow";
  if (is_case(&test, "macro-putc_unlocked") ||
      is_case(&test, "macro-putchar_unlocked"))
    lookup_name = "__overflow";
  test.operation = lookup(lookup_name);
  verify_provider(dlsym(RTLD_DEFAULT, "fdopen"));
  verify_provider(dlsym(RTLD_DEFAULT, "fclose"));
  verify_provider(dlsym(RTLD_DEFAULT, "pthread_create"));
  if (test.socket_io) {
    const char *const providers[] = {"pthread_join", "pthread_timedjoin_np", "pthread_cancel",
        "pthread_self", "pthread_setcancelstate", "__pthread_register_cancel",
        "__pthread_unregister_cancel", "__pthread_unwind_next", "flockfile", "funlockfile",
        "ftrylockfile", "__fpurge", "__errno_location", NULL};
    for (size_t i = 0; providers[i]; i++) verify_provider(dlsym(RTLD_DEFAULT, providers[i]));
    /* A line read must not discover an allocator hazard instead of testing I/O
     * cancellation: provide its caller-owned space before creating the worker. */
    test.line = (char *)malloc(16384);
    test.line_size = 16384;
    if (!test.line) fail("stdio cancellation: line storage allocation failed", 97);
  }

  int descriptors[2];
  if ((test.socket_io ? socketpair(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0, descriptors)
                      : pipe(descriptors)) != 0)
    fail("stdio cancellation: transport creation failed", 97);
  test.fd = descriptors[test.output ? 1 : 0];
  int partial_transfer = strcmp(test.phase, "partial") == 0 ||
                         strcmp(test.phase, "partial-flush") == 0;
  if (partial_transfer) {
    int size = 4096;
    if (setsockopt(test.fd, SOL_SOCKET, SO_SNDBUF, &size, sizeof(size)) != 0)
      fail("stdio cancellation: send capacity setup failed", 97);
  }
  if (strcmp(test.path, "memory") == 0) {
    test.stream = test.wide ? open_wmemstream(&test.wide_memory, &test.memory_size)
                            : open_memstream(&test.memory, &test.memory_size);
  } else {
    test.stream = fdopen(test.fd, test.output ? "w" : "r");
  }
  if (!test.stream)
    fail("stdio cancellation: fdopen failed", 97);
  int flushing = is_case(&test, "fflush") || is_case(&test, "fflush_unlocked") ||
                 is_case(&test, "fclose") || is_case(&test, "_IO_fflush") ||
                 is_case(&test, "_IO_fclose");
  int buffering = strcmp(test.path, "line") == 0 ? _IOLBF :
      (strcmp(test.path, "unbuffered") == 0 ||
       (test.output && strcmp(test.phase, "buffered") != 0 && !flushing)
           ? _IONBF : _IOFBF);
  char flush_buffer[32768];
  if (strcmp(test.path, "memory") != 0 &&
      setvbuf(test.stream, strcmp(test.phase, "partial-flush") == 0 ? flush_buffer : NULL, buffering,
              strcmp(test.phase, "partial-flush") == 0 ? 32768 : 8192) != 0)
    fail("stdio cancellation: setvbuf failed", 97);
  FILE *saved_stdin = stdin;
  FILE *saved_stdout = stdout;
  if (named_in(test.name, standard_stream_cases)) {
    if (test.output)
      stdout = test.stream;
    else
      stdin = test.stream;
  }
  if (test.output) {
    if (strcmp(test.path, "memory") != 0 && !partial_transfer) {
      if (test.socket_io) fill_socket(descriptors[1]);
      else fill_pipe(descriptors[1]);
    }
    if (strcmp(test.phase, "partial-flush") == 0) {
      char bytes[16384];
      for (size_t i = 0; i < sizeof(bytes); i++) bytes[i] = (char)('!' + i % 90);
      if (fwrite(bytes, 1, sizeof(bytes), test.stream) != sizeof(bytes) ||
          __fpending(test.stream) != sizeof(bytes))
        fail("stdio cancellation: partial flush setup failed", 98);
    } else if (flushing && fputs("R", test.stream) < 0) {
      fail("stdio cancellation: flush setup failed", 98);
    }
  }

  if (!test.output && strcmp(test.path, "cold") != 0) {
    const char *initial = strcmp(test.path, "partial") == 0 ? "W\xe2" :
                         (strcmp(test.phase, "buffered") == 0 ? "WR\n" : "W");
    size_t length = strlen(initial);
    if (write(descriptors[1], initial, length) != (ssize_t)length)
      fail("stdio cancellation: initial write failed", 98);
  }
  pthread_t thread;
  if (pthread_create(&thread, NULL, reader, &test) != 0)
    fail("stdio cancellation: thread creation failed", 99);
  void *result = NULL;
  if (strcmp(test.phase, "blocked") == 0 || strcmp(test.phase, "disabled") == 0 ||
      partial_transfer) {
    wait_for_read(&test);
    if (partial_transfer &&
        (syscall(SYS_ioctl, descriptors[0], FIONREAD, &test.committed_prefix) != 0 ||
         test.committed_prefix <= 0 || test.committed_prefix >= 16384))
      fail("stdio cancellation: no independently observed partial transfer", 111);
    if (pthread_cancel(thread) != 0)
      fail("stdio cancellation: cancel failed", 100);
    if (strcmp(test.phase, "disabled") == 0) {
      struct timespec short_deadline = deadline(30);
      if (pthread_timedjoin_np(thread, &result, &short_deadline) != ETIMEDOUT)
        fail("stdio cancellation: disabled request acted", 101);
      if (test.output) {
        for (int attempt = 0; attempt < 2000; attempt++) {
          if (test.socket_io) drain_socket(descriptors[0]);
          else drain_pipe(descriptors[0]);
          if (__atomic_load_n(&test.finished, __ATOMIC_ACQUIRE))
            break;
          struct timespec pause = {0, 1000000};
          nanosleep(&pause, NULL);
        }
      } else {
        if (write(descriptors[1], "R\n", 2) != 2)
          fail("stdio cancellation: release write failed", 102);
        close(descriptors[1]);
        descriptors[1] = -1;
      }
    }
  }
  struct timespec finish = deadline(2000);
  if (pthread_timedjoin_np(thread, &result, &finish) != 0)
    fail("stdio cancellation: join did not complete", 103);
  int expected_cancel = strcmp(test.phase, "pending") == 0 ||
                        strcmp(test.phase, "blocked") == 0 ||
                        partial_transfer;
  if (expected_cancel) {
    if (result != PTHREAD_CANCELED || test.cleaned != 1 || test.reused != 1)
      fail("stdio cancellation: cancellation or stream cleanup was lost", 104);
  } else if (result != (void *)(uintptr_t)0x5354494f || test.cleaned != 0 ||
             test.result != 1) {
    fail("stdio cancellation: valid I/O or non-cancel control failed", 105);
  }
#ifdef __cplusplus
  if (test.destructors != 2 || test.forced != expected_cancel)
    fail("stdio cancellation: C++ unwind was not preserved", 106);
#endif
  stdin = saved_stdin;
  stdout = saved_stdout;
  free(test.line);
  if (strcmp(test.phase, "partial") == 0)
    verify_partial_output(&test, descriptors[0]);
  else if (strcmp(test.phase, "partial-flush") == 0)
    verify_partial_flush(&test, descriptors[0]);
  else if (test.output && strcmp(test.path, "memory") != 0) {
    if (test.socket_io) drain_socket(descriptors[0]);
    else drain_pipe(descriptors[0]);
  }
  if (!test.closed && ftrylockfile(test.stream) != 0)
    fail("stdio cancellation: explicit stream lock remained owned", 109);
  if (!test.closed)
    funlockfile(test.stream);
  if (!test.closed && fclose(test.stream) != 0)
    fail("stdio cancellation: stream could not be closed after the join", 107);
  if (strcmp(test.path, "memory") == 0) {
    if (test.memory_size == 0 ||
        (test.wide ? test.wide_memory[0] != L'R' : test.memory[0] != 'R'))
      fail("stdio cancellation: output missed the selected memory stream", 110);
    free(test.memory);
    free(test.wide_memory);
    close(descriptors[0]);
    close(descriptors[1]);
  } else if (test.output) {
    close(descriptors[0]);
  } else if (descriptors[1] >= 0) {
    close(descriptors[1]);
  }
  printf("PASS %s %s %s\n", test.name, test.phase, test.path);
  return 0;
}
