// C++ exceptions thrown from callbacks that libc invokes must propagate
// through the libc frame to the caller's catch, exactly as with glibc
// (bd-rc0923-epic-eeuy4f.6). Each case prints one line; a libc frame that
// cannot be unwound through aborts the whole process instead.
#include <dirent.h>
#include <dlfcn.h>
#include <fcntl.h>
#include <ftw.h>
#include <link.h>
#include <pthread.h>
#include <printf.h>
#include <search.h>
#include <stdio.h>
#include <stdarg.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>
#include <wchar.h>

#define obstack_chunk_alloc malloc
#define obstack_chunk_free free
#include <obstack.h>

#include <cxxabi.h>
#include <cstdint>

#include <mutex>
#include <stdexcept>
#include <string>

struct Boom : std::runtime_error {
  explicit Boom(const char *where) : std::runtime_error(where) {}
};

template <typename F>
static void run_case(const char *name, F body) {
  try {
    body();
    printf("%s: returned normally\n", name);
  } catch (const Boom &e) {
    printf("%s: caught %s\n", name, e.what());
  }
  fflush(stdout);
}

static int ints[] = {5, 3, 9, 1, 7};

static int cmp_throw(const void *, const void *) { throw Boom("qsort-compar"); }
static int cmp_r_throw(const void *, const void *, void *) { throw Boom("qsort_r-compar"); }
static int bsearch_throw(const void *, const void *) { throw Boom("bsearch-compar"); }
static int lfind_throw(const void *, const void *) { throw Boom("lfind-compar"); }

static int tree_cmp(const void *a, const void *b) {
  return *(const int *)a - *(const int *)b;
}
static int tree_cmp_throw(const void *, const void *) { throw Boom("tsearch-compar"); }
static void twalk_throw(const void *, VISIT, int) { throw Boom("twalk-action"); }

static pthread_once_t once = PTHREAD_ONCE_INIT;
static int once_calls;
static void once_init() {
  once_calls++;
  if (once_calls == 1) {
    throw Boom("pthread_once-init");
  }
}

static int phdr_throw(struct dl_phdr_info *, size_t, void *) { throw Boom("dl_iterate_phdr-callback"); }

static ssize_t cookie_read(void *, char *, size_t) { throw Boom("fopencookie-read"); }
static int cookie_writes;
// Throws once; the FILE is flushed again at exit and must then succeed.
static ssize_t cookie_write(void *, const char *, size_t n) {
  if (cookie_writes++ == 0) {
    throw Boom("fopencookie-write");
  }
  return (ssize_t)n;
}

static int ftw_throw(const char *, const struct stat *, int) { throw Boom("ftw-callback"); }
static int nftw_throw(const char *, const struct stat *, int, struct FTW *) { throw Boom("nftw-callback"); }
static int scandir_filter_throw(const struct dirent *) { throw Boom("scandir-filter"); }

static int open_fd_count() {
  int n = 0;
  DIR *d = opendir("/proc/self/fd");
  if (!d) {
    return -1;
  }
  while (readdir(d)) {
    n++;
  }
  closedir(d);
  return n;
}

// Thread cancellation is a forced unwind: C++ destructors on the cancelled
// thread's stack run, and catch(abi::__forced_unwind&) sees it and must rethrow.
static int cancel_pipe[2];
struct Announce {
  const char *what;
  ~Announce() {
    printf("  destructor ran: %s\n", what);
    fflush(stdout);
  }
};
static void *cancelled_in_read(void *) {
  Announce guard{"read frame"};
  try {
    char c;
    ssize_t n = read(cancel_pipe[0], &c, 1);
    (void)n;
  } catch (abi::__forced_unwind &) {
    printf("  caught abi::__forced_unwind, rethrowing\n");
    fflush(stdout);
    throw;
  }
  return nullptr;
}

// Isolated native printf regression: every entrypoint is obtained through a
// correctly typed, potentially unwinding pointer. Some glibc headers declare
// buffer frontends noexcept; calling through those declarations would test the
// caller's noexcept contract instead of the libc frame's unwind boundary.
static int printf_stage, printf_type, printf_caller_drops, printf_callback_drops;
struct PrintfBoom { int stage; };
struct PrintfGuard {
  int *count;
  ~PrintfGuard() { ++*count; }
};
static void printf_check_at(bool condition, int line) {
  if (!condition) {
    dprintf(2, "printf-callback-unwind: assertion failed at %d\n", line);
    _exit(86);
  }
}
#define printf_check(condition) printf_check_at((condition), __LINE__)
static void *printf_symbol(const char *name) {
  void *address = dlsym(RTLD_DEFAULT, name);
  const char *expected = getenv("FRANKENLIBC_TEST_LIBRARY");
  if (!address || !expected) {
    static const char error[] = "printf-callback-unwind: missing provider\n";
    ssize_t written = write(2, error, sizeof error - 1);
    _exit(written < 0 ? 89 : 87);
  }
  Dl_info info;
  struct stat actual, wanted;
  if (!dladdr(address, &info) || stat(info.dli_fname, &actual) || stat(expected, &wanted)
      || actual.st_dev != wanted.st_dev || actual.st_ino != wanted.st_ino) {
    static const char error[] = "printf-callback-unwind: wrong provider\n";
    ssize_t written = write(2, error, sizeof error - 1);
    _exit(written < 0 ? 89 : 88);
  }
  return address;
}
static int printf_render_throw(FILE *, const printf_info *, const void *const *) {
  PrintfGuard guard{&printf_callback_drops};
  throw PrintfBoom{0};
}
static int printf_args_throw(const printf_info *, size_t n, int *types, int *sizes) {
  if (printf_stage == 1) {
    PrintfGuard guard{&printf_callback_drops};
    throw PrintfBoom{1};
  }
  if (n) {
    types[0] = printf_stage == 2 ? printf_type : PA_INT;
    if (sizes) sizes[0] = sizeof(int);
  }
  return 1;
}
static void printf_read_throw(void *, va_list *) {
  PrintfGuard guard{&printf_callback_drops};
  throw PrintfBoom{2};
}
static size_t printf_stream_count() {
  using Head = FILE *(*)();
  auto head = reinterpret_cast<Head>(dlsym(RTLD_DEFAULT, "_IO_list_all_get"));
  FILE *stream = head ? reinterpret_cast<Head>(printf_symbol("_IO_list_all_get"))()
                      : *reinterpret_cast<FILE **>(printf_symbol("_IO_list_all"));
  size_t count = 0;
  while (stream) {
    printf_check(++count < 4096);
    stream = stream->_chain;
  }
  return count;
}
static void *printf_other_thread_lock(void *opaque) {
  FILE *stream = static_cast<FILE *>(opaque);
  int result = ftrylockfile(stream);
  if (!result) funlockfile(stream);
  return reinterpret_cast<void *>(static_cast<intptr_t>(result));
}

static int invoke_printf(const char *name, FILE *stream, obstack *stack,
                         char **allocated, const char *fmt, ...) {
  void *address = printf_symbol(name);
  char buffer[128]; wchar_t wide[128]; const wchar_t *wfmt = L"%Q";
  va_list ap; va_start(ap, fmt);
  struct End { va_list *ap; ~End() { va_end(*ap); } } end{&ap};
#define IS(value) (!strcmp(name, value))
#define CALL(signature, ...) reinterpret_cast<signature>(address)(__VA_ARGS__)
  using Print = int (*)(const char *, ...);
  using VPrint = int (*)(const char *, va_list);
  using FPrint = int (*)(FILE *, const char *, ...);
  using VFPrint = int (*)(FILE *, const char *, va_list);
  using SPrint = int (*)(char *, const char *, ...);
  using VSPrint = int (*)(char *, const char *, va_list);
  using SNPrint = int (*)(char *, size_t, const char *, ...);
  using VSNPrint = int (*)(char *, size_t, const char *, va_list);
  using DPrint = int (*)(int, const char *, ...);
  using VDPrint = int (*)(int, const char *, va_list);
  using APrint = int (*)(char **, const char *, ...);
  using VAPrint = int (*)(char **, const char *, va_list);
  if (IS("printf") || IS("_IO_printf")) return CALL(Print, fmt, 42);
  if (IS("vprintf")) return CALL(VPrint, fmt, ap);
  if (IS("fprintf") || IS("_IO_fprintf")) return CALL(FPrint, stream, fmt, 42);
  if (IS("vfprintf") || IS("_IO_vfprintf")) return CALL(VFPrint, stream, fmt, ap);
  if (IS("sprintf") || IS("_IO_sprintf")) return CALL(SPrint, buffer, fmt, 42);
  if (IS("vsprintf") || IS("_IO_vsprintf")) return CALL(VSPrint, buffer, fmt, ap);
  if (IS("snprintf")) return CALL(SNPrint, buffer, sizeof buffer, fmt, 42);
  if (IS("vsnprintf") || IS("__vsnprintf")) return CALL(VSNPrint, buffer, sizeof buffer, fmt, ap);
  if (IS("dprintf")) return CALL(DPrint, fileno(stream), fmt, 42);
  if (IS("vdprintf")) return CALL(VDPrint, fileno(stream), fmt, ap);
  if (IS("asprintf") || IS("__asprintf")) return CALL(APrint, allocated, fmt, 42);
  if (IS("vasprintf")) return CALL(VAPrint, allocated, fmt, ap);
  using WPrint = int (*)(const wchar_t *, ...);
  using VWPrint = int (*)(const wchar_t *, va_list);
  using FWPrint = int (*)(FILE *, const wchar_t *, ...);
  using VFWPrint = int (*)(FILE *, const wchar_t *, va_list);
  using SWPrint = int (*)(wchar_t *, size_t, const wchar_t *, ...);
  using VSWPrint = int (*)(wchar_t *, size_t, const wchar_t *, va_list);
  if (IS("wprintf")) return CALL(WPrint, wfmt, 42);
  if (IS("vwprintf")) return CALL(VWPrint, wfmt, ap);
  if (IS("fwprintf")) return CALL(FWPrint, stream, wfmt, 42);
  if (IS("vfwprintf")) return CALL(VFWPrint, stream, wfmt, ap);
  if (IS("swprintf")) return CALL(SWPrint, wide, 128, wfmt, 42);
  if (IS("vswprintf")) return CALL(VSWPrint, wide, 128, wfmt, ap);
  using PrintChk = int (*)(int, const char *, ...);
  using VPrintChk = int (*)(int, const char *, va_list);
  using FPrintChk = int (*)(FILE *, int, const char *, ...);
  using VFPrintChk = int (*)(FILE *, int, const char *, va_list);
  using SPrintChk = int (*)(char *, int, size_t, const char *, ...);
  using VSPrintChk = int (*)(char *, int, size_t, const char *, va_list);
  using SNPrintChk = int (*)(char *, size_t, int, size_t, const char *, ...);
  using VSNPrintChk = int (*)(char *, size_t, int, size_t, const char *, va_list);
  using DPrintChk = int (*)(int, int, const char *, ...);
  using VDPrintChk = int (*)(int, int, const char *, va_list);
  using APrintChk = int (*)(char **, int, const char *, ...);
  using VAPrintChk = int (*)(char **, int, const char *, va_list);
  if (IS("__printf_chk")) return CALL(PrintChk, 1, fmt, 42);
  if (IS("__vprintf_chk")) return CALL(VPrintChk, 1, fmt, ap);
  if (IS("__fprintf_chk")) return CALL(FPrintChk, stream, 1, fmt, 42);
  if (IS("__vfprintf_chk")) return CALL(VFPrintChk, stream, 1, fmt, ap);
  if (IS("__sprintf_chk")) return CALL(SPrintChk, buffer, 1, sizeof buffer, fmt, 42);
  if (IS("__vsprintf_chk")) return CALL(VSPrintChk, buffer, 1, sizeof buffer, fmt, ap);
  if (IS("__snprintf_chk")) return CALL(SNPrintChk, buffer, sizeof buffer, 1, sizeof buffer, fmt, 42);
  if (IS("__vsnprintf_chk")) return CALL(VSNPrintChk, buffer, sizeof buffer, 1, sizeof buffer, fmt, ap);
  if (IS("__dprintf_chk")) return CALL(DPrintChk, fileno(stream), 1, fmt, 42);
  if (IS("__vdprintf_chk")) return CALL(VDPrintChk, fileno(stream), 1, fmt, ap);
  if (IS("__asprintf_chk")) return CALL(APrintChk, allocated, 1, fmt, 42);
  if (IS("__vasprintf_chk")) return CALL(VAPrintChk, allocated, 1, fmt, ap);
  using WPrintChk = int (*)(int, const wchar_t *, ...);
  using VWPrintChk = int (*)(int, const wchar_t *, va_list);
  using FWPrintChk = int (*)(FILE *, int, const wchar_t *, ...);
  using VFWPrintChk = int (*)(FILE *, int, const wchar_t *, va_list);
  using SWPrintChk = int (*)(wchar_t *, size_t, int, size_t, const wchar_t *, ...);
  using VSWPrintChk = int (*)(wchar_t *, size_t, int, size_t, const wchar_t *, va_list);
  if (IS("__wprintf_chk")) return CALL(WPrintChk, 1, wfmt, 42);
  if (IS("__vwprintf_chk")) return CALL(VWPrintChk, 1, wfmt, ap);
  if (IS("__fwprintf_chk")) return CALL(FWPrintChk, stream, 1, wfmt, 42);
  if (IS("__vfwprintf_chk")) return CALL(VFWPrintChk, stream, 1, wfmt, ap);
  if (IS("__swprintf_chk")) return CALL(SWPrintChk, wide, 128, 1, 128, wfmt, 42);
  if (IS("__vswprintf_chk")) return CALL(VSWPrintChk, wide, 128, 1, 128, wfmt, ap);
  using OPrint = int (*)(obstack *, const char *, ...);
  using VOPrint = int (*)(obstack *, const char *, va_list);
  using OPrintChk = int (*)(obstack *, int, const char *, ...);
  using VOPrintChk = int (*)(obstack *, int, const char *, va_list);
  if (IS("obstack_printf")) return CALL(OPrint, stack, fmt, 42);
  if (IS("obstack_vprintf")) return CALL(VOPrint, stack, fmt, ap);
  if (IS("__obstack_printf_chk")) return CALL(OPrintChk, stack, 1, fmt, 42);
  if (IS("__obstack_vprintf_chk")) return CALL(VOPrintChk, stack, 1, fmt, ap);
  if (IS("parse_printf_format")) {
    using Parse = size_t (*)(const char *, size_t, int *);
    int types[4]; return static_cast<int>(CALL(Parse, fmt, 4, types));
  }
  printf_check(false);
  return -1;
#undef CALL
#undef IS
}

static int printf_callback_case(const char *name, int stage) {
  alarm(10);
  printf_stage = stage;
  using Register = int (*)(int, printf_function *, printf_arginfo_size_function *);
  using RegisterType = int (*)(printf_va_arg_function *);
  auto reg = reinterpret_cast<Register>(printf_symbol("register_printf_specifier"));
  printf_type = reinterpret_cast<RegisterType>(printf_symbol("register_printf_type"))(printf_read_throw);
  printf_check(printf_type >= PA_LAST);
  printf_check(reg('Q', printf_render_throw, printf_args_throw) == 0);
  for (const char *symbol : {"fclose", "snprintf", "ftrylockfile", "funlockfile"}) (void)printf_symbol(symbol);
  FILE *stream = tmpfile(); printf_check(stream != nullptr);
  obstack stack; printf_check(obstack_init(&stack));
  size_t before = printf_stream_count();
  char *allocated = nullptr;
  bool caught = false;
  try {
    PrintfGuard guard{&printf_caller_drops};
    (void)invoke_printf(name, stream, &stack, &allocated, "%Q", 42);
  } catch (const PrintfBoom &e) { caught = e.stage == stage; }
  printf_check(caught && printf_caller_drops == 1 && printf_callback_drops == 1);
  printf_check(printf_stream_count() == before);
  pthread_t thread; void *result = nullptr;
  FILE *locked = strstr(name, "fprintf") || strstr(name, "fwprintf") ? stream : stdout;
  printf_check(pthread_create(&thread, nullptr, printf_other_thread_lock, locked) == 0);
  printf_check(pthread_join(thread, &result) == 0 && result == nullptr);
  printf_check(fclose(stream) == 0);
  obstack_free(&stack, nullptr); free(allocated);
  char again[32];
  using SNPrint = int (*)(char *, size_t, const char *, ...);
  printf_check(reinterpret_cast<SNPrint>(printf_symbol("snprintf"))(again, sizeof again, "%d", 41) == 2);
  printf_check(!strcmp(again, "41"));
  if (!strcmp(name, "__asprintf")) {
    using APrint = int (*)(char **, const char *, ...);
    auto alias = reinterpret_cast<APrint>(printf_symbol(name));
    allocated = nullptr;
    printf_check(alias(&allocated, "%d:%s", 17, "ok") == 5);
    printf_check(allocated && !strcmp(allocated, "17:ok")); free(allocated);
    allocated = nullptr;
    printf_check(alias(&allocated, "") == 0);
    printf_check(allocated && !*allocated); free(allocated);
  }
  static const char ok[] = "printf-callback-unwind:PASS\n";
  printf_check(write(1, ok, sizeof ok - 1) == sizeof ok - 1);
  return 0;
}

int main(int argc, char **argv) {
  if (argc == 4 && !strcmp(argv[1], "--printf")) return printf_callback_case(argv[2], atoi(argv[3]));
  if (argc != 1) return 2;
  run_case("qsort", [] { qsort(ints, 5, sizeof(int), cmp_throw); });
  run_case("qsort_r", [] { qsort_r(ints, 5, sizeof(int), cmp_r_throw, nullptr); });
  run_case("bsearch", [] {
    int key = 3;
    void *hit = bsearch(&key, ints, 5, sizeof(int), bsearch_throw);
    (void)hit;
  });
  run_case("lfind", [] {
    int key = 3;
    size_t n = 5;
    (void)lfind(&key, ints, &n, sizeof(int), lfind_throw);
  });

  void *root = nullptr;
  for (int &v : ints) {
    (void)tsearch(&v, &root, tree_cmp);
  }
  run_case("tsearch", [&] {
    int key = 42;
    (void)tsearch(&key, &root, tree_cmp_throw);
  });
  run_case("tfind", [&] {
    int key = 3;
    (void)tfind(&key, &root, tree_cmp_throw);
  });
  run_case("twalk", [&] { twalk(root, twalk_throw); });
  // The tree must still be intact and usable after the unwinds.
  {
    int key = 7;
    void *hit = tfind(&key, &root, tree_cmp);
    printf("tree_after_unwind: find7=%d\n", hit ? **(int **)hit : -1);
  }

  run_case("pthread_once_first", [] { pthread_once(&once, once_init); });
  run_case("pthread_once_retry", [] { pthread_once(&once, once_init); });
  printf("pthread_once calls=%d\n", once_calls);

  static std::once_flag flag;
  static int call_once_calls;
  auto init = [] {
    call_once_calls++;
    if (call_once_calls == 1) {
      throw Boom("std::call_once");
    }
  };
  run_case("std_call_once_first", [&] { std::call_once(flag, init); });
  run_case("std_call_once_retry", [&] { std::call_once(flag, init); });
  printf("std::call_once calls=%d\n", call_once_calls);

  run_case("dl_iterate_phdr", [] { dl_iterate_phdr(phdr_throw, nullptr); });

  run_case("fopencookie_read", [] {
    cookie_io_functions_t io = {cookie_read, nullptr, nullptr, nullptr};
    FILE *f = fopencookie(nullptr, "r", io);
    if (f) {
      (void)fgetc(f);
    }
  });
  run_case("fopencookie_write", [] {
    cookie_io_functions_t io = {nullptr, cookie_write, nullptr, nullptr};
    FILE *f = fopencookie(nullptr, "w", io);
    if (f) {
      fputs("x", f);
      fflush(f);
    }
  });

  run_case("ftw", [] { (void)ftw("/etc", ftw_throw, 4); });
  run_case("nftw", [] { (void)nftw("/etc", nftw_throw, 4, FTW_PHYS); });
  int fds_before = open_fd_count();
  run_case("scandir", [] {
    struct dirent **list = nullptr;
    (void)scandir("/etc", &list, scandir_filter_throw, alphasort);
  });

  // scandir releases its DIR when the filter unwinds (glibc does too).
  printf("scandir_fds_left_open=%d\n", open_fd_count() - fds_before);

  printf("pthread_cancel of a thread blocked in read:\n");
  fflush(stdout);
  if (pipe(cancel_pipe) == 0) {
    pthread_t t;
    void *ret = nullptr;
    pthread_create(&t, nullptr, cancelled_in_read, nullptr);
    usleep(100000);
    pthread_cancel(t);
    pthread_join(t, &ret);
    printf("  joined: %s\n", ret == PTHREAD_CANCELED ? "PTHREAD_CANCELED" : "returned");
  }

  // Normal operation still works after all the unwinds.
  int again[] = {3, 1, 2};
  qsort(again, 3, sizeof(int), tree_cmp);
  printf("qsort_after_unwind: %d %d %d\n", again[0], again[1], again[2]);
  return 0;
}
