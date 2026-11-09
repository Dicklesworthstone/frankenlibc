// C++ exceptions thrown from callbacks that libc invokes must propagate
// through the libc frame to the caller's catch, exactly as with glibc
// (bd-rc0923-epic-eeuy4f.6). Each case prints one line; a libc frame that
// cannot be unwound through aborts the whole process instead.
#include <dirent.h>
#include <dlfcn.h>
#include <fcntl.h>
#include <fts.h>
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
#include <sys/syscall.h>
#include <sys/wait.h>
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

// Focused scan ABI observer, also loaded as a GNU-backed shared library by
// Rust. The supplied pointer is the actual resolved provider entrypoint.
static unsigned scan_throw_calls;
static int scan_throw_filter(const struct dirent *) {
  if (++scan_throw_calls == 3) throw Boom("scan-filter");
  return 1;
}
static int scan_throw_compare(const struct dirent **a, const struct dirent **b) {
  if (++scan_throw_calls == 3) throw Boom("scan-compare");
  return strcmp((*a)->d_name, (*b)->d_name);
}
extern "C" int flc_scan_unwind(void *function, unsigned variant, const char *directory,
                                unsigned stage) {
  using Select = int (*)(const struct dirent *);
  using Compare = int (*)(const struct dirent **, const struct dirent **);
  using Scan = int (*)(const char *, struct dirent ***, Select, Compare);
  using ScanAt = int (*)(int, const char *, struct dirent ***, Select, Compare);
  if (!function || variant > 3 || stage > 1) return 2;
  int before = open_fd_count();
  if (before < 0) return 3;
  auto sentinel = reinterpret_cast<struct dirent **>(uintptr_t(1));
  struct dirent **list = sentinel;
  scan_throw_calls = 0;
  bool caught = false;
  try {
    if (variant < 2)
      (void)reinterpret_cast<Scan>(function)(directory, &list,
          stage == 0 ? scan_throw_filter : nullptr, stage == 1 ? scan_throw_compare : nullptr);
    else
      (void)reinterpret_cast<ScanAt>(function)(AT_FDCWD, directory, &list,
          stage == 0 ? scan_throw_filter : nullptr, stage == 1 ? scan_throw_compare : nullptr);
  } catch (const Boom &error) {
    caught = !strcmp(error.what(), stage == 0 ? "scan-filter" : "scan-compare");
  }
  return caught && scan_throw_calls == 3 && list == sentinel && open_fd_count() == before ? 0 : 1;
}

// Keep an oracle crash local to its observation. A signal is returned as a
// negative number; it must never be mistaken for a caught exception.
extern "C" int flc_scan_unwind_child(void *function, unsigned variant,
                                      const char *directory, unsigned stage) {
  pid_t pid = fork();
  if (pid < 0) return 3;
  if (pid == 0) _exit(flc_scan_unwind(function, variant, directory, stage));
  int status = 0;
  if (waitpid(pid, &status, 0) != pid) return 4;
  return WIFSIGNALED(status) ? -WTERMSIG(status) : WIFEXITED(status) ? WEXITSTATUS(status) : 5;
}

static int walk_throw_calls, walk_throw_flags, walk_throw_origin;
static bool walk_throw_cwd_wrong;
static int walk_throw_visit(const char *path) {
  walk_throw_calls++;
  struct stat actual, expected;
  const char *slash = strrchr(path, '/');
  std::string parent = slash ? std::string(path, (size_t)(slash - path + 1)) : ".";
  const char *wanted = walk_throw_flags & FTW_CHDIR ? parent.c_str() : ".";
  if (syscall(SYS_newfstatat, AT_FDCWD, ".", &actual, 0) ||
      syscall(SYS_newfstatat, walk_throw_origin, wanted, &expected, 0) ||
      actual.st_dev != expected.st_dev || actual.st_ino != expected.st_ino)
    walk_throw_cwd_wrong = true;
  if (walk_throw_calls == 3) throw Boom("tree-walk");
  return 0;
}
static int walk_throw_simple(const char *path, const struct stat *, int) {
  return walk_throw_visit(path);
}
static int walk_throw_extended(const char *path, const struct stat *, int, struct FTW *) {
  return walk_throw_visit(path);
}
// Bits distinguish catch/count/CWD/FD/input/during-callback failures. A GNU
// cleanup failure remains an observation, not evidence that native cleanup works.
extern "C" int flc_walk_unwind(void *function, unsigned variant, const char *directory, int flags) {
  using Simple = int (*)(const char *, const struct stat *, int);
  using Extended = int (*)(const char *, const struct stat *, int, struct FTW *);
  using Walk = int (*)(const char *, Simple, int);
  using WalkNew = int (*)(const char *, Extended, int, int);
  if (!function || variant > 3) return 64;
  int before = open_fd_count();
  if (before < 0) return 64;
  walk_throw_origin = open(".", O_RDONLY | O_DIRECTORY | O_CLOEXEC);
  if (walk_throw_origin < 0) return 64;
  std::string input(directory);
  walk_throw_calls = 0; walk_throw_flags = flags; walk_throw_cwd_wrong = false;
  bool caught = false;
  try {
    if (variant < 2) (void)reinterpret_cast<Walk>(function)(directory, walk_throw_simple, 1);
    else (void)reinterpret_cast<WalkNew>(function)(directory, walk_throw_extended, 1, flags);
  } catch (const Boom &error) {
    caught = !strcmp(error.what(), "tree-walk");
  }
  struct stat actual, expected;
  bool cwd_ok = !syscall(SYS_newfstatat, AT_FDCWD, ".", &actual, 0) &&
      !syscall(SYS_newfstatat, walk_throw_origin, ".", &expected, 0) &&
      actual.st_dev == expected.st_dev && actual.st_ino == expected.st_ino;
  int result = (caught ? 0 : 1) | (walk_throw_calls == 3 ? 0 : 2) | (cwd_ok ? 0 : 4) |
      (input == directory ? 0 : 16) | (walk_throw_cwd_wrong ? 32 : 0);
  // Recover only after observing the caller's CWD; each case is also fork-isolated.
  int restored = fchdir(walk_throw_origin);
  int closed = close(walk_throw_origin);
  if (restored || closed) result |= 64;
  if (open_fd_count() != before) result |= 8;
  return result;
}
extern "C" int flc_walk_unwind_child(void *function, unsigned variant, const char *directory, int flags) {
  pid_t child = fork();
  if (child < 0) return 64;
  if (child == 0) _exit(flc_walk_unwind(function, variant, directory, flags));
  int status = 0;
  if (waitpid(child, &status, 0) != child) return 64;
  return WIFSIGNALED(status) ? -WTERMSIG(status) : WIFEXITED(status) ? WEXITSTATUS(status) : 64;
}

// The legacy cleanup-buffer ABI must use the same chain as pthread_exit and
// pthread_cancel. Exercise actual exported functions; modern pthread_cleanup_*
// macros use a different ABI and would not expose a broken legacy chain.
static void legacy_check_at(bool condition, int line) {
  if (!condition) {
    dprintf(2, "legacy-cleanup: assertion failed at %d\n", line);
    _exit(86);
  }
}
#define legacy_check(condition) legacy_check_at((condition), __LINE__)
static void *legacy_symbol(const char *name) {
  void *address = dlsym(RTLD_DEFAULT, name);
  // GNU retains defer/restore as compatibility-only symbols on newer hosts.
#if defined(__aarch64__)
  if (!address) address = dlvsym(RTLD_DEFAULT, name, "GLIBC_2.17");
#else
  if (!address) address = dlvsym(RTLD_DEFAULT, name, "GLIBC_2.2.5");
#endif
  const char *pin = getenv("FRANKENLIBC_TEST_LIBRARY");
  struct stat wanted, actual;
  Dl_info info;
  legacy_check(pin && address && dladdr(address, &info) && info.dli_fname);
  legacy_check(!syscall(SYS_newfstatat, AT_FDCWD, pin, &wanted, 0));
  legacy_check(!syscall(SYS_newfstatat, AT_FDCWD, info.dli_fname, &actual, 0));
  legacy_check(actual.st_dev == wanted.st_dev && actual.st_ino == wanted.st_ino);
  return address;
}
struct LegacyCleanupApi {
  using Push = void (*)(void *, void (*)(void *), void *);
  using Pop = void (*)(void *, int);
  using Change = int (*)(int, int *);
  Push push, push_defer;
  Pop pop, pop_restore;
  Change set_state, set_type;
  int (*create)(pthread_t *, const pthread_attr_t *, void *(*)(void *), void *);
  int (*join)(pthread_t, void **);
  int (*cancel)(pthread_t);
  pthread_t (*self)();
  void (*testcancel)();
  void (*exit)(void *);
};
static LegacyCleanupApi legacy_api() {
  // Potentially unwinding pointers deliberately have no C++ noexcept qualifier.
  return {
    reinterpret_cast<LegacyCleanupApi::Push>(legacy_symbol("_pthread_cleanup_push")),
    reinterpret_cast<LegacyCleanupApi::Push>(legacy_symbol("_pthread_cleanup_push_defer")),
    reinterpret_cast<LegacyCleanupApi::Pop>(legacy_symbol("_pthread_cleanup_pop")),
    reinterpret_cast<LegacyCleanupApi::Pop>(legacy_symbol("_pthread_cleanup_pop_restore")),
    reinterpret_cast<LegacyCleanupApi::Change>(legacy_symbol("pthread_setcancelstate")),
    reinterpret_cast<LegacyCleanupApi::Change>(legacy_symbol("pthread_setcanceltype")),
    reinterpret_cast<int (*)(pthread_t *, const pthread_attr_t *, void *(*)(void *), void *)>(legacy_symbol("pthread_create")),
    reinterpret_cast<int (*)(pthread_t, void **)>(legacy_symbol("pthread_join")),
    reinterpret_cast<int (*)(pthread_t)>(legacy_symbol("pthread_cancel")),
    reinterpret_cast<pthread_t (*)()>(legacy_symbol("pthread_self")),
    reinterpret_cast<void (*)()>(legacy_symbol("pthread_testcancel")),
    reinterpret_cast<void (*)(void *)>(legacy_symbol("pthread_exit"))
  };
}
struct LegacyCleanupTrace {
  LegacyCleanupApi api;
  int action;
  int order[4]{};
  int count = 0;
  int caller_drops = 0;
  int callback_drops = 0;
  int observed_type[2] = {-1, -1};
};
struct LegacyCleanupArgument {
  LegacyCleanupTrace *trace;
  int index;
  bool observe_type;
};
struct LegacyCleanupGuard {
  int *drops;
  ~LegacyCleanupGuard() { ++*drops; }
};
struct LegacyCleanupBoom {};
static void legacy_record(void *opaque) {
  auto *argument = static_cast<LegacyCleanupArgument *>(opaque);
  auto *trace = argument->trace;
  legacy_check(trace->count < 4);
  trace->order[trace->count++] = argument->index;
  if (argument->observe_type) {
    int old = -1;
    legacy_check(!trace->api.set_type(PTHREAD_CANCEL_DEFERRED, &old));
    trace->observed_type[argument->index - 1] = old;
    legacy_check(!trace->api.set_type(old, nullptr));
  }
}
static void legacy_throw(void *opaque) {
  auto *argument = static_cast<LegacyCleanupArgument *>(opaque);
  LegacyCleanupGuard guard{&argument->trace->callback_drops};
  legacy_record(opaque);
  throw LegacyCleanupBoom{};
}
static void legacy_exit_from_callback(void *opaque) {
  auto *argument = static_cast<LegacyCleanupArgument *>(opaque);
  LegacyCleanupGuard guard{&argument->trace->callback_drops};
  legacy_record(opaque);
  argument->trace->api.exit(reinterpret_cast<void *>(uintptr_t(73)));
  _exit(87);
}
static void legacy_pop_exception(LegacyCleanupTrace *trace, bool restore) {
  auto &api = trace->api;
  _pthread_cleanup_buffer outer{}, inner{};
  LegacyCleanupArgument outer_argument{trace, 1, true}, inner_argument{trace, 2, true};
  int saved_state = -1, saved_type = -1;
  legacy_check(!api.set_state(PTHREAD_CANCEL_DISABLE, &saved_state));
  legacy_check(!api.set_type(PTHREAD_CANCEL_ASYNCHRONOUS, &saved_type));
  auto push = restore ? api.push_defer : api.push;
  auto pop = restore ? api.pop_restore : api.pop;
  push(&outer, legacy_record, &outer_argument);
  push(&inner, legacy_throw, &inner_argument);
  bool caught = false;
  try {
    LegacyCleanupGuard guard{&trace->caller_drops};
    pop(&inner, 1);
  } catch (const LegacyCleanupBoom &) {
    caught = true;
  }
  pop(&outer, 1);
  int restored = -1;
  legacy_check(!api.set_type(saved_type, &restored));
  legacy_check(!api.set_state(saved_state, nullptr));
  legacy_check(caught && trace->caller_drops == 1 && trace->callback_drops == 1);
  legacy_check(trace->count == 2 && trace->order[0] == 2 && trace->order[1] == 1);
  legacy_check(restored == PTHREAD_CANCEL_ASYNCHRONOUS);
  legacy_check(trace->observed_type[0] == PTHREAD_CANCEL_ASYNCHRONOUS);
  legacy_check(trace->observed_type[1] ==
               (restore ? PTHREAD_CANCEL_DEFERRED : PTHREAD_CANCEL_ASYNCHRONOUS));
}
static void *legacy_cleanup_worker(void *opaque) {
  auto *trace = static_cast<LegacyCleanupTrace *>(opaque);
  auto &api = trace->api;
  _pthread_cleanup_buffer outer{}, inner{};
  LegacyCleanupArgument outer_argument{trace, 1, false}, inner_argument{trace, 2, false};
  if (trace->action == 4) {
    legacy_check(!api.set_state(PTHREAD_CANCEL_DISABLE, nullptr));
    legacy_check(!api.set_type(PTHREAD_CANCEL_ASYNCHRONOUS, nullptr));
  }
  api.push(&outer, legacy_record, &outer_argument);
  if (trace->action == 4) api.push_defer(&inner, legacy_record, &inner_argument);
  else api.push(&inner, trace->action == 5 ? legacy_exit_from_callback : legacy_record,
                &inner_argument);
  LegacyCleanupGuard guard{&trace->caller_drops};
  if (trace->action == 2) api.exit(reinterpret_cast<void *>(uintptr_t(73)));
  if (trace->action == 5) api.pop(&inner, 1);
  legacy_check(!api.cancel(api.self()));
  if (trace->action == 4) {
    legacy_check(!api.set_state(PTHREAD_CANCEL_ENABLE, nullptr));
    // A pending request acts while restoring ASYNCHRONOUS. The popped inner
    // handler must be gone, and the outer handler must still run exactly once.
    api.pop_restore(&inner, 1);
  } else {
    api.testcancel();
  }
  return reinterpret_cast<void *>(uintptr_t(99));
}
static int legacy_cleanup_case(const char *name) {
  const char *cases[] = {"pop", "pop-restore", "exit", "cancel", "restore-cancel", "pop-exit"};
  int action = -1;
  for (int i = 0; i < 6; ++i) if (!strcmp(name, cases[i])) action = i;
  if (action < 0) return 2;
  LegacyCleanupTrace trace{legacy_api(), action};
  if (action < 2) legacy_pop_exception(&trace, action == 1);
  else {
    pthread_t thread;
    void *result = nullptr;
    legacy_check(!trace.api.create(&thread, nullptr, legacy_cleanup_worker, &trace));
    legacy_check(!trace.api.join(thread, &result));
    legacy_check(result == ((action == 2 || action == 5)
                           ? reinterpret_cast<void *>(uintptr_t(73)) : PTHREAD_CANCELED));
    legacy_check(trace.caller_drops == 1);
    legacy_check(trace.callback_drops == (action == 5 ? 1 : 0));
    if (action == 4) legacy_check(trace.count == 1 && trace.order[0] == 1);
    else legacy_check(trace.count == 2 && trace.order[0] == 2 && trace.order[1] == 1);
  }
  printf("legacy-cleanup:%s:PASS\n", name);
  return 0;
}

// FTS calls comparators while opening roots, building a traversal frontier,
// and listing children. Each boundary must pass foreign exceptions through.
static bool fts_should_throw;
static int fts_comparisons, fts_callback_drops, fts_caller_drops;
struct FtsBoom {};
struct FtsGuard {
  int *drops;
  ~FtsGuard() { ++*drops; }
};
static void fts_check_at(bool condition, int line) {
  if (!condition) {
    dprintf(2, "fts-callback-unwind: assertion failed at %d\n", line);
    _exit(86);
  }
}
#define fts_check(condition) fts_check_at((condition), __LINE__)
static void *fts_symbol(const char *name) {
  void *address = dlsym(RTLD_DEFAULT, name);
  const char *pin = getenv("FRANKENLIBC_TEST_LIBRARY");
  struct stat wanted, actual;
  Dl_info info;
  fts_check(pin && address && dladdr(address, &info) && info.dli_fname);
  fts_check(!syscall(SYS_newfstatat, AT_FDCWD, pin, &wanted, 0));
  fts_check(!syscall(SYS_newfstatat, AT_FDCWD, info.dli_fname, &actual, 0));
  fts_check(actual.st_dev == wanted.st_dev && actual.st_ino == wanted.st_ino);
  return address;
}
template <typename Entry>
static int fts_compare(const Entry **a, const Entry **b) {
  ++fts_comparisons;
  if (fts_should_throw) {
    FtsGuard guard{&fts_callback_drops};
    throw FtsBoom{};
  }
  return strcmp((*a)->fts_name, (*b)->fts_name);
}
template <typename Stream, typename Entry>
static int fts_unwind_case(const char *phase, bool large) {
  if (strcmp(phase, "open") && strcmp(phase, "read") && strcmp(phase, "children")) return 2;
  // No noexcept qualifiers: these callbacks and their public callers unwind.
  using Open = Stream *(*)(char *const *, int, int (*)(const Entry **, const Entry **));
  using Read = Entry *(*)(Stream *);
  using Children = Entry *(*)(Stream *, int);
  using Close = int (*)(Stream *);
  auto open_api = reinterpret_cast<Open>(fts_symbol(large ? "fts64_open" : "fts_open"));
  auto read_api = reinterpret_cast<Read>(fts_symbol(large ? "fts64_read" : "fts_read"));
  auto children_api = reinterpret_cast<Children>(fts_symbol(large ? "fts64_children" : "fts_children"));
  auto close_api = reinterpret_cast<Close>(fts_symbol(large ? "fts64_close" : "fts_close"));
  char root[] = "/tmp/fl-fts-unwind-XXXXXX", a[128], b[128];
  fts_check(mkdtemp(root));
  fts_check(snprintf(a, sizeof a, "%s/a", root) > 0);
  fts_check(snprintf(b, sizeof b, "%s/b", root) > 0);
  for (const char *path : {a, b}) {
    int fd = open(path, O_CREAT | O_TRUNC | O_WRONLY, 0600);
    fts_check(fd >= 0 && !close(fd));
  }
  char *one_root[] = {root, nullptr}, *two_roots[] = {b, a, nullptr};
  Stream *stream = nullptr;
  bool caught = false;
  try {
    FtsGuard guard{&fts_caller_drops};
    if (!strcmp(phase, "open")) {
      fts_should_throw = true;
      stream = open_api(two_roots, FTS_PHYSICAL | FTS_NOCHDIR, fts_compare<Entry>);
    } else {
      stream = open_api(one_root, FTS_PHYSICAL | FTS_NOCHDIR, fts_compare<Entry>);
      fts_check(stream);
      Entry *entry = read_api(stream);
      fts_check(entry && entry->fts_info == FTS_D);
      fts_should_throw = true;
      if (!strcmp(phase, "read")) (void)read_api(stream);
      else (void)children_api(stream, 0);
    }
  } catch (const FtsBoom &) {
    caught = true;
  }
  fts_should_throw = false;
  fts_check(caught && fts_callback_drops == 1 && fts_caller_drops == 1 && fts_comparisons > 0);
  if (stream) fts_check(!close_api(stream));
  // Closing the interrupted stream and starting another walk must remain safe.
  stream = open_api(one_root, FTS_PHYSICAL | FTS_NOCHDIR, fts_compare<Entry>);
  fts_check(stream);
  int visits = 0, files = 0, comparisons_before = fts_comparisons;
  while (Entry *entry = read_api(stream)) {
    fts_check(++visits <= 4);
    if (entry->fts_info == FTS_F) {
      fts_check(files < 2 && !strcmp(entry->fts_name, files ? "b" : "a"));
      ++files;
    }
  }
  fts_check(visits == 4 && files == 2 && fts_comparisons > comparisons_before);
  fts_check(!close_api(stream));
  fts_check(!unlink(a) && !unlink(b) && !rmdir(root));
  printf("fts-callback-unwind:%s:%s:PASS\n", large ? "fts64" : "fts", phase);
  return 0;
}

int main(int argc, char **argv) {
  if (argc == 4 && !strcmp(argv[1], "--fts-unwind")) {
    if (!strcmp(argv[3], "0")) return fts_unwind_case<FTS, FTSENT>(argv[2], false);
    if (!strcmp(argv[3], "1")) return fts_unwind_case<FTS64, FTSENT64>(argv[2], true);
    return 2;
  }
  if (argc == 3 && !strcmp(argv[1], "--legacy-cleanup")) return legacy_cleanup_case(argv[2]);
  if (argc == 5 && !strcmp(argv[1], "--walk-unwind")) {
    const char *names[] = {"ftw", "ftw64", "nftw", "nftw64"};
    unsigned variant = (unsigned)strtoul(argv[2], nullptr, 10);
    if (variant > 3) return 64;
    void *function = dlsym(RTLD_DEFAULT, names[variant]);
    const char *pin = getenv("FLC_WALK_EXPECT_PROVIDER");
    struct stat expected, actual; Dl_info info;
    if (!pin || !function || syscall(SYS_newfstatat, AT_FDCWD, pin, &expected, 0) || !dladdr(function, &info) ||
        !info.dli_fname || syscall(SYS_newfstatat, AT_FDCWD, info.dli_fname, &actual, 0) ||
        expected.st_dev != actual.st_dev || expected.st_ino != actual.st_ino) return 42;
    int result = flc_walk_unwind(function, variant, argv[4], atoi(argv[3]));
    printf("walk unwind variant=%u flags=%s result=%d\n", variant, argv[3], result);
    return result;
  }
  if (argc == 5 && !strcmp(argv[1], "--scan-unwind")) {
    const char *names[] = {"scandir", "scandir64", "scandirat", "scandirat64"};
    unsigned variant = (unsigned)strtoul(argv[2], nullptr, 10);
    if (variant > 3) return 2;
    void *function = dlsym(RTLD_DEFAULT, names[variant]);
    const char *pin = getenv("FLC_SCAN_EXPECT_PROVIDER");
    struct stat expected, actual; Dl_info info;
    if (!pin || !function || syscall(SYS_newfstatat, AT_FDCWD, pin, &expected, 0) || !dladdr(function, &info) ||
        !info.dli_fname || syscall(SYS_newfstatat, AT_FDCWD, info.dli_fname, &actual, 0) ||
        expected.st_dev != actual.st_dev || expected.st_ino != actual.st_ino) return 42;
    int result = flc_scan_unwind(function, variant, argv[4], (unsigned)strtoul(argv[3], nullptr, 10));
    printf("scan unwind variant=%u stage=%s result=%d\n", variant, argv[3], result);
    return result;
  }
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
