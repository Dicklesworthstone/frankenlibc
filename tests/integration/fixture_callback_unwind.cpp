// C++ exceptions thrown from callbacks that libc invokes must propagate
// through the libc frame to the caller's catch, exactly as with glibc
// (bd-rc0923-epic-eeuy4f.6). Each case prints one line; a libc frame that
// cannot be unwound through aborts the whole process instead.
#include <dirent.h>
#include <fcntl.h>
#include <ftw.h>
#include <link.h>
#include <pthread.h>
#include <search.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

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

int main() {
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

  // Normal operation still works after all the unwinds.
  int again[] = {3, 1, 2};
  qsort(again, 3, sizeof(int), tree_cmp);
  printf("qsort_after_unwind: %d %d %d\n", again[0], again[1], again[2]);
  return 0;
}
