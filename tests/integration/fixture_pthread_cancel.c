// Thread cancellation and cleanup handlers (bd-rc0923-epic-eeuy4f.24).
//
// Output must be byte-identical under host glibc and FrankenLibC:
//   - statically initialized condvars (PTHREAD_COND_INITIALIZER) work;
//   - pthread_exit and pthread_testcancel run pthread_cleanup_push handlers;
//   - pthread_cancel of a thread blocked in read, sleep, nanosleep, poll or
//     pthread_cond_wait, open of a FIFO, or fcntl(F_OFD_SETLKW) completes, runs its cleanup handlers (cond_wait's with
//     the mutex re-acquired), and pthread_join reports PTHREAD_CANCELED;
//   - a thread with cancellation disabled is not cancelled while blocked;
//   - a thread cancelled inside system() has its shell killed and reaped and
//     SIGINT's disposition restored (glibc's system cancel handler);
//   - every other cancellation point fl implements itself acts: blocked in it
//     (pipes, sockets, epoll, waits for a child, signals, semaphores,
//     condvars, joins, splice/tee/vmsplice), or entered with a
//     request already pending (pread/pwrite and the vector forms, close,
//     fsync, msync, copy_file_range, fallocate, ...), including the
//     _FORTIFY_SOURCE entry points (__read_chk, __recv_chk, __open_2, ...)
//     and the glibc-namespace aliases (__read, __recv, __waitpid, ...) that
//     programs bind to;
//   - a pending request does not abort the process inside calls fl
//     implements with its own file I/O (getpwnam, getgrnam, getaddrinfo);
//   - cleanup handlers run in LIFO order; pthread_cleanup_pop(1) runs one;
//     handlers popped with pop(0) do not run when the thread returns;
//   - the main thread can cancel itself (single-threaded) or be cancelled by
//     another thread. fl names the main thread by its tid, which glibc's
//     pthread_cancel would dereference. These run in a re-executed copy with
//     FRANKENLIBC_STARTUP_DELEGATE=1 (ignored by glibc): fl's default owned
//     startup does not yet give the main thread glibc's cancellation jump
//     buffer, so any unwind out of main (pthread_exit included) crashes there
//     -- a separate defect, recorded on bd-rc0923-epic-eeuy4f.24.
#define _GNU_SOURCE
#include <dlfcn.h>
#include <errno.h>
#include <fcntl.h>
#include <grp.h>
#include <netdb.h>
#include <poll.h>
#include <pthread.h>
#include <pwd.h>
#include <sched.h>
#include <semaphore.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/epoll.h>
#include <sys/ipc.h>
#include <sys/mman.h>
#include <sys/msg.h>
#include <sys/select.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/uio.h>
#include <sys/un.h>
#include <sys/wait.h>
#include <termios.h>
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

static void *blocked_system(void *arg) {
  (void)arg;
  pthread_cleanup_push(cleanup, "system");
  int rc = system("sleep 30");
  (void)rc;
  pthread_cleanup_pop(0);
  return NULL;
}

static char fifo_path[64];
static char lock_path[64];

static void *blocked_fifo_open(void *arg) {
  (void)arg;
  pthread_cleanup_push(cleanup, "open(FIFO)");
  int fd = open(fifo_path, O_RDONLY); // blocks until a writer opens it
  if (fd >= 0) {
    close(fd);
  }
  pthread_cleanup_pop(0);
  return NULL;
}

static void *blocked_ofd_lock(void *arg) {
  (void)arg;
  int fd = open(lock_path, O_RDWR);
  struct flock fl = {0};
  fl.l_type = F_WRLCK;
  fl.l_whence = SEEK_SET;
  pthread_cleanup_push(cleanup, "fcntl(F_OFD_SETLKW)");
  fcntl(fd, F_OFD_SETLKW, &fl); // main holds a conflicting OFD lock
  pthread_cleanup_pop(0);
  close(fd);
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

// ---------------------------------------------------------------------------
// Every cancellation point, one thread per call.
// ---------------------------------------------------------------------------

static int emptyr = -1;    // read end of an empty pipe: reads block
static int fullw = -1;     // write end of a full pipe: writes block
static int sockr = -1;     // socket with nothing to receive
static int sockw = -1;     // socket whose send buffer is full
static int listener = -1;  // listening socket nobody connects to
static int epfd = -1;      // epoll set watching `emptyr`
static int regfd = -1;     // regular file: the non-blocking points
static void *regmap;       // shared mapping of `regfd`, for msync
static pid_t kid = -1;     // child that never exits on its own
static sem_t never_posted;
static pthread_t sleeper;  // thread that never returns on its own
static char fifo2[64];
static int msq = -1;
static pthread_mutex_t m2 = PTHREAD_MUTEX_INITIALIZER;
static pthread_cond_t c2 = PTHREAD_COND_INITIALIZER;
static volatile int cleanup_ran;
static volatile int returned_after_call;
static int cancel_sent;

static struct timespec in_100s(clockid_t clock) {
  struct timespec ts;
  clock_gettime(clock, &ts);
  ts.tv_sec += 100;
  return ts;
}

static void *sym(const char *name) { return dlsym(RTLD_DEFAULT, name); }

static void cp_write(void) { (void)!write(fullw, "x", 1); }
static void cp_writev(void) {
  struct iovec v = {"x", 1};
  (void)!writev(fullw, &v, 1);
}
static void cp_readv(void) {
  char c;
  struct iovec v = {&c, 1};
  (void)!readv(emptyr, &v, 1);
}
static void cp_usleep(void) { usleep(50000000); }
static void cp_clock_nanosleep(void) {
  struct timespec t = {100, 0};
  clock_nanosleep(CLOCK_MONOTONIC, 0, &t, NULL);
}
static void cp_ppoll(void) {
  struct pollfd p = {emptyr, POLLIN, 0};
  ppoll(&p, 1, NULL, NULL);
}
static void cp_select(void) {
  fd_set r;
  FD_ZERO(&r);
  FD_SET(emptyr, &r);
  select(emptyr + 1, &r, NULL, NULL, NULL);
}
static void cp_pselect(void) {
  fd_set r;
  FD_ZERO(&r);
  FD_SET(emptyr, &r);
  pselect(emptyr + 1, &r, NULL, NULL, NULL, NULL);
}
static void cp_epoll_wait(void) {
  struct epoll_event e;
  epoll_wait(epfd, &e, 1, -1);
}
static void cp_epoll_pwait(void) {
  struct epoll_event e;
  epoll_pwait(epfd, &e, 1, -1, NULL);
}
static void cp_epoll_pwait2(void) {
  struct epoll_event e;
  epoll_pwait2(epfd, &e, 1, NULL, NULL);
}
static void cp_accept(void) { accept(listener, NULL, NULL); }
static void cp_accept4(void) { accept4(listener, NULL, NULL, 0); }
static void cp_recv(void) {
  char c;
  recv(sockr, &c, 1, 0);
}
static void cp_recvfrom(void) {
  char c;
  recvfrom(sockr, &c, 1, 0, NULL, NULL);
}
static void cp_recvmsg(void) {
  char c;
  struct iovec v = {&c, 1};
  struct msghdr m = {0};
  m.msg_iov = &v;
  m.msg_iovlen = 1;
  recvmsg(sockr, &m, 0);
}
static void cp_recvmmsg(void) {
  char c;
  struct iovec v = {&c, 1};
  struct mmsghdr m = {0};
  m.msg_hdr.msg_iov = &v;
  m.msg_hdr.msg_iovlen = 1;
  recvmmsg(sockr, &m, 1, 0, NULL);
}
static void cp_send(void) { send(sockw, "x", 1, 0); }
static void cp_sendto(void) { sendto(sockw, "x", 1, 0, NULL, 0); }
static void cp_sendmsg(void) {
  struct iovec v = {"x", 1};
  struct msghdr m = {0};
  m.msg_iov = &v;
  m.msg_iovlen = 1;
  sendmsg(sockw, &m, 0);
}
static void cp_sendmmsg(void) {
  struct iovec v = {"x", 1};
  struct mmsghdr m = {0};
  m.msg_hdr.msg_iov = &v;
  m.msg_hdr.msg_iovlen = 1;
  sendmmsg(sockw, &m, 1, 0);
}
static void cp_waitpid(void) { waitpid(kid, NULL, 0); }
static void cp_wait(void) { wait(NULL); }
static void cp_wait3(void) { wait3(NULL, 0, NULL); }
static void cp_wait4(void) { wait4(kid, NULL, 0, NULL); }
static void cp_waitid(void) {
  siginfo_t si;
  waitid(P_PID, (id_t)kid, &si, WEXITED);
}
static sigset_t usr2_only(void) {
  sigset_t s;
  sigemptyset(&s);
  sigaddset(&s, SIGUSR2);
  return s;
}
static void cp_sigwait(void) {
  sigset_t s = usr2_only();
  int sig;
  sigwait(&s, &sig);
}
static void cp_sigwaitinfo(void) {
  sigset_t s = usr2_only();
  sigwaitinfo(&s, NULL);
}
static void cp_sigtimedwait(void) {
  sigset_t s = usr2_only();
  struct timespec t = {100, 0};
  sigtimedwait(&s, NULL, &t);
}
static void cp_sigsuspend(void) {
  sigset_t s = usr2_only();
  sigsuspend(&s);
}
static void cp_pause(void) { pause(); }
static void cp_sem_wait(void) { sem_wait(&never_posted); }
static void cp_sem_timedwait(void) {
  struct timespec t = in_100s(CLOCK_REALTIME);
  sem_timedwait(&never_posted, &t);
}
static void cp_sem_clockwait(void) {
  struct timespec t = in_100s(CLOCK_MONOTONIC);
  sem_clockwait(&never_posted, CLOCK_MONOTONIC, &t);
}
static void unlock_m2(void *arg) {
  (void)arg;
  pthread_mutex_unlock(&m2);
}
static void cp_cond_timedwait(void) {
  struct timespec t = in_100s(CLOCK_REALTIME);
  pthread_mutex_lock(&m2);
  pthread_cleanup_push(unlock_m2, NULL);
  pthread_cond_timedwait(&c2, &m2, &t);
  pthread_cleanup_pop(1);
}
static void cp_cond_clockwait(void) {
  struct timespec t = in_100s(CLOCK_MONOTONIC);
  pthread_mutex_lock(&m2);
  pthread_cleanup_push(unlock_m2, NULL);
  pthread_cond_clockwait(&c2, &m2, CLOCK_MONOTONIC, &t);
  pthread_cleanup_pop(1);
}
static void cp_pthread_join(void) { pthread_join(sleeper, NULL); }
static void cp_msgrcv(void) {
  struct {
    long type;
    char text[8];
  } m;
  msgrcv(msq, &m, sizeof m.text, 0, 0);
}
static void cp_splice(void) { splice(emptyr, NULL, fullw, NULL, 1, 0); }
static void cp_tee(void) { tee(emptyr, fullw, 1, 0); }
static void cp_vmsplice(void) {
  struct iovec v = {"x", 1};
  vmsplice(fullw, &v, 1, 0);
}
static void cp_creat_fifo(void) {
  int fd = creat(fifo2, 0600);  // a writer blocks until a reader opens
  if (fd >= 0) {
    close(fd);
  }
}

// The _FORTIFY_SOURCE entry points and the glibc-namespace aliases, looked
// up as a program binds them (the same symbol the dynamic linker resolves).
static void cp_read_chk(void) {
  ssize_t (*f)(int, void *, size_t, size_t) = sym("__read_chk");
  char c[4];
  f(emptyr, c, 1, sizeof c);
}
static void cp_recv_chk(void) {
  ssize_t (*f)(int, void *, size_t, size_t, int) = sym("__recv_chk");
  char c[4];
  f(sockr, c, 1, sizeof c, 0);
}
static void cp_recvfrom_chk(void) {
  ssize_t (*f)(int, void *, size_t, size_t, int, void *, socklen_t *) = sym("__recvfrom_chk");
  char c[4];
  f(sockr, c, 1, sizeof c, 0, NULL, NULL);
}
static void cp_open_2(void) {
  int (*f)(const char *, int) = sym("__open_2");
  int fd = f(fifo2, O_RDONLY);
  if (fd >= 0) {
    close(fd);
  }
}
static void cp_openat_2(void) {
  int (*f)(int, const char *, int) = sym("__openat_2");
  int fd = f(AT_FDCWD, fifo2, O_RDONLY);
  if (fd >= 0) {
    close(fd);
  }
}
static void cp_alias_read(void) {
  ssize_t (*f)(int, void *, size_t) = sym("__read");
  char c;
  f(emptyr, &c, 1);
}
static void cp_alias_write(void) {
  ssize_t (*f)(int, const void *, size_t) = sym("__write");
  f(fullw, "x", 1);
}
static void cp_alias_recv(void) {
  ssize_t (*f)(int, void *, size_t, int) = sym("__recv");
  char c;
  f(sockr, &c, 1, 0);
}
static void cp_alias_send(void) {
  ssize_t (*f)(int, const void *, size_t, int) = sym("__send");
  f(sockw, "x", 1, 0);
}
static void cp_alias_nanosleep(void) {
  int (*f)(const struct timespec *, struct timespec *) = sym("__nanosleep");
  struct timespec t = {100, 0};
  f(&t, NULL);
}
static void cp_alias_waitpid(void) {
  pid_t (*f)(pid_t, int *, int) = sym("__waitpid");
  f(kid, NULL, 0);
}
static void cp_alias_wait(void) {
  pid_t (*f)(int *) = sym("__wait");
  f(NULL);
}
static void cp_alias_sigtimedwait(void) {
  int (*f)(const sigset_t *, siginfo_t *, const struct timespec *) = sym("__sigtimedwait");
  sigset_t s = usr2_only();
  struct timespec t = {100, 0};
  f(&s, NULL, &t);
}

// Points that do not block here: the request is already pending on entry.
static void cp_pread(void) {
  char c;
  (void)!pread(regfd, &c, 1, 0);
}
static void cp_pwrite(void) { (void)!pwrite(regfd, "a", 1, 0); }
static void cp_preadv(void) {
  char c;
  struct iovec v = {&c, 1};
  (void)!preadv(regfd, &v, 1, 0);
}
static void cp_pwritev(void) {
  struct iovec v = {"a", 1};
  (void)!pwritev(regfd, &v, 1, 0);
}
static void cp_preadv2(void) {
  char c;
  struct iovec v = {&c, 1};
  (void)!preadv2(regfd, &v, 1, 0, 0);
}
static void cp_pwritev2(void) {
  struct iovec v = {"a", 1};
  (void)!pwritev2(regfd, &v, 1, 0, 0);
}
static void cp_pread_chk(void) {
  ssize_t (*f)(int, void *, size_t, off_t, size_t) = sym("__pread_chk");
  char c[4];
  f(regfd, c, 1, 0, sizeof c);
}
static void cp_alias_pread64(void) {
  ssize_t (*f)(int, void *, size_t, off_t) = sym("__pread64");
  char c;
  f(regfd, &c, 1, 0);
}
static void cp_alias_pwrite64(void) {
  ssize_t (*f)(int, const void *, size_t, off_t) = sym("__pwrite64");
  f(regfd, "a", 1, 0);
}
static void cp_close(void) { close(dup(regfd)); }
static void cp_alias_close(void) {
  int (*f)(int) = sym("__close");
  f(dup(regfd));
}
static void cp_fsync(void) { fsync(regfd); }
static void cp_fdatasync(void) { fdatasync(regfd); }
static void cp_msync(void) { msync(regmap, 4096, MS_SYNC); }
static void cp_copy_file_range(void) {
  loff_t off = 0;
  copy_file_range(regfd, &off, regfd, NULL, 0, 0);
}
static void cp_fallocate(void) { fallocate(regfd, 0, 0, 4096); }
static void cp_sync_file_range(void) { sync_file_range(regfd, 0, 0, 0); }
static void cp_tcdrain(void) { tcdrain(regfd); }

// Calls fl implements with its own file I/O. glibc acts inside them; fl
// does not, but must not abort the process either: testcancel acts.
static void cp_getpwnam(void) {
  getpwnam("root");
  pthread_testcancel();
}
static void cp_getgrnam(void) {
  getgrnam("root");
  pthread_testcancel();
}
static void cp_getaddrinfo(void) {
  struct addrinfo hints, *ai = NULL;
  memset(&hints, 0, sizeof hints);
  hints.ai_family = AF_INET;
  if (getaddrinfo("localhost", NULL, &hints, &ai) == 0) {
    freeaddrinfo(ai);
  }
  pthread_testcancel();
}

struct cp_case {
  const char *name;
  void (*call)(void);
};

static void mark_cleanup(void *arg) {
  (void)arg;
  cleanup_ran = 1;
}

static void *blocked_in(void *arg) {
  const struct cp_case *c = arg;
  pthread_cleanup_push(mark_cleanup, NULL);
  c->call();
  returned_after_call = 1;
  pthread_cleanup_pop(0);
  return NULL;
}

static void *pending_at(void *arg) {
  const struct cp_case *c = arg;
  pthread_setcancelstate(PTHREAD_CANCEL_DISABLE, NULL);
  while (!__atomic_load_n(&cancel_sent, __ATOMIC_ACQUIRE)) {
    sched_yield();
  }
  pthread_cleanup_push(mark_cleanup, NULL);
  // Deferred: enabling does not act; the next cancellation point does.
  pthread_setcancelstate(PTHREAD_CANCEL_ENABLE, NULL);
  c->call();
  returned_after_call = 1;
  pthread_cleanup_pop(0);
  return NULL;
}

static void run_point(const struct cp_case *c, int pending) {
  pthread_t t;
  void *ret = NULL;
  cleanup_ran = 0;
  returned_after_call = 0;
  __atomic_store_n(&cancel_sent, 0, __ATOMIC_RELEASE);
  pthread_create(&t, NULL, pending ? pending_at : blocked_in, (void *)c);
  if (!pending) {
    struct timespec settle = {0, 40000000};
    nanosleep(&settle, NULL);
  }
  pthread_cancel(t);
  __atomic_store_n(&cancel_sent, 1, __ATOMIC_RELEASE);
  pthread_join(t, &ret);
  printf("  %-22s %s: cleanup=%s %s\n", c->name, pending ? "pending" : "blocked",
         cleanup_ran ? "yes" : "no",
         ret == PTHREAD_CANCELED ? "PTHREAD_CANCELED"
                                 : (returned_after_call ? "returned" : "exited"));
  fflush(stdout);
}

static void *sleeps_forever(void *arg) {
  (void)arg;
  for (;;) {
    pause();
  }
  return NULL;
}

static int setup_points(void) {
  int p[2];
  if (pipe(p) != 0) {
    return -1;
  }
  emptyr = p[0];
  if (pipe2(p, O_NONBLOCK) != 0) {
    return -1;
  }
  char chunk[4096];
  memset(chunk, 'x', sizeof chunk);
  while (write(p[1], chunk, sizeof chunk) > 0) {
  }
  while (write(p[1], chunk, 1) > 0) {
  }
  fcntl(p[1], F_SETFL, 0);
  fullw = p[1];
  int sv[2];
  if (socketpair(AF_UNIX, SOCK_STREAM, 0, sv) != 0) {
    return -1;
  }
  sockr = sv[0];
  if (socketpair(AF_UNIX, SOCK_STREAM | SOCK_NONBLOCK, 0, sv) != 0) {
    return -1;
  }
  while (send(sv[0], chunk, sizeof chunk, 0) > 0) {
  }
  while (send(sv[0], chunk, 1, 0) > 0) {
  }
  fcntl(sv[0], F_SETFL, 0);
  sockw = sv[0];
  listener = socket(AF_UNIX, SOCK_STREAM, 0);
  struct sockaddr_un sa;
  memset(&sa, 0, sizeof sa);
  sa.sun_family = AF_UNIX;
  snprintf(sa.sun_path + 1, sizeof sa.sun_path - 1, "fl_cancel_%d", (int)getpid());
  if (bind(listener, (struct sockaddr *)&sa, sizeof sa) != 0 || listen(listener, 1) != 0) {
    return -1;
  }
  epfd = epoll_create1(0);
  struct epoll_event ev;
  memset(&ev, 0, sizeof ev);
  ev.events = EPOLLIN;
  epoll_ctl(epfd, EPOLL_CTL_ADD, emptyr, &ev);
  char path[64];
  snprintf(path, sizeof path, "/tmp/fl_cancel_reg_%d", (int)getpid());
  regfd = open(path, O_RDWR | O_CREAT | O_TRUNC, 0600);
  unlink(path);
  if (regfd < 0 || ftruncate(regfd, 4096) != 0) {
    return -1;
  }
  regmap = mmap(NULL, 4096, PROT_READ | PROT_WRITE, MAP_SHARED, regfd, 0);
  snprintf(fifo2, sizeof fifo2, "/tmp/fl_cancel_fifo2_%d", (int)getpid());
  if (mkfifo(fifo2, 0600) != 0) {
    return -1;
  }
  sem_init(&never_posted, 0, 0);
  pthread_create(&sleeper, NULL, sleeps_forever, NULL);
  msq = msgget(IPC_PRIVATE, 0600 | IPC_CREAT);
  fflush(stdout);
  kid = fork();
  if (kid == 0) {
    for (;;) {
      pause();
    }
  }
  return kid > 0 ? 0 : -1;
}

static void teardown_points(void) {
  kill(kid, SIGKILL);
  waitpid(kid, NULL, 0);
  pthread_cancel(sleeper);
  pthread_join(sleeper, NULL);
  if (msq >= 0) {
    msgctl(msq, IPC_RMID, NULL);
  }
  unlink(fifo2);
  munmap(regmap, 4096);
  close(regfd);
  close(epfd);
  close(listener);
  close(sockr);
  close(sockw);
  close(emptyr);
  close(fullw);
}

static const struct cp_case blocking_points[] = {
    {"write", cp_write},
    {"writev", cp_writev},
    {"readv", cp_readv},
    {"usleep", cp_usleep},
    {"clock_nanosleep", cp_clock_nanosleep},
    {"ppoll", cp_ppoll},
    {"select", cp_select},
    {"pselect", cp_pselect},
    {"epoll_wait", cp_epoll_wait},
    {"epoll_pwait", cp_epoll_pwait},
    {"epoll_pwait2", cp_epoll_pwait2},
    {"accept", cp_accept},
    {"accept4", cp_accept4},
    {"recv", cp_recv},
    {"recvfrom", cp_recvfrom},
    {"recvmsg", cp_recvmsg},
    {"recvmmsg", cp_recvmmsg},
    {"send", cp_send},
    {"sendto", cp_sendto},
    {"sendmsg", cp_sendmsg},
    {"sendmmsg", cp_sendmmsg},
    {"waitpid", cp_waitpid},
    {"wait", cp_wait},
    {"wait3", cp_wait3},
    {"wait4", cp_wait4},
    {"waitid", cp_waitid},
    {"sigwait", cp_sigwait},
    {"sigwaitinfo", cp_sigwaitinfo},
    {"sigtimedwait", cp_sigtimedwait},
    {"sigsuspend", cp_sigsuspend},
    {"pause", cp_pause},
    {"sem_wait", cp_sem_wait},
    {"sem_timedwait", cp_sem_timedwait},
    {"sem_clockwait", cp_sem_clockwait},
    {"cond_timedwait", cp_cond_timedwait},
    {"cond_clockwait", cp_cond_clockwait},
    {"pthread_join", cp_pthread_join},
    {"splice", cp_splice},
    {"tee", cp_tee},
    {"vmsplice", cp_vmsplice},
    {"creat(FIFO)", cp_creat_fifo},
    {"__read_chk", cp_read_chk},
    {"__recv_chk", cp_recv_chk},
    {"__recvfrom_chk", cp_recvfrom_chk},
    {"__open_2(FIFO)", cp_open_2},
    {"__openat_2(FIFO)", cp_openat_2},
    {"__read", cp_alias_read},
    {"__write", cp_alias_write},
    {"__recv", cp_alias_recv},
    {"__send", cp_alias_send},
    {"__nanosleep", cp_alias_nanosleep},
    {"__waitpid", cp_alias_waitpid},
    {"__wait", cp_alias_wait},
    {"__sigtimedwait", cp_alias_sigtimedwait},
};

static const struct cp_case msgrcv_point = {"msgrcv", cp_msgrcv};

static const struct cp_case pending_points[] = {
    {"pread", cp_pread},
    {"pwrite", cp_pwrite},
    {"preadv", cp_preadv},
    {"pwritev", cp_pwritev},
    {"preadv2", cp_preadv2},
    {"pwritev2", cp_pwritev2},
    {"__pread_chk", cp_pread_chk},
    {"__pread64", cp_alias_pread64},
    {"__pwrite64", cp_alias_pwrite64},
    {"close", cp_close},
    {"__close", cp_alias_close},
    {"fsync", cp_fsync},
    {"fdatasync", cp_fdatasync},
    {"msync", cp_msync},
    {"copy_file_range", cp_copy_file_range},
    {"fallocate", cp_fallocate},
    {"sync_file_range", cp_sync_file_range},
    {"tcdrain", cp_tcdrain},
    {"getpwnam+testcancel", cp_getpwnam},
    {"getgrnam+testcancel", cp_getgrnam},
    {"getaddrinfo+testcancel", cp_getaddrinfo},
};

static void every_cancellation_point(void) {
  printf("cancellation points:\n");
  // The signal waits wait for SIGUSR2, which nobody sends; the test threads
  // inherit this mask.
  sigset_t usr2 = usr2_only();
  pthread_sigmask(SIG_BLOCK, &usr2, NULL);
  if (setup_points() != 0) {
    printf("  setup failed\n");
    return;
  }
  for (size_t i = 0; i < sizeof blocking_points / sizeof blocking_points[0]; i++) {
    run_point(&blocking_points[i], 0);
  }
  if (msq >= 0) {
    run_point(&msgrcv_point, 0);
  }
  for (size_t i = 0; i < sizeof pending_points / sizeof pending_points[0]; i++) {
    run_point(&pending_points[i], 1);
  }
  teardown_points();
}

// ---------------------------------------------------------------------------
// Cleanup handler order and pop semantics.
// ---------------------------------------------------------------------------

static void *lifo_handlers(void *arg) {
  (void)arg;
  char c;
  pthread_cleanup_push(cleanup, "outer");
  pthread_cleanup_push(cleanup, "middle");
  pthread_cleanup_push(cleanup, "inner");
  (void)!read(pipefd[0], &c, 1);
  pthread_cleanup_pop(0);
  pthread_cleanup_pop(0);
  pthread_cleanup_pop(0);
  return NULL;
}

static void *pop_executes(void *arg) {
  (void)arg;
  pthread_cleanup_push(cleanup, "pop(1) ran it");
  pthread_cleanup_pop(1);
  return (void *)5;
}

static void *pops_without_running(void *arg) {
  (void)arg;
  pthread_cleanup_push(cleanup, "must not run (a)");
  pthread_cleanup_push(cleanup, "must not run (b)");
  pthread_cleanup_pop(0);
  pthread_cleanup_pop(0);
  return (void *)6;
}

static void handler_order(void) {
  cancel_case("LIFO handlers on cancel", lifo_handlers);
  pthread_t t;
  void *ret = NULL;
  printf("cleanup_pop(1):\n");
  pthread_create(&t, NULL, pop_executes, NULL);
  pthread_join(t, &ret);
  printf("  joined: %ld\n", (long)ret);
  printf("cleanup_pop(0) then return:\n");
  pthread_create(&t, NULL, pops_without_running, NULL);
  pthread_join(t, &ret);
  printf("  joined: %ld\n", (long)ret);
  fflush(stdout);
}

// ---------------------------------------------------------------------------
// The main thread cancelled (run in a re-executed copy, see the top).
// ---------------------------------------------------------------------------

static void note(void *msg) { (void)!write(1, msg, strlen(msg)); }

static pthread_t main_thread;

static void *cancels_main(void *arg) {
  (void)arg;
  struct timespec t = {0, 50000000};
  nanosleep(&t, NULL);
  pthread_cancel(main_thread);
  t.tv_nsec = 300000000;
  nanosleep(&t, NULL);
  note("  worker exits the process\n");
  exit(0);
}

static int main_thread_scenario(const char *which) {
  int p[2];
  char c;
  if (pipe(p) != 0) {
    return 1;
  }
  if (strcmp(which, "self") == 0) {
    // Single-threaded: glibc's pthread_cancel marks the process
    // multi-threaded so that the read below acts.
    (void)!write(p[1], "x", 1);
    pthread_cleanup_push(note, "  main cleanup ran\n");
    pthread_cancel(pthread_self());
    (void)!read(p[0], &c, 1);
    note("  read returned: not cancelled\n");
    pthread_cleanup_pop(0);
    return 3;
  }
  main_thread = pthread_self();
  pthread_t w;
  pthread_create(&w, NULL, cancels_main, NULL);
  pthread_cleanup_push(note, "  main cleanup ran\n");
  (void)!read(p[0], &c, 1);  // blocks until cancelled
  note("  main read returned: not cancelled\n");
  pthread_cleanup_pop(0);
  return 4;
}

static void main_thread_cancelled(const char *argv0, const char *which) {
  printf("main thread, %s:\n", strcmp(which, "self") == 0 ? "cancels itself (single-threaded)"
                                                          : "cancelled by another thread");
  fflush(stdout);
  pid_t pid = fork();
  if (pid == 0) {
    setenv("FRANKENLIBC_STARTUP_DELEGATE", "1", 1);
    execl("/proc/self/exe", argv0, "main-thread", which, (char *)NULL);
    _exit(127);
  }
  int status = 0;
  waitpid(pid, &status, 0);
  if (WIFEXITED(status)) {
    printf("  exit status %d\n", WEXITSTATUS(status));
  } else {
    printf("  killed by signal %d\n", WTERMSIG(status));
  }
  fflush(stdout);
}

int main(int argc, char **argv) {
  if (argc == 3 && strcmp(argv[1], "main-thread") == 0) {
    return main_thread_scenario(argv[2]);
  }
  main_thread_cancelled(argv[0], "self");
  main_thread_cancelled(argv[0], "worker");

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

  cancel_case("system", blocked_system);
  errno = 0;
  pid_t left = waitpid(-1, NULL, WNOHANG);
  printf("  shell reaped: %s\n", left == -1 && errno == ECHILD ? "yes" : "no");
  struct sigaction int_action;
  sigaction(SIGINT, NULL, &int_action);
  printf("  SIGINT restored: %s\n", int_action.sa_handler == SIG_DFL ? "yes" : "no");

  snprintf(fifo_path, sizeof fifo_path, "/tmp/fl_cancel_fifo_%d", (int)getpid());
  if (mkfifo(fifo_path, 0600) == 0) {
    cancel_case("open(FIFO)", blocked_fifo_open);
    unlink(fifo_path);
  }

  snprintf(lock_path, sizeof lock_path, "/tmp/fl_cancel_lock_%d", (int)getpid());
  int holder = open(lock_path, O_RDWR | O_CREAT | O_TRUNC, 0600);
  if (holder >= 0) {
    struct flock fl = {0};
    fl.l_type = F_WRLCK;
    fl.l_whence = SEEK_SET;
    if (fcntl(holder, F_OFD_SETLK, &fl) == 0) {
      cancel_case("fcntl(F_OFD_SETLKW)", blocked_ofd_lock);
    }
    close(holder);
    unlink(lock_path);
  }
  cancel_case("cancel disabled until testcancel", disabled_sleep);

  handler_order();
  every_cancellation_point();

  // The mutex is usable after a cancelled waiter's cleanup released it.
  printf("mutex after cancellations: trylock=%d\n", pthread_mutex_trylock(&lock));
  pthread_mutex_unlock(&lock);
  return 0;
}
