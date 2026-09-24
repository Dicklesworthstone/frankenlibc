// setjmp/longjmp parity + pointer-mangling fixture (bd-rc0923-epic-eeuy4f.12).
//
// Output is byte-identical under host glibc and FrankenLibC when both mangle
// the saved rbp/rsp/rip with the TCB pointer guard exactly as glibc does:
//   - ordinary, nested and value-0 jumps return the documented values;
//   - sigsetjmp(…, 1) restores the signal mask, sigsetjmp(…, 0) does not;
//   - siglongjmp out of a signal handler resumes with the mask restored;
//   - the raw jmp_buf words for rsp/rip are NOT the plaintext values, and they
//     demangle with rol17/xor(%fs:0x30) to the real ones (glibc-compatible);
//   - a corrupted saved rip is not jumped to verbatim (it demangles to junk);
//   - built with _FORTIFY_SOURCE, longjmp to a frame that already returned is
//     rejected by __longjmp_chk with SIGABRT.
#define _GNU_SOURCE
#include <fcntl.h>
#include <setjmp.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/wait.h>
#include <unistd.h>

static jmp_buf jb;
static sigjmp_buf sjb;
static volatile int depth;

static uint64_t guard(void) {
#if defined(__x86_64__)
  uint64_t g;
  __asm__ volatile("mov %%fs:0x30, %0" : "=r"(g));
  return g;
#else
  return 0;
#endif
}

static uint64_t demangle(uint64_t v) {
  return ((v >> 17) | (v << 47)) ^ guard();
}

static void __attribute__((noinline)) jump_from_depth(int n, int val) {
  depth = n;
  if (n > 0) {
    jump_from_depth(n - 1, val);
  } else {
    longjmp(jb, val);
  }
}

static void on_usr1(int sig) {
  (void)sig;
  siglongjmp(sjb, 7);
}

static int usr1_blocked(void) {
  sigset_t cur;
  sigprocmask(SIG_BLOCK, NULL, &cur);
  return sigismember(&cur, SIGUSR1);
}

static void __attribute__((noinline)) set_in_returned_frame(void) {
  volatile char pad[8192];
  pad[0] = 1;
  pad[sizeof pad - 1] = pad[0];
  (void)setjmp(jb);
}

int main(void) {
  volatile int n = 0;
  pid_t pid;
  int st;

  // 1. plain jump, value passthrough.
  int r = setjmp(jb);
  if (r == 0) {
    longjmp(jb, 42);
  }
  printf("plain=%d\n", r);

  // 2. value 0 becomes 1.
  r = setjmp(jb);
  if (r == 0) {
    longjmp(jb, 0);
  }
  printf("zero_becomes=%d\n", r);

  // 3. deep nested unwind.
  r = setjmp(jb);
  if (r == 0) {
    jump_from_depth(50, 9);
  }
  printf("nested=%d depth=%d\n", r, depth);

  // 4. repeated jumps to the same buffer keep volatile state.
  r = setjmp(jb);
  n++;
  if (n < 5) {
    longjmp(jb, n);
  }
  printf("loop n=%d last=%d\n", (int)n, r);

  // 5. sigsetjmp with and without mask save.
  sigset_t block;
  sigemptyset(&block);
  sigaddset(&block, SIGUSR1);
  if (sigsetjmp(sjb, 1) == 0) {
    sigprocmask(SIG_BLOCK, &block, NULL);
    siglongjmp(sjb, 1);
  }
  printf("savemask1_restores=%d\n", !usr1_blocked());
  if (sigsetjmp(sjb, 0) == 0) {
    sigprocmask(SIG_BLOCK, &block, NULL);
    siglongjmp(sjb, 1);
  }
  printf("savemask0_keeps_block=%d\n", usr1_blocked());
  sigprocmask(SIG_UNBLOCK, &block, NULL);

  // 6. siglongjmp out of a signal handler (SIGUSR1 is blocked inside it).
  signal(SIGUSR1, on_usr1);
  r = sigsetjmp(sjb, 1);
  if (r == 0) {
    raise(SIGUSR1);
    puts("handler did not jump");
  }
  printf("from_handler=%d unblocked_after=%d\n", r, !usr1_blocked());

#if defined(__x86_64__)
  // 7. raw words are mangled glibc-style.
  uint64_t probe_sp;
  if (setjmp(jb) == 0) {
    __asm__ volatile("mov %%rsp, %0" : "=r"(probe_sp));
    uint64_t *w = (uint64_t *)jb;
    uint64_t raw_sp = w[6];
    uint64_t sp = demangle(raw_sp);
    uint64_t pc = demangle(w[7]);
    int sp_plain = raw_sp - probe_sp < 65536 || probe_sp - raw_sp < 65536;
    int sp_near = sp - probe_sp < 65536 || probe_sp - sp < 65536;
    int pc_in_main = pc > (uint64_t)(uintptr_t)&main && pc < (uint64_t)(uintptr_t)&main + 65536;
    printf("rsp_plaintext=%d rsp_demangles=%d rip_demangles_into_main=%d guard_nonzero=%d\n",
           sp_plain, sp_near, pc_in_main, guard() != 0);
  }

  // 8. a jmp_buf whose rip was overwritten with a plaintext address is not
  //    jumped to verbatim: the child must die rather than print "hijacked".
  fflush(stdout);
  pid = fork();
  if (pid == 0) {
    if (setjmp(jb) == 0) {
      ((uint64_t *)jb)[7] = (uint64_t)(uintptr_t)&&hijacked;
      longjmp(jb, 1);
    }
    _exit(3);
  hijacked:
    puts("hijacked");
    _exit(4);
  }
  st = 0;
  waitpid(pid, &st, 0);
  printf("overwritten_rip_signaled=%d\n", WIFSIGNALED(st));
#endif

  // 9. __longjmp_chk rejects a jump into a frame that already returned.
  fflush(stdout);
  pid = fork();
  if (pid == 0) {
    int devnull = open("/dev/null", O_WRONLY);
    dup2(devnull, 2);
    set_in_returned_frame();
    longjmp(jb, 1);
    _exit(5);
  }
  st = 0;
  waitpid(pid, &st, 0);
  printf("chk_returned_frame=%s\n",
         WIFSIGNALED(st) ? (WTERMSIG(st) == SIGABRT ? "SIGABRT" : "other-signal")
                         : "exited");
  return 0;
}
