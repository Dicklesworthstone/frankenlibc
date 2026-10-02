/* backtrace() from inside signal handlers unwinds to the interrupted code.
 *
 * fl's signal restorer (the sa_restorer its sigaction installs) began right
 * at a function boundary. Unwinders look up a return address's frame info at
 * ra - 1, which landed in the preceding function's FDE: backtrace() in a
 * handler stopped at the restorer, and inside a SIGSEGV handler it crashed
 * (CPython's faulthandler "C stack trace" died there). Build with -rdynamic.
 * Output names only this program's functions, so it is libc-independent.
 */
#define _GNU_SOURCE
#include <dlfcn.h>
#include <execinfo.h>
#include <setjmp.h>
#include <signal.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

static sigjmp_buf back;

static void handler(int sig) {
    void *frames[64];
    int n = backtrace(frames, 64);
    int saw_fault_site = 0, saw_main = 0;
    for (int i = 0; i < n; i++) {
        Dl_info info;
        if (dladdr(frames[i], &info) && info.dli_sname) {
            saw_fault_site |= strcmp(info.dli_sname, "fault_site") == 0 ||
                              strcmp(info.dli_sname, "raise_site") == 0;
            saw_main |= strcmp(info.dli_sname, "main") == 0;
        }
    }
    printf("signal %d: backtrace reached the interrupted function=%d main=%d\n", sig, saw_fault_site,
           saw_main);
    siglongjmp(back, 1);
}

__attribute__((noinline)) void fault_site(volatile int *p) { *p = 1; }

__attribute__((noinline)) void raise_site(void) { raise(SIGUSR1); }

int main(void) {
    setvbuf(stdout, NULL, _IONBF, 0);
    struct sigaction sa;
    memset(&sa, 0, sizeof sa);
    sa.sa_handler = handler;
    sa.sa_flags = SA_NODEFER;
    sigaction(SIGSEGV, &sa, NULL);
    sigaction(SIGUSR1, &sa, NULL);
    if (!sigsetjmp(back, 1))
        fault_site((volatile int *)0);
    if (!sigsetjmp(back, 1))
        raise_site();
    puts("done");
    return 0;
}
