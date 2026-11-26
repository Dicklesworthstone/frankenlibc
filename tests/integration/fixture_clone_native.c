/* Public clone/__clone contracts and a separately built host-route trap.
 * The callback avoids libc so a caller-supplied minimal TLS block is valid.
 * Compile this file again with FRANKENLIBC_CLONE_HOST_TRAP for the preload trap.
 */
#define _GNU_SOURCE
#include <sched.h>
#include <signal.h>
#include <sys/mman.h>
#include <sys/syscall.h>
#include <sys/wait.h>
#include <sys/stat.h>
#include <linux/futex.h>
#include <dlfcn.h>
#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#ifdef FRANKENLIBC_CLONE_HOST_TRAP
int clone(int (*fn)(void *), void *stack, int flags, void *arg, ...) {
    (void)fn; (void)stack; (void)flags; (void)arg;
    _exit(91);
}
int __clone(int (*fn)(void *), void *stack, int flags, void *arg, ...) {
    (void)fn; (void)stack; (void)flags; (void)arg;
    _exit(91);
}
#else
typedef int (*clone_fn)(int (*)(void *), void *, int, void *, ...);
typedef long (*syscall_fn)(long, ...);
typedef int *(*errno_fn)(void);
struct child_data {
    unsigned magic;
    int check_tls;
    int check_tid;
    void *tls;
    int *ctid;
    int seen;
    int seen_tid;
    void *seen_tls;
};
static int child_callback(void *arg) {
    struct child_data *data = arg;
    if (data == NULL || data->magic != 0xc10e1234U) return 81;
    void *thread_pointer = __builtin_thread_pointer();
    if (data->check_tls && thread_pointer != data->tls) return 82;
    int tid = data->ctid == NULL ? 0 : __atomic_load_n(data->ctid, __ATOMIC_ACQUIRE);
    if (data->check_tid && tid <= 0) return 83;
    data->seen_tid = tid;
    data->seen_tls = thread_pointer;
    __atomic_store_n(&data->seen, 1, __ATOMIC_RELEASE);
    return 43;
}
static int fail(const char *symbol, const char *test, const char *what) {
    fprintf(stderr, "FAIL %s %s: %s (errno=%d)\n", symbol, test, what, errno);
    return 1;
}
int main(int argc, char **argv) {
    if (argc != 3) return 90;
    const char *symbol = argv[1], *test = argv[2];
    clone_fn call = (clone_fn)dlsym(RTLD_DEFAULT, symbol);
    if (call == NULL) return fail(symbol,test,"clone symbol missing");
    const char *expected_provider = getenv("FRANKENLIBC_TEST_LIBRARY");
    if (expected_provider != NULL) {
        Dl_info info;
        if (dladdr((void *)call, &info) == 0 || info.dli_fname == NULL)
            return fail(symbol,test,"clone provider missing");
        struct stat actual, expected;
        if (stat(info.dli_fname,&actual) != 0 || stat(expected_provider,&expected) != 0 ||
            actual.st_dev != expected.st_dev || actual.st_ino != expected.st_ino)
            return fail(symbol,test,"clone provider mismatch");
    }
    void *host = dlopen("libc.so.6", RTLD_NOW | RTLD_LOCAL);
    syscall_fn host_syscall = host == NULL ? NULL : (syscall_fn)dlsym(host,"syscall");
    errno_fn host_errno = host == NULL ? NULL : (errno_fn)dlsym(host,"__errno_location");
    if (host_syscall == NULL || host_errno == NULL) return fail(symbol,test,"host syscall oracle missing");

    size_t mapping_size = 128U*1024U;
    char *mapping = mmap(NULL,mapping_size,PROT_READ|PROT_WRITE,
                         MAP_PRIVATE|MAP_ANONYMOUS|MAP_STACK,-1,0);
    void *tls = mmap(NULL,4096,PROT_READ|PROT_WRITE,MAP_PRIVATE|MAP_ANONYMOUS,-1,0);
    if (mapping == MAP_FAILED || tls == MAP_FAILED) return fail(symbol,test,"mmap");
    /* x86's thread-pointer builtin reads fs:0; AArch64 reads its TLS register. */
    *(void **)tls = tls;
    void *stack = mapping + mapping_size;
    void *parent_tls = __builtin_thread_pointer();
    int ptid = -1234, ctid = 1;
    struct child_data data = {
        .magic=0xc10e1234U,.tls=tls,.ctid=&ctid,.seen=0,.seen_tid=0,.seen_tls=NULL
    };
    int flags = SIGCHLD, tail = 0, want_shared = 0, want_clear = 0, want_parent = 0;
    int want_pidfd = 0, want_thread = 0, want_vfork = 0, expected_error = 0;
    int (*fn)(void *) = child_callback;
    if (strcmp(test,"basic")==0) {}
    else if (strcmp(test,"unaligned")==0) stack=(char *)stack-3;
    else if (strcmp(test,"bad_fn")==0) { fn=NULL; expected_error=EINVAL; }
    else if (strcmp(test,"bad_stack")==0) { stack=NULL; expected_error=EINVAL; }
    else if (strcmp(test,"bad_flags")==0) { flags|=CLONE_SIGHAND; expected_error=EINVAL; }
    else if (strcmp(test,"shared")==0) { flags|=CLONE_VM; want_shared=1; }
    else if (strcmp(test,"vfork")==0) {
        flags|=CLONE_VM|CLONE_VFORK; want_shared=1; want_vfork=1;
    }
    else if (strcmp(test,"parent_tid")==0) {
        flags|=CLONE_PARENT_SETTID; tail=1; want_parent=1;
    }
    else if (strcmp(test,"pidfd")==0) {
        flags|=CLONE_PIDFD; tail=1; want_pidfd=1;
    }
    else if (strcmp(test,"tls")==0) {
        flags|=CLONE_SETTLS; tail=2; data.check_tls=1;
    }
    else if (strcmp(test,"child_tid")==0 || strcmp(test,"clear_tid")==0) {
        flags|=CLONE_VM|CLONE_CHILD_SETTID; tail=3; want_shared=1; data.check_tid=1;
        if (strcmp(test,"clear_tid")==0) { flags|=CLONE_CHILD_CLEARTID; want_clear=1; }
    }
    else if (strcmp(test,"all_tail")==0 || strcmp(test,"thread")==0) {
        flags|=CLONE_VM|CLONE_SETTLS|CLONE_PARENT_SETTID|CLONE_CHILD_SETTID|CLONE_CHILD_CLEARTID;
        tail=3; want_shared=1; want_parent=1; want_clear=1;
        data.check_tls=1; data.check_tid=1;
        if (strcmp(test,"thread")==0) {
            flags=(flags & ~CSIGNAL)|CLONE_SIGHAND|CLONE_THREAD; want_thread=1;
        }
    }
    else return fail(symbol,test,"unknown case");
    errno=0;
    int pid;
    if (tail==0) pid=call(fn,stack,flags,&data);
    else if (tail==1) pid=call(fn,stack,flags,&data,&ptid);
    else if (tail==2) pid=call(fn,stack,flags,&data,NULL,tls);
    else pid=call(fn,stack,flags,&data,want_parent?&ptid:NULL,data.check_tls?tls:NULL,&ctid);
    int clone_error=errno;
    if (expected_error) {
        if (pid!=-1 || clone_error!=expected_error) return fail(symbol,test,"invalid arguments accepted or wrong errno");
        if (__atomic_load_n(&data.seen,__ATOMIC_ACQUIRE)!=0) return fail(symbol,test,"invalid request ran callback");
        printf("PASS %s %s\n",symbol,test);
        return 0;
    }
    if (pid<=0) return fail(symbol,test,"clone failed or returned in child");
    if (__builtin_thread_pointer()!=parent_tls) return fail(symbol,test,"parent TLS changed");
    if (want_parent && ptid!=pid) return fail(symbol,test,"parent_tid slot");
    if (want_vfork && __atomic_load_n(&data.seen,__ATOMIC_ACQUIRE)!=1)
        return fail(symbol,test,"vfork returned before callback completion");
    if (want_thread) {
        struct timespec timeout = {.tv_sec=2,.tv_nsec=0};
        for (;;) {
            int value=__atomic_load_n(&ctid,__ATOMIC_ACQUIRE);
            if (value==0) break;
            long rc=host_syscall(SYS_futex,&ctid,FUTEX_WAIT,value,&timeout,NULL,0);
            if (rc<0 && *host_errno()!=EAGAIN && *host_errno()!=EINTR) return fail(symbol,test,"thread clear_child_tid wake");
        }
    } else {
        int status=0;
        long waited;
        do { waited=host_syscall(SYS_wait4,pid,&status,0,NULL); } while (waited<0 && *host_errno()==EINTR);
        if (waited!=pid || !WIFEXITED(status) || WEXITSTATUS(status)!=43)
            return fail(symbol,test,"callback/exit status");
    }
    if (__atomic_load_n(&data.seen,__ATOMIC_ACQUIRE)!=want_shared)
        return fail(symbol,test,"CLONE_VM visibility");
    if (want_shared && data.check_tid && data.seen_tid!=pid) return fail(symbol,test,"child_tid slot");
    if (want_shared && data.check_tls && data.seen_tls!=tls) return fail(symbol,test,"TLS slot");
    if (want_clear && __atomic_load_n(&ctid,__ATOMIC_ACQUIRE)!=0) return fail(symbol,test,"child_tid not cleared");
    if (strcmp(test,"child_tid")==0 && ctid!=pid) return fail(symbol,test,"child_tid disappeared");
    if (want_pidfd) {
        int descriptor_flags = ptid < 0 ? -1 : fcntl(ptid,F_GETFD);
        if (descriptor_flags < 0 || !(descriptor_flags & FD_CLOEXEC))
            return fail(symbol,test,"PIDFD tail slot");
        struct pollfd p={.fd=ptid,.events=POLLIN,.revents=0};
        if (poll(&p,1,0)!=1 || !(p.revents&POLLIN)) return fail(symbol,test,"PIDFD exit readiness");
        close(ptid);
    }
    printf("PASS %s %s\n",symbol,test);
    munmap(mapping,mapping_size); munmap(tls,4096); dlclose(host);
    return 0;
}
#endif
