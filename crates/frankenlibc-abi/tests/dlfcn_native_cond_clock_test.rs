//! Explicit-clock condition waits executed by compiled C in native loader groups.
#![cfg(all(target_os = "linux", target_arch = "x86_64"))]
use frankenlibc_abi::{dlfcn_abi as dl, pthread_abi};
use frankenlibc_core::elf::ElfLoader;
use std::ffi::{CStr, CString, c_char, c_int, c_void};
use std::process::Command;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};
#[path = "common/dlsym_oracle.rs"]
mod dlsym_oracle;

const SOURCE: &str = r#"
#define _GNU_SOURCE
#include <pthread.h>
#include <stdint.h>
#include <stdatomic.h>
#include <limits.h>
#include <errno.h>
#include <time.h>
#include <dlfcn.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/syscall.h>
#ifndef SYS_futex_waitv
#define SYS_futex_waitv 449
#endif
#define CHECK(c) do {if(!(c)) return __LINE__;} while(0)

static int setup(pthread_cond_t *c,pthread_mutex_t *m,int clock,int robust) {
    pthread_condattr_t ca;pthread_mutexattr_t ma;
    CHECK(pthread_condattr_init(&ca)==0);
    CHECK(pthread_condattr_setclock(&ca,clock)==0);
    CHECK(pthread_cond_init(c,&ca)==0);
    CHECK(pthread_condattr_destroy(&ca)==0);
    CHECK(pthread_mutexattr_init(&ma)==0);
    if(robust) CHECK(pthread_mutexattr_setrobust(&ma,PTHREAD_MUTEX_ROBUST)==0);
    CHECK(pthread_mutex_init(m,&ma)==0);
    CHECK(pthread_mutexattr_destroy(&ma)==0);
    return 0;
}
int deadline_matrix(void) {
    const int clocks[]={CLOCK_REALTIME,CLOCK_MONOTONIC};
    const int64_t seconds[]={0,-1,INT64_MIN};
    for(unsigned a=0;a<2;++a) for(unsigned b=0;b<2;++b) for(int robust=0;robust<2;++robust) {
        pthread_cond_t c;pthread_mutex_t m;
        CHECK(setup(&c,&m,clocks[a],robust)==0);
        CHECK(pthread_mutex_lock(&m)==0);
        for(unsigned i=0;i<3;++i) {
            struct timespec t={seconds[i],999999999};
            CHECK(pthread_cond_clockwait(&c,&m,clocks[b],&t)==ETIMEDOUT);
            CHECK(pthread_mutex_trylock(&m)==EBUSY);
            CHECK(pthread_cond_timedwait(&c,&m,&t)==ETIMEDOUT);
            CHECK(pthread_mutex_trylock(&m)==EBUSY);
        }
        struct timespec invalid={0,-1};
        CHECK(pthread_cond_clockwait(&c,&m,clocks[b],&invalid)==EINVAL);
        invalid.tv_nsec=1000000000;
        CHECK(pthread_cond_clockwait(&c,&m,clocks[b],&invalid)==EINVAL);
        invalid.tv_nsec=0;
        CHECK(pthread_cond_clockwait(&c,&m,CLOCK_BOOTTIME,&invalid)==EINVAL);
        CHECK(pthread_mutex_trylock(&m)==EBUSY);
        CHECK(pthread_mutex_unlock(&m)==0);
        CHECK(pthread_cond_destroy(&c)==0 && pthread_mutex_destroy(&m)==0);
    }
    return 0;
}

int finite_timeouts_use_the_requested_clock(void) {
    const int clocks[]={CLOCK_REALTIME,CLOCK_MONOTONIC};
    for(unsigned a=0;a<2;++a) for(unsigned b=0;b<2;++b) {
        pthread_cond_t c;pthread_mutex_t m;struct timespec until,before,after;
        CHECK(setup(&c,&m,clocks[a],0)==0);
        CHECK(pthread_mutex_lock(&m)==0);
        CHECK(clock_gettime(clocks[b],&until)==0);
        until.tv_nsec+=20000000;if(until.tv_nsec>=1000000000){until.tv_nsec-=1000000000;until.tv_sec++;}
        CHECK(clock_gettime(CLOCK_MONOTONIC,&before)==0);
        CHECK(pthread_cond_clockwait(&c,&m,clocks[b],&until)==ETIMEDOUT);
        CHECK(clock_gettime(CLOCK_MONOTONIC,&after)==0);
        int64_t ns=(after.tv_sec-before.tv_sec)*1000000000+(after.tv_nsec-before.tv_nsec);
        CHECK(ns>=10000000 && ns<5000000000LL);
        CHECK(pthread_mutex_trylock(&m)==EBUSY);
        CHECK(pthread_mutex_unlock(&m)==0);
        CHECK(pthread_cond_destroy(&c)==0 && pthread_mutex_destroy(&m)==0);
    }
    return 0;
}

struct state { pthread_cond_t cond;pthread_mutex_t mutex;_Atomic int ready;int go; };
struct request { struct state *state;int clock;int huge;int result; };
static void *waiter(void *argument) {
    struct request *r=argument;struct state *s=r->state;struct timespec until;
    if(clock_gettime(r->clock,&until)) {r->result=1;return 0;}
    until.tv_sec=r->huge ? INT64_MAX : until.tv_sec+3;
    if(pthread_mutex_lock(&s->mutex)) {r->result=2;return 0;}
    atomic_fetch_add(&s->ready,1);
    while(!s->go) {
        int rc=pthread_cond_clockwait(&s->cond,&s->mutex,r->clock,&until);
        if(rc){r->result=rc;break;}
    }
    if(pthread_mutex_unlock(&s->mutex)) r->result=3;
    return 0;
}
int concurrent_clock_waits_and_extreme_deadlines(void) {
    const int clocks[]={CLOCK_REALTIME,CLOCK_MONOTONIC};
    for(unsigned configured=0;configured<2;++configured) for(int huge=0;huge<2;++huge) for(int robust=0;robust<2;++robust) {
        struct state s;atomic_init(&s.ready,0);s.go=0;
        CHECK(setup(&s.cond,&s.mutex,clocks[configured],robust)==0);
        struct request requests[2]={{&s,CLOCK_REALTIME,huge,0},{&s,CLOCK_MONOTONIC,huge,0}};
        pthread_t threads[2];
        for(unsigned i=0;i<2;++i) CHECK(pthread_create(&threads[i],0,waiter,&requests[i])==0);
        while(atomic_load(&s.ready)!=2) { }
        CHECK(pthread_mutex_lock(&s.mutex)==0);
        s.go=1;CHECK(pthread_cond_broadcast(&s.cond)==0);
        CHECK(pthread_mutex_unlock(&s.mutex)==0);
        for(unsigned i=0;i<2;++i) {CHECK(pthread_join(threads[i],0)==0);CHECK(requests[i].result==0);}
        // An explicit wait must not rewrite the condition's configured clock.
        // Using that clock's current time after both overrides must expire.
        struct timespec now;CHECK(clock_gettime(clocks[configured],&now)==0);
        CHECK(pthread_mutex_lock(&s.mutex)==0);
        CHECK(pthread_cond_timedwait(&s.cond,&s.mutex,&now)==ETIMEDOUT);
        CHECK(pthread_mutex_trylock(&s.mutex)==EBUSY);
        CHECK(pthread_mutex_unlock(&s.mutex)==0);
        CHECK(pthread_cond_destroy(&s.cond)==0 && pthread_mutex_destroy(&s.mutex)==0);
    }
    return 0;
}

static struct state cancel_state;
static _Atomic int cleaned;
static int requested_clock;
static void cleanup(void *argument) {
    struct state *s=argument;
    // Successful unlock proves cancellation reacquired the mutex first.
    atomic_store(&cleaned,pthread_mutex_unlock(&s->mutex)==0 ? 1 : -1);
}
static void *cancel_waiter(void *unused) {
    (void)unused;struct state *s=&cancel_state;
    struct timespec until={INT64_MAX,0};
    if(pthread_mutex_lock(&s->mutex)) return (void *)1;
    pthread_cleanup_push(cleanup,s);
    atomic_store(&s->ready,1);
    for(;;) {
        int rc=pthread_cond_clockwait(&s->cond,&s->mutex,requested_clock,&until);
        if(rc) break;
    }
    pthread_cleanup_pop(1);
    return (void *)2;
}
int explicit_clock_cancellation_reacquires_mutex(void) {
    const int clocks[]={CLOCK_REALTIME,CLOCK_MONOTONIC};
    for(unsigned i=0;i<2;++i) for(int robust=0;robust<2;++robust) {
        requested_clock=clocks[1-i];atomic_store(&cleaned,0);atomic_init(&cancel_state.ready,0);
        CHECK(setup(&cancel_state.cond,&cancel_state.mutex,clocks[i],robust)==0);
        pthread_t thread;CHECK(pthread_create(&thread,0,cancel_waiter,0)==0);
        while(!atomic_load(&cancel_state.ready)) { }
        // Locking here guarantees the worker has entered the atomic wait.
        CHECK(pthread_mutex_lock(&cancel_state.mutex)==0);
        CHECK(pthread_cancel(thread)==0);
        CHECK(pthread_mutex_unlock(&cancel_state.mutex)==0);
        void *result=0;CHECK(pthread_join(thread,&result)==0 && result==PTHREAD_CANCELED);
        CHECK(atomic_load(&cleaned)==1);
        CHECK(pthread_mutex_trylock(&cancel_state.mutex)==0 && pthread_mutex_unlock(&cancel_state.mutex)==0);
        CHECK(pthread_cond_destroy(&cancel_state.cond)==0 && pthread_mutex_destroy(&cancel_state.mutex)==0);
    }
    return 0;
}

/* Recursive waits release one level, including timeout and cancellation.
   Observe the kernel wait before testing exclusion: a readiness flag alone
   could let the contender run before the condition wait actually releases. */
struct recursive_state {
    pthread_cond_t cond;
    pthread_mutex_t mutex;
    _Atomic int tid;
    _Atomic int finished;
    _Atomic int release;
    _Atomic int cleaned;
    _Atomic int failure;
    int depth;
    int api;
    int action;
    int wait_result;
};
static int (*recursive_thread_probe)(void);
static int recursive_expected_native;
void recursive_set_thread_probe(int (*probe)(void), int expected) {
    recursive_thread_probe=probe;
    recursive_expected_native=expected;
}
void *recursive_provider(int which) {
    switch(which) {
    case 0: return (void *)pthread_cond_wait;
    case 1: return (void *)pthread_cond_timedwait;
    case 2: return (void *)pthread_cond_clockwait;
    case 3: return (void *)pthread_mutex_lock;
    case 4: return (void *)pthread_mutex_unlock;
    case 5: return (void *)pthread_create;
    case 6: return (void *)pthread_cancel;
    default: return 0;
    }
}
static void recursive_fail(struct recursive_state *s,int line) {
    int empty=0;
    atomic_compare_exchange_strong(&s->failure,&empty,line);
}
static int recursive_deadline(int clock,long milliseconds,struct timespec *until) {
    CHECK(clock_gettime(clock,until)==0);
    until->tv_sec+=milliseconds/1000;
    until->tv_nsec+=(milliseconds%1000)*1000000;
    if(until->tv_nsec>=1000000000) {
        until->tv_nsec-=1000000000;
        ++until->tv_sec;
    }
    return 0;
}
static void recursive_cleanup(void *argument) {
    struct recursive_state *s=argument;
    for(int i=0;i<s->depth;++i) {
        if(pthread_mutex_unlock(&s->mutex)!=0) recursive_fail(s,__LINE__);
    }
    if(pthread_mutex_unlock(&s->mutex)!=EPERM) recursive_fail(s,__LINE__);
    atomic_fetch_add(&s->cleaned,1);
}
static void *recursive_waiter(void *argument) {
    struct recursive_state *s=argument;
    if(!recursive_thread_probe ||
       recursive_thread_probe()!=recursive_expected_native) {
        recursive_fail(s,__LINE__);
        atomic_store(&s->finished,1);
        return (void *)1;
    }
    int acquired=0;
    while(acquired<s->depth) {
        if(pthread_mutex_lock(&s->mutex)!=0) {
            recursive_fail(s,__LINE__);
            while(acquired-->0) pthread_mutex_unlock(&s->mutex);
            atomic_store(&s->finished,1);
            return (void *)1;
        }
        ++acquired;
    }
    int clock=s->api==3 ? CLOCK_MONOTONIC : CLOCK_REALTIME;
    struct timespec until={0,0};
    if(s->action!=1 && recursive_deadline(clock,10000,&until)) {
        recursive_fail(s,__LINE__);
        recursive_cleanup(s);
        atomic_store(&s->finished,1);
        return (void *)1;
    }
    pthread_cleanup_push(recursive_cleanup,s);
    atomic_store(&s->tid,gettid());
    do {
        switch(s->api) {
        case 0: s->wait_result=pthread_cond_wait(&s->cond,&s->mutex);break;
        case 1: s->wait_result=pthread_cond_timedwait(&s->cond,&s->mutex,&until);break;
        default:
            s->wait_result=pthread_cond_clockwait(&s->cond,&s->mutex,clock,&until);
            break;
        }
    } while(s->wait_result==0 && !atomic_load(&s->release));
    if(s->action==2 || s->wait_result!=(s->action==1 ? ETIMEDOUT : 0))
        recursive_fail(s,__LINE__);
    pthread_cleanup_pop(1);
    atomic_store(&s->finished,1);
    return 0;
}
static int recursive_number(const char **cursor,uintptr_t *value) {
    const char *p=*cursor;
    while(*p==' ' || *p=='\t') ++p;
    unsigned base=10;
    if(p[0]=='0' && p[1]=='x') {base=16;p+=2;}
    uintptr_t number=0;
    int digits=0;
    for(;;++p) {
        unsigned digit;
        if(*p>='0' && *p<='9') digit=(unsigned)(*p-'0');
        else if(*p>='a' && *p<='f') digit=(unsigned)(*p-'a'+10);
        else if(*p>='A' && *p<='F') digit=(unsigned)(*p-'A'+10);
        else break;
        if(digit>=base) break;
        number=number*base+digit;
        ++digits;
    }
    *cursor=p;
    *value=number;
    return digits!=0;
}
static int recursive_parked(struct recursive_state *s) {
    struct timespec deadline,now;
    if(recursive_deadline(CLOCK_MONOTONIC,3000,&deadline)) return 0;
    do {
        if(atomic_load(&s->finished) || atomic_load(&s->failure)) return 0;
        int tid=atomic_load(&s->tid);
        if(tid>0) {
            char path[64]="/proc/self/task/";
            char digits[16];unsigned count=0,at=sizeof("/proc/self/task/")-1;
            unsigned number=(unsigned)tid;
            do {digits[count++]=(char)('0'+number%10);number/=10;} while(number);
            while(count) path[at++]=digits[--count];
            const char suffix[]="/syscall";
            for(unsigned i=0;i<sizeof(suffix);++i) path[at++]=suffix[i];
            int fd=open(path,O_RDONLY|O_CLOEXEC);
            if(fd>=0) {
                char buffer[512];
                ssize_t n=read(fd,buffer,sizeof(buffer)-1);
                close(fd);
                if(n>0) {
                    buffer[n]=0;
                    const char *cursor=buffer;uintptr_t nr,address,argument;
                    if(recursive_number(&cursor,&nr) &&
                       recursive_number(&cursor,&address) &&
                       recursive_number(&cursor,&argument)) {
                        uintptr_t first=(uintptr_t)&s->cond;
                        uintptr_t limit=first+sizeof(s->cond);
                        if(nr==SYS_futex && address>=first && address<=limit-4)
                            return 1;
                        /* The native cancellation adapter waits on two words.
                           This worker calls no other waitv operation. */
                        if(nr==SYS_futex_waitv && argument==2) return 1;
                    }
                }
            }
        }
        if(clock_gettime(CLOCK_MONOTONIC,&now)) return 0;
    } while(now.tv_sec<deadline.tv_sec ||
            (now.tv_sec==deadline.tv_sec && now.tv_nsec<deadline.tv_nsec));
    return 0;
}
static int recursive_case(int kind,int depth,int api,int action) {
    struct recursive_state s;
    atomic_init(&s.tid,0);atomic_init(&s.finished,0);
    atomic_init(&s.release,0);atomic_init(&s.cleaned,0);atomic_init(&s.failure,0);
    s.depth=depth;s.api=api;s.action=action;s.wait_result=-1;
    pthread_mutexattr_t attr;
    CHECK(pthread_mutexattr_init(&attr)==0);
    CHECK(pthread_mutexattr_settype(&attr,PTHREAD_MUTEX_RECURSIVE)==0);
    if(kind==1) CHECK(pthread_mutexattr_setpshared(&attr,PTHREAD_PROCESS_SHARED)==0);
    if(kind==2 || kind==4) CHECK(pthread_mutexattr_setrobust(&attr,PTHREAD_MUTEX_ROBUST)==0);
    if(kind==3 || kind==4) CHECK(pthread_mutexattr_setprotocol(&attr,PTHREAD_PRIO_INHERIT)==0);
    CHECK(pthread_mutex_init(&s.mutex,&attr)==0);
    CHECK(pthread_mutexattr_destroy(&attr)==0);
    CHECK(pthread_cond_init(&s.cond,0)==0);
    pthread_t thread;
    CHECK(pthread_create(&thread,0,recursive_waiter,&s)==0);
    int parked=1,contender=0,contender_unlock=0,complete=0;
    if(action!=1) {
        parked=recursive_parked(&s);
        struct timespec until;
        if(recursive_deadline(CLOCK_REALTIME,depth==1 ? 1000 : 20,&until)) {
            contender=-1;
        } else {
            contender=pthread_mutex_timedlock(&s.mutex,&until);
            if(contender==0) contender_unlock=pthread_mutex_unlock(&s.mutex);
        }
        if(action==2) complete=pthread_cancel(thread);
        else {
            atomic_store(&s.release,1);
            complete=pthread_cond_signal(&s.cond);
        }
    }
    /* Join before reporting a failed property so no worker outlives its DSO. */
    void *result=0;
    CHECK(pthread_join(thread,&result)==0);
    int failure=atomic_load(&s.failure);
    int cleaned=atomic_load(&s.cleaned);
    int final_lock=pthread_mutex_trylock(&s.mutex);
    int final_unlock=final_lock==0 ? pthread_mutex_unlock(&s.mutex) : -1;
    int cond_destroy=pthread_cond_destroy(&s.cond);
    int mutex_destroy=pthread_mutex_destroy(&s.mutex);
    if(failure) return failure;
    CHECK(parked && complete==0 && contender_unlock==0);
    if(action!=1) CHECK(contender==(depth==1 ? 0 : ETIMEDOUT));
    CHECK(result==(action==2 ? PTHREAD_CANCELED : 0));
    CHECK(cleaned==1 && final_lock==0 && final_unlock==0);
    CHECK(cond_destroy==0 && mutex_destroy==0);
    return 0;
}
static int recursive_matrix(int action) {
    for(int kind=0;kind<5;++kind)
        for(int depth=1;depth<=3;++depth)
            for(int api=action==1 ? 1 : 0;api<4;++api) {
                int rc=recursive_case(kind,depth,api,action);
                if(rc) return rc;
            }
    return 0;
}
int recursive_signal_preserves_exclusion(void) {return recursive_matrix(0);}
int recursive_timeouts_preserve_depth(void) {return recursive_matrix(1);}
int recursive_cancellation_preserves_depth(void) {return recursive_matrix(2);}

void *clock_wait_pointer(const char *version) {
    if(!version) return (void *)pthread_cond_clockwait;
    return dlvsym(RTLD_DEFAULT,"pthread_cond_clockwait",version);
}
void *thread_id_pointer(const char *version) {
    if(!version) return (void *)gettid;
    return dlvsym(RTLD_DEFAULT,"gettid",version);
}
static int kernel_tid(void) {
    long result;
    __asm__ volatile("syscall" : "=a"(result) : "a"((long)SYS_gettid) : "rcx","r11","memory");
    return (int)result;
}
struct identity { int creator;int observed;int kernel; };
static void *identity_worker(void *argument) {
    struct identity *state=argument;
    state->observed=gettid();state->kernel=kernel_tid();
    return 0;
}
int thread_identity_values(void) {
    struct identity state={gettid(),0,0};
    CHECK(state.creator>0 && state.creator==kernel_tid());
    pthread_t worker;CHECK(pthread_create(&worker,0,identity_worker,&state)==0);
    CHECK(pthread_join(worker,0)==0);
    CHECK(state.observed>0 && state.observed==state.kernel);
    CHECK(state.observed!=state.creator && gettid()==state.creator);
    return 0;
}
"#;

struct Library {
    handle: *mut c_void,
    native: bool,
}
impl Library {
    fn new(native: bool, got: bool) -> Self {
        let stamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let dir = std::env::temp_dir().join(format!(
            "frankenlibc-condclock-{}-{stamp}",
            std::process::id()
        ));
        std::fs::create_dir(&dir).unwrap();
        let source = dir.join("clock.c");
        let path = dir.join("clock.so");
        std::fs::write(&source, SOURCE).unwrap();
        let mut command = Command::new("cc");
        command.args([
            "-shared",
            "-fPIC",
            "-O2",
            "-fno-builtin",
            "-U_FORTIFY_SOURCE",
            "-D_FORTIFY_SOURCE=0",
        ]);
        if native {
            command.arg("-nostdlib");
        }
        if got {
            command.arg("-fno-plt");
        }
        let result = command.arg(&source).arg("-o").arg(&path).output().unwrap();
        assert!(
            result.status.success(),
            "{}",
            String::from_utf8_lossy(&result.stderr)
        );
        let object = ElfLoader::new(0)
            .parse(&std::fs::read(&path).unwrap())
            .unwrap();
        if native {
            assert!(object.needed_libraries.is_empty());
        }
        assert!(
            object
                .undefined_symbols()
                .any(|(_, symbol)| object.symbol_name(symbol) == Some("pthread_cond_clockwait"))
        );
        let path = CString::new(path.as_os_str().as_encoded_bytes()).unwrap();
        // SAFETY: exact loader signatures and a terminated generated pathname.
        let handle = unsafe {
            if native {
                dl::dlopen(path.as_ptr(), libc::RTLD_NOW)
            } else {
                let open: unsafe extern "C" fn(*const c_char, c_int) -> *mut c_void =
                    dlsym_oracle::host_fn(c"dlopen", dl::dlopen as *const ());
                open(path.as_ptr(), libc::RTLD_NOW)
            }
        };
        assert!(!handle.is_null());
        if native {
            assert!(dl::native_dso_handle_for_tests(handle), "host fallback");
        }
        Self { handle, native }
    }
    fn symbol(&self, name: &CStr) -> *mut c_void {
        // SAFETY: all entry names are terminated, and the handle remains live.
        let p = unsafe {
            if self.native {
                dl::dlsym(self.handle, name.as_ptr())
            } else {
                let find: unsafe extern "C" fn(*mut c_void, *const c_char) -> *mut c_void =
                    dlsym_oracle::host_fn(c"dlsym", dl::dlsym as *const ());
                find(self.handle, name.as_ptr())
            }
        };
        assert!(!p.is_null(), "{name:?}");
        p
    }
}
impl Drop for Library {
    fn drop(&mut self) {
        // SAFETY: every protocol joins its workers before the library is dropped.
        let result = unsafe {
            if self.native {
                dl::dlclose(self.handle)
            } else {
                let close: unsafe extern "C" fn(*mut c_void) -> c_int =
                    dlsym_oracle::host_fn(c"dlclose", dl::dlclose as *const ());
                close(self.handle)
            }
        };
        assert_eq!(result, 0);
    }
}
fn isolated(name: &str, body: fn(bool)) {
    if let Ok(backend) = std::env::var("FL_CONDCLOCK_CHILD") {
        body(backend == "native");
        return;
    }
    for (backend, mode) in [
        ("host", "strict"),
        ("native", "strict"),
        ("native", "hardened"),
    ] {
        let mut child = Command::new(std::env::current_exe().unwrap())
            .args(["--exact", name, "--nocapture"])
            .env("FL_CONDCLOCK_CHILD", backend)
            .env("FRANKENLIBC_MODE", mode)
            .env_remove("LD_PRELOAD")
            .spawn()
            .unwrap();
        let deadline = Instant::now() + Duration::from_secs(45);
        loop {
            if let Some(status) = child.try_wait().unwrap() {
                assert!(status.success(), "{name}/{backend}/{mode}: {status}");
                break;
            }
            if Instant::now() >= deadline {
                child.kill().unwrap();
                child.wait().unwrap();
                panic!("{name}/{backend}/{mode}: timeout");
            }
            std::thread::sleep(Duration::from_millis(10));
        }
    }
}
fn protocol(native: bool, name: &CStr) {
    for got in [false, true] {
        let lib = Library::new(native, got);
        // SAFETY: protocol function is the compiled int(void) export.
        let run: unsafe extern "C" fn() -> c_int = unsafe { std::mem::transmute(lib.symbol(name)) };
        assert_eq!(unsafe { run() }, 0, "C assertion line in {name:?}");
    }
}
#[test]
fn native_clock_deadline_and_invalid_input_matrix() {
    isolated("native_clock_deadline_and_invalid_input_matrix", |native| {
        protocol(native, c"deadline_matrix")
    });
}
#[test]
fn native_clock_finite_and_extreme_deadlines() {
    isolated("native_clock_finite_and_extreme_deadlines", |native| {
        protocol(native, c"finite_timeouts_use_the_requested_clock");
        protocol(native, c"concurrent_clock_waits_and_extreme_deadlines");
    });
}
#[test]
fn native_clock_cancellation_preserves_mutex_ownership() {
    isolated(
        "native_clock_cancellation_preserves_mutex_ownership",
        |native| protocol(native, c"explicit_clock_cancellation_reacquires_mutex"),
    );
}
#[test]
fn native_clock_provider_versions_are_exact() {
    isolated("native_clock_provider_versions_are_exact", |native| {
        let lib = Library::new(native, false);
        // SAFETY: the pointer probe has exactly void *(const char *) signature.
        let pointer: unsafe extern "C" fn(*const c_char) -> *mut c_void =
            unsafe { std::mem::transmute(lib.symbol(c"clock_wait_pointer")) };
        let expected = if native {
            pthread_abi::pthread_cond_clockwait as *const () as *mut c_void
        } else {
            unsafe {
                dlsym_oracle::host_addr(
                    c"pthread_cond_clockwait",
                    pthread_abi::pthread_cond_clockwait as *const (),
                )
            }
        };
        assert_eq!(unsafe { pointer(std::ptr::null()) }, expected);
        for version in [c"GLIBC_2.30", c"GLIBC_2.34"] {
            assert_eq!(unsafe { pointer(version.as_ptr()) }, expected);
        }
        for version in [c"GLIBC_2.2.5", c"GLIBC_PRIVATE", c"MISSING_VERSION"] {
            assert!(unsafe { pointer(version.as_ptr()) }.is_null());
        }
        // A single unresolved gettid import used to reject this whole DSO,
        // silently selecting the host loader before any condition test ran.
        // Check both direct binding and caller-relative versioned lookup.
        let pointer: unsafe extern "C" fn(*const c_char) -> *mut c_void =
            unsafe { std::mem::transmute(lib.symbol(c"thread_id_pointer")) };
        let candidate = frankenlibc_abi::glibc_internal_abi::gettid as *const ();
        let expected = if native {
            candidate.cast_mut().cast()
        } else {
            unsafe { dlsym_oracle::host_addr(c"gettid", candidate) }
        };
        assert_eq!(unsafe { pointer(std::ptr::null()) }, expected);
        assert_eq!(unsafe { pointer(c"GLIBC_2.30".as_ptr()) }, expected);
        for version in [
            c"GLIBC_2.2.5",
            c"GLIBC_2.17",
            c"GLIBC_2.34",
            c"GLIBC_PRIVATE",
        ] {
            assert!(unsafe { pointer(version.as_ptr()) }.is_null());
        }
        protocol(native, c"thread_identity_values");
        if native {
            struct RestoreThreading(bool);
            impl Drop for RestoreThreading {
                fn drop(&mut self) {
                    pthread_abi::pthread_threading_restore_for_tests(self.0);
                }
            }
            let _threading =
                RestoreThreading(pthread_abi::pthread_threading_swap_force_native_for_tests());
            protocol(native, c"thread_identity_values");
        }
    });
}

extern "C" fn recursive_native_thread_probe() -> c_int {
    c_int::from(frankenlibc_core::pthread::thread::current_thread_handle().is_some())
}

fn recursive_protocol(native: bool, native_threads: bool, name: &CStr) {
    struct RestoreThreading(bool);
    impl Drop for RestoreThreading {
        fn drop(&mut self) {
            pthread_abi::pthread_threading_restore_for_tests(self.0);
        }
    }
    let _threading = native_threads
        .then(|| RestoreThreading(pthread_abi::pthread_threading_swap_force_native_for_tests()));
    for got in [false, true] {
        let lib = Library::new(native, got);
        // SAFETY: these are the exact signatures of the compiled probes.
        let set_probe: unsafe extern "C" fn(extern "C" fn() -> c_int, c_int) =
            unsafe { std::mem::transmute(lib.symbol(c"recursive_set_thread_probe")) };
        let provider: unsafe extern "C" fn(c_int) -> *mut c_void =
            unsafe { std::mem::transmute(lib.symbol(c"recursive_provider")) };
        unsafe { set_probe(recursive_native_thread_probe, c_int::from(native_threads)) };
        for (index, (symbol, candidate)) in [
            (
                c"pthread_cond_wait",
                pthread_abi::pthread_cond_wait as *const (),
            ),
            (
                c"pthread_cond_timedwait",
                pthread_abi::pthread_cond_timedwait as *const (),
            ),
            (
                c"pthread_cond_clockwait",
                pthread_abi::pthread_cond_clockwait as *const (),
            ),
            (
                c"pthread_mutex_lock",
                pthread_abi::pthread_mutex_lock as *const (),
            ),
            (
                c"pthread_mutex_unlock",
                pthread_abi::pthread_mutex_unlock as *const (),
            ),
            (c"pthread_create", pthread_abi::pthread_create as *const ()),
            (c"pthread_cancel", pthread_abi::pthread_cancel as *const ()),
        ]
        .into_iter()
        .enumerate()
        {
            let expected = if native {
                candidate.cast_mut().cast()
            } else {
                // SAFETY: the independent GNU resolver rejects the candidate.
                unsafe { dlsym_oracle::host_addr(symbol, candidate) }
            };
            assert_eq!(
                unsafe { provider(index as c_int) },
                expected,
                "recursive protocol provider {symbol:?}"
            );
        }
        // SAFETY: the protocol joins every worker before returning int(void).
        let run: unsafe extern "C" fn() -> c_int = unsafe { std::mem::transmute(lib.symbol(name)) };
        assert_eq!(
            unsafe { run() },
            0,
            "recursive C assertion line in {name:?}, GOT={got}, native threads={native_threads}"
        );
    }
}

fn recursive_isolated(test: &str, protocol: &CStr) {
    const CHILD: &str = "FL_CONDCLOCK_RECURSIVE_CHILD";
    const THREADS: &str = "FL_CONDCLOCK_RECURSIVE_THREADS";
    if let Ok(provider) = std::env::var(CHILD) {
        let native = provider == "native";
        let native_threads = std::env::var(THREADS).unwrap() == "native";
        assert!(native || !native_threads);
        recursive_protocol(native, native_threads, protocol);
        return;
    }
    for (provider, mode, threads) in [
        ("host", "strict", "host"),
        ("native", "strict", "host"),
        ("native", "hardened", "host"),
        ("native", "strict", "native"),
        ("native", "hardened", "native"),
    ] {
        let mut child = Command::new(std::env::current_exe().unwrap())
            .args(["--exact", test, "--nocapture", "--test-threads=1"])
            .env(CHILD, provider)
            .env(THREADS, threads)
            .env("FRANKENLIBC_MODE", mode)
            .env("FRANKENLIBC_THREAD_NATIVE", "0")
            .env_remove("LD_PRELOAD")
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::piped())
            .spawn()
            .unwrap();
        let deadline = Instant::now() + Duration::from_secs(60);
        let mut timed_out = false;
        while child.try_wait().unwrap().is_none() {
            if Instant::now() >= deadline {
                timed_out = true;
                child.kill().unwrap();
                break;
            }
            std::thread::sleep(Duration::from_millis(10));
        }
        let output = child.wait_with_output().unwrap();
        assert!(
            !timed_out
                && output.status.success()
                && String::from_utf8_lossy(&output.stdout).contains("1 passed;"),
            "{test}/{provider}/{mode}/{threads}: timeout={timed_out} status={}\n{}\n{}",
            output.status,
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr),
        );
    }
}

#[test]
fn native_recursive_condition_wait_retains_deeper_locks() {
    recursive_isolated(
        "native_recursive_condition_wait_retains_deeper_locks",
        c"recursive_signal_preserves_exclusion",
    );
}

#[test]
fn native_recursive_condition_timeout_restores_lock_depth() {
    recursive_isolated(
        "native_recursive_condition_timeout_restores_lock_depth",
        c"recursive_timeouts_preserve_depth",
    );
}

#[test]
fn native_recursive_condition_cancellation_restores_lock_depth() {
    recursive_isolated(
        "native_recursive_condition_cancellation_restores_lock_depth",
        c"recursive_cancellation_preserves_depth",
    );
}
