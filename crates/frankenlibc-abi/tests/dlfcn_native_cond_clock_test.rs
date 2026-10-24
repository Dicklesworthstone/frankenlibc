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
void *clock_wait_pointer(const char *version) {
    if(!version) return (void *)pthread_cond_clockwait;
    return dlvsym(RTLD_DEFAULT,"pthread_cond_clockwait",version);
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
    });
}
