//! Real native-plugin thread control with a separate live-host oracle.
#![cfg(all(target_os = "linux", target_arch = "x86_64"))]
use frankenlibc_abi::{dlfcn_abi as dl, pthread_abi as pthread};
use frankenlibc_core::elf::ElfLoader;
use std::ffi::{CStr, CString, c_char, c_int, c_void};
use std::process::Command;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};
#[path = "common/dlsym_oracle.rs"]
mod dlsym_oracle;

fn bindings() -> Vec<(&'static str, &'static str, bool, *const ())> {
    macro_rules! row {
        ($f:ident, $v:literal, $m:literal) => {
            (stringify!($f), $v, $m, pthread::$f as *const ())
        };
    }
    vec![
        row!(pthread_attr_init, "GLIBC_2.2.5", false),
        row!(pthread_attr_destroy, "GLIBC_2.2.5", false),
        row!(pthread_attr_getdetachstate, "GLIBC_2.2.5", false),
        row!(pthread_attr_setdetachstate, "GLIBC_2.2.5", false),
        row!(pthread_attr_getstacksize, "GLIBC_2.2.5", true),
        row!(pthread_attr_setstacksize, "GLIBC_2.2.5", true),
        row!(pthread_attr_getguardsize, "GLIBC_2.2.5", true),
        row!(pthread_attr_setguardsize, "GLIBC_2.2.5", true),
        row!(pthread_attr_getstack, "GLIBC_2.2.5", true),
        row!(pthread_attr_setstack, "GLIBC_2.2.5", true),
        row!(pthread_attr_getinheritsched, "GLIBC_2.2.5", false),
        row!(pthread_attr_setinheritsched, "GLIBC_2.2.5", false),
        row!(pthread_attr_getschedpolicy, "GLIBC_2.2.5", false),
        row!(pthread_attr_setschedpolicy, "GLIBC_2.2.5", false),
        row!(pthread_attr_getschedparam, "GLIBC_2.2.5", false),
        row!(pthread_attr_setschedparam, "GLIBC_2.2.5", false),
        row!(pthread_attr_getscope, "GLIBC_2.2.5", false),
        row!(pthread_attr_setscope, "GLIBC_2.2.5", false),
        row!(pthread_mutexattr_init, "GLIBC_2.2.5", true),
        row!(pthread_mutexattr_destroy, "GLIBC_2.2.5", true),
        row!(pthread_mutexattr_gettype, "GLIBC_2.2.5", true),
        row!(pthread_mutexattr_settype, "GLIBC_2.2.5", true),
        row!(pthread_mutexattr_getpshared, "GLIBC_2.2.5", true),
        row!(pthread_mutexattr_setpshared, "GLIBC_2.2.5", true),
        row!(pthread_mutexattr_getprotocol, "GLIBC_2.4", true),
        row!(pthread_mutexattr_setprotocol, "GLIBC_2.4", true),
        row!(pthread_mutexattr_getrobust, "GLIBC_2.12", true),
        row!(pthread_mutexattr_setrobust, "GLIBC_2.12", true),
        row!(pthread_mutex_consistent, "GLIBC_2.12", true),
        row!(pthread_condattr_init, "GLIBC_2.2.5", false),
        row!(pthread_condattr_destroy, "GLIBC_2.2.5", false),
        row!(pthread_condattr_getclock, "GLIBC_2.3.3", true),
        row!(pthread_condattr_setclock, "GLIBC_2.3.3", true),
        row!(pthread_condattr_getpshared, "GLIBC_2.2.5", true),
        row!(pthread_condattr_setpshared, "GLIBC_2.2.5", true),
        row!(pthread_rwlockattr_init, "GLIBC_2.2.5", true),
        row!(pthread_rwlockattr_destroy, "GLIBC_2.2.5", true),
        row!(pthread_rwlockattr_getpshared, "GLIBC_2.2.5", true),
        row!(pthread_rwlockattr_setpshared, "GLIBC_2.2.5", true),
        row!(pthread_rwlock_timedrdlock, "GLIBC_2.2.5", true),
        row!(pthread_rwlock_timedwrlock, "GLIBC_2.2.5", true),
        row!(pthread_cancel, "GLIBC_2.2.5", true),
        row!(pthread_testcancel, "GLIBC_2.2.5", true),
        row!(pthread_setcancelstate, "GLIBC_2.2.5", false),
        row!(pthread_setcanceltype, "GLIBC_2.2.5", false),
        row!(__pthread_register_cancel, "GLIBC_2.3.3", true),
        row!(__pthread_unregister_cancel, "GLIBC_2.3.3", true),
        row!(__pthread_register_cancel_defer, "GLIBC_2.3.3", true),
        row!(__pthread_unregister_cancel_restore, "GLIBC_2.3.3", true),
        row!(__pthread_cleanup_routine, "GLIBC_2.3.3", true),
        row!(__pthread_unwind_next, "GLIBC_2.3.3", true),
        (
            "__sigsetjmp",
            "GLIBC_2.2.5",
            false,
            cleanup_setjmp_address(),
        ),
    ]
}

const SOURCE: &str = r#"
#define _GNU_SOURCE
#include <pthread.h>
#include <errno.h>
#include <stdint.h>
#include <stdatomic.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <dlfcn.h>
#define CHECK(x) do { if (!(x)) return __LINE__; } while (0)
static void *identity(void *arg) { return arg; }
int attributes(void) {
    pthread_attr_t a; int v; size_t z; pthread_t t; void *result;
    CHECK(pthread_attr_init(&a)==0);
    CHECK(pthread_attr_setdetachstate(&a,PTHREAD_CREATE_JOINABLE)==0);
    CHECK(pthread_attr_getdetachstate(&a,&v)==0 && v==PTHREAD_CREATE_JOINABLE);
    CHECK(pthread_attr_setstacksize(&a,262144)==0);
    CHECK(pthread_attr_getstacksize(&a,&z)==0 && z==262144);
    CHECK(pthread_attr_setguardsize(&a,4096)==0);
    CHECK(pthread_attr_getguardsize(&a,&z)==0 && z==4096);
    CHECK(pthread_attr_setinheritsched(&a,PTHREAD_INHERIT_SCHED)==0);
    CHECK(pthread_attr_getinheritsched(&a,&v)==0 && v==PTHREAD_INHERIT_SCHED);
    CHECK(pthread_attr_setschedpolicy(&a,SCHED_OTHER)==0);
    CHECK(pthread_attr_getschedpolicy(&a,&v)==0 && v==SCHED_OTHER);
    struct sched_param sp={0}; CHECK(pthread_attr_setschedparam(&a,&sp)==0);
    sp.sched_priority=17; CHECK(pthread_attr_getschedparam(&a,&sp)==0 && sp.sched_priority==0);
    CHECK(pthread_attr_setscope(&a,PTHREAD_SCOPE_SYSTEM)==0);
    CHECK(pthread_attr_getscope(&a,&v)==0 && v==PTHREAD_SCOPE_SYSTEM);
    CHECK(pthread_attr_setstacksize(&a,1)==EINVAL);
    CHECK(pthread_create(&t,&a,identity,(void *)37)==0);
    CHECK(pthread_join(t,&result)==0 && result==(void *)37);
    void *stack=malloc(262144); CHECK(stack);
    CHECK(pthread_attr_setstack(&a,stack,262144)==0);
    CHECK(pthread_attr_getstack(&a,&result,&z)==0 && result==stack && z==262144);
    CHECK(pthread_attr_destroy(&a)==0); free(stack);
    return 0;
}

int mutex_types(void) {
    pthread_mutexattr_t a; pthread_mutex_t m; int v;
    CHECK(pthread_mutexattr_init(&a)==0);
    CHECK(pthread_mutexattr_settype(&a,PTHREAD_MUTEX_ERRORCHECK)==0);
    CHECK(pthread_mutexattr_gettype(&a,&v)==0 && v==PTHREAD_MUTEX_ERRORCHECK);
    CHECK(pthread_mutexattr_setpshared(&a,PTHREAD_PROCESS_PRIVATE)==0);
    CHECK(pthread_mutexattr_getpshared(&a,&v)==0 && v==PTHREAD_PROCESS_PRIVATE);
    CHECK(pthread_mutexattr_setprotocol(&a,PTHREAD_PRIO_NONE)==0);
    CHECK(pthread_mutexattr_getprotocol(&a,&v)==0 && v==PTHREAD_PRIO_NONE);
    CHECK(pthread_mutex_init(&m,&a)==0);
    CHECK(pthread_mutex_lock(&m)==0 && pthread_mutex_lock(&m)==EDEADLK);
    CHECK(pthread_mutex_unlock(&m)==0 && pthread_mutex_unlock(&m)==EPERM);
    CHECK(pthread_mutex_destroy(&m)==0);
    CHECK(pthread_mutexattr_settype(&a,PTHREAD_MUTEX_RECURSIVE)==0);
    CHECK(pthread_mutex_init(&m,&a)==0);
    CHECK(pthread_mutex_lock(&m)==0 && pthread_mutex_trylock(&m)==0);
    CHECK(pthread_mutex_unlock(&m)==0 && pthread_mutex_unlock(&m)==0);
    CHECK(pthread_mutex_destroy(&m)==0 && pthread_mutexattr_destroy(&a)==0);
    return 0;
}

static void *die_holding_mutex(void *arg) { return (void *)(intptr_t)pthread_mutex_lock(arg); }
int robust_recovery(void) {
    pthread_mutexattr_t a; int v; pthread_t t; void *result;
    CHECK(pthread_mutexattr_init(&a)==0);
    CHECK(pthread_mutexattr_setrobust(&a,PTHREAD_MUTEX_ROBUST)==0);
    CHECK(pthread_mutexattr_getrobust(&a,&v)==0 && v==PTHREAD_MUTEX_ROBUST);
    for(int repair=0;repair<2;++repair) {
        pthread_mutex_t m; CHECK(pthread_mutex_init(&m,&a)==0);
        CHECK(pthread_create(&t,0,die_holding_mutex,&m)==0);
        CHECK(pthread_join(t,&result)==0 && result==0);
        CHECK(pthread_mutex_lock(&m)==EOWNERDEAD);
        if(repair) CHECK(pthread_mutex_consistent(&m)==0);
        CHECK(pthread_mutex_unlock(&m)==0);
        CHECK(pthread_mutex_lock(&m)==(repair ? 0 : ENOTRECOVERABLE));
        if(repair) CHECK(pthread_mutex_unlock(&m)==0);
        CHECK(pthread_mutex_destroy(&m)==0);
    }
    CHECK(pthread_mutexattr_destroy(&a)==0); return 0;
}

struct held { pthread_mutex_t mutex; pthread_rwlock_t rw; _Atomic int phase; };
static void *hold_locks(void *arg) {
    struct held *s=arg;
    if(pthread_mutex_lock(&s->mutex)||pthread_rwlock_wrlock(&s->rw)) { atomic_store(&s->phase,-1); return (void *)1; }
    atomic_store(&s->phase,1);
    while(atomic_load(&s->phase)==1) { }
    return (void *)(intptr_t)(pthread_rwlock_unlock(&s->rw)||pthread_mutex_unlock(&s->mutex));
}
int deadlines(void) {
    struct timespec expired={0,0}; pthread_condattr_t ca; pthread_cond_t c;
    pthread_mutex_t m; clockid_t clock; int v;
    CHECK(pthread_condattr_init(&ca)==0);
    CHECK(pthread_condattr_setclock(&ca,CLOCK_MONOTONIC)==0);
    CHECK(pthread_condattr_getclock(&ca,&clock)==0 && clock==CLOCK_MONOTONIC);
    CHECK(pthread_condattr_setpshared(&ca,PTHREAD_PROCESS_PRIVATE)==0);
    CHECK(pthread_condattr_getpshared(&ca,&v)==0 && v==PTHREAD_PROCESS_PRIVATE);
    CHECK(pthread_cond_init(&c,&ca)==0 && pthread_condattr_destroy(&ca)==0);
    CHECK(pthread_mutex_init(&m,0)==0 && pthread_mutex_lock(&m)==0);
    CHECK(pthread_cond_timedwait(&c,&m,&expired)==ETIMEDOUT);
    CHECK(pthread_mutex_trylock(&m)==EBUSY);
    CHECK(pthread_mutex_unlock(&m)==0 && pthread_mutex_destroy(&m)==0 && pthread_cond_destroy(&c)==0);
    struct held s; atomic_init(&s.phase,0); pthread_rwlockattr_t ra;
    CHECK(pthread_rwlockattr_init(&ra)==0);
    CHECK(pthread_rwlockattr_setpshared(&ra,PTHREAD_PROCESS_PRIVATE)==0);
    CHECK(pthread_rwlockattr_getpshared(&ra,&v)==0 && v==PTHREAD_PROCESS_PRIVATE);
    CHECK(pthread_rwlock_init(&s.rw,&ra)==0 && pthread_rwlockattr_destroy(&ra)==0);
    CHECK(pthread_mutex_init(&s.mutex,0)==0);
    pthread_t t; CHECK(pthread_create(&t,0,hold_locks,&s)==0);
    while(atomic_load(&s.phase)==0) { }
    CHECK(atomic_load(&s.phase)==1);
    int r[3];
    r[0]=pthread_mutex_timedlock(&s.mutex,&expired);
    r[1]=pthread_rwlock_timedrdlock(&s.rw,&expired);
    r[2]=pthread_rwlock_timedwrlock(&s.rw,&expired);
    atomic_store(&s.phase,2); void *result;
    CHECK(pthread_join(t,&result)==0 && result==0);
    for(int i=0;i<3;++i) CHECK(r[i]==ETIMEDOUT);
    CHECK(pthread_mutex_lock(&s.mutex)==0 && pthread_mutex_unlock(&s.mutex)==0);
    CHECK(pthread_rwlock_rdlock(&s.rw)==0 && pthread_rwlock_unlock(&s.rw)==0);
    CHECK(pthread_mutex_destroy(&s.mutex)==0 && pthread_rwlock_destroy(&s.rw)==0);
    return 0;
}

static _Atomic int stage, trace;
static pthread_key_t key;
static pthread_mutex_t cancel_mutex;
static pthread_cond_t cancel_condition;
static int read_end, scenario;
static void record(void *p) { atomic_store(&trace,atomic_load(&trace)*10+(int)(intptr_t)p); }
static void unlock_cleanup(void *p) { record(p); if(pthread_mutex_unlock(&cancel_mutex)) atomic_store(&trace,-100); }
static void *cancellable(void *arg) {
    (void)arg; int old; pthread_setspecific(key,(void *)3);
    pthread_setcanceltype(PTHREAD_CANCEL_DEFERRED,&old);
    if(scenario==2) pthread_mutex_lock(&cancel_mutex);
    pthread_cleanup_push(record,(void *)1);
    pthread_cleanup_push_defer_np(scenario==2 ? unlock_cleanup : record,(void *)2);
    atomic_store(&stage,1);
    if(scenario==0) { char c; read(read_end,&c,1); }
    if(scenario==1) {
        pthread_setcancelstate(PTHREAD_CANCEL_DISABLE,&old);
        pthread_cancel(pthread_self());
        pthread_testcancel();
        pthread_setcancelstate(PTHREAD_CANCEL_ENABLE,&old);
        pthread_testcancel();
    }
    if(scenario==2) pthread_cond_wait(&cancel_condition,&cancel_mutex);
    if(scenario==3) pthread_exit((void *)41);
    pthread_cleanup_pop_restore_np(1);
    pthread_cleanup_pop(1);
    return (void *)42;
}
int cancellation(unsigned which) {
    scenario=(int)which; atomic_store(&stage,0); atomic_store(&trace,0);
    CHECK(pthread_key_create(&key,record)==0);
    CHECK(pthread_mutex_init(&cancel_mutex,0)==0 && pthread_cond_init(&cancel_condition,0)==0);
    int ends[2]; CHECK(pipe(ends)==0); read_end=ends[0]; pthread_t t;
    CHECK(pthread_create(&t,0,cancellable,0)==0);
    while(atomic_load(&stage)==0) { }
    if(which==0 || which==2) CHECK(pthread_cancel(t)==0);
    void *result; CHECK(pthread_join(t,&result)==0);
    CHECK(result==(which<3 ? PTHREAD_CANCELED : (void *)(uintptr_t)(which==3 ? 41 : 42)));
    CHECK(atomic_load(&trace)==213);
    CHECK(pthread_mutex_trylock(&cancel_mutex)==0 && pthread_mutex_unlock(&cancel_mutex)==0);
    CHECK(close(ends[0])==0 && close(ends[1])==0);
    CHECK(pthread_key_delete(key)==0 && pthread_mutex_destroy(&cancel_mutex)==0 && pthread_cond_destroy(&cancel_condition)==0);
    return 0;
}
void *control_dynamic(const char *name,const char *version,int *failed) {
    dlerror(); void *p=version ? dlvsym(RTLD_DEFAULT,name,version) : dlsym(RTLD_DEFAULT,name);
    *failed=dlerror()!=0; __asm__ __volatile__("" : "+r"(p)); return p;
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
            "frankenlibc-thread-control-{}-{stamp}",
            std::process::id()
        ));
        std::fs::create_dir(&dir).unwrap();
        let input = dir.join("control.c");
        let path = dir.join("control.so");
        let mut code = SOURCE.to_owned();
        for (i, (name, _, _, _)) in bindings().iter().enumerate() {
            code.push_str(&format!(
                "\nextern void import_{i}(void) __asm__(\"{name}\");"
            ));
        }
        code.push_str("\nvoid *control_direct(unsigned n) { switch(n) {");
        for i in 0..bindings().len() {
            code.push_str(&format!("case {i}: return (void *)import_{i};"));
        }
        code.push_str("default: return 0;} }\n");
        std::fs::write(&input, code).unwrap();
        let mut cc = Command::new("cc");
        cc.args([
            "-shared",
            "-fPIC",
            "-O2",
            "-fno-builtin",
            "-fno-optimize-sibling-calls",
            "-U_FORTIFY_SOURCE",
            "-D_FORTIFY_SOURCE=0",
        ]);
        // A normal host link supplies the modern condition-variable version.
        // Unversioned -nostdlib imports can bind glibc's obsolete 2.2.5 cond
        // layout, which is not the ABI described by the headers we compiled.
        // Only the native image is deliberately independent of host DT_NEEDED.
        if native {
            cc.arg("-nostdlib");
        }
        if got {
            cc.arg("-fno-plt");
        }
        let build = cc
            .arg(&input)
            .arg("-o")
            .arg(&path)
            .output()
            .expect("C compiler required");
        assert!(
            build.status.success(),
            "{}",
            String::from_utf8_lossy(&build.stderr)
        );
        let object = ElfLoader::new(0)
            .parse(&std::fs::read(&path).unwrap())
            .unwrap();
        if native {
            assert!(object.needed_libraries.is_empty());
        } else {
            assert!(
                object
                    .needed_libraries
                    .iter()
                    .any(|name| name == "libc.so.6")
            );
        }
        for (name, _, _, _) in bindings() {
            assert!(
                object
                    .undefined_symbols()
                    .any(|(_, s)| object.symbol_name(s) == Some(name)),
                "missing import {name}"
            );
        }
        let path = CString::new(path.as_os_str().as_encoded_bytes()).unwrap();
        // SAFETY: compiler-created path, exact loader ABI; handle stays alive
        // until all worker threads and cleanup callbacks have finished.
        let handle = unsafe {
            if native {
                dl::dlopen(path.as_ptr(), libc::RTLD_NOW)
            } else {
                let open: unsafe extern "C" fn(*const c_char, c_int) -> *mut c_void =
                    dlsym_oracle::host_fn(c"dlopen", dl::dlopen as *const ());
                open(path.as_ptr(), libc::RTLD_NOW)
            }
        };
        assert!(!handle.is_null(), "thread-control DSO load failed");
        if native {
            assert!(
                dl::native_dso_handle_for_tests(handle),
                "host fallback is not native coverage"
            );
        }
        Self { handle, native }
    }
    fn symbol(&self, name: &CStr) -> *mut c_void {
        // SAFETY: retained handle and terminated symbol name.
        let p = unsafe {
            if self.native {
                dl::dlsym(self.handle, name.as_ptr())
            } else {
                let find: unsafe extern "C" fn(*mut c_void, *const c_char) -> *mut c_void =
                    dlsym_oracle::host_fn(c"dlsym", dl::dlsym as *const ());
                find(self.handle, name.as_ptr())
            }
        };
        assert!(!p.is_null(), "missing {name:?}");
        p
    }
    fn close(self) {
        // SAFETY: fixture has joined every worker before releasing the DSO.
        let rc = unsafe {
            if self.native {
                dl::dlclose(self.handle)
            } else {
                let close: unsafe extern "C" fn(*mut c_void) -> c_int =
                    dlsym_oracle::host_fn(c"dlclose", dl::dlclose as *const ());
                close(self.handle)
            }
        };
        assert_eq!(rc, 0);
    }
}
fn scenario(name: &str, body: fn(bool)) {
    if let Ok(backend) = std::env::var("FL_THREAD_CONTROL_CHILD") {
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
            .env("FL_THREAD_CONTROL_CHILD", backend)
            .env("FRANKENLIBC_MODE", mode)
            .env_remove("LD_PRELOAD")
            .spawn()
            .unwrap();
        let deadline = Instant::now() + Duration::from_secs(45);
        loop {
            if let Some(status) = child.try_wait().unwrap() {
                assert!(status.success(), "{name}: {backend}/{mode}: {status}");
                break;
            }
            if Instant::now() >= deadline {
                child.kill().unwrap();
                child.wait().unwrap();
                panic!("{name}: {backend}/{mode}: timed out");
            }
            std::thread::sleep(Duration::from_millis(10));
        }
    }
}
#[test]
fn native_thread_control_attributes_recovery_and_deadlines() {
    scenario(
        "native_thread_control_attributes_recovery_and_deadlines",
        |native| {
            for got in [false, true] {
                let lib = Library::new(native, got);
                for name in [
                    c"attributes",
                    c"mutex_types",
                    c"robust_recovery",
                    c"deadlines",
                ] {
                    // SAFETY: all protocol entries return int and take no arguments.
                    let run: unsafe extern "C" fn() -> c_int =
                        unsafe { std::mem::transmute(lib.symbol(name)) };
                    assert_eq!(unsafe { run() }, 0, "C protocol assertion in {name:?}");
                }
                lib.close();
            }
        },
    );
}
#[test]
fn native_thread_control_cancellation_cleanup_and_tls_destructors() {
    scenario(
        "native_thread_control_cancellation_cleanup_and_tls_destructors",
        |native| {
            for got in [false, true] {
                let lib = Library::new(native, got);
                // SAFETY: protocol signature is exactly int cancellation(unsigned).
                let run: unsafe extern "C" fn(u32) -> c_int =
                    unsafe { std::mem::transmute(lib.symbol(c"cancellation")) };
                for which in 0..5 {
                    assert_eq!(unsafe { run(which) }, 0, "cancellation scenario {which}");
                }
                lib.close();
            }
        },
    );
}
#[test]
fn native_thread_control_exact_versions_and_provider_identity() {
    scenario(
        "native_thread_control_exact_versions_and_provider_identity",
        |native| {
            let lib = Library::new(native, false);
            // SAFETY: exact function signatures from the compiled fixture.
            unsafe {
                let direct: unsafe extern "C" fn(u32) -> *mut c_void =
                    std::mem::transmute(lib.symbol(c"control_direct"));
                let dynamic: unsafe extern "C" fn(
                    *const c_char,
                    *const c_char,
                    *mut c_int,
                ) -> *mut c_void = std::mem::transmute(lib.symbol(c"control_dynamic"));
                for (i, (name, first, merged, expected)) in bindings().into_iter().enumerate() {
                    let name = CString::new(name).unwrap();
                    let first = CString::new(first).unwrap();
                    let provider = direct(i as u32);
                    let expected = if native {
                        expected.cast_mut().cast()
                    } else {
                        // Debug builds deliberately omit the owned naked
                        // __sigsetjmp, so that one provider IS the host entry.
                        // Exclude the actual debug Rust frontend instead; all
                        // other entries still exclude their owned definition.
                        let owned = if cfg!(debug_assertions) && name.as_bytes() == b"__sigsetjmp" {
                            frankenlibc_abi::setjmp_abi::sigsetjmp as *const ()
                        } else {
                            expected
                        };
                        dlsym_oracle::host_addr(&name, owned)
                    };
                    assert_eq!(provider, expected, "direct {name:?}");
                    for (version, permitted) in [
                        (std::ptr::null(), true),
                        (first.as_ptr(), true),
                        (c"GLIBC_2.34".as_ptr(), merged),
                        (c"GLIBC_PRIVATE".as_ptr(), false),
                        (c"MISSING_VERSION".as_ptr(), false),
                    ] {
                        let mut failed = -1;
                        let result = dynamic(name.as_ptr(), version, &mut failed);
                        if permitted {
                            assert_eq!(result, provider, "versioned {name:?}");
                            assert_eq!(failed, 0);
                        } else {
                            assert!(result.is_null(), "unsupported {name:?}");
                            assert_eq!(failed, 1);
                        }
                    }
                }
            }
            lib.close();
        },
    );
}

fn cleanup_setjmp_address() -> *const () {
    #[cfg(not(debug_assertions))]
    {
        frankenlibc_abi::setjmp_abi::__sigsetjmp as *const ()
    }
    #[cfg(debug_assertions)]
    {
        unsafe extern "C" {
            #[link_name = "__sigsetjmp"]
            fn host_sigsetjmp(env: *mut c_void, save: c_int) -> c_int;
        }
        host_sigsetjmp as *const ()
    }
}
