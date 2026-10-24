//! Compiled C semaphore protocols, requiring native admission and a live host oracle.
#![cfg(all(target_os = "linux", target_arch = "x86_64"))]
use frankenlibc_abi::{dlfcn_abi as dl, glibc_internal_abi, unistd_abi as sem};
use frankenlibc_core::elf::ElfLoader;
use std::ffi::{CStr, CString, c_char, c_int, c_void};
use std::process::Command;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};
#[path = "common/dlsym_oracle.rs"]
mod dlsym_oracle;

const SOURCE: &str = r#"
#define _GNU_SOURCE
#include <semaphore.h>
#include <pthread.h>
#include <stdatomic.h>
#include <stdint.h>
#include <limits.h>
#include <errno.h>
#include <fcntl.h>
#include <time.h>
#include <unistd.h>
#include <sys/wait.h>
#include <dlfcn.h>
#define CHECK(c) do { if (!(c)) return __LINE__; } while (0)
static int value(sem_t *s) { int n=-999; return sem_getvalue(s,&n) ? -999 : n; }
static struct timespec deadline(void) { struct timespec t; clock_gettime(CLOCK_REALTIME,&t); t.tv_sec+=3; return t; }
int named_lifetime(const char *name) {
    sem_t *a=sem_open(name,O_CREAT|O_EXCL,0600,3);
    CHECK(a!=SEM_FAILED && value(a)==3);
    CHECK(!sem_wait(a) && value(a)==2);
    sem_t *b=sem_open(name,O_CREAT,0600,9), *c=sem_open(name,0);
    CHECK(b==a && c==a && value(a)==2);
    sem_t *ignored=sem_open(name,O_CREAT,0600,UINT_MAX);
    CHECK(ignored==a && value(a)==2 && !sem_close(ignored));
    CHECK(!sem_close(b) && !sem_post(c) && value(a)==3);
    errno=0; CHECK(sem_open(name,O_CREAT|O_EXCL,0600,1)==SEM_FAILED && errno==EEXIST);
    CHECK(!sem_unlink(name));
    sem_t *fresh=sem_open(name,O_CREAT|O_EXCL,0600,7);
    CHECK(fresh!=SEM_FAILED && fresh!=a && value(fresh)==7 && value(c)==3);
    CHECK(!sem_close(c) && !sem_trywait(a) && value(a)==2);
    CHECK(!sem_close(a) && !sem_close(fresh) && !sem_unlink(name));
    errno=0; CHECK(sem_open(name,0)==SEM_FAILED && errno==ENOENT);
    return 0;
}
int named_errors(const char *name) {
    errno=0; CHECK(sem_open(name,0)==SEM_FAILED && errno==ENOENT);
    errno=0; CHECK(sem_open(name,O_CREAT|O_EXCL,0600,UINT_MAX)==SEM_FAILED && errno==EINVAL);
    errno=0; CHECK(sem_open(name,0)==SEM_FAILED && errno==ENOENT);
    errno=0; CHECK(sem_open("",O_CREAT,0600,1)==SEM_FAILED && errno==EINVAL);
    errno=0; CHECK(sem_open("/fl/invalid",O_CREAT,0600,1)==SEM_FAILED && errno==EINVAL);
    char longname[300]; longname[0]='/'; for(int i=1;i<299;i++)longname[i]='x';longname[299]=0;
    errno=0; CHECK(sem_open(longname,O_CREAT,0600,1)==SEM_FAILED && errno==ENAMETOOLONG);
    return 0;
}
struct creator { const char *name; pthread_barrier_t *gate; sem_t *handle; int error; };
static void *create_thread(void *arg) {
    struct creator *c=arg;
    pthread_barrier_wait(c->gate);
    c->handle=sem_open(c->name,O_CREAT,0600,5);
    if(c->handle==SEM_FAILED) c->error=1;
    else if(sem_post(c->handle)) c->error=2;
    return 0;
}
int concurrent_creators(const char *name) {
    enum { N=8 }; pthread_barrier_t gate;
    CHECK(!pthread_barrier_init(&gate,0,N));
    for(int round=0;round<24;round++) {
        struct creator c[N]; pthread_t t[N];
        for(int i=0;i<N;i++) { c[i]=(struct creator){name,&gate,SEM_FAILED,0}; CHECK(!pthread_create(&t[i],0,create_thread,&c[i])); }
        for(int i=0;i<N;i++) CHECK(!pthread_join(t[i],0));
        for(int i=0;i<N;i++) CHECK(!c[i].error && c[i].handle==c[0].handle);
        CHECK(value(c[0].handle)==5+N);
        CHECK(!sem_unlink(name));
        for(int i=0;i<N;i++) CHECK(!sem_close(c[i].handle));
    }
    CHECK(!pthread_barrier_destroy(&gate)); return 0;
}
int process_creators(const char *name,pid_t (*fork_process)(void),pid_t (*reap)(pid_t,int*,int)) {
    enum { N=6 }; pid_t children[N]; int start[2]; CHECK(!pipe(start));
    for(int i=0;i<N;i++) {
        children[i]=fork_process(); CHECK(children[i]>=0);
        if(!children[i]) {
            close(start[1]);char b; if(read(start[0],&b,1)!=1)_exit(11);
            sem_t *s=sem_open(name,O_CREAT,0600,5);
            if(s==SEM_FAILED)_exit(12);
            if(sem_post(s)||sem_close(s))_exit(13);
            _exit(0);
        }
    }
    CHECK(!close(start[0])); CHECK(write(start[1],"abcdef",N)==N); CHECK(!close(start[1]));
    for(int i=0;i<N;i++) { int status; CHECK(reap(children[i],&status,0)==children[i]); CHECK(WIFEXITED(status)&&WEXITSTATUS(status)==0); }
    sem_t *s=sem_open(name,0); CHECK(s!=SEM_FAILED && value(s)==5+N);
    CHECK(!sem_unlink(name) && !sem_close(s)); return 0;
}
int process_handoff(const char *name,pid_t (*fork_process)(void),pid_t (*reap)(pid_t,int*,int)) {
    sem_t *s=sem_open(name,O_CREAT|O_EXCL,0600,0); CHECK(s!=SEM_FAILED);
    int ready[2]; CHECK(!pipe(ready)); pid_t child=fork_process(); CHECK(child>=0);
    if(!child) {
        close(ready[0]); sem_t *other=sem_open(name,0); if(other==SEM_FAILED)_exit(20);
        char b=1; if(write(ready[1],&b,1)!=1)_exit(21);
        struct timespec until=deadline(); if(sem_timedwait(other,&until))_exit(22);
        if(value(other)!=0 || sem_close(other))_exit(23); _exit(0);
    }
    CHECK(!close(ready[1]));char b=0;CHECK(read(ready[0],&b,1)==1&&b==1);CHECK(!close(ready[0]));
    struct timespec delay={0,20000000};nanosleep(&delay,0); CHECK(!sem_post(s));
    int status; CHECK(reap(child,&status,0)==child);CHECK(WIFEXITED(status)&&WEXITSTATUS(status)==0);
    CHECK(value(s)==0 && !sem_close(s) && !sem_unlink(name));return 0;
}
static sem_t cancelled;static _Atomic int ready,cleaned;
static void cleanup(void *p) { (void)p;atomic_store(&cleaned,1); }
static void *blocked(void *p) {
    (void)p; pthread_cleanup_push(cleanup,0);
    atomic_store(&ready,1); sem_wait(&cancelled);
    pthread_cleanup_pop(1);return (void*)2;
}
int unnamed_and_cancellation(const char *unused) {
    (void)unused; sem_t s; CHECK(!sem_init(&s,0,2));CHECK(value(&s)==2);
    CHECK(!sem_wait(&s)&&!sem_trywait(&s));errno=0;CHECK(sem_trywait(&s)==-1&&errno==EAGAIN);
    struct timespec past={0,0};errno=0;CHECK(sem_timedwait(&s,&past)==-1&&errno==ETIMEDOUT);
    CHECK(!sem_post(&s)&&!sem_wait(&s)&&!sem_destroy(&s));
    CHECK(!sem_init(&cancelled,0,0));atomic_store(&ready,0);atomic_store(&cleaned,0);
    pthread_t thread;CHECK(!pthread_create(&thread,0,blocked,0));
    while(!atomic_load(&ready)) { }
    struct timespec delay={0,20000000};nanosleep(&delay,0);
    CHECK(!pthread_cancel(thread));void *result=0;
    CHECK(!pthread_join(thread,&result)&&result==PTHREAD_CANCELED&&atomic_load(&cleaned)==1);
    CHECK(!sem_post(&cancelled)&&!sem_trywait(&cancelled)&&!sem_destroy(&cancelled));return 0;
}
static const char *names[]={"sem_open","sem_close","sem_unlink","sem_init","sem_destroy","sem_post","sem_wait","sem_trywait","sem_timedwait","sem_getvalue","sem_clockwait"};
void *direct(int n) {
    switch(n) {
#define ENTRY(i,fn) case i:return (void*)fn
        ENTRY(0,sem_open);ENTRY(1,sem_close);ENTRY(2,sem_unlink);ENTRY(3,sem_init);ENTRY(4,sem_destroy);
        ENTRY(5,sem_post);ENTRY(6,sem_wait);ENTRY(7,sem_trywait);ENTRY(8,sem_timedwait);ENTRY(9,sem_getvalue);
        ENTRY(10,sem_clockwait);
    }return 0;
}
int clockwait_deadlines(const char *unused) {
    (void)unused;sem_t s;CHECK(!sem_init(&s,0,1));
    struct timespec bad={0,-1};errno=0;
    CHECK(sem_clockwait(&s,CLOCK_MONOTONIC,&bad)==-1&&errno==EINVAL&&value(&s)==1);
    struct timespec past={INT64_MIN,0};
    CHECK(!sem_clockwait(&s,CLOCK_REALTIME,&past)&&value(&s)==0);
    errno=0;CHECK(sem_clockwait(&s,CLOCK_MONOTONIC,&past)==-1&&errno==ETIMEDOUT);
    CHECK(!sem_post(&s));errno=0;
    CHECK(sem_clockwait(&s,CLOCK_BOOTTIME,&past)==-1&&errno==EINVAL&&value(&s)==1);
    CHECK(!sem_trywait(&s)&&!sem_destroy(&s));return 0;
}

void *lookup(int n,const char *v) { return v?dlvsym(RTLD_DEFAULT,names[n],v):dlsym(RTLD_DEFAULT,names[n]); }
"#;

struct Library {
    handle: *mut c_void,
    native: bool,
    name: CString,
}
impl Library {
    fn new(native: bool, got: bool) -> Self {
        let stamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let dir = std::env::temp_dir().join(format!("fl-sem-{}-{stamp}", std::process::id()));
        std::fs::create_dir(&dir).unwrap();
        let source = dir.join("sem.c");
        let path = dir.join("sem.so");
        std::fs::write(&source, SOURCE).unwrap();
        let mut cc = Command::new("cc");
        cc.args([
            "-shared",
            "-fPIC",
            "-O2",
            "-fno-builtin",
            "-U_FORTIFY_SOURCE",
            "-D_FORTIFY_SOURCE=0",
        ]);
        cc.arg(if native { "-nostdlib" } else { "-pthread" });
        if got {
            cc.arg("-fno-plt");
        }
        let output = cc.arg(&source).arg("-o").arg(&path).output().unwrap();
        assert!(
            output.status.success(),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
        let object = ElfLoader::new(0)
            .parse(&std::fs::read(&path).unwrap())
            .unwrap();
        if native {
            assert!(object.needed_libraries.is_empty());
        }
        for name in [
            "sem_open",
            "sem_close",
            "sem_unlink",
            "sem_init",
            "sem_destroy",
            "sem_post",
            "sem_wait",
            "sem_trywait",
            "sem_timedwait",
            "sem_getvalue",
            "sem_clockwait",
        ] {
            assert!(
                object
                    .undefined_symbols()
                    .any(|(_, s)| object.symbol_name(s) == Some(name)),
                "missing import {name}"
            );
        }
        let pathname = CString::new(path.as_os_str().as_encoded_bytes()).unwrap();
        // SAFETY: the terminated fixture path and exact loader signatures remain live.
        let handle = unsafe {
            if native {
                dl::dlopen(pathname.as_ptr(), libc::RTLD_NOW)
            } else {
                let open: unsafe extern "C" fn(*const c_char, c_int) -> *mut c_void =
                    dlsym_oracle::host_fn(c"dlopen", dl::dlopen as *const ());
                open(pathname.as_ptr(), libc::RTLD_NOW)
            }
        };
        assert!(
            !handle.is_null(),
            "fixture admission failed, native={native}"
        );
        if native {
            assert!(dl::native_dso_handle_for_tests(handle), "host fallback");
        }
        Self {
            handle,
            native,
            name: CString::new(format!("/fl-sem-{}-{stamp}", std::process::id())).unwrap(),
        }
    }
    fn symbol(&self, name: &CStr) -> *mut c_void {
        // SAFETY: this object retains its loader handle and the symbol is terminated.
        let address = unsafe {
            if self.native {
                dl::dlsym(self.handle, name.as_ptr())
            } else {
                let find: unsafe extern "C" fn(*mut c_void, *const c_char) -> *mut c_void =
                    dlsym_oracle::host_fn(c"dlsym", dl::dlsym as *const ());
                find(self.handle, name.as_ptr())
            }
        };
        assert!(!address.is_null(), "{name:?}");
        address
    }
}
impl Drop for Library {
    fn drop(&mut self) {
        // SAFETY: all workers/children are joined before the protocol returns.
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
fn isolated(name: &str, body: fn(bool)) {
    if let Ok(mode) = std::env::var("FL_SEMAPHORE_CHILD") {
        body(mode == "native");
        return;
    }
    for (backend, mode) in [
        ("host", "strict"),
        ("native", "strict"),
        ("native", "hardened"),
    ] {
        let mut child = Command::new(std::env::current_exe().unwrap())
            .args(["--exact", name, "--nocapture"])
            .env("FL_SEMAPHORE_CHILD", backend)
            .env("FRANKENLIBC_MODE", mode)
            .env_remove("LD_PRELOAD")
            .spawn()
            .unwrap();
        let until = Instant::now() + Duration::from_secs(45);
        loop {
            if let Some(status) = child.try_wait().unwrap() {
                assert!(status.success(), "{name}/{backend}/{mode}: {status}");
                break;
            }
            if Instant::now() > until {
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
        // SAFETY: all ordinary protocols export int(const char*).
        let run: unsafe extern "C" fn(*const c_char) -> c_int =
            unsafe { std::mem::transmute(lib.symbol(name)) };
        assert_eq!(
            unsafe { run(lib.name.as_ptr()) },
            0,
            "C assertion line in {name:?}"
        );
    }
}
#[test]
fn named_lifetime_reopen_unlink_and_replacement() {
    isolated("named_lifetime_reopen_unlink_and_replacement", |native| {
        protocol(native, c"named_lifetime")
    });
}
#[test]
fn named_errors_return_the_platform_failure_sentinel() {
    isolated(
        "named_errors_return_the_platform_failure_sentinel",
        |native| protocol(native, c"named_errors"),
    );
}
#[test]
fn named_concurrent_creation_never_resets_published_state() {
    isolated(
        "named_concurrent_creation_never_resets_published_state",
        |native| protocol(native, c"concurrent_creators"),
    );
}
#[test]
fn unnamed_waits_and_blocked_cancellation_preserve_state() {
    isolated(
        "unnamed_waits_and_blocked_cancellation_preserve_state",
        |native| {
            protocol(native, c"unnamed_and_cancellation");
            protocol(native, c"clockwait_deadlines");
        },
    );
}
#[test]
fn named_processes_create_atomically_and_wake_each_other() {
    isolated(
        "named_processes_create_atomically_and_wake_each_other",
        |native| {
            type Fork = unsafe extern "C" fn() -> libc::pid_t;
            type Wait = unsafe extern "C" fn(libc::pid_t, *mut c_int, c_int) -> libc::pid_t;
            // SAFETY: use driver-owned process creation, not an unimplemented native import.
            let fork: Fork = unsafe {
                dlsym_oracle::host_fn(c"fork", frankenlibc_abi::process_abi::fork as *const ())
            };
            let reap: Wait = unsafe {
                dlsym_oracle::host_fn(
                    c"waitpid",
                    frankenlibc_abi::process_abi::waitpid as *const (),
                )
            };
            for got in [false, true] {
                for name in [c"process_creators", c"process_handoff"] {
                    let lib = Library::new(native, got);
                    let run: unsafe extern "C" fn(*const c_char, Fork, Wait) -> c_int =
                        unsafe { std::mem::transmute(lib.symbol(name)) };
                    assert_eq!(unsafe { run(lib.name.as_ptr(), fork, reap) }, 0, "{name:?}");
                }
            }
        },
    );
}
#[test]
fn semaphore_direct_and_dynamic_versions_select_one_provider() {
    isolated(
        "semaphore_direct_and_dynamic_versions_select_one_provider",
        |native| {
            for got in [false, true] {
                let lib = Library::new(native, got);
                // SAFETY: these are the exact compiled pointer-probe signatures.
                let direct: unsafe extern "C" fn(c_int) -> *mut c_void =
                    unsafe { std::mem::transmute(lib.symbol(c"direct")) };
                let lookup: unsafe extern "C" fn(c_int, *const c_char) -> *mut c_void =
                    unsafe { std::mem::transmute(lib.symbol(c"lookup")) };
                for n in 0..11 {
                    let expected = unsafe { direct(n) };
                    assert!(!expected.is_null());
                    if native {
                        let public = [
                            sem::sem_open as *const (),
                            sem::sem_close as *const (),
                            sem::sem_unlink as *const (),
                            sem::sem_init as *const (),
                            sem::sem_destroy as *const (),
                            sem::sem_post as *const (),
                            sem::sem_wait as *const (),
                            sem::sem_trywait as *const (),
                            sem::sem_timedwait as *const (),
                            sem::sem_getvalue as *const (),
                            glibc_internal_abi::sem_clockwait as *const (),
                        ];
                        assert_eq!(expected, public[n as usize] as *mut c_void);
                    }
                    for version in [
                        std::ptr::null(),
                        if n == 10 {
                            c"GLIBC_2.30".as_ptr()
                        } else {
                            c"GLIBC_2.2.5".as_ptr()
                        },
                        c"GLIBC_2.34".as_ptr(),
                    ] {
                        assert_eq!(unsafe { lookup(n, version) }, expected);
                    }
                    for version in [c"GLIBC_PRIVATE", c"GLIBC_2.35", c"MISSING_VERSION"] {
                        assert!(unsafe { lookup(n, version.as_ptr()) }.is_null());
                    }
                }
            }
        },
    );
}
