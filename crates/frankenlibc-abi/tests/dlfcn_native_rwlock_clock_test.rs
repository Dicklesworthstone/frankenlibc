//! Clock-specific rwlocks executed by real native C DSOs and a separate host oracle.
#![cfg(all(target_os = "linux", target_arch = "x86_64"))]
use frankenlibc_abi::{dlfcn_abi as dl, pthread_abi as p};
use frankenlibc_core::elf::ElfLoader;
use std::ffi::{CStr, CString, c_char, c_int, c_void};
use std::process::Command;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};
#[path = "common/dlsym_oracle.rs"]
mod dlsym_oracle;

const SOURCE: &str = r#"
#define _GNU_SOURCE
#include <pthread.h>
#include <time.h>
#include <errno.h>
#include <stdint.h>
#include <stdatomic.h>
#include <dlfcn.h>
#include <sched.h>
#include <sys/mman.h>
#include <sys/wait.h>
#include <unistd.h>
#define CHECK(x) do { if (!(x)) return __LINE__; } while (0)

static int lock_until(pthread_rwlock_t *rw, int op, clockid_t clock, const struct timespec *ts) {
    switch (op) {
        case 0: return pthread_rwlock_timedrdlock(rw, ts);
        case 1: return pthread_rwlock_timedwrlock(rw, ts);
        case 2: return pthread_rwlock_clockrdlock(rw, clock, ts);
        default: return pthread_rwlock_clockwrlock(rw, clock, ts);
    }
}
static void pause_briefly(void) {
    struct timespec start, now;
    clock_gettime(CLOCK_MONOTONIC, &start);
    do {
        clock_gettime(CLOCK_MONOTONIC, &now);
    } while ((now.tv_sec - start.tv_sec) * 1000000000LL + now.tv_nsec - start.tv_nsec < 20000000);
}
static struct timespec future(clockid_t clock, long ns) {
    struct timespec ts;
    clock_gettime(clock, &ts);
    ts.tv_nsec += ns;
    ts.tv_sec += ts.tv_nsec / 1000000000;
    ts.tv_nsec %= 1000000000;
    return ts;
}
int deadline_matrix(void) {
    for (int shared = 0; shared < 2; ++shared) {
        pthread_rwlockattr_t attr;
        pthread_rwlock_t rw;
        CHECK(!pthread_rwlockattr_init(&attr));
        CHECK(!pthread_rwlockattr_setpshared(&attr, shared ? PTHREAD_PROCESS_SHARED : PTHREAD_PROCESS_PRIVATE));
        CHECK(!pthread_rwlock_init(&rw, &attr));
        CHECK(!pthread_rwlockattr_destroy(&attr));
        for (int clock = 0; clock < 2; ++clock) for (int op = 0; op < 4; ++op) {
            if (op < 2 && clock) continue;
            const int64_t seconds[] = {0, -1, INT64_MIN, INT64_MAX};
            for (int i = 0; i < 4; ++i) {
                struct timespec ts = {seconds[i], 999999999};
                CHECK(!lock_until(&rw, op, clock, &ts));
                CHECK(!pthread_rwlock_unlock(&rw));
            }
            const int64_t bad[] = {-1, 1000000000, INT64_MIN, INT64_MAX};
            for (int i = 0; i < 4; ++i) {
                struct timespec ts = {INT64_MAX, bad[i]};
                CHECK(lock_until(&rw, op, clock, &ts) == EINVAL);
                CHECK(!pthread_rwlock_trywrlock(&rw));
                CHECK(lock_until(&rw, op, clock, &ts) == EINVAL);
                CHECK(pthread_rwlock_tryrdlock(&rw) == EBUSY);
                CHECK(!pthread_rwlock_unlock(&rw));
            }
        }
        struct timespec ts = {INT64_MAX, 0};
        CHECK(pthread_rwlock_clockrdlock(&rw, CLOCK_BOOTTIME, &ts) == EINVAL);
        CHECK(pthread_rwlock_clockwrlock(&rw, CLOCK_PROCESS_CPUTIME_ID, &ts) == EINVAL);
        CHECK(!pthread_rwlock_destroy(&rw));
    }
    pthread_rwlock_t rw = PTHREAD_RWLOCK_INITIALIZER;
    struct timespec ts = {INT64_MAX, 999999999};
    CHECK(!pthread_rwlock_clockrdlock(&rw, CLOCK_MONOTONIC, &ts));
    CHECK(!pthread_rwlock_unlock(&rw));
    CHECK(!pthread_rwlock_clockwrlock(&rw, CLOCK_MONOTONIC, &ts));
    CHECK(!pthread_rwlock_unlock(&rw));
    CHECK(!pthread_rwlock_destroy(&rw));
    return 0;
}
struct task {
    pthread_rwlock_t *rw;
    int op, clock, kind, rc;
    _Atomic int ready, returned;
    int64_t elapsed;
};
static void *waiter(void *arg) {
    struct task *t = arg;
    struct timespec begin, end, ts;
    clock_gettime(CLOCK_MONOTONIC, &begin);
    if (t->kind == 0) ts = (struct timespec){INT64_MIN, 0};
    else if (t->kind == 1) ts = future(t->clock, 30000000);
    else ts = (struct timespec){INT64_MAX, 999999999};
    atomic_store_explicit(&t->ready, 1, memory_order_release);
    t->rc = lock_until(t->rw, t->op, t->clock, &ts);
    clock_gettime(CLOCK_MONOTONIC, &end);
    t->elapsed = (end.tv_sec - begin.tv_sec) * 1000000000LL + end.tv_nsec - begin.tv_nsec;
    atomic_store_explicit(&t->returned, 1, memory_order_release);
    if (!t->rc && pthread_rwlock_unlock(t->rw)) t->rc = -100;
    return 0;
}
int contention_and_handoff(void) {
    for (int shared = 0; shared < 2; ++shared) {
        pthread_rwlockattr_t attr;
        pthread_rwlock_t rw;
        CHECK(!pthread_rwlockattr_init(&attr));
        CHECK(!pthread_rwlockattr_setpshared(&attr, shared ? PTHREAD_PROCESS_SHARED : PTHREAD_PROCESS_PRIVATE));
        CHECK(!pthread_rwlock_init(&rw, &attr));
        CHECK(!pthread_rwlockattr_destroy(&attr));
        for (int clock = 0; clock < 2; ++clock) for (int op = 0; op < 4; ++op) {
            if (op < 2 && clock) continue;
            for (int kind = 0; kind < 3; ++kind) {
                CHECK(!pthread_rwlock_wrlock(&rw));
                struct task t = {.rw=&rw, .op=op, .clock=clock, .kind=kind, .rc=-99};
                pthread_t worker;
                CHECK(!pthread_create(&worker, 0, waiter, &t));
                if (kind == 2) {
                    while (!atomic_load_explicit(&t.ready, memory_order_acquire)) atomic_signal_fence(memory_order_acq_rel);
                    pause_briefly();
                    CHECK(!atomic_load_explicit(&t.returned, memory_order_acquire));
                    CHECK(!pthread_rwlock_unlock(&rw));
                }
                CHECK(!pthread_join(worker, 0));
                if (kind == 2) CHECK(!t.rc);
                else {
                    CHECK(t.rc == ETIMEDOUT);
                    if (kind == 1) CHECK(t.elapsed >= 25000000);
                    CHECK(!pthread_rwlock_unlock(&rw));
                }
            }
        }
        CHECK(!pthread_rwlock_destroy(&rw));
    }
    return 0;
}
/* The driver owns shared storage and process creation/reaping. The native
   DSO owns every rwlock operation, including initialization and destruction. */
int process_shared_handoff(pthread_rwlock_t *rw, pid_t (*host_fork)(void), pid_t (*host_waitpid)(pid_t, int *, int)) {
    pthread_rwlockattr_t attr;
    CHECK(!pthread_rwlockattr_init(&attr));
    CHECK(!pthread_rwlockattr_setpshared(&attr, PTHREAD_PROCESS_SHARED));
    CHECK(!pthread_rwlock_init(rw, &attr));
    CHECK(!pthread_rwlockattr_destroy(&attr));
    for (int clock = 0; clock < 2; ++clock) for (int op = 0; op < 4; ++op) {
        if (op < 2 && clock) continue;
        int ready[2];
        CHECK(!pipe(ready));
        CHECK(!pthread_rwlock_wrlock(rw));
        pid_t child = host_fork();
        CHECK(child >= 0);
        if (!child) {
            close(ready[0]);
            char b = 1;
            if (write(ready[1], &b, 1) != 1) _exit(10);
            close(ready[1]);
            struct timespec ts = future(clock, 1000000000);
            int rc = lock_until(rw, op, clock, &ts);
            if (!rc) rc = pthread_rwlock_unlock(rw);
            _exit(rc ? 11 : 0);
        }
        CHECK(!close(ready[1]));
        char b = 0;
        CHECK(read(ready[0], &b, 1) == 1 && b == 1);
        CHECK(!close(ready[0]));
        pause_briefly();
        CHECK(!pthread_rwlock_unlock(rw));
        int status = 0;
        CHECK(host_waitpid(child, &status, 0) == child);
        CHECK(WIFEXITED(status) && WEXITSTATUS(status) == 0);
    }
    CHECK(!pthread_rwlock_destroy(rw));
    return 0;
}
void *clock_pointer(int write, const char *version) {
    const char *name = write ? "pthread_rwlock_clockwrlock" : "pthread_rwlock_clockrdlock";
    if (version) return dlvsym(RTLD_DEFAULT, name, version);
    return dlsym(RTLD_DEFAULT, name);
}
void *direct_pointer(int write) {
    return write ? (void *)pthread_rwlock_clockwrlock : (void *)pthread_rwlock_clockrdlock;
}
"#;

struct Library {
    handle: *mut c_void,
    native: bool,
}
impl Library {
    fn new(native: bool, got: bool) -> Self {
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let dir = std::env::temp_dir().join(format!("fl-rwclock-{}-{nonce}", std::process::id()));
        std::fs::create_dir(&dir).unwrap();
        let source = dir.join("rwclock.c");
        let path = dir.join("rwclock.so");
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
        } else {
            command.arg("-pthread");
        }
        if got {
            command.arg("-fno-plt");
        }
        let out = command.arg(&source).arg("-o").arg(&path).output().unwrap();
        assert!(
            out.status.success(),
            "{}",
            String::from_utf8_lossy(&out.stderr)
        );
        let bytes = std::fs::read(&path).unwrap();
        let object = ElfLoader::new(0).parse(&bytes).unwrap();
        if native {
            assert!(object.needed_libraries.is_empty());
        }
        for expected in ["pthread_rwlock_clockrdlock", "pthread_rwlock_clockwrlock"] {
            assert!(
                object
                    .undefined_symbols()
                    .any(|(_, s)| object.symbol_name(s) == Some(expected))
            );
        }
        let path = CString::new(path.as_os_str().as_encoded_bytes()).unwrap();
        // SAFETY: correct dlopen signatures and a NUL-terminated generated path.
        let handle = unsafe {
            if native {
                dl::dlopen(path.as_ptr(), libc::RTLD_NOW)
            } else {
                let open: unsafe extern "C" fn(*const c_char, c_int) -> *mut c_void =
                    dlsym_oracle::host_fn(c"dlopen", dl::dlopen as *const ());
                open(path.as_ptr(), libc::RTLD_NOW)
            }
        };
        assert!(
            !handle.is_null(),
            "fixture admission failed: native={native}, got={got}"
        );
        if native {
            assert!(dl::native_dso_handle_for_tests(handle), "host fallback");
        }
        Self { handle, native }
    }
    fn symbol(&self, name: &CStr) -> *mut c_void {
        // SAFETY: self owns the handle and the symbol name is terminated.
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
        // SAFETY: all worker threads and child processes were joined first.
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
    if let Ok(backend) = std::env::var("FL_NATIVE_RWCLOCK_CHILD") {
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
            .env("FL_NATIVE_RWCLOCK_CHILD", backend)
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
            if Instant::now() >= until {
                child.kill().unwrap();
                child.wait().unwrap();
                panic!("{name}/{backend}/{mode}: timed out");
            }
            std::thread::sleep(Duration::from_millis(10));
        }
    }
}
fn protocol(native: bool, entry: &CStr) {
    for got in [false, true] {
        let lib = Library::new(native, got);
        // SAFETY: each protocol's actual compiled signature is int(void).
        let call: unsafe extern "C" fn() -> c_int =
            unsafe { std::mem::transmute(lib.symbol(entry)) };
        assert_eq!(unsafe { call() }, 0, "C assertion line in {entry:?}");
    }
}
#[test]
fn native_rwclock_deadline_matrix() {
    isolated("native_rwclock_deadline_matrix", |native| {
        protocol(native, c"deadline_matrix")
    });
}
#[test]
fn native_rwclock_contention_and_handoffs() {
    isolated("native_rwclock_contention_and_handoffs", |native| {
        protocol(native, c"contention_and_handoff")
    });
}
#[test]
fn native_rwclock_process_shared_waits_wake_across_fork() {
    isolated(
        "native_rwclock_process_shared_waits_wake_across_fork",
        |native| {
            type Fork = unsafe extern "C" fn() -> libc::pid_t;
            type Wait = unsafe extern "C" fn(libc::pid_t, *mut c_int, c_int) -> libc::pid_t;
            // Process creation belongs to the test driver, outside the native
            // import surface. Resolve it independently of fl's process ABI.
            let fork: Fork = unsafe {
                dlsym_oracle::host_fn(c"fork", frankenlibc_abi::process_abi::fork as *const ())
            };
            let wait: Wait = unsafe {
                dlsym_oracle::host_fn(
                    c"waitpid",
                    frankenlibc_abi::process_abi::waitpid as *const (),
                )
            };
            for got in [false, true] {
                let lib = Library::new(native, got);
                let call: unsafe extern "C" fn(*mut libc::pthread_rwlock_t, Fork, Wait) -> c_int =
                    unsafe { std::mem::transmute(lib.symbol(c"process_shared_handoff")) };
                // SAFETY: anonymous shared storage outlives all child processes.
                let storage = unsafe {
                    libc::mmap(
                        std::ptr::null_mut(),
                        4096,
                        libc::PROT_READ | libc::PROT_WRITE,
                        libc::MAP_SHARED | libc::MAP_ANONYMOUS,
                        -1,
                        0,
                    )
                };
                assert_ne!(storage, libc::MAP_FAILED);
                let rc = unsafe { call(storage.cast(), fork, wait) };
                assert_eq!(unsafe { libc::munmap(storage, 4096) }, 0);
                assert_eq!(rc, 0, "shared futex handoff");
            }
        },
    );
}
#[test]
fn native_rwclock_providers_and_versions_are_exact() {
    isolated(
        "native_rwclock_providers_and_versions_are_exact",
        |native| {
            for got in [false, true] {
                let lib = Library::new(native, got);
                let lookup: unsafe extern "C" fn(c_int, *const c_char) -> *mut c_void =
                    unsafe { std::mem::transmute(lib.symbol(c"clock_pointer")) };
                let direct: unsafe extern "C" fn(c_int) -> *mut c_void =
                    unsafe { std::mem::transmute(lib.symbol(c"direct_pointer")) };
                for (write, name, implementation) in [
                    (
                        0,
                        c"pthread_rwlock_clockrdlock",
                        p::pthread_rwlock_clockrdlock as *const (),
                    ),
                    (
                        1,
                        c"pthread_rwlock_clockwrlock",
                        p::pthread_rwlock_clockwrlock as *const (),
                    ),
                ] {
                    let expected = if native {
                        implementation as *mut c_void
                    } else {
                        unsafe { dlsym_oracle::host_addr(name, implementation) }
                    };
                    assert_eq!(unsafe { direct(write) }, expected);
                    assert_eq!(unsafe { lookup(write, std::ptr::null()) }, expected);
                    for version in [c"GLIBC_2.30", c"GLIBC_2.34"] {
                        assert_eq!(unsafe { lookup(write, version.as_ptr()) }, expected);
                    }
                    for version in [c"GLIBC_2.2.5", c"GLIBC_PRIVATE", c"MISSING_VERSION"] {
                        assert!(unsafe { lookup(write, version.as_ptr()) }.is_null());
                    }
                }
            }
        },
    );
}
