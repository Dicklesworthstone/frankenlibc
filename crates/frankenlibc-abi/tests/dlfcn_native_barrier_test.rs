//! Real C barriers and spinlocks must stay in the native loader's pthread runtime.
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
#include <stdint.h>
#include <stdatomic.h>
#include <errno.h>
#include <dlfcn.h>
#include <unistd.h>
#include <sys/wait.h>
#define CHECK(c) do { if (!(c)) return __LINE__; } while (0)
#define N 6
#define ROUNDS 400
struct group {
    pthread_barrier_t barrier;
    pthread_spinlock_t lock;
    unsigned serials, sum;
    int slots[N];
};
static int phase(struct group *g) {
    int rc = pthread_barrier_wait(&g->barrier);
    CHECK(rc == 0 || rc == PTHREAD_BARRIER_SERIAL_THREAD);
    if (rc == PTHREAD_BARRIER_SERIAL_THREAD) {
        CHECK(!pthread_spin_lock(&g->lock));
        ++g->serials;
        CHECK(!pthread_spin_unlock(&g->lock));
    }
    return 0;
}
int attributes_and_errors(void) {
    pthread_barrierattr_t attr;
    pthread_barrier_t barrier;
    pthread_spinlock_t spin;
    int shared = -1;
    CHECK(!pthread_barrierattr_init(&attr));
    CHECK(!pthread_barrierattr_getpshared(&attr, &shared) && shared == PTHREAD_PROCESS_PRIVATE);
    CHECK(!pthread_barrierattr_setpshared(&attr, PTHREAD_PROCESS_SHARED));
    CHECK(!pthread_barrierattr_getpshared(&attr, &shared) && shared == PTHREAD_PROCESS_SHARED);
    CHECK(pthread_barrierattr_setpshared(&attr, -99) == EINVAL);
    CHECK(!pthread_barrierattr_getpshared(&attr, &shared) && shared == PTHREAD_PROCESS_SHARED);
    CHECK(pthread_barrier_init(&barrier, &attr, 0) == EINVAL);
    CHECK(!pthread_barrier_init(&barrier, &attr, 1));
    CHECK(!pthread_barrierattr_destroy(&attr));
    for (int round = 0; round < 100; ++round)
        CHECK(pthread_barrier_wait(&barrier) == PTHREAD_BARRIER_SERIAL_THREAD);
    CHECK(!pthread_barrier_destroy(&barrier));
    CHECK(!pthread_spin_init(&spin, PTHREAD_PROCESS_PRIVATE));
    CHECK(!pthread_spin_trylock(&spin));
    errno = EDOM;
    CHECK(pthread_spin_trylock(&spin) == EBUSY && errno == EDOM);
    CHECK(!pthread_spin_unlock(&spin));
    CHECK(!pthread_spin_lock(&spin));
    CHECK(!pthread_spin_unlock(&spin));
    CHECK(!pthread_spin_destroy(&spin));
    return 0;
}
struct task { struct group *g; int id, result; };
static void *worker(void *opaque) {
    struct task *t = opaque;
    struct group *g = t->g;
    for (int round = 1; round <= ROUNDS; ++round) {
        g->slots[t->id] = round;
        if (phase(g)) t->result = 1;
        for (int i = 0; i < N; ++i) if (g->slots[i] != round) t->result = 2;
        for (int i = 0; i < 32; ++i) {
            if (pthread_spin_lock(&g->lock)) t->result = 3;
            ++g->sum;
            if (pthread_spin_unlock(&g->lock)) t->result = 4;
        }
        if (phase(g)) t->result = 5;
    }
    return 0;
}
int threaded_phases_publish_memory(void) {
    struct group g = {0};
    pthread_t threads[N];
    struct task tasks[N];
    CHECK(!pthread_barrier_init(&g.barrier, 0, N));
    CHECK(!pthread_spin_init(&g.lock, PTHREAD_PROCESS_PRIVATE));
    for (int i = 0; i < N; ++i) {
        tasks[i] = (struct task){&g, i, 0};
        CHECK(!pthread_create(&threads[i], 0, worker, &tasks[i]));
    }
    for (int i = 0; i < N; ++i) {
        CHECK(!pthread_join(threads[i], 0));
        CHECK(!tasks[i].result);
    }
    CHECK(g.sum == N * ROUNDS * 32 && g.serials == 2 * ROUNDS);
    CHECK(!pthread_barrier_destroy(&g.barrier));
    CHECK(!pthread_spin_destroy(&g.lock));
    return 0;
}
struct cancellation { struct group g; _Atomic int ready, go, passed, cleaned; };
static void cleanup(void *opaque) {
    struct cancellation *c = opaque;
    atomic_fetch_add(&c->cleaned, 1);
}
static void *cancel_worker(void *opaque) {
    struct cancellation *c = opaque;
    pthread_cleanup_push(cleanup, c);
    atomic_store(&c->ready, 1);
    while (!atomic_load(&c->go)) atomic_signal_fence(memory_order_acq_rel);
    if (!phase(&c->g) && !pthread_spin_lock(&c->g.lock)) {
        atomic_store(&c->passed, 1);
        pthread_spin_unlock(&c->g.lock);
    }
    pthread_testcancel();
    pthread_cleanup_pop(0);
    return (void *)1;
}
int deferred_cancel_is_not_consumed_by_synchronization(void) {
    struct cancellation c = {0};
    CHECK(!pthread_barrier_init(&c.g.barrier, 0, 2));
    CHECK(!pthread_spin_init(&c.g.lock, PTHREAD_PROCESS_PRIVATE));
    pthread_t thread;
    CHECK(!pthread_create(&thread, 0, cancel_worker, &c));
    while (!atomic_load(&c.ready)) atomic_signal_fence(memory_order_acq_rel);
    CHECK(!pthread_cancel(thread));
    atomic_store(&c.go, 1);
    CHECK(!phase(&c.g));
    void *result = 0;
    CHECK(!pthread_join(thread, &result));
    CHECK(result == PTHREAD_CANCELED && atomic_load(&c.passed) == 1 && atomic_load(&c.cleaned) == 1);
    CHECK(!pthread_barrier_destroy(&c.g.barrier));
    CHECK(!pthread_spin_destroy(&c.g.lock));
    return 0;
}
/* Process creation and shared mapping belong to the driver, all synchronization to the DSO. */
int process_shared_phases(struct group *g, pid_t (*fork_process)(void), pid_t (*reap)(pid_t, int *, int)) {
    pthread_barrierattr_t attr;
    g->serials = g->sum = 0;
    CHECK(!pthread_barrierattr_init(&attr));
    CHECK(!pthread_barrierattr_setpshared(&attr, PTHREAD_PROCESS_SHARED));
    CHECK(!pthread_barrier_init(&g->barrier, &attr, 2));
    CHECK(!pthread_barrierattr_destroy(&attr));
    CHECK(!pthread_spin_init(&g->lock, PTHREAD_PROCESS_SHARED));
    pid_t child = fork_process();
    CHECK(child >= 0);
    int id = child ? 0 : 1;
    for (int round = 1; round <= 100; ++round) {
        g->slots[id] = round;
        int bad = phase(g);
        if (g->slots[1-id] != round) bad = 1;
        for (int i = 0; i < 64; ++i) {
            if (pthread_spin_lock(&g->lock)) bad = 2;
            ++g->sum;
            if (pthread_spin_unlock(&g->lock)) bad = 3;
        }
        if (phase(g)) bad = 4;
        if (bad && !child) _exit(20 + bad);
        CHECK(!bad);
    }
    if (!child) _exit(0);
    int status = 0;
    CHECK(reap(child, &status, 0) == child && WIFEXITED(status) && !WEXITSTATUS(status));
    CHECK(g->sum == 2 * 100 * 64 && g->serials == 2 * 100);
    CHECK(!pthread_barrier_destroy(&g->barrier));
    CHECK(!pthread_spin_destroy(&g->lock));
    return 0;
}
void *pointer(int which, const char *version) {
    const char *names[] = {"pthread_barrier_init", "pthread_barrier_destroy", "pthread_barrier_wait",
        "pthread_barrierattr_init", "pthread_barrierattr_destroy", "pthread_barrierattr_getpshared",
        "pthread_barrierattr_setpshared", "pthread_spin_init", "pthread_spin_destroy",
        "pthread_spin_lock", "pthread_spin_trylock", "pthread_spin_unlock"};
    if (version) return dlvsym(RTLD_DEFAULT, names[which], version);
    return dlsym(RTLD_DEFAULT, names[which]);
}
void *direct(int which) {
    void *functions[] = {(void *)pthread_barrier_init, (void *)pthread_barrier_destroy, (void *)pthread_barrier_wait,
        (void *)pthread_barrierattr_init, (void *)pthread_barrierattr_destroy, (void *)pthread_barrierattr_getpshared,
        (void *)pthread_barrierattr_setpshared, (void *)pthread_spin_init, (void *)pthread_spin_destroy,
        (void *)pthread_spin_lock, (void *)pthread_spin_trylock, (void *)pthread_spin_unlock};
    return functions[which];
}
"#;

fn exports() -> [(&'static CStr, *const ()); 12] {
    [
        (
            c"pthread_barrier_init",
            p::pthread_barrier_init as *const (),
        ),
        (
            c"pthread_barrier_destroy",
            p::pthread_barrier_destroy as *const (),
        ),
        (
            c"pthread_barrier_wait",
            p::pthread_barrier_wait as *const (),
        ),
        (
            c"pthread_barrierattr_init",
            p::pthread_barrierattr_init as *const (),
        ),
        (
            c"pthread_barrierattr_destroy",
            p::pthread_barrierattr_destroy as *const (),
        ),
        (
            c"pthread_barrierattr_getpshared",
            p::pthread_barrierattr_getpshared as *const (),
        ),
        (
            c"pthread_barrierattr_setpshared",
            p::pthread_barrierattr_setpshared as *const (),
        ),
        (c"pthread_spin_init", p::pthread_spin_init as *const ()),
        (
            c"pthread_spin_destroy",
            p::pthread_spin_destroy as *const (),
        ),
        (c"pthread_spin_lock", p::pthread_spin_lock as *const ()),
        (
            c"pthread_spin_trylock",
            p::pthread_spin_trylock as *const (),
        ),
        (c"pthread_spin_unlock", p::pthread_spin_unlock as *const ()),
    ]
}
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
        let dir = std::env::temp_dir().join(format!("fl-barrier-{}-{stamp}", std::process::id()));
        std::fs::create_dir(&dir).unwrap();
        let source = dir.join("barrier.c");
        let path = dir.join("barrier.so");
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
        if native {
            cc.arg("-nostdlib");
        } else {
            cc.arg("-pthread");
        }
        if got {
            cc.arg("-fno-plt");
        }
        let out = cc.arg(&source).arg("-o").arg(&path).output().unwrap();
        assert!(
            out.status.success(),
            "{}",
            String::from_utf8_lossy(&out.stderr)
        );
        let object = ElfLoader::new(0)
            .parse(&std::fs::read(&path).unwrap())
            .unwrap();
        if native {
            assert!(object.needed_libraries.is_empty());
        }
        for (name, _) in exports() {
            assert!(
                object
                    .undefined_symbols()
                    .any(|(_, s)| object.symbol_name(s) == name.to_str().ok()),
                "missing import {name:?}"
            );
        }
        let path = CString::new(path.as_os_str().as_encoded_bytes()).unwrap();
        // SAFETY: a terminated pathname and the exact dlopen ABI.
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
            "native={native}, got={got}: admission failed"
        );
        if native {
            assert!(dl::native_dso_handle_for_tests(handle), "host fallback");
        }
        Self { handle, native }
    }
    fn symbol(&self, name: &CStr) -> *mut c_void {
        // SAFETY: the handle and terminated symbol name remain live.
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
        // SAFETY: the protocols join every worker before releasing their DSO.
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
    if let Ok(backend) = std::env::var("FL_NATIVE_BARRIER_CHILD") {
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
            .env("FL_NATIVE_BARRIER_CHILD", backend)
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
                panic!("{name}/{backend}/{mode}: timed out");
            }
            std::thread::sleep(Duration::from_millis(10));
        }
    }
}
fn protocol(native: bool, name: &CStr) {
    for got in [false, true] {
        let lib = Library::new(native, got);
        // SAFETY: these generated protocols export int(void).
        let run: unsafe extern "C" fn() -> c_int = unsafe { std::mem::transmute(lib.symbol(name)) };
        assert_eq!(unsafe { run() }, 0, "C assertion line in {name:?}");
    }
}
#[test]
fn native_barrier_attributes_and_spinlock_errors() {
    isolated("native_barrier_attributes_and_spinlock_errors", |native| {
        protocol(native, c"attributes_and_errors")
    });
}
#[test]
fn native_barrier_threads_publish_memory_over_repeated_phases() {
    isolated(
        "native_barrier_threads_publish_memory_over_repeated_phases",
        |native| protocol(native, c"threaded_phases_publish_memory"),
    );
}
#[test]
fn native_barrier_and_spinlock_preserve_pending_deferred_cancellation() {
    isolated(
        "native_barrier_and_spinlock_preserve_pending_deferred_cancellation",
        |native| {
            protocol(
                native,
                c"deferred_cancel_is_not_consumed_by_synchronization",
            )
        },
    );
}
#[test]
fn native_barrier_and_spinlock_synchronize_across_processes() {
    isolated(
        "native_barrier_and_spinlock_synchronize_across_processes",
        |native| {
            type Fork = unsafe extern "C" fn() -> libc::pid_t;
            type Wait = unsafe extern "C" fn(libc::pid_t, *mut c_int, c_int) -> libc::pid_t;
            // SAFETY: process creation belongs to the driver, not the DSO import surface.
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
                let lib = Library::new(native, got);
                // SAFETY: the generated C function takes driver-owned shared storage and two exact callbacks.
                let run: unsafe extern "C" fn(*mut c_void, Fork, Wait) -> c_int =
                    unsafe { std::mem::transmute(lib.symbol(c"process_shared_phases")) };
                let shared = unsafe {
                    libc::mmap(
                        std::ptr::null_mut(),
                        4096,
                        libc::PROT_READ | libc::PROT_WRITE,
                        libc::MAP_SHARED | libc::MAP_ANONYMOUS,
                        -1,
                        0,
                    )
                };
                assert_ne!(shared, libc::MAP_FAILED);
                let result = unsafe { run(shared, fork, reap) };
                assert_eq!(unsafe { libc::munmap(shared, 4096) }, 0);
                assert_eq!(result, 0, "C assertion line in shared protocol");
            }
        },
    );
}
#[test]
fn native_barrier_provider_versions_match_direct_and_dynamic_calls() {
    isolated(
        "native_barrier_provider_versions_match_direct_and_dynamic_calls",
        |native| {
            for got in [false, true] {
                let lib = Library::new(native, got);
                // SAFETY: these function pointer types match the compiled pointer probes.
                let find: unsafe extern "C" fn(c_int, *const c_char) -> *mut c_void =
                    unsafe { std::mem::transmute(lib.symbol(c"pointer")) };
                let direct: unsafe extern "C" fn(c_int) -> *mut c_void =
                    unsafe { std::mem::transmute(lib.symbol(c"direct")) };
                for (index, (name, implementation)) in exports().into_iter().enumerate() {
                    let expected = if native {
                        implementation as *mut c_void
                    } else {
                        unsafe { dlsym_oracle::host_addr(name, implementation) }
                    };
                    let first = if index == 5 {
                        c"GLIBC_2.3.3"
                    } else {
                        c"GLIBC_2.2.5"
                    };
                    assert_eq!(unsafe { direct(index as c_int) }, expected, "{name:?}");
                    assert_eq!(
                        unsafe { find(index as c_int, std::ptr::null()) },
                        expected,
                        "{name:?}"
                    );
                    for version in [first, c"GLIBC_2.34"] {
                        assert_eq!(
                            unsafe { find(index as c_int, version.as_ptr()) },
                            expected,
                            "{name:?}/{version:?}"
                        );
                    }
                    for version in [c"GLIBC_PRIVATE", c"GLIBC_2.35", c"MISSING_VERSION"] {
                        assert!(
                            unsafe { find(index as c_int, version.as_ptr()) }.is_null(),
                            "{name:?}/{version:?}"
                        );
                    }
                    if index == 5 {
                        assert!(unsafe { find(index as c_int, c"GLIBC_2.2.5".as_ptr()) }.is_null());
                    }
                }
            }
        },
    );
}
