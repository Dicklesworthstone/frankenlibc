#![cfg(target_os = "linux")]

//! Integration tests for `<pthread.h>` ABI entrypoints.
//!
//! Covers: mutex (normal/recursive/errorcheck), condvar, rwlock, thread lifecycle,
//! thread-specific data, once, spinlock, barrier, attributes, cancel, naming.

use std::ffi::{CStr, CString, c_int, c_void};
use std::ptr;
use std::sync::atomic::{AtomicI32, AtomicU32, AtomicUsize, Ordering};

use frankenlibc_abi::pthread_abi::*;
use frankenlibc_abi::signal_abi::pthread_sigmask;

// POSIX cancel constants (not always exported by the libc crate)
const PTHREAD_CANCEL_ENABLE: c_int = 0;
const PTHREAD_CANCEL_DISABLE: c_int = 1;
const PTHREAD_CANCEL_DEFERRED: c_int = 0;
const PTHREAD_CANCEL_ASYNCHRONOUS: c_int = 1;
const PTHREAD_SCOPE_SYSTEM: c_int = 0;
#[allow(dead_code)] // used via libc:: in inheritsched test; kept for reference
const PTHREAD_INHERIT_SCHED: c_int = 0;
const PTHREAD_EXPLICIT_SCHED: c_int = 1;

// ===========================================================================
// Thread lifecycle: create, join, detach, self, equal
// ===========================================================================

unsafe extern "C" fn add_ten(arg: *mut c_void) -> *mut c_void {
    let val = arg as usize;
    (val + 10) as *mut c_void
}

unsafe extern "C" fn tryjoin_self_result(_arg: *mut c_void) -> *mut c_void {
    let self_id = unsafe { pthread_self() };
    unsafe { pthread_tryjoin_np(self_id, ptr::null_mut()) as usize as *mut c_void }
}

unsafe extern "C" fn timedjoin_self_result(_arg: *mut c_void) -> *mut c_void {
    let self_id = unsafe { pthread_self() };
    let mut ts: libc::timespec = unsafe { std::mem::zeroed() };
    unsafe { libc::clock_gettime(libc::CLOCK_REALTIME, &mut ts) };
    ts.tv_sec += 1;
    unsafe { pthread_timedjoin_np(self_id, ptr::null_mut(), &ts) as usize as *mut c_void }
}

unsafe extern "C" fn sleepy_thread(_arg: *mut c_void) -> *mut c_void {
    std::thread::sleep(std::time::Duration::from_millis(200));
    ptr::null_mut()
}

unsafe extern "C" fn explicit_pthread_exit(arg: *mut c_void) -> *mut c_void {
    unsafe { pthread_exit(arg) }
}

struct ExitDestructorCtx {
    key: libc::pthread_key_t,
    ran: AtomicI32,
}

unsafe extern "C" fn exit_destructor(arg: *mut c_void) {
    let ctx = unsafe { &*(arg as *const ExitDestructorCtx) };
    ctx.ran.fetch_add(1, Ordering::SeqCst);
}

unsafe extern "C" fn managed_exit_with_tls_destructor(arg: *mut c_void) -> *mut c_void {
    let ctx = unsafe { &*(arg as *const ExitDestructorCtx) };
    assert_eq!(unsafe { pthread_setspecific(ctx.key, arg) }, 0);
    unsafe { pthread_exit(0x55usize as *mut c_void) }
}

unsafe extern "C" fn getattr_self_stacksize(_arg: *mut c_void) -> *mut c_void {
    let self_id = unsafe { pthread_self() };
    let mut attr: libc::pthread_attr_t = unsafe { std::mem::zeroed() };
    let rc = unsafe { pthread_getattr_np(self_id, &mut attr) };
    if rc != 0 {
        return rc as usize as *mut c_void;
    }
    let mut stack_size = 0usize;
    let get_rc = unsafe { pthread_attr_getstacksize(&attr, &mut stack_size) };
    let _ = unsafe { pthread_attr_destroy(&mut attr) };
    if get_rc != 0 {
        return get_rc as usize as *mut c_void;
    }
    stack_size as *mut c_void
}

struct ThreadingForceNativeGuard {
    previous: bool,
}

impl Drop for ThreadingForceNativeGuard {
    fn drop(&mut self) {
        pthread_threading_restore_for_tests(self.previous);
    }
}

struct MutexForceNativeGuard {
    previous: bool,
}

impl Drop for MutexForceNativeGuard {
    fn drop(&mut self) {
        pthread_mutex_restore_for_tests(self.previous);
    }
}

fn first_allowed_cpu() -> usize {
    unsafe {
        let mut cpuset: libc::cpu_set_t = std::mem::zeroed();
        let rc = libc::sched_getaffinity(
            0,
            std::mem::size_of::<libc::cpu_set_t>(),
            (&mut cpuset as *mut libc::cpu_set_t).cast(),
        );
        assert_eq!(
            rc, 0,
            "sched_getaffinity should succeed for the test process"
        );
        for cpu in 0..libc::CPU_SETSIZE as usize {
            if libc::CPU_ISSET(cpu, &cpuset) {
                return cpu;
            }
        }
    }
    unreachable!("test process affinity mask should contain at least one CPU");
}

#[test]
fn thread_create_join() {
    unsafe {
        let mut thr: libc::pthread_t = 0;
        let rc = pthread_create(&mut thr, ptr::null(), Some(add_ten), 42usize as *mut c_void);
        assert_eq!(rc, 0, "pthread_create should succeed");

        let mut retval: *mut c_void = ptr::null_mut();
        let rc = pthread_join(thr, &mut retval);
        assert_eq!(rc, 0, "pthread_join should succeed");
        assert_eq!(retval as usize, 52, "thread should return 42+10");
    }
}

unsafe extern "C" fn noop_thread(_arg: *mut c_void) -> *mut c_void {
    ptr::null_mut()
}

#[test]
fn thread_detach() {
    unsafe {
        let mut thr: libc::pthread_t = 0;
        let rc = pthread_create(&mut thr, ptr::null(), Some(noop_thread), ptr::null_mut());
        assert_eq!(rc, 0);
        let rc = pthread_detach(thr);
        assert_eq!(rc, 0, "pthread_detach should succeed");
        // Don't join a detached thread — just let it finish.
        std::thread::sleep(std::time::Duration::from_millis(50));
    }
}

#[test]
fn thread_join_managed_thread_after_restoring_host_mode() {
    unsafe {
        let thr: libc::pthread_t;
        {
            let _guard = ThreadingForceNativeGuard {
                previous: pthread_threading_swap_force_native_for_tests(),
            };
            let mut created: libc::pthread_t = 0;
            assert_eq!(
                pthread_create(
                    &mut created,
                    ptr::null(),
                    Some(add_ten),
                    9usize as *mut c_void
                ),
                0
            );
            thr = created;
        }

        let mut retval: *mut c_void = ptr::null_mut();
        assert_eq!(pthread_join(thr, &mut retval), 0);
        assert_eq!(retval as usize, 19);
    }
}

#[test]
fn thread_detach_managed_thread_after_restoring_host_mode() {
    unsafe {
        let thr: libc::pthread_t;
        {
            let _guard = ThreadingForceNativeGuard {
                previous: pthread_threading_swap_force_native_for_tests(),
            };
            let mut created: libc::pthread_t = 0;
            assert_eq!(
                pthread_create(
                    &mut created,
                    ptr::null(),
                    Some(sleepy_thread),
                    ptr::null_mut()
                ),
                0
            );
            thr = created;
        }

        assert_eq!(pthread_detach(thr), 0);
        std::thread::sleep(std::time::Duration::from_millis(250));
    }
}

#[test]
fn detach_on_detached_managed_thread_after_restoring_host_mode_returns_esrch() {
    unsafe {
        let thr: libc::pthread_t;
        {
            let _guard = ThreadingForceNativeGuard {
                previous: pthread_threading_swap_force_native_for_tests(),
            };
            let mut created: libc::pthread_t = 0;
            assert_eq!(
                pthread_create(
                    &mut created,
                    ptr::null(),
                    Some(sleepy_thread),
                    ptr::null_mut()
                ),
                0
            );
            thr = created;
        }

        // After a successful pthread_detach, the managed handle has been
        // consumed: it is removed from THREAD_HANDLE_REGISTRY and a tombstone
        // recorded. A second detach therefore refers to no live thread, so
        // ESRCH is the consistent answer used project-wide for consumed
        // handles (matching pthread_thread_lifecycle_test::pthread_detach_twice_is_esrch).
        // POSIX leaves double-detach undefined, so this is permissible.
        assert_eq!(pthread_detach(thr), 0);
        assert_eq!(pthread_detach(thr), libc::ESRCH);
        std::thread::sleep(std::time::Duration::from_millis(250));
    }
}

#[test]
fn join_on_detached_managed_thread_after_restoring_host_mode_returns_esrch() {
    unsafe {
        let thr: libc::pthread_t;
        {
            let _guard = ThreadingForceNativeGuard {
                previous: pthread_threading_swap_force_native_for_tests(),
            };
            let mut created: libc::pthread_t = 0;
            assert_eq!(
                pthread_create(
                    &mut created,
                    ptr::null(),
                    Some(sleepy_thread),
                    ptr::null_mut()
                ),
                0
            );
            thr = created;
        }

        // pthread_join on a consumed (detached) handle returns ESRCH for the
        // same reason as the double-detach case above. See
        // pthread_thread_lifecycle_test::pthread_detach_makes_subsequent_join_fail_with_esrch.
        assert_eq!(pthread_detach(thr), 0);
        assert_eq!(pthread_join(thr, ptr::null_mut()), libc::ESRCH);
        std::thread::sleep(std::time::Duration::from_millis(250));
    }
}

#[test]
fn thread_host_backed_pthread_exit_preserves_join_value() {
    unsafe {
        let mut thr: libc::pthread_t = 0;
        assert_eq!(
            pthread_create(
                &mut thr,
                ptr::null(),
                Some(explicit_pthread_exit),
                0x31usize as *mut c_void
            ),
            0
        );

        let mut retval: *mut c_void = ptr::null_mut();
        assert_eq!(pthread_join(thr, &mut retval), 0);
        assert_eq!(retval as usize, 0x31);
    }
}

#[test]
fn thread_managed_pthread_exit_runs_tls_destructors() {
    unsafe {
        let _guard = ThreadingForceNativeGuard {
            previous: pthread_threading_swap_force_native_for_tests(),
        };
        let mut ctx = Box::new(ExitDestructorCtx {
            key: 0,
            ran: AtomicI32::new(0),
        });
        assert_eq!(pthread_key_create(&mut ctx.key, Some(exit_destructor)), 0);

        let mut thr: libc::pthread_t = 0;
        assert_eq!(
            pthread_create(
                &mut thr,
                ptr::null(),
                Some(managed_exit_with_tls_destructor),
                (&mut *ctx as *mut ExitDestructorCtx).cast::<c_void>(),
            ),
            0
        );

        let mut retval: *mut c_void = ptr::null_mut();
        assert_eq!(pthread_join(thr, &mut retval), 0);
        assert_eq!(retval as usize, 0x55);
        assert_eq!(ctx.ran.load(Ordering::SeqCst), 1);
        assert_eq!(pthread_key_delete(ctx.key), 0);
    }
}

#[test]
fn detached_managed_pthread_exit_runs_tls_destructors() {
    unsafe {
        let _guard = ThreadingForceNativeGuard {
            previous: pthread_threading_swap_force_native_for_tests(),
        };
        let mut ctx = Box::new(ExitDestructorCtx {
            key: 0,
            ran: AtomicI32::new(0),
        });
        assert_eq!(pthread_key_create(&mut ctx.key, Some(exit_destructor)), 0);

        let mut thr: libc::pthread_t = 0;
        assert_eq!(
            pthread_create(
                &mut thr,
                ptr::null(),
                Some(managed_exit_with_tls_destructor),
                (&mut *ctx as *mut ExitDestructorCtx).cast::<c_void>(),
            ),
            0
        );
        assert_eq!(pthread_detach(thr), 0);

        for _ in 0..200 {
            if ctx.ran.load(Ordering::SeqCst) == 1 {
                break;
            }
            std::thread::sleep(std::time::Duration::from_millis(5));
        }

        assert_eq!(ctx.ran.load(Ordering::SeqCst), 1);
        let mut exited = false;
        for _ in 0..200 {
            if pthread_kill(thr, 0) == libc::ESRCH {
                exited = true;
                break;
            }
            std::thread::sleep(std::time::Duration::from_millis(5));
        }
        assert!(
            exited,
            "detached thread should become ESRCH after explicit exit"
        );
        assert_eq!(pthread_key_delete(ctx.key), 0);
    }
}

#[test]
fn thread_self_nonzero() {
    let self_id = unsafe { pthread_self() };
    assert_ne!(self_id, 0, "pthread_self should return non-zero");
}

#[test]
fn thread_equal_same() {
    let self_id = unsafe { pthread_self() };
    let rc = unsafe { pthread_equal(self_id, self_id) };
    assert_ne!(rc, 0, "pthread_equal(self, self) should be nonzero");
}

#[test]
fn thread_equal_different() {
    unsafe {
        let main_id = pthread_self();
        let mut thr: libc::pthread_t = 0;
        let rc = pthread_create(&mut thr, ptr::null(), Some(noop_thread), ptr::null_mut());
        assert_eq!(rc, 0);
        let eq = pthread_equal(main_id, thr);
        assert_eq!(eq, 0, "main thread and child should not be equal");
        pthread_join(thr, ptr::null_mut());
    }
}

// ===========================================================================
// Mutex: init, lock, trylock, unlock, destroy (NORMAL)
// ===========================================================================

#[test]
fn mutex_init_destroy() {
    unsafe {
        let mut mutex: libc::pthread_mutex_t = std::mem::zeroed();
        let rc = pthread_mutex_init(&mut mutex, ptr::null());
        assert_eq!(rc, 0);
        let rc = pthread_mutex_destroy(&mut mutex);
        assert_eq!(rc, 0);
    }
}

#[test]
fn mutex_null_returns_einval() {
    unsafe {
        let null_mutex = ptr::null_mut::<libc::pthread_mutex_t>();
        assert_eq!(pthread_mutex_init(null_mutex, ptr::null()), libc::EINVAL);
        assert_eq!(pthread_mutex_lock(null_mutex), libc::EINVAL);
        assert_eq!(pthread_mutex_trylock(null_mutex), libc::EINVAL);
        assert_eq!(pthread_mutex_unlock(null_mutex), libc::EINVAL);
        assert_eq!(pthread_mutex_destroy(null_mutex), libc::EINVAL);
    }
}

#[test]
fn mutex_lock_unlock() {
    unsafe {
        let mut mutex: libc::pthread_mutex_t = std::mem::zeroed();
        pthread_mutex_init(&mut mutex, ptr::null());
        let rc = pthread_mutex_lock(&mut mutex);
        assert_eq!(rc, 0);
        let rc = pthread_mutex_unlock(&mut mutex);
        assert_eq!(rc, 0);
        pthread_mutex_destroy(&mut mutex);
    }
}

#[test]
fn mutex_trylock_succeeds_when_unlocked() {
    unsafe {
        let mut mutex: libc::pthread_mutex_t = std::mem::zeroed();
        pthread_mutex_init(&mut mutex, ptr::null());
        let rc = pthread_mutex_trylock(&mut mutex);
        assert_eq!(rc, 0, "trylock on unlocked mutex should succeed");
        pthread_mutex_unlock(&mut mutex);
        pthread_mutex_destroy(&mut mutex);
    }
}

#[test]
fn mutex_trylock_fails_when_locked() {
    unsafe {
        let mut mutex: libc::pthread_mutex_t = std::mem::zeroed();
        pthread_mutex_init(&mut mutex, ptr::null());
        pthread_mutex_lock(&mut mutex);
        let rc = pthread_mutex_trylock(&mut mutex);
        assert_eq!(
            rc,
            libc::EBUSY,
            "trylock on locked mutex should return EBUSY"
        );
        pthread_mutex_unlock(&mut mutex);
        pthread_mutex_destroy(&mut mutex);
    }
}

// ===========================================================================
// Mutex: recursive type
// ===========================================================================

#[test]
fn mutex_recursive_multiple_locks() {
    unsafe {
        let mut attr: libc::pthread_mutexattr_t = std::mem::zeroed();
        pthread_mutexattr_init(&mut attr);
        pthread_mutexattr_settype(&mut attr, libc::PTHREAD_MUTEX_RECURSIVE);

        let mut mutex: libc::pthread_mutex_t = std::mem::zeroed();
        pthread_mutex_init(&mut mutex, &attr);
        pthread_mutexattr_destroy(&mut attr);

        // Lock three times
        assert_eq!(pthread_mutex_lock(&mut mutex), 0);
        assert_eq!(pthread_mutex_lock(&mut mutex), 0);
        assert_eq!(pthread_mutex_lock(&mut mutex), 0);

        // Unlock three times
        assert_eq!(pthread_mutex_unlock(&mut mutex), 0);
        assert_eq!(pthread_mutex_unlock(&mut mutex), 0);
        assert_eq!(pthread_mutex_unlock(&mut mutex), 0);

        pthread_mutex_destroy(&mut mutex);
    }
}

// ===========================================================================
// Mutex: errorcheck type
// ===========================================================================

#[test]
fn mutex_errorcheck_double_lock_returns_edeadlk() {
    unsafe {
        let mut attr: libc::pthread_mutexattr_t = std::mem::zeroed();
        pthread_mutexattr_init(&mut attr);
        pthread_mutexattr_settype(&mut attr, libc::PTHREAD_MUTEX_ERRORCHECK);

        let mut mutex: libc::pthread_mutex_t = std::mem::zeroed();
        pthread_mutex_init(&mut mutex, &attr);
        pthread_mutexattr_destroy(&mut attr);

        assert_eq!(pthread_mutex_lock(&mut mutex), 0);
        let rc = pthread_mutex_lock(&mut mutex);
        assert_eq!(
            rc,
            libc::EDEADLK,
            "errorcheck double lock should return EDEADLK"
        );
        assert_eq!(pthread_mutex_unlock(&mut mutex), 0);

        pthread_mutex_destroy(&mut mutex);
    }
}

#[test]
fn mutex_errorcheck_unlock_without_lock_returns_eperm() {
    unsafe {
        let mut attr: libc::pthread_mutexattr_t = std::mem::zeroed();
        pthread_mutexattr_init(&mut attr);
        pthread_mutexattr_settype(&mut attr, libc::PTHREAD_MUTEX_ERRORCHECK);

        let mut mutex: libc::pthread_mutex_t = std::mem::zeroed();
        pthread_mutex_init(&mut mutex, &attr);
        pthread_mutexattr_destroy(&mut attr);

        let rc = pthread_mutex_unlock(&mut mutex);
        assert_eq!(
            rc,
            libc::EPERM,
            "errorcheck unlock without lock should return EPERM"
        );

        pthread_mutex_destroy(&mut mutex);
    }
}

// ===========================================================================
// Mutex attributes
// ===========================================================================

#[test]
fn mutexattr_init_destroy() {
    unsafe {
        let mut attr: libc::pthread_mutexattr_t = std::mem::zeroed();
        assert_eq!(pthread_mutexattr_init(&mut attr), 0);
        assert_eq!(pthread_mutexattr_destroy(&mut attr), 0);
    }
}

#[test]
fn mutexattr_settype_gettype() {
    unsafe {
        let mut attr: libc::pthread_mutexattr_t = std::mem::zeroed();
        pthread_mutexattr_init(&mut attr);

        assert_eq!(
            pthread_mutexattr_settype(&mut attr, libc::PTHREAD_MUTEX_RECURSIVE),
            0
        );
        let mut kind: c_int = 0;
        assert_eq!(pthread_mutexattr_gettype(&attr, &mut kind), 0);
        assert_eq!(kind, libc::PTHREAD_MUTEX_RECURSIVE);

        pthread_mutexattr_destroy(&mut attr);
    }
}

#[test]
fn mutexattr_getpshared() {
    unsafe {
        let mut attr: libc::pthread_mutexattr_t = std::mem::zeroed();
        pthread_mutexattr_init(&mut attr);

        let mut pshared: c_int = -1;
        assert_eq!(pthread_mutexattr_getpshared(&attr, &mut pshared), 0);
        assert_eq!(pshared, libc::PTHREAD_PROCESS_PRIVATE);

        pthread_mutexattr_destroy(&mut attr);
    }
}

#[test]
fn mutexattr_getrobust() {
    unsafe {
        let mut attr: libc::pthread_mutexattr_t = std::mem::zeroed();
        pthread_mutexattr_init(&mut attr);

        let mut robust: c_int = -1;
        assert_eq!(pthread_mutexattr_getrobust(&attr, &mut robust), 0);
        assert_eq!(robust, libc::PTHREAD_MUTEX_STALLED);

        pthread_mutexattr_destroy(&mut attr);
    }
}

// ===========================================================================
// Condvar: init, signal, broadcast, destroy
// ===========================================================================

#[test]
fn condvar_init_destroy() {
    unsafe {
        let mut cond: libc::pthread_cond_t = std::mem::zeroed();
        assert_eq!(pthread_cond_init(&mut cond, ptr::null()), 0);
        assert_eq!(pthread_cond_destroy(&mut cond), 0);
    }
}

#[test]
fn condvar_null_returns_einval() {
    unsafe {
        let null_cond = ptr::null_mut::<libc::pthread_cond_t>();
        let null_mutex = ptr::null_mut::<libc::pthread_mutex_t>();
        assert_eq!(pthread_cond_init(null_cond, ptr::null()), libc::EINVAL);
        assert_eq!(pthread_cond_destroy(null_cond), libc::EINVAL);
        assert_eq!(pthread_cond_signal(null_cond), libc::EINVAL);
        assert_eq!(pthread_cond_broadcast(null_cond), libc::EINVAL);
        assert_eq!(pthread_cond_wait(null_cond, null_mutex), libc::EINVAL);
    }
}

#[test]
fn condvar_signal_no_waiters() {
    unsafe {
        let mut cond: libc::pthread_cond_t = std::mem::zeroed();
        pthread_cond_init(&mut cond, ptr::null());
        assert_eq!(pthread_cond_signal(&mut cond), 0);
        pthread_cond_destroy(&mut cond);
    }
}

#[test]
fn condvar_broadcast_no_waiters() {
    unsafe {
        let mut cond: libc::pthread_cond_t = std::mem::zeroed();
        pthread_cond_init(&mut cond, ptr::null());
        assert_eq!(pthread_cond_broadcast(&mut cond), 0);
        pthread_cond_destroy(&mut cond);
    }
}

// ===========================================================================
// Condvar attributes
// ===========================================================================

#[test]
fn condattr_init_destroy() {
    unsafe {
        let mut attr: libc::pthread_condattr_t = std::mem::zeroed();
        assert_eq!(pthread_condattr_init(&mut attr), 0);
        assert_eq!(pthread_condattr_destroy(&mut attr), 0);
    }
}

#[test]
fn condattr_setclock_getclock() {
    unsafe {
        let mut attr: libc::pthread_condattr_t = std::mem::zeroed();
        pthread_condattr_init(&mut attr);

        assert_eq!(
            pthread_condattr_setclock(&mut attr, libc::CLOCK_MONOTONIC),
            0
        );
        let mut clock_id: libc::clockid_t = 0;
        assert_eq!(pthread_condattr_getclock(&attr, &mut clock_id), 0);
        assert_eq!(clock_id, libc::CLOCK_MONOTONIC);

        pthread_condattr_destroy(&mut attr);
    }
}

#[test]
fn condattr_getpshared() {
    unsafe {
        let mut attr: libc::pthread_condattr_t = std::mem::zeroed();
        pthread_condattr_init(&mut attr);

        let mut pshared: c_int = -1;
        let rc = pthread_condattr_getpshared(&attr, &mut pshared);
        assert_eq!(rc, 0);
        assert_eq!(pshared, libc::PTHREAD_PROCESS_PRIVATE);

        pthread_condattr_destroy(&mut attr);
    }
}

// ===========================================================================
// Condvar: wait + signal (multi-threaded)
// ===========================================================================

struct SharedCondState {
    mutex: libc::pthread_mutex_t,
    cond: libc::pthread_cond_t,
    ready: AtomicI32,
}

#[repr(C)]
struct TimedMutexCtx {
    mutex: *mut libc::pthread_mutex_t,
    ready: AtomicI32,
}

unsafe extern "C" fn condvar_waiter(arg: *mut c_void) -> *mut c_void {
    unsafe {
        let state = &*(arg as *const SharedCondState);
        pthread_mutex_lock(&state.mutex as *const _ as *mut _);
        while state.ready.load(Ordering::Acquire) == 0 {
            pthread_cond_wait(
                &state.cond as *const _ as *mut _,
                &state.mutex as *const _ as *mut _,
            );
        }
        pthread_mutex_unlock(&state.mutex as *const _ as *mut _);
        ptr::null_mut()
    }
}

unsafe extern "C" fn delayed_condvar_signal(arg: *mut c_void) -> *mut c_void {
    let state = unsafe { &*(arg as *const SharedCondState) };
    std::thread::sleep(std::time::Duration::from_millis(150));
    unsafe {
        pthread_mutex_lock(&state.mutex as *const _ as *mut _);
        pthread_cond_signal(&state.cond as *const _ as *mut _);
        pthread_mutex_unlock(&state.mutex as *const _ as *mut _);
    }
    ptr::null_mut()
}

fn absolute_deadline_after(clock_id: libc::clockid_t, millis: i64) -> libc::timespec {
    unsafe {
        let mut ts: libc::timespec = std::mem::zeroed();
        assert_eq!(
            libc::clock_gettime(clock_id, &mut ts),
            0,
            "clock_gettime({clock_id}) should succeed"
        );
        ts.tv_sec += millis / 1000;
        ts.tv_nsec += (millis % 1000) * 1_000_000;
        if ts.tv_nsec >= 1_000_000_000 {
            ts.tv_sec += 1;
            ts.tv_nsec -= 1_000_000_000;
        } else if ts.tv_nsec < 0 {
            ts.tv_sec -= 1;
            ts.tv_nsec += 1_000_000_000;
        }
        ts
    }
}

unsafe extern "C" fn hold_mutex_briefly(arg: *mut c_void) -> *mut c_void {
    let ctx = unsafe { &*(arg as *const TimedMutexCtx) };
    unsafe {
        pthread_mutex_lock(ctx.mutex);
    }
    ctx.ready.store(1, Ordering::Release);
    std::thread::sleep(std::time::Duration::from_millis(200));
    unsafe {
        pthread_mutex_unlock(ctx.mutex);
    }
    ptr::null_mut()
}

#[test]
fn condvar_wait_signal_wakeup() {
    unsafe {
        let state = Box::new(SharedCondState {
            mutex: std::mem::zeroed(),
            cond: std::mem::zeroed(),
            ready: AtomicI32::new(0),
        });
        pthread_mutex_init(&state.mutex as *const _ as *mut _, ptr::null());
        pthread_cond_init(&state.cond as *const _ as *mut _, ptr::null());

        let state_ptr = &*state as *const SharedCondState as *mut c_void;
        let mut thr: libc::pthread_t = 0;
        pthread_create(&mut thr, ptr::null(), Some(condvar_waiter), state_ptr);

        std::thread::sleep(std::time::Duration::from_millis(30));

        pthread_mutex_lock(&state.mutex as *const _ as *mut _);
        state.ready.store(1, Ordering::Release);
        pthread_cond_signal(&state.cond as *const _ as *mut _);
        pthread_mutex_unlock(&state.mutex as *const _ as *mut _);

        pthread_join(thr, ptr::null_mut());

        pthread_cond_destroy(&state.cond as *const _ as *mut _);
        pthread_mutex_destroy(&state.mutex as *const _ as *mut _);
    }
}

#[test]
fn condvar_native_attr_stays_on_native_path_for_lifecycle_and_waits() {
    unsafe {
        let mut mutex_attr: libc::pthread_mutexattr_t = std::mem::zeroed();
        assert_eq!(pthread_mutexattr_init(&mut mutex_attr), 0);
        let mut attr: libc::pthread_condattr_t = std::mem::zeroed();
        assert_eq!(pthread_condattr_init(&mut attr), 0);
        assert_eq!(
            pthread_condattr_setclock(&mut attr, libc::CLOCK_MONOTONIC),
            0
        );

        let state = Box::new(SharedCondState {
            mutex: std::mem::zeroed(),
            cond: std::mem::zeroed(),
            ready: AtomicI32::new(0),
        });
        assert_eq!(
            pthread_mutex_init(&state.mutex as *const _ as *mut _, &mutex_attr),
            0
        );
        assert_eq!(
            pthread_cond_init(&state.cond as *const _ as *mut _, &attr),
            0
        );
        assert_eq!(pthread_mutexattr_destroy(&mut mutex_attr), 0);
        assert_eq!(pthread_condattr_destroy(&mut attr), 0);

        let state_ptr = &*state as *const SharedCondState as *mut c_void;
        let mut thr: libc::pthread_t = 0;
        assert_eq!(
            pthread_create(&mut thr, ptr::null(), Some(condvar_waiter), state_ptr),
            0
        );

        std::thread::sleep(std::time::Duration::from_millis(30));

        assert_eq!(pthread_mutex_lock(&state.mutex as *const _ as *mut _), 0);
        state.ready.store(1, Ordering::Release);
        assert_eq!(pthread_cond_signal(&state.cond as *const _ as *mut _), 0);
        assert_eq!(pthread_mutex_unlock(&state.mutex as *const _ as *mut _), 0);

        assert_eq!(pthread_join(thr, ptr::null_mut()), 0);
        assert_eq!(pthread_cond_broadcast(&state.cond as *const _ as *mut _), 0);
        assert_eq!(pthread_cond_destroy(&state.cond as *const _ as *mut _), 0);
        assert_eq!(pthread_mutex_destroy(&state.mutex as *const _ as *mut _), 0);
    }
}

#[test]
fn native_condvar_wait_rejects_host_mutex_mismatch() {
    unsafe {
        let _guard = MutexForceNativeGuard {
            previous: pthread_mutex_swap_force_native_for_tests(),
        };
        let mut attr: libc::pthread_condattr_t = std::mem::zeroed();
        assert_eq!(pthread_condattr_init(&mut attr), 0);
        assert_eq!(
            pthread_condattr_setclock(&mut attr, libc::CLOCK_MONOTONIC),
            0
        );

        let mut cond: libc::pthread_cond_t = std::mem::zeroed();
        let mut mutex: libc::pthread_mutex_t = std::mem::zeroed();
        assert_eq!(pthread_cond_init(&mut cond, &attr), 0);
        assert_eq!(pthread_condattr_destroy(&mut attr), 0);
        assert_eq!(libc::pthread_mutex_init(&mut mutex, ptr::null()), 0);
        assert_eq!(libc::pthread_mutex_lock(&mut mutex), 0);

        assert_eq!(pthread_cond_wait(&mut cond, &mut mutex), libc::EINVAL);

        assert_eq!(libc::pthread_mutex_unlock(&mut mutex), 0);
        assert_eq!(libc::pthread_mutex_destroy(&mut mutex), 0);
        assert_eq!(pthread_cond_destroy(&mut cond), 0);
    }
}

#[test]
fn cond_clockwait_realtime_deadline_on_monotonic_condvar_times_out_before_signal() {
    unsafe {
        let mut mutex_attr: libc::pthread_mutexattr_t = std::mem::zeroed();
        assert_eq!(pthread_mutexattr_init(&mut mutex_attr), 0);
        let mut cond_attr: libc::pthread_condattr_t = std::mem::zeroed();
        assert_eq!(pthread_condattr_init(&mut cond_attr), 0);
        assert_eq!(
            pthread_condattr_setclock(&mut cond_attr, libc::CLOCK_MONOTONIC),
            0
        );

        let state = Box::new(SharedCondState {
            mutex: std::mem::zeroed(),
            cond: std::mem::zeroed(),
            ready: AtomicI32::new(0),
        });
        assert_eq!(
            pthread_mutex_init(&state.mutex as *const _ as *mut _, &mutex_attr),
            0
        );
        assert_eq!(
            pthread_cond_init(&state.cond as *const _ as *mut _, &cond_attr),
            0
        );
        assert_eq!(pthread_mutexattr_destroy(&mut mutex_attr), 0);
        assert_eq!(pthread_condattr_destroy(&mut cond_attr), 0);

        let state_ptr = &*state as *const SharedCondState as *mut c_void;
        let mut signaler: libc::pthread_t = 0;
        assert_eq!(
            pthread_create(
                &mut signaler,
                ptr::null(),
                Some(delayed_condvar_signal),
                state_ptr
            ),
            0
        );

        assert_eq!(pthread_mutex_lock(&state.mutex as *const _ as *mut _), 0);
        let mut deadline: libc::timespec = std::mem::zeroed();
        libc::clock_gettime(libc::CLOCK_REALTIME, &mut deadline);
        deadline.tv_nsec += 50_000_000;
        if deadline.tv_nsec >= 1_000_000_000 {
            deadline.tv_sec += 1;
            deadline.tv_nsec -= 1_000_000_000;
        }
        let rc = pthread_cond_clockwait(
            &state.cond as *const _ as *mut _,
            &state.mutex as *const _ as *mut _,
            libc::CLOCK_REALTIME,
            &deadline,
        );
        assert_eq!(
            rc,
            libc::ETIMEDOUT,
            "clockwait should honor the requested realtime deadline even on a monotonic condvar"
        );
        assert_eq!(pthread_mutex_unlock(&state.mutex as *const _ as *mut _), 0);

        assert_eq!(pthread_join(signaler, ptr::null_mut()), 0);
        assert_eq!(pthread_cond_destroy(&state.cond as *const _ as *mut _), 0);
        assert_eq!(pthread_mutex_destroy(&state.mutex as *const _ as *mut _), 0);
    }
}

#[test]
fn cond_clockwait_realtime_immediate_timeout_on_managed_condvar() {
    unsafe {
        let mut mutex: libc::pthread_mutex_t = std::mem::zeroed();
        let mut cond: libc::pthread_cond_t = std::mem::zeroed();
        assert_eq!(pthread_mutex_init(&mut mutex, ptr::null()), 0);
        assert_eq!(pthread_cond_init(&mut cond, ptr::null()), 0);
        assert_eq!(pthread_mutex_lock(&mut mutex), 0);

        let deadline = absolute_deadline_after(libc::CLOCK_REALTIME, -1);
        assert_eq!(
            pthread_cond_clockwait(&mut cond, &mut mutex, libc::CLOCK_REALTIME, &deadline),
            libc::ETIMEDOUT
        );

        assert_eq!(pthread_mutex_unlock(&mut mutex), 0);
        assert_eq!(pthread_cond_destroy(&mut cond), 0);
        assert_eq!(pthread_mutex_destroy(&mut mutex), 0);
    }
}

#[test]
fn cond_clockwait_realtime_future_signal_returns_zero_on_managed_condvar() {
    unsafe {
        let state = Box::new(SharedCondState {
            mutex: std::mem::zeroed(),
            cond: std::mem::zeroed(),
            ready: AtomicI32::new(0),
        });
        assert_eq!(
            pthread_mutex_init(&state.mutex as *const _ as *mut _, ptr::null()),
            0
        );
        assert_eq!(
            pthread_cond_init(&state.cond as *const _ as *mut _, ptr::null()),
            0
        );

        let state_ptr = &*state as *const SharedCondState as *mut c_void;
        let mut signaler: libc::pthread_t = 0;
        assert_eq!(
            pthread_create(
                &mut signaler,
                ptr::null(),
                Some(delayed_condvar_signal),
                state_ptr
            ),
            0
        );

        assert_eq!(pthread_mutex_lock(&state.mutex as *const _ as *mut _), 0);
        let deadline = absolute_deadline_after(libc::CLOCK_REALTIME, 500);
        assert_eq!(
            pthread_cond_clockwait(
                &state.cond as *const _ as *mut _,
                &state.mutex as *const _ as *mut _,
                libc::CLOCK_REALTIME,
                &deadline,
            ),
            0
        );
        assert_eq!(pthread_mutex_unlock(&state.mutex as *const _ as *mut _), 0);

        assert_eq!(pthread_join(signaler, ptr::null_mut()), 0);
        assert_eq!(pthread_cond_destroy(&state.cond as *const _ as *mut _), 0);
        assert_eq!(pthread_mutex_destroy(&state.mutex as *const _ as *mut _), 0);
    }
}

#[test]
fn cond_clockwait_monotonic_immediate_timeout_on_managed_condvar() {
    unsafe {
        let mut attr: libc::pthread_condattr_t = std::mem::zeroed();
        assert_eq!(pthread_condattr_init(&mut attr), 0);
        assert_eq!(
            pthread_condattr_setclock(&mut attr, libc::CLOCK_MONOTONIC),
            0
        );

        let mut mutex: libc::pthread_mutex_t = std::mem::zeroed();
        let mut cond: libc::pthread_cond_t = std::mem::zeroed();
        assert_eq!(pthread_mutex_init(&mut mutex, ptr::null()), 0);
        assert_eq!(pthread_cond_init(&mut cond, &attr), 0);
        assert_eq!(pthread_condattr_destroy(&mut attr), 0);
        assert_eq!(pthread_mutex_lock(&mut mutex), 0);

        let deadline = absolute_deadline_after(libc::CLOCK_MONOTONIC, -1);
        assert_eq!(
            pthread_cond_clockwait(&mut cond, &mut mutex, libc::CLOCK_MONOTONIC, &deadline),
            libc::ETIMEDOUT
        );

        assert_eq!(pthread_mutex_unlock(&mut mutex), 0);
        assert_eq!(pthread_cond_destroy(&mut cond), 0);
        assert_eq!(pthread_mutex_destroy(&mut mutex), 0);
    }
}

#[test]
fn cond_clockwait_monotonic_future_signal_returns_zero_on_managed_condvar() {
    unsafe {
        let mut cond_attr: libc::pthread_condattr_t = std::mem::zeroed();
        assert_eq!(pthread_condattr_init(&mut cond_attr), 0);
        assert_eq!(
            pthread_condattr_setclock(&mut cond_attr, libc::CLOCK_MONOTONIC),
            0
        );

        let state = Box::new(SharedCondState {
            mutex: std::mem::zeroed(),
            cond: std::mem::zeroed(),
            ready: AtomicI32::new(0),
        });
        assert_eq!(
            pthread_mutex_init(&state.mutex as *const _ as *mut _, ptr::null()),
            0
        );
        assert_eq!(
            pthread_cond_init(&state.cond as *const _ as *mut _, &cond_attr),
            0
        );
        assert_eq!(pthread_condattr_destroy(&mut cond_attr), 0);

        let state_ptr = &*state as *const SharedCondState as *mut c_void;
        let mut signaler: libc::pthread_t = 0;
        assert_eq!(
            pthread_create(
                &mut signaler,
                ptr::null(),
                Some(delayed_condvar_signal),
                state_ptr
            ),
            0
        );

        assert_eq!(pthread_mutex_lock(&state.mutex as *const _ as *mut _), 0);
        let deadline = absolute_deadline_after(libc::CLOCK_MONOTONIC, 500);
        assert_eq!(
            pthread_cond_clockwait(
                &state.cond as *const _ as *mut _,
                &state.mutex as *const _ as *mut _,
                libc::CLOCK_MONOTONIC,
                &deadline,
            ),
            0
        );
        assert_eq!(pthread_mutex_unlock(&state.mutex as *const _ as *mut _), 0);

        assert_eq!(pthread_join(signaler, ptr::null_mut()), 0);
        assert_eq!(pthread_cond_destroy(&state.cond as *const _ as *mut _), 0);
        assert_eq!(pthread_mutex_destroy(&state.mutex as *const _ as *mut _), 0);
    }
}

// ===========================================================================
// RWLock: init, rdlock, wrlock, unlock, tryrdlock, trywrlock, destroy
// ===========================================================================

#[test]
fn rwlock_init_destroy() {
    unsafe {
        let mut rwl: libc::pthread_rwlock_t = std::mem::zeroed();
        assert_eq!(pthread_rwlock_init(&mut rwl, ptr::null()), 0);
        assert_eq!(pthread_rwlock_destroy(&mut rwl), 0);
    }
}

#[test]
fn rwlock_rdlock_unlock() {
    unsafe {
        let mut rwl: libc::pthread_rwlock_t = std::mem::zeroed();
        pthread_rwlock_init(&mut rwl, ptr::null());
        assert_eq!(pthread_rwlock_rdlock(&mut rwl), 0);
        assert_eq!(pthread_rwlock_unlock(&mut rwl), 0);
        pthread_rwlock_destroy(&mut rwl);
    }
}

#[test]
fn rwlock_wrlock_unlock() {
    unsafe {
        let mut rwl: libc::pthread_rwlock_t = std::mem::zeroed();
        pthread_rwlock_init(&mut rwl, ptr::null());
        assert_eq!(pthread_rwlock_wrlock(&mut rwl), 0);
        assert_eq!(pthread_rwlock_unlock(&mut rwl), 0);
        pthread_rwlock_destroy(&mut rwl);
    }
}

#[test]
fn rwlock_multiple_readers() {
    unsafe {
        let mut rwl: libc::pthread_rwlock_t = std::mem::zeroed();
        pthread_rwlock_init(&mut rwl, ptr::null());
        assert_eq!(pthread_rwlock_rdlock(&mut rwl), 0);
        assert_eq!(pthread_rwlock_rdlock(&mut rwl), 0);
        assert_eq!(pthread_rwlock_unlock(&mut rwl), 0);
        assert_eq!(pthread_rwlock_unlock(&mut rwl), 0);
        pthread_rwlock_destroy(&mut rwl);
    }
}

#[test]
fn rwlock_tryrdlock_succeeds() {
    unsafe {
        let mut rwl: libc::pthread_rwlock_t = std::mem::zeroed();
        pthread_rwlock_init(&mut rwl, ptr::null());
        assert_eq!(pthread_rwlock_tryrdlock(&mut rwl), 0);
        assert_eq!(pthread_rwlock_unlock(&mut rwl), 0);
        pthread_rwlock_destroy(&mut rwl);
    }
}

#[test]
fn rwlock_trywrlock_succeeds() {
    unsafe {
        let mut rwl: libc::pthread_rwlock_t = std::mem::zeroed();
        pthread_rwlock_init(&mut rwl, ptr::null());
        assert_eq!(pthread_rwlock_trywrlock(&mut rwl), 0);
        assert_eq!(pthread_rwlock_unlock(&mut rwl), 0);
        pthread_rwlock_destroy(&mut rwl);
    }
}

#[test]
fn rwlock_trywrlock_fails_when_rdlocked() {
    unsafe {
        let mut rwl: libc::pthread_rwlock_t = std::mem::zeroed();
        pthread_rwlock_init(&mut rwl, ptr::null());
        pthread_rwlock_rdlock(&mut rwl);
        let rc = pthread_rwlock_trywrlock(&mut rwl);
        assert_eq!(rc, libc::EBUSY, "trywrlock should fail when read-locked");
        pthread_rwlock_unlock(&mut rwl);
        pthread_rwlock_destroy(&mut rwl);
    }
}

// ===========================================================================
// RWLock attributes
// ===========================================================================

#[test]
fn rwlockattr_init_destroy() {
    unsafe {
        let mut attr: libc::pthread_rwlockattr_t = std::mem::zeroed();
        assert_eq!(pthread_rwlockattr_init(&mut attr), 0);
        assert_eq!(pthread_rwlockattr_destroy(&mut attr), 0);
    }
}

#[test]
fn rwlockattr_getpshared() {
    unsafe {
        let mut attr: libc::pthread_rwlockattr_t = std::mem::zeroed();
        pthread_rwlockattr_init(&mut attr);
        let mut pshared: c_int = -1;
        assert_eq!(pthread_rwlockattr_getpshared(&attr, &mut pshared), 0);
        assert_eq!(pshared, libc::PTHREAD_PROCESS_PRIVATE);
        pthread_rwlockattr_destroy(&mut attr);
    }
}

// ===========================================================================
// Thread attributes
// ===========================================================================

#[test]
fn attr_init_destroy() {
    unsafe {
        let mut attr: libc::pthread_attr_t = std::mem::zeroed();
        assert_eq!(pthread_attr_init(&mut attr), 0);
        assert_eq!(pthread_attr_destroy(&mut attr), 0);
    }
}

#[test]
fn attr_setdetachstate_getdetachstate() {
    unsafe {
        let mut attr: libc::pthread_attr_t = std::mem::zeroed();
        pthread_attr_init(&mut attr);

        assert_eq!(
            pthread_attr_setdetachstate(&mut attr, libc::PTHREAD_CREATE_DETACHED),
            0
        );
        let mut state: c_int = 0;
        assert_eq!(pthread_attr_getdetachstate(&attr, &mut state), 0);
        assert_eq!(state, libc::PTHREAD_CREATE_DETACHED);

        pthread_attr_destroy(&mut attr);
    }
}

#[test]
fn attr_setstacksize_getstacksize() {
    unsafe {
        let mut attr: libc::pthread_attr_t = std::mem::zeroed();
        pthread_attr_init(&mut attr);

        let target_size: usize = 2 * 1024 * 1024; // 2 MiB
        assert_eq!(pthread_attr_setstacksize(&mut attr, target_size), 0);
        let mut actual: usize = 0;
        assert_eq!(pthread_attr_getstacksize(&attr, &mut actual), 0);
        assert_eq!(actual, target_size);

        pthread_attr_destroy(&mut attr);
    }
}

#[test]
fn attr_getstacksize_after_destroy_is_rejected() {
    unsafe {
        let mut attr: libc::pthread_attr_t = std::mem::zeroed();
        assert_eq!(pthread_attr_init(&mut attr), 0);
        assert_eq!(pthread_attr_destroy(&mut attr), 0);

        let mut actual: usize = 0;
        assert_eq!(pthread_attr_getstacksize(&attr, &mut actual), libc::EINVAL);
    }
}

#[test]
fn attr_getguardsize() {
    unsafe {
        let mut attr: libc::pthread_attr_t = std::mem::zeroed();
        pthread_attr_init(&mut attr);

        let mut guard_size: usize = 0;
        assert_eq!(pthread_attr_getguardsize(&attr, &mut guard_size), 0);
        assert!(guard_size > 0, "default guard size should be > 0");

        pthread_attr_destroy(&mut attr);
    }
}

#[test]
fn attr_setguardsize() {
    unsafe {
        let mut attr: libc::pthread_attr_t = std::mem::zeroed();
        pthread_attr_init(&mut attr);

        let target: usize = 8192;
        assert_eq!(pthread_attr_setguardsize(&mut attr, target), 0);
        let mut actual: usize = 0;
        assert_eq!(pthread_attr_getguardsize(&attr, &mut actual), 0);
        assert_eq!(actual, target);

        pthread_attr_destroy(&mut attr);
    }
}

#[test]
fn attr_getschedpolicy() {
    unsafe {
        let mut attr: libc::pthread_attr_t = std::mem::zeroed();
        pthread_attr_init(&mut attr);

        let mut policy: c_int = -1;
        assert_eq!(pthread_attr_getschedpolicy(&attr, &mut policy), 0);
        assert_eq!(policy, libc::SCHED_OTHER);

        pthread_attr_destroy(&mut attr);
    }
}

#[test]
fn attr_getscope() {
    unsafe {
        let mut attr: libc::pthread_attr_t = std::mem::zeroed();
        pthread_attr_init(&mut attr);

        let mut scope: c_int = -1;
        assert_eq!(pthread_attr_getscope(&attr, &mut scope), 0);
        assert_eq!(scope, PTHREAD_SCOPE_SYSTEM);

        pthread_attr_destroy(&mut attr);
    }
}

#[test]
fn attr_getinheritsched() {
    unsafe {
        let mut attr: libc::pthread_attr_t = std::mem::zeroed();
        pthread_attr_init(&mut attr);

        let mut inherit: c_int = -1;
        assert_eq!(pthread_attr_getinheritsched(&attr, &mut inherit), 0);
        assert!(
            inherit == libc::PTHREAD_INHERIT_SCHED || inherit == libc::PTHREAD_EXPLICIT_SCHED,
            "inheritsched must be valid enum"
        );

        pthread_attr_destroy(&mut attr);
    }
}

// ===========================================================================
// Thread-specific data (TSD / pthread_key_*)
// ===========================================================================

#[test]
fn key_create_delete() {
    unsafe {
        let mut key: libc::pthread_key_t = 0;
        assert_eq!(pthread_key_create(&mut key, None), 0);
        assert_eq!(pthread_key_delete(key), 0);
    }
}

#[test]
fn key_setspecific_getspecific() {
    unsafe {
        let mut key: libc::pthread_key_t = 0;
        pthread_key_create(&mut key, None);

        let val = 0xDEADu64 as *mut c_void;
        assert_eq!(pthread_setspecific(key, val), 0);
        let got = pthread_getspecific(key);
        assert_eq!(got as u64, 0xDEAD);

        pthread_key_delete(key);
    }
}

#[test]
fn key_default_is_null() {
    unsafe {
        let mut key: libc::pthread_key_t = 0;
        pthread_key_create(&mut key, None);
        let got = pthread_getspecific(key);
        assert!(got.is_null(), "newly created key should have null value");
        pthread_key_delete(key);
    }
}

// ===========================================================================
// pthread_once
// ===========================================================================

static ONCE_COUNTER: AtomicI32 = AtomicI32::new(0);

unsafe extern "C" fn once_init_fn() {
    ONCE_COUNTER.fetch_add(1, Ordering::Relaxed);
}

#[test]
fn once_runs_exactly_once() {
    ONCE_COUNTER.store(0, Ordering::Relaxed);
    let mut once: libc::pthread_once_t = libc::PTHREAD_ONCE_INIT;
    unsafe {
        pthread_once(&mut once, Some(once_init_fn));
        pthread_once(&mut once, Some(once_init_fn));
        pthread_once(&mut once, Some(once_init_fn));
    }
    assert_eq!(
        ONCE_COUNTER.load(Ordering::Relaxed),
        1,
        "init_fn should run exactly once"
    );
}

// ===========================================================================
// Spinlock
// ===========================================================================

#[test]
fn spinlock_init_destroy() {
    unsafe {
        let mut lock: c_int = 0;
        assert_eq!(
            pthread_spin_init(&mut lock as *mut c_int as *mut c_void, 0),
            0
        );
        assert_eq!(
            pthread_spin_destroy(&mut lock as *mut c_int as *mut c_void),
            0
        );
    }
}

#[test]
fn spinlock_lock_unlock() {
    unsafe {
        let mut lock: c_int = 0;
        pthread_spin_init(&mut lock as *mut c_int as *mut c_void, 0);
        assert_eq!(pthread_spin_lock(&mut lock as *mut c_int as *mut c_void), 0);
        assert_eq!(
            pthread_spin_unlock(&mut lock as *mut c_int as *mut c_void),
            0
        );
        pthread_spin_destroy(&mut lock as *mut c_int as *mut c_void);
    }
}

#[test]
fn spinlock_trylock_succeeds_unlocked() {
    unsafe {
        let mut lock: c_int = 0;
        pthread_spin_init(&mut lock as *mut c_int as *mut c_void, 0);
        let rc = pthread_spin_trylock(&mut lock as *mut c_int as *mut c_void);
        assert_eq!(rc, 0);
        pthread_spin_unlock(&mut lock as *mut c_int as *mut c_void);
        pthread_spin_destroy(&mut lock as *mut c_int as *mut c_void);
    }
}

#[test]
fn spinlock_trylock_fails_locked() {
    unsafe {
        let mut lock: c_int = 0;
        pthread_spin_init(&mut lock as *mut c_int as *mut c_void, 0);
        pthread_spin_lock(&mut lock as *mut c_int as *mut c_void);
        let rc = pthread_spin_trylock(&mut lock as *mut c_int as *mut c_void);
        assert_eq!(rc, libc::EBUSY);
        pthread_spin_unlock(&mut lock as *mut c_int as *mut c_void);
        pthread_spin_destroy(&mut lock as *mut c_int as *mut c_void);
    }
}

// ===========================================================================
// Barrier
// ===========================================================================

#[test]
fn barrier_init_destroy() {
    unsafe {
        let mut barrier: libc::pthread_barrier_t = std::mem::zeroed();
        let rc = pthread_barrier_init(&mut barrier as *mut _ as *mut c_void, ptr::null_mut(), 1);
        assert_eq!(rc, 0);
        let rc = pthread_barrier_destroy(&mut barrier as *mut _ as *mut c_void);
        assert_eq!(rc, 0);
    }
}

#[test]
fn barrier_single_thread_wait() {
    unsafe {
        let mut barrier: libc::pthread_barrier_t = std::mem::zeroed();
        assert_eq!(
            pthread_barrier_init(&mut barrier as *mut _ as *mut c_void, ptr::null_mut(), 1),
            0
        );

        let rc = pthread_barrier_wait(&mut barrier as *mut _ as *mut c_void);
        assert_eq!(
            rc,
            libc::PTHREAD_BARRIER_SERIAL_THREAD,
            "single-thread barrier wait should return SERIAL_THREAD"
        );

        assert_eq!(
            pthread_barrier_destroy(&mut barrier as *mut _ as *mut c_void),
            0
        );
    }
}

// ===========================================================================
// Barrier attributes
// ===========================================================================

#[test]
fn barrierattr_init_destroy() {
    unsafe {
        let mut attr: libc::pthread_barrierattr_t = std::mem::zeroed();
        assert_eq!(pthread_barrierattr_init(&mut attr), 0);
        assert_eq!(pthread_barrierattr_destroy(&mut attr), 0);
    }
}

#[test]
fn barrierattr_getpshared() {
    unsafe {
        let mut attr: libc::pthread_barrierattr_t = std::mem::zeroed();
        pthread_barrierattr_init(&mut attr);
        let mut pshared: c_int = -1;
        assert_eq!(pthread_barrierattr_getpshared(&attr, &mut pshared), 0);
        assert_eq!(pshared, libc::PTHREAD_PROCESS_PRIVATE);
        pthread_barrierattr_destroy(&mut attr);
    }
}

// ===========================================================================
// Cancel state
// ===========================================================================

#[test]
fn setcancelstate_returns_old() {
    unsafe {
        let mut old: c_int = -1;
        let rc = pthread_setcancelstate(PTHREAD_CANCEL_DISABLE, &mut old);
        assert_eq!(rc, 0);
        assert!(
            old == PTHREAD_CANCEL_ENABLE || old == PTHREAD_CANCEL_DISABLE,
            "old cancel state must be valid"
        );
        pthread_setcancelstate(old, ptr::null_mut());
    }
}

#[test]
fn setcanceltype_returns_old() {
    unsafe {
        let mut old: c_int = -1;
        let rc = pthread_setcanceltype(PTHREAD_CANCEL_DEFERRED, &mut old);
        assert_eq!(rc, 0);
        assert!(
            old == PTHREAD_CANCEL_DEFERRED || old == PTHREAD_CANCEL_ASYNCHRONOUS,
            "old cancel type must be valid"
        );
        pthread_setcanceltype(old, ptr::null_mut());
    }
}

#[test]
fn testcancel_does_not_panic() {
    unsafe { pthread_testcancel() };
}

// ===========================================================================
// Thread naming (GNU extensions)
// ===========================================================================

#[test]
fn setname_getname_np() {
    unsafe {
        let self_id = pthread_self();
        let name = CString::new("test-thrd").unwrap();
        let rc = pthread_setname_np(self_id, name.as_ptr());
        assert_eq!(rc, 0, "pthread_setname_np should succeed");

        let mut buf = [0u8; 16];
        let rc = pthread_getname_np(self_id, buf.as_mut_ptr() as *mut _, buf.len());
        assert_eq!(rc, 0, "pthread_getname_np should succeed");
        let got = CStr::from_ptr(buf.as_ptr() as *const _);
        assert_eq!(got.to_bytes(), b"test-thrd");
    }
}

#[test]
fn setname_getname_np_live_thread() {
    unsafe {
        let mut thr: libc::pthread_t = 0;
        assert_eq!(
            pthread_create(
                &mut thr,
                ptr::null(),
                Some(cancellable_thread),
                ptr::null_mut()
            ),
            0
        );
        std::thread::sleep(std::time::Duration::from_millis(20));

        let name = CString::new("peer").unwrap();
        assert_eq!(
            pthread_setname_np(thr, name.as_ptr()),
            0,
            "pthread_setname_np should succeed for a live thread"
        );

        let mut buf = [0u8; 16];
        assert_eq!(
            pthread_getname_np(thr, buf.as_mut_ptr() as *mut _, buf.len()),
            0,
            "pthread_getname_np should succeed for a live thread"
        );
        let got = CStr::from_ptr(buf.as_ptr() as *const _);
        assert_eq!(got.to_bytes(), b"peer");

        assert_eq!(pthread_cancel(thr), 0);
        assert_eq!(pthread_join(thr, ptr::null_mut()), 0);
    }
}

#[test]
fn setname_too_long_returns_erange() {
    unsafe {
        let self_id = pthread_self();
        let long_name = CString::new("this_name_is_way_too_long_for_pthread").unwrap();
        let rc = pthread_setname_np(self_id, long_name.as_ptr());
        assert_eq!(rc, libc::ERANGE, "name > 15 chars should return ERANGE");
    }
}

// ===========================================================================
// Concurrency (GNU legacy)
// ===========================================================================

#[test]
fn concurrency_set_succeeds() {
    unsafe {
        assert_eq!(
            pthread_setconcurrency(-1),
            libc::EINVAL,
            "negative concurrency level should be rejected"
        );
        let rc = pthread_setconcurrency(4);
        assert_eq!(rc, 0, "pthread_setconcurrency should return 0");
        let level = pthread_getconcurrency();
        assert_eq!(level, 4, "getconcurrency should return the last set value");
    }
}

// ===========================================================================
// pthread_yield (GNU)
// ===========================================================================

#[test]
fn yield_succeeds() {
    let rc = unsafe { pthread_yield() };
    assert_eq!(rc, 0, "pthread_yield should succeed");
}

// ===========================================================================
// pthread_kill
// ===========================================================================

#[test]
fn kill_sig_zero_to_self() {
    let self_id = unsafe { pthread_self() };
    let rc = unsafe { pthread_kill(self_id, 0) };
    assert_eq!(rc, 0, "pthread_kill(self, 0) should succeed");
}

#[test]
fn kill_sig_zero_to_live_thread() {
    unsafe {
        let mut thr: libc::pthread_t = 0;
        assert_eq!(
            pthread_create(
                &mut thr,
                ptr::null(),
                Some(cancellable_thread),
                ptr::null_mut()
            ),
            0
        );
        std::thread::sleep(std::time::Duration::from_millis(20));

        assert_eq!(
            pthread_kill(thr, 0),
            0,
            "pthread_kill(thread, 0) should succeed for a live thread"
        );

        assert_eq!(pthread_cancel(thr), 0);
        assert_eq!(pthread_join(thr, ptr::null_mut()), 0);
    }
}

#[test]
fn kill_sig_zero_to_joined_thread_returns_esrch() {
    unsafe {
        let thr: libc::pthread_t;
        {
            let _guard = ThreadingForceNativeGuard {
                previous: pthread_threading_swap_force_native_for_tests(),
            };
            let mut created: libc::pthread_t = 0;
            assert_eq!(
                pthread_create(
                    &mut created,
                    ptr::null(),
                    Some(noop_thread),
                    ptr::null_mut()
                ),
                0
            );
            assert_eq!(pthread_join(created, ptr::null_mut()), 0);
            thr = created;
        }
        assert_eq!(
            pthread_kill(thr, 0),
            libc::ESRCH,
            "joined thread handle should no longer be treated as a live TID"
        );
    }
}

struct SigqueueWaitCtx {
    ready: AtomicI32,
    wait_rc: AtomicI32,
    signal_code: AtomicI32,
    value_bits: AtomicUsize,
}

unsafe extern "C" fn sigqueue_waiting_thread(arg: *mut c_void) -> *mut c_void {
    let ctx = unsafe { &*(arg as *const SigqueueWaitCtx) };
    let mut set: libc::sigset_t = unsafe { std::mem::zeroed() };
    unsafe {
        libc::sigemptyset(&mut set);
        libc::sigaddset(&mut set, libc::SIGUSR1);
    }
    let mask_rc = unsafe { pthread_sigmask(libc::SIG_BLOCK, &set, ptr::null_mut()) };
    if mask_rc != 0 {
        ctx.wait_rc.store(-mask_rc, Ordering::Release);
        return ptr::null_mut();
    }

    ctx.ready.store(1, Ordering::Release);

    let mut info: libc::siginfo_t = unsafe { std::mem::zeroed() };
    let wait_rc = unsafe { libc::sigwaitinfo(&set, &mut info) };
    ctx.wait_rc.store(wait_rc, Ordering::Release);
    if wait_rc == libc::SIGUSR1 {
        ctx.signal_code.store(info.si_code, Ordering::Release);
        let value = unsafe { info.si_value() };
        ctx.value_bits
            .store(value.sival_ptr as usize, Ordering::Release);
    }
    ptr::null_mut()
}

#[test]
fn sigqueue_live_thread_preserves_queued_value() {
    unsafe {
        let ctx = SigqueueWaitCtx {
            ready: AtomicI32::new(0),
            wait_rc: AtomicI32::new(i32::MIN),
            signal_code: AtomicI32::new(0),
            value_bits: AtomicUsize::new(0),
        };
        let mut thr: libc::pthread_t = 0;
        assert_eq!(
            pthread_create(
                &mut thr,
                ptr::null(),
                Some(sigqueue_waiting_thread),
                (&ctx as *const SigqueueWaitCtx).cast_mut().cast()
            ),
            0
        );

        for _ in 0..100 {
            if ctx.ready.load(Ordering::Acquire) == 1 {
                break;
            }
            std::thread::sleep(std::time::Duration::from_millis(1));
        }
        assert_eq!(
            ctx.ready.load(Ordering::Acquire),
            1,
            "target thread should block SIGUSR1 before queueing"
        );

        let payload = 0x1234_5678usize;
        let value = libc::sigval {
            sival_ptr: payload as *mut c_void,
        };
        assert_eq!(
            pthread_sigqueue(thr, libc::SIGUSR1, value),
            0,
            "pthread_sigqueue should succeed for a live thread"
        );
        assert_eq!(pthread_join(thr, ptr::null_mut()), 0);
        assert_eq!(
            ctx.wait_rc.load(Ordering::Acquire),
            libc::SIGUSR1,
            "sigwaitinfo should return the queued signal"
        );
        assert_eq!(
            ctx.signal_code.load(Ordering::Acquire),
            libc::SI_QUEUE,
            "queued signal should preserve SI_QUEUE metadata"
        );
        assert_eq!(
            ctx.value_bits.load(Ordering::Acquire),
            payload,
            "queued signal payload should round-trip through siginfo_t"
        );
    }
}

// ===========================================================================
// pthread_getaffinity_np / pthread_setaffinity_np
// ===========================================================================

#[test]
fn getaffinity_np() {
    unsafe {
        let self_id = pthread_self();
        let mut cpuset: libc::cpu_set_t = std::mem::zeroed();
        let rc =
            pthread_getaffinity_np(self_id, std::mem::size_of::<libc::cpu_set_t>(), &mut cpuset);
        assert_eq!(rc, 0, "pthread_getaffinity_np should succeed for self");
    }
}

#[test]
fn getaffinity_np_live_thread() {
    unsafe {
        let mut thr: libc::pthread_t = 0;
        assert_eq!(
            pthread_create(
                &mut thr,
                ptr::null(),
                Some(cancellable_thread),
                ptr::null_mut()
            ),
            0
        );
        std::thread::sleep(std::time::Duration::from_millis(20));

        let mut cpuset: libc::cpu_set_t = std::mem::zeroed();
        assert_eq!(
            pthread_getaffinity_np(thr, std::mem::size_of::<libc::cpu_set_t>(), &mut cpuset),
            0,
            "pthread_getaffinity_np should succeed for a live thread"
        );

        assert_eq!(pthread_cancel(thr), 0);
        assert_eq!(pthread_join(thr, ptr::null_mut()), 0);
    }
}

// ===========================================================================
// pthread_atfork
// ===========================================================================

unsafe extern "C" fn prepare_fn() {}
unsafe extern "C" fn parent_fn() {}
unsafe extern "C" fn child_fn() {}

#[test]
fn atfork_register_succeeds() {
    let rc = unsafe { pthread_atfork(Some(prepare_fn), Some(parent_fn), Some(child_fn)) };
    assert_eq!(rc, 0, "pthread_atfork should succeed");
}

// ===========================================================================
// __pthread_* internal aliases
// ===========================================================================

#[test]
fn internal_mutex_aliases() {
    unsafe {
        let mut mutex: libc::pthread_mutex_t = std::mem::zeroed();
        assert_eq!(__pthread_mutex_init(&mut mutex, ptr::null()), 0);
        assert_eq!(__pthread_mutex_lock(&mut mutex), 0);
        assert_eq!(__pthread_mutex_unlock(&mut mutex), 0);
        assert_eq!(__pthread_mutex_destroy(&mut mutex), 0);
    }
}

#[test]
fn internal_mutex_trylock() {
    unsafe {
        let mut mutex: libc::pthread_mutex_t = std::mem::zeroed();
        __pthread_mutex_init(&mut mutex, ptr::null());
        assert_eq!(__pthread_mutex_trylock(&mut mutex), 0);
        __pthread_mutex_unlock(&mut mutex);
        __pthread_mutex_destroy(&mut mutex);
    }
}

#[test]
fn internal_rwlock_aliases() {
    unsafe {
        let mut rwl: libc::pthread_rwlock_t = std::mem::zeroed();
        assert_eq!(__pthread_rwlock_init(&mut rwl, ptr::null()), 0);
        assert_eq!(__pthread_rwlock_rdlock(&mut rwl), 0);
        assert_eq!(__pthread_rwlock_unlock(&mut rwl), 0);
        assert_eq!(__pthread_rwlock_wrlock(&mut rwl), 0);
        assert_eq!(__pthread_rwlock_unlock(&mut rwl), 0);
        assert_eq!(__pthread_rwlock_destroy(&mut rwl), 0);
    }
}

#[test]
fn internal_rwlock_try() {
    unsafe {
        let mut rwl: libc::pthread_rwlock_t = std::mem::zeroed();
        __pthread_rwlock_init(&mut rwl, ptr::null());
        assert_eq!(__pthread_rwlock_tryrdlock(&mut rwl), 0);
        __pthread_rwlock_unlock(&mut rwl);
        assert_eq!(__pthread_rwlock_trywrlock(&mut rwl), 0);
        __pthread_rwlock_unlock(&mut rwl);
        __pthread_rwlock_destroy(&mut rwl);
    }
}

static INTERNAL_ONCE_CTR: AtomicI32 = AtomicI32::new(0);

unsafe extern "C" fn internal_once_fn() {
    INTERNAL_ONCE_CTR.fetch_add(1, Ordering::Relaxed);
}

#[test]
fn internal_once_alias() {
    INTERNAL_ONCE_CTR.store(0, Ordering::Relaxed);
    let mut once: libc::pthread_once_t = libc::PTHREAD_ONCE_INIT;
    unsafe {
        __pthread_once(&mut once, Some(internal_once_fn));
        __pthread_once(&mut once, Some(internal_once_fn));
    }
    assert_eq!(INTERNAL_ONCE_CTR.load(Ordering::Relaxed), 1);
}

#[test]
fn internal_key_aliases() {
    unsafe {
        let mut key: libc::pthread_key_t = 0;
        assert_eq!(__pthread_key_create(&mut key, None), 0);
        let val = 0xCAFEu64 as *mut c_void;
        assert_eq!(__pthread_setspecific(key, val), 0);
        let got = __pthread_getspecific(key);
        assert_eq!(got as u64, 0xCAFE);
        pthread_key_delete(key);
    }
}

#[test]
fn internal_mutexattr_aliases() {
    unsafe {
        let mut attr: libc::pthread_mutexattr_t = std::mem::zeroed();
        assert_eq!(__pthread_mutexattr_init(&mut attr), 0);
        assert_eq!(
            __pthread_mutexattr_settype(&mut attr, libc::PTHREAD_MUTEX_RECURSIVE),
            0
        );
        assert_eq!(__pthread_mutexattr_destroy(&mut attr), 0);
    }
}

// ===========================================================================
// pthread_cancel register/unregister stubs (no-op)
// ===========================================================================

#[test]
fn cancel_register_unregister_stubs() {
    unsafe {
        let mut buf = [0u8; 64];
        __pthread_register_cancel(buf.as_mut_ptr() as *mut c_void);
        __pthread_unregister_cancel(buf.as_mut_ptr() as *mut c_void);
        __pthread_register_cancel_defer(buf.as_mut_ptr() as *mut c_void);
        __pthread_unregister_cancel_restore(buf.as_mut_ptr() as *mut c_void);
        __pthread_cleanup_routine(buf.as_mut_ptr() as *mut c_void);
    }
}

// ===========================================================================
// __pthread_get_minstack
// ===========================================================================

#[test]
fn get_minstack_returns_nonzero() {
    unsafe {
        let attr: libc::pthread_attr_t = std::mem::zeroed();
        let min = __pthread_get_minstack(&attr);
        assert!(
            min > 0,
            "__pthread_get_minstack should return > 0, got {min}"
        );
    }
}

// ===========================================================================
// Mutex multi-threaded contention
// ===========================================================================

unsafe extern "C" fn increment_with_mutex(arg: *mut c_void) -> *mut c_void {
    unsafe {
        let (mutex_ptr, counter_ptr) =
            &*(arg as *const (*mut libc::pthread_mutex_t, *mut AtomicU32));
        for _ in 0..1000 {
            pthread_mutex_lock(*mutex_ptr);
            (**counter_ptr).fetch_add(1, Ordering::Relaxed);
            pthread_mutex_unlock(*mutex_ptr);
        }
        ptr::null_mut()
    }
}

#[test]
fn mutex_contended_increment() {
    unsafe {
        let mut mutex: libc::pthread_mutex_t = std::mem::zeroed();
        pthread_mutex_init(&mut mutex, ptr::null());

        let counter = AtomicU32::new(0);
        let ctx: (*mut libc::pthread_mutex_t, *mut AtomicU32) =
            (&mut mutex, &counter as *const AtomicU32 as *mut AtomicU32);
        let ctx_ptr = &ctx as *const _ as *mut c_void;

        let mut threads = [0 as libc::pthread_t; 4];
        for thr in threads.iter_mut() {
            pthread_create(thr, ptr::null(), Some(increment_with_mutex), ctx_ptr);
        }
        for thr in threads.iter() {
            pthread_join(*thr, ptr::null_mut());
        }

        assert_eq!(
            counter.load(Ordering::Relaxed),
            4000,
            "4 threads x 1000 increments = 4000"
        );
        pthread_mutex_destroy(&mut mutex);
    }
}

// ===========================================================================
// Thread attribute setters (schedparam, schedpolicy, inheritsched, scope)
// ===========================================================================

#[test]
fn attr_setschedparam_getschedparam() {
    unsafe {
        let mut attr: libc::pthread_attr_t = std::mem::zeroed();
        pthread_attr_init(&mut attr);

        let mut param: libc::sched_param = std::mem::zeroed();
        param.sched_priority = 0; // SCHED_OTHER only supports priority 0
        assert_eq!(pthread_attr_setschedparam(&mut attr, &param), 0);

        let mut got: libc::sched_param = std::mem::zeroed();
        assert_eq!(pthread_attr_getschedparam(&attr, &mut got), 0);
        assert_eq!(got.sched_priority, 0);

        pthread_attr_destroy(&mut attr);
    }
}

#[test]
fn attr_setschedpolicy_roundtrip() {
    unsafe {
        let mut attr: libc::pthread_attr_t = std::mem::zeroed();
        pthread_attr_init(&mut attr);

        assert_eq!(pthread_attr_setschedpolicy(&mut attr, libc::SCHED_OTHER), 0);
        let mut policy: c_int = -1;
        assert_eq!(pthread_attr_getschedpolicy(&attr, &mut policy), 0);
        assert_eq!(policy, libc::SCHED_OTHER);

        pthread_attr_destroy(&mut attr);
    }
}

#[test]
fn attr_setinheritsched_roundtrip() {
    unsafe {
        let mut attr: libc::pthread_attr_t = std::mem::zeroed();
        pthread_attr_init(&mut attr);

        assert_eq!(
            pthread_attr_setinheritsched(&mut attr, PTHREAD_EXPLICIT_SCHED),
            0
        );
        let mut inherit: c_int = -1;
        assert_eq!(pthread_attr_getinheritsched(&attr, &mut inherit), 0);
        assert_eq!(inherit, PTHREAD_EXPLICIT_SCHED);

        pthread_attr_destroy(&mut attr);
    }
}

#[test]
fn attr_setscope_roundtrip() {
    unsafe {
        let mut attr: libc::pthread_attr_t = std::mem::zeroed();
        pthread_attr_init(&mut attr);

        assert_eq!(pthread_attr_setscope(&mut attr, PTHREAD_SCOPE_SYSTEM), 0);
        let mut scope: c_int = -1;
        assert_eq!(pthread_attr_getscope(&attr, &mut scope), 0);
        assert_eq!(scope, PTHREAD_SCOPE_SYSTEM);

        pthread_attr_destroy(&mut attr);
    }
}

// ===========================================================================
// Stack attributes
// ===========================================================================

#[test]
fn attr_setstack_getstack() {
    unsafe {
        let mut attr: libc::pthread_attr_t = std::mem::zeroed();
        pthread_attr_init(&mut attr);

        let stack_size: usize = 1024 * 1024; // 1 MiB
        let stack = libc::mmap(
            std::ptr::null_mut(),
            stack_size,
            libc::PROT_READ | libc::PROT_WRITE,
            libc::MAP_PRIVATE | libc::MAP_ANONYMOUS,
            -1,
            0,
        );
        assert_ne!(stack, libc::MAP_FAILED);

        let rc = pthread_attr_setstack(&mut attr, stack, stack_size);
        assert_eq!(rc, 0);

        let mut got_addr: *mut c_void = ptr::null_mut();
        let mut got_size: usize = 0;
        assert_eq!(
            pthread_attr_getstack(&attr, &mut got_addr, &mut got_size),
            0
        );
        assert_eq!(got_addr, stack);
        assert_eq!(got_size, stack_size);

        pthread_attr_destroy(&mut attr);
        libc::munmap(stack, stack_size);
    }
}

#[test]
fn attr_setstackaddr_getstackaddr() {
    unsafe {
        let mut attr: libc::pthread_attr_t = std::mem::zeroed();
        pthread_attr_init(&mut attr);

        let fake_addr = 0x1000usize as *mut c_void;
        #[allow(deprecated)]
        let rc = pthread_attr_setstackaddr(&mut attr, fake_addr);
        assert_eq!(rc, 0);

        let mut got: *mut c_void = ptr::null_mut();
        #[allow(deprecated)]
        let rc = pthread_attr_getstackaddr(&attr, &mut got);
        assert_eq!(rc, 0);
        assert_eq!(got, fake_addr);

        pthread_attr_destroy(&mut attr);
    }
}

// ===========================================================================
// Affinity attributes
// ===========================================================================

#[test]
fn attr_setaffinity_np_getaffinity_np() {
    unsafe {
        let mut attr: libc::pthread_attr_t = std::mem::zeroed();
        pthread_attr_init(&mut attr);

        let cpu = first_allowed_cpu();
        let mut cpuset: libc::cpu_set_t = std::mem::zeroed();
        libc::CPU_SET(cpu, &mut cpuset);

        let rc =
            pthread_attr_setaffinity_np(&mut attr, std::mem::size_of::<libc::cpu_set_t>(), &cpuset);
        assert_eq!(rc, 0);

        let mut got: libc::cpu_set_t = std::mem::zeroed();
        let rc =
            pthread_attr_getaffinity_np(&attr, std::mem::size_of::<libc::cpu_set_t>(), &mut got);
        assert_eq!(rc, 0);
        assert!(libc::CPU_ISSET(cpu, &got), "selected CPU should be set");

        pthread_attr_destroy(&mut attr);
    }
}

// ===========================================================================
// Signal mask attributes
// ===========================================================================

#[test]
fn attr_setsigmask_np_getsigmask_np() {
    unsafe {
        let mut attr: libc::pthread_attr_t = std::mem::zeroed();
        pthread_attr_init(&mut attr);

        let mut sigmask: libc::sigset_t = std::mem::zeroed();
        libc::sigemptyset(&mut sigmask);
        libc::sigaddset(&mut sigmask, libc::SIGUSR1);

        let rc = pthread_attr_setsigmask_np(&mut attr, &sigmask);
        assert_eq!(rc, 0);

        let mut got: libc::sigset_t = std::mem::zeroed();
        let rc = pthread_attr_getsigmask_np(&attr, &mut got);
        assert_eq!(rc, 0);
        assert_eq!(libc::sigismember(&got, libc::SIGUSR1), 1);

        pthread_attr_destroy(&mut attr);
    }
}

// ===========================================================================
// Mutex attribute setters: pshared, protocol, robust
// ===========================================================================

#[test]
fn mutexattr_setpshared_roundtrip() {
    unsafe {
        let mut attr: libc::pthread_mutexattr_t = std::mem::zeroed();
        pthread_mutexattr_init(&mut attr);

        assert_eq!(
            pthread_mutexattr_setpshared(&mut attr, libc::PTHREAD_PROCESS_PRIVATE),
            0
        );
        let mut val: c_int = -1;
        assert_eq!(pthread_mutexattr_getpshared(&attr, &mut val), 0);
        assert_eq!(val, libc::PTHREAD_PROCESS_PRIVATE);

        pthread_mutexattr_destroy(&mut attr);
    }
}

#[test]
fn mutexattr_setprotocol_getprotocol() {
    unsafe {
        let mut attr: libc::pthread_mutexattr_t = std::mem::zeroed();
        pthread_mutexattr_init(&mut attr);

        assert_eq!(
            pthread_mutexattr_setprotocol(&mut attr, libc::PTHREAD_PRIO_NONE),
            0
        );
        let mut val: c_int = -1;
        assert_eq!(pthread_mutexattr_getprotocol(&attr, &mut val), 0);
        assert_eq!(val, libc::PTHREAD_PRIO_NONE);

        pthread_mutexattr_destroy(&mut attr);
    }
}

#[test]
fn mutexattr_setrobust_roundtrip() {
    unsafe {
        let mut attr: libc::pthread_mutexattr_t = std::mem::zeroed();
        pthread_mutexattr_init(&mut attr);

        assert_eq!(
            pthread_mutexattr_setrobust(&mut attr, libc::PTHREAD_MUTEX_STALLED),
            0
        );
        let mut val: c_int = -1;
        assert_eq!(pthread_mutexattr_getrobust(&attr, &mut val), 0);
        assert_eq!(val, libc::PTHREAD_MUTEX_STALLED);

        pthread_mutexattr_destroy(&mut attr);
    }
}

#[test]
fn mutexattr_protocol_pshared_and_robust_roundtrip_independent() {
    unsafe {
        let mut attr: libc::pthread_mutexattr_t = std::mem::zeroed();
        pthread_mutexattr_init(&mut attr);

        assert_eq!(
            pthread_mutexattr_setprotocol(&mut attr, libc::PTHREAD_PRIO_INHERIT),
            0
        );
        assert_eq!(
            pthread_mutexattr_setpshared(&mut attr, libc::PTHREAD_PROCESS_SHARED),
            0
        );
        assert_eq!(
            pthread_mutexattr_setrobust(&mut attr, libc::PTHREAD_MUTEX_ROBUST),
            0
        );

        let mut kind: c_int = -1;
        let mut protocol: c_int = -1;
        let mut pshared: c_int = -1;
        let mut robust: c_int = -1;
        assert_eq!(pthread_mutexattr_gettype(&attr, &mut kind), 0);
        assert_eq!(pthread_mutexattr_getprotocol(&attr, &mut protocol), 0);
        assert_eq!(pthread_mutexattr_getpshared(&attr, &mut pshared), 0);
        assert_eq!(pthread_mutexattr_getrobust(&attr, &mut robust), 0);
        assert_eq!(kind, libc::PTHREAD_MUTEX_DEFAULT);
        assert_eq!(protocol, libc::PTHREAD_PRIO_INHERIT);
        assert_eq!(pshared, libc::PTHREAD_PROCESS_SHARED);
        assert_eq!(robust, libc::PTHREAD_MUTEX_ROBUST);

        pthread_mutexattr_destroy(&mut attr);
    }
}

#[test]
fn mutexattr_gettype_after_destroy_is_rejected() {
    unsafe {
        let mut attr: libc::pthread_mutexattr_t = std::mem::zeroed();
        pthread_mutexattr_init(&mut attr);
        assert_eq!(pthread_mutexattr_destroy(&mut attr), 0);

        let mut kind: c_int = -1;
        assert_eq!(pthread_mutexattr_gettype(&attr, &mut kind), libc::EINVAL);
    }
}

#[test]
fn mutex_init_rejects_destroyed_attr() {
    unsafe {
        let mut attr: libc::pthread_mutexattr_t = std::mem::zeroed();
        let mut mutex: libc::pthread_mutex_t = std::mem::zeroed();
        assert_eq!(pthread_mutexattr_init(&mut attr), 0);
        assert_eq!(pthread_mutexattr_destroy(&mut attr), 0);
        assert_eq!(pthread_mutex_init(&mut mutex, &attr), libc::EINVAL);
    }
}

// ===========================================================================
// Condattr setpshared
// ===========================================================================

#[test]
fn condattr_setpshared_roundtrip() {
    unsafe {
        let mut attr: libc::pthread_condattr_t = std::mem::zeroed();
        pthread_condattr_init(&mut attr);

        assert_eq!(
            pthread_condattr_setpshared(&mut attr, libc::PTHREAD_PROCESS_PRIVATE),
            0
        );
        let mut val: c_int = -1;
        assert_eq!(pthread_condattr_getpshared(&attr, &mut val), 0);
        assert_eq!(val, libc::PTHREAD_PROCESS_PRIVATE);

        pthread_condattr_destroy(&mut attr);
    }
}

#[test]
fn condattr_clock_and_pshared_roundtrip_independent() {
    unsafe {
        let mut attr: libc::pthread_condattr_t = std::mem::zeroed();
        pthread_condattr_init(&mut attr);

        assert_eq!(
            pthread_condattr_setclock(&mut attr, libc::CLOCK_MONOTONIC),
            0
        );
        assert_eq!(
            pthread_condattr_setpshared(&mut attr, libc::PTHREAD_PROCESS_SHARED),
            0
        );

        let mut clock_id: libc::clockid_t = 0;
        let mut pshared: c_int = -1;
        assert_eq!(pthread_condattr_getclock(&attr, &mut clock_id), 0);
        assert_eq!(pthread_condattr_getpshared(&attr, &mut pshared), 0);
        assert_eq!(clock_id, libc::CLOCK_MONOTONIC);
        assert_eq!(pshared, libc::PTHREAD_PROCESS_SHARED);

        pthread_condattr_destroy(&mut attr);
    }
}

#[test]
fn condattr_getclock_after_destroy_is_rejected() {
    unsafe {
        let mut attr: libc::pthread_condattr_t = std::mem::zeroed();
        pthread_condattr_init(&mut attr);
        assert_eq!(pthread_condattr_destroy(&mut attr), 0);

        let mut clock_id: libc::clockid_t = 0;
        assert_eq!(
            pthread_condattr_getclock(&attr, &mut clock_id),
            libc::EINVAL
        );
    }
}

#[test]
fn cond_init_rejects_destroyed_attr() {
    unsafe {
        let mut attr: libc::pthread_condattr_t = std::mem::zeroed();
        let mut cond: libc::pthread_cond_t = std::mem::zeroed();
        assert_eq!(pthread_condattr_init(&mut attr), 0);
        assert_eq!(pthread_condattr_destroy(&mut attr), 0);
        assert_eq!(pthread_cond_init(&mut cond, &attr), libc::EINVAL);
    }
}

// ===========================================================================
// RWLockattr setpshared
// ===========================================================================

#[test]
fn rwlockattr_setpshared_roundtrip() {
    unsafe {
        let mut attr: libc::pthread_rwlockattr_t = std::mem::zeroed();
        pthread_rwlockattr_init(&mut attr);

        assert_eq!(
            pthread_rwlockattr_setpshared(&mut attr, libc::PTHREAD_PROCESS_PRIVATE),
            0
        );
        let mut val: c_int = -1;
        assert_eq!(pthread_rwlockattr_getpshared(&attr, &mut val), 0);
        assert_eq!(val, libc::PTHREAD_PROCESS_PRIVATE);

        pthread_rwlockattr_destroy(&mut attr);
    }
}

#[test]
fn rwlockattr_getpshared_after_destroy_is_rejected() {
    unsafe {
        let mut attr: libc::pthread_rwlockattr_t = std::mem::zeroed();
        assert_eq!(pthread_rwlockattr_init(&mut attr), 0);
        assert_eq!(pthread_rwlockattr_destroy(&mut attr), 0);

        let mut val: c_int = -1;
        assert_eq!(pthread_rwlockattr_getpshared(&attr, &mut val), libc::EINVAL);
    }
}

// ===========================================================================
// Barrierattr setpshared
// ===========================================================================

#[test]
fn barrierattr_setpshared_roundtrip() {
    unsafe {
        let mut attr: libc::pthread_barrierattr_t = std::mem::zeroed();
        pthread_barrierattr_init(&mut attr);

        assert_eq!(
            pthread_barrierattr_setpshared(&mut attr, libc::PTHREAD_PROCESS_PRIVATE),
            0
        );
        let mut val: c_int = -1;
        assert_eq!(pthread_barrierattr_getpshared(&attr, &mut val), 0);
        assert_eq!(val, libc::PTHREAD_PROCESS_PRIVATE);

        pthread_barrierattr_destroy(&mut attr);
    }
}

#[test]
fn barrierattr_getpshared_after_destroy_is_rejected() {
    unsafe {
        let mut attr: libc::pthread_barrierattr_t = std::mem::zeroed();
        assert_eq!(pthread_barrierattr_init(&mut attr), 0);
        assert_eq!(pthread_barrierattr_destroy(&mut attr), 0);

        let mut val: c_int = -1;
        assert_eq!(
            pthread_barrierattr_getpshared(&attr, &mut val),
            libc::EINVAL
        );
    }
}

#[test]
fn barrier_init_rejects_destroyed_attr() {
    unsafe {
        let mut attr: libc::pthread_barrierattr_t = std::mem::zeroed();
        let mut barrier: libc::pthread_barrier_t = std::mem::zeroed();
        assert_eq!(pthread_barrierattr_init(&mut attr), 0);
        assert_eq!(pthread_barrierattr_destroy(&mut attr), 0);
        assert_eq!(
            pthread_barrier_init(
                &mut barrier as *mut _ as *mut c_void,
                &attr as *const _ as *mut _,
                1
            ),
            libc::EINVAL
        );
    }
}

#[test]
fn barrier_init_rejects_process_shared_attr() {
    unsafe {
        let mut attr: libc::pthread_barrierattr_t = std::mem::zeroed();
        let mut barrier: libc::pthread_barrier_t = std::mem::zeroed();
        assert_eq!(pthread_barrierattr_init(&mut attr), 0);
        assert_eq!(
            pthread_barrierattr_setpshared(&mut attr, libc::PTHREAD_PROCESS_SHARED),
            0
        );
        assert_eq!(
            pthread_barrier_init(
                &mut barrier as *mut _ as *mut c_void,
                &attr as *const _ as *mut _,
                1
            ),
            libc::EINVAL
        );
        assert_eq!(pthread_barrierattr_destroy(&mut attr), 0);
    }
}

// ===========================================================================
// pthread_mutex_timedlock
// ===========================================================================

#[test]
fn mutex_timedlock_succeeds_when_unlocked() {
    unsafe {
        let mut mutex: libc::pthread_mutex_t = std::mem::zeroed();
        pthread_mutex_init(&mut mutex, ptr::null());

        let mut ts: libc::timespec = std::mem::zeroed();
        libc::clock_gettime(libc::CLOCK_REALTIME, &mut ts);
        ts.tv_sec += 1; // 1 second from now

        let rc = pthread_mutex_timedlock(&mut mutex, &ts);
        assert_eq!(rc, 0, "timedlock on unlocked mutex should succeed");
        pthread_mutex_unlock(&mut mutex);
        pthread_mutex_destroy(&mut mutex);
    }
}

#[test]
fn mutex_timedlock_times_out() {
    unsafe {
        let mut mutex: libc::pthread_mutex_t = std::mem::zeroed();
        let mut attr: libc::pthread_mutexattr_t = std::mem::zeroed();
        pthread_mutexattr_init(&mut attr);
        // Use ERRORCHECK to prevent recursive locking
        pthread_mutexattr_settype(&mut attr, libc::PTHREAD_MUTEX_ERRORCHECK);
        pthread_mutex_init(&mut mutex, &attr);
        pthread_mutexattr_destroy(&mut attr);

        pthread_mutex_lock(&mut mutex);

        // Try timedlock with a time already in the past
        let ts = libc::timespec {
            tv_sec: 0,
            tv_nsec: 0,
        };
        let rc = pthread_mutex_timedlock(&mut mutex, &ts);
        assert_eq!(
            rc,
            libc::EDEADLK,
            "errorcheck timedlock by the owning thread should return EDEADLK"
        );

        pthread_mutex_unlock(&mut mutex);
        pthread_mutex_destroy(&mut mutex);
    }
}

#[test]
fn mutex_timedlock_rejects_invalid_abstime_nanoseconds() {
    unsafe {
        let mut mutex: libc::pthread_mutex_t = std::mem::zeroed();
        assert_eq!(pthread_mutex_init(&mut mutex, ptr::null()), 0);

        let ts = libc::timespec {
            tv_sec: 1,
            tv_nsec: 1_000_000_000,
        };
        assert_eq!(pthread_mutex_timedlock(&mut mutex, &ts), libc::EINVAL);

        assert_eq!(pthread_mutex_destroy(&mut mutex), 0);
    }
}

#[test]
fn mutex_timedlock_delegates_for_host_errorcheck_mutex() {
    unsafe {
        let mut attr: libc::pthread_mutexattr_t = std::mem::zeroed();
        assert_eq!(libc::pthread_mutexattr_init(&mut attr), 0);
        assert_eq!(
            libc::pthread_mutexattr_settype(&mut attr, libc::PTHREAD_MUTEX_ERRORCHECK),
            0
        );

        let mut mutex: libc::pthread_mutex_t = std::mem::zeroed();
        assert_eq!(libc::pthread_mutex_init(&mut mutex, &attr), 0);
        assert_eq!(libc::pthread_mutexattr_destroy(&mut attr), 0);
        assert_eq!(libc::pthread_mutex_lock(&mut mutex), 0);

        let ts = libc::timespec {
            tv_sec: 0,
            tv_nsec: 0,
        };
        assert_eq!(
            pthread_mutex_timedlock(&mut mutex, &ts),
            libc::EDEADLK,
            "host-managed errorcheck mutexes must stay on the host timedlock path"
        );

        assert_eq!(libc::pthread_mutex_unlock(&mut mutex), 0);
        assert_eq!(libc::pthread_mutex_destroy(&mut mutex), 0);
    }
}

#[test]
fn mutex_timedlock_future_deadline_times_out_before_unlock() {
    unsafe {
        let mut mutex: libc::pthread_mutex_t = std::mem::zeroed();
        let mut attr: libc::pthread_mutexattr_t = std::mem::zeroed();
        assert_eq!(pthread_mutexattr_init(&mut attr), 0);
        assert_eq!(pthread_mutex_init(&mut mutex, &attr), 0);
        assert_eq!(pthread_mutexattr_destroy(&mut attr), 0);

        let mut ctx = TimedMutexCtx {
            mutex: &mut mutex,
            ready: AtomicI32::new(0),
        };
        let mut thr: libc::pthread_t = 0;
        assert_eq!(
            pthread_create(
                &mut thr,
                ptr::null(),
                Some(hold_mutex_briefly),
                (&mut ctx as *mut TimedMutexCtx).cast::<c_void>(),
            ),
            0
        );

        while ctx.ready.load(Ordering::Acquire) == 0 {
            std::thread::sleep(std::time::Duration::from_millis(1));
        }

        let start = std::time::Instant::now();
        let mut ts: libc::timespec = std::mem::zeroed();
        libc::clock_gettime(libc::CLOCK_REALTIME, &mut ts);
        ts.tv_nsec += 50_000_000;
        if ts.tv_nsec >= 1_000_000_000 {
            ts.tv_sec += 1;
            ts.tv_nsec -= 1_000_000_000;
        }

        assert_eq!(pthread_mutex_timedlock(&mut mutex, &ts), libc::ETIMEDOUT);
        assert!(
            start.elapsed() < std::time::Duration::from_millis(150),
            "timedlock should time out near the requested deadline, not wait for unlock"
        );

        assert_eq!(pthread_join(thr, ptr::null_mut()), 0);
        assert_eq!(pthread_mutex_destroy(&mut mutex), 0);
    }
}

#[test]
fn mutex_clocklock_rejects_invalid_clockid() {
    unsafe {
        let mut mutex: libc::pthread_mutex_t = std::mem::zeroed();
        assert_eq!(pthread_mutex_init(&mut mutex, ptr::null()), 0);

        let mut ts: libc::timespec = std::mem::zeroed();
        libc::clock_gettime(libc::CLOCK_REALTIME, &mut ts);
        ts.tv_sec += 1;

        assert_eq!(
            pthread_mutex_clocklock(&mut mutex, -1, &ts),
            libc::EINVAL,
            "invalid clock ids should be rejected instead of being converted into bogus deadlines"
        );

        assert_eq!(pthread_mutex_destroy(&mut mutex), 0);
    }
}

#[test]
fn mutex_timedlock_recursive_relocks_for_owner() {
    unsafe {
        let mut mutex: libc::pthread_mutex_t = std::mem::zeroed();
        let mut attr: libc::pthread_mutexattr_t = std::mem::zeroed();
        pthread_mutexattr_init(&mut attr);
        pthread_mutexattr_settype(&mut attr, libc::PTHREAD_MUTEX_RECURSIVE);
        pthread_mutex_init(&mut mutex, &attr);
        pthread_mutexattr_destroy(&mut attr);

        assert_eq!(pthread_mutex_lock(&mut mutex), 0);

        let mut ts: libc::timespec = std::mem::zeroed();
        libc::clock_gettime(libc::CLOCK_REALTIME, &mut ts);
        ts.tv_sec += 1;

        assert_eq!(
            pthread_mutex_timedlock(&mut mutex, &ts),
            0,
            "recursive timedlock by the owning thread should succeed"
        );

        assert_eq!(pthread_mutex_unlock(&mut mutex), 0);
        assert_eq!(pthread_mutex_unlock(&mut mutex), 0);
        assert_eq!(pthread_mutex_destroy(&mut mutex), 0);
    }
}

// ===========================================================================
// pthread_rwlock_timedrdlock / timedwrlock
// ===========================================================================

#[test]
fn rwlock_timedrdlock_succeeds() {
    unsafe {
        let mut rwl: libc::pthread_rwlock_t = std::mem::zeroed();
        pthread_rwlock_init(&mut rwl, ptr::null());

        let mut ts: libc::timespec = std::mem::zeroed();
        libc::clock_gettime(libc::CLOCK_REALTIME, &mut ts);
        ts.tv_sec += 1;

        let rc = pthread_rwlock_timedrdlock(&mut rwl, &ts);
        assert_eq!(rc, 0);
        pthread_rwlock_unlock(&mut rwl);
        pthread_rwlock_destroy(&mut rwl);
    }
}

#[test]
fn rwlock_timedwrlock_succeeds() {
    unsafe {
        let mut rwl: libc::pthread_rwlock_t = std::mem::zeroed();
        pthread_rwlock_init(&mut rwl, ptr::null());

        let mut ts: libc::timespec = std::mem::zeroed();
        libc::clock_gettime(libc::CLOCK_REALTIME, &mut ts);
        ts.tv_sec += 1;

        let rc = pthread_rwlock_timedwrlock(&mut rwl, &ts);
        assert_eq!(rc, 0);
        pthread_rwlock_unlock(&mut rwl);
        pthread_rwlock_destroy(&mut rwl);
    }
}

#[test]
fn rwlock_clockrdlock_rejects_invalid_clockid() {
    unsafe {
        let mut rwl: libc::pthread_rwlock_t = std::mem::zeroed();
        assert_eq!(pthread_rwlock_init(&mut rwl, ptr::null()), 0);

        let mut ts: libc::timespec = std::mem::zeroed();
        libc::clock_gettime(libc::CLOCK_REALTIME, &mut ts);
        ts.tv_sec += 1;

        assert_eq!(pthread_rwlock_clockrdlock(&mut rwl, -1, &ts), libc::EINVAL);
        assert_eq!(pthread_rwlock_destroy(&mut rwl), 0);
    }
}

#[test]
fn rwlock_clockwrlock_rejects_invalid_clockid() {
    unsafe {
        let mut rwl: libc::pthread_rwlock_t = std::mem::zeroed();
        assert_eq!(pthread_rwlock_init(&mut rwl, ptr::null()), 0);

        let mut ts: libc::timespec = std::mem::zeroed();
        libc::clock_gettime(libc::CLOCK_REALTIME, &mut ts);
        ts.tv_sec += 1;

        assert_eq!(pthread_rwlock_clockwrlock(&mut rwl, -1, &ts), libc::EINVAL);
        assert_eq!(pthread_rwlock_destroy(&mut rwl), 0);
    }
}

// ===========================================================================
// pthread_cond_timedwait (immediate timeout)
// ===========================================================================

#[test]
fn cond_timedwait_times_out() {
    unsafe {
        let mut mutex: libc::pthread_mutex_t = std::mem::zeroed();
        let mut cond: libc::pthread_cond_t = std::mem::zeroed();
        pthread_mutex_init(&mut mutex, ptr::null());
        pthread_cond_init(&mut cond, ptr::null());

        pthread_mutex_lock(&mut mutex);

        // Use a time in the past to trigger immediate timeout
        let ts = libc::timespec {
            tv_sec: 0,
            tv_nsec: 0,
        };
        let rc = pthread_cond_timedwait(&mut cond, &mut mutex, &ts);
        assert_eq!(
            rc,
            libc::ETIMEDOUT,
            "timedwait with past time should return ETIMEDOUT"
        );

        pthread_mutex_unlock(&mut mutex);
        pthread_cond_destroy(&mut cond);
        pthread_mutex_destroy(&mut mutex);
    }
}

#[test]
fn cond_timedwait_rejects_invalid_abstime_nanoseconds() {
    unsafe {
        let mut mutex: libc::pthread_mutex_t = std::mem::zeroed();
        let mut cond: libc::pthread_cond_t = std::mem::zeroed();
        assert_eq!(pthread_mutex_init(&mut mutex, ptr::null()), 0);
        assert_eq!(pthread_cond_init(&mut cond, ptr::null()), 0);
        assert_eq!(pthread_mutex_lock(&mut mutex), 0);

        let ts = libc::timespec {
            tv_sec: 1,
            tv_nsec: 1_000_000_000,
        };
        assert_eq!(
            pthread_cond_timedwait(&mut cond, &mut mutex, &ts),
            libc::EINVAL
        );

        assert_eq!(pthread_mutex_unlock(&mut mutex), 0);
        assert_eq!(pthread_cond_destroy(&mut cond), 0);
        assert_eq!(pthread_mutex_destroy(&mut mutex), 0);
    }
}

#[test]
fn cond_timedwait_rejects_null_cond_before_host_fallback() {
    unsafe {
        let mut mutex: libc::pthread_mutex_t = std::mem::zeroed();
        assert_eq!(pthread_mutex_init(&mut mutex, ptr::null()), 0);
        assert_eq!(pthread_mutex_lock(&mut mutex), 0);

        let ts = libc::timespec {
            tv_sec: 1,
            tv_nsec: 0,
        };
        assert_eq!(
            pthread_cond_timedwait(ptr::null_mut(), &mut mutex, &ts),
            libc::EINVAL
        );

        assert_eq!(pthread_mutex_unlock(&mut mutex), 0);
        assert_eq!(pthread_mutex_destroy(&mut mutex), 0);
    }
}

#[test]
fn cond_clockwait_rejects_invalid_clockid() {
    unsafe {
        let mut mutex: libc::pthread_mutex_t = std::mem::zeroed();
        let mut cond: libc::pthread_cond_t = std::mem::zeroed();
        assert_eq!(pthread_mutex_init(&mut mutex, ptr::null()), 0);
        assert_eq!(pthread_cond_init(&mut cond, ptr::null()), 0);
        assert_eq!(pthread_mutex_lock(&mut mutex), 0);

        let mut ts: libc::timespec = std::mem::zeroed();
        libc::clock_gettime(libc::CLOCK_REALTIME, &mut ts);
        ts.tv_sec += 1;

        assert_eq!(
            pthread_cond_clockwait(&mut cond, &mut mutex, -1, &ts),
            libc::EINVAL
        );

        assert_eq!(pthread_mutex_unlock(&mut mutex), 0);
        assert_eq!(pthread_cond_destroy(&mut cond), 0);
        assert_eq!(pthread_mutex_destroy(&mut mutex), 0);
    }
}

// ===========================================================================
// pthread_getattr_np
// ===========================================================================

#[test]
fn getattr_np_returns_valid_info() {
    unsafe {
        let self_id = pthread_self();
        let mut attr: libc::pthread_attr_t = std::mem::zeroed();
        let rc = pthread_getattr_np(self_id, &mut attr);
        assert_eq!(rc, 0, "pthread_getattr_np(self) should succeed");
        let mut stack_size: usize = 0;
        pthread_attr_getstacksize(&attr, &mut stack_size);
        assert!(stack_size > 0, "stack size should be > 0");
        pthread_attr_destroy(&mut attr);
    }
}

#[test]
fn getattr_np_preserves_managed_thread_stacksize() {
    unsafe {
        let _guard = ThreadingForceNativeGuard {
            previous: pthread_threading_swap_force_native_for_tests(),
        };
        let mut attr: libc::pthread_attr_t = std::mem::zeroed();
        assert_eq!(pthread_attr_init(&mut attr), 0);
        assert_eq!(pthread_attr_setstacksize(&mut attr, 4 * 1024 * 1024), 0);

        let mut thr: libc::pthread_t = 0;
        assert_eq!(
            pthread_create(
                &mut thr,
                &attr,
                Some(getattr_self_stacksize),
                ptr::null_mut()
            ),
            0
        );

        let mut retval: *mut c_void = ptr::null_mut();
        assert_eq!(pthread_join(thr, &mut retval), 0);
        assert_eq!(retval as usize, 4 * 1024 * 1024);
        assert_eq!(pthread_attr_destroy(&mut attr), 0);
    }
}

#[test]
fn getattr_np_rejects_joined_thread_handle() {
    unsafe {
        let thr: libc::pthread_t;
        {
            let _guard = ThreadingForceNativeGuard {
                previous: pthread_threading_swap_force_native_for_tests(),
            };
            let mut created: libc::pthread_t = 0;
            assert_eq!(
                pthread_create(
                    &mut created,
                    ptr::null(),
                    Some(noop_thread),
                    ptr::null_mut()
                ),
                0
            );
            assert_eq!(pthread_join(created, ptr::null_mut()), 0);
            thr = created;
        }

        let mut attr: libc::pthread_attr_t = std::mem::zeroed();
        assert_eq!(
            pthread_getattr_np(thr, &mut attr),
            libc::ESRCH,
            "joined thread handle should no longer resolve"
        );
    }
}

#[test]
fn getattr_np_returns_valid_info_for_live_detached_managed_thread_after_restoring_host_mode() {
    unsafe {
        let thr: libc::pthread_t;
        {
            let _guard = ThreadingForceNativeGuard {
                previous: pthread_threading_swap_force_native_for_tests(),
            };
            let mut created: libc::pthread_t = 0;
            assert_eq!(
                pthread_create(
                    &mut created,
                    ptr::null(),
                    Some(sleepy_thread),
                    ptr::null_mut()
                ),
                0
            );
            thr = created;
        }

        assert_eq!(pthread_detach(thr), 0);

        let mut attr: libc::pthread_attr_t = std::mem::zeroed();
        assert_eq!(pthread_getattr_np(thr, &mut attr), 0);

        let mut detach_state = 0;
        assert_eq!(pthread_attr_getdetachstate(&attr, &mut detach_state), 0);
        assert_eq!(detach_state, libc::PTHREAD_CREATE_DETACHED);

        let mut stack_size = 0usize;
        assert_eq!(pthread_attr_getstacksize(&attr, &mut stack_size), 0);
        assert!(stack_size >= 2 * 1024 * 1024);

        assert_eq!(pthread_attr_destroy(&mut attr), 0);
        std::thread::sleep(std::time::Duration::from_millis(250));
    }
}

// ---------------------------------------------------------------------------
// pthread_getattr_np — /proc/self/maps fallback (bd-zh1y.1.1)
// ---------------------------------------------------------------------------

#[test]
fn getattr_np_main_thread_native_via_proc_maps() {
    // The main test thread is NOT created by pthread_create, so there is no
    // ThreadHandle in the registry. With FORCE_NATIVE_THREADING the host
    // delegation path is skipped. The implementation must fall back to
    // /proc/self/task/<tid>/maps parsing to discover the stack boundaries.
    unsafe {
        let _guard = ThreadingForceNativeGuard {
            previous: pthread_threading_swap_force_native_for_tests(),
        };
        let self_id = pthread_self();
        let mut attr: libc::pthread_attr_t = std::mem::zeroed();
        let rc = pthread_getattr_np(self_id, &mut attr);
        assert_eq!(
            rc, 0,
            "pthread_getattr_np should succeed for main thread via /proc maps"
        );

        let mut stack_size: usize = 0;
        assert_eq!(pthread_attr_getstacksize(&attr, &mut stack_size), 0);
        // The main thread typically has an 8 MiB stack (Linux default).
        // At minimum it must be larger than PTHREAD_STACK_MIN (16384).
        assert!(
            stack_size >= 16384,
            "main thread stack_size ({stack_size}) should be >= PTHREAD_STACK_MIN"
        );

        let mut stack_addr: *mut c_void = ptr::null_mut();
        let mut stack_addr_size: usize = 0;
        assert_eq!(
            pthread_attr_getstack(&attr, &mut stack_addr, &mut stack_addr_size),
            0
        );
        assert!(
            !stack_addr.is_null(),
            "stack_addr should be non-null for main thread"
        );
        assert!(
            stack_addr_size >= 16384,
            "stack from getstack ({stack_addr_size}) should be >= PTHREAD_STACK_MIN"
        );

        let mut detach_state: c_int = -1;
        assert_eq!(pthread_attr_getdetachstate(&attr, &mut detach_state), 0);
        assert_eq!(
            detach_state,
            libc::PTHREAD_CREATE_JOINABLE,
            "main thread should report JOINABLE"
        );

        assert_eq!(pthread_attr_destroy(&mut attr), 0);
    }
}

#[test]
fn getattr_np_spawned_thread_native_via_proc_maps() {
    // A thread spawned via std::thread (not our pthread_create) should also
    // work via the /proc maps fallback when forced native.
    let result = std::thread::spawn(|| unsafe {
        let _guard = ThreadingForceNativeGuard {
            previous: pthread_threading_swap_force_native_for_tests(),
        };
        let self_id = pthread_self();
        let mut attr: libc::pthread_attr_t = std::mem::zeroed();
        let rc = pthread_getattr_np(self_id, &mut attr);
        assert_eq!(
            rc, 0,
            "pthread_getattr_np should succeed for std::thread via /proc maps"
        );

        let mut stack_size: usize = 0;
        assert_eq!(pthread_attr_getstacksize(&attr, &mut stack_size), 0);
        assert!(
            stack_size >= 16384,
            "spawned thread stack_size ({stack_size}) should be >= PTHREAD_STACK_MIN"
        );
        assert_eq!(pthread_attr_destroy(&mut attr), 0);
        stack_size
    })
    .join()
    .expect("thread should not panic");
    assert!(result >= 16384);
}

// ===========================================================================
// pthread_gettid_np
// ===========================================================================

#[test]
fn gettid_np_returns_tid() {
    unsafe {
        let self_id = pthread_self();
        let tid = pthread_gettid_np(self_id);
        assert!(
            tid > 0,
            "gettid_np(self) should return a positive tid, got {tid}"
        );
    }
}

#[test]
fn gettid_np_returns_tid_for_live_thread() {
    unsafe {
        let mut thr: libc::pthread_t = 0;
        assert_eq!(
            pthread_create(
                &mut thr,
                ptr::null(),
                Some(cancellable_thread),
                ptr::null_mut()
            ),
            0
        );
        std::thread::sleep(std::time::Duration::from_millis(20));

        let tid = pthread_gettid_np(thr);
        assert!(
            tid > 0,
            "gettid_np(thread) should return a positive tid for a live thread, got {tid}"
        );

        assert_eq!(pthread_cancel(thr), 0);
        assert_eq!(pthread_join(thr, ptr::null_mut()), 0);
    }
}

#[test]
fn gettid_np_joined_thread_returns_negative_one() {
    unsafe {
        let thr: libc::pthread_t;
        {
            let _guard = ThreadingForceNativeGuard {
                previous: pthread_threading_swap_force_native_for_tests(),
            };
            let mut created: libc::pthread_t = 0;
            assert_eq!(
                pthread_create(
                    &mut created,
                    ptr::null(),
                    Some(noop_thread),
                    ptr::null_mut()
                ),
                0
            );
            assert_eq!(pthread_join(created, ptr::null_mut()), 0);
            thr = created;
        }
        assert_eq!(
            pthread_gettid_np(thr),
            -1,
            "joined thread handle should not decode to a stale positive TID"
        );
    }
}

#[test]
fn gettid_np_returns_tid_for_live_detached_managed_thread_after_restoring_host_mode() {
    unsafe {
        let thr: libc::pthread_t;
        {
            let _guard = ThreadingForceNativeGuard {
                previous: pthread_threading_swap_force_native_for_tests(),
            };
            let mut created: libc::pthread_t = 0;
            assert_eq!(
                pthread_create(
                    &mut created,
                    ptr::null(),
                    Some(sleepy_thread),
                    ptr::null_mut()
                ),
                0
            );
            thr = created;
        }

        assert_eq!(pthread_detach(thr), 0);
        let tid = pthread_gettid_np(thr);
        assert!(
            tid > 0,
            "detached live managed thread should still expose a positive tid"
        );
        assert_eq!(pthread_kill(thr, 0), 0);

        std::thread::sleep(std::time::Duration::from_millis(250));
        assert_eq!(pthread_kill(thr, 0), libc::ESRCH);
    }
}

// ===========================================================================
// pthread_tryjoin_np
// ===========================================================================

#[test]
fn tryjoin_np_on_finished_thread() {
    unsafe {
        let mut thr: libc::pthread_t = 0;
        let rc = pthread_create(&mut thr, ptr::null(), Some(noop_thread), ptr::null_mut());
        assert_eq!(rc, 0);

        let mut retval: *mut c_void = ptr::null_mut();
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(1);
        loop {
            match pthread_tryjoin_np(thr, &mut retval) {
                0 => break,
                rc if rc == libc::EBUSY && std::time::Instant::now() < deadline => {
                    std::thread::sleep(std::time::Duration::from_millis(10));
                }
                rc => unreachable!(
                    // ubs:ignore — loop should exit via success or timeout
                    "pthread_tryjoin_np should eventually succeed, got {rc}"
                ),
            }
        }
    }
}

#[test]
fn tryjoin_np_rejects_self_join_for_managed_thread() {
    unsafe {
        let _guard = ThreadingForceNativeGuard {
            previous: pthread_threading_swap_force_native_for_tests(),
        };
        let mut thr: libc::pthread_t = 0;
        assert_eq!(
            pthread_create(
                &mut thr,
                ptr::null(),
                Some(tryjoin_self_result),
                ptr::null_mut()
            ),
            0
        );

        let mut retval: *mut c_void = ptr::null_mut();
        assert_eq!(pthread_join(thr, &mut retval), 0);
        assert_eq!(retval as usize as c_int, libc::EDEADLK);
    }
}

#[test]
fn tryjoin_np_joined_managed_thread_returns_esrch_after_restoring_host_mode() {
    unsafe {
        let thr: libc::pthread_t;
        {
            let _guard = ThreadingForceNativeGuard {
                previous: pthread_threading_swap_force_native_for_tests(),
            };
            let mut created: libc::pthread_t = 0;
            assert_eq!(
                pthread_create(
                    &mut created,
                    ptr::null(),
                    Some(noop_thread),
                    ptr::null_mut()
                ),
                0
            );
            assert_eq!(pthread_join(created, ptr::null_mut()), 0);
            thr = created;
        }

        let mut retval: *mut c_void = ptr::null_mut();
        assert_eq!(pthread_tryjoin_np(thr, &mut retval), libc::ESRCH);
    }
}

#[test]
fn tryjoin_np_detached_managed_thread_returns_einval_after_restoring_host_mode() {
    unsafe {
        let thr: libc::pthread_t;
        {
            let _guard = ThreadingForceNativeGuard {
                previous: pthread_threading_swap_force_native_for_tests(),
            };
            let mut created: libc::pthread_t = 0;
            assert_eq!(
                pthread_create(
                    &mut created,
                    ptr::null(),
                    Some(sleepy_thread),
                    ptr::null_mut()
                ),
                0
            );
            thr = created;
        }

        assert_eq!(pthread_detach(thr), 0);
        let mut retval: *mut c_void = ptr::null_mut();
        assert_eq!(pthread_tryjoin_np(thr, &mut retval), libc::EINVAL);
        std::thread::sleep(std::time::Duration::from_millis(250));
    }
}

#[test]
fn timedjoin_np_rejects_self_join_for_managed_thread() {
    unsafe {
        let _guard = ThreadingForceNativeGuard {
            previous: pthread_threading_swap_force_native_for_tests(),
        };
        let mut thr: libc::pthread_t = 0;
        assert_eq!(
            pthread_create(
                &mut thr,
                ptr::null(),
                Some(timedjoin_self_result),
                ptr::null_mut()
            ),
            0
        );

        let mut retval: *mut c_void = ptr::null_mut();
        assert_eq!(pthread_join(thr, &mut retval), 0);
        assert_eq!(retval as usize as c_int, libc::EDEADLK);
    }
}

#[test]
fn timedjoin_np_joined_managed_thread_returns_esrch_after_restoring_host_mode() {
    unsafe {
        let thr: libc::pthread_t;
        {
            let _guard = ThreadingForceNativeGuard {
                previous: pthread_threading_swap_force_native_for_tests(),
            };
            let mut created: libc::pthread_t = 0;
            assert_eq!(
                pthread_create(
                    &mut created,
                    ptr::null(),
                    Some(noop_thread),
                    ptr::null_mut()
                ),
                0
            );
            assert_eq!(pthread_join(created, ptr::null_mut()), 0);
            thr = created;
        }

        let ts = libc::timespec {
            tv_sec: 1,
            tv_nsec: 0,
        };
        assert_eq!(pthread_timedjoin_np(thr, ptr::null_mut(), &ts), libc::ESRCH);
    }
}

#[test]
fn timedjoin_np_detached_managed_thread_returns_einval_after_restoring_host_mode() {
    unsafe {
        let thr: libc::pthread_t;
        {
            let _guard = ThreadingForceNativeGuard {
                previous: pthread_threading_swap_force_native_for_tests(),
            };
            let mut created: libc::pthread_t = 0;
            assert_eq!(
                pthread_create(
                    &mut created,
                    ptr::null(),
                    Some(sleepy_thread),
                    ptr::null_mut()
                ),
                0
            );
            thr = created;
        }

        assert_eq!(pthread_detach(thr), 0);
        let mut ts: libc::timespec = std::mem::zeroed();
        libc::clock_gettime(libc::CLOCK_REALTIME, &mut ts);
        ts.tv_sec += 1;
        assert_eq!(
            pthread_timedjoin_np(thr, ptr::null_mut(), &ts),
            libc::EINVAL
        );
        std::thread::sleep(std::time::Duration::from_millis(250));
    }
}

#[test]
fn timedjoin_np_times_out_before_thread_exit() {
    unsafe {
        let _guard = ThreadingForceNativeGuard {
            previous: pthread_threading_swap_force_native_for_tests(),
        };
        let mut thr: libc::pthread_t = 0;
        assert_eq!(
            pthread_create(&mut thr, ptr::null(), Some(sleepy_thread), ptr::null_mut()),
            0
        );

        let start = std::time::Instant::now();
        let mut ts: libc::timespec = std::mem::zeroed();
        libc::clock_gettime(libc::CLOCK_REALTIME, &mut ts);
        ts.tv_nsec += 50_000_000;
        if ts.tv_nsec >= 1_000_000_000 {
            ts.tv_sec += 1;
            ts.tv_nsec -= 1_000_000_000;
        }

        assert_eq!(
            pthread_timedjoin_np(thr, ptr::null_mut(), &ts),
            libc::ETIMEDOUT
        );
        assert!(
            start.elapsed() < std::time::Duration::from_millis(150),
            "timedjoin should time out near the requested deadline, not wait for thread exit"
        );

        assert_eq!(pthread_join(thr, ptr::null_mut()), 0);
    }
}

#[test]
fn timedjoin_np_rejects_invalid_abstime_nanoseconds() {
    unsafe {
        let _guard = ThreadingForceNativeGuard {
            previous: pthread_threading_swap_force_native_for_tests(),
        };
        let mut thr: libc::pthread_t = 0;
        assert_eq!(
            pthread_create(&mut thr, ptr::null(), Some(sleepy_thread), ptr::null_mut()),
            0
        );

        let ts = libc::timespec {
            tv_sec: 1,
            tv_nsec: 1_000_000_000,
        };
        assert_eq!(
            pthread_timedjoin_np(thr, ptr::null_mut(), &ts),
            libc::EINVAL
        );
        assert_eq!(pthread_join(thr, ptr::null_mut()), 0);
    }
}

#[test]
fn clockjoin_np_joined_managed_thread_returns_esrch_after_restoring_host_mode() {
    unsafe {
        let thr: libc::pthread_t;
        {
            let _guard = ThreadingForceNativeGuard {
                previous: pthread_threading_swap_force_native_for_tests(),
            };
            let mut created: libc::pthread_t = 0;
            assert_eq!(
                pthread_create(
                    &mut created,
                    ptr::null(),
                    Some(noop_thread),
                    ptr::null_mut()
                ),
                0
            );
            assert_eq!(pthread_join(created, ptr::null_mut()), 0);
            thr = created;
        }

        let ts = libc::timespec {
            tv_sec: 1,
            tv_nsec: 0,
        };
        assert_eq!(
            pthread_clockjoin_np(thr, ptr::null_mut(), libc::CLOCK_REALTIME, &ts),
            libc::ESRCH
        );
    }
}

#[test]
fn clockjoin_np_detached_managed_thread_returns_einval_after_restoring_host_mode() {
    unsafe {
        let thr: libc::pthread_t;
        {
            let _guard = ThreadingForceNativeGuard {
                previous: pthread_threading_swap_force_native_for_tests(),
            };
            let mut created: libc::pthread_t = 0;
            assert_eq!(
                pthread_create(
                    &mut created,
                    ptr::null(),
                    Some(sleepy_thread),
                    ptr::null_mut()
                ),
                0
            );
            thr = created;
        }

        assert_eq!(pthread_detach(thr), 0);
        let mut ts: libc::timespec = std::mem::zeroed();
        libc::clock_gettime(libc::CLOCK_REALTIME, &mut ts);
        ts.tv_sec += 1;
        assert_eq!(
            pthread_clockjoin_np(thr, ptr::null_mut(), libc::CLOCK_REALTIME, &ts),
            libc::EINVAL
        );
        std::thread::sleep(std::time::Duration::from_millis(250));
    }
}

#[test]
fn clockjoin_np_rejects_invalid_clockid() {
    unsafe {
        let _guard = ThreadingForceNativeGuard {
            previous: pthread_threading_swap_force_native_for_tests(),
        };
        let mut thr: libc::pthread_t = 0;
        assert_eq!(
            pthread_create(&mut thr, ptr::null(), Some(sleepy_thread), ptr::null_mut()),
            0
        );

        let mut ts: libc::timespec = std::mem::zeroed();
        libc::clock_gettime(libc::CLOCK_REALTIME, &mut ts);
        ts.tv_sec += 1;

        assert_eq!(
            pthread_clockjoin_np(thr, ptr::null_mut(), -1, &ts),
            libc::EINVAL
        );
        assert_eq!(pthread_join(thr, ptr::null_mut()), 0);
    }
}

// ===========================================================================
// pthread_getcpuclockid
// ===========================================================================

#[test]
fn getcpuclockid_returns_valid_clock() {
    unsafe {
        let self_id = pthread_self();
        let mut clock_id: libc::clockid_t = 0;
        let rc = pthread_getcpuclockid(self_id, &mut clock_id);
        assert_eq!(rc, 0, "pthread_getcpuclockid(self) should succeed");
        // Verify we can use the clock
        let mut ts: libc::timespec = std::mem::zeroed();
        let rc2 = libc::clock_gettime(clock_id, &mut ts);
        assert_eq!(rc2, 0, "should be able to read thread CPU clock");
    }
}

#[test]
fn getcpuclockid_returns_valid_clock_for_live_thread() {
    unsafe {
        let mut thr: libc::pthread_t = 0;
        assert_eq!(
            pthread_create(
                &mut thr,
                ptr::null(),
                Some(cancellable_thread),
                ptr::null_mut()
            ),
            0
        );
        std::thread::sleep(std::time::Duration::from_millis(20));

        let mut clock_id: libc::clockid_t = 0;
        assert_eq!(
            pthread_getcpuclockid(thr, &mut clock_id),
            0,
            "pthread_getcpuclockid(thread) should succeed for a live thread"
        );

        let mut ts: libc::timespec = std::mem::zeroed();
        assert_eq!(
            libc::clock_gettime(clock_id, &mut ts),
            0,
            "should be able to read a live thread CPU clock"
        );

        assert_eq!(pthread_cancel(thr), 0);
        assert_eq!(pthread_join(thr, ptr::null_mut()), 0);
    }
}

#[test]
fn getcpuclockid_joined_thread_returns_esrch() {
    unsafe {
        let thr: libc::pthread_t;
        {
            let _guard = ThreadingForceNativeGuard {
                previous: pthread_threading_swap_force_native_for_tests(),
            };
            let mut created: libc::pthread_t = 0;
            assert_eq!(
                pthread_create(
                    &mut created,
                    ptr::null(),
                    Some(noop_thread),
                    ptr::null_mut()
                ),
                0
            );
            assert_eq!(pthread_join(created, ptr::null_mut()), 0);
            thr = created;
        }

        let mut clock_id: libc::clockid_t = 0;
        assert_eq!(
            pthread_getcpuclockid(thr, &mut clock_id),
            libc::ESRCH,
            "joined thread handle should no longer resolve to a CPU clock"
        );
    }
}

// ===========================================================================
// pthread_cancel (cancel a thread that's blocked)
// ===========================================================================

unsafe extern "C" fn cancellable_thread(_arg: *mut c_void) -> *mut c_void {
    unsafe {
        // Enable cancellation
        pthread_setcancelstate(PTHREAD_CANCEL_ENABLE, ptr::null_mut());
        pthread_setcanceltype(PTHREAD_CANCEL_DEFERRED, ptr::null_mut());
        // Sleep loop with cancellation points
        for _ in 0..100 {
            pthread_testcancel();
            std::thread::sleep(std::time::Duration::from_millis(10));
        }
        ptr::null_mut()
    }
}

#[repr(C)]
struct CancelTransitionCtx {
    ready: AtomicI32,
    go: AtomicI32,
}

struct CancelDisableCtx {
    ready: AtomicI32,
}

unsafe extern "C" fn enable_async_after_pending_cancel(arg: *mut c_void) -> *mut c_void {
    let ctx = unsafe { &*(arg as *const CancelTransitionCtx) };
    unsafe {
        pthread_setcanceltype(PTHREAD_CANCEL_ASYNCHRONOUS, ptr::null_mut());
        pthread_setcancelstate(PTHREAD_CANCEL_DISABLE, ptr::null_mut());
    }
    ctx.ready.store(1, Ordering::Release);
    while ctx.go.load(Ordering::Acquire) == 0 {
        std::thread::sleep(std::time::Duration::from_millis(1));
    }
    unsafe { pthread_setcancelstate(PTHREAD_CANCEL_ENABLE, ptr::null_mut()) };
    7usize as *mut c_void
}

unsafe extern "C" fn set_async_after_pending_cancel(arg: *mut c_void) -> *mut c_void {
    let ctx = unsafe { &*(arg as *const CancelTransitionCtx) };
    unsafe {
        pthread_setcancelstate(PTHREAD_CANCEL_ENABLE, ptr::null_mut());
        pthread_setcanceltype(PTHREAD_CANCEL_DEFERRED, ptr::null_mut());
    }
    ctx.ready.store(1, Ordering::Release);
    while ctx.go.load(Ordering::Acquire) == 0 {
        std::thread::sleep(std::time::Duration::from_millis(1));
    }
    unsafe { pthread_setcanceltype(PTHREAD_CANCEL_ASYNCHRONOUS, ptr::null_mut()) };
    9usize as *mut c_void
}

unsafe extern "C" fn host_cancel_disabled_thread(arg: *mut c_void) -> *mut c_void {
    let ctx = unsafe { &*(arg as *const CancelDisableCtx) };
    unsafe {
        pthread_setcancelstate(PTHREAD_CANCEL_DISABLE, ptr::null_mut());
        pthread_setcanceltype(PTHREAD_CANCEL_DEFERRED, ptr::null_mut());
    }
    ctx.ready.store(1, Ordering::Release);
    std::thread::sleep(std::time::Duration::from_millis(200));
    7usize as *mut c_void
}

#[test]
fn cancel_running_thread() {
    unsafe {
        let mut thr: libc::pthread_t = 0;
        let rc = pthread_create(
            &mut thr,
            ptr::null(),
            Some(cancellable_thread),
            ptr::null_mut(),
        );
        assert_eq!(rc, 0);

        std::thread::sleep(std::time::Duration::from_millis(20));

        let rc = pthread_cancel(thr);
        assert_eq!(rc, 0, "pthread_cancel should succeed for a live thread");

        let mut retval: *mut c_void = ptr::null_mut();
        assert_eq!(pthread_join(thr, &mut retval), 0);
        assert_eq!(
            retval as usize, !0usize,
            "cancelled thread should join with PTHREAD_CANCELED"
        );
    }
}

#[test]
fn enabling_async_cancellation_with_pending_cancel_exits_thread() {
    unsafe {
        let _guard = ThreadingForceNativeGuard {
            previous: pthread_threading_swap_force_native_for_tests(),
        };
        let mut ctx = CancelTransitionCtx {
            ready: AtomicI32::new(0),
            go: AtomicI32::new(0),
        };
        let mut thr: libc::pthread_t = 0;
        assert_eq!(
            pthread_create(
                &mut thr,
                ptr::null(),
                Some(enable_async_after_pending_cancel),
                (&mut ctx as *mut CancelTransitionCtx).cast::<c_void>(),
            ),
            0
        );

        while ctx.ready.load(Ordering::Acquire) == 0 {
            std::thread::sleep(std::time::Duration::from_millis(1));
        }

        assert_eq!(pthread_cancel(thr), 0);
        ctx.go.store(1, Ordering::Release);

        let mut retval: *mut c_void = ptr::null_mut();
        assert_eq!(pthread_join(thr, &mut retval), 0);
        assert_eq!(retval as usize, !0usize);
    }
}

#[test]
fn switching_to_async_cancellation_with_pending_cancel_exits_thread() {
    unsafe {
        let _guard = ThreadingForceNativeGuard {
            previous: pthread_threading_swap_force_native_for_tests(),
        };
        let mut ctx = CancelTransitionCtx {
            ready: AtomicI32::new(0),
            go: AtomicI32::new(0),
        };
        let mut thr: libc::pthread_t = 0;
        assert_eq!(
            pthread_create(
                &mut thr,
                ptr::null(),
                Some(set_async_after_pending_cancel),
                (&mut ctx as *mut CancelTransitionCtx).cast::<c_void>(),
            ),
            0
        );

        while ctx.ready.load(Ordering::Acquire) == 0 {
            std::thread::sleep(std::time::Duration::from_millis(1));
        }

        assert_eq!(pthread_cancel(thr), 0);
        ctx.go.store(1, Ordering::Release);

        let mut retval: *mut c_void = ptr::null_mut();
        assert_eq!(pthread_join(thr, &mut retval), 0);
        assert_eq!(retval as usize, !0usize);
    }
}

#[test]
fn host_backed_thread_with_cancel_disabled_survives_external_cancel() {
    unsafe {
        let mut ctx = CancelDisableCtx {
            ready: AtomicI32::new(0),
        };
        let mut thr: libc::pthread_t = 0;
        assert_eq!(
            pthread_create(
                &mut thr,
                ptr::null(),
                Some(host_cancel_disabled_thread),
                (&mut ctx as *mut CancelDisableCtx).cast::<c_void>(),
            ),
            0
        );

        while ctx.ready.load(Ordering::Acquire) == 0 {
            std::thread::sleep(std::time::Duration::from_millis(1));
        }

        assert_eq!(pthread_cancel(thr), 0);

        let mut retval: *mut c_void = ptr::null_mut();
        assert_eq!(pthread_join(thr, &mut retval), 0);
        assert_eq!(retval as usize, 7);
    }
}

// ===========================================================================
// pthread_setaffinity_np
// ===========================================================================

#[test]
fn setaffinity_np_to_allowed_cpu() {
    unsafe {
        let self_id = pthread_self();
        let cpu = first_allowed_cpu();
        let mut cpuset: libc::cpu_set_t = std::mem::zeroed();
        libc::CPU_SET(cpu, &mut cpuset);

        let rc = pthread_setaffinity_np(self_id, std::mem::size_of::<libc::cpu_set_t>(), &cpuset);
        assert_eq!(rc, 0, "pthread_setaffinity_np should succeed for self");
    }
}

// ===========================================================================
// pthread_getattr_default_np / pthread_setattr_default_np
// ===========================================================================

#[test]
fn getattr_default_np_succeeds() {
    unsafe {
        let mut attr: libc::pthread_attr_t = std::mem::zeroed();
        let rc = pthread_getattr_default_np(&mut attr);
        assert_eq!(rc, 0, "getattr_default_np should succeed");
        pthread_attr_destroy(&mut attr);
    }
}

#[test]
fn setattr_default_np_roundtrip() {
    unsafe {
        let mut attr: libc::pthread_attr_t = std::mem::zeroed();
        pthread_attr_init(&mut attr);
        pthread_attr_setstacksize(&mut attr, 4 * 1024 * 1024); // 4 MiB

        let rc = pthread_setattr_default_np(&attr);
        assert_eq!(rc, 0, "setattr_default_np should succeed");

        // Read back defaults
        let mut got: libc::pthread_attr_t = std::mem::zeroed();
        let rc = pthread_getattr_default_np(&mut got);
        assert_eq!(rc, 0);

        let mut stack_size: usize = 0;
        pthread_attr_getstacksize(&got, &mut stack_size);
        assert_eq!(stack_size, 4 * 1024 * 1024);

        pthread_attr_destroy(&mut got);
        pthread_attr_destroy(&mut attr);
    }
}

#[test]
fn setattr_default_np_preserves_affinity_and_sigmask() {
    unsafe {
        let mut attr: libc::pthread_attr_t = std::mem::zeroed();
        assert_eq!(pthread_attr_init(&mut attr), 0);

        let cpu = first_allowed_cpu();
        let mut cpuset: libc::cpu_set_t = std::mem::zeroed();
        libc::CPU_SET(cpu, &mut cpuset);
        assert_eq!(
            pthread_attr_setaffinity_np(&mut attr, std::mem::size_of::<libc::cpu_set_t>(), &cpuset),
            0
        );

        let mut sigmask: libc::sigset_t = std::mem::zeroed();
        libc::sigemptyset(&mut sigmask);
        libc::sigaddset(&mut sigmask, libc::SIGUSR1);
        assert_eq!(pthread_attr_setsigmask_np(&mut attr, &sigmask), 0);

        assert_eq!(pthread_setattr_default_np(&attr), 0);

        let mut got: libc::pthread_attr_t = std::mem::zeroed();
        assert_eq!(pthread_getattr_default_np(&mut got), 0);

        let mut got_cpuset: libc::cpu_set_t = std::mem::zeroed();
        assert_eq!(
            pthread_attr_getaffinity_np(
                &got,
                std::mem::size_of::<libc::cpu_set_t>(),
                &mut got_cpuset
            ),
            0
        );
        assert!(libc::CPU_ISSET(cpu, &got_cpuset));

        let mut got_sigmask: libc::sigset_t = std::mem::zeroed();
        assert_eq!(pthread_attr_getsigmask_np(&got, &mut got_sigmask), 0);
        assert_eq!(libc::sigismember(&got_sigmask, libc::SIGUSR1), 1);

        assert_eq!(pthread_attr_destroy(&mut got), 0);
        assert_eq!(pthread_attr_destroy(&mut attr), 0);
    }
}

#[test]
fn setattr_default_np_rejects_destroyed_attr() {
    unsafe {
        let mut attr: libc::pthread_attr_t = std::mem::zeroed();
        assert_eq!(pthread_attr_init(&mut attr), 0);
        assert_eq!(pthread_attr_destroy(&mut attr), 0);
        assert_eq!(pthread_setattr_default_np(&attr), libc::EINVAL);
    }
}

#[test]
fn thread_create_with_managed_attr_succeeds() {
    unsafe {
        let mut attr: libc::pthread_attr_t = std::mem::zeroed();
        assert_eq!(pthread_attr_init(&mut attr), 0);
        assert_eq!(pthread_attr_setstacksize(&mut attr, 4 * 1024 * 1024), 0);

        let mut thr: libc::pthread_t = 0;
        let rc = pthread_create(&mut thr, &attr, Some(add_ten), 7usize as *mut c_void);
        assert_eq!(rc, 0);

        let mut retval: *mut c_void = ptr::null_mut();
        assert_eq!(pthread_join(thr, &mut retval), 0);
        assert_eq!(retval as usize, 17);
        assert_eq!(pthread_attr_destroy(&mut attr), 0);
    }
}

#[test]
fn thread_create_rejects_destroyed_managed_attr() {
    unsafe {
        let mut attr: libc::pthread_attr_t = std::mem::zeroed();
        assert_eq!(pthread_attr_init(&mut attr), 0);
        assert_eq!(pthread_attr_destroy(&mut attr), 0);

        let mut thr: libc::pthread_t = 0;
        let rc = pthread_create(&mut thr, &attr, Some(add_ten), ptr::null_mut());
        assert_eq!(rc, libc::EINVAL);
    }
}

// ===========================================================================
// pthread_mutex_consistent (for robust mutexes)
// ===========================================================================

#[test]
fn mutex_consistent_does_not_crash() {
    unsafe {
        let mut mutex: libc::pthread_mutex_t = std::mem::zeroed();
        pthread_mutex_init(&mut mutex, ptr::null());

        let rc = pthread_mutex_consistent(&mut mutex);
        assert_eq!(rc, 0, "mutex_consistent is currently a compatibility no-op");

        pthread_mutex_destroy(&mut mutex);
    }
}

#[test]
fn mutex_init_rejects_unsupported_extension_attributes() {
    unsafe {
        let mut attr: libc::pthread_mutexattr_t = std::mem::zeroed();
        let mut mutex: libc::pthread_mutex_t = std::mem::zeroed();
        pthread_mutexattr_init(&mut attr);
        assert_eq!(
            pthread_mutexattr_setrobust(&mut attr, libc::PTHREAD_MUTEX_ROBUST),
            0
        );

        let rc = pthread_mutex_init(&mut mutex, &attr);
        assert_eq!(rc, libc::EINVAL);

        pthread_mutexattr_destroy(&mut attr);
    }
}
