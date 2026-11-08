#![cfg(target_os = "linux")]

use std::ffi::{CStr, CString, c_void};
use std::sync::{Arc, Barrier, Mutex};
use std::time::Duration;

use frankenlibc_abi::pthread_abi::{
    __test_threading_force_native_override_state, pthread_create, pthread_detach, pthread_equal,
    pthread_getname_np, pthread_join, pthread_self, pthread_setname_np,
    pthread_threading_restore_for_tests, pthread_threading_swap_force_native_for_tests,
};

/// Acquire poison-tolerantly, so a failing assertion reports as one failure instead of
/// poisoning this guard and taking every later test with it (bd-9ri7g1).
static TEST_GUARD: Mutex<()> = Mutex::new(());

fn lock_only() -> std::sync::MutexGuard<'static, ()> {
    TEST_GUARD.lock().unwrap_or_else(|e| e.into_inner())
}

struct NativeThreadingTestGuard {
    _guard: std::sync::MutexGuard<'static, ()>,
    previous: bool,
}

impl Drop for NativeThreadingTestGuard {
    fn drop(&mut self) {
        pthread_threading_restore_for_tests(self.previous);
    }
}

fn lock_and_force_native() -> NativeThreadingTestGuard {
    let guard = TEST_GUARD.lock().unwrap_or_else(|e| e.into_inner());
    let previous = pthread_threading_swap_force_native_for_tests();
    NativeThreadingTestGuard {
        _guard: guard,
        previous,
    }
}

#[test]
fn nested_threading_force_native_overrides_restore_only_after_the_last_lease() {
    let _guard = lock_only();
    assert_eq!(
        __test_threading_force_native_override_state().1,
        0,
        "the lifecycle test lock must start with no native-threading lease"
    );

    let first_previous = pthread_threading_swap_force_native_for_tests();
    assert_eq!(
        __test_threading_force_native_override_state(),
        (true, 1),
        "first lease must enable native threading"
    );

    let second_previous = pthread_threading_swap_force_native_for_tests();
    assert_eq!(
        __test_threading_force_native_override_state(),
        (true, 2),
        "nested lease must retain native threading"
    );

    pthread_threading_restore_for_tests(first_previous);
    assert_eq!(
        __test_threading_force_native_override_state(),
        (true, 1),
        "releasing one lease must not restore host delegation early"
    );

    pthread_threading_restore_for_tests(second_previous);
    assert_eq!(
        __test_threading_force_native_override_state(),
        (first_previous, 0),
        "the final lease must restore the original worker mode"
    );
}

#[test]
fn scoped_native_override_does_not_change_another_test_worker() {
    let entered_native_scope = Arc::new(Barrier::new(2));
    let release_native_scope = Arc::new(Barrier::new(2));
    let entered_native_scope_for_worker = Arc::clone(&entered_native_scope);
    let release_native_scope_for_worker = Arc::clone(&release_native_scope);

    let worker = std::thread::spawn(move || {
        let previous = pthread_threading_swap_force_native_for_tests();
        assert_eq!(
            __test_threading_force_native_override_state(),
            (true, 1),
            "the scoped override must be visible to its owning worker"
        );
        entered_native_scope_for_worker.wait();
        release_native_scope_for_worker.wait();
        pthread_threading_restore_for_tests(previous);
    });

    entered_native_scope.wait();
    assert_eq!(
        __test_threading_force_native_override_state(),
        (false, 0),
        "a native override on another test worker must not alter host dispatch here"
    );
    release_native_scope.wait();
    worker
        .join()
        .expect("native override worker must not panic");
}

#[cfg(any(target_arch = "x86_64", target_arch = "aarch64"))]
mod policy_context_tests {
    use super::lock_only;
    use frankenlibc_abi::pthread_abi::{
        __test_threading_policy_context_active as context_active,
        __test_with_threading_policy_context as with_context,
    };
    use frankenlibc_core::{pthread::thread, syscall};
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::time::{Duration, Instant};

    struct Probe {
        ready: AtomicBool,
        release: AtomicBool,
    }

    impl Probe {
        fn new() -> Self {
            Self {
                ready: AtomicBool::new(false),
                release: AtomicBool::new(false),
            }
        }

        fn wait_ready(&self) {
            let deadline = Instant::now() + Duration::from_secs(10);
            while !self.ready.load(Ordering::Acquire) {
                assert!(
                    Instant::now() < deadline,
                    "native policy probe did not start"
                );
                syscall::sys_sched_yield();
            }
        }

        fn wait_release(&self) {
            while !self.release.load(Ordering::Acquire) {
                syscall::sys_sched_yield();
            }
        }
    }

    // No allocation, assertion, panic, or host call is allowed in this child:
    // the real core clone intentionally inherits its creator's compiler TLS.
    unsafe extern "C" fn policy_child(argument: usize) -> usize {
        // SAFETY: NativeChild keeps the borrowed probe alive until join.
        let probe = unsafe { &*(argument as *const Probe) };
        let mut observed = usize::from(!context_active());
        let entered = with_context(|| {
            observed |= 1 << 1;
            if context_active() {
                observed |= 1 << 2;
            }
            if with_context(|| ()).is_none() {
                observed |= 1 << 3;
            }
            probe.ready.store(true, Ordering::Release);
            probe.wait_release();
            if context_active() {
                observed |= 1 << 4;
            }
        });
        if entered.is_none() {
            // The old shared-depth implementation takes this path. Publish
            // readiness anyway, so it fails the observations rather than hangs.
            probe.ready.store(true, Ordering::Release);
            probe.wait_release();
        }
        if !context_active() {
            observed |= 1 << 5;
        }
        observed
    }

    struct NativeChild<'a> {
        handle: *mut thread::ThreadHandle,
        probe: &'a Probe,
    }

    impl<'a> NativeChild<'a> {
        fn create(probe: &'a Probe) -> Self {
            // SAFETY: the entry has the expected C pointer-sized signature;
            // this guard joins before the borrowed probe can be destroyed.
            let handle = unsafe {
                thread::create_thread(
                    policy_child as *const () as usize,
                    probe as *const Probe as usize,
                    64 * 1024,
                )
            }
            .expect("creating an actual native policy probe must succeed");
            Self { handle, probe }
        }

        fn join(mut self) -> usize {
            self.probe.release.store(true, Ordering::Release);
            // SAFETY: this guard exclusively owns its live joinable handle.
            let result = unsafe { thread::join_thread(self.handle) }
                .expect("joining the native policy probe must succeed");
            self.handle = std::ptr::null_mut();
            result
        }
    }

    impl Drop for NativeChild<'_> {
        fn drop(&mut self) {
            if !self.handle.is_null() {
                self.probe.release.store(true, Ordering::Release);
                // SAFETY: release and join even when a parent assertion
                // unwinds, before any child can outlive its borrowed probe.
                let _ = unsafe { thread::join_thread(self.handle) };
            }
        }
    }

    #[test]
    fn threading_policy_context_isolated_between_creator_and_native_siblings() {
        let _guard = lock_only();
        assert!(!context_active());
        let first_probe = Probe::new();
        let second_probe = Probe::new();
        let observations = with_context(|| {
            assert!(context_active());
            assert!(with_context(|| ()).is_none());
            let first = NativeChild::create(&first_probe);
            first_probe.wait_ready();
            let second = NativeChild::create(&second_probe);
            second_probe.wait_ready();

            let parent_with_both = context_active();
            let first_observed = first.join();
            let parent_after_first = context_active();
            // The second child still owns its guard after its sibling exits.
            let second_observed = second.join();
            (
                parent_with_both,
                parent_after_first,
                context_active(),
                first_observed,
                second_observed,
            )
        });
        assert_eq!(
            observations,
            Some((true, true, true, 0b11_1111, 0b11_1111)),
            "each native child must enter and leave its own context while its creator and sibling remain active"
        );
        assert!(
            !context_active(),
            "creator guard must be restored after exit"
        );
    }

    #[test]
    fn threading_policy_context_hosted_unwind_restores_depth() {
        let _guard = lock_only();
        assert!(!context_active());
        let unwind = std::panic::catch_unwind(|| {
            let _ = with_context(|| {
                assert!(context_active());
                assert!(with_context(|| ()).is_none());
                // Only the ordinary hosted test worker unwinds. Native child
                // code above records observations without panicking.
                panic!("exercise threading-policy guard unwinding");
            });
        });
        assert!(unwind.is_err());
        assert!(!context_active(), "unwinding must release the hosted guard");
        assert_eq!(with_context(context_active), Some(true));
        assert!(!context_active(), "the replacement guard must also release");
    }
}

unsafe extern "C" fn start_return_arg(arg: *mut c_void) -> *mut c_void {
    arg
}

unsafe extern "C" fn start_return_pthread_self(_arg: *mut c_void) -> *mut c_void {
    // SAFETY: calling our ABI-layer pthread_self; return value treated as an integer payload.
    unsafe { pthread_self() as usize as *mut c_void }
}

unsafe extern "C" fn start_self_join_errno(_arg: *mut c_void) -> *mut c_void {
    // SAFETY: calling our ABI-layer pthread_self/pthread_join in the child.
    let self_tid = unsafe { pthread_self() };
    // SAFETY: self_tid is a valid pthread_t for this thread; null retval is allowed.
    let rc = unsafe { pthread_join(self_tid, std::ptr::null_mut()) };
    rc as usize as *mut c_void
}

unsafe extern "C" fn start_name_test_window(_arg: *mut c_void) -> *mut c_void {
    std::thread::sleep(Duration::from_millis(250));
    std::ptr::null_mut()
}

fn env_usize(var: &str, default: usize, max: usize) -> usize {
    std::env::var(var)
        .ok()
        .and_then(|value| value.parse::<usize>().ok())
        .map(|value| value.clamp(1, max))
        .unwrap_or(default)
}

fn run_create_join_roundtrip_iters(iters: usize) {
    for i in 1usize..=iters {
        let arg = i as *mut c_void;
        let mut tid: libc::pthread_t = 0;
        let create_rc = unsafe {
            pthread_create(
                &mut tid as *mut libc::pthread_t,
                std::ptr::null(),
                Some(start_return_arg),
                arg,
            )
        };
        assert_eq!(create_rc, 0, "pthread_create failed on iteration {i}");

        let mut retval: *mut c_void = std::ptr::null_mut();
        let join_rc = unsafe { pthread_join(tid, &mut retval as *mut *mut c_void) };
        assert_eq!(join_rc, 0, "pthread_join failed on iteration {i}");
        assert_eq!(retval, arg, "returned arg mismatch on iteration {i}");
    }
}

fn run_create_join_parallel_batch(batch: usize) {
    let mut tids = vec![0 as libc::pthread_t; batch];
    let mut args = vec![std::ptr::null_mut::<c_void>(); batch];

    for idx in 0..batch {
        args[idx] = (idx + 1) as *mut c_void;
        let create_rc = unsafe {
            pthread_create(
                &mut tids[idx] as *mut libc::pthread_t,
                std::ptr::null(),
                Some(start_return_arg),
                args[idx],
            )
        };
        assert_eq!(create_rc, 0, "pthread_create failed for slot {idx}");
    }

    for idx in 0..batch {
        let mut retval: *mut c_void = std::ptr::null_mut();
        let join_rc = unsafe { pthread_join(tids[idx], &mut retval as *mut *mut c_void) };
        assert_eq!(join_rc, 0, "pthread_join failed for slot {idx}");
        assert_eq!(retval, args[idx], "returned arg mismatch for slot {idx}");
    }
}

fn run_detach_join_esrch_iters(iters: usize) {
    for i in 0..iters {
        let mut tid: libc::pthread_t = 0;
        let create_rc = unsafe {
            pthread_create(
                &mut tid as *mut libc::pthread_t,
                std::ptr::null(),
                Some(start_return_arg),
                std::ptr::null_mut(),
            )
        };
        assert_eq!(create_rc, 0, "pthread_create failed on iteration {i}");

        let detach_rc = unsafe { pthread_detach(tid) };
        assert_eq!(detach_rc, 0, "pthread_detach failed on iteration {i}");

        let join_rc = unsafe { pthread_join(tid, std::ptr::null_mut()) };
        assert_eq!(join_rc, libc::ESRCH, "join-after-detach mismatch on {i}");
    }
}

#[test]
fn pthread_self_is_nonzero_and_stable_within_thread() {
    let _guard = lock_and_force_native();
    let a = unsafe { pthread_self() };
    let b = unsafe { pthread_self() };
    assert_ne!(a, 0, "pthread_self must be nonzero");
    assert_eq!(a, b, "pthread_self must be stable within a thread");
}

#[test]
fn pthread_equal_reflexive_and_distinct_threads_not_equal() {
    let _guard = lock_and_force_native();

    let main_id = unsafe { pthread_self() };
    assert_eq!(unsafe { pthread_equal(main_id, main_id) }, 1);

    // Create a thread that returns its own pthread_self.
    let mut tid: libc::pthread_t = 0;
    let rc = unsafe {
        pthread_create(
            &mut tid as *mut libc::pthread_t,
            std::ptr::null(),
            Some(start_return_pthread_self),
            std::ptr::null_mut(),
        )
    };
    assert_eq!(rc, 0, "pthread_create failed rc={rc}");

    let mut retval: *mut c_void = std::ptr::null_mut();
    let join_rc = unsafe { pthread_join(tid, &mut retval as *mut *mut c_void) };
    assert_eq!(join_rc, 0, "pthread_join failed rc={join_rc}");

    let child_id = retval as usize as libc::pthread_t;
    assert_ne!(child_id, 0, "child pthread_self must be nonzero");
    assert_eq!(unsafe { pthread_equal(main_id, child_id) }, 0);
}

#[test]
fn pthread_create_argument_validation() {
    let _guard = lock_and_force_native();

    // Null thread_out -> EINVAL
    let rc = unsafe {
        pthread_create(
            std::ptr::null_mut(),
            std::ptr::null(),
            Some(start_return_arg),
            std::ptr::null_mut(),
        )
    };
    assert_eq!(rc, libc::EINVAL);

    // Missing start routine -> EINVAL
    let mut tid: libc::pthread_t = 0;
    let rc = unsafe {
        pthread_create(
            &mut tid as *mut libc::pthread_t,
            std::ptr::null(),
            None,
            std::ptr::null_mut(),
        )
    };
    assert_eq!(rc, libc::EINVAL);
}

#[test]
fn pthread_create_join_roundtrip_uses_default_host_routing() {
    let _guard = lock_only();

    let arg = 0x4444usize as *mut c_void;
    let mut tid: libc::pthread_t = 0;
    let create_rc = unsafe {
        pthread_create(
            &mut tid as *mut libc::pthread_t,
            std::ptr::null(),
            Some(start_return_arg),
            arg,
        )
    };
    assert_eq!(create_rc, 0, "pthread_create failed rc={create_rc}");

    let mut retval: *mut c_void = std::ptr::null_mut();
    let join_rc = unsafe { pthread_join(tid, &mut retval as *mut *mut c_void) };
    assert_eq!(join_rc, 0, "pthread_join failed rc={join_rc}");
    assert_eq!(retval, arg, "default host routing lost thread return value");
}

#[test]
fn pthread_create_join_parallel_batch_uses_default_host_routing() {
    let _guard = lock_only();
    run_create_join_parallel_batch(8);
}

#[test]
fn pthread_join_and_detach_unknown_thread_are_esrch() {
    let _guard = lock_and_force_native();

    let mut retval: *mut c_void = std::ptr::null_mut();
    let rc = unsafe { pthread_join(0xFFFF_FFFF_FFFF_u64 as libc::pthread_t, &mut retval) };
    assert_eq!(rc, libc::ESRCH);

    let rc = unsafe { pthread_detach(0xFFFF_FFFF_FFFF_u64 as libc::pthread_t) };
    assert_eq!(rc, libc::ESRCH);
}

#[test]
#[ignore = "stress profile; run explicitly when exercising lifecycle endurance"]
fn pthread_create_join_roundtrip_stress() {
    let _guard = lock_and_force_native();
    let iters = env_usize("FRANKENLIBC_THREAD_ROUNDTRIP_STRESS_ITERS", 16, 128);
    run_create_join_roundtrip_iters(iters);
}

#[test]
#[ignore = "long-running stress profile; run with --ignored when explicitly validating lifecycle endurance"]
fn pthread_create_join_roundtrip_long_stress_profile() {
    let _guard = lock_and_force_native();
    run_create_join_roundtrip_iters(128);
}

#[test]
#[ignore = "stress profile; run explicitly when exercising lifecycle endurance"]
fn pthread_create_join_parallel_batch_stress() {
    let _guard = lock_and_force_native();
    let batch = env_usize("FRANKENLIBC_THREAD_PARALLEL_BATCH", 8, 32);
    run_create_join_parallel_batch(batch);
}

#[test]
fn pthread_detach_makes_subsequent_join_fail_with_esrch() {
    let _guard = lock_and_force_native();

    let mut tid: libc::pthread_t = 0;
    let rc = unsafe {
        pthread_create(
            &mut tid as *mut libc::pthread_t,
            std::ptr::null(),
            Some(start_return_arg),
            std::ptr::null_mut(),
        )
    };
    assert_eq!(rc, 0, "pthread_create failed rc={rc}");

    let detach_rc = unsafe { pthread_detach(tid) };
    assert_eq!(detach_rc, 0, "pthread_detach failed rc={detach_rc}");

    // Join after detach should fail; thread handle was removed from join table.
    let join_rc = unsafe { pthread_join(tid, std::ptr::null_mut()) };
    assert_eq!(join_rc, libc::ESRCH);
}

#[test]
fn pthread_join_then_reuse_handle_is_esrch() {
    let _guard = lock_and_force_native();

    let mut tid: libc::pthread_t = 0;
    let create_rc = unsafe {
        pthread_create(
            &mut tid as *mut libc::pthread_t,
            std::ptr::null(),
            Some(start_return_arg),
            std::ptr::null_mut(),
        )
    };
    assert_eq!(create_rc, 0, "pthread_create failed rc={create_rc}");

    let first_join_rc = unsafe { pthread_join(tid, std::ptr::null_mut()) };
    assert_eq!(
        first_join_rc, 0,
        "first pthread_join failed rc={first_join_rc}"
    );

    let second_join_rc = unsafe { pthread_join(tid, std::ptr::null_mut()) };
    assert_eq!(
        second_join_rc,
        libc::ESRCH,
        "second join on consumed handle should be ESRCH"
    );

    let detach_after_join_rc = unsafe { pthread_detach(tid) };
    assert_eq!(
        detach_after_join_rc,
        libc::ESRCH,
        "detach after join-consumption should be ESRCH"
    );
}

#[test]
fn pthread_self_join_is_rejected_with_edeadlk() {
    let _guard = lock_and_force_native();

    let mut tid: libc::pthread_t = 0;
    let create_rc = unsafe {
        pthread_create(
            &mut tid as *mut libc::pthread_t,
            std::ptr::null(),
            Some(start_self_join_errno),
            std::ptr::null_mut(),
        )
    };
    assert_eq!(create_rc, 0, "pthread_create failed rc={create_rc}");

    let mut retval: *mut c_void = std::ptr::null_mut();
    let join_rc = unsafe { pthread_join(tid, &mut retval as *mut *mut c_void) };
    assert_eq!(join_rc, 0, "pthread_join(child) failed rc={join_rc}");

    let child_errno = retval as usize as i32;
    assert_eq!(
        child_errno,
        libc::EDEADLK,
        "child pthread_join(self) should return EDEADLK"
    );
}

#[test]
#[ignore = "stress profile; run explicitly when exercising lifecycle endurance"]
fn pthread_detach_join_esrch_stress() {
    let _guard = lock_and_force_native();
    let iters = env_usize("FRANKENLIBC_THREAD_DETACH_STRESS_ITERS", 16, 128);
    run_detach_join_esrch_iters(iters);
}

#[test]
#[ignore = "long-running stress profile; run with --ignored when explicitly validating lifecycle endurance"]
fn pthread_detach_join_esrch_long_stress_profile() {
    let _guard = lock_and_force_native();
    run_detach_join_esrch_iters(128);
}

#[test]
fn pthread_setname_getname_self_roundtrip() {
    let _guard = lock_and_force_native();

    let self_id = unsafe { pthread_self() };
    let mut original = [0 as libc::c_char; 16];
    let original_rc = unsafe { pthread_getname_np(self_id, original.as_mut_ptr(), original.len()) };
    assert_eq!(
        original_rc, 0,
        "initial pthread_getname_np failed rc={original_rc}"
    );

    let desired = CString::new("flc-self").expect("valid name");
    let set_rc = unsafe { pthread_setname_np(self_id, desired.as_ptr()) };
    assert_eq!(set_rc, 0, "pthread_setname_np(self) failed rc={set_rc}");

    let mut got = [0 as libc::c_char; 16];
    let get_rc = unsafe { pthread_getname_np(self_id, got.as_mut_ptr(), got.len()) };
    assert_eq!(get_rc, 0, "pthread_getname_np(self) failed rc={get_rc}");
    let got_name = unsafe { CStr::from_ptr(got.as_ptr()) }
        .to_str()
        .expect("thread name should be UTF-8");
    assert_eq!(got_name, "flc-self");

    let restore_rc = unsafe { pthread_setname_np(self_id, original.as_ptr()) };
    assert_eq!(
        restore_rc, 0,
        "restoring original thread name failed rc={restore_rc}"
    );
}

#[test]
fn pthread_setname_getname_other_thread_roundtrip() {
    let _guard = lock_and_force_native();

    let mut tid: libc::pthread_t = 0;
    let create_rc = unsafe {
        pthread_create(
            &mut tid as *mut libc::pthread_t,
            std::ptr::null(),
            Some(start_name_test_window),
            std::ptr::null_mut(),
        )
    };
    assert_eq!(
        create_rc, 0,
        "pthread_create for setname/getname test failed rc={create_rc}"
    );

    // Give the child a brief window to enter its sleep period.
    std::thread::sleep(Duration::from_millis(10));

    let desired = CString::new("flc-child").expect("valid child name");
    let set_rc = unsafe { pthread_setname_np(tid, desired.as_ptr()) };
    assert_eq!(set_rc, 0, "pthread_setname_np(other) failed rc={set_rc}");

    let mut got = [0 as libc::c_char; 16];
    let get_rc = unsafe { pthread_getname_np(tid, got.as_mut_ptr(), got.len()) };
    assert_eq!(get_rc, 0, "pthread_getname_np(other) failed rc={get_rc}");
    let got_name = unsafe { CStr::from_ptr(got.as_ptr()) }
        .to_str()
        .expect("thread name should be UTF-8");
    assert_eq!(got_name, "flc-child");

    let join_rc = unsafe { pthread_join(tid, std::ptr::null_mut()) };
    assert_eq!(
        join_rc, 0,
        "pthread_join(name-test thread) failed rc={join_rc}"
    );
}

#[test]
fn pthread_setname_getname_unknown_thread_return_esrch() {
    let _guard = lock_and_force_native();
    let unknown = 0x7fff_ffff as libc::pthread_t;

    let desired = CString::new("flc-ghost").expect("valid name");
    let set_rc = unsafe { pthread_setname_np(unknown, desired.as_ptr()) };
    assert_eq!(
        set_rc,
        libc::ESRCH,
        "unknown-thread pthread_setname_np should be ESRCH"
    );

    let mut got = [0 as libc::c_char; 16];
    let get_rc = unsafe { pthread_getname_np(unknown, got.as_mut_ptr(), got.len()) };
    assert_eq!(
        get_rc,
        libc::ESRCH,
        "unknown-thread pthread_getname_np should be ESRCH"
    );
}

#[test]
fn pthread_detach_twice_is_esrch() {
    let _guard = lock_and_force_native();

    let mut tid: libc::pthread_t = 0;
    let rc = unsafe {
        pthread_create(
            &mut tid as *mut libc::pthread_t,
            std::ptr::null(),
            Some(start_return_arg),
            std::ptr::null_mut(),
        )
    };
    assert_eq!(rc, 0);

    let first = unsafe { pthread_detach(tid) };
    assert_eq!(first, 0, "first detach should succeed");

    let second = unsafe { pthread_detach(tid) };
    assert_eq!(
        second,
        libc::ESRCH,
        "second detach on same tid should be ESRCH"
    );
}

#[test]
fn pthread_setname_too_long_is_erange() {
    let _guard = lock_and_force_native();

    let self_id = unsafe { pthread_self() };
    // POSIX thread name limit is 15 chars + NUL = 16 bytes.
    let long_name = CString::new("a]234567890123456").expect("valid cstring");
    let rc = unsafe { pthread_setname_np(self_id, long_name.as_ptr()) };
    assert_eq!(
        rc,
        libc::ERANGE,
        "name exceeding 15 chars should return ERANGE"
    );
}

#[test]
fn pthread_create_join_multiple_sequential() {
    let _guard = lock_and_force_native();

    for i in 1usize..=5 {
        let arg = (i * 100) as *mut c_void;
        let mut tid: libc::pthread_t = 0;
        let rc = unsafe {
            pthread_create(
                &mut tid as *mut libc::pthread_t,
                std::ptr::null(),
                Some(start_return_arg),
                arg,
            )
        };
        assert_eq!(rc, 0, "pthread_create failed for thread {i}");

        let mut retval: *mut c_void = std::ptr::null_mut();
        let join_rc = unsafe { pthread_join(tid, &mut retval as *mut *mut c_void) };
        assert_eq!(join_rc, 0, "pthread_join failed for thread {i}");
        assert_eq!(retval, arg, "return value mismatch for thread {i}");
    }
}

#[test]
fn pthread_equal_same_thread_returns_nonzero() {
    let _guard = lock_and_force_native();

    let mut tid: libc::pthread_t = 0;
    let rc = unsafe {
        pthread_create(
            &mut tid as *mut libc::pthread_t,
            std::ptr::null(),
            Some(start_return_arg),
            std::ptr::null_mut(),
        )
    };
    assert_eq!(rc, 0);

    // Equal on same tid should return nonzero.
    assert_ne!(unsafe { pthread_equal(tid, tid) }, 0);

    let join_rc = unsafe { pthread_join(tid, std::ptr::null_mut()) };
    assert_eq!(join_rc, 0);
}

#[test]
fn pthread_getname_zero_buflen_is_einval() {
    let _guard = lock_and_force_native();

    let self_id = unsafe { pthread_self() };
    let mut buf = [0 as libc::c_char; 1];
    // Zero-length buffer should fail with EINVAL.
    let rc = unsafe { pthread_getname_np(self_id, buf.as_mut_ptr(), 0) };
    assert_eq!(rc, libc::EINVAL, "zero-length buffer should return EINVAL");
}
