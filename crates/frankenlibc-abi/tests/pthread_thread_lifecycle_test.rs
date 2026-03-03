#![cfg(target_os = "linux")]

use std::ffi::{CStr, CString, c_void};
use std::sync::Mutex;
use std::time::Duration;

use frankenlibc_abi::pthread_abi::{
    pthread_create, pthread_detach, pthread_equal, pthread_getname_np, pthread_join, pthread_self,
    pthread_setname_np, pthread_threading_force_native_for_tests,
};

static TEST_GUARD: Mutex<()> = Mutex::new(());

fn lock_and_force_native() -> std::sync::MutexGuard<'static, ()> {
    let guard = TEST_GUARD.lock().unwrap();
    pthread_threading_force_native_for_tests();
    guard
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
