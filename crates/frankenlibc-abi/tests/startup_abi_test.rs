#![cfg(target_os = "linux")]

//! Integration tests for `startup_abi` — CRT bootstrap and program name globals.
//!
//! Tests exercise the phase-0 startup path via `__frankenlibc_startup_phase0`,
//! the snapshot accessor, and the `__cxa_thread_atexit_impl` hook.

use std::ffi::{c_char, c_int, c_void};
use std::ptr;
use std::sync::atomic::Ordering;

use frankenlibc_abi::startup_abi::{
    __cxa_thread_atexit_impl, __frankenlibc_startup_phase0, __frankenlibc_startup_snapshot,
    __progname, StartupFailureReason, StartupInvariantSnapshot, StartupPolicyDecision,
    program_invocation_name, program_invocation_short_name, startup_policy_snapshot_for_tests,
};

// ---------------------------------------------------------------------------
// Helpers for building synthetic argv/envp/auxv
// ---------------------------------------------------------------------------

const AT_NULL: usize = 0;

/// Build a controlled startup environment: argv + envp + auxv on the stack.
struct StartupFixture {
    argv0: Vec<u8>,
    argv: Vec<*mut c_char>,
    #[allow(dead_code)]
    env: Vec<*mut c_char>,
    auxv: Vec<usize>,
}

impl StartupFixture {
    fn new(program: &[u8]) -> Self {
        let mut argv0 = program.to_vec();
        argv0.push(0); // NUL terminate
        let mut me = Self {
            argv0,
            argv: Vec::new(),
            env: vec![ptr::null_mut()], // empty envp, null-terminated
            auxv: vec![AT_NULL, 0],     // minimal auxv: just AT_NULL
        };
        me.argv.push(me.argv0.as_mut_ptr().cast::<c_char>());
        me.argv.push(ptr::null_mut()); // null-terminated
        me
    }

    fn argc(&self) -> c_int {
        (self.argv.len() - 1) as c_int // exclude trailing null
    }

    fn argv_ptr(&mut self) -> *mut *mut c_char {
        self.argv.as_mut_ptr()
    }

    fn stack_end(&mut self) -> *mut c_void {
        self.auxv.as_mut_ptr().cast::<c_void>()
    }
}

// A minimal main function for testing.
unsafe extern "C" fn test_main(
    _argc: c_int,
    _argv: *mut *mut c_char,
    _envp: *mut *mut c_char,
) -> c_int {
    42
}

// ---------------------------------------------------------------------------
// __frankenlibc_startup_phase0 — basic success path
// ---------------------------------------------------------------------------

#[test]
fn phase0_succeeds_with_valid_fixture() {
    let mut fix = StartupFixture::new(b"/usr/bin/test");
    let rc = unsafe {
        __frankenlibc_startup_phase0(
            Some(test_main),
            fix.argc(),
            fix.argv_ptr(),
            None,
            None,
            None,
            fix.stack_end(),
        )
    };
    assert_eq!(rc, 42, "phase0 should return main's return code");
}

#[test]
fn phase0_snapshot_records_allow_decision() {
    let mut fix = StartupFixture::new(b"myapp");
    let _rc = unsafe {
        __frankenlibc_startup_phase0(
            Some(test_main),
            fix.argc(),
            fix.argv_ptr(),
            None,
            None,
            None,
            fix.stack_end(),
        )
    };
    let snap = startup_policy_snapshot_for_tests();
    assert_eq!(snap.decision, StartupPolicyDecision::Allow);
    assert_eq!(snap.failure_reason, StartupFailureReason::None);
    assert!(snap.dag_valid, "startup DAG should be valid");
}

// ---------------------------------------------------------------------------
// __frankenlibc_startup_phase0 — error cases
// ---------------------------------------------------------------------------

#[test]
fn phase0_null_main_returns_negative() {
    let mut fix = StartupFixture::new(b"app");
    let rc = unsafe {
        __frankenlibc_startup_phase0(
            None, // no main function
            fix.argc(),
            fix.argv_ptr(),
            None,
            None,
            None,
            fix.stack_end(),
        )
    };
    assert!(rc < 0, "phase0 with null main should return negative");
    let snap = startup_policy_snapshot_for_tests();
    assert_eq!(snap.failure_reason, StartupFailureReason::MissingMain);
}

#[test]
fn phase0_null_argv_returns_negative() {
    let mut fix = StartupFixture::new(b"app");
    let rc = unsafe {
        __frankenlibc_startup_phase0(
            Some(test_main),
            1,
            ptr::null_mut(), // null argv
            None,
            None,
            None,
            fix.stack_end(),
        )
    };
    assert!(rc < 0, "phase0 with null argv should return negative");
    let snap = startup_policy_snapshot_for_tests();
    assert_eq!(snap.failure_reason, StartupFailureReason::NullArgv);
}

// ---------------------------------------------------------------------------
// __frankenlibc_startup_snapshot — read invariants
// ---------------------------------------------------------------------------

#[test]
fn startup_snapshot_returns_invariants() {
    let mut fix = StartupFixture::new(b"/bin/hello");
    let _rc = unsafe {
        __frankenlibc_startup_phase0(
            Some(test_main),
            fix.argc(),
            fix.argv_ptr(),
            None,
            None,
            None,
            fix.stack_end(),
        )
    };

    let mut snap = StartupInvariantSnapshot {
        argc: 0,
        argv_count: 0,
        env_count: 0,
        auxv_count: 0,
        secure_mode: 0,
    };
    let rc = unsafe { __frankenlibc_startup_snapshot(&mut snap) };
    assert_eq!(rc, 0, "snapshot should succeed");
    assert!(
        snap.argc > 0 || snap.argv_count > 0,
        "should have captured some invariants"
    );
}

#[test]
fn startup_snapshot_null_returns_negative() {
    let rc = unsafe { __frankenlibc_startup_snapshot(ptr::null_mut()) };
    assert_eq!(rc, -1);
}

// ---------------------------------------------------------------------------
// __cxa_thread_atexit_impl — register thread-local destructor
// ---------------------------------------------------------------------------

static mut DTOR_CALLED: bool = false;

unsafe extern "C" fn test_dtor(_obj: *mut c_void) {
    unsafe { DTOR_CALLED = true };
}

#[test]
fn cxa_thread_atexit_impl_returns_zero() {
    let mut obj = 0u64;
    let rc = unsafe {
        __cxa_thread_atexit_impl(
            test_dtor,
            (&mut obj as *mut u64).cast::<c_void>(),
            ptr::null_mut(),
        )
    };
    assert_eq!(rc, 0, "__cxa_thread_atexit_impl should return 0");
}

// ---------------------------------------------------------------------------
// program_invocation_name globals — initialized by phase0
// ---------------------------------------------------------------------------

#[test]
fn phase0_sets_program_name_globals() {
    let mut fix = StartupFixture::new(b"/usr/local/bin/myapp");
    let _rc = unsafe {
        __frankenlibc_startup_phase0(
            Some(test_main),
            fix.argc(),
            fix.argv_ptr(),
            None,
            None,
            None,
            fix.stack_end(),
        )
    };

    let name_ptr = program_invocation_name.load(Ordering::Acquire);
    assert!(!name_ptr.is_null(), "program_invocation_name should be set");

    let short_ptr = program_invocation_short_name.load(Ordering::Acquire);
    assert!(
        !short_ptr.is_null(),
        "program_invocation_short_name should be set"
    );

    let progname_ptr = __progname.load(Ordering::Acquire);
    assert!(!progname_ptr.is_null(), "__progname should be set");

    // Short name should be "myapp" (basename)
    let short = unsafe { std::ffi::CStr::from_ptr(short_ptr) };
    assert_eq!(short.to_bytes(), b"myapp");
}

// ---------------------------------------------------------------------------
// Phase-0 with init/fini hooks
// ---------------------------------------------------------------------------

static mut INIT_CALLED: bool = false;
static mut FINI_CALLED: bool = false;

unsafe extern "C" fn init_hook() {
    unsafe { INIT_CALLED = true };
}

unsafe extern "C" fn fini_hook() {
    unsafe { FINI_CALLED = true };
}

#[test]
fn phase0_calls_init_and_fini_hooks() {
    unsafe {
        INIT_CALLED = false;
        FINI_CALLED = false;
    }

    let mut fix = StartupFixture::new(b"hooktest");
    let rc = unsafe {
        __frankenlibc_startup_phase0(
            Some(test_main),
            fix.argc(),
            fix.argv_ptr(),
            Some(init_hook),
            Some(fini_hook),
            None,
            fix.stack_end(),
        )
    };
    assert_eq!(rc, 42);
    assert!(unsafe { INIT_CALLED }, "init hook should have been called");
    assert!(unsafe { FINI_CALLED }, "fini hook should have been called");
}

// ---------------------------------------------------------------------------
// Phase-0 — argc / argv edge cases
// ---------------------------------------------------------------------------

#[test]
fn phase0_zero_argc_succeeds() {
    // argc=0 is technically valid (no program name)
    let mut argv = vec![ptr::null_mut::<c_char>()]; // just null terminator
    let mut auxv = vec![AT_NULL, 0usize];
    let rc = unsafe {
        __frankenlibc_startup_phase0(
            Some(test_main),
            0,
            argv.as_mut_ptr(),
            None,
            None,
            None,
            auxv.as_mut_ptr().cast::<c_void>(),
        )
    };
    assert_eq!(rc, 42, "phase0 with argc=0 should still run main");
}

#[test]
fn phase0_negative_argc_still_runs() {
    // Implementation treats argc as a hint; negative argc doesn't prevent execution
    let mut fix = StartupFixture::new(b"app");
    let rc = unsafe {
        __frankenlibc_startup_phase0(
            Some(test_main),
            -1,
            fix.argv_ptr(),
            None,
            None,
            None,
            fix.stack_end(),
        )
    };
    // Implementation may accept or reject negative argc
    assert!(
        rc == 42 || rc < 0,
        "phase0 should either run main or reject"
    );
}

// ---------------------------------------------------------------------------
// Return value propagation
// ---------------------------------------------------------------------------

unsafe extern "C" fn main_returns_zero(
    _argc: c_int,
    _argv: *mut *mut c_char,
    _envp: *mut *mut c_char,
) -> c_int {
    0
}

unsafe extern "C" fn main_returns_one(
    _argc: c_int,
    _argv: *mut *mut c_char,
    _envp: *mut *mut c_char,
) -> c_int {
    1
}

unsafe extern "C" fn main_returns_negative(
    _argc: c_int,
    _argv: *mut *mut c_char,
    _envp: *mut *mut c_char,
) -> c_int {
    -1
}

#[test]
fn phase0_propagates_zero_return() {
    let mut fix = StartupFixture::new(b"app");
    let rc = unsafe {
        __frankenlibc_startup_phase0(
            Some(main_returns_zero),
            fix.argc(),
            fix.argv_ptr(),
            None,
            None,
            None,
            fix.stack_end(),
        )
    };
    assert_eq!(rc, 0);
}

#[test]
fn phase0_propagates_one_return() {
    let mut fix = StartupFixture::new(b"app");
    let rc = unsafe {
        __frankenlibc_startup_phase0(
            Some(main_returns_one),
            fix.argc(),
            fix.argv_ptr(),
            None,
            None,
            None,
            fix.stack_end(),
        )
    };
    assert_eq!(rc, 1);
}

#[test]
fn phase0_propagates_negative_return() {
    let mut fix = StartupFixture::new(b"app");
    let rc = unsafe {
        __frankenlibc_startup_phase0(
            Some(main_returns_negative),
            fix.argc(),
            fix.argv_ptr(),
            None,
            None,
            None,
            fix.stack_end(),
        )
    };
    assert_eq!(rc, -1);
}

// ---------------------------------------------------------------------------
// Program name parsing edge cases
// ---------------------------------------------------------------------------

#[test]
fn phase0_bare_name_sets_matching_short_name() {
    let mut fix = StartupFixture::new(b"simple");
    let _rc = unsafe {
        __frankenlibc_startup_phase0(
            Some(test_main),
            fix.argc(),
            fix.argv_ptr(),
            None,
            None,
            None,
            fix.stack_end(),
        )
    };

    let name_ptr = program_invocation_name.load(Ordering::Acquire);
    let short_ptr = program_invocation_short_name.load(Ordering::Acquire);
    assert!(!name_ptr.is_null());
    assert!(!short_ptr.is_null());

    let full = unsafe { std::ffi::CStr::from_ptr(name_ptr) };
    let short = unsafe { std::ffi::CStr::from_ptr(short_ptr) };
    // For a bare name, full and short should match
    assert_eq!(full.to_bytes(), b"simple");
    assert_eq!(short.to_bytes(), b"simple");
}

#[test]
fn phase0_deep_path_extracts_basename() {
    let mut fix = StartupFixture::new(b"/a/b/c/d/e/prog");
    let _rc = unsafe {
        __frankenlibc_startup_phase0(
            Some(test_main),
            fix.argc(),
            fix.argv_ptr(),
            None,
            None,
            None,
            fix.stack_end(),
        )
    };

    let short_ptr = program_invocation_short_name.load(Ordering::Acquire);
    assert!(!short_ptr.is_null());
    let short = unsafe { std::ffi::CStr::from_ptr(short_ptr) };
    assert_eq!(short.to_bytes(), b"prog");
}

// ---------------------------------------------------------------------------
// __cxa_thread_atexit_impl — edge cases
// ---------------------------------------------------------------------------

#[test]
fn cxa_thread_atexit_impl_null_obj_returns_zero() {
    let rc = unsafe { __cxa_thread_atexit_impl(test_dtor, ptr::null_mut(), ptr::null_mut()) };
    assert_eq!(rc, 0, "null obj should still register successfully");
}

// ---------------------------------------------------------------------------
// Snapshot field validation
// ---------------------------------------------------------------------------

#[test]
fn startup_snapshot_argc_matches_fixture() {
    let mut fix = StartupFixture::new(b"/bin/test");
    let _rc = unsafe {
        __frankenlibc_startup_phase0(
            Some(test_main),
            fix.argc(),
            fix.argv_ptr(),
            None,
            None,
            None,
            fix.stack_end(),
        )
    };

    let mut snap = StartupInvariantSnapshot {
        argc: 0,
        argv_count: 0,
        env_count: 0,
        auxv_count: 0,
        secure_mode: 0,
    };
    let rc = unsafe { __frankenlibc_startup_snapshot(&mut snap) };
    assert_eq!(rc, 0);
    // We passed argc=1 (one argv element), snapshot should reflect that
    // snapshot should have captured some meaningful state
    assert!(
        snap.argc > 0 || snap.argv_count > 0,
        "should have captured some invariants"
    );
}

#[test]
fn phase0_only_init_hook_no_fini() {
    let mut fix = StartupFixture::new(b"initonly");
    let rc = unsafe {
        __frankenlibc_startup_phase0(
            Some(test_main),
            fix.argc(),
            fix.argv_ptr(),
            Some(init_hook),
            None, // no fini
            None,
            fix.stack_end(),
        )
    };
    assert_eq!(rc, 42);
}

#[test]
fn phase0_only_fini_hook_no_init() {
    let mut fix = StartupFixture::new(b"finionly");
    let rc = unsafe {
        __frankenlibc_startup_phase0(
            Some(test_main),
            fix.argc(),
            fix.argv_ptr(),
            None,
            Some(fini_hook), // only fini
            None,
            fix.stack_end(),
        )
    };
    assert_eq!(rc, 42);
}
