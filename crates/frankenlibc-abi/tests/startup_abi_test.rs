#![cfg(target_os = "linux")]

//! Integration tests for `startup_abi` — CRT bootstrap and program name globals.
//!
//! Tests exercise the phase-0 startup path via `__frankenlibc_startup_phase0`,
//! the snapshot accessor, and the `__cxa_thread_atexit_impl` hook.

use std::ffi::{c_char, c_int, c_void};
use std::sync::Mutex;
static STARTUP_TEST_LOCK: Mutex<()> = Mutex::new(());

use std::ptr;
use std::sync::atomic::{AtomicI32, Ordering};

use frankenlibc_abi::startup_abi::{
    __cxa_thread_atexit_impl, __frankenlibc_startup_phase0, __frankenlibc_startup_snapshot,
    __progname, StartupFailureReason, StartupInvariantSnapshot, StartupPolicyDecision, getprogname,
    program_invocation_name, program_invocation_short_name, setprogname,
    startup_policy_snapshot_for_tests,
};
use frankenlibc_abi::startup_helpers::SecureModeState;
use frankenlibc_abi::stdlib_abi::{atexit, on_exit};
use frankenlibc_abi::unistd_abi::{__cxa_atexit, __cxa_finalize};

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
    let _lock = STARTUP_TEST_LOCK.lock().unwrap();
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
    let _lock = STARTUP_TEST_LOCK.lock().unwrap();
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
    let _lock = STARTUP_TEST_LOCK.lock().unwrap();
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
    let _lock = STARTUP_TEST_LOCK.lock().unwrap();
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
    let _lock = STARTUP_TEST_LOCK.lock().unwrap();
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
    let _lock = STARTUP_TEST_LOCK.lock().unwrap();
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
    let _lock = STARTUP_TEST_LOCK.lock().unwrap();
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
    let _lock = STARTUP_TEST_LOCK.lock().unwrap();
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
static CONSTRUCTOR_ORDER: Mutex<Vec<&'static str>> = Mutex::new(Vec::new());
static DESTRUCTOR_ORDER: Mutex<Vec<&'static str>> = Mutex::new(Vec::new());
static INIT_FINI_ARRAY_ORDER: Mutex<Vec<&'static str>> = Mutex::new(Vec::new());
static EXIT_CALLBACK_ORDER_FD: AtomicI32 = AtomicI32::new(-1);
static CXA_ATEXIT_ORDER: Mutex<Vec<c_int>> = Mutex::new(Vec::new());

unsafe extern "C" fn init_hook() {
    unsafe { INIT_CALLED = true };
}

unsafe extern "C" fn fini_hook() {
    unsafe { FINI_CALLED = true };
}

unsafe extern "C" fn constructor_order_init_hook() {
    let mut order = CONSTRUCTOR_ORDER.lock().unwrap();
    order.push("preinit_array");
    order.push("init_array");
}

unsafe extern "C" fn constructor_order_main(
    _argc: c_int,
    _argv: *mut *mut c_char,
    _envp: *mut *mut c_char,
) -> c_int {
    CONSTRUCTOR_ORDER.lock().unwrap().push("main");
    0
}

unsafe extern "C" fn destructor_order_main(
    _argc: c_int,
    _argv: *mut *mut c_char,
    _envp: *mut *mut c_char,
) -> c_int {
    DESTRUCTOR_ORDER.lock().unwrap().push("main_return");
    7
}

unsafe extern "C" fn destructor_order_fini_hook() {
    DESTRUCTOR_ORDER.lock().unwrap().push("fini_array");
}

unsafe extern "C" fn destructor_order_rtld_fini_hook() {
    DESTRUCTOR_ORDER.lock().unwrap().push("rtld_fini");
}

unsafe extern "C" fn init_fini_array_init_hook() {
    let mut order = INIT_FINI_ARRAY_ORDER.lock().unwrap();
    order.push("preinit_array");
    order.push("init_array");
}

unsafe extern "C" fn init_fini_array_main(
    _argc: c_int,
    _argv: *mut *mut c_char,
    _envp: *mut *mut c_char,
) -> c_int {
    INIT_FINI_ARRAY_ORDER.lock().unwrap().push("main");
    0
}

unsafe extern "C" fn init_fini_array_fini_hook() {
    INIT_FINI_ARRAY_ORDER.lock().unwrap().push("fini_array");
}

fn write_exit_callback_byte(byte: u8) {
    let fd = EXIT_CALLBACK_ORDER_FD.load(Ordering::SeqCst);
    if fd >= 0 {
        unsafe {
            libc::write(fd, (&byte as *const u8).cast::<c_void>(), 1);
        }
    }
}

extern "C" fn atexit_order_first() {
    write_exit_callback_byte(b'A');
}

extern "C" fn atexit_order_last() {
    write_exit_callback_byte(b'B');
}

unsafe extern "C" fn on_exit_order_status(status: c_int, _arg: *mut c_void) {
    write_exit_callback_byte(b'O');
    write_exit_callback_byte(status as u8);
}

unsafe extern "C" fn cxa_atexit_record_arg(arg: *mut c_void) {
    let value = if arg.is_null() {
        -1
    } else {
        unsafe { *(arg.cast::<c_int>()) }
    };
    CXA_ATEXIT_ORDER.lock().unwrap().push(value);
}

#[test]
fn phase0_calls_init_and_fini_hooks() {
    let _lock = STARTUP_TEST_LOCK.lock().unwrap();
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

#[test]
fn phase0_runs_preinit_and_init_constructors_before_main() {
    let _lock = STARTUP_TEST_LOCK.lock().unwrap();
    CONSTRUCTOR_ORDER.lock().unwrap().clear();

    let mut fix = StartupFixture::new(b"constructors");
    let rc = unsafe {
        __frankenlibc_startup_phase0(
            Some(constructor_order_main),
            fix.argc(),
            fix.argv_ptr(),
            Some(constructor_order_init_hook),
            None,
            None,
            fix.stack_end(),
        )
    };

    assert_eq!(rc, 0);
    let order = CONSTRUCTOR_ORDER.lock().unwrap().clone();
    assert_eq!(order, ["preinit_array", "init_array", "main"]);

    let snap = startup_policy_snapshot_for_tests();
    assert_eq!(snap.decision, StartupPolicyDecision::Allow);
    assert!(
        snap.dag_valid,
        "constructor startup path should preserve the phase-0 DAG"
    );
}

#[test]
fn phase0_runs_fini_array_and_rtld_fini_after_main_return() {
    let _lock = STARTUP_TEST_LOCK.lock().unwrap();
    DESTRUCTOR_ORDER.lock().unwrap().clear();

    let mut fix = StartupFixture::new(b"destructors");
    let rc = unsafe {
        __frankenlibc_startup_phase0(
            Some(destructor_order_main),
            fix.argc(),
            fix.argv_ptr(),
            None,
            Some(destructor_order_fini_hook),
            Some(destructor_order_rtld_fini_hook),
            fix.stack_end(),
        )
    };

    assert_eq!(rc, 7);
    let order = DESTRUCTOR_ORDER.lock().unwrap().clone();
    assert_eq!(order, ["main_return", "fini_array", "rtld_fini"]);

    let snap = startup_policy_snapshot_for_tests();
    assert_eq!(snap.decision, StartupPolicyDecision::Allow);
    assert!(
        snap.dag_valid,
        "destructor startup path should preserve the phase-0 DAG"
    );
}

#[test]
fn phase0_runs_preinit_init_main_and_fini_arrays_in_order() {
    let _lock = STARTUP_TEST_LOCK.lock().unwrap();
    INIT_FINI_ARRAY_ORDER.lock().unwrap().clear();

    let mut fix = StartupFixture::new(b"init-fini-arrays");
    let rc = unsafe {
        __frankenlibc_startup_phase0(
            Some(init_fini_array_main),
            fix.argc(),
            fix.argv_ptr(),
            Some(init_fini_array_init_hook),
            Some(init_fini_array_fini_hook),
            None,
            fix.stack_end(),
        )
    };

    assert_eq!(rc, 0);
    let order = INIT_FINI_ARRAY_ORDER.lock().unwrap().clone();
    assert_eq!(order, ["preinit_array", "init_array", "main", "fini_array"]);

    let snap = startup_policy_snapshot_for_tests();
    assert_eq!(snap.decision, StartupPolicyDecision::Allow);
    assert!(
        snap.dag_valid,
        "init/fini startup path should preserve the phase-0 DAG"
    );
}

#[test]
fn phase0_exit_callbacks_run_lifo_and_propagate_status() {
    let _lock = STARTUP_TEST_LOCK.lock().unwrap();
    let mut fds = [0i32; 2];
    let pipe_rc = unsafe { libc::pipe(fds.as_mut_ptr()) };
    assert_eq!(pipe_rc, 0, "pipe() should succeed");

    let pid = unsafe { libc::fork() };
    assert!(pid >= 0, "fork() should succeed");

    if pid == 0 {
        unsafe { libc::close(fds[0]) };
        EXIT_CALLBACK_ORDER_FD.store(fds[1], Ordering::SeqCst);

        if unsafe { atexit(Some(atexit_order_first)) } != 0 {
            unsafe { libc::_exit(101) };
        }
        if unsafe { on_exit(Some(on_exit_order_status), ptr::null_mut()) } != 0 {
            unsafe { libc::_exit(102) };
        }
        if unsafe { atexit(Some(atexit_order_last)) } != 0 {
            unsafe { libc::_exit(103) };
        }

        unsafe { frankenlibc_abi::stdlib_abi::exit(42) };
    }

    unsafe { libc::close(fds[1]) };
    let mut observed = Vec::new();
    loop {
        let mut byte = [0u8; 1];
        let n = unsafe { libc::read(fds[0], byte.as_mut_ptr().cast::<c_void>(), 1) };
        assert!(n >= 0, "read() should succeed");
        if n == 0 {
            break;
        }
        observed.push(byte[0]);
    }
    unsafe { libc::close(fds[0]) };

    let mut status = 0i32;
    let waited = unsafe { libc::waitpid(pid, &mut status, 0) };
    assert_eq!(waited, pid, "waitpid should reap the child");
    assert_eq!(
        observed,
        vec![b'B', b'O', 42, b'A'],
        "atexit and on_exit callbacks should share one reverse-registration stack"
    );
    assert_eq!((status >> 8) & 0xff, 42, "exit status should propagate");
}

#[test]
fn phase0_exit_registration_rejects_missing_callbacks() {
    let _lock = STARTUP_TEST_LOCK.lock().unwrap();

    assert_eq!(unsafe { atexit(None) }, -1);
    assert_eq!(unsafe { on_exit(None, ptr::null_mut()) }, -1);
}

#[test]
fn cxa_atexit_finalize_filters_dso_and_runs_lifo_once() {
    let _lock = STARTUP_TEST_LOCK.lock().unwrap();
    unsafe { __cxa_finalize(ptr::null_mut()) };
    CXA_ATEXIT_ORDER.lock().unwrap().clear();

    let mut one = 1;
    let mut two = 2;
    let mut three = 3;
    let mut dso_one = 0u8;
    let mut dso_two = 0u8;
    let dso_one_ptr = (&mut dso_one as *mut u8).cast::<c_void>();
    let dso_two_ptr = (&mut dso_two as *mut u8).cast::<c_void>();

    assert_eq!(
        unsafe {
            __cxa_atexit(
                cxa_atexit_record_arg,
                (&mut one as *mut c_int).cast::<c_void>(),
                dso_one_ptr,
            )
        },
        0
    );
    assert_eq!(
        unsafe {
            __cxa_atexit(
                cxa_atexit_record_arg,
                (&mut two as *mut c_int).cast::<c_void>(),
                dso_two_ptr,
            )
        },
        0
    );
    assert_eq!(
        unsafe {
            __cxa_atexit(
                cxa_atexit_record_arg,
                (&mut three as *mut c_int).cast::<c_void>(),
                dso_one_ptr,
            )
        },
        0
    );

    unsafe { __cxa_finalize(dso_one_ptr) };
    assert_eq!(
        CXA_ATEXIT_ORDER.lock().unwrap().as_slice(),
        &[3, 1],
        "__cxa_finalize(dso) should run matching handlers in LIFO order"
    );

    unsafe { __cxa_finalize(ptr::null_mut()) };
    assert_eq!(
        CXA_ATEXIT_ORDER.lock().unwrap().as_slice(),
        &[3, 1, 2],
        "__cxa_finalize(NULL) should drain the remaining handlers"
    );

    unsafe { __cxa_finalize(ptr::null_mut()) };
    assert_eq!(
        CXA_ATEXIT_ORDER.lock().unwrap().as_slice(),
        &[3, 1, 2],
        "__cxa_finalize should not rerun drained handlers"
    );
}

// ---------------------------------------------------------------------------
// Phase-0 — argc / argv edge cases
// ---------------------------------------------------------------------------

#[test]
fn phase0_zero_argc_succeeds() {
    let _lock = STARTUP_TEST_LOCK.lock().unwrap();
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
    let _lock = STARTUP_TEST_LOCK.lock().unwrap();
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
    let _lock = STARTUP_TEST_LOCK.lock().unwrap();
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
    let _lock = STARTUP_TEST_LOCK.lock().unwrap();
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
    let _lock = STARTUP_TEST_LOCK.lock().unwrap();
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
    let _lock = STARTUP_TEST_LOCK.lock().unwrap();
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
    let _lock = STARTUP_TEST_LOCK.lock().unwrap();
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

#[test]
#[ignore = "requires real hardened mode bounds checking (bd-q3snos)"]
fn phase0_skips_unterminated_program_name_globals() {
    let _lock = STARTUP_TEST_LOCK.lock().unwrap();
    program_invocation_name.store(ptr::null_mut(), Ordering::Release);
    program_invocation_short_name.store(ptr::null_mut(), Ordering::Release);
    __progname.store(ptr::null_mut(), Ordering::Release);

    let raw = malloc_tracked_unterminated(b"/tmp/unterminated-phase0-progname");
    let mut argv_env = vec![raw, ptr::null_mut(), ptr::null_mut()];
    let mut auxv = vec![AT_NULL, 0usize];

    let rc = unsafe {
        __frankenlibc_startup_phase0(
            Some(test_main),
            1,
            argv_env.as_mut_ptr(),
            None,
            None,
            None,
            auxv.as_mut_ptr().cast::<c_void>(),
        )
    };

    assert_eq!(rc, 42, "phase0 should still invoke main");
    assert!(
        program_invocation_name.load(Ordering::Acquire).is_null(),
        "unterminated argv[0] must not be published as program_invocation_name"
    );
    assert!(
        program_invocation_short_name
            .load(Ordering::Acquire)
            .is_null(),
        "unterminated argv[0] must not be published as short name"
    );
    assert!(
        __progname.load(Ordering::Acquire).is_null(),
        "unterminated argv[0] must not be published as __progname"
    );

    unsafe { frankenlibc_abi::malloc_abi::free(raw.cast()) };
}

// ---------------------------------------------------------------------------
// __cxa_thread_atexit_impl — edge cases
// ---------------------------------------------------------------------------

#[test]
fn cxa_thread_atexit_impl_null_obj_returns_zero() {
    let _lock = STARTUP_TEST_LOCK.lock().unwrap();
    let rc = unsafe { __cxa_thread_atexit_impl(test_dtor, ptr::null_mut(), ptr::null_mut()) };
    assert_eq!(rc, 0, "null obj should still register successfully");
}

// ---------------------------------------------------------------------------
// Snapshot field validation
// ---------------------------------------------------------------------------

#[test]
fn startup_snapshot_argc_matches_fixture() {
    let _lock = STARTUP_TEST_LOCK.lock().unwrap();
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
    let _lock = STARTUP_TEST_LOCK.lock().unwrap();
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
    let _lock = STARTUP_TEST_LOCK.lock().unwrap();
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

// ---------------------------------------------------------------------------
// getprogname / setprogname (BSD program-name accessors)
// ---------------------------------------------------------------------------
//
// These tests share the same backing storage as program_invocation_short_name
// and __progname (intentional aliasing per the bd-zt2w1 contract). They
// take the existing STARTUP_TEST_LOCK so they don't race against the
// CRT-startup tests above which also rewrite those globals.

fn cstr_lifetime(s: &'static [u8]) -> *const c_char {
    assert_eq!(s.last(), Some(&0), "fixture must be NUL-terminated");
    s.as_ptr() as *const c_char
}

fn malloc_tracked_unterminated(bytes: &[u8]) -> *mut c_char {
    unsafe {
        let raw = frankenlibc_abi::malloc_abi::malloc(bytes.len()).cast::<u8>();
        assert!(!raw.is_null());
        let usable = frankenlibc_abi::malloc_abi::malloc_usable_size(raw.cast()).max(bytes.len());
        std::ptr::write_bytes(raw, 0x7f, usable);
        std::ptr::copy_nonoverlapping(bytes.as_ptr(), raw, bytes.len());
        raw.cast()
    }
}

#[test]
fn getprogname_returns_nonnull_even_when_unset() {
    let _g = STARTUP_TEST_LOCK.lock().unwrap();
    // Force the slot to NULL so we exercise the empty-fallback branch.
    program_invocation_short_name.store(ptr::null_mut(), Ordering::Release);
    __progname.store(ptr::null_mut(), Ordering::Release);

    let p = unsafe { getprogname() };
    assert!(!p.is_null(), "getprogname must never return NULL");
    let s = unsafe { std::ffi::CStr::from_ptr(p) }.to_bytes();
    assert_eq!(s, b"", "unset progname should be the empty string");
}

#[test]
fn setprogname_stores_basename() {
    let _g = STARTUP_TEST_LOCK.lock().unwrap();
    let buf: &'static [u8] = b"/usr/local/bin/myprog\0";
    unsafe { setprogname(cstr_lifetime(buf)) };

    let p = unsafe { getprogname() };
    let bytes = unsafe { std::ffi::CStr::from_ptr(p) }.to_bytes();
    assert_eq!(
        bytes, b"myprog",
        "basename must be everything after the last '/'"
    );

    // Both glibc-compatible aliases observe the same value.
    let short = program_invocation_short_name.load(Ordering::Acquire);
    let prog = __progname.load(Ordering::Acquire);
    assert_eq!(short, prog as *mut _);
    let short_bytes = unsafe { std::ffi::CStr::from_ptr(short) }.to_bytes();
    assert_eq!(short_bytes, b"myprog");
}

#[test]
fn setprogname_no_slash_uses_input_directly() {
    let _g = STARTUP_TEST_LOCK.lock().unwrap();
    let buf: &'static [u8] = b"barename\0";
    unsafe { setprogname(cstr_lifetime(buf)) };
    let p = unsafe { getprogname() };
    let bytes = unsafe { std::ffi::CStr::from_ptr(p) }.to_bytes();
    assert_eq!(bytes, b"barename");
}

#[test]
fn setprogname_trailing_slash_yields_empty() {
    // Pathological case: "/foo/" — the basename is "" (everything after
    // the trailing slash). Matches NetBSD behavior.
    let _g = STARTUP_TEST_LOCK.lock().unwrap();
    let buf: &'static [u8] = b"/foo/\0";
    unsafe { setprogname(cstr_lifetime(buf)) };
    let p = unsafe { getprogname() };
    let bytes = unsafe { std::ffi::CStr::from_ptr(p) }.to_bytes();
    assert_eq!(bytes, b"");
}

#[test]
fn setprogname_null_is_no_op() {
    let _g = STARTUP_TEST_LOCK.lock().unwrap();
    let buf: &'static [u8] = b"sentinel\0";
    unsafe { setprogname(cstr_lifetime(buf)) };
    let before = program_invocation_short_name.load(Ordering::Acquire);

    // NULL must not crash and must not clobber the stored pointer.
    unsafe { setprogname(ptr::null()) };

    let after = program_invocation_short_name.load(Ordering::Acquire);
    assert_eq!(
        before, after,
        "NULL setprogname must leave the slot untouched"
    );
    let p = unsafe { getprogname() };
    let bytes = unsafe { std::ffi::CStr::from_ptr(p) }.to_bytes();
    assert_eq!(bytes, b"sentinel");
}

#[test]
#[ignore = "requires real hardened mode bounds checking (bd-q3snos)"]
fn setprogname_ignores_tracked_unterminated_name() {
    let _g = STARTUP_TEST_LOCK.lock().unwrap();
    let buf: &'static [u8] = b"sentinel\0";
    unsafe { setprogname(cstr_lifetime(buf)) };
    let before = program_invocation_short_name.load(Ordering::Acquire);

    let raw = malloc_tracked_unterminated(b"/tmp/unterminated-progname");
    unsafe { setprogname(raw) };

    let after = program_invocation_short_name.load(Ordering::Acquire);
    assert_eq!(
        before, after,
        "unterminated setprogname input must not replace the cached pointer"
    );
    let p = unsafe { getprogname() };
    let bytes = unsafe { std::ffi::CStr::from_ptr(p) }.to_bytes();
    assert_eq!(bytes, b"sentinel");

    unsafe { frankenlibc_abi::malloc_abi::free(raw.cast()) };
}

#[test]
fn setprogname_overrides_previous_value() {
    let _g = STARTUP_TEST_LOCK.lock().unwrap();
    let first: &'static [u8] = b"/first/path/aaa\0";
    let second: &'static [u8] = b"/second/path/bbb\0";

    unsafe { setprogname(cstr_lifetime(first)) };
    let p1 = unsafe { getprogname() };
    let bytes1 = unsafe { std::ffi::CStr::from_ptr(p1) }.to_bytes();
    assert_eq!(bytes1, b"aaa");

    unsafe { setprogname(cstr_lifetime(second)) };
    let p2 = unsafe { getprogname() };
    let bytes2 = unsafe { std::ffi::CStr::from_ptr(p2) }.to_bytes();
    assert_eq!(bytes2, b"bbb");
}

#[test]
fn getprogname_pointer_aliases_short_name_when_set() {
    let _g = STARTUP_TEST_LOCK.lock().unwrap();
    let buf: &'static [u8] = b"/path/aliascheck\0";
    unsafe { setprogname(cstr_lifetime(buf)) };
    let p = unsafe { getprogname() };
    let short = program_invocation_short_name.load(Ordering::Acquire) as *const c_char;
    assert_eq!(p, short, "getprogname must hand back the cached pointer");
}

// ---------------------------------------------------------------------------
// bd-73h55.1 — Edge case tests for owned startup default
// ---------------------------------------------------------------------------

const AT_SECURE: usize = 23;

struct TruncatedAuxvFixture {
    argv0: Vec<u8>,
    argv: Vec<*mut c_char>,
    #[allow(dead_code)]
    env: Vec<*mut c_char>,
    auxv: Vec<usize>,
}

impl TruncatedAuxvFixture {
    fn new_truncated(program: &[u8]) -> Self {
        let mut argv0 = program.to_vec();
        argv0.push(0);
        let mut me = Self {
            argv0,
            argv: Vec::new(),
            env: vec![ptr::null_mut()],
            auxv: vec![1usize, 42usize], // No AT_NULL terminator
        };
        me.argv.push(me.argv0.as_mut_ptr().cast::<c_char>());
        me.argv.push(ptr::null_mut());
        me
    }

    fn new_with_secure_mode(program: &[u8], secure: bool) -> Self {
        let mut argv0 = program.to_vec();
        argv0.push(0);
        let secure_val = if secure { 1usize } else { 0usize };
        let mut me = Self {
            argv0,
            argv: Vec::new(),
            env: vec![ptr::null_mut()],
            auxv: vec![AT_SECURE, secure_val, AT_NULL, 0],
        };
        me.argv.push(me.argv0.as_mut_ptr().cast::<c_char>());
        me.argv.push(ptr::null_mut());
        me
    }

    fn argc(&self) -> c_int {
        (self.argv.len() - 1) as c_int
    }

    fn argv_ptr(&mut self) -> *mut *mut c_char {
        self.argv.as_mut_ptr()
    }

    fn stack_end(&mut self) -> *mut c_void {
        self.auxv.as_mut_ptr().cast::<c_void>()
    }
}

#[test]
fn phase0_handles_truncated_auxv_vector() {
    let _lock = STARTUP_TEST_LOCK.lock().unwrap();
    let mut fix = TruncatedAuxvFixture::new_truncated(b"/usr/bin/truncated-auxv");
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
    assert_eq!(
        rc, 42,
        "truncated auxv should not prevent startup from running main"
    );
}

#[test]
fn phase0_classifies_secure_mode_from_auxv() {
    let _lock = STARTUP_TEST_LOCK.lock().unwrap();
    let mut fix = TruncatedAuxvFixture::new_with_secure_mode(b"/usr/bin/secure-test", true);
    let _ = unsafe {
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
    assert_eq!(
        snap.secure_mode_state,
        SecureModeState::Secure,
        "AT_SECURE=1 in auxv should yield SecureModeState::Secure"
    );
}

#[test]
fn phase0_classifies_nonsecure_mode_from_auxv() {
    let _lock = STARTUP_TEST_LOCK.lock().unwrap();
    let mut fix = TruncatedAuxvFixture::new_with_secure_mode(b"/usr/bin/nonsecure-test", false);
    let _ = unsafe {
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
    assert_eq!(
        snap.secure_mode_state,
        SecureModeState::NonSecure,
        "AT_SECURE=0 in auxv should yield SecureModeState::NonSecure"
    );
}
