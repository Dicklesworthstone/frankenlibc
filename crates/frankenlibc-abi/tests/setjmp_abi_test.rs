#![cfg(target_os = "linux")]

//! Integration smoke coverage for the native setjmp ABI path.
//!
//! Direct Rust calls into `setjmp`/`longjmp` are not a sound verification
//! strategy here:
//! - debug builds intentionally resolve to host libc to avoid symbol/runtime
//!   conflicts inside Rust's own test harness
//! - release builds can still interact badly with Rust/libtest because
//!   `setjmp` is a C control-transfer primitive, not a normal Rust FFI call
//!
//! The real verification for this surface lives in the C-based LD_PRELOAD
//! smoke script invoked below.

use std::ffi::c_void;
use std::path::PathBuf;
use std::process::Command;

use frankenlibc_abi::setjmp_abi::{_setjmp, setjmp, sigsetjmp};

const PHASE1_JMPBUF_BYTES: usize = 128;

unsafe fn malloc_tracked_zeroed_bytes(len: usize) -> *mut c_void {
    let raw = unsafe { frankenlibc_abi::malloc_abi::malloc(len) }.cast::<u8>();
    assert!(!raw.is_null());
    unsafe { std::ptr::write_bytes(raw, 0, len) };
    raw.cast()
}

fn assert_known_short(raw: *const c_void, required: usize) {
    let remaining =
        frankenlibc_abi::malloc_abi::malloc_known_remaining_for_tests(raw).unwrap_or(usize::MAX);
    assert_ne!(
        remaining,
        usize::MAX,
        "test allocation should be tracked by malloc metadata"
    );
    assert!(
        remaining < required,
        "test allocation should expose {remaining} tracked bytes, less than required {required}"
    );
}

fn errno_value() -> i32 {
    unsafe { *frankenlibc_abi::errno_abi::__errno_location() }
}

unsafe fn free_tracked(raw: *mut c_void) {
    unsafe { frankenlibc_abi::malloc_abi::free(raw) };
}

fn workspace_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .expect("crate dir should have workspace parent")
        .parent()
        .expect("workspace root should exist")
        .to_path_buf()
}

#[test]
fn setjmp_rejects_tracked_short_jump_buffer() {
    let raw = unsafe { malloc_tracked_zeroed_bytes(PHASE1_JMPBUF_BYTES - 1) };
    assert_known_short(raw, PHASE1_JMPBUF_BYTES);

    let rc = unsafe { setjmp(raw) };

    assert_eq!(rc, -1);
    assert_eq!(errno_value(), libc::EFAULT);
    unsafe { free_tracked(raw) };
}

#[test]
fn underscored_setjmp_rejects_tracked_short_jump_buffer() {
    let raw = unsafe { malloc_tracked_zeroed_bytes(PHASE1_JMPBUF_BYTES - 1) };
    assert_known_short(raw, PHASE1_JMPBUF_BYTES);

    let rc = unsafe { _setjmp(raw) };

    assert_eq!(rc, -1);
    assert_eq!(errno_value(), libc::EFAULT);
    unsafe { free_tracked(raw) };
}

#[test]
fn sigsetjmp_rejects_tracked_short_jump_buffer() {
    let raw = unsafe { malloc_tracked_zeroed_bytes(PHASE1_JMPBUF_BYTES - 1) };
    assert_known_short(raw, PHASE1_JMPBUF_BYTES);

    let rc = unsafe { sigsetjmp(raw, 1) };

    assert_eq!(rc, -1);
    assert_eq!(errno_value(), libc::EFAULT);
    unsafe { free_tracked(raw) };
}

#[test]
fn native_setjmp_smoke_script_exists_and_is_executable() {
    let script = workspace_root().join("scripts/check_setjmp_native.sh");
    assert!(script.exists(), "missing script: {}", script.display());

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;

        let mode = std::fs::metadata(&script)
            .expect("script metadata should be readable")
            .permissions()
            .mode();
        assert_ne!(
            mode & 0o111,
            0,
            "script must be executable: {}",
            script.display()
        );
    }
}

#[test]
fn native_setjmp_smoke_script_succeeds() {
    let root = workspace_root();
    let script = root.join("scripts/check_setjmp_native.sh");
    let output = Command::new("bash")
        .arg(&script)
        .current_dir(&root)
        .output()
        .expect("check_setjmp_native.sh should execute");

    assert!(
        output.status.success(),
        "check_setjmp_native.sh failed\nstatus={:?}\nstdout:\n{}\nstderr:\n{}",
        output.status.code(),
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
}
