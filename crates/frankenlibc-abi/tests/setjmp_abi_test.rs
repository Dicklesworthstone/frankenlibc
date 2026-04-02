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

use std::path::PathBuf;
use std::process::Command;

fn workspace_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .expect("crate dir should have workspace parent")
        .parent()
        .expect("workspace root should exist")
        .to_path_buf()
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
