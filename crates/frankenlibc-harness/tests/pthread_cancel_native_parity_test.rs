//! Integration gate test for `bd-rc0923-epic-eeuy4f.24`:
//! verifies the architecture and live execution of deferred + asynchronous
//! `pthread_cancel` across hosted and native-thread (`FRANKENLIBC_THREAD_NATIVE=1`)
//! backends, RIP-guarded `__fl_syscall_cancel_arch` blocking-syscall interruption,
//! owned-startup `main`-thread unwind boundaries + last-thread `exit(0)` teardown,
//! C cleanup handlers, C++ `abi::__forced_unwind` / `catch (...)`, C11 `thrd_*`
//! cancellation, and narrow/wide `stdio` stream lock release.

use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

fn workspace_root() -> PathBuf {
    if let Some(manifest_dir) = option_env!("CARGO_MANIFEST_DIR") {
        Path::new(manifest_dir)
            .parent()
            .and_then(Path::parent)
            .expect("workspace root must exist")
            .to_path_buf()
    } else {
        std::env::current_dir().expect("cwd must exist")
    }
}

#[test]
fn native_syscall_cancellation_and_startup_unwind_contracts_are_wired() {
    let root = workspace_root();

    let raw = fs::read_to_string(root.join("crates/frankenlibc-core/src/syscall/raw.rs"))
        .expect("syscall/raw.rs readable");
    assert!(raw.contains("__fl_syscall_cancel_arch"));
    assert!(raw.contains("__fl_syscall_cancel_begin"));
    assert!(raw.contains("__fl_syscall_cancel_insn"));
    assert!(raw.contains("__fl_syscall_cancel_abort"));
    assert!(raw.contains("pub fn arm_native_cancel_syscall"));
    assert!(raw.contains("pub fn disarm_native_cancel_syscall"));

    let tls = fs::read_to_string(root.join("crates/frankenlibc-core/src/pthread/tls.rs"))
        .expect("pthread/tls.rs readable");
    assert!(tls.contains("pub const CANCEL_FLAG_DISABLED"));
    assert!(tls.contains("pub const CANCEL_FLAG_ASYNC"));
    assert!(tls.contains("pub const CANCEL_FLAG_IN_POINT"));
    assert!(tls.contains("pub fn unregistered_cancellation_wait"));
    assert!(tls.contains("pub fn request_unregistered_cancellation_with_flags"));

    let signal_abi = fs::read_to_string(root.join("crates/frankenlibc-abi/src/signal_abi.rs"))
        .expect("signal_abi.rs readable");
    assert!(signal_abi.contains("pub(crate) const NATIVE_SIGCANCEL: c_int = 32"));
    assert!(signal_abi.contains("pub(crate) fn ensure_native_sigcancel_installed"));
    assert!(signal_abi.contains("native_sigcancel_trampoline"));

    let pthread_abi = fs::read_to_string(root.join("crates/frankenlibc-abi/src/pthread_abi.rs"))
        .expect("pthread_abi.rs readable");
    assert!(pthread_abi.contains("pub(crate) fn install_native_last_thread_exit_hook"));
    assert!(pthread_abi.contains("pub(crate) fn set_current_native_unwind_boundary"));
    assert!(pthread_abi.contains("set_native_cancel_point_active"));

    let startup_abi = fs::read_to_string(root.join("crates/frankenlibc-abi/src/startup_abi.rs"))
        .expect("startup_abi.rs readable");
    assert!(startup_abi.contains("unsafe extern \"C-unwind\" fn run_owned_main_native"));
    assert!(startup_abi.contains("install_native_last_thread_exit_hook"));

    let malloc_abi = fs::read_to_string(root.join("crates/frankenlibc-abi/src/malloc_abi.rs"))
        .expect("malloc_abi.rs readable");
    assert!(malloc_abi.contains("HOST_ALLOCATOR_NATIVE_THREAD_OWNER_TID"));
    assert!(malloc_abi.contains("disable_compiler_tls_cache_for_native_threads"));
}

#[test]
fn pthread_cancel_native_and_hosted_e2e_parity_gate_passes() {
    let root = workspace_root();
    let gate_script = root.join("scripts/check_pthread_cancel_native_parity.sh");
    assert!(
        gate_script.is_file(),
        "gate script must exist at {}",
        gate_script.display()
    );

    let explicit_lib = std::env::var_os("FRANKENLIBC_CANCEL_TEST_LIB").map(PathBuf::from);
    let lib = explicit_lib
        .clone()
        .unwrap_or_else(|| root.join("target/release/libfrankenlibc_abi.so"));
    if explicit_lib.is_some() {
        assert!(
            lib.is_file(),
            "FRANKENLIBC_CANCEL_TEST_LIB must point to an existing release libfrankenlibc_abi.so: {}",
            lib.display()
        );
    }

    let syntax = Command::new("bash")
        .arg("-n")
        .arg(&gate_script)
        .current_dir(&root)
        .output()
        .expect("failed to syntax-check check_pthread_cancel_native_parity.sh");
    assert!(
        syntax.status.success(),
        "bash -n failed: {}",
        String::from_utf8_lossy(&syntax.stderr)
    );

    if !lib.is_file() {
        // Remote debug-only test workers omit `target/release/libfrankenlibc_abi.so`;
        // still verify all C11/C++17 cancellation fixtures compile cleanly under -Werror.
        for (compiler, flags, src) in [
            (
                "cc",
                &["-std=c11"][..],
                "tests/integration/fixture_pthread_cancel.c",
            ),
            (
                "c++",
                &["-std=c++17"][..],
                "tests/integration/fixture_cancel_forced_unwind.cpp",
            ),
            (
                "cc",
                &["-std=c11"][..],
                "tests/integration/fixture_c11_thread_cancel_lifecycle.c",
            ),
            (
                "c++",
                &["-x", "c++", "-std=c++17"][..],
                "tests/integration/fixture_stdio_cancel.c",
            ),
        ] {
            let status = Command::new(compiler)
                .args(flags)
                .args(["-fsyntax-only", "-Wall", "-Wextra", "-Werror", "-pthread"])
                .arg(root.join(src))
                .status()
                .expect("compiler invocation must succeed");
            assert!(
                status.success(),
                "{compiler} -fsyntax-only failed for {src}"
            );
        }
        return;
    }

    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0);
    let out_dir =
        std::env::temp_dir().join(format!("fl_cancel_parity_{}_{nanos}", std::process::id()));
    let output = Command::new("bash")
        .arg(&gate_script)
        .arg(&lib)
        .env("FRANKENLIBC_CANCEL_PARITY_OUT_DIR", &out_dir)
        .current_dir(&root)
        .output()
        .expect("failed to invoke check_pthread_cancel_native_parity.sh");
    if !output.status.success() {
        panic!(
            "check_pthread_cancel_native_parity.sh failed (status={:?}):\nstdout:\n{}\nstderr:\n{}",
            output.status.code(),
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
    }
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains("PASS: pthread_cancel native+hosted parity gate verified"),
        "unexpected gate stdout: {stdout}"
    );
}
