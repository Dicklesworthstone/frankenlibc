//! Shared real-linker fixture construction for the core and native ABI tests.
use std::path::{Path, PathBuf};
use std::process::{Command, Output};
use std::sync::atomic::{AtomicU64, Ordering};

static NEXT_DIRECTORY: AtomicU64 = AtomicU64::new(0);

pub fn build(style: &str, packing: &str) -> PathBuf {
    let directory = std::env::temp_dir().join(format!(
        "frankenlibc-sectionless-{}-{}-{}-{}",
        std::process::id(),
        NEXT_DIRECTORY.fetch_add(1, Ordering::Relaxed),
        style,
        packing
    ));
    // Do not silently reuse a fixture from another run or skip missing tools.
    std::fs::create_dir(&directory).expect("create isolated sectionless fixture directory");
    let script = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../tests/fixtures/elf_sectionless/build.sh");
    let output = Command::new("bash")
        .arg(script)
        .arg(&directory)
        .arg(style)
        .arg(packing)
        .env_remove("LD_PRELOAD")
        .output()
        .expect("run fixture compiler");
    assert_success(&output);
    directory
}

pub fn assert_success(output: &Output) {
    assert!(
        output.status.success(),
        "status={}\nstdout={}\nstderr={}",
        output.status,
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
}
