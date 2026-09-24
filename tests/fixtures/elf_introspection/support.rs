use std::path::PathBuf;
use std::process::Command;
use std::sync::atomic::{AtomicU64, Ordering};

static NEXT: AtomicU64 = AtomicU64::new(0);

pub fn fixture() -> PathBuf {
    let stamp = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH).unwrap().as_nanos();
    let directory = std::env::temp_dir().join(format!(
        "frankenlibc-inspection-{}-{stamp}-{}", std::process::id(),
        NEXT.fetch_add(1, Ordering::Relaxed),
    ));
    std::fs::create_dir_all(&directory).unwrap();
    let output = directory.join("libinspect.so");
    let source = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../tests/fixtures/elf_introspection/object.c");
    let result = Command::new("cc")
        .args(["-shared", "-fPIC", "-nostdlib", "-O0", "-fno-omit-frame-pointer",
            "-fasynchronous-unwind-tables", "-Wl,--eh-frame-hdr", "-Wl,--hash-style=both",
            "-Wl,--build-id=none", "-Wl,-soname,libinspect.so", "-o"])
        .arg(&output).arg(source).output().expect("cc is required for the real ELF fixture");
    assert!(result.status.success(), "fixture build failed: {}", String::from_utf8_lossy(&result.stderr));
    output
}
