//! Differential + semantic conformance for `posix_fallocate`'s glibc fallback
//! emulation (`internal_fallocate_emulate`).
//!
//! On the test host (ext4/tmpfs) the `fallocate(2)` syscall is natively
//! supported, so the production `posix_fallocate` never exercises its
//! `EOPNOTSUPP` fallback path. The fallback (a faithful port of glibc's
//! `sysdeps/posix/posix_fallocate.c` `__internal_fallocate`) is therefore
//! exposed as the Rust-visible `internal_fallocate_emulate` so this gate can
//! drive it directly.
//!
//! The parity contract is *observable file state*: after the call the file must
//! be extended to `offset+len` (never shrunk), every pre-existing byte must be
//! preserved, and every hole inside the requested range reads back as zero.
//! That state is identical whether produced by the kernel's native
//! `fallocate(fd, 0, …)` (what glibc uses on a supporting FS) or by the
//! byte-by-byte zero-fill emulation, so each scenario runs glibc's real
//! `posix_fallocate` on one file and the emulation on a byte-identical twin and
//! asserts the resulting size + full content match exactly.

use std::io::{Read, Seek, SeekFrom, Write};
use std::os::unix::io::AsRawFd;
use std::sync::atomic::{AtomicU64, Ordering};

use frankenlibc_abi::unistd_abi::internal_fallocate_emulate;

static COUNTER: AtomicU64 = AtomicU64::new(0);

/// A unique temp path for this process + call site.
fn temp_path(tag: &str) -> std::path::PathBuf {
    let n = COUNTER.fetch_add(1, Ordering::Relaxed);
    let mut p = std::env::temp_dir();
    p.push(format!(
        "fl-posix-fallocate-{}-{}-{}.tmp",
        std::process::id(),
        tag,
        n
    ));
    p
}

/// Initial file shape: a list of `(offset, bytes)` segments written at explicit
/// offsets (gaps between segments become real holes via `SeekFrom::Start`).
/// `final_len` optionally extends the file (sparsely) past the last segment.
struct Shape {
    segments: Vec<(u64, Vec<u8>)>,
    final_len: Option<u64>,
}

fn build_file(path: &std::path::Path, shape: &Shape) {
    let mut f = std::fs::OpenOptions::new()
        .create(true)
        .read(true)
        .write(true)
        .truncate(true)
        .open(path)
        .expect("create temp file");
    for (off, bytes) in &shape.segments {
        f.seek(SeekFrom::Start(*off)).expect("seek");
        f.write_all(bytes).expect("write segment");
    }
    if let Some(len) = shape.final_len {
        f.set_len(len).expect("set_len");
    }
    f.sync_all().expect("sync");
}

fn read_all(path: &std::path::Path) -> Vec<u8> {
    let mut f = std::fs::File::open(path).expect("open for read");
    let mut v = Vec::new();
    f.read_to_end(&mut v).expect("read_to_end");
    v
}

/// Build two byte-identical files, run glibc's real `posix_fallocate` on one and
/// the emulation on the other, and assert the resulting size + content match.
fn assert_parity(tag: &str, shape: Shape, offset: i64, len: i64) {
    let glibc_path = temp_path(&format!("{tag}-glibc"));
    let emul_path = temp_path(&format!("{tag}-emul"));
    build_file(&glibc_path, &shape);
    build_file(&emul_path, &shape);

    // glibc native path (kernel `fallocate` on a supporting FS).
    let glibc_file = std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .open(&glibc_path)
        .expect("open glibc file");
    // SAFETY: fd is valid and owned for the duration of the call.
    let glibc_rc = unsafe { libc::posix_fallocate(glibc_file.as_raw_fd(), offset, len) };
    assert_eq!(glibc_rc, 0, "[{tag}] glibc posix_fallocate failed");
    glibc_file.sync_all().expect("sync glibc");

    // FrankenLibC emulation path.
    let emul_file = std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .open(&emul_path)
        .expect("open emul file");
    // SAFETY: fd is valid and owned for the duration of the call.
    let emul_rc = unsafe { internal_fallocate_emulate(emul_file.as_raw_fd(), offset, len) };
    assert_eq!(emul_rc, 0, "[{tag}] emulation returned errno {emul_rc}");
    emul_file.sync_all().expect("sync emul");

    let glibc_bytes = read_all(&glibc_path);
    let emul_bytes = read_all(&emul_path);

    assert_eq!(
        emul_bytes.len(),
        glibc_bytes.len(),
        "[{tag}] size mismatch: emul={} glibc={}",
        emul_bytes.len(),
        glibc_bytes.len()
    );
    assert_eq!(
        emul_bytes, glibc_bytes,
        "[{tag}] content mismatch after fallocate(offset={offset}, len={len})"
    );

    let _ = std::fs::remove_file(&glibc_path);
    let _ = std::fs::remove_file(&emul_path);
}

#[test]
fn extend_empty_file() {
    assert_parity(
        "extend-empty",
        Shape {
            segments: vec![],
            final_len: None,
        },
        0,
        8192,
    );
}

#[test]
fn extend_file_with_leading_data() {
    assert_parity(
        "leading-data",
        Shape {
            segments: vec![(0, vec![0xAB; 100])],
            final_len: None,
        },
        0,
        8192,
    );
}

#[test]
fn fully_within_existing_data_is_noop_on_content() {
    assert_parity(
        "within-existing",
        Shape {
            segments: vec![(0, (0..10_000u32).map(|i| (i % 251) as u8).collect())],
            final_len: None,
        },
        0,
        4096,
    );
}

#[test]
fn within_sparse_hole_preserves_size() {
    // 1 byte at offset 20000 → file size 20001 with a large leading hole.
    assert_parity(
        "sparse-hole",
        Shape {
            segments: vec![(20_000, vec![0x7E])],
            final_len: None,
        },
        0,
        8192,
    );
}

#[test]
fn offset_beyond_eof_leaves_leading_hole() {
    // File of 100 bytes; allocate a region starting well past EOF.
    assert_parity(
        "beyond-eof",
        Shape {
            segments: vec![(0, vec![0x5A; 100])],
            final_len: None,
        },
        50_000,
        4096,
    );
}

// NOTE on `len == 0`: glibc's *native* `posix_fallocate` forwards to the
// `fallocate(2)` syscall, which the kernel rejects with `EINVAL` for a
// zero-length request — so on the test host the production `posix_fallocate`
// (and glibc's) both return `EINVAL`. glibc's *fallback* emulation, however,
// special-cases `len == 0` (extend-only via `ftruncate`, never shrink). The two
// `len == 0` cases below therefore exercise the emulation's documented fallback
// semantics directly rather than diffing against the native (EINVAL) path.

#[test]
fn zero_length_extends_via_truncate() {
    // len==0 extends (ftruncate) only when offset > current size.
    let path = temp_path("zerolen-extend");
    build_file(
        &path,
        &Shape {
            segments: vec![(0, vec![0xC3; 100])],
            final_len: None,
        },
    );
    let f = std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .open(&path)
        .expect("open");
    // SAFETY: fd is valid for the duration of the call.
    assert_eq!(
        unsafe { internal_fallocate_emulate(f.as_raw_fd(), 200, 0) },
        0
    );
    f.sync_all().expect("sync");
    let bytes = read_all(&path);
    assert_eq!(bytes.len(), 200, "len==0 must extend to offset");
    assert!(bytes[..100].iter().all(|&b| b == 0xC3), "data preserved");
    assert!(
        bytes[100..].iter().all(|&b| b == 0),
        "extension zero-filled"
    );
    let _ = std::fs::remove_file(&path);
}

#[test]
fn zero_length_within_is_noop() {
    // len==0 with offset <= size leaves the file untouched.
    let path = temp_path("zerolen-within");
    build_file(
        &path,
        &Shape {
            segments: vec![(0, vec![0x11; 500])],
            final_len: None,
        },
    );
    let f = std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .open(&path)
        .expect("open");
    // SAFETY: fd is valid for the duration of the call.
    assert_eq!(
        unsafe { internal_fallocate_emulate(f.as_raw_fd(), 100, 0) },
        0
    );
    f.sync_all().expect("sync");
    let bytes = read_all(&path);
    assert_eq!(bytes.len(), 500, "len==0 within must not shrink or grow");
    assert!(bytes.iter().all(|&b| b == 0x11), "content unchanged");
    let _ = std::fs::remove_file(&path);
}

#[test]
fn unaligned_offset_and_len() {
    // Exercise the `(len-1) % increment` leading-block alignment with values
    // that are not multiples of the filesystem block size.
    assert_parity(
        "unaligned",
        Shape {
            segments: vec![(0, vec![0xF0; 333])],
            final_len: None,
        },
        333,
        5000,
    );
}

#[test]
fn large_multiblock_extension() {
    assert_parity(
        "multiblock",
        Shape {
            segments: vec![(0, vec![0x99; 4096])],
            final_len: None,
        },
        0,
        64 * 1024,
    );
}

/// Direct semantic checks that do not depend on the glibc oracle: negative
/// ranges are rejected, the file is never shrunk, and pre-existing data is
/// preserved verbatim while the tail of the requested range reads back zero.
#[test]
fn semantic_contract_holds() {
    let path = temp_path("semantic");
    build_file(
        &path,
        &Shape {
            segments: vec![(0, vec![0x42; 1000])],
            final_len: None,
        },
    );
    let f = std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .open(&path)
        .expect("open");
    let fd = f.as_raw_fd();

    // Negative offset / len rejected with EINVAL (matches the C entry point).
    // SAFETY: fd is valid.
    assert_eq!(
        unsafe { internal_fallocate_emulate(fd, -1, 16) },
        libc::EINVAL
    );
    // SAFETY: fd is valid.
    assert_eq!(
        unsafe { internal_fallocate_emulate(fd, 0, -1) },
        libc::EINVAL
    );

    // Allocate past EOF: extend to 4000, preserve [0,1000), zero [1000,4000).
    // SAFETY: fd is valid.
    assert_eq!(unsafe { internal_fallocate_emulate(fd, 0, 4000) }, 0);
    f.sync_all().expect("sync");

    let bytes = read_all(&path);
    assert_eq!(bytes.len(), 4000, "file must extend to offset+len");
    assert!(
        bytes[..1000].iter().all(|&b| b == 0x42),
        "pre-existing data must be preserved"
    );
    assert!(
        bytes[1000..].iter().all(|&b| b == 0),
        "newly allocated region must read back as zero"
    );

    // A request fully inside the file must never shrink it.
    // SAFETY: fd is valid.
    assert_eq!(unsafe { internal_fallocate_emulate(fd, 0, 100) }, 0);
    f.sync_all().expect("sync");
    assert_eq!(read_all(&path).len(), 4000, "file must never shrink");

    let _ = std::fs::remove_file(&path);
}
