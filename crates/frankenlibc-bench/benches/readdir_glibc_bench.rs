//! Head-to-head `readdir` benchmark: frankenlibc vs host glibc (cc/BlackThrush,
//! BOLD-VERIFY). Validates the `ApiFamily::IoFd` membrane fast-path additions
//! (observe() + STRICT decide(), commit 0b08a21e8): `readdir` is the hot
//! directory-iteration idiom (`while ((d = readdir(dir)))`), buffered so most calls
//! don't hit getdents, so the per-entry membrane overhead it previously paid was a
//! meaningful fraction.
//!
//! Measures one full rewind+drain pass per iteration over a stable, entry-rich
//! directory; the rewind cost is amortized over all entries. glibc is resolved via
//! `dlmopen(LM_ID_NEWLM)` so frankenlibc's exported dir symbols cannot shadow it,
//! and glibc's `DIR*` comes from glibc's own `opendir` (no cross-libc DIR* mixing).
//!
//! Run: `cargo bench -p frankenlibc-bench --bench readdir_glibc_bench --features abi-bench`
//! (PENDING: authored during the disk-low window; to be RUN when disk recovers.)

use std::ffi::{c_char, c_void, CString};
use std::hint::black_box;
use std::sync::OnceLock;

use criterion::{criterion_group, criterion_main, Criterion};
use frankenlibc_abi::dirent_abi as fl;

type OpendirFn = unsafe extern "C" fn(*const c_char) -> *mut c_void;
type ReaddirFn = unsafe extern "C" fn(*mut c_void) -> *mut libc::dirent;
type RewinddirFn = unsafe extern "C" fn(*mut c_void);

struct HostDir {
    opendir: OpendirFn,
    readdir: ReaddirFn,
    rewinddir: RewinddirFn,
}

fn host() -> &'static HostDir {
    static H: OnceLock<HostDir> = OnceLock::new();
    H.get_or_init(|| unsafe {
        let handle = libc::dlmopen(
            libc::LM_ID_NEWLM,
            b"libc.so.6\0".as_ptr().cast(),
            libc::RTLD_LAZY | libc::RTLD_LOCAL,
        );
        assert!(!handle.is_null(), "dlmopen libc.so.6 failed");
        let sym = |n: &[u8]| {
            let s = libc::dlsym(handle, n.as_ptr().cast());
            assert!(!s.is_null(), "dlsym failed");
            s
        };
        HostDir {
            opendir: std::mem::transmute::<*mut c_void, OpendirFn>(sym(b"opendir\0")),
            readdir: std::mem::transmute::<*mut c_void, ReaddirFn>(sym(b"readdir\0")),
            rewinddir: std::mem::transmute::<*mut c_void, RewinddirFn>(sym(b"rewinddir\0")),
        }
    })
}

/// A stable, entry-rich directory present on essentially every Linux host. If it
/// is missing on a given worker, the resume turn can swap it.
const DIR_PATH: &str = "/usr/lib";

fn bench(c: &mut Criterion) {
    let path = CString::new(DIR_PATH).expect("path");

    let fl_dir = unsafe { fl::opendir(path.as_ptr()) };
    assert!(!fl_dir.is_null(), "fl::opendir({DIR_PATH}) returned NULL");

    let h = host();
    let gl_dir = unsafe { (h.opendir)(path.as_ptr()) };
    assert!(!gl_dir.is_null(), "host opendir({DIR_PATH}) returned NULL");

    // Sanity: fl and glibc enumerate the same number of entries over the same dir.
    let fl_count = unsafe {
        fl::rewinddir(fl_dir);
        let mut n = 0u64;
        while !fl::readdir(fl_dir).is_null() {
            n += 1;
        }
        n
    };
    let gl_count = unsafe {
        (h.rewinddir)(gl_dir);
        let mut n = 0u64;
        while !(h.readdir)(gl_dir).is_null() {
            n += 1;
        }
        n
    };
    assert!(fl_count > 1, "{DIR_PATH} should have entries (got {fl_count})");
    assert_eq!(fl_count, gl_count, "fl vs glibc readdir entry-count mismatch");

    let mut group = c.benchmark_group("readdir_drain");
    group.bench_function("frankenlibc_abi", |b| {
        b.iter(|| {
            unsafe { fl::rewinddir(fl_dir) };
            let mut n = 0u64;
            while !unsafe { fl::readdir(fl_dir) }.is_null() {
                n += 1;
            }
            black_box(n);
        });
    });
    group.bench_function("host_glibc", |b| {
        b.iter(|| {
            unsafe { (h.rewinddir)(gl_dir) };
            let mut n = 0u64;
            while !unsafe { (h.readdir)(gl_dir) }.is_null() {
                n += 1;
            }
            black_box(n);
        });
    });
    group.finish();

    unsafe { fl::closedir(fl_dir) };
}

criterion_group! {
    name = benches;
    config = Criterion::default()
        .sample_size(50)
        .warm_up_time(std::time::Duration::from_millis(500))
        .measurement_time(std::time::Duration::from_secs(2));
    targets = bench
}
criterion_main!(benches);
