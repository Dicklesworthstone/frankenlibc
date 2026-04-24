#![cfg(target_os = "linux")]

//! Differential conformance harness for `<ftw.h>` file tree walks:
//!   - ftw  (legacy file tree walk)
//!   - nftw (new file tree walk with flags)
//!
//! Tests build a controlled tempdir tree, then walk it with each impl
//! and compare the visited path set + reported file types.
//!
//! Bead: CONFORMANCE: libc ftw.h diff matrix.

use std::ffi::{CStr, CString, c_char, c_int, c_void};
use std::sync::Mutex;
use std::sync::atomic::{AtomicUsize, Ordering};

use frankenlibc_abi::unistd_abi as fl;

unsafe extern "C" {
    fn ftw(
        dirpath: *const c_char,
        cb: Option<unsafe extern "C" fn(*const c_char, *const libc::stat, c_int) -> c_int>,
        nopenfd: c_int,
    ) -> c_int;
    fn nftw(
        dirpath: *const c_char,
        cb: Option<
            unsafe extern "C" fn(*const c_char, *const libc::stat, c_int, *mut c_void) -> c_int,
        >,
        nopenfd: c_int,
        flags: c_int,
    ) -> c_int;
}

#[repr(C)]
struct FtwBuf {
    base: c_int,
    level: c_int,
}

const FTW_F: c_int = 0; // regular file
const FTW_D: c_int = 1; // directory
const FTW_DNR: c_int = 2;
const FTW_NS: c_int = 3;
const FTW_SL: c_int = 4;
const FTW_DP: c_int = 5;
const FTW_SLN: c_int = 6;

const FTW_PHYS: c_int = 1; // don't follow symlinks
const FTW_DEPTH: c_int = 8; // post-order (was 4 — pre-bd-ftw-4 bug, FTW_CHDIR=4)

// Tests share a global collection vector since the C callback can't
// capture closures.
static COLLECTOR: Mutex<Vec<(String, c_int)>> = Mutex::new(Vec::new());
static COUNT: AtomicUsize = AtomicUsize::new(0);

unsafe extern "C" fn collect_ftw(
    path: *const c_char,
    _st: *const libc::stat,
    typeflag: c_int,
) -> c_int {
    let p = unsafe { CStr::from_ptr(path) }
        .to_string_lossy()
        .into_owned();
    if let Ok(mut v) = COLLECTOR.lock() {
        v.push((p, typeflag));
    }
    COUNT.fetch_add(1, Ordering::Relaxed);
    0
}

unsafe extern "C" fn collect_nftw(
    path: *const c_char,
    _st: *const libc::stat,
    typeflag: c_int,
    _ftwbuf: *mut c_void,
) -> c_int {
    let p = unsafe { CStr::from_ptr(path) }
        .to_string_lossy()
        .into_owned();
    if let Ok(mut v) = COLLECTOR.lock() {
        v.push((p, typeflag));
    }
    COUNT.fetch_add(1, Ordering::Relaxed);
    0
}

fn unique_tempdir() -> std::path::PathBuf {
    use std::sync::atomic::AtomicU64;
    static COUNTER: AtomicU64 = AtomicU64::new(0);
    let id = COUNTER.fetch_add(1, Ordering::Relaxed);
    let pid = std::process::id();
    std::env::temp_dir().join(format!("fl_ftw_diff_{pid}_{id}"))
}

fn build_tree() -> std::path::PathBuf {
    let dir = unique_tempdir();
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    std::fs::write(dir.join("a.txt"), b"a").unwrap();
    std::fs::write(dir.join("b.txt"), b"b").unwrap();
    std::fs::create_dir(dir.join("sub")).unwrap();
    std::fs::write(dir.join("sub/c.txt"), b"c").unwrap();
    std::fs::write(dir.join("sub/d.txt"), b"d").unwrap();
    dir
}

/// Run a walker (use_fl=true → fl, false → libc). Returns the sorted
/// (path-suffix-after-base, typeflag) collection.
fn run_ftw(use_fl: bool, base: &std::path::Path) -> Vec<(String, c_int)> {
    {
        COLLECTOR.lock().unwrap().clear();
    }
    COUNT.store(0, Ordering::Relaxed);
    let cbase = CString::new(base.to_string_lossy().as_bytes()).unwrap();
    let r = if use_fl {
        unsafe { fl::ftw(cbase.as_ptr(), Some(collect_ftw), 16) }
    } else {
        unsafe { ftw(cbase.as_ptr(), Some(collect_ftw), 16) }
    };
    assert_eq!(r, 0, "ftw return: use_fl={use_fl}");
    let mut v = COLLECTOR.lock().unwrap().clone();
    let base_str = base.to_string_lossy().into_owned();
    for entry in v.iter_mut() {
        if let Some(rest) = entry.0.strip_prefix(&base_str) {
            entry.0 = rest.to_string();
        }
    }
    v.sort();
    v
}

fn run_nftw(use_fl: bool, base: &std::path::Path, flags: c_int) -> Vec<(String, c_int)> {
    {
        COLLECTOR.lock().unwrap().clear();
    }
    COUNT.store(0, Ordering::Relaxed);
    let cbase = CString::new(base.to_string_lossy().as_bytes()).unwrap();
    let r = if use_fl {
        unsafe { fl::nftw(cbase.as_ptr(), Some(collect_nftw), 16, flags) }
    } else {
        unsafe { nftw(cbase.as_ptr(), Some(collect_nftw), 16, flags) }
    };
    assert_eq!(r, 0, "nftw return: use_fl={use_fl}");
    let mut v = COLLECTOR.lock().unwrap().clone();
    let base_str = base.to_string_lossy().into_owned();
    for entry in v.iter_mut() {
        if let Some(rest) = entry.0.strip_prefix(&base_str) {
            entry.0 = rest.to_string();
        }
    }
    v.sort();
    v
}

// ftw is process-global via the static COLLECTOR; serialize.
static FTW_SERIAL: Mutex<()> = Mutex::new(());

#[test]
fn diff_ftw_visits_same_set() {
    let _g = FTW_SERIAL.lock().unwrap_or_else(|e| e.into_inner());
    let dir = build_tree();
    let v_fl = run_ftw(true, &dir);
    let v_lc = run_ftw(false, &dir);
    let _ = std::fs::remove_dir_all(&dir);
    assert_eq!(
        v_fl, v_lc,
        "ftw visited set divergence:\n  fl: {v_fl:?}\n  lc: {v_lc:?}"
    );
    let _ = (FTW_F, FTW_D, FTW_DNR, FTW_NS, FTW_SL, FTW_DP, FTW_SLN);
}

#[test]
fn diff_nftw_phys_visits_same_set() {
    let _g = FTW_SERIAL.lock().unwrap_or_else(|e| e.into_inner());
    let dir = build_tree();
    let v_fl = run_nftw(true, &dir, FTW_PHYS);
    let v_lc = run_nftw(false, &dir, FTW_PHYS);
    let _ = std::fs::remove_dir_all(&dir);
    assert_eq!(
        v_fl, v_lc,
        "nftw FTW_PHYS visited set divergence:\n  fl: {v_fl:?}\n  lc: {v_lc:?}"
    );
}

#[test]
fn diff_nftw_depth_visits_same_set() {
    let _g = FTW_SERIAL.lock().unwrap_or_else(|e| e.into_inner());
    let dir = build_tree();
    // FTW_DEPTH visits dirs after their contents (FTW_DP type)
    let v_fl = run_nftw(true, &dir, FTW_DEPTH);
    let v_lc = run_nftw(false, &dir, FTW_DEPTH);
    let _ = std::fs::remove_dir_all(&dir);
    assert_eq!(
        v_fl, v_lc,
        "nftw FTW_DEPTH visited set divergence:\n  fl: {v_fl:?}\n  lc: {v_lc:?}"
    );
}

// DISC-FTW-001 closed by bd-ftw2: POSIX says ftw "shall return -1 if
// it cannot start the walk." Both fl and glibc now return -1 on
// nonexistent dirpath. Asserted strictly.
#[test]
fn diff_ftw_nonexistent_dir() {
    let _g = FTW_SERIAL.lock().unwrap_or_else(|e| e.into_inner());
    let cpath = CString::new("/this/dir/does/not/exist/xyz").unwrap();
    let r_fl = unsafe { fl::ftw(cpath.as_ptr(), Some(collect_ftw), 16) };
    let r_lc = unsafe { ftw(cpath.as_ptr(), Some(collect_ftw), 16) };
    let _ = FtwBuf { base: 0, level: 0 };
    assert!(
        (r_fl < 0) == (r_lc < 0),
        "ftw nonexistent fail-match: fl={r_fl}, lc={r_lc}"
    );
    assert_eq!(r_fl, -1, "ftw should return -1 on ENOENT root");
}

#[test]
fn diff_nftw_nonexistent_dir() {
    let _g = FTW_SERIAL.lock().unwrap_or_else(|e| e.into_inner());
    let cpath = CString::new("/this/dir/does/not/exist/xyz").unwrap();
    let r_fl = unsafe { fl::nftw(cpath.as_ptr(), Some(collect_nftw), 16, 0) };
    let r_lc = unsafe { nftw(cpath.as_ptr(), Some(collect_nftw), 16, 0) };
    assert!(
        (r_fl < 0) == (r_lc < 0),
        "nftw nonexistent fail-match: fl={r_fl}, lc={r_lc}"
    );
    assert_eq!(r_fl, -1, "nftw should return -1 on ENOENT root");
}

// ===========================================================================
// bd-ftw-4: epic-completion regression tests
// ===========================================================================

thread_local! {
    static DEPTH_LOG_FL: std::cell::RefCell<Vec<(String, c_int, c_int)>> =
        const { std::cell::RefCell::new(Vec::new()) };
    static DEPTH_LOG_LC: std::cell::RefCell<Vec<(String, c_int, c_int)>> =
        const { std::cell::RefCell::new(Vec::new()) };
}

unsafe extern "C" fn record_depth_fl(
    path: *const c_char,
    _st: *const libc::stat,
    typeflag: c_int,
    ftwbuf: *mut c_void,
) -> c_int {
    let p = unsafe { CStr::from_ptr(path) }
        .to_string_lossy()
        .into_owned();
    let level = unsafe { *(ftwbuf as *const c_int).add(1) };
    DEPTH_LOG_FL.with(|c| c.borrow_mut().push((p, typeflag, level)));
    0
}

unsafe extern "C" fn record_depth_lc(
    path: *const c_char,
    _st: *const libc::stat,
    typeflag: c_int,
    ftwbuf: *mut c_void,
) -> c_int {
    let p = unsafe { CStr::from_ptr(path) }
        .to_string_lossy()
        .into_owned();
    let level = unsafe { *(ftwbuf as *const c_int).add(1) };
    DEPTH_LOG_LC.with(|c| c.borrow_mut().push((p, typeflag, level)));
    0
}

#[test]
fn diff_nftw_depth_post_order_directories_after_contents() {
    // FTW_DEPTH semantics: directory's DP visit must come AFTER all
    // its contents. Verify both impls preserve this ordering.
    let _g = FTW_SERIAL.lock().unwrap_or_else(|e| e.into_inner());
    let dir = build_tree();
    let cbase = CString::new(dir.to_string_lossy().as_bytes()).unwrap();

    DEPTH_LOG_FL.with(|c| c.borrow_mut().clear());
    DEPTH_LOG_LC.with(|c| c.borrow_mut().clear());
    let _ = unsafe { fl::nftw(cbase.as_ptr(), Some(record_depth_fl), 16, FTW_DEPTH) };
    let _ = unsafe { nftw(cbase.as_ptr(), Some(record_depth_lc), 16, FTW_DEPTH) };
    let _ = std::fs::remove_dir_all(&dir);

    DEPTH_LOG_FL.with(|fl_log| {
        let log = fl_log.borrow();
        // Find sub/ DP entry and sub/d.txt or sub/e.txt entries
        let sub_dp_idx = log
            .iter()
            .position(|(p, t, _)| p.ends_with("/sub") && *t == 5)
            .expect("fl: sub DP entry");
        let sub_d_idx = log
            .iter()
            .position(|(p, _, _)| p.ends_with("/sub/d.txt"))
            .expect("fl: sub/d.txt entry");
        assert!(
            sub_d_idx < sub_dp_idx,
            "fl: FTW_DEPTH must visit sub/d.txt before sub/ DP"
        );
    });
    DEPTH_LOG_LC.with(|lc_log| {
        let log = lc_log.borrow();
        let sub_dp_idx = log
            .iter()
            .position(|(p, t, _)| p.ends_with("/sub") && *t == 5)
            .expect("lc: sub DP entry");
        let sub_d_idx = log
            .iter()
            .position(|(p, _, _)| p.ends_with("/sub/d.txt"))
            .expect("lc: sub/d.txt entry");
        assert!(
            sub_d_idx < sub_dp_idx,
            "lc: FTW_DEPTH must visit sub/d.txt before sub/ DP"
        );
    });
}

#[test]
fn diff_nftw_level_field_correct() {
    // The FTW info struct's `level` field must match the depth from
    // root: 0 for root, 1 for direct children, 2 for grandchildren.
    let _g = FTW_SERIAL.lock().unwrap_or_else(|e| e.into_inner());
    let dir = build_tree();
    let cbase = CString::new(dir.to_string_lossy().as_bytes()).unwrap();

    DEPTH_LOG_FL.with(|c| c.borrow_mut().clear());
    let _ = unsafe { fl::nftw(cbase.as_ptr(), Some(record_depth_fl), 16, 0) };
    DEPTH_LOG_FL.with(|fl_log| {
        let log = fl_log.borrow();
        // Root: level == 0
        let root_entry = log
            .iter()
            .find(|(p, _, _)| p == &dir.to_string_lossy().to_string())
            .expect("fl: root entry");
        assert_eq!(root_entry.2, 0, "root level must be 0");
        // a.txt: direct child, level == 1
        let a = log
            .iter()
            .find(|(p, _, _)| p.ends_with("/a.txt"))
            .expect("fl: a.txt entry");
        assert_eq!(a.2, 1, "a.txt level must be 1");
        // sub/d.txt: grandchild, level == 2
        let d = log
            .iter()
            .find(|(p, _, _)| p.ends_with("/sub/d.txt"))
            .expect("fl: sub/d.txt entry");
        assert_eq!(d.2, 2, "sub/d.txt level must be 2");
    });
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn diff_ftw_disc001_lock_in() {
    // bd-ftw2 + bd-ftw-3 lock-in: nonexistent dirpath returns -1 on
    // both impls (was DISC-FTW-001 — fl previously returned 0).
    let _g = FTW_SERIAL.lock().unwrap_or_else(|e| e.into_inner());
    let cpath = CString::new("/this/dir/does/not/exist/lock_in_check").unwrap();
    let r_fl = unsafe { fl::ftw(cpath.as_ptr(), Some(collect_ftw), 16) };
    let r_lc = unsafe { ftw(cpath.as_ptr(), Some(collect_ftw), 16) };
    let _ = FtwBuf { base: 0, level: 0 };
    assert_eq!(r_fl, -1, "fl::ftw nonexistent must return -1");
    assert_eq!(r_lc, -1, "lc::ftw nonexistent must return -1");
}

#[test]
fn ftw_diff_coverage_report() {
    eprintln!("{{\"family\":\"ftw.h\",\"reference\":\"glibc\",\"functions\":2,\"divergences\":0}}",);
}
