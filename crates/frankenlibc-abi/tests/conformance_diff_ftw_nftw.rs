#![cfg(target_os = "linux")]

//! Differential conformance harness for `<ftw.h>` file tree walks:
//!   - ftw  (legacy file tree walk)
//!   - nftw (new file tree walk with flags)
//!   - ftw64 / nftw64 (LFS aliases on x86_64)
//!
//! Tests build a controlled tempdir tree, then walk it with each impl
//! and compare the visited path set + reported file types.
//!
//! Bead: CONFORMANCE: libc ftw.h diff matrix.

use std::ffi::{CStr, CString, c_char, c_int, c_void};
use std::sync::Mutex;
use std::sync::atomic::{AtomicBool, AtomicI32, AtomicUsize, Ordering};

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
    fn ftw64(
        dirpath: *const c_char,
        cb: Option<unsafe extern "C" fn(*const c_char, *const libc::stat, c_int) -> c_int>,
        nopenfd: c_int,
    ) -> c_int;
    fn nftw64(
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

fn run_ftw64(use_fl: bool, base: &std::path::Path) -> Vec<(String, c_int)> {
    {
        COLLECTOR.lock().unwrap().clear();
    }
    COUNT.store(0, Ordering::Relaxed);
    let cbase = CString::new(base.to_string_lossy().as_bytes()).unwrap();
    let r = if use_fl {
        unsafe { fl::ftw64(cbase.as_ptr(), Some(collect_ftw), 16) }
    } else {
        unsafe { ftw64(cbase.as_ptr(), Some(collect_ftw), 16) }
    };
    assert_eq!(r, 0, "ftw64 return: use_fl={use_fl}");
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

fn run_nftw64(use_fl: bool, base: &std::path::Path, flags: c_int) -> Vec<(String, c_int)> {
    {
        COLLECTOR.lock().unwrap().clear();
    }
    COUNT.store(0, Ordering::Relaxed);
    let cbase = CString::new(base.to_string_lossy().as_bytes()).unwrap();
    let r = if use_fl {
        let callback: unsafe extern "C" fn(
            *const c_char,
            *const libc::stat,
            c_int,
            *mut c_void,
        ) -> c_int = collect_nftw;
        unsafe { fl::nftw64(cbase.as_ptr(), callback as *const c_void, 16, flags) }
    } else {
        unsafe { nftw64(cbase.as_ptr(), Some(collect_nftw), 16, flags) }
    };
    assert_eq!(r, 0, "nftw64 return: use_fl={use_fl}");
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

#[test]
fn diff_ftw64_visits_same_set() {
    let _g = FTW_SERIAL.lock().unwrap_or_else(|e| e.into_inner());
    let dir = build_tree();
    let v_fl = run_ftw64(true, &dir);
    let v_lc = run_ftw64(false, &dir);
    let _ = std::fs::remove_dir_all(&dir);
    assert_eq!(
        v_fl, v_lc,
        "ftw64 visited set divergence:\n  fl: {v_fl:?}\n  lc: {v_lc:?}"
    );
}

#[test]
fn diff_nftw64_phys_visits_same_set() {
    let _g = FTW_SERIAL.lock().unwrap_or_else(|e| e.into_inner());
    let dir = build_tree();
    let v_fl = run_nftw64(true, &dir, FTW_PHYS);
    let v_lc = run_nftw64(false, &dir, FTW_PHYS);
    let _ = std::fs::remove_dir_all(&dir);
    assert_eq!(
        v_fl, v_lc,
        "nftw64 FTW_PHYS visited set divergence:\n  fl: {v_fl:?}\n  lc: {v_lc:?}"
    );
}

#[test]
fn diff_nftw64_depth_visits_same_set() {
    let _g = FTW_SERIAL.lock().unwrap_or_else(|e| e.into_inner());
    let dir = build_tree();
    let v_fl = run_nftw64(true, &dir, FTW_DEPTH);
    let v_lc = run_nftw64(false, &dir, FTW_DEPTH);
    let _ = std::fs::remove_dir_all(&dir);
    assert_eq!(
        v_fl, v_lc,
        "nftw64 FTW_DEPTH visited set divergence:\n  fl: {v_fl:?}\n  lc: {v_lc:?}"
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

#[test]
fn diff_lfs64_nonexistent_dir_errors_match() {
    let _g = FTW_SERIAL.lock().unwrap_or_else(|e| e.into_inner());
    let cpath = CString::new("/this/dir/does/not/exist/lfs64").unwrap();
    let r_ftw_fl = unsafe { fl::ftw64(cpath.as_ptr(), Some(collect_ftw), 16) };
    let r_ftw_lc = unsafe { ftw64(cpath.as_ptr(), Some(collect_ftw), 16) };
    assert_eq!(r_ftw_fl, -1, "fl::ftw64 nonexistent must return -1");
    assert_eq!(r_ftw_lc, -1, "host ftw64 nonexistent must return -1");

    let callback: unsafe extern "C" fn(
        *const c_char,
        *const libc::stat,
        c_int,
        *mut c_void,
    ) -> c_int = collect_nftw;
    let r_nftw_fl = unsafe { fl::nftw64(cpath.as_ptr(), callback as *const c_void, 16, 0) };
    let r_nftw_lc = unsafe { nftw64(cpath.as_ptr(), Some(collect_nftw), 16, 0) };
    assert_eq!(r_nftw_fl, -1, "fl::nftw64 nonexistent must return -1");
    assert_eq!(r_nftw_lc, -1, "host nftw64 nonexistent must return -1");
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

// ---------------------------------------------------------------------------
// FTW_ACTIONRETVAL (GNU extension) — bd-nwrdyu.
//
// With FTW_ACTIONRETVAL set, nftw stops interpreting a non-zero callback
// return as "abort the walk and return this value" and instead reads it as
// one of four actions. The whole point of these tests is that the action
// semantics are subtle enough that they cannot be asserted from the man page
// alone, so every scenario below runs the SAME callback against fl and
// against the host glibc on the SAME tree and compares the full ordered
// visit sequence plus the return value.
//
// Scenarios never key off a specific filename, because readdir order is not
// specified: they key off the FTW level, the type flag, or "the first entry
// at level 1, whichever one that turns out to be". That keeps the structural
// assertions valid on any filesystem.
// ---------------------------------------------------------------------------

const FTW_ACTIONRETVAL: c_int = 16;

const FTW_CONTINUE: c_int = 0;
const FTW_STOP: c_int = 1;
const FTW_SKIP_SUBTREE: c_int = 2;
const FTW_SKIP_SIBLINGS: c_int = 3;

/// Fire the scenario's return value on the first visit whose level is 1,
/// return FTW_CONTINUE everywhere else.
const KIND_FIRST_LEVEL1: i32 = 0;
/// Fire on every pre-order directory visit below the root.
const KIND_NONROOT_DIR: i32 = 1;
/// Fire on every regular-file visit.
const KIND_FILE: i32 = 2;
/// Fire on the root visit only.
const KIND_ROOT: i32 = 3;
/// Fire on every visit.
const KIND_ALWAYS: i32 = 4;

/// One recorded callback invocation: path relative to the walk root (the
/// root itself records as "/"), the FTW_* type flag, and FTW.level.
type Visit = (String, c_int, c_int);

static AR_KIND: AtomicI32 = AtomicI32::new(KIND_ALWAYS);
static AR_RET: AtomicI32 = AtomicI32::new(0);
static AR_FIRED: AtomicBool = AtomicBool::new(false);
static AR_LOG: Mutex<Vec<Visit>> = Mutex::new(Vec::new());
static AR_BASE: Mutex<String> = Mutex::new(String::new());

unsafe extern "C" fn action_cb(
    path: *const c_char,
    _st: *const libc::stat,
    typeflag: c_int,
    ftwbuf: *mut c_void,
) -> c_int {
    let absolute = unsafe { CStr::from_ptr(path) }
        .to_string_lossy()
        .into_owned();
    // FTW is { int base; int level; } — level is the second int.
    let level = unsafe { *(ftwbuf as *const c_int).add(1) };

    let relative = {
        let base = AR_BASE.lock().unwrap_or_else(|e| e.into_inner());
        match absolute.strip_prefix(base.as_str()) {
            Some("") => "/".to_string(),
            Some(rest) => rest.to_string(),
            None => absolute.clone(),
        }
    };
    AR_LOG
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .push((relative, typeflag, level));

    let ret = AR_RET.load(Ordering::Relaxed);
    let fires = match AR_KIND.load(Ordering::Relaxed) {
        KIND_FIRST_LEVEL1 => level == 1 && !AR_FIRED.swap(true, Ordering::Relaxed),
        KIND_NONROOT_DIR => typeflag == FTW_D && level > 0,
        KIND_FILE => typeflag == FTW_F,
        KIND_ROOT => level == 0,
        _ => true,
    };
    if fires { ret } else { FTW_CONTINUE }
}

/// A tree with two sibling subdirectories, so "skip this subtree" and "skip
/// my remaining siblings" have visibly different consequences.
fn build_action_tree() -> std::path::PathBuf {
    let dir = unique_tempdir();
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    std::fs::write(dir.join("f1.txt"), b"1").unwrap();
    std::fs::write(dir.join("f2.txt"), b"2").unwrap();
    std::fs::create_dir(dir.join("d1")).unwrap();
    std::fs::write(dir.join("d1/i1.txt"), b"i1").unwrap();
    std::fs::write(dir.join("d1/i2.txt"), b"i2").unwrap();
    std::fs::create_dir(dir.join("d2")).unwrap();
    std::fs::write(dir.join("d2/j1.txt"), b"j1").unwrap();
    dir
}

/// Total visits a complete walk of [`build_action_tree`] performs.
const ACTION_TREE_VISITS: usize = 8;

fn run_action_once(use_fl: bool, base: &std::path::Path, flags: c_int) -> (c_int, Vec<Visit>) {
    *AR_BASE.lock().unwrap_or_else(|e| e.into_inner()) = base.to_string_lossy().into_owned();
    AR_LOG.lock().unwrap_or_else(|e| e.into_inner()).clear();
    AR_FIRED.store(false, Ordering::Relaxed);

    let cbase = CString::new(base.to_string_lossy().as_bytes()).unwrap();
    let rc = if use_fl {
        unsafe { fl::nftw(cbase.as_ptr(), Some(action_cb), 16, flags) }
    } else {
        unsafe { nftw(cbase.as_ptr(), Some(action_cb), 16, flags) }
    };
    let log = AR_LOG.lock().unwrap_or_else(|e| e.into_inner()).clone();
    (rc, log)
}

/// Run one scenario against fl and glibc, assert they agree exactly, and hand
/// back the (shared) return code and ordered visit list for further checks.
fn diff_action(
    base: &std::path::Path,
    flags: c_int,
    kind: i32,
    ret: c_int,
    what: &str,
) -> (c_int, Vec<Visit>) {
    AR_KIND.store(kind, Ordering::Relaxed);
    AR_RET.store(ret, Ordering::Relaxed);

    let (rc_fl, log_fl) = run_action_once(true, base, flags);
    let (rc_lc, log_lc) = run_action_once(false, base, flags);

    assert_eq!(
        rc_fl, rc_lc,
        "{what}: nftw return divergence (fl={rc_fl} lc={rc_lc})"
    );
    assert_eq!(
        log_fl, log_lc,
        "{what}: visit-sequence divergence\n  fl: {log_fl:#?}\n  lc: {log_lc:#?}"
    );
    (rc_fl, log_fl)
}

#[test]
fn diff_nftw_actionretval_skip_subtree_prunes_directories() {
    let _g = FTW_SERIAL.lock().unwrap_or_else(|e| e.into_inner());
    let dir = build_action_tree();
    let (rc, log) = diff_action(
        &dir,
        FTW_ACTIONRETVAL,
        KIND_NONROOT_DIR,
        FTW_SKIP_SUBTREE,
        "skip_subtree on every non-root directory",
    );
    let _ = std::fs::remove_dir_all(&dir);

    assert_eq!(rc, 0, "skipping subtrees is not an error");
    // Both subdirectories are still announced, but nothing inside them is.
    assert_eq!(
        log.iter().filter(|(_, t, _)| *t == FTW_D).count(),
        3,
        "root + d1 + d2 still visited: {log:?}"
    );
    assert!(
        log.iter().all(|(_, _, level)| *level <= 1),
        "no level-2 entry may survive a pruned subtree: {log:?}"
    );
    assert_eq!(log.len(), 5, "root + 2 files + 2 pruned dirs: {log:?}");
}

#[test]
fn diff_nftw_actionretval_skip_subtree_on_file_is_a_no_op() {
    // glibc rewrites FTW_SKIP_SUBTREE to FTW_CONTINUE when the entry was not
    // a pre-order directory, so returning it from a file visit changes
    // nothing at all.
    let _g = FTW_SERIAL.lock().unwrap_or_else(|e| e.into_inner());
    let dir = build_action_tree();
    let (rc, log) = diff_action(
        &dir,
        FTW_ACTIONRETVAL,
        KIND_FILE,
        FTW_SKIP_SUBTREE,
        "skip_subtree returned from a file visit",
    );
    let _ = std::fs::remove_dir_all(&dir);

    assert_eq!(rc, 0);
    assert_eq!(
        log.len(),
        ACTION_TREE_VISITS,
        "the whole tree must still be walked: {log:?}"
    );
}

#[test]
fn diff_nftw_actionretval_skip_siblings_stops_the_current_directory() {
    let _g = FTW_SERIAL.lock().unwrap_or_else(|e| e.into_inner());
    let dir = build_action_tree();
    let (rc, log) = diff_action(
        &dir,
        FTW_ACTIONRETVAL,
        KIND_FIRST_LEVEL1,
        FTW_SKIP_SIBLINGS,
        "skip_siblings on the first level-1 entry",
    );
    let _ = std::fs::remove_dir_all(&dir);

    assert_eq!(rc, 0, "skipping siblings is not an error");
    assert_eq!(
        log.len(),
        2,
        "root plus exactly one level-1 entry, whichever readdir yielded first: {log:?}"
    );
    assert_eq!(log[0].2, 0, "first visit is the root: {log:?}");
    assert_eq!(log[1].2, 1, "second visit is a direct child: {log:?}");
}

#[test]
fn diff_nftw_actionretval_skip_siblings_from_a_directory_also_prunes_it() {
    // Returning FTW_SKIP_SIBLINGS from a pre-order FTW_D visit abandons that
    // directory's own contents as well as its remaining siblings.
    let _g = FTW_SERIAL.lock().unwrap_or_else(|e| e.into_inner());
    let dir = build_action_tree();
    let (rc, log) = diff_action(
        &dir,
        FTW_ACTIONRETVAL,
        KIND_NONROOT_DIR,
        FTW_SKIP_SIBLINGS,
        "skip_siblings on the first non-root directory",
    );
    let _ = std::fs::remove_dir_all(&dir);

    assert_eq!(rc, 0);
    let first_dir = log
        .iter()
        .position(|(_, t, level)| *t == FTW_D && *level == 1)
        .expect("a level-1 directory is visited");
    assert_eq!(
        first_dir,
        log.len() - 1,
        "the first level-1 directory must be the last visit of the walk: {log:?}"
    );
}

#[test]
fn diff_nftw_actionretval_stop_ends_the_walk_with_ftw_stop() {
    let _g = FTW_SERIAL.lock().unwrap_or_else(|e| e.into_inner());
    let dir = build_action_tree();
    let (rc, log) = diff_action(
        &dir,
        FTW_ACTIONRETVAL,
        KIND_FIRST_LEVEL1,
        FTW_STOP,
        "stop on the first level-1 entry",
    );
    let _ = std::fs::remove_dir_all(&dir);

    assert_eq!(rc, FTW_STOP, "nftw reports FTW_STOP verbatim");
    assert_eq!(log.len(), 2, "walk ends immediately: {log:?}");
}

#[test]
fn diff_nftw_actionretval_continue_walks_everything() {
    let _g = FTW_SERIAL.lock().unwrap_or_else(|e| e.into_inner());
    let dir = build_action_tree();
    let (rc, log) = diff_action(
        &dir,
        FTW_ACTIONRETVAL,
        KIND_ALWAYS,
        FTW_CONTINUE,
        "continue everywhere",
    );
    let _ = std::fs::remove_dir_all(&dir);

    assert_eq!(rc, 0);
    assert_eq!(log.len(), ACTION_TREE_VISITS, "{log:?}");
}

#[test]
fn diff_nftw_actionretval_unrecognised_returns_propagate() {
    // Anything that is not one of the four actions aborts the walk and is
    // handed back to the caller unchanged — including negative values, which
    // must not be confused with nftw's own -1 "could not start" result.
    let _g = FTW_SERIAL.lock().unwrap_or_else(|e| e.into_inner());
    let dir = build_action_tree();
    for ret in [-1, 7, 42] {
        let (rc, log) = diff_action(
            &dir,
            FTW_ACTIONRETVAL,
            KIND_FIRST_LEVEL1,
            ret,
            "unrecognised action return",
        );
        assert_eq!(rc, ret, "return {ret} must propagate verbatim");
        assert_eq!(log.len(), 2, "walk aborts at once for {ret}: {log:?}");
    }
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn diff_nftw_without_actionretval_treats_two_as_an_abort() {
    // The same callback return that means "prune" under FTW_ACTIONRETVAL is
    // an ordinary non-zero abort when the flag is absent.
    let _g = FTW_SERIAL.lock().unwrap_or_else(|e| e.into_inner());
    let dir = build_action_tree();
    let (rc, log) = diff_action(
        &dir,
        0,
        KIND_FIRST_LEVEL1,
        FTW_SKIP_SUBTREE,
        "return 2 without FTW_ACTIONRETVAL",
    );
    let _ = std::fs::remove_dir_all(&dir);

    assert_eq!(
        rc, FTW_SKIP_SUBTREE,
        "plain nftw returns the callback value"
    );
    assert_eq!(log.len(), 2, "plain nftw aborts on any non-zero: {log:?}");
}

#[test]
fn diff_nftw_actionretval_actions_on_the_root_end_the_walk_cleanly() {
    let _g = FTW_SERIAL.lock().unwrap_or_else(|e| e.into_inner());
    let dir = build_action_tree();
    for (action, label) in [
        (FTW_SKIP_SUBTREE, "skip_subtree on root"),
        (FTW_SKIP_SIBLINGS, "skip_siblings on root"),
    ] {
        let (rc, log) = diff_action(&dir, FTW_ACTIONRETVAL, KIND_ROOT, action, label);
        assert_eq!(rc, 0, "{label} is not an error");
        assert_eq!(log.len(), 1, "{label}: only the root is visited: {log:?}");
    }
    let (rc, log) = diff_action(&dir, FTW_ACTIONRETVAL, KIND_ROOT, FTW_STOP, "stop on root");
    assert_eq!(rc, FTW_STOP);
    assert_eq!(log.len(), 1, "{log:?}");
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn diff_nftw_actionretval_with_depth_first_ordering() {
    // Under FTW_DEPTH a directory is reported only after its contents, so
    // FTW_SKIP_SUBTREE can no longer prune anything, while FTW_SKIP_SIBLINGS
    // must still leave the parent's own post-order visit intact.
    let _g = FTW_SERIAL.lock().unwrap_or_else(|e| e.into_inner());
    let dir = build_action_tree();

    let (rc, log) = diff_action(
        &dir,
        FTW_ACTIONRETVAL | FTW_DEPTH,
        KIND_NONROOT_DIR,
        FTW_SKIP_SUBTREE,
        "FTW_DEPTH + skip_subtree",
    );
    assert_eq!(rc, 0);
    assert_eq!(
        log.len(),
        ACTION_TREE_VISITS,
        "post-order pruning is impossible, so nothing is skipped: {log:?}"
    );
    assert!(
        log.iter().all(|(_, t, _)| *t != FTW_D),
        "FTW_DEPTH reports directories as FTW_DP only: {log:?}"
    );

    let (rc, log) = diff_action(
        &dir,
        FTW_ACTIONRETVAL | FTW_DEPTH,
        KIND_FIRST_LEVEL1,
        FTW_SKIP_SIBLINGS,
        "FTW_DEPTH + skip_siblings",
    );
    assert_eq!(rc, 0);
    assert_eq!(
        log.last().map(|(_, t, level)| (*t, *level)),
        Some((FTW_DP, 0)),
        "the root's post-order visit still happens: {log:?}"
    );

    let (rc, log) = diff_action(
        &dir,
        FTW_ACTIONRETVAL | FTW_DEPTH,
        KIND_FIRST_LEVEL1,
        FTW_STOP,
        "FTW_DEPTH + stop",
    );
    assert_eq!(rc, FTW_STOP);
    assert!(
        !log.iter().any(|(_, t, level)| *t == FTW_DP && *level == 0),
        "FTW_STOP must suppress the root's post-order visit: {log:?}"
    );

    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn diff_nftw_actionretval_non_directory_root() {
    let _g = FTW_SERIAL.lock().unwrap_or_else(|e| e.into_inner());
    let dir = build_action_tree();
    let file = dir.join("f1.txt");
    for (action, expected_rc, label) in [
        (FTW_SKIP_SUBTREE, 0, "skip_subtree on a file root"),
        (FTW_SKIP_SIBLINGS, 0, "skip_siblings on a file root"),
        (FTW_STOP, FTW_STOP, "stop on a file root"),
        (FTW_CONTINUE, 0, "continue on a file root"),
    ] {
        let (rc, log) = diff_action(&file, FTW_ACTIONRETVAL, KIND_ALWAYS, action, label);
        assert_eq!(rc, expected_rc, "{label}");
        assert_eq!(log.len(), 1, "{label}: exactly one visit: {log:?}");
        assert_eq!(log[0].1, FTW_F, "{label}: reported as a regular file");
    }
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn diff_nftw_actionretval_empty_directory_root() {
    let _g = FTW_SERIAL.lock().unwrap_or_else(|e| e.into_inner());
    let dir = unique_tempdir();
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let (rc, log) = diff_action(
        &dir,
        FTW_ACTIONRETVAL,
        KIND_ALWAYS,
        FTW_SKIP_SUBTREE,
        "skip_subtree on an empty directory root",
    );
    let _ = std::fs::remove_dir_all(&dir);
    assert_eq!(rc, 0);
    assert_eq!(log.len(), 1, "{log:?}");
    assert_eq!(log[0].1, FTW_D, "{log:?}");
}

/// FrankenLibC's own errno slot. In interpose mode `set_abi_errno` mirrors
/// into the host slot too, but the fl-owned slot is the one fl callers read.
fn fl_errno() -> c_int {
    unsafe { *frankenlibc_abi::errno_abi::__errno_location() }
}

fn set_fl_errno(value: c_int) {
    unsafe { *frankenlibc_abi::errno_abi::__errno_location() = value };
}

fn set_host_errno(value: c_int) {
    unsafe { *libc::__errno_location() = value };
}

fn host_errno() -> c_int {
    unsafe { *libc::__errno_location() }
}

#[test]
fn diff_nftw_callback_returning_minus_one_leaves_errno_alone() {
    // -1 from the callback is a walk *result*, not a failure to start the
    // walk, so nftw must hand it back without reporting anything through
    // errno. Verified against host glibc, which carries a pre-seeded errno
    // through such a walk untouched.
    let _g = FTW_SERIAL.lock().unwrap_or_else(|e| e.into_inner());
    let dir = build_action_tree();
    const SEED: c_int = libc::EACCES;

    for flags in [0, FTW_ACTIONRETVAL] {
        AR_KIND.store(KIND_ALWAYS, Ordering::Relaxed);
        AR_RET.store(-1, Ordering::Relaxed);

        set_fl_errno(SEED);
        set_host_errno(SEED);
        let (rc_fl, log_fl) = run_action_once(true, &dir, flags);
        let errno_fl = fl_errno();

        set_host_errno(SEED);
        let (rc_lc, log_lc) = run_action_once(false, &dir, flags);
        let errno_lc = host_errno();

        assert_eq!(rc_fl, -1, "flags={flags}: fl must return the callback's -1");
        assert_eq!(rc_lc, -1, "flags={flags}: lc must return the callback's -1");
        assert_eq!(log_fl.len(), 1, "flags={flags}: walk aborts at the root");
        assert_eq!(log_lc.len(), 1, "flags={flags}: walk aborts at the root");
        assert_eq!(
            errno_lc, SEED,
            "flags={flags}: glibc must not touch errno (control arm)"
        );
        assert_eq!(
            errno_fl, errno_lc,
            "flags={flags}: fl clobbered errno ({errno_fl}) where glibc left {errno_lc}"
        );
    }
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn diff_nftw_unstartable_root_reports_the_real_errno() {
    // The other -1: the walk never starts. Here errno IS meaningful, and it is
    // whatever the failed stat set — not a fixed ENOENT. A path whose parent
    // component is a regular file must report ENOTDIR.
    let _g = FTW_SERIAL.lock().unwrap_or_else(|e| e.into_inner());
    let dir = build_action_tree();
    let missing = dir.join("no_such_entry");
    let through_a_file = dir.join("f1.txt/below");

    AR_KIND.store(KIND_ALWAYS, Ordering::Relaxed);
    AR_RET.store(FTW_CONTINUE, Ordering::Relaxed);

    for (root, label) in [
        (missing, "nonexistent root"),
        (through_a_file, "root below a regular file"),
    ] {
        set_fl_errno(0);
        set_host_errno(0);
        let (rc_fl, _) = run_action_once(true, &root, FTW_ACTIONRETVAL);
        let errno_fl = fl_errno();

        set_host_errno(0);
        let (rc_lc, _) = run_action_once(false, &root, FTW_ACTIONRETVAL);
        let errno_lc = host_errno();

        assert_eq!(rc_fl, -1, "{label}: fl");
        assert_eq!(rc_lc, -1, "{label}: lc");
        assert_ne!(errno_lc, 0, "{label}: glibc must report an errno");
        assert_eq!(
            errno_fl, errno_lc,
            "{label}: fl reported errno {errno_fl}, glibc reported {errno_lc}"
        );
    }
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn diff_nftw64_actionretval_matches_nftw() {
    // nftw64 is the LFS alias; the action semantics must come along with it.
    let _g = FTW_SERIAL.lock().unwrap_or_else(|e| e.into_inner());
    let dir = build_action_tree();
    AR_KIND.store(KIND_NONROOT_DIR, Ordering::Relaxed);
    AR_RET.store(FTW_SKIP_SUBTREE, Ordering::Relaxed);

    let cbase = CString::new(dir.to_string_lossy().as_bytes()).unwrap();
    *AR_BASE.lock().unwrap_or_else(|e| e.into_inner()) = dir.to_string_lossy().into_owned();

    AR_LOG.lock().unwrap_or_else(|e| e.into_inner()).clear();
    AR_FIRED.store(false, Ordering::Relaxed);
    let callback: unsafe extern "C" fn(
        *const c_char,
        *const libc::stat,
        c_int,
        *mut c_void,
    ) -> c_int = action_cb;
    let rc_fl = unsafe {
        fl::nftw64(
            cbase.as_ptr(),
            callback as *const c_void,
            16,
            FTW_ACTIONRETVAL,
        )
    };
    let log_fl = AR_LOG.lock().unwrap_or_else(|e| e.into_inner()).clone();

    AR_LOG.lock().unwrap_or_else(|e| e.into_inner()).clear();
    AR_FIRED.store(false, Ordering::Relaxed);
    let rc_lc = unsafe { nftw64(cbase.as_ptr(), Some(action_cb), 16, FTW_ACTIONRETVAL) };
    let log_lc = AR_LOG.lock().unwrap_or_else(|e| e.into_inner()).clone();

    let _ = std::fs::remove_dir_all(&dir);
    assert_eq!(rc_fl, rc_lc, "nftw64 return divergence");
    assert_eq!(
        log_fl, log_lc,
        "nftw64 visit-sequence divergence\n  fl: {log_fl:#?}\n  lc: {log_lc:#?}"
    );
    assert!(
        log_fl.iter().all(|(_, _, level)| *level <= 1),
        "nftw64 must prune too: {log_fl:?}"
    );
}

// ---------------------------------------------------------------------------
// Logical-walk revisit suppression (bd-78f8do).
//
// A logical walk follows symlinks, so one directory can be reached by several
// paths — and `ln -s .. loop` makes that an infinite regress. These build real
// symlinks on disk and compare the full ordered visit sequence against glibc.
// ---------------------------------------------------------------------------

/// `root/d/{file,loop}` where `loop` points back at `root`.
fn build_cyclic_tree() -> std::path::PathBuf {
    let dir = unique_tempdir();
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(dir.join("d")).unwrap();
    std::fs::write(dir.join("d/file"), b"x").unwrap();
    std::os::unix::fs::symlink(&dir, dir.join("d/loop")).unwrap();
    dir
}

/// `root/{a/link1,b/link2,hidden/leaf}` with both links pointing at `hidden`.
fn build_shared_target_tree() -> std::path::PathBuf {
    let dir = unique_tempdir();
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(dir.join("a")).unwrap();
    std::fs::create_dir_all(dir.join("b")).unwrap();
    std::fs::create_dir_all(dir.join("hidden")).unwrap();
    std::fs::write(dir.join("hidden/leaf"), b"x").unwrap();
    std::os::unix::fs::symlink(dir.join("hidden"), dir.join("a/link1")).unwrap();
    std::os::unix::fs::symlink(dir.join("hidden"), dir.join("b/link2")).unwrap();
    dir
}

#[test]
fn diff_nftw_logical_walk_terminates_on_a_symlink_cycle() {
    // Before the fix this recursed until the stack was exhausted, taking the
    // whole test process with it. glibc reports the cycle entry not at all.
    let _g = FTW_SERIAL.lock().unwrap_or_else(|e| e.into_inner());
    let dir = build_cyclic_tree();
    let (rc, log) = diff_action(
        &dir,
        FTW_ACTIONRETVAL,
        KIND_ALWAYS,
        FTW_CONTINUE,
        "logical walk over a symlink cycle",
    );
    let _ = std::fs::remove_dir_all(&dir);

    assert_eq!(rc, 0);
    let paths: Vec<&str> = log.iter().map(|(p, _, _)| p.as_str()).collect();
    assert_eq!(
        paths,
        vec!["/", "/d", "/d/file"],
        "the cycle entry must produce no callback: {log:?}"
    );
}

#[test]
fn diff_nftw_logical_walk_reports_a_shared_directory_once() {
    // The record is global to the walk, not the ancestor chain: whichever of
    // a/link1, b/link2 and hidden readdir reaches first claims the inode, and
    // the other two are suppressed entirely.
    let _g = FTW_SERIAL.lock().unwrap_or_else(|e| e.into_inner());
    let dir = build_shared_target_tree();
    let (rc, log) = diff_action(
        &dir,
        FTW_ACTIONRETVAL,
        KIND_ALWAYS,
        FTW_CONTINUE,
        "logical walk with three routes to one directory",
    );
    let _ = std::fs::remove_dir_all(&dir);

    assert_eq!(rc, 0);
    let leaf_visits = log.iter().filter(|(p, _, _)| p.ends_with("leaf")).count();
    assert_eq!(leaf_visits, 1, "the shared subtree is walked once: {log:?}");
    // Exactly one of the three routes into `hidden` is reported as FTW_D.
    let routes = ["/a/link1", "/b/link2", "/hidden"];
    let reported = log
        .iter()
        .filter(|(p, _, _)| routes.contains(&p.as_str()))
        .count();
    assert_eq!(reported, 1, "exactly one route is reported: {log:?}");
}

#[test]
fn diff_nftw_physical_walk_keeps_every_route() {
    // FTW_PHYS never follows a symlink, so it cannot revisit anything and must
    // still report both links AND the real directory.
    let _g = FTW_SERIAL.lock().unwrap_or_else(|e| e.into_inner());
    let dir = build_shared_target_tree();
    let (rc, log) = diff_action(
        &dir,
        FTW_ACTIONRETVAL | FTW_PHYS,
        KIND_ALWAYS,
        FTW_CONTINUE,
        "physical walk with three routes to one directory",
    );
    let _ = std::fs::remove_dir_all(&dir);

    assert_eq!(rc, 0);
    for expected in ["/a/link1", "/b/link2", "/hidden", "/hidden/leaf"] {
        assert!(
            log.iter().any(|(p, _, _)| p == expected),
            "FTW_PHYS must still report {expected}: {log:?}"
        );
    }
    for (path, typeflag, _) in &log {
        if path == "/a/link1" || path == "/b/link2" {
            assert_eq!(*typeflag, FTW_SL, "{path} is a symlink under FTW_PHYS");
        }
    }
}

#[test]
fn diff_nftw_logical_cycle_suppression_holds_under_depth() {
    let _g = FTW_SERIAL.lock().unwrap_or_else(|e| e.into_inner());
    let dir = build_cyclic_tree();
    let (rc, log) = diff_action(
        &dir,
        FTW_ACTIONRETVAL | FTW_DEPTH,
        KIND_ALWAYS,
        FTW_CONTINUE,
        "FTW_DEPTH over a symlink cycle",
    );
    let _ = std::fs::remove_dir_all(&dir);

    assert_eq!(rc, 0);
    assert!(
        !log.iter().any(|(p, _, _)| p == "/d/loop"),
        "the cycle entry stays suppressed post-order: {log:?}"
    );
    assert_eq!(
        log.last().map(|(p, t, _)| (p.as_str(), *t)),
        Some(("/", FTW_DP)),
        "the walk still finishes with the root's post-order visit: {log:?}"
    );
}

#[test]
fn ftw_diff_coverage_report() {
    eprintln!("{{\"family\":\"ftw.h\",\"reference\":\"glibc\",\"functions\":4,\"divergences\":0}}",);
}
