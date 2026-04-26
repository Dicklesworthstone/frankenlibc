#![cfg(target_os = "linux")]

//! Integration tests for `<dirent.h>` ABI entrypoints.
//!
//! Tests cover: opendir/readdir/closedir, seekdir/telldir/rewinddir,
//! readdir_r, readdir64, alphasort, versionsort, scandir,
//! fdopendir, dirfd.

use std::collections::HashSet;
use std::ffi::{CStr, CString, c_void};
use std::sync::atomic::{AtomicU32, Ordering};
use std::thread;

use frankenlibc_abi::dirent_abi::*;

// ===========================================================================
// Helpers
// ===========================================================================

static TEST_DIR_COUNTER: AtomicU32 = AtomicU32::new(0);

/// Create a unique temporary directory with known files.
fn make_test_dir() -> (CString, String) {
    let id = TEST_DIR_COUNTER.fetch_add(1, Ordering::Relaxed);
    let pid = std::process::id();
    let base = format!("/tmp/franken_dirent_{}_{}", pid, id);
    let path = CString::new(base.as_str()).unwrap();
    unsafe {
        libc::mkdir(path.as_ptr(), 0o755);
    }
    for name in &["aaa.txt", "bbb.txt", "ccc.txt"] {
        let full = format!("{}/{}\0", base, name);
        let fd = unsafe { libc::open(full.as_ptr().cast(), libc::O_CREAT | libc::O_WRONLY, 0o644) };
        if fd >= 0 {
            unsafe { libc::close(fd) };
        }
    }
    (path, base)
}

fn cleanup_test_dir(base: &str) {
    for name in &["aaa.txt", "bbb.txt", "ccc.txt"] {
        let full = format!("{}/{}\0", base, name);
        unsafe { libc::unlink(full.as_ptr().cast()) };
    }
    let path = CString::new(base).unwrap();
    unsafe { libc::rmdir(path.as_ptr()) };
}

/// Read all entry names from a DIR stream.
unsafe fn collect_names(dirp: *mut DIR) -> Vec<String> {
    let mut names = Vec::new();
    loop {
        let ent = unsafe { readdir(dirp) };
        if ent.is_null() {
            break;
        }
        let name = unsafe { CStr::from_ptr((*ent).d_name.as_ptr()) };
        names.push(name.to_str().unwrap().to_string());
    }
    names
}

// ===========================================================================
// opendir / readdir / closedir
// ===========================================================================

#[test]
fn opendir_readdir_closedir_basic() {
    let (path, base) = make_test_dir();
    let dirp = unsafe { opendir(path.as_ptr()) };
    assert!(!dirp.is_null(), "opendir should succeed");

    let names = unsafe { collect_names(dirp) };
    assert!(names.contains(&".".to_string()));
    assert!(names.contains(&"..".to_string()));
    assert!(names.contains(&"aaa.txt".to_string()));
    assert!(names.contains(&"bbb.txt".to_string()));
    assert!(names.contains(&"ccc.txt".to_string()));

    let rc = unsafe { closedir(dirp) };
    assert_eq!(rc, 0);
    cleanup_test_dir(&base);
}

#[test]
fn opendir_null_returns_null() {
    let dirp = unsafe { opendir(std::ptr::null()) };
    assert!(dirp.is_null());
}

#[test]
fn opendir_nonexistent_returns_null() {
    let path = CString::new("/tmp/nonexistent_dir_12345").unwrap();
    let dirp = unsafe { opendir(path.as_ptr()) };
    assert!(dirp.is_null());
}

#[test]
fn readdir_returns_null_after_exhaustion() {
    let path = CString::new("/proc/self/fd").unwrap();
    let dirp = unsafe { opendir(path.as_ptr()) };
    assert!(!dirp.is_null());

    loop {
        let ent = unsafe { readdir(dirp) };
        if ent.is_null() {
            break;
        }
    }
    let ent = unsafe { readdir(dirp) };
    assert!(ent.is_null());

    unsafe { closedir(dirp) };
}

// ===========================================================================
// seekdir / telldir / rewinddir
// ===========================================================================

#[test]
fn telldir_and_seekdir_roundtrip() {
    let (path, base) = make_test_dir();
    let dirp = unsafe { opendir(path.as_ptr()) };
    assert!(!dirp.is_null());

    let ent1 = unsafe { readdir(dirp) };
    assert!(!ent1.is_null());
    let pos = unsafe { telldir(dirp) };

    let ent2 = unsafe { readdir(dirp) };
    assert!(!ent2.is_null());
    let name2 = unsafe { CStr::from_ptr((*ent2).d_name.as_ptr()) }
        .to_str()
        .unwrap()
        .to_string();

    unsafe { seekdir(dirp, pos) };

    let ent_after_seek = unsafe { readdir(dirp) };
    assert!(!ent_after_seek.is_null());
    let name_after = unsafe { CStr::from_ptr((*ent_after_seek).d_name.as_ptr()) }
        .to_str()
        .unwrap()
        .to_string();
    assert_eq!(name2, name_after, "seekdir should restore position");

    unsafe { closedir(dirp) };
    cleanup_test_dir(&base);
}

#[test]
fn rewinddir_restarts() {
    let (path, base) = make_test_dir();
    let dirp = unsafe { opendir(path.as_ptr()) };
    assert!(!dirp.is_null());

    let names1 = unsafe { collect_names(dirp) };
    assert!(!names1.is_empty());

    unsafe { rewinddir(dirp) };
    let names2 = unsafe { collect_names(dirp) };

    let set1: HashSet<_> = names1.into_iter().collect();
    let set2: HashSet<_> = names2.into_iter().collect();
    assert_eq!(set1, set2, "rewinddir should produce same entries");

    unsafe { closedir(dirp) };
    cleanup_test_dir(&base);
}

// ===========================================================================
// readdir_r (reentrant)
// ===========================================================================

#[test]
fn readdir_r_basic() {
    let path = CString::new("/proc/self/fd").unwrap();
    let dirp = unsafe { opendir(path.as_ptr()) };
    assert!(!dirp.is_null());

    let mut entry: libc::dirent = unsafe { std::mem::zeroed() };
    let mut result: *mut libc::dirent = std::ptr::null_mut();

    let rc = unsafe { readdir_r(dirp, &mut entry, &mut result) };
    assert_eq!(rc, 0, "readdir_r should succeed");
    assert!(!result.is_null(), "result should be set");

    let name = unsafe { CStr::from_ptr(entry.d_name.as_ptr()) };
    assert!(!name.to_str().unwrap().is_empty());

    unsafe { closedir(dirp) };
}

#[test]
fn readdir_r_exhaustion() {
    let (path, base) = make_test_dir();
    let dirp = unsafe { opendir(path.as_ptr()) };
    assert!(!dirp.is_null());

    let mut count = 0;
    loop {
        let mut entry: libc::dirent = unsafe { std::mem::zeroed() };
        let mut result: *mut libc::dirent = std::ptr::null_mut();
        let rc = unsafe { readdir_r(dirp, &mut entry, &mut result) };
        if rc != 0 || result.is_null() {
            break;
        }
        count += 1;
    }
    assert!(count >= 5, "should read at least 5 entries, got {count}");

    unsafe { closedir(dirp) };
    cleanup_test_dir(&base);
}

// ===========================================================================
// readdir64
// ===========================================================================

#[test]
fn readdir64_basic() {
    let path = CString::new("/proc/self/fd").unwrap();
    let dirp = unsafe { opendir(path.as_ptr()) };
    assert!(!dirp.is_null());

    let ent = unsafe { readdir64(dirp) };
    assert!(!ent.is_null(), "readdir64 should return an entry");

    unsafe { closedir(dirp) };
}

#[test]
fn readdir64_r_basic() {
    let path = CString::new("/proc/self/fd").unwrap();
    let dirp = unsafe { opendir(path.as_ptr()) };
    assert!(!dirp.is_null());

    let mut entry: libc::dirent64 = unsafe { std::mem::zeroed() };
    let mut result: *mut libc::dirent64 = std::ptr::null_mut();

    let rc =
        unsafe { frankenlibc_abi::unistd_abi::readdir64_r(dirp.cast(), &mut entry, &mut result) };
    assert_eq!(rc, 0, "readdir64_r should succeed");
    assert!(!result.is_null(), "result should be set");

    let name = unsafe { CStr::from_ptr(entry.d_name.as_ptr()) };
    assert!(!name.to_str().unwrap().is_empty());

    unsafe { closedir(dirp) };
}

// ===========================================================================
// alphasort / versionsort
// ===========================================================================

#[test]
fn alphasort_ordering() {
    let mut a: libc::dirent = unsafe { std::mem::zeroed() };
    let mut b: libc::dirent = unsafe { std::mem::zeroed() };

    let name_a = b"apple\0";
    let name_b = b"banana\0";
    a.d_name[..name_a.len()].copy_from_slice(unsafe {
        std::slice::from_raw_parts(name_a.as_ptr().cast(), name_a.len())
    });
    b.d_name[..name_b.len()].copy_from_slice(unsafe {
        std::slice::from_raw_parts(name_b.as_ptr().cast(), name_b.len())
    });

    let mut pa: *const c_void = (&a as *const libc::dirent).cast();
    let mut pb: *const c_void = (&b as *const libc::dirent).cast();

    let cmp = unsafe {
        alphasort(
            (&mut pa as *mut *const c_void).cast(),
            (&mut pb as *mut *const c_void).cast(),
        )
    };
    assert!(cmp < 0, "apple should sort before banana");

    let cmp2 = unsafe {
        alphasort(
            (&mut pb as *mut *const c_void).cast(),
            (&mut pa as *mut *const c_void).cast(),
        )
    };
    assert!(cmp2 > 0, "banana should sort after apple");

    let cmp3 = unsafe {
        alphasort(
            (&mut pa as *mut *const c_void).cast(),
            (&mut pa as *mut *const c_void).cast(),
        )
    };
    assert_eq!(cmp3, 0, "same name should compare equal");
}

#[test]
fn versionsort_ordering() {
    let mut a: libc::dirent = unsafe { std::mem::zeroed() };
    let mut b: libc::dirent = unsafe { std::mem::zeroed() };

    let name_a = b"file2\0";
    let name_b = b"file10\0";
    a.d_name[..name_a.len()].copy_from_slice(unsafe {
        std::slice::from_raw_parts(name_a.as_ptr().cast(), name_a.len())
    });
    b.d_name[..name_b.len()].copy_from_slice(unsafe {
        std::slice::from_raw_parts(name_b.as_ptr().cast(), name_b.len())
    });

    let mut pa: *const c_void = (&a as *const libc::dirent).cast();
    let mut pb: *const c_void = (&b as *const libc::dirent).cast();

    let cmp = unsafe {
        versionsort(
            (&mut pa as *mut *const c_void).cast(),
            (&mut pb as *mut *const c_void).cast(),
        )
    };
    assert!(cmp < 0, "file2 should sort before file10 in version sort");
}

// ===========================================================================
// scandir — allocates with our malloc_abi, so call count only (no free)
// ===========================================================================

#[test]
fn scandir_returns_entries() {
    let (path, base) = make_test_dir();
    let mut namelist: *mut *mut libc::dirent = std::ptr::null_mut();

    let n = unsafe { scandir(path.as_ptr(), &mut namelist, None, None) };
    assert!(n >= 5, "scandir should find at least 5 entries (got {n})");
    assert!(!namelist.is_null());

    // Note: entries allocated with our malloc_abi; just leak in test to avoid
    // allocator mismatch issues. The OS reclaims on process exit.
    cleanup_test_dir(&base);
}

#[test]
fn scandir_nonexistent_fails() {
    let path = CString::new("/tmp/no_such_scandir_dir_99999").unwrap();
    let mut namelist: *mut *mut libc::dirent = std::ptr::null_mut();
    let n = unsafe { scandir(path.as_ptr(), &mut namelist, None, None) };
    assert_eq!(n, -1, "scandir on nonexistent dir should return -1");
}

// ===========================================================================
// fdopendir / dirfd
// ===========================================================================

#[test]
fn fdopendir_and_dirfd() {
    let (path, base) = make_test_dir();
    let fd = unsafe { libc::open(path.as_ptr(), libc::O_RDONLY | libc::O_DIRECTORY) };
    assert!(fd >= 0, "open directory should succeed");

    let dirp = unsafe { fdopendir(fd) };
    assert!(!dirp.is_null(), "fdopendir should succeed");

    let got_fd = unsafe { dirfd(dirp.cast()) };
    assert!(got_fd >= 0, "dirfd should return valid fd");

    // Use our closedir (not libc::closedir) since fdopendir returns our handle
    unsafe { closedir(dirp.cast()) };
    cleanup_test_dir(&base);
}

#[test]
fn dirfd_from_opendir() {
    let path = CString::new("/proc/self/fd").unwrap();
    let dirp = unsafe { opendir(path.as_ptr()) };
    assert!(!dirp.is_null());

    let fd = unsafe { dirfd(dirp.cast()) };
    assert!(fd >= 0, "dirfd should return non-negative fd");

    unsafe { closedir(dirp) };
}

// ===========================================================================
// Null safety
// ===========================================================================

#[test]
fn closedir_null_returns_error() {
    let rc = unsafe { closedir(std::ptr::null_mut()) };
    assert_eq!(rc, -1);
}

#[test]
fn readdir_null_returns_null() {
    let ent = unsafe { readdir(std::ptr::null_mut()) };
    assert!(ent.is_null());
}

#[test]
fn readdir_closed_dir_sets_ebadf() {
    let path = CString::new("/proc/self/fd").unwrap();
    let dirp = unsafe { opendir(path.as_ptr()) };
    assert!(!dirp.is_null());
    assert_eq!(unsafe { closedir(dirp) }, 0);

    unsafe { frankenlibc_abi::errno_abi::set_abi_errno(0) };
    let ent = unsafe { readdir(dirp) };
    assert!(ent.is_null());
    assert_eq!(
        unsafe { *frankenlibc_abi::errno_abi::__errno_location() },
        libc::EBADF
    );
}

// ===========================================================================
// scandir with alphasort comparator
// ===========================================================================

#[test]
fn scandir_with_alphasort() {
    let (path, base) = make_test_dir();
    let mut namelist: *mut *mut libc::dirent = std::ptr::null_mut();

    let n = unsafe { scandir(path.as_ptr(), &mut namelist, None, Some(alphasort)) };
    assert!(
        n >= 5,
        "scandir with alphasort should find entries (got {n})"
    );
    assert!(!namelist.is_null());

    // Verify alphabetical order
    if n >= 2 {
        let mut prev_name = String::new();
        for i in 0..n {
            let ent = unsafe { *namelist.offset(i as isize) };
            let name = unsafe { CStr::from_ptr((*ent).d_name.as_ptr()) }
                .to_str()
                .unwrap()
                .to_string();
            if !prev_name.is_empty() {
                assert!(
                    prev_name <= name,
                    "entries should be sorted: {} <= {}",
                    prev_name,
                    name
                );
            }
            prev_name = name;
        }
    }

    cleanup_test_dir(&base);
}

// ===========================================================================
// scandir64
// ===========================================================================

#[test]
fn scandir64_basic() {
    let (path, base) = make_test_dir();
    let mut namelist: *mut *mut c_void = std::ptr::null_mut();

    // scandir64 takes c_void pointers on the ABI boundary
    let n = unsafe { scandir64(path.as_ptr(), &mut namelist, None, None) };
    assert!(n >= 5, "scandir64 should find entries (got {n})");
    assert!(!namelist.is_null());

    cleanup_test_dir(&base);
}

// ===========================================================================
// readdir64 exhaustion
// ===========================================================================

#[test]
fn readdir64_exhaustion() {
    let (path, base) = make_test_dir();
    let dirp = unsafe { opendir(path.as_ptr()) };
    assert!(!dirp.is_null());

    let mut count = 0;
    loop {
        let ent = unsafe { readdir64(dirp) };
        if ent.is_null() {
            break;
        }
        count += 1;
    }
    assert!(
        count >= 5,
        "readdir64 should read at least 5 entries (got {count})"
    );

    unsafe { closedir(dirp) };
    cleanup_test_dir(&base);
}

// ===========================================================================
// Multiple opens and closes
// ===========================================================================

#[test]
fn opendir_multiple_dirs() {
    let (path1, base1) = make_test_dir();
    let (path2, base2) = make_test_dir();

    let dirp1 = unsafe { opendir(path1.as_ptr()) };
    let dirp2 = unsafe { opendir(path2.as_ptr()) };
    assert!(!dirp1.is_null());
    assert!(!dirp2.is_null());

    // Both should be independently readable
    let ent1 = unsafe { readdir(dirp1) };
    assert!(!ent1.is_null());
    let ent2 = unsafe { readdir(dirp2) };
    assert!(!ent2.is_null());

    unsafe {
        closedir(dirp1);
        closedir(dirp2);
    }
    cleanup_test_dir(&base1);
    cleanup_test_dir(&base2);
}

#[test]
fn readdir_independent_dirs_can_run_concurrently() {
    let (path1, base1) = make_test_dir();
    let (path2, base2) = make_test_dir();

    let dirp1 = unsafe { opendir(path1.as_ptr()) };
    let dirp2 = unsafe { opendir(path2.as_ptr()) };
    assert!(!dirp1.is_null());
    assert!(!dirp2.is_null());

    let dirp1_addr = dirp1 as usize;
    let dirp2_addr = dirp2 as usize;
    let worker1 = thread::spawn(move || unsafe { collect_names(dirp1_addr as *mut DIR) });
    let worker2 = thread::spawn(move || unsafe { collect_names(dirp2_addr as *mut DIR) });

    let names1 = match worker1.join() {
        Ok(names) => names,
        Err(payload) => std::panic::resume_unwind(payload),
    };
    let names2 = match worker2.join() {
        Ok(names) => names,
        Err(payload) => std::panic::resume_unwind(payload),
    };

    assert!(names1.contains(&"aaa.txt".to_string()));
    assert!(names2.contains(&"aaa.txt".to_string()));

    unsafe {
        closedir(dirp1);
        closedir(dirp2);
    }
    cleanup_test_dir(&base1);
    cleanup_test_dir(&base2);
}

// ===========================================================================
// readdir_r null safety
// ===========================================================================

#[test]
fn readdir_r_null_dirp() {
    let mut entry: libc::dirent = unsafe { std::mem::zeroed() };
    let mut result: *mut libc::dirent = std::ptr::null_mut();
    let rc = unsafe { readdir_r(std::ptr::null_mut(), &mut entry, &mut result) };
    assert!(rc != 0 || result.is_null());
}

#[test]
fn readdir_r_closed_dir_reports_error() {
    let path = CString::new("/proc/self/fd").unwrap();
    let dirp = unsafe { opendir(path.as_ptr()) };
    assert!(!dirp.is_null());
    assert_eq!(unsafe { closedir(dirp) }, 0);

    let mut entry: libc::dirent = unsafe { std::mem::zeroed() };
    let mut result: *mut libc::dirent = std::ptr::null_mut();
    let rc = unsafe { readdir_r(dirp, &mut entry, &mut result) };
    assert_eq!(rc, libc::EBADF);
    assert!(result.is_null());
}

// ===========================================================================
// telldir returns different positions
// ===========================================================================

#[test]
fn telldir_advances() {
    let (path, base) = make_test_dir();
    let dirp = unsafe { opendir(path.as_ptr()) };
    assert!(!dirp.is_null());

    let pos1 = unsafe { telldir(dirp) };
    unsafe { readdir(dirp) };
    let pos2 = unsafe { telldir(dirp) };
    unsafe { readdir(dirp) };
    let pos3 = unsafe { telldir(dirp) };

    // Positions should generally advance (though not strictly monotonic on all fs)
    assert!(
        pos1 != pos3 || pos2 != pos3,
        "telldir should change as we read entries"
    );

    unsafe { closedir(dirp) };
    cleanup_test_dir(&base);
}

// ===========================================================================
// rewinddir after partial read
// ===========================================================================

#[test]
fn rewinddir_after_partial_read() {
    let (path, base) = make_test_dir();
    let dirp = unsafe { opendir(path.as_ptr()) };
    assert!(!dirp.is_null());

    // Read 2 entries
    unsafe { readdir(dirp) };
    unsafe { readdir(dirp) };

    // Rewind
    unsafe { rewinddir(dirp) };

    // Should be able to read all entries again
    let names = unsafe { collect_names(dirp) };
    assert!(names.contains(&"aaa.txt".to_string()));
    assert!(names.contains(&"bbb.txt".to_string()));
    assert!(names.contains(&"ccc.txt".to_string()));

    unsafe { closedir(dirp) };
    cleanup_test_dir(&base);
}

// ===========================================================================
// dirfd with fdopendir roundtrip
// ===========================================================================

#[test]
fn fdopendir_reads_entries() {
    let (path, base) = make_test_dir();
    let fd = unsafe { libc::open(path.as_ptr(), libc::O_RDONLY | libc::O_DIRECTORY) };
    assert!(fd >= 0);

    let dirp = unsafe { fdopendir(fd) };
    assert!(!dirp.is_null());

    let names = unsafe { collect_names(dirp.cast()) };
    assert!(names.contains(&"aaa.txt".to_string()));
    assert!(names.contains(&"bbb.txt".to_string()));
    assert!(names.contains(&"ccc.txt".to_string()));

    unsafe { closedir(dirp.cast()) };
    cleanup_test_dir(&base);
}

#[test]
fn fdopendir_bad_fd() {
    let dirp = unsafe { fdopendir(-1) };
    assert!(dirp.is_null(), "fdopendir(-1) should fail");
}

// ===========================================================================
// Entry d_type field
// ===========================================================================

#[test]
fn readdir_has_d_type() {
    let (path, base) = make_test_dir();
    let dirp = unsafe { opendir(path.as_ptr()) };
    assert!(!dirp.is_null());

    loop {
        let ent = unsafe { readdir(dirp) };
        if ent.is_null() {
            break;
        }
        let name = unsafe { CStr::from_ptr((*ent).d_name.as_ptr()) }
            .to_str()
            .unwrap();
        if name == "aaa.txt" {
            // Regular files should have DT_REG on most filesystems
            let d_type = unsafe { (*ent).d_type };
            assert!(
                d_type == libc::DT_REG || d_type == libc::DT_UNKNOWN,
                "aaa.txt should be DT_REG or DT_UNKNOWN, got {d_type}"
            );
        }
    }

    unsafe { closedir(dirp) };
    cleanup_test_dir(&base);
}

// ===========================================================================
// Empty directory
// ===========================================================================

#[test]
fn readdir_empty_dir() {
    let id = TEST_DIR_COUNTER.fetch_add(1, Ordering::Relaxed);
    let pid = std::process::id();
    let base = format!("/tmp/franken_dirent_empty_{}_{}", pid, id);
    let path = CString::new(base.as_str()).unwrap();
    unsafe { libc::mkdir(path.as_ptr(), 0o755) };

    let dirp = unsafe { opendir(path.as_ptr()) };
    assert!(!dirp.is_null());

    let names = unsafe { collect_names(dirp) };
    // Even empty dirs have "." and ".."
    assert!(names.contains(&".".to_string()));
    assert!(names.contains(&"..".to_string()));
    assert_eq!(names.len(), 2, "empty dir should only have . and ..");

    unsafe { closedir(dirp) };
    unsafe { libc::rmdir(path.as_ptr()) };
}

// ---------------------------------------------------------------------------
// __opendir / __closedir / __readdir / __readdir_r (glibc reserved aliases)
// ---------------------------------------------------------------------------

#[test]
fn under_opendir_closedir_round_trip() {
    let path = std::ffi::CString::new("/tmp").unwrap();
    let dirp = unsafe { __opendir(path.as_ptr()) };
    assert!(!dirp.is_null());
    let rc = unsafe { __closedir(dirp) };
    assert_eq!(rc, 0);
}

#[test]
fn under_readdir_yields_entries() {
    let path = std::ffi::CString::new("/tmp").unwrap();
    let dirp = unsafe { __opendir(path.as_ptr()) };
    assert!(!dirp.is_null());
    let mut count = 0usize;
    loop {
        let entry = unsafe { __readdir(dirp) };
        if entry.is_null() {
            break;
        }
        count += 1;
        if count > 10_000 {
            break;
        }
    }
    assert!(count >= 2, "/tmp should have at least . and ..");
    unsafe { __closedir(dirp) };
}

#[test]
fn under_readdir_r_yields_entries() {
    let path = std::ffi::CString::new("/tmp").unwrap();
    let dirp = unsafe { __opendir(path.as_ptr()) };
    assert!(!dirp.is_null());
    let mut entry: libc::dirent = unsafe { std::mem::zeroed() };
    let mut result: *mut libc::dirent = std::ptr::null_mut();
    let mut count = 0usize;
    loop {
        let rc = unsafe { __readdir_r(dirp, &mut entry, &mut result) };
        assert_eq!(rc, 0);
        if result.is_null() {
            break;
        }
        count += 1;
        if count > 10_000 {
            break;
        }
    }
    assert!(count >= 2);
    unsafe { __closedir(dirp) };
}
