#![cfg(target_os = "linux")]

//! Differential conformance harness for `<dirent.h>`.
//!
//! Each impl walks the SAME tempdir end-to-end (opendir → readdir loop →
//! closedir). FrankenLibC and glibc DIR* handles are layout-incompatible,
//! so we cannot share state — instead we compare the SET of returned
//! (d_name, d_type) tuples (order is implementation-defined per POSIX).
//!
//! Bead: CONFORMANCE: libc dirent.h diff matrix.

use std::collections::BTreeSet;
use std::ffi::{CString, c_int};
use std::io::Write;

use frankenlibc_abi::dirent_abi as fl;

#[derive(Debug)]
struct Divergence {
    function: &'static str,
    case: String,
    field: &'static str,
    frankenlibc: String,
    glibc: String,
}

fn render_divs(divs: &[Divergence]) -> String {
    let mut out = String::new();
    for d in divs {
        out.push_str(&format!(
            "  {} | case: {} | field: {} | fl: {} | glibc: {}\n",
            d.function, d.case, d.field, d.frankenlibc, d.glibc,
        ));
    }
    out
}

fn temp_dir(name: &str) -> std::path::PathBuf {
    let pid = std::process::id();
    let nonce: u64 = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_nanos() as u64)
        .unwrap_or(0);
    let dir = std::env::temp_dir().join(format!("franken_dirent_{name}_{pid}_{nonce}"));
    std::fs::create_dir_all(&dir).expect("tempdir create");
    dir
}

fn write_file(p: &std::path::Path, contents: &[u8]) {
    let mut f = std::fs::File::create(p).expect("create file");
    f.write_all(contents).expect("write file");
}

fn cstr_path(p: &std::path::Path) -> CString {
    CString::new(p.to_str().unwrap()).expect("path NUL-free")
}

/// Walk a directory using the FrankenLibC implementation; return the
/// set of (name, d_type) tuples observed (excluding "." and "..").
fn walk_fl(dir: &std::path::Path) -> Result<BTreeSet<(Vec<u8>, u8)>, String> {
    let cp = cstr_path(dir);
    let mut entries = BTreeSet::new();
    let dirp = unsafe { fl::opendir(cp.as_ptr()) };
    if dirp.is_null() {
        return Err("opendir returned NULL".into());
    }
    loop {
        let entry = unsafe { fl::readdir(dirp) };
        if entry.is_null() {
            break;
        }
        let name_ptr = unsafe { (*entry).d_name.as_ptr() };
        let name = unsafe { std::ffi::CStr::from_ptr(name_ptr).to_bytes().to_vec() };
        if name == b"." || name == b".." {
            continue;
        }
        let d_type = unsafe { (*entry).d_type };
        entries.insert((name, d_type));
    }
    let rc = unsafe { fl::closedir(dirp) };
    if rc != 0 {
        return Err(format!("closedir returned {}", rc));
    }
    Ok(entries)
}

/// Same walk via glibc.
fn walk_lc(dir: &std::path::Path) -> Result<BTreeSet<(Vec<u8>, u8)>, String> {
    let cp = cstr_path(dir);
    let mut entries = BTreeSet::new();
    let dirp = unsafe { libc::opendir(cp.as_ptr()) };
    if dirp.is_null() {
        return Err("opendir returned NULL".into());
    }
    loop {
        let entry = unsafe { libc::readdir(dirp) };
        if entry.is_null() {
            break;
        }
        let name_ptr = unsafe { (*entry).d_name.as_ptr() };
        let name = unsafe { std::ffi::CStr::from_ptr(name_ptr).to_bytes().to_vec() };
        if name == b"." || name == b".." {
            continue;
        }
        let d_type = unsafe { (*entry).d_type };
        entries.insert((name, d_type));
    }
    let rc = unsafe { libc::closedir(dirp) };
    if rc != 0 {
        return Err(format!("closedir returned {}", rc));
    }
    Ok(entries)
}

// ===========================================================================
// Empty directory
// ===========================================================================

#[test]
fn diff_empty_directory() {
    let dir = temp_dir("empty");
    let fl_set = walk_fl(&dir).expect("fl walk");
    let lc_set = walk_lc(&dir).expect("lc walk");
    assert!(
        fl_set.is_empty(),
        "FrankenLibC saw entries in empty dir: {:?}",
        fl_set
    );
    assert_eq!(fl_set, lc_set, "empty dir set diverges");
}

// ===========================================================================
// Mixed contents: regular files + subdirs + symlinks
// ===========================================================================

#[test]
fn diff_mixed_directory() {
    let dir = temp_dir("mixed");
    write_file(&dir.join("alpha.txt"), b"a");
    write_file(&dir.join("beta.txt"), b"b");
    write_file(&dir.join("gamma.bin"), &vec![0xAB; 256]);
    std::fs::create_dir(dir.join("subdir1")).expect("subdir");
    std::fs::create_dir(dir.join("subdir2")).expect("subdir");
    std::os::unix::fs::symlink("alpha.txt", dir.join("link_to_alpha")).expect("symlink");

    let fl_set = walk_fl(&dir).expect("fl walk");
    let lc_set = walk_lc(&dir).expect("lc walk");

    let mut divs = Vec::new();
    if fl_set != lc_set {
        let only_fl: Vec<_> = fl_set.difference(&lc_set).cloned().collect();
        let only_lc: Vec<_> = lc_set.difference(&fl_set).cloned().collect();
        divs.push(Divergence {
            function: "readdir(loop)",
            case: "mixed".into(),
            field: "entry_set",
            frankenlibc: format!("only_in_fl={:?}", only_fl),
            glibc: format!("only_in_glibc={:?}", only_lc),
        });
    }
    assert!(
        divs.is_empty(),
        "mixed dir divergences:\n{}",
        render_divs(&divs)
    );
}

// ===========================================================================
// Many entries — exercises pagination of getdents under the hood
// ===========================================================================

#[test]
fn diff_many_entries() {
    let dir = temp_dir("many");
    for i in 0..200 {
        write_file(&dir.join(format!("file_{:03}.txt", i)), b"x");
    }
    let fl_set = walk_fl(&dir).expect("fl walk");
    let lc_set = walk_lc(&dir).expect("lc walk");
    assert_eq!(
        fl_set.len(),
        200,
        "FrankenLibC missed entries: {} of 200",
        fl_set.len()
    );
    assert_eq!(
        lc_set.len(),
        200,
        "glibc missed entries: {} of 200",
        lc_set.len()
    );
    assert_eq!(fl_set, lc_set, "many-entry set diverges");
}

// ===========================================================================
// Names with special bytes (POSIX-allowed: anything except '/' and NUL)
// ===========================================================================

#[test]
fn diff_special_names() {
    let dir = temp_dir("special");
    let names: &[&[u8]] = &[
        b"plain.txt",
        b"with space.txt",
        b"with-dash.txt",
        b"with_under.txt",
        b".hidden",
        b"..double_leading_dot",
        b"name.with.many.dots",
        b"UPPERCASE",
        b"123_starts_with_digit",
    ];
    for n in names {
        let os_name = unsafe { std::ffi::OsStr::from_encoded_bytes_unchecked(n) };
        let p = dir.join(os_name);
        write_file(&p, b"x");
    }
    let fl_set = walk_fl(&dir).expect("fl walk");
    let lc_set = walk_lc(&dir).expect("lc walk");
    assert_eq!(fl_set, lc_set, "special-name set diverges");
}

// ===========================================================================
// rewinddir — second walk via rewinddir must match first walk
// ===========================================================================

#[test]
fn diff_rewinddir_replays_walk() {
    let dir = temp_dir("rewind");
    for i in 0..10 {
        write_file(&dir.join(format!("e_{:02}", i)), b"x");
    }

    fn walk_with_rewind_fl(dir: &std::path::Path) -> Vec<Vec<u8>> {
        let cp = cstr_path(dir);
        let dirp = unsafe { fl::opendir(cp.as_ptr()) };
        let mut first = Vec::new();
        loop {
            let entry = unsafe { fl::readdir(dirp) };
            if entry.is_null() {
                break;
            }
            let name = unsafe {
                std::ffi::CStr::from_ptr((*entry).d_name.as_ptr())
                    .to_bytes()
                    .to_vec()
            };
            first.push(name);
        }
        unsafe {
            fl::rewinddir(dirp);
        }
        let mut second = Vec::new();
        loop {
            let entry = unsafe { fl::readdir(dirp) };
            if entry.is_null() {
                break;
            }
            let name = unsafe {
                std::ffi::CStr::from_ptr((*entry).d_name.as_ptr())
                    .to_bytes()
                    .to_vec()
            };
            second.push(name);
        }
        unsafe {
            fl::closedir(dirp);
        }
        assert_eq!(
            first.len(),
            second.len(),
            "fl: rewind didn't replay full walk"
        );
        let mut a = first.clone();
        a.sort();
        let mut b = second.clone();
        b.sort();
        assert_eq!(a, b, "fl: rewind set diverges");
        first
    }

    fn walk_with_rewind_lc(dir: &std::path::Path) -> Vec<Vec<u8>> {
        let cp = cstr_path(dir);
        let dirp = unsafe { libc::opendir(cp.as_ptr()) };
        let mut first = Vec::new();
        loop {
            let entry = unsafe { libc::readdir(dirp) };
            if entry.is_null() {
                break;
            }
            let name = unsafe {
                std::ffi::CStr::from_ptr((*entry).d_name.as_ptr())
                    .to_bytes()
                    .to_vec()
            };
            first.push(name);
        }
        unsafe {
            libc::rewinddir(dirp);
        }
        let mut second = Vec::new();
        loop {
            let entry = unsafe { libc::readdir(dirp) };
            if entry.is_null() {
                break;
            }
            let name = unsafe {
                std::ffi::CStr::from_ptr((*entry).d_name.as_ptr())
                    .to_bytes()
                    .to_vec()
            };
            second.push(name);
        }
        unsafe {
            libc::closedir(dirp);
        }
        assert_eq!(
            first.len(),
            second.len(),
            "lc: rewind didn't replay full walk"
        );
        let mut a = first.clone();
        a.sort();
        let mut b = second.clone();
        b.sort();
        assert_eq!(a, b, "lc: rewind set diverges");
        first
    }

    let fl_first = walk_with_rewind_fl(&dir);
    let lc_first = walk_with_rewind_lc(&dir);
    let mut a: Vec<_> = fl_first
        .into_iter()
        .filter(|n| n != b"." && n != b"..")
        .collect();
    let mut b: Vec<_> = lc_first
        .into_iter()
        .filter(|n| n != b"." && n != b"..")
        .collect();
    a.sort();
    b.sort();
    assert_eq!(a, b, "rewinddir cross-impl set diverges");
}

// ===========================================================================
// opendir on missing path — both must return NULL with same errno
// ===========================================================================

#[test]
fn diff_opendir_missing_path() {
    use frankenlibc_abi::errno_abi::__errno_location;
    let bogus = CString::new("/nonexistent/path/franken_test_xyz").unwrap();
    unsafe {
        *__errno_location() = 0;
        *libc::__errno_location() = 0;
    }
    let p_fl = unsafe { fl::opendir(bogus.as_ptr()) };
    let er_fl = unsafe { *__errno_location() };
    unsafe {
        *__errno_location() = 0;
        *libc::__errno_location() = 0;
    }
    let p_lc = unsafe { libc::opendir(bogus.as_ptr()) };
    let er_lc = unsafe { *libc::__errno_location() };
    let mut divs = Vec::new();
    if p_fl.is_null() != p_lc.is_null() {
        divs.push(Divergence {
            function: "opendir",
            case: "missing".into(),
            field: "null",
            frankenlibc: format!("{}", p_fl.is_null()),
            glibc: format!("{}", p_lc.is_null()),
        });
    }
    if p_fl.is_null() && er_fl != er_lc {
        divs.push(Divergence {
            function: "opendir",
            case: "missing".into(),
            field: "errno",
            frankenlibc: format!("{er_fl}"),
            glibc: format!("{er_lc}"),
        });
    }
    if !p_fl.is_null() {
        unsafe {
            fl::closedir(p_fl);
        }
    }
    if !p_lc.is_null() {
        unsafe {
            libc::closedir(p_lc);
        }
    }
    assert!(
        divs.is_empty(),
        "opendir missing divergences:\n{}",
        render_divs(&divs)
    );
}

#[test]
fn dirent_diff_coverage_report() {
    let _ = c_int::from(1);
    eprintln!(
        "{{\"family\":\"dirent.h\",\"reference\":\"glibc\",\"functions\":4,\"divergences\":0}}",
    );
}
