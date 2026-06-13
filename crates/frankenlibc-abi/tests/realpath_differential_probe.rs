//! Differential probe: FrankenLibC `realpath` vs host glibc `realpath`, over a
//! controlled temp directory tree with real dirs/files, symlink chains, a
//! dangling symlink, and a symlink loop. fl's realpath is a bespoke
//! implementation (open(O_PATH) + readlink /proc/self/fd/N), so this checks both
//! the resolved string AND the errno on the error/edge cases (dangling -> ENOENT,
//! loop -> ELOOP, trailing slash on a file -> ENOTDIR, `..`/`.`/`//` normalisation,
//! nonexistent components) where divergences are most likely. fl mirrors errno to
//! the host slot in interpose mode, so the host __errno_location reflects both.
#![allow(unsafe_code)]

use std::ffi::CString;
use std::fs;
use std::os::unix::fs::symlink;
use std::path::PathBuf;

use frankenlibc_abi::stdlib_abi as fl;

unsafe extern "C" {
    fn realpath(path: *const libc::c_char, resolved: *mut libc::c_char) -> *mut libc::c_char;
}

fn errno() -> i32 {
    unsafe { *libc::__errno_location() }
}
fn clear_errno() {
    unsafe { *libc::__errno_location() = 0 };
}

#[derive(Debug, PartialEq, Eq, Clone)]
struct Out {
    ok: bool,
    resolved: String, // only meaningful when ok
    err: i32,         // only meaningful when !ok
}

fn run_host(path: &CString) -> Out {
    clear_errno();
    let mut buf = vec![0u8; libc::PATH_MAX as usize + 16];
    // SAFETY: buf is PATH_MAX-sized; path is a valid C string.
    let r = unsafe { realpath(path.as_ptr(), buf.as_mut_ptr() as *mut libc::c_char) };
    finish(r.is_null(), &buf)
}
fn run_fl(path: &CString) -> Out {
    clear_errno();
    let mut buf = vec![0u8; libc::PATH_MAX as usize + 16];
    // SAFETY: as above; fl::realpath has the C ABI.
    let r = unsafe { fl::realpath(path.as_ptr(), buf.as_mut_ptr() as *mut std::ffi::c_char) };
    finish(r.is_null(), &buf)
}

/// The pure-userspace fallback path (used when /proc is unavailable), exercised
/// directly so it is verified against glibc even though /proc IS mounted here.
fn run_fl_fallback(path: &str) -> Out {
    match fl::realpath_resolve_userspace(path.as_bytes()) {
        Ok(bytes) => Out {
            ok: true,
            resolved: String::from_utf8_lossy(&bytes).into_owned(),
            err: 0,
        },
        Err(e) => Out {
            ok: false,
            resolved: String::new(),
            err: e,
        },
    }
}
fn finish(is_null: bool, buf: &[u8]) -> Out {
    if is_null {
        Out {
            ok: false,
            resolved: String::new(),
            err: errno(),
        }
    } else {
        let n = buf.iter().position(|&b| b == 0).unwrap_or(buf.len());
        Out {
            ok: true,
            resolved: String::from_utf8_lossy(&buf[..n]).into_owned(),
            err: 0,
        }
    }
}

#[test]
fn realpath_matches_host_glibc() {
    // Unique temp tree (avoid std::env::temp_dir symlink ambiguity by resolving
    // the base with glibc itself, so all expectations share the same prefix).
    let base = std::env::temp_dir().join(format!("fl_realpath_probe_{}", std::process::id()));
    let _ = fs::remove_dir_all(&base);
    fs::create_dir_all(base.join("d/sub")).unwrap();
    fs::write(base.join("d/f"), b"x").unwrap();
    let _ = symlink("d", base.join("lnk_dir")); // -> d
    let _ = symlink("d/f", base.join("lnk_file")); // -> d/f
    let _ = symlink(base.join("d/f"), base.join("lnk_abs")); // absolute target
    let _ = symlink("nonexistent_target", base.join("dangle"));
    let _ = symlink("loop", base.join("loop")); // self-loop

    let b = base.to_string_lossy().into_owned();
    let cases: Vec<String> = vec![
        b.clone(),
        format!("{b}/d"),
        format!("{b}/d/"),
        format!("{b}/d/f"),
        format!("{b}/d/f/"),       // trailing slash on a file -> ENOTDIR
        format!("{b}/d//f"),       // double slash
        format!("{b}/d/./f"),      // .
        format!("{b}/d/../d/f"),   // ..
        format!("{b}/d/sub/../f"), // .. through subdir
        format!("{b}/lnk_dir"),
        format!("{b}/lnk_dir/f"), // through symlinked dir
        format!("{b}/lnk_file"),
        format!("{b}/lnk_abs"),
        format!("{b}/dangle"), // -> ENOENT
        format!("{b}/loop"),   // -> ELOOP
        format!("{b}/nope"),   // nonexistent -> ENOENT
        format!("{b}/d/f/x"),  // component under a file -> ENOTDIR
        format!("{b}/../{}/d/f", base.file_name().unwrap().to_string_lossy()),
        ".".to_string(),
        "/".to_string(),
        "//".to_string(),
        "/usr/../usr".to_string(),
        String::new(), // empty -> ENOENT
    ];

    let mut divergences: Vec<(String, Out, Out)> = Vec::new();
    let mut fb_divergences: Vec<(String, Out, Out)> = Vec::new();
    for case in &cases {
        let Ok(c) = CString::new(case.as_str()) else {
            continue;
        };
        let h = run_host(&c);
        let f = run_fl(&c);
        if h != f {
            divergences.push((case.clone(), h.clone(), f));
        }
        // Verify the pure-userspace fallback (bd-2g7oyh.188) against glibc too.
        let fb = run_fl_fallback(case);
        if h != fb {
            fb_divergences.push((case.clone(), h, fb));
        }
    }

    let _ = fs::remove_dir_all(&base);

    assert!(
        divergences.is_empty(),
        "realpath (primary) diverged from host glibc on {}/{} cases:\n{:#?}",
        divergences.len(),
        cases.len(),
        divergences
    );
    assert!(
        fb_divergences.is_empty(),
        "realpath (userspace fallback) diverged from host glibc on {}/{} cases:\n{:#?}",
        fb_divergences.len(),
        cases.len(),
        fb_divergences
    );
    eprintln!(
        "realpath: {} cases, 0 divergences vs host glibc (primary + userspace fallback)",
        cases.len()
    );
}

// silence unused import on platforms where PathBuf isn't otherwise referenced
const _: Option<PathBuf> = None;
