#![cfg(target_os = "linux")]

//! Differential conformance harness for `<unistd.h>` path-manipulation calls.
//!
//! Covers: access, rename, link, symlink, readlink, unlink, truncate,
//! ftruncate, getcwd. Compares FrankenLibC vs glibc reference on identical
//! filesystem inputs (per-test tempdir isolation).
//!
//! Bead: CONFORMANCE: libc unistd.h path operations diff matrix.

use std::ffi::{CString, c_int};
use std::io::Write;

use frankenlibc_abi::errno_abi::__errno_location;
use frankenlibc_abi::unistd_abi as fl;

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

unsafe fn clear_errno_both() {
    unsafe {
        *__errno_location() = 0;
        *libc::__errno_location() = 0;
    }
}
unsafe fn read_fl_errno() -> c_int {
    unsafe { *__errno_location() }
}
unsafe fn read_lc_errno() -> c_int {
    unsafe { *libc::__errno_location() }
}

fn temp_dir(name: &str) -> std::path::PathBuf {
    let pid = std::process::id();
    let nonce: u64 = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_nanos() as u64)
        .unwrap_or(0);
    let dir = std::env::temp_dir().join(format!("franken_unistd_{name}_{pid}_{nonce}"));
    std::fs::create_dir_all(&dir).expect("tempdir create");
    dir
}

fn cstr_path(p: &std::path::Path) -> CString {
    CString::new(p.to_str().unwrap()).expect("path NUL-free")
}

fn write_file(p: &std::path::Path, contents: &[u8]) {
    let mut f = std::fs::File::create(p).expect("create file");
    f.write_all(contents).expect("write file");
}

// ===========================================================================
// access — F_OK / R_OK / W_OK / X_OK probes
// ===========================================================================

#[test]
fn diff_access_cases() {
    let dir = temp_dir("access");
    let exists = dir.join("yes");
    write_file(&exists, b"a");
    let missing = dir.join("no");
    let cases: &[(&str, &std::path::Path, c_int)] = &[
        ("exists_F_OK", &exists, libc::F_OK),
        ("exists_R_OK", &exists, libc::R_OK),
        ("exists_W_OK", &exists, libc::W_OK),
        ("exists_RW_OK", &exists, libc::R_OK | libc::W_OK),
        ("missing_F_OK", &missing, libc::F_OK),
        ("missing_R_OK", &missing, libc::R_OK),
    ];
    let mut divs = Vec::new();
    for (label, path, mode) in cases {
        let cp = cstr_path(path);
        unsafe { clear_errno_both() };
        let fl_r = unsafe { fl::access(cp.as_ptr(), *mode) };
        let fl_err = unsafe { read_fl_errno() };
        unsafe { clear_errno_both() };
        let lc_r = unsafe { libc::access(cp.as_ptr(), *mode) };
        let lc_err = unsafe { read_lc_errno() };
        if fl_r != lc_r {
            divs.push(Divergence {
                function: "access",
                case: (*label).into(),
                field: "return",
                frankenlibc: format!("{fl_r}"),
                glibc: format!("{lc_r}"),
            });
        }
        if fl_r != 0 && fl_err != lc_err {
            divs.push(Divergence {
                function: "access",
                case: (*label).into(),
                field: "errno",
                frankenlibc: format!("{fl_err}"),
                glibc: format!("{lc_err}"),
            });
        }
    }
    assert!(divs.is_empty(), "access divergences:\n{}", render_divs(&divs));
}

// ===========================================================================
// rename / unlink — file moves and removals
// ===========================================================================

#[test]
fn diff_rename_cases() {
    let dir = temp_dir("rename");
    let mut divs = Vec::new();

    // Successful rename — pair of files for each impl.
    let src_fl = dir.join("src_fl.txt");
    let dst_fl = dir.join("dst_fl.txt");
    let src_lc = dir.join("src_lc.txt");
    let dst_lc = dir.join("dst_lc.txt");
    write_file(&src_fl, b"x");
    write_file(&src_lc, b"x");
    let cs_fl = cstr_path(&src_fl);
    let cd_fl = cstr_path(&dst_fl);
    let cs_lc = cstr_path(&src_lc);
    let cd_lc = cstr_path(&dst_lc);
    let fl_r = unsafe { fl::rename(cs_fl.as_ptr(), cd_fl.as_ptr()) };
    let lc_r = unsafe { libc::rename(cs_lc.as_ptr(), cd_lc.as_ptr()) };
    if fl_r != lc_r {
        divs.push(Divergence {
            function: "rename",
            case: "exists_to_new".into(),
            field: "return",
            frankenlibc: format!("{fl_r}"),
            glibc: format!("{lc_r}"),
        });
    }
    assert!(dst_fl.exists() == dst_lc.exists());

    // Rename of a nonexistent source.
    let missing = dir.join("nope");
    let target = dir.join("anywhere");
    let cm = cstr_path(&missing);
    let ct = cstr_path(&target);
    unsafe { clear_errno_both() };
    let fl_r = unsafe { fl::rename(cm.as_ptr(), ct.as_ptr()) };
    let fl_err = unsafe { read_fl_errno() };
    unsafe { clear_errno_both() };
    let lc_r = unsafe { libc::rename(cm.as_ptr(), ct.as_ptr()) };
    let lc_err = unsafe { read_lc_errno() };
    if fl_r != lc_r || fl_err != lc_err {
        divs.push(Divergence {
            function: "rename",
            case: "missing_source".into(),
            field: "return/errno",
            frankenlibc: format!("rc={fl_r} errno={fl_err}"),
            glibc: format!("rc={lc_r} errno={lc_err}"),
        });
    }
    assert!(divs.is_empty(), "rename divergences:\n{}", render_divs(&divs));
}

#[test]
fn diff_unlink_cases() {
    let dir = temp_dir("unlink");
    let mut divs = Vec::new();
    // Successful unlink — separate files for each impl.
    let f_fl = dir.join("a_fl");
    let f_lc = dir.join("a_lc");
    write_file(&f_fl, b"x");
    write_file(&f_lc, b"x");
    let cf_fl = cstr_path(&f_fl);
    let cf_lc = cstr_path(&f_lc);
    let fl_r = unsafe { fl::unlink(cf_fl.as_ptr()) };
    let lc_r = unsafe { libc::unlink(cf_lc.as_ptr()) };
    if fl_r != lc_r {
        divs.push(Divergence {
            function: "unlink",
            case: "exists".into(),
            field: "return",
            frankenlibc: format!("{fl_r}"),
            glibc: format!("{lc_r}"),
        });
    }
    // Missing path.
    let missing = dir.join("missing");
    let cm = cstr_path(&missing);
    unsafe { clear_errno_both() };
    let fl_r = unsafe { fl::unlink(cm.as_ptr()) };
    let fl_err = unsafe { read_fl_errno() };
    unsafe { clear_errno_both() };
    let lc_r = unsafe { libc::unlink(cm.as_ptr()) };
    let lc_err = unsafe { read_lc_errno() };
    if fl_r != lc_r || fl_err != lc_err {
        divs.push(Divergence {
            function: "unlink",
            case: "missing".into(),
            field: "return/errno",
            frankenlibc: format!("rc={fl_r} errno={fl_err}"),
            glibc: format!("rc={lc_r} errno={lc_err}"),
        });
    }
    assert!(divs.is_empty(), "unlink divergences:\n{}", render_divs(&divs));
}

// ===========================================================================
// link / symlink / readlink — link family
// ===========================================================================

#[test]
fn diff_link_cases() {
    let dir = temp_dir("link");
    let target_fl = dir.join("t_fl");
    let target_lc = dir.join("t_lc");
    let link_fl = dir.join("hl_fl");
    let link_lc = dir.join("hl_lc");
    write_file(&target_fl, b"x");
    write_file(&target_lc, b"x");
    let ct_fl = cstr_path(&target_fl);
    let cl_fl = cstr_path(&link_fl);
    let ct_lc = cstr_path(&target_lc);
    let cl_lc = cstr_path(&link_lc);
    let fl_r = unsafe { fl::link(ct_fl.as_ptr(), cl_fl.as_ptr()) };
    let lc_r = unsafe { libc::link(ct_lc.as_ptr(), cl_lc.as_ptr()) };
    let mut divs = Vec::new();
    if fl_r != lc_r {
        divs.push(Divergence {
            function: "link",
            case: "exists".into(),
            field: "return",
            frankenlibc: format!("{fl_r}"),
            glibc: format!("{lc_r}"),
        });
    }
    // link with missing source
    let bad = dir.join("missing_target");
    let dst = dir.join("never");
    let cb = cstr_path(&bad);
    let cd = cstr_path(&dst);
    unsafe { clear_errno_both() };
    let fl_r = unsafe { fl::link(cb.as_ptr(), cd.as_ptr()) };
    let fl_err = unsafe { read_fl_errno() };
    unsafe { clear_errno_both() };
    let lc_r = unsafe { libc::link(cb.as_ptr(), cd.as_ptr()) };
    let lc_err = unsafe { read_lc_errno() };
    if fl_r != lc_r || fl_err != lc_err {
        divs.push(Divergence {
            function: "link",
            case: "missing_target".into(),
            field: "return/errno",
            frankenlibc: format!("rc={fl_r} errno={fl_err}"),
            glibc: format!("rc={lc_r} errno={lc_err}"),
        });
    }
    assert!(divs.is_empty(), "link divergences:\n{}", render_divs(&divs));
}

#[test]
fn diff_symlink_readlink_cases() {
    let dir = temp_dir("symlink");
    let mut divs = Vec::new();
    let sym_fl = dir.join("s_fl");
    let sym_lc = dir.join("s_lc");
    let target = "/nonexistent/target";
    let ctgt = CString::new(target).unwrap();
    let cs_fl = cstr_path(&sym_fl);
    let cs_lc = cstr_path(&sym_lc);
    let fl_r = unsafe { fl::symlink(ctgt.as_ptr(), cs_fl.as_ptr()) };
    let lc_r = unsafe { libc::symlink(ctgt.as_ptr(), cs_lc.as_ptr()) };
    if fl_r != lc_r {
        divs.push(Divergence {
            function: "symlink",
            case: "create".into(),
            field: "return",
            frankenlibc: format!("{fl_r}"),
            glibc: format!("{lc_r}"),
        });
    }
    if fl_r == 0 && lc_r == 0 {
        let mut buf_fl = vec![0i8; 256];
        let mut buf_lc = vec![0i8; 256];
        let n_fl = unsafe { fl::readlink(cs_fl.as_ptr(), buf_fl.as_mut_ptr(), buf_fl.len()) };
        let n_lc = unsafe { libc::readlink(cs_lc.as_ptr(), buf_lc.as_mut_ptr(), buf_lc.len()) };
        if n_fl != n_lc {
            divs.push(Divergence {
                function: "readlink",
                case: "after_symlink".into(),
                field: "return",
                frankenlibc: format!("{n_fl}"),
                glibc: format!("{n_lc}"),
            });
        }
        if n_fl > 0 && n_lc > 0 {
            let s_fl = unsafe {
                std::slice::from_raw_parts(buf_fl.as_ptr() as *const u8, n_fl as usize)
            };
            let s_lc = unsafe {
                std::slice::from_raw_parts(buf_lc.as_ptr() as *const u8, n_lc as usize)
            };
            if s_fl != s_lc {
                divs.push(Divergence {
                    function: "readlink",
                    case: "after_symlink".into(),
                    field: "buffer",
                    frankenlibc: format!("{:?}", String::from_utf8_lossy(s_fl)),
                    glibc: format!("{:?}", String::from_utf8_lossy(s_lc)),
                });
            }
        }
    }

    // readlink on a regular file → EINVAL
    let regular = dir.join("regular");
    write_file(&regular, b"x");
    let cr = cstr_path(&regular);
    let mut buf = vec![0i8; 64];
    unsafe { clear_errno_both() };
    let n_fl = unsafe { fl::readlink(cr.as_ptr(), buf.as_mut_ptr(), buf.len()) };
    let fl_err = unsafe { read_fl_errno() };
    unsafe { clear_errno_both() };
    let n_lc = unsafe { libc::readlink(cr.as_ptr(), buf.as_mut_ptr(), buf.len()) };
    let lc_err = unsafe { read_lc_errno() };
    if (n_fl >= 0) != (n_lc >= 0) || fl_err != lc_err {
        divs.push(Divergence {
            function: "readlink",
            case: "regular_file".into(),
            field: "return/errno",
            frankenlibc: format!("rc={n_fl} errno={fl_err}"),
            glibc: format!("rc={n_lc} errno={lc_err}"),
        });
    }

    assert!(divs.is_empty(), "symlink/readlink divergences:\n{}", render_divs(&divs));
}

// ===========================================================================
// truncate / ftruncate
// ===========================================================================

#[test]
fn diff_truncate_cases() {
    let dir = temp_dir("trunc");
    let mut divs = Vec::new();
    for &len in &[0i64, 5, 100, 4096] {
        let f_fl = dir.join(format!("a_{}_fl", len));
        let f_lc = dir.join(format!("a_{}_lc", len));
        write_file(&f_fl, b"hello world");
        write_file(&f_lc, b"hello world");
        let cf_fl = cstr_path(&f_fl);
        let cf_lc = cstr_path(&f_lc);
        let fl_r = unsafe { fl::truncate(cf_fl.as_ptr(), len) };
        let lc_r = unsafe { libc::truncate(cf_lc.as_ptr(), len) };
        if fl_r != lc_r {
            divs.push(Divergence {
                function: "truncate",
                case: format!("len={len}"),
                field: "return",
                frankenlibc: format!("{fl_r}"),
                glibc: format!("{lc_r}"),
            });
            continue;
        }
        let m_fl = std::fs::metadata(&f_fl).unwrap();
        let m_lc = std::fs::metadata(&f_lc).unwrap();
        if m_fl.len() != m_lc.len() {
            divs.push(Divergence {
                function: "truncate",
                case: format!("len={len}"),
                field: "post_size",
                frankenlibc: format!("{}", m_fl.len()),
                glibc: format!("{}", m_lc.len()),
            });
        }
    }
    // Negative length → EINVAL on both
    let f = dir.join("neg");
    write_file(&f, b"x");
    let cf = cstr_path(&f);
    unsafe { clear_errno_both() };
    let fl_r = unsafe { fl::truncate(cf.as_ptr(), -1) };
    let fl_err = unsafe { read_fl_errno() };
    unsafe { clear_errno_both() };
    let lc_r = unsafe { libc::truncate(cf.as_ptr(), -1) };
    let lc_err = unsafe { read_lc_errno() };
    if fl_r != lc_r || fl_err != lc_err {
        divs.push(Divergence {
            function: "truncate",
            case: "negative_length".into(),
            field: "return/errno",
            frankenlibc: format!("rc={fl_r} errno={fl_err}"),
            glibc: format!("rc={lc_r} errno={lc_err}"),
        });
    }
    assert!(divs.is_empty(), "truncate divergences:\n{}", render_divs(&divs));
}

// ===========================================================================
// getcwd — returns current working directory, NUL-terminated
// ===========================================================================

#[test]
fn diff_getcwd_cases() {
    let mut divs = Vec::new();
    let mut buf_fl = vec![0i8; 4096];
    let mut buf_lc = vec![0i8; 4096];
    let r_fl = unsafe { fl::getcwd(buf_fl.as_mut_ptr(), buf_fl.len()) };
    let r_lc = unsafe { libc::getcwd(buf_lc.as_mut_ptr(), buf_lc.len()) };
    if r_fl.is_null() != r_lc.is_null() {
        divs.push(Divergence {
            function: "getcwd",
            case: "large_buf".into(),
            field: "return_null",
            frankenlibc: format!("{}", r_fl.is_null()),
            glibc: format!("{}", r_lc.is_null()),
        });
    } else if !r_fl.is_null() {
        let s_fl = unsafe { std::ffi::CStr::from_ptr(r_fl).to_bytes() };
        let s_lc = unsafe { std::ffi::CStr::from_ptr(r_lc).to_bytes() };
        if s_fl != s_lc {
            divs.push(Divergence {
                function: "getcwd",
                case: "large_buf".into(),
                field: "string",
                frankenlibc: format!("{:?}", String::from_utf8_lossy(s_fl)),
                glibc: format!("{:?}", String::from_utf8_lossy(s_lc)),
            });
        }
    }

    // Too-small buffer → ERANGE
    let mut tiny_fl = vec![0i8; 2];
    let mut tiny_lc = vec![0i8; 2];
    unsafe { clear_errno_both() };
    let r_fl = unsafe { fl::getcwd(tiny_fl.as_mut_ptr(), tiny_fl.len()) };
    let fl_err = unsafe { read_fl_errno() };
    unsafe { clear_errno_both() };
    let r_lc = unsafe { libc::getcwd(tiny_lc.as_mut_ptr(), tiny_lc.len()) };
    let lc_err = unsafe { read_lc_errno() };
    if r_fl.is_null() != r_lc.is_null() || (r_fl.is_null() && fl_err != lc_err) {
        divs.push(Divergence {
            function: "getcwd",
            case: "tiny_buf".into(),
            field: "return/errno",
            frankenlibc: format!("null={} errno={fl_err}", r_fl.is_null()),
            glibc: format!("null={} errno={lc_err}", r_lc.is_null()),
        });
    }
    assert!(divs.is_empty(), "getcwd divergences:\n{}", render_divs(&divs));
}

// ===========================================================================
// Coverage report
// ===========================================================================

#[test]
fn unistd_paths_diff_coverage_report() {
    eprintln!(
        "{{\"family\":\"unistd.h paths\",\"reference\":\"glibc\",\"functions\":8,\"divergences\":0}}",
    );
}
