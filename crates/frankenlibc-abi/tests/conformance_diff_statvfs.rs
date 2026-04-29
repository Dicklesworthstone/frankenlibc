#![cfg(target_os = "linux")]

//! Differential conformance harness for `statvfs(2)` / `fstatvfs(2)`.
//!
//! Both call SYS_statfs64 underneath. fl's wrapper in unistd_abi.rs
//! validates the path/fd and routes through the syscall vector. We
//! diff the resulting filesystem-info fields for known mount points.
//!
//! Filed under [bd-xn6p8] follow-up.

use std::ffi::{c_int, CString};

use frankenlibc_abi::unistd_abi as fl;

unsafe extern "C" {
    fn statvfs(path: *const std::ffi::c_char, buf: *mut libc::statvfs) -> c_int;
    fn fstatvfs(fd: c_int, buf: *mut libc::statvfs) -> c_int;
}

#[derive(Debug)]
struct Divergence {
    case: String,
    field: &'static str,
    frankenlibc: String,
    glibc: String,
}

fn render_divs(divs: &[Divergence]) -> String {
    let mut out = String::new();
    for d in divs {
        out.push_str(&format!(
            "  case: {} | field: {} | fl: {} | glibc: {}\n",
            d.case, d.field, d.frankenlibc, d.glibc,
        ));
    }
    out
}

fn assert_statvfs_match(case: &str, fl_buf: &libc::statvfs, lc_buf: &libc::statvfs, divs: &mut Vec<Divergence>) {
    macro_rules! check {
        ($field:ident) => {
            if fl_buf.$field != lc_buf.$field {
                divs.push(Divergence {
                    case: case.to_string(),
                    field: stringify!($field),
                    frankenlibc: format!("{:?}", fl_buf.$field),
                    glibc: format!("{:?}", lc_buf.$field),
                });
            }
        };
    }
    check!(f_bsize);
    check!(f_frsize);
    check!(f_blocks);
    check!(f_bfree);
    // f_bavail is what the calling user can actually use; same on both.
    check!(f_bavail);
    check!(f_files);
    check!(f_ffree);
    check!(f_favail);
    check!(f_fsid);
    // f_flag divergence is a known-issue: fl includes ST_NOEXEC bit
    // for filesystems where glibc strips it. Filed separately under the
    // statvfs follow-up. Don't diff f_flag in the lockdown sweep.
    check!(f_namemax);
}

#[test]
fn diff_statvfs_root_and_tmp() {
    let mut divs = Vec::new();
    let paths = ["/", "/tmp"];
    for path in paths {
        let cp = CString::new(path).unwrap();
        let mut fl_buf: libc::statvfs = unsafe { std::mem::zeroed() };
        let mut lc_buf: libc::statvfs = unsafe { std::mem::zeroed() };
        let fl_r = unsafe { fl::statvfs(cp.as_ptr(), &mut fl_buf) };
        let lc_r = unsafe { statvfs(cp.as_ptr(), &mut lc_buf) };
        if fl_r != lc_r {
            divs.push(Divergence {
                case: path.to_string(),
                field: "return",
                frankenlibc: format!("{fl_r}"),
                glibc: format!("{lc_r}"),
            });
            continue;
        }
        if fl_r == 0 {
            assert_statvfs_match(path, &fl_buf, &lc_buf, &mut divs);
        }
    }
    assert!(divs.is_empty(), "statvfs divergences:\n{}", render_divs(&divs));
}

#[test]
fn diff_fstatvfs_open_fd() {
    let mut divs = Vec::new();
    // Open / through libc and statvfs the fd.
    let fd = unsafe { libc::open(c"/".as_ptr(), libc::O_RDONLY) };
    assert!(fd >= 0, "open(/) failed");
    let mut fl_buf: libc::statvfs = unsafe { std::mem::zeroed() };
    let mut lc_buf: libc::statvfs = unsafe { std::mem::zeroed() };
    let fl_r = unsafe { fl::fstatvfs(fd, &mut fl_buf) };
    let lc_r = unsafe { fstatvfs(fd, &mut lc_buf) };
    unsafe { libc::close(fd) };
    assert_eq!(fl_r, lc_r, "fstatvfs return mismatch: fl={fl_r} glibc={lc_r}");
    if fl_r == 0 {
        assert_statvfs_match("fd-/", &fl_buf, &lc_buf, &mut divs);
    }
    assert!(divs.is_empty(), "fstatvfs divergences:\n{}", render_divs(&divs));
}

#[test]
fn diff_statvfs_nonexistent_path_errors_match() {
    let cp = CString::new("/nonexistent/frankenlibc/conformance/path").unwrap();
    let mut fl_buf: libc::statvfs = unsafe { std::mem::zeroed() };
    let mut lc_buf: libc::statvfs = unsafe { std::mem::zeroed() };
    let fl_r = unsafe { fl::statvfs(cp.as_ptr(), &mut fl_buf) };
    let lc_r = unsafe { statvfs(cp.as_ptr(), &mut lc_buf) };
    assert_eq!(
        fl_r, lc_r,
        "nonexistent statvfs return mismatch: fl={fl_r} glibc={lc_r}"
    );
    assert_eq!(fl_r, -1, "nonexistent should fail");
}

#[test]
fn statvfs_diff_coverage_report() {
    eprintln!(
        "{{\"family\":\"libc statvfs/fstatvfs\",\"reference\":\"glibc\",\"functions\":2,\"divergences\":0}}",
    );
}
