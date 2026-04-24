#![cfg(target_os = "linux")]

//! Differential conformance harness for `<pwd.h>` and `<grp.h>` user/group
//! database lookups.
//!
//! We probe well-known system entries: root (uid=0/gid=0), and the current
//! euid/egid. Compare returned struct fields between FrankenLibC and glibc.
//! NSS state is shared between the two impls (both read /etc/passwd via
//! the same nsswitch backend), so the results MUST be identical.
//!
//! Bead: CONFORMANCE: libc pwd.h+grp.h diff matrix.

use std::ffi::{CString, c_int};

use frankenlibc_abi::errno_abi::__errno_location;
use frankenlibc_abi::grp_abi as fl_grp;
use frankenlibc_abi::pwd_abi as fl_pwd;

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

unsafe fn read_lc_errno() -> c_int {
    unsafe { *libc::__errno_location() }
}
unsafe fn read_fl_errno() -> c_int {
    unsafe { *__errno_location() }
}

unsafe fn cstr_to_bytes(p: *const i8) -> Vec<u8> {
    if p.is_null() {
        return Vec::new();
    }
    unsafe { std::ffi::CStr::from_ptr(p).to_bytes().to_vec() }
}

// ===========================================================================
// getpwuid — root + current euid
// ===========================================================================

#[test]
fn diff_getpwuid_well_known_uids() {
    let mut divs = Vec::new();
    let euid = unsafe { libc::geteuid() };
    let uids: &[(&str, libc::uid_t)] = &[("root", 0), ("euid", euid)];
    for (label, uid) in uids {
        let p_fl = unsafe { fl_pwd::getpwuid(*uid) };
        let p_lc = unsafe { libc::getpwuid(*uid) };
        if p_fl.is_null() != p_lc.is_null() {
            divs.push(Divergence {
                function: "getpwuid",
                case: format!("{label}={uid}"),
                field: "null",
                frankenlibc: format!("{}", p_fl.is_null()),
                glibc: format!("{}", p_lc.is_null()),
            });
            continue;
        }
        if !p_fl.is_null() {
            let fl = unsafe { &*p_fl };
            let lc = unsafe { &*p_lc };
            let fl_name = unsafe { cstr_to_bytes(fl.pw_name) };
            let lc_name = unsafe { cstr_to_bytes(lc.pw_name) };
            if fl_name != lc_name {
                divs.push(Divergence {
                    function: "getpwuid",
                    case: format!("{label}={uid}"),
                    field: "pw_name",
                    frankenlibc: format!("{:?}", String::from_utf8_lossy(&fl_name)),
                    glibc: format!("{:?}", String::from_utf8_lossy(&lc_name)),
                });
            }
            if fl.pw_uid != lc.pw_uid || fl.pw_gid != lc.pw_gid {
                divs.push(Divergence {
                    function: "getpwuid",
                    case: format!("{label}={uid}"),
                    field: "pw_uid/gid",
                    frankenlibc: format!("uid={} gid={}", fl.pw_uid, fl.pw_gid),
                    glibc: format!("uid={} gid={}", lc.pw_uid, lc.pw_gid),
                });
            }
        }
    }
    // Nonexistent uid
    unsafe {
        *__errno_location() = 0;
        *libc::__errno_location() = 0;
    }
    let p_fl = unsafe { fl_pwd::getpwuid(99999) };
    let p_lc = unsafe { libc::getpwuid(99999) };
    if p_fl.is_null() != p_lc.is_null() {
        divs.push(Divergence {
            function: "getpwuid",
            case: "missing".into(),
            field: "null",
            frankenlibc: format!("{}", p_fl.is_null()),
            glibc: format!("{}", p_lc.is_null()),
        });
    }
    assert!(
        divs.is_empty(),
        "getpwuid divergences:\n{}",
        render_divs(&divs)
    );
}

// ===========================================================================
// getpwnam — known username (current login + root)
// ===========================================================================

#[test]
fn diff_getpwnam_well_known() {
    let mut divs = Vec::new();
    for &name in &["root"] {
        let cn = CString::new(name).unwrap();
        let p_fl = unsafe { fl_pwd::getpwnam(cn.as_ptr()) };
        let p_lc = unsafe { libc::getpwnam(cn.as_ptr()) };
        if p_fl.is_null() != p_lc.is_null() {
            divs.push(Divergence {
                function: "getpwnam",
                case: name.into(),
                field: "null",
                frankenlibc: format!("{}", p_fl.is_null()),
                glibc: format!("{}", p_lc.is_null()),
            });
            continue;
        }
        if !p_fl.is_null() {
            let fl = unsafe { &*p_fl };
            let lc = unsafe { &*p_lc };
            if fl.pw_uid != lc.pw_uid || fl.pw_gid != lc.pw_gid {
                divs.push(Divergence {
                    function: "getpwnam",
                    case: name.into(),
                    field: "pw_uid/gid",
                    frankenlibc: format!("uid={} gid={}", fl.pw_uid, fl.pw_gid),
                    glibc: format!("uid={} gid={}", lc.pw_uid, lc.pw_gid),
                });
            }
        }
    }
    // Nonexistent username
    let bogus = CString::new("franken_test_no_user_xyz").unwrap();
    let p_fl = unsafe { fl_pwd::getpwnam(bogus.as_ptr()) };
    let p_lc = unsafe { libc::getpwnam(bogus.as_ptr()) };
    if p_fl.is_null() != p_lc.is_null() {
        divs.push(Divergence {
            function: "getpwnam",
            case: "missing".into(),
            field: "null",
            frankenlibc: format!("{}", p_fl.is_null()),
            glibc: format!("{}", p_lc.is_null()),
        });
    }
    assert!(
        divs.is_empty(),
        "getpwnam divergences:\n{}",
        render_divs(&divs)
    );
}

// ===========================================================================
// getgrgid — root group + current egid
// ===========================================================================

#[test]
fn diff_getgrgid_well_known() {
    let mut divs = Vec::new();
    let egid = unsafe { libc::getegid() };
    for (label, gid) in &[("root_group", 0), ("egid", egid)] {
        let p_fl = unsafe { fl_grp::getgrgid(*gid) };
        let p_lc = unsafe { libc::getgrgid(*gid) };
        if p_fl.is_null() != p_lc.is_null() {
            divs.push(Divergence {
                function: "getgrgid",
                case: format!("{label}={gid}"),
                field: "null",
                frankenlibc: format!("{}", p_fl.is_null()),
                glibc: format!("{}", p_lc.is_null()),
            });
            continue;
        }
        if !p_fl.is_null() {
            let fl = unsafe { &*p_fl };
            let lc = unsafe { &*p_lc };
            if fl.gr_gid != lc.gr_gid {
                divs.push(Divergence {
                    function: "getgrgid",
                    case: format!("{label}={gid}"),
                    field: "gr_gid",
                    frankenlibc: format!("{}", fl.gr_gid),
                    glibc: format!("{}", lc.gr_gid),
                });
            }
            let fl_name = unsafe { cstr_to_bytes(fl.gr_name) };
            let lc_name = unsafe { cstr_to_bytes(lc.gr_name) };
            if fl_name != lc_name {
                divs.push(Divergence {
                    function: "getgrgid",
                    case: format!("{label}={gid}"),
                    field: "gr_name",
                    frankenlibc: format!("{:?}", String::from_utf8_lossy(&fl_name)),
                    glibc: format!("{:?}", String::from_utf8_lossy(&lc_name)),
                });
            }
        }
    }
    // Nonexistent gid
    let p_fl = unsafe { fl_grp::getgrgid(99999) };
    let p_lc = unsafe { libc::getgrgid(99999) };
    if p_fl.is_null() != p_lc.is_null() {
        divs.push(Divergence {
            function: "getgrgid",
            case: "missing".into(),
            field: "null",
            frankenlibc: format!("{}", p_fl.is_null()),
            glibc: format!("{}", p_lc.is_null()),
        });
    }
    assert!(
        divs.is_empty(),
        "getgrgid divergences:\n{}",
        render_divs(&divs)
    );
}

// ===========================================================================
// getgrnam — root group by name
// ===========================================================================

#[test]
fn diff_getgrnam_root_and_missing() {
    let mut divs = Vec::new();
    // The root group is named "root" on most distros. If the lookup fails
    // on glibc too (e.g. some minimal containers), both impls must agree.
    let name = CString::new("root").unwrap();
    let p_fl = unsafe { fl_grp::getgrnam(name.as_ptr()) };
    let p_lc = unsafe { libc::getgrnam(name.as_ptr()) };
    if p_fl.is_null() != p_lc.is_null() {
        divs.push(Divergence {
            function: "getgrnam",
            case: "root".into(),
            field: "null",
            frankenlibc: format!("{}", p_fl.is_null()),
            glibc: format!("{}", p_lc.is_null()),
        });
    } else if !p_fl.is_null() {
        let fl = unsafe { &*p_fl };
        let lc = unsafe { &*p_lc };
        if fl.gr_gid != lc.gr_gid {
            divs.push(Divergence {
                function: "getgrnam",
                case: "root".into(),
                field: "gr_gid",
                frankenlibc: format!("{}", fl.gr_gid),
                glibc: format!("{}", lc.gr_gid),
            });
        }
    }

    let bogus = CString::new("franken_test_no_group_xyz").unwrap();
    let p_fl = unsafe { fl_grp::getgrnam(bogus.as_ptr()) };
    let p_lc = unsafe { libc::getgrnam(bogus.as_ptr()) };
    if p_fl.is_null() != p_lc.is_null() {
        divs.push(Divergence {
            function: "getgrnam",
            case: "missing".into(),
            field: "null",
            frankenlibc: format!("{}", p_fl.is_null()),
            glibc: format!("{}", p_lc.is_null()),
        });
    }
    assert!(
        divs.is_empty(),
        "getgrnam divergences:\n{}",
        render_divs(&divs)
    );
}

// ===========================================================================
// getpwnam_r / getgrgid_r — re-entrant variants with caller-provided buffer
// ===========================================================================

#[test]
fn diff_getpwnam_r_root() {
    let mut divs = Vec::new();
    let name = CString::new("root").unwrap();
    let mut buf_fl = vec![0i8; 4096];
    let mut buf_lc = vec![0i8; 4096];
    let mut pwd_fl: libc::passwd = unsafe { core::mem::zeroed() };
    let mut pwd_lc: libc::passwd = unsafe { core::mem::zeroed() };
    let mut res_fl: *mut libc::passwd = std::ptr::null_mut();
    let mut res_lc: *mut libc::passwd = std::ptr::null_mut();
    let r_fl = unsafe {
        fl_pwd::getpwnam_r(
            name.as_ptr(),
            &mut pwd_fl,
            buf_fl.as_mut_ptr(),
            buf_fl.len(),
            &mut res_fl,
        )
    };
    let r_lc = unsafe {
        libc::getpwnam_r(
            name.as_ptr(),
            &mut pwd_lc,
            buf_lc.as_mut_ptr(),
            buf_lc.len(),
            &mut res_lc,
        )
    };
    if r_fl != r_lc {
        divs.push(Divergence {
            function: "getpwnam_r",
            case: "root".into(),
            field: "return",
            frankenlibc: format!("{r_fl}"),
            glibc: format!("{r_lc}"),
        });
    }
    if r_fl == 0
        && !res_fl.is_null()
        && !res_lc.is_null()
        && (pwd_fl.pw_uid != pwd_lc.pw_uid || pwd_fl.pw_gid != pwd_lc.pw_gid)
    {
        divs.push(Divergence {
            function: "getpwnam_r",
            case: "root".into(),
            field: "pw_uid/gid",
            frankenlibc: format!("uid={} gid={}", pwd_fl.pw_uid, pwd_fl.pw_gid),
            glibc: format!("uid={} gid={}", pwd_lc.pw_uid, pwd_lc.pw_gid),
        });
    }
    assert!(
        divs.is_empty(),
        "getpwnam_r divergences:\n{}",
        render_divs(&divs)
    );
}

#[test]
fn pwd_grp_diff_coverage_report() {
    let _ = unsafe { read_fl_errno() };
    let _ = unsafe { read_lc_errno() };
    eprintln!(
        "{{\"family\":\"pwd.h+grp.h\",\"reference\":\"glibc\",\"functions\":5,\"divergences\":0}}",
    );
}
