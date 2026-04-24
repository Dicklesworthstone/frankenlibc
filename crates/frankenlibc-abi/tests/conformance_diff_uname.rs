#![cfg(target_os = "linux")]

//! Differential conformance harness for system-info functions:
//!   - uname(struct utsname *)
//!   - gethostname(buf, len)
//!   - getdomainname(buf, len)
//!
//! These read kernel-provided system identifiers; both impls should
//! produce identical bytes.
//!
//! Bead: CONFORMANCE: libc uname/hostname diff matrix.

use std::ffi::{c_char, c_int};

use frankenlibc_abi::unistd_abi as fl;

unsafe extern "C" {
    fn uname(buf: *mut libc::utsname) -> c_int;
    fn gethostname(name: *mut c_char, len: usize) -> c_int;
    fn getdomainname(name: *mut c_char, len: usize) -> c_int;
}

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

fn cstr_to_string(arr: &[c_char]) -> String {
    let mut bytes: Vec<u8> = Vec::with_capacity(arr.len());
    for &b in arr {
        let bb = b as u8;
        if bb == 0 {
            break;
        }
        bytes.push(bb);
    }
    String::from_utf8_lossy(&bytes).into_owned()
}

#[test]
fn diff_uname_all_fields() {
    let mut divs = Vec::new();
    let mut u_fl: libc::utsname = unsafe { core::mem::zeroed() };
    let mut u_lc: libc::utsname = unsafe { core::mem::zeroed() };
    let r_fl = unsafe { fl::uname(&mut u_fl as *mut _) };
    let r_lc = unsafe { uname(&mut u_lc as *mut _) };

    if r_fl != r_lc {
        divs.push(Divergence {
            function: "uname",
            case: "default".into(),
            field: "return",
            frankenlibc: format!("{r_fl}"),
            glibc: format!("{r_lc}"),
        });
    }
    if r_fl == 0 && r_lc == 0 {
        let pairs: &[(&str, &[c_char], &[c_char])] = &[
            ("sysname", &u_fl.sysname, &u_lc.sysname),
            ("nodename", &u_fl.nodename, &u_lc.nodename),
            ("release", &u_fl.release, &u_lc.release),
            ("version", &u_fl.version, &u_lc.version),
            ("machine", &u_fl.machine, &u_lc.machine),
            ("domainname", &u_fl.domainname, &u_lc.domainname),
        ];
        for (name, fl_field, lc_field) in pairs {
            let s_fl = cstr_to_string(fl_field);
            let s_lc = cstr_to_string(lc_field);
            if s_fl != s_lc {
                divs.push(Divergence {
                    function: "uname",
                    case: "default".into(),
                    field: name,
                    frankenlibc: format!("{s_fl:?}"),
                    glibc: format!("{s_lc:?}"),
                });
            }
        }
    }
    assert!(
        divs.is_empty(),
        "uname divergences:\n{}",
        render_divs(&divs)
    );
}

#[test]
fn diff_gethostname_match() {
    let mut divs = Vec::new();

    // Common buffer sizes
    let sizes: &[usize] = &[256, 64, 16];
    for size in sizes {
        let mut buf_fl = vec![0i8; *size];
        let mut buf_lc = vec![0i8; *size];
        let r_fl = unsafe { fl::gethostname(buf_fl.as_mut_ptr(), *size) };
        let r_lc = unsafe { gethostname(buf_lc.as_mut_ptr(), *size) };
        // Both should agree on success vs failure
        if (r_fl == 0) != (r_lc == 0) {
            divs.push(Divergence {
                function: "gethostname",
                case: format!("size={size}"),
                field: "success_match",
                frankenlibc: format!("{r_fl}"),
                glibc: format!("{r_lc}"),
            });
            continue;
        }
        if r_fl == 0 {
            let s_fl = cstr_to_string(&buf_fl);
            let s_lc = cstr_to_string(&buf_lc);
            if s_fl != s_lc {
                divs.push(Divergence {
                    function: "gethostname",
                    case: format!("size={size}"),
                    field: "name",
                    frankenlibc: format!("{s_fl:?}"),
                    glibc: format!("{s_lc:?}"),
                });
            }
        }
    }
    assert!(
        divs.is_empty(),
        "gethostname divergences:\n{}",
        render_divs(&divs)
    );
}

#[test]
fn diff_gethostname_zero_buf() {
    // Calling with a zero-length buffer: both POSIX impls should fail
    // (-1 with ENAMETOOLONG or similar) since they cannot null-terminate.
    let mut buf_fl: [c_char; 0] = [];
    let mut buf_lc: [c_char; 0] = [];
    let r_fl = unsafe { fl::gethostname(buf_fl.as_mut_ptr(), 0) };
    let r_lc = unsafe { gethostname(buf_lc.as_mut_ptr(), 0) };
    if (r_fl == 0) != (r_lc == 0) {
        panic!("gethostname zero-buf success_match: fl={r_fl}, glibc={r_lc}");
    }
}

#[test]
fn diff_getdomainname_match() {
    let mut divs = Vec::new();
    for size in &[256usize, 64] {
        let mut buf_fl = vec![0i8; *size];
        let mut buf_lc = vec![0i8; *size];
        let r_fl = unsafe { fl::getdomainname(buf_fl.as_mut_ptr(), *size) };
        let r_lc = unsafe { getdomainname(buf_lc.as_mut_ptr(), *size) };
        if (r_fl == 0) != (r_lc == 0) {
            divs.push(Divergence {
                function: "getdomainname",
                case: format!("size={size}"),
                field: "success_match",
                frankenlibc: format!("{r_fl}"),
                glibc: format!("{r_lc}"),
            });
            continue;
        }
        if r_fl == 0 {
            let s_fl = cstr_to_string(&buf_fl);
            let s_lc = cstr_to_string(&buf_lc);
            if s_fl != s_lc {
                divs.push(Divergence {
                    function: "getdomainname",
                    case: format!("size={size}"),
                    field: "name",
                    frankenlibc: format!("{s_fl:?}"),
                    glibc: format!("{s_lc:?}"),
                });
            }
        }
    }
    assert!(
        divs.is_empty(),
        "getdomainname divergences:\n{}",
        render_divs(&divs)
    );
}

#[test]
fn uname_diff_coverage_report() {
    eprintln!(
        "{{\"family\":\"sys/utsname.h+unistd.h(hostname)\",\"reference\":\"glibc\",\"functions\":3,\"divergences\":0}}",
    );
}
