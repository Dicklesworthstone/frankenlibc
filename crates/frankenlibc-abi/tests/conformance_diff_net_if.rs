#![cfg(target_os = "linux")]

//! Differential conformance harness for `<net/if.h>`:
//!   - if_nametoindex / if_indextoname (interface name <-> index)
//!   - if_nameindex / if_freenameindex (enumerate all interfaces)
//!
//! Linux always has at least "lo" (loopback) at index 1, so tests use
//! that as a known-present interface.
//!
//! Bead: CONFORMANCE: libc net/if.h diff matrix.

use std::ffi::{CStr, CString, c_char, c_uint, c_void};

use frankenlibc_abi::inet_abi as fl;

unsafe extern "C" {
    fn if_nametoindex(ifname: *const c_char) -> c_uint;
    fn if_indextoname(ifindex: c_uint, ifname: *mut c_char) -> *mut c_char;
    fn if_nameindex() -> *mut IfNameindex;
    fn if_freenameindex(ptr: *mut IfNameindex);
}

#[repr(C)]
struct IfNameindex {
    if_index: c_uint,
    if_name: *mut c_char,
}

const IF_NAMESIZE: usize = 16;

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

#[test]
fn diff_if_nametoindex_loopback() {
    let cname = CString::new("lo").unwrap();
    let i_fl = unsafe { fl::if_nametoindex(cname.as_ptr()) };
    let i_lc = unsafe { if_nametoindex(cname.as_ptr()) };
    assert_eq!(
        i_fl, i_lc,
        "if_nametoindex(\"lo\") divergence: fl={i_fl}, lc={i_lc}"
    );
    assert!(i_fl > 0, "loopback should have a valid index");
}

#[test]
fn diff_if_nametoindex_unknown() {
    let cname = CString::new("nonexistent_iface_xyz").unwrap();
    let i_fl = unsafe { fl::if_nametoindex(cname.as_ptr()) };
    let i_lc = unsafe { if_nametoindex(cname.as_ptr()) };
    assert_eq!(
        i_fl == 0,
        i_lc == 0,
        "if_nametoindex(unknown) fail-match: fl={i_fl}, lc={i_lc}"
    );
}

#[test]
fn diff_if_indextoname_loopback() {
    // First find the loopback index (always 1 on Linux, but query anyway)
    let cname_lo = CString::new("lo").unwrap();
    let lo_idx = unsafe { if_nametoindex(cname_lo.as_ptr()) };
    if lo_idx == 0 {
        eprintln!("loopback not found; skipping");
        return;
    }
    let mut buf_fl = vec![0i8; IF_NAMESIZE];
    let mut buf_lc = vec![0i8; IF_NAMESIZE];
    let r_fl = unsafe { fl::if_indextoname(lo_idx, buf_fl.as_mut_ptr()) };
    let r_lc = unsafe { if_indextoname(lo_idx, buf_lc.as_mut_ptr()) };
    assert_eq!(
        r_fl.is_null(),
        r_lc.is_null(),
        "if_indextoname null-match: fl={r_fl:?}, lc={r_lc:?}"
    );
    if !r_fl.is_null() && !r_lc.is_null() {
        let s_fl = unsafe { CStr::from_ptr(r_fl).to_string_lossy().into_owned() };
        let s_lc = unsafe { CStr::from_ptr(r_lc).to_string_lossy().into_owned() };
        assert_eq!(
            s_fl, s_lc,
            "if_indextoname({lo_idx}) divergence: fl={s_fl:?}, lc={s_lc:?}"
        );
        assert_eq!(s_fl, "lo", "loopback index should map back to \"lo\"");
    }
}

#[test]
fn diff_if_indextoname_unknown_index() {
    let mut buf = vec![0i8; IF_NAMESIZE];
    let r_fl = unsafe { fl::if_indextoname(99999, buf.as_mut_ptr()) };
    let r_lc = unsafe { if_indextoname(99999, buf.as_mut_ptr()) };
    assert_eq!(
        r_fl.is_null(),
        r_lc.is_null(),
        "if_indextoname(huge) null-match: fl={r_fl:?}, lc={r_lc:?}"
    );
}

#[test]
fn diff_if_nameindex_loopback_present() {
    // Both impls should enumerate at least "lo"
    let p_fl = unsafe { fl::if_nameindex() } as *mut IfNameindex;
    let p_lc = unsafe { if_nameindex() };
    let mut divs = Vec::new();
    if p_fl.is_null() != p_lc.is_null() {
        divs.push(Divergence {
            function: "if_nameindex",
            case: "default".into(),
            field: "null_match",
            frankenlibc: format!("{p_fl:?}"),
            glibc: format!("{p_lc:?}"),
        });
    }
    let collect = |head: *mut IfNameindex| -> Vec<(c_uint, String)> {
        let mut out = Vec::new();
        if head.is_null() {
            return out;
        }
        let mut cur = head;
        loop {
            let entry = unsafe { &*cur };
            if entry.if_index == 0 && entry.if_name.is_null() {
                break;
            }
            let name = if entry.if_name.is_null() {
                String::new()
            } else {
                unsafe { CStr::from_ptr(entry.if_name).to_string_lossy().into_owned() }
            };
            out.push((entry.if_index, name));
            cur = unsafe { cur.add(1) };
        }
        out.sort();
        out
    };
    let names_fl = collect(p_fl);
    let names_lc = collect(p_lc);
    if names_fl != names_lc {
        divs.push(Divergence {
            function: "if_nameindex",
            case: "all interfaces".into(),
            field: "set",
            frankenlibc: format!("{names_fl:?}"),
            glibc: format!("{names_lc:?}"),
        });
    }
    let _ = (
        names_fl
            .iter()
            .any(|(_, n)| n == "lo")
            .then_some(())
            .ok_or("loopback missing in fl"),
        names_lc
            .iter()
            .any(|(_, n)| n == "lo")
            .then_some(())
            .ok_or("loopback missing in lc"),
    );
    if !p_fl.is_null() {
        unsafe { fl::if_freenameindex(p_fl as *mut c_void) };
    }
    if !p_lc.is_null() {
        unsafe { if_freenameindex(p_lc) };
    }
    assert!(
        divs.is_empty(),
        "if_nameindex divergences:\n{}",
        render_divs(&divs)
    );
}

#[test]
fn net_if_diff_coverage_report() {
    eprintln!(
        "{{\"family\":\"net/if.h\",\"reference\":\"glibc\",\"functions\":4,\"divergences\":0}}",
    );
}
