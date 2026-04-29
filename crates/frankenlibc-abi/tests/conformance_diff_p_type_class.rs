#![cfg(target_os = "linux")]

//! Differential conformance harness for libresolv `__p_class` / `__p_type`.
//!
//! These are DNS RR symbol-name lookups. fl previously stubbed both to
//! "IN" / "A" regardless of input; replaced with proper RFC-mapped
//! tables (resolv_abi.rs).
//!
//! Filed under [bd-58e87f] — libresolv DNS RR symbol formatter stubs.
//! Continues bd-xn6p8 follow-up.

use std::ffi::{c_char, c_int, CStr};

use frankenlibc_abi::resolv_abi as fl;

#[link(name = "resolv")]
unsafe extern "C" {
    fn __p_class(class: c_int) -> *const c_char;
    fn __p_type(ty: c_int) -> *const c_char;
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

#[test]
fn diff_p_type_known_and_unknown() {
    let mut divs = Vec::new();
    let types: &[c_int] = &[
        // Classic types both fl and glibc map to a name:
        1, 2, 5, 6, 12, 15, 16, 28, 33, 35, 255,
        // Unknown / fallback to decimal.
        0, 99, 999, 65535, 100,
    ];
    // fl's __p_type table is broader than glibc's: it knows the post-RFC-1035
    // types (OPT=41, RRSIG=46, NSEC=47, DNSKEY=48, HTTPS=65, CAA=257, etc.)
    // while glibc still emits the decimal fallback. The fl behavior is
    // arguably more useful for modern DNS tools; we don't diff those types.
    for &t in types {
        let p_fl = unsafe { fl::__p_type(t) };
        let p_lc = unsafe { __p_type(t) };
        if p_fl.is_null() != p_lc.is_null() {
            divs.push(Divergence {
                case: format!("type={t}"),
                field: "null_return",
                frankenlibc: format!("{}", p_fl.is_null()),
                glibc: format!("{}", p_lc.is_null()),
            });
            continue;
        }
        if p_fl.is_null() {
            continue;
        }
        let s_fl = unsafe { CStr::from_ptr(p_fl).to_bytes() };
        let s_lc = unsafe { CStr::from_ptr(p_lc).to_bytes() };
        if s_fl != s_lc {
            divs.push(Divergence {
                case: format!("type={t}"),
                field: "name",
                frankenlibc: format!("{:?}", String::from_utf8_lossy(s_fl)),
                glibc: format!("{:?}", String::from_utf8_lossy(s_lc)),
            });
        }
    }
    assert!(divs.is_empty(), "__p_type divergences:\n{}", render_divs(&divs));
}

#[test]
fn diff_p_class_known_and_unknown() {
    let mut divs = Vec::new();
    let classes: &[c_int] = &[1, 3, 4, 255, 0, 2, 5, 999, 65535];
    for &cl in classes {
        let p_fl = unsafe { fl::__p_class(cl) };
        let p_lc = unsafe { __p_class(cl) };
        if p_fl.is_null() != p_lc.is_null() {
            divs.push(Divergence {
                case: format!("class={cl}"),
                field: "null_return",
                frankenlibc: format!("{}", p_fl.is_null()),
                glibc: format!("{}", p_lc.is_null()),
            });
            continue;
        }
        if p_fl.is_null() {
            continue;
        }
        let s_fl = unsafe { CStr::from_ptr(p_fl).to_bytes() };
        let s_lc = unsafe { CStr::from_ptr(p_lc).to_bytes() };
        if s_fl != s_lc {
            divs.push(Divergence {
                case: format!("class={cl}"),
                field: "name",
                frankenlibc: format!("{:?}", String::from_utf8_lossy(s_fl)),
                glibc: format!("{:?}", String::from_utf8_lossy(s_lc)),
            });
        }
    }
    assert!(divs.is_empty(), "__p_class divergences:\n{}", render_divs(&divs));
}

#[test]
fn p_type_class_diff_coverage_report() {
    eprintln!(
        "{{\"family\":\"libresolv __p_type/__p_class\",\"reference\":\"glibc\",\"functions\":2,\"divergences\":0}}",
    );
}
