#![cfg(target_os = "linux")]
#![allow(unsafe_code)] // host-glibc tow* oracle (libc)

//! Differential scan of fl's wide case mappings (towupper/towlower) vs host
//! glibc tow*, over the full code-point range, in the C.UTF-8 locale. fl's
//! mappings are derived from Rust's Unicode case tables plus hand-coded
//! override/version-skew patches (bd-2g7oyh.150); this scan re-verifies they
//! stay glibc-exact and characterizes any residual divergence.

use std::ffi::{c_char, c_int};

use frankenlibc_core::string::wchar::{towlower as fl_towlower, towupper as fl_towupper};

unsafe extern "C" {
    fn setlocale(category: c_int, locale: *const c_char) -> *mut c_char;
    fn towupper(wc: u32) -> u32;
    fn towlower(wc: u32) -> u32;
}

const LC_CTYPE: c_int = 0;

fn set_locale(locale: &str) -> bool {
    let c = std::ffi::CString::new(locale).unwrap();
    !unsafe { setlocale(LC_CTYPE, c.as_ptr()) }.is_null()
}

#[test]
fn towcase_differential_scan_vs_glibc() {
    assert!(set_locale("C.UTF-8"), "C.UTF-8 locale required");
    let mut up_div = 0u64;
    let mut lo_div = 0u64;
    let mut up_first = String::new();
    let mut lo_first = String::new();
    for cp in 0u32..0x11_0000 {
        if (0xD800..=0xDFFF).contains(&cp) {
            continue;
        }
        let flu = fl_towupper(cp);
        let hu = unsafe { towupper(cp) };
        if flu != hu {
            up_div += 1;
            if up_first.is_empty() {
                up_first = format!("U+{cp:04X} fl=U+{flu:04X} glibc=U+{hu:04X}");
            }
        }
        let fll = fl_towlower(cp);
        let hl = unsafe { towlower(cp) };
        if fll != hl {
            lo_div += 1;
            if lo_first.is_empty() {
                lo_first = format!("U+{cp:04X} fl=U+{fll:04X} glibc=U+{hl:04X}");
            }
        }
    }
    eprintln!("towupper divergences={up_div} first={up_first}");
    eprintln!("towlower divergences={lo_div} first={lo_first}");
    assert_eq!(
        up_div, 0,
        "towupper diverges from glibc C.UTF-8; first {up_first}"
    );
    assert_eq!(
        lo_div, 0,
        "towlower diverges from glibc C.UTF-8; first {lo_first}"
    );
}
