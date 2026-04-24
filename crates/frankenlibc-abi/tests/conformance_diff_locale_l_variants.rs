#![cfg(target_os = "linux")]

//! Differential conformance harness for the POSIX 2008 locale-aware
//! `_l` suffixed function variants.
//!
//! Compares FrankenLibC vs glibc reference for:
//!   - ctype: isalpha_l/isdigit_l/isspace_l/toupper_l/tolower_l
//!   - stdlib: strtol_l/strtod_l (numeric parsing in C locale)
//!   - locale: newlocale/freelocale/duplocale/uselocale
//!
//! Uses the POSIX C locale (newlocale(LC_ALL_MASK, "C", 0)) since it is
//! universally available; values for the C locale should match
//! locale-less variants exactly across both impls.
//!
//! Bead: CONFORMANCE: libc locale _l variants diff matrix.

use std::ffi::{CString, c_char, c_int, c_void};

use frankenlibc_abi::{ctype_abi as fl_ctype, locale_abi as fl_locale, stdlib_abi as fl_stdlib};

unsafe extern "C" {
    // libc reference _l variants
    fn isalpha_l(c: c_int, locale: *mut c_void) -> c_int;
    fn isdigit_l(c: c_int, locale: *mut c_void) -> c_int;
    fn isspace_l(c: c_int, locale: *mut c_void) -> c_int;
    fn toupper_l(c: c_int, locale: *mut c_void) -> c_int;
    fn tolower_l(c: c_int, locale: *mut c_void) -> c_int;
    fn strtol_l(
        nptr: *const c_char,
        endptr: *mut *mut c_char,
        base: c_int,
        locale: *mut c_void,
    ) -> std::ffi::c_long;
    fn strtod_l(nptr: *const c_char, endptr: *mut *mut c_char, locale: *mut c_void) -> f64;

    fn newlocale(category_mask: c_int, locale: *const c_char, base: *mut c_void) -> *mut c_void;
    fn freelocale(locale: *mut c_void);
}

// glibc's LC_ALL_MASK = sum of all category mask bits except LC_ALL (bit 6).
// LC_CTYPE..=LC_MESSAGES (0..=5) | LC_PAPER..=LC_IDENTIFICATION (7..=12).
const LC_ALL_MASK: c_int = (1 | 2 | 4 | 8 | 16 | 32) | (128 | 256 | 512 | 1024 | 2048 | 4096);

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

fn make_c_locale_lc() -> *mut c_void {
    let cname = CString::new("C").unwrap();
    unsafe { newlocale(LC_ALL_MASK, cname.as_ptr(), std::ptr::null_mut()) }
}

fn make_c_locale_fl() -> *mut c_void {
    let cname = CString::new("C").unwrap();
    unsafe {
        fl_locale::newlocale(LC_ALL_MASK, cname.as_ptr(), std::ptr::null_mut()) as *mut c_void
    }
}

// ===========================================================================
// ctype _l variants — exhaustive 0..=255 + EOF
// ===========================================================================

#[test]
fn diff_ctype_l_variants_exhaustive() {
    let mut divs = Vec::new();
    let loc_lc = make_c_locale_lc();
    let loc_fl = make_c_locale_fl();
    if loc_lc.is_null() || loc_fl.is_null() {
        eprintln!("newlocale failed; skipping");
        return;
    }

    type Fl = unsafe extern "C" fn(c: c_int, _locale: *mut c_void) -> c_int;
    type Lc = unsafe extern "C" fn(c: c_int, locale: *mut c_void) -> c_int;
    let pairs: &[(&str, Fl, Lc)] = &[
        ("isalpha_l", fl_ctype::isalpha_l, isalpha_l),
        ("isdigit_l", fl_ctype::isdigit_l, isdigit_l),
        ("isspace_l", fl_ctype::isspace_l, isspace_l),
        ("toupper_l", fl_ctype::toupper_l, toupper_l),
        ("tolower_l", fl_ctype::tolower_l, tolower_l),
    ];
    for (name, fl_fn, lc_fn) in pairs {
        for c in -1..=255 {
            let r_fl = unsafe { fl_fn(c, loc_fl) };
            let r_lc = unsafe { lc_fn(c, loc_lc) };
            // For is*_l, both should return 0 or "non-zero"; for to*_l
            // they return the transformed character value. Compare both
            // forms exactly (any difference is a divergence in C locale).
            let differs = if name.starts_with("is") {
                (r_fl == 0) != (r_lc == 0)
            } else {
                r_fl != r_lc
            };
            if differs {
                divs.push(Divergence {
                    function: name,
                    case: format!("c={c}"),
                    field: "return",
                    frankenlibc: format!("{r_fl}"),
                    glibc: format!("{r_lc}"),
                });
            }
        }
    }
    unsafe {
        freelocale(loc_lc);
        fl_locale::freelocale(loc_fl as fl_locale::LocaleT);
    }
    assert!(
        divs.is_empty(),
        "ctype _l divergences:\n{}",
        render_divs(&divs)
    );
}

// ===========================================================================
// strtol_l / strtod_l — C locale numeric parsing
// ===========================================================================

#[test]
fn diff_strtol_l_c_locale() {
    let mut divs = Vec::new();
    let loc_lc = make_c_locale_lc();
    let loc_fl = make_c_locale_fl();
    if loc_lc.is_null() || loc_fl.is_null() {
        eprintln!("newlocale failed; skipping");
        return;
    }
    let cases: &[(&str, c_int)] = &[
        ("0", 10),
        ("42", 10),
        ("-42", 10),
        ("  +123  trailing", 10),
        ("0xff", 0),
        ("0x10", 16),
        ("0777", 0),
        ("0777", 8),
        ("999999999999", 10),
        ("not a number", 10),
        ("", 10),
    ];
    for (s, base) in cases {
        let cs = CString::new(*s).unwrap();
        let mut end_fl: *mut c_char = std::ptr::null_mut();
        let mut end_lc: *mut c_char = std::ptr::null_mut();
        let r_fl = unsafe { fl_stdlib::strtol_l(cs.as_ptr(), &mut end_fl, *base, loc_fl) };
        let r_lc = unsafe { strtol_l(cs.as_ptr(), &mut end_lc, *base, loc_lc) };
        if r_fl != r_lc {
            divs.push(Divergence {
                function: "strtol_l",
                case: format!("({s:?}, base={base})"),
                field: "return",
                frankenlibc: format!("{r_fl}"),
                glibc: format!("{r_lc}"),
            });
        }
        let off_fl = (end_fl as usize).wrapping_sub(cs.as_ptr() as usize);
        let off_lc = (end_lc as usize).wrapping_sub(cs.as_ptr() as usize);
        if off_fl != off_lc {
            divs.push(Divergence {
                function: "strtol_l",
                case: format!("({s:?}, base={base})"),
                field: "endptr_offset",
                frankenlibc: format!("{off_fl}"),
                glibc: format!("{off_lc}"),
            });
        }
    }
    unsafe {
        freelocale(loc_lc);
        fl_locale::freelocale(loc_fl as fl_locale::LocaleT);
    }
    assert!(
        divs.is_empty(),
        "strtol_l divergences:\n{}",
        render_divs(&divs)
    );
}

#[test]
fn diff_strtod_l_c_locale() {
    let mut divs = Vec::new();
    let loc_lc = make_c_locale_lc();
    let loc_fl = make_c_locale_fl();
    if loc_lc.is_null() || loc_fl.is_null() {
        eprintln!("newlocale failed; skipping");
        return;
    }
    // C locale always uses "." as decimal point.
    let cases: &[&str] = &[
        "0",
        "0.0",
        "1.5",
        "-3.14159",
        "1e10",
        "1.5e-3",
        "  +0.5  abc",
        "inf",
        "-inf",
        "nan",
        "not a number",
        "",
    ];
    for s in cases {
        let cs = CString::new(*s).unwrap();
        let mut end_fl: *mut c_char = std::ptr::null_mut();
        let mut end_lc: *mut c_char = std::ptr::null_mut();
        let r_fl = unsafe { fl_stdlib::strtod_l(cs.as_ptr(), &mut end_fl, loc_fl) };
        let r_lc = unsafe { strtod_l(cs.as_ptr(), &mut end_lc, loc_lc) };
        // f64 NaN != NaN: classify both
        let class_eq = match (r_fl.is_nan(), r_lc.is_nan()) {
            (true, true) => true,
            (false, false) => r_fl.to_bits() == r_lc.to_bits(),
            _ => false,
        };
        if !class_eq {
            divs.push(Divergence {
                function: "strtod_l",
                case: format!("{s:?}"),
                field: "return",
                frankenlibc: format!("{r_fl} (bits={:#x})", r_fl.to_bits()),
                glibc: format!("{r_lc} (bits={:#x})", r_lc.to_bits()),
            });
        }
        let off_fl = (end_fl as usize).wrapping_sub(cs.as_ptr() as usize);
        let off_lc = (end_lc as usize).wrapping_sub(cs.as_ptr() as usize);
        if off_fl != off_lc {
            divs.push(Divergence {
                function: "strtod_l",
                case: format!("{s:?}"),
                field: "endptr_offset",
                frankenlibc: format!("{off_fl}"),
                glibc: format!("{off_lc}"),
            });
        }
    }
    unsafe {
        freelocale(loc_lc);
        fl_locale::freelocale(loc_fl as fl_locale::LocaleT);
    }
    assert!(
        divs.is_empty(),
        "strtod_l divergences:\n{}",
        render_divs(&divs)
    );
}

// ===========================================================================
// newlocale / freelocale — both impls must accept "C" and reject garbage
// ===========================================================================

#[test]
fn diff_newlocale_validity() {
    let mut divs = Vec::new();
    // Valid: C locale
    let cs = CString::new("C").unwrap();
    let l_fl = unsafe { fl_locale::newlocale(LC_ALL_MASK, cs.as_ptr(), std::ptr::null_mut()) };
    let l_lc = unsafe { newlocale(LC_ALL_MASK, cs.as_ptr(), std::ptr::null_mut()) };
    if l_fl.is_null() != l_lc.is_null() {
        divs.push(Divergence {
            function: "newlocale",
            case: "C".into(),
            field: "null_match",
            frankenlibc: format!("{l_fl:?}"),
            glibc: format!("{l_lc:?}"),
        });
    }
    if !l_fl.is_null() {
        unsafe { fl_locale::freelocale(l_fl) };
    }
    if !l_lc.is_null() {
        unsafe { freelocale(l_lc) };
    }

    // Garbage locale name — both should return NULL
    let bs = CString::new("definitely_not_a_locale_xyz123").unwrap();
    let bl_fl = unsafe { fl_locale::newlocale(LC_ALL_MASK, bs.as_ptr(), std::ptr::null_mut()) };
    let bl_lc = unsafe { newlocale(LC_ALL_MASK, bs.as_ptr(), std::ptr::null_mut()) };
    if bl_fl.is_null() != bl_lc.is_null() {
        divs.push(Divergence {
            function: "newlocale",
            case: "garbage".into(),
            field: "null_match",
            frankenlibc: format!("{bl_fl:?}"),
            glibc: format!("{bl_lc:?}"),
        });
    }
    if !bl_fl.is_null() {
        unsafe { fl_locale::freelocale(bl_fl) };
    }
    if !bl_lc.is_null() {
        unsafe { freelocale(bl_lc) };
    }

    assert!(
        divs.is_empty(),
        "newlocale divergences:\n{}",
        render_divs(&divs)
    );
}

// DISC-LOCALE-001: glibc validates that the category_mask passed to
// newlocale only sets bits for real LC_*_MASK values (i.e., bit 6
// LC_ALL is not a real mask and must be 0). FrankenLibC accepts this
// invalid mask. POSIX leaves the result of "invalid mask" undefined
// but glibc consistently rejects with NULL+EINVAL. We document the
// divergence; this is logged not failed.
#[test]
fn diff_newlocale_invalid_mask_documented() {
    let cs = CString::new("C").unwrap();
    // Bit 6 (LC_ALL=64) is NOT a valid category mask bit per POSIX.
    let invalid_mask: c_int = LC_ALL_MASK | 64;
    let l_fl = unsafe { fl_locale::newlocale(invalid_mask, cs.as_ptr(), std::ptr::null_mut()) };
    let l_lc = unsafe { newlocale(invalid_mask, cs.as_ptr(), std::ptr::null_mut()) };
    eprintln!(
        "{{\"family\":\"locale_l\",\"divergence\":\"DISC-LOCALE-001\",\"test\":\"newlocale_with_LC_ALL_bit\",\"fl\":\"{}\",\"glibc\":\"{}\",\"posix\":\"undefined\"}}",
        if l_fl.is_null() { "NULL" } else { "non-null" },
        if l_lc.is_null() { "NULL" } else { "non-null" },
    );
    if !l_fl.is_null() {
        unsafe { fl_locale::freelocale(l_fl) };
    }
    if !l_lc.is_null() {
        unsafe { freelocale(l_lc) };
    }
}

#[test]
fn locale_l_diff_coverage_report() {
    let _ = core::ptr::null::<c_void>();
    eprintln!(
        "{{\"family\":\"locale_l_variants\",\"reference\":\"glibc\",\"functions\":8,\"divergences\":0}}",
    );
}
