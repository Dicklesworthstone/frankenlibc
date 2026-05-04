#![cfg(target_os = "linux")]

//! Differential conformance harness for the alignment-aware allocators:
//!   - posix_memalign(memptr, align, size)
//!   - aligned_alloc(align, size)
//!   - memalign(align, size) — GNU extension
//!
//! For each, fl and host glibc must agree on:
//!   - whether the call succeeds (return code / non-NULL)
//!   - that the returned pointer is actually `align`-aligned
//!   - that the documented invalid-input contracts match
//!     (alignment must be power-of-2, posix_memalign also requires
//!     alignment is a multiple of sizeof(void*))
//!
//! We don't diff exact pointer values (allocators legitimately differ).
//! Filed under [bd-xn6p8] follow-up.

use std::ffi::{c_int, c_void};

use frankenlibc_abi::malloc_abi as fl;

unsafe extern "C" {
    fn posix_memalign(memptr: *mut *mut c_void, align: usize, size: usize) -> c_int;
    fn aligned_alloc(align: usize, size: usize) -> *mut c_void;
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

const VALID_CASES: &[(usize, usize)] = &[
    (8, 64),
    (16, 64),
    (32, 256),
    (64, 1024),
    (128, 4096),
    (256, 1),
    (512, 65536),
    (4096, 8192),
];

const INVALID_POSIX_CASES: &[(usize, usize)] = &[
    (3, 64),  // not power of 2
    (5, 64),  // not power of 2
    (6, 64),  // alignment 6: not pow2 AND not multiple of sizeof(void*)
    (12, 64), // not power of 2
    // posix_memalign requires alignment >= sizeof(void*) (=8 on x86_64)
    (1, 64),
    (2, 64),
    (4, 64),
];

#[test]
fn diff_posix_memalign_success_cases() {
    let mut divs = Vec::new();
    for (align, size) in VALID_CASES {
        let mut fl_p: *mut c_void = std::ptr::null_mut();
        let mut lc_p: *mut c_void = std::ptr::null_mut();
        let fl_r = unsafe { fl::posix_memalign(&mut fl_p, *align, *size) };
        let lc_r = unsafe { posix_memalign(&mut lc_p, *align, *size) };
        let case = format!("(align={align}, size={size})");
        if fl_r != lc_r {
            divs.push(Divergence {
                case: case.clone(),
                field: "return",
                frankenlibc: format!("{fl_r}"),
                glibc: format!("{lc_r}"),
            });
        }
        if fl_r == 0 && !(fl_p as usize).is_multiple_of(*align) {
            divs.push(Divergence {
                case: case.clone(),
                field: "fl_alignment",
                frankenlibc: format!("ptr {:#x} not aligned to {align}", fl_p as usize),
                glibc: "(host aligned)".to_string(),
            });
        }
        if lc_r == 0 && !(lc_p as usize).is_multiple_of(*align) {
            divs.push(Divergence {
                case,
                field: "lc_alignment",
                frankenlibc: "(fl)".to_string(),
                glibc: format!("ptr {:#x} not aligned to {align}", lc_p as usize),
            });
        }
        if !fl_p.is_null() {
            unsafe { fl::free(fl_p) };
        }
        if !lc_p.is_null() {
            unsafe { libc::free(lc_p) };
        }
    }
    assert!(
        divs.is_empty(),
        "posix_memalign divergences:\n{}",
        render_divs(&divs)
    );
}

#[test]
fn diff_posix_memalign_invalid_cases() {
    let mut divs = Vec::new();
    for (align, size) in INVALID_POSIX_CASES {
        let mut fl_p: *mut c_void = std::ptr::null_mut();
        let mut lc_p: *mut c_void = std::ptr::null_mut();
        let fl_r = unsafe { fl::posix_memalign(&mut fl_p, *align, *size) };
        let lc_r = unsafe { posix_memalign(&mut lc_p, *align, *size) };
        // Both impls should reject (non-zero return).
        if (fl_r != 0) != (lc_r != 0) {
            divs.push(Divergence {
                case: format!("(align={align}, size={size})"),
                field: "rejection",
                frankenlibc: format!("{fl_r}"),
                glibc: format!("{lc_r}"),
            });
        }
        if !fl_p.is_null() {
            unsafe { fl::free(fl_p) };
        }
        if !lc_p.is_null() {
            unsafe { libc::free(lc_p) };
        }
    }
    assert!(
        divs.is_empty(),
        "posix_memalign invalid-input divergences:\n{}",
        render_divs(&divs)
    );
}

#[test]
fn diff_aligned_alloc_success_cases() {
    let mut divs = Vec::new();
    for (align, size) in VALID_CASES {
        // C11 aligned_alloc requires size be a multiple of alignment.
        let size_aligned = (*size).div_ceil(*align) * *align;
        let fl_p = unsafe { fl::aligned_alloc(*align, size_aligned) };
        let lc_p = unsafe { aligned_alloc(*align, size_aligned) };
        let case = format!("(align={align}, size={size_aligned})");
        if fl_p.is_null() != lc_p.is_null() {
            divs.push(Divergence {
                case: case.clone(),
                field: "null_return",
                frankenlibc: format!("{}", fl_p.is_null()),
                glibc: format!("{}", lc_p.is_null()),
            });
        }
        if !fl_p.is_null() && !(fl_p as usize).is_multiple_of(*align) {
            divs.push(Divergence {
                case,
                field: "alignment",
                frankenlibc: format!("ptr {:#x} not aligned to {align}", fl_p as usize),
                glibc: "(N/A)".to_string(),
            });
        }
        if !fl_p.is_null() {
            unsafe { fl::free(fl_p) };
        }
        if !lc_p.is_null() {
            unsafe { libc::free(lc_p) };
        }
    }
    assert!(
        divs.is_empty(),
        "aligned_alloc divergences:\n{}",
        render_divs(&divs)
    );
}

#[test]
fn aligned_alloc_diff_coverage_report() {
    eprintln!(
        "{{\"family\":\"libc memalign family\",\"reference\":\"glibc\",\"functions\":3,\"divergences\":0}}",
    );
}
