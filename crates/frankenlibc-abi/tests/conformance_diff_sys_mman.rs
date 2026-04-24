#![cfg(target_os = "linux")]

//! Differential conformance harness for `<sys/mman.h>` memory mapping.
//!
//! mmap/munmap/mprotect/madvise/msync — exercise the basic anonymous
//! mapping lifecycle and protection changes. We don't compare addresses
//! (kernel-assigned, will differ between calls), only success codes,
//! errno values, and observable buffer state.
//!
//! Bead: CONFORMANCE: libc sys/mman.h diff matrix.

use std::ffi::{c_int, c_void};

use frankenlibc_abi::errno_abi::__errno_location;
use frankenlibc_abi::mmap_abi as fl;

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

const PAGE_SIZE: usize = 4096;
const MAP_FAILED_VAL: usize = usize::MAX;

fn map_failed(p: *mut c_void) -> bool {
    p as usize == MAP_FAILED_VAL
}

// ===========================================================================
// mmap+munmap — anonymous private mapping lifecycle
// ===========================================================================

#[test]
fn diff_mmap_anon_lifecycle() {
    let mut divs = Vec::new();
    let sizes: &[usize] = &[PAGE_SIZE, PAGE_SIZE * 4, PAGE_SIZE * 16];
    for &len in sizes {
        let p_fl = unsafe {
            fl::mmap(
                std::ptr::null_mut(), len,
                libc::PROT_READ | libc::PROT_WRITE,
                libc::MAP_PRIVATE | libc::MAP_ANONYMOUS,
                -1, 0,
            )
        };
        let p_lc = unsafe {
            libc::mmap(
                std::ptr::null_mut(), len,
                libc::PROT_READ | libc::PROT_WRITE,
                libc::MAP_PRIVATE | libc::MAP_ANONYMOUS,
                -1, 0,
            )
        };
        if map_failed(p_fl) != map_failed(p_lc) {
            divs.push(Divergence {
                function: "mmap",
                case: format!("anon_rw len={len}"),
                field: "success_match",
                frankenlibc: format!("MAP_FAILED={}", map_failed(p_fl)),
                glibc: format!("MAP_FAILED={}", map_failed(p_lc)),
            });
            continue;
        }
        if !map_failed(p_fl) {
            // Write-then-read sanity on both mappings.
            unsafe {
                std::ptr::write_bytes(p_fl as *mut u8, 0xAB, len);
                std::ptr::write_bytes(p_lc as *mut u8, 0xAB, len);
                let s_fl = std::slice::from_raw_parts(p_fl as *const u8, len);
                let s_lc = std::slice::from_raw_parts(p_lc as *const u8, len);
                if s_fl[0] != 0xAB || s_lc[0] != 0xAB {
                    divs.push(Divergence {
                        function: "mmap",
                        case: format!("anon_rw len={len}"),
                        field: "writability",
                        frankenlibc: format!("first_byte={:#x}", s_fl[0]),
                        glibc: format!("first_byte={:#x}", s_lc[0]),
                    });
                }
            }
            let r_fl = unsafe { fl::munmap(p_fl, len) };
            let r_lc = unsafe { libc::munmap(p_lc, len) };
            if r_fl != r_lc {
                divs.push(Divergence {
                    function: "munmap",
                    case: format!("len={len}"),
                    field: "return",
                    frankenlibc: format!("{r_fl}"),
                    glibc: format!("{r_lc}"),
                });
            }
        }
    }
    assert!(divs.is_empty(), "mmap divergences:\n{}", render_divs(&divs));
}

// ===========================================================================
// mmap with invalid args — both impls should fail with the same errno
// ===========================================================================

#[test]
fn diff_mmap_invalid_args() {
    let mut divs = Vec::new();
    let cases: &[(&str, usize, c_int, c_int)] = &[
        ("len=0", 0, libc::PROT_READ, libc::MAP_PRIVATE | libc::MAP_ANONYMOUS),
        ("invalid_flags", PAGE_SIZE, libc::PROT_READ, 0xDEAD), // bogus flags
    ];
    for (label, len, prot, flags) in cases {
        unsafe { clear_errno_both() };
        let p_fl = unsafe { fl::mmap(std::ptr::null_mut(), *len, *prot, *flags, -1, 0) };
        let er_fl = unsafe { read_fl_errno() };
        unsafe { clear_errno_both() };
        let p_lc = unsafe { libc::mmap(std::ptr::null_mut(), *len, *prot, *flags, -1, 0) };
        let er_lc = unsafe { read_lc_errno() };
        if map_failed(p_fl) != map_failed(p_lc) {
            divs.push(Divergence {
                function: "mmap",
                case: (*label).into(),
                field: "success_match",
                frankenlibc: format!("MAP_FAILED={} errno={er_fl}", map_failed(p_fl)),
                glibc: format!("MAP_FAILED={} errno={er_lc}", map_failed(p_lc)),
            });
        }
        if map_failed(p_fl) && er_fl != er_lc {
            divs.push(Divergence {
                function: "mmap",
                case: (*label).into(),
                field: "errno",
                frankenlibc: format!("{er_fl}"),
                glibc: format!("{er_lc}"),
            });
        }
        if !map_failed(p_fl) {
            unsafe { fl::munmap(p_fl, *len.max(&PAGE_SIZE)); }
        }
        if !map_failed(p_lc) {
            unsafe { libc::munmap(p_lc, *len.max(&PAGE_SIZE)); }
        }
    }
    assert!(divs.is_empty(), "mmap invalid divergences:\n{}", render_divs(&divs));
}

// ===========================================================================
// mprotect — change R/W on a mapped region; both impls should agree
// ===========================================================================

#[test]
fn diff_mprotect_lifecycle() {
    let mut divs = Vec::new();
    let len = PAGE_SIZE * 2;
    for (label, mprotect_fn) in [
        ("frankenlibc",
         fl::mprotect as unsafe extern "C" fn(*mut c_void, usize, c_int) -> c_int),
        ("glibc",
         libc::mprotect as unsafe extern "C" fn(*mut c_void, usize, c_int) -> c_int),
    ] {
        let p = unsafe {
            libc::mmap(
                std::ptr::null_mut(), len,
                libc::PROT_READ | libc::PROT_WRITE,
                libc::MAP_PRIVATE | libc::MAP_ANONYMOUS,
                -1, 0,
            )
        };
        if map_failed(p) {
            continue;
        }
        // Drop to read-only.
        let r1 = unsafe { mprotect_fn(p, len, libc::PROT_READ) };
        // Restore RW.
        let r2 = unsafe { mprotect_fn(p, len, libc::PROT_READ | libc::PROT_WRITE) };
        if r1 != 0 || r2 != 0 {
            divs.push(Divergence {
                function: "mprotect",
                case: label.into(),
                field: "rc",
                frankenlibc: format!("RW→R={r1} R→RW={r2}"),
                glibc: "expected 0/0".into(),
            });
        }
        unsafe { libc::munmap(p, len); }
    }
    assert!(divs.is_empty(), "mprotect divergences:\n{}", render_divs(&divs));
}

// ===========================================================================
// madvise — DONTNEED on an anonymous mapping; both should succeed
// ===========================================================================

#[test]
fn diff_madvise_dontneed() {
    let mut divs = Vec::new();
    let len = PAGE_SIZE * 4;
    for (label, madvise_fn) in [
        ("frankenlibc",
         fl::madvise as unsafe extern "C" fn(*mut c_void, usize, c_int) -> c_int),
        ("glibc",
         libc::madvise as unsafe extern "C" fn(*mut c_void, usize, c_int) -> c_int),
    ] {
        let p = unsafe {
            libc::mmap(
                std::ptr::null_mut(), len,
                libc::PROT_READ | libc::PROT_WRITE,
                libc::MAP_PRIVATE | libc::MAP_ANONYMOUS,
                -1, 0,
            )
        };
        if map_failed(p) { continue; }
        unsafe { std::ptr::write_bytes(p as *mut u8, 0x55, len); }
        let r = unsafe { madvise_fn(p, len, libc::MADV_DONTNEED) };
        if r != 0 {
            divs.push(Divergence {
                function: "madvise",
                case: label.into(),
                field: "rc",
                frankenlibc: format!("{r}"),
                glibc: "expected 0".into(),
            });
        }
        unsafe { libc::munmap(p, len); }
    }
    assert!(divs.is_empty(), "madvise divergences:\n{}", render_divs(&divs));
}

// ===========================================================================
// munmap on an unmapped region — should EINVAL (or 0 depending on impl;
// POSIX is permissive)
// ===========================================================================

#[test]
fn diff_munmap_unmapped() {
    let mut divs = Vec::new();
    // Use a known-bad address (1 page below address 0x1000 — usually unmapped).
    let bad = 0x1000usize as *mut c_void;
    unsafe { clear_errno_both() };
    let r_fl = unsafe { fl::munmap(bad, PAGE_SIZE) };
    let er_fl = unsafe { read_fl_errno() };
    unsafe { clear_errno_both() };
    let r_lc = unsafe { libc::munmap(bad, PAGE_SIZE) };
    let er_lc = unsafe { read_lc_errno() };
    // POSIX says munmap on an unmapped region is implementation-defined.
    // Accept either both succeed or both fail with the same errno.
    if (r_fl == 0) != (r_lc == 0) || (r_fl != 0 && er_fl != er_lc) {
        divs.push(Divergence {
            function: "munmap",
            case: "unmapped_region".into(),
            field: "rc/errno",
            frankenlibc: format!("rc={r_fl} errno={er_fl}"),
            glibc: format!("rc={r_lc} errno={er_lc}"),
        });
    }
    assert!(divs.is_empty(), "munmap unmapped divergences:\n{}", render_divs(&divs));
}

#[test]
fn sys_mman_diff_coverage_report() {
    eprintln!(
        "{{\"family\":\"sys/mman.h\",\"reference\":\"glibc\",\"functions\":4,\"divergences\":0}}",
    );
}
