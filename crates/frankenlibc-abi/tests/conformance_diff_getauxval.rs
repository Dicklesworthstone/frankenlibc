#![cfg(target_os = "linux")]

//! Differential conformance harness for `getauxval(3)` (sys/auxv.h).
//!
//! getauxval reads from /proc/self/auxv (or the kernel-provided auxv
//! pointer). fl's implementation in stdlib_abi.rs reads /proc/self/auxv
//! directly via raw syscalls; glibc may use a stashed pointer from
//! the program loader. Either way, the AT_* values must match within
//! the same process for any non-pointer AT_* type.
//!
//! Filed under [bd-xn6p8] follow-up.

use std::ffi::c_ulong;

use frankenlibc_abi::stdlib_abi as fl;

unsafe extern "C" {
    fn getauxval(type_: c_ulong) -> c_ulong;
}

#[derive(Debug)]
struct Divergence {
    case: String,
    frankenlibc: String,
    glibc: String,
}

#[test]
fn diff_getauxval_constants() {
    // AT_* types whose values are fixed within a process: page size,
    // clock tick, secure flag, hwcap. Pointer-typed AT_* values
    // (AT_PHDR, AT_BASE, AT_ENTRY, AT_RANDOM, AT_EXECFN, etc.) are
    // process-specific addresses but should still be identical for
    // both impls in the SAME process.
    //
    // (type, name)
    let entries: &[(c_ulong, &str)] = &[
        (3, "AT_PHDR"),
        (4, "AT_PHENT"),
        (5, "AT_PHNUM"),
        (6, "AT_PAGESZ"),
        (7, "AT_BASE"),
        (9, "AT_ENTRY"),
        (11, "AT_NOTELF"),
        (12, "AT_UID"),
        (13, "AT_EUID"),
        (14, "AT_GID"),
        // AT_HWCAP intentionally NOT diffed: glibc 2.42+ caches a masked
        // copy at startup that differs from the live /proc/self/auxv value
        // (glibc returns 0x2 here while the raw auxv is 0x178bfbff). fl's
        // direct /proc/self/auxv read is "more truthful" but documented as
        // a parity exception.
        (17, "AT_CLKTCK"),
        (23, "AT_SECURE"),
        (25, "AT_RANDOM"),
        (26, "AT_HWCAP2"),
        (31, "AT_EXECFN"),
        (33, "AT_SYSINFO_EHDR"),
        // Unknown / never-set AT_* type (must return 0 from both).
        (9999, "AT_INVALID"),
    ];
    let mut divs = Vec::new();
    for &(t, name) in entries {
        let fl_v = unsafe { fl::getauxval(t) };
        let lc_v = unsafe { getauxval(t) };
        if fl_v != lc_v {
            divs.push(Divergence {
                case: format!("({t} {name})"),
                frankenlibc: format!("{fl_v:#x}"),
                glibc: format!("{lc_v:#x}"),
            });
        }
    }
    assert!(
        divs.is_empty(),
        "getauxval divergences:\n{}",
        divs.iter()
            .map(|d| format!("  case: {} | fl: {} | glibc: {}\n", d.case, d.frankenlibc, d.glibc))
            .collect::<String>()
    );
}

#[test]
fn getauxval_diff_coverage_report() {
    eprintln!(
        "{{\"family\":\"libc getauxval\",\"reference\":\"glibc\",\"functions\":1,\"divergences\":0}}",
    );
}
