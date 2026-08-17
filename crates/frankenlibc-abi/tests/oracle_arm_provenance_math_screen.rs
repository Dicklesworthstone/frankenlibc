#![cfg(all(target_os = "linux", target_arch = "x86_64"))]
#![allow(unsafe_code)] // dladdr provenance probe over live oracle arms

//! SCREEN, not a fix: which link-time "glibc" arms in the math differentials
//! actually reach `libc.so.6`, and which are captured by a local provider?
//!
//! bd-v0388t measured 387 gates / 1546 symbols where the arm a differential
//! calls "glibc" names a symbol FrankenLibC also exports. That is the AT-RISK
//! population, not the defect count, and the difference matters for how the
//! bead gets worked: converting 387 gates by hand is weeks, converting the ones
//! that are actually hollow is an afternoon.
//!
//! ## Why the population is not the defect count
//!
//! fl's exports are debug-gated — every one carries
//! `#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]`, 608 of them in
//! `glibc_internal_abi.rs` alone — so in the debug profile these tests run in,
//! fl's symbols are NOT exported under their C names and a link-time reference
//! cannot bind to fl. The mechanism that actually bit `conformance_diff_fma` was
//! different and is recorded on the bead: it collapsed in a PLAIN DEBUG run
//! because **`compiler_builtins` supplies an `fma`**, with five sibling symbols
//! in the same binary resolving correctly to `libc.so`. A non-fl local provider
//! can capture a symbol regardless of profile.
//!
//! So the question this file answers is narrow and empirical: across the math
//! surface — the family `compiler_builtins` and Rust's own runtime are most
//! likely to provide — how many arms are captured, and by what?
//!
//! ## Why `dladdr` and not an address comparison
//!
//! A link-time reference goes through a PLT stub, so comparing the reference's
//! address against fl's function address can differ while both still reach the
//! same code. `dladdr` reports the object a code address actually lives in,
//! which is the question. A captured arm reports the test binary; a real one
//! reports `libc.so.6` or `libm.so.6`.
//!
//! This file asserts nothing about which symbols must be clean — it PRINTS the
//! census and fails only if it cannot run at all. Turning its findings into
//! per-gate `dlsym` conversions is the fix, and belongs on the gates.

use std::ffi::{CStr, c_void};

macro_rules! declare_more_arms {
    ($($name:ident),* $(,)?) => {
        unsafe extern "C" {
            $(fn $name() -> *const c_void;)*
        }
        /// `(symbol name, code address as the linker resolved it)`.
        fn other_arm_addresses() -> Vec<(&'static str, *const c_void)> {
            vec![
                $((stringify!($name), $name as *const c_void)),*
            ]
        }
    };
}

macro_rules! declare_math_arms {
    ($($name:ident),* $(,)?) => {
        unsafe extern "C" {
            $(fn $name(x: f64) -> f64;)*
        }
        /// `(symbol name, code address as the linker resolved it)`.
        fn math_arm_addresses() -> Vec<(&'static str, *const c_void)> {
            vec![
                $((stringify!($name), $name as *const c_void)),*
            ]
        }
    };
}

// The one-argument-double subset of the arms declared by
// `conformance_diff_math.rs` and `conformance_diff_fp_exceptions.rs`. The
// signature is deliberately uniform: this file never CALLS these, it only takes
// their addresses, so the declared prototype does not have to match the real one
// for `dladdr` to answer correctly. Nothing here is invoked.
declare_math_arms!(
    acos, acosh, asin, atanh, ceil, cos, cosh, erfc, exp, exp2, exp10, expm1, fabs, floor, ilogb,
    lgamma, log, log10, log1p, log2, logb, sin, sinh, sqrt, tan, tanh, tgamma, y0, y1,
);

// `inet_net_ntop` / `inet_net_pton` are deliberately ABSENT: they live in
// `libresolv.so.2`, which this binary does not link, so declaring them here is
// an undefined symbol at link time rather than a census entry. That is a fact
// about this screen's link line, NOT about `conformance_diff_inet_net.rs` --
// that gate links them successfully and needs its own look.
//
// The NON-math surface, taken verbatim from the extern blocks of the twelve
// at-risk gates that assert on errno -- the order bd-v0388t asks for, because an
// errno-only divergence hides rather than crashes. Same rule as above: these are
// never called, only addressed, so one uniform prototype is enough for `dladdr`.
declare_more_arms!(
    __errno_location,
    __sched_get_priority_max,
    __sched_get_priority_min,
    __sched_getparam,
    __sched_getscheduler,
    __sched_setscheduler,
    __sched_yield,
    a64l,
    abs,
    alphasort,
    alphasort64,
    canonicalize_file_name,
    dirfd,
    div,
    ecvt,
    ecvt_r,
    fcvt,
    fcvt_r,
    fdopendir,
    ffs,
    ffsl,
    ffsll,
    ftw,
    ftw64,
    gcvt,
    getpriority,
    grantpt,
    hcreate,
    hcreate_r,
    hdestroy,
    hdestroy_r,
    hsearch,
    hsearch_r,
    imaxabs,
    isatty,
    l64a,
    labs,
    ldiv,
    lfind,
    llabs,
    lldiv,
    lsearch,
    nftw,
    nftw64,
    nice,
    pkey_alloc,
    pkey_free,
    pkey_get,
    pkey_mprotect,
    pkey_set,
    posix_openpt,
    ptsname_r,
    readdir64,
    readdir_r,
    realpath,
    scandir,
    scandir64,
    sched_getcpu,
    setpriority,
    sockatmark,
    ttyname,
    ttyname_r,
    ttyslot,
    unlockpt,
    versionsort
);

/// Which object does `addr` live in?
fn owning_object(addr: *const c_void) -> String {
    let mut info: libc::Dl_info = unsafe { std::mem::zeroed() };
    // SAFETY: `addr` is a code address taken from a live function item and
    // `info` is a live local.
    if unsafe { libc::dladdr(addr, &mut info) } == 0 || info.dli_fname.is_null() {
        return "<dladdr failed>".to_owned();
    }
    // SAFETY: `dli_fname` is a NUL-terminated path owned by the loader.
    let path = unsafe { CStr::from_ptr(info.dli_fname) }.to_string_lossy();
    path.rsplit('/').next().unwrap_or(&path).to_owned()
}

/// Census the math oracle arms and print where each one actually resolves.
#[test]
fn math_oracle_arms_report_their_owning_object() {
    let mut arms = math_arm_addresses();
    arms.extend(other_arm_addresses());
    assert!(!arms.is_empty(), "no arms declared; the macro did not expand");

    let mut captured = Vec::new();
    let mut clean = Vec::new();
    for (name, addr) in &arms {
        let object = owning_object(*addr);
        // A real oracle lives in a shared library the loader mapped. Anything
        // resolving into this test binary is a local provider capturing the
        // symbol -- the `conformance_diff_fma` failure mode.
        if object.starts_with("lib") && object.contains(".so") {
            clean.push((*name, object));
        } else {
            captured.push((*name, object));
        }
    }

    println!("ORACLE_ARM_CENSUS total={} clean={} captured={}", arms.len(), clean.len(), captured.len());
    for (name, object) in &clean {
        println!("  CLEAN    {name:12} -> {object}");
    }
    for (name, object) in &captured {
        println!("  CAPTURED {name:12} -> {object}");
    }

    // Deliberately not an assertion on the capture count. This file is a
    // measurement instrument for bd-v0388t: a threshold here would have to be
    // guessed, and a guessed threshold that passes is exactly the kind of gate
    // that proves nothing. What it DOES assert is that the probe ran and that
    // dladdr answered for every arm, so a silent zero cannot be read as "clean".
    let unresolved: Vec<_> = arms
        .iter()
        .map(|(name, addr)| (*name, owning_object(*addr)))
        .filter(|(_, object)| object == "<dladdr failed>")
        .collect();
    assert!(
        unresolved.is_empty(),
        "dladdr could not place these arms, so the census is incomplete: {unresolved:?}"
    );
}
