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
//! This file PRINTS the census and PINS the captured set. The pin arrived only
//! after the set was measured and found stable across four extensions of the
//! screen; the per-gate `dlsym` conversions are the fix, and belong on the gates.

use std::ffi::{CStr, c_void};

macro_rules! declare_mem_arms {
    ($($name:ident),* $(,)?) => {
        unsafe extern "C" {
            $(fn $name(a: *mut c_void, b: *const c_void, n: usize) -> *mut c_void;)*
        }
        /// `(symbol name, code address as the linker resolved it)`.
        fn mem_arm_addresses() -> Vec<(&'static str, *const c_void)> {
            vec![
                $((stringify!($name), $name as *const c_void)),*
            ]
        }
    };
}

macro_rules! declare_binary_arms {
    ($($name:ident),* $(,)?) => {
        unsafe extern "C" {
            $(fn $name(x: f64, y: f64) -> f64;)*
        }
        /// `(symbol name, code address as the linker resolved it)`.
        fn binary_arm_addresses() -> Vec<(&'static str, *const c_void)> {
            vec![
                $((stringify!($name), $name as *const c_void)),*
            ]
        }
    };
}

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
/// The measured set of oracle arms a local provider captures in this binary.
///
/// ONE definition, used by both tests here: the ratchet that pins the measured
/// set, and the check that no differential binds one of these at link time.
/// They were briefly two literal copies and that is a silent-drift hazard --
/// updating the ratchet after a new measurement while leaving the other list
/// stale would quietly stop protecting the gates.
///
/// Every entry is MEASURED by `math_oracle_arms_report_their_owning_object`, not
/// predicted. Do not add one by reasoning about what an operation lowers to:
/// `nearbyint` is a roundsd lowering and is CLEAN, `cbrt` is not one and is
/// CAPTURED, and `lrint` returns an integer from the same operation as the
/// captured `rint` and is CLEAN.
const KNOWN_CAPTURED: &[&str] = &[
    "cbrt", "cbrtf", "ceil", "copysign", "fabs", "fdim", "floor", "fmax", "fmin", "fmod", "rint",
    "rintf", "round", "roundf", "sqrt", "trunc", "truncf",
];

declare_math_arms!(
    acos, acosh, asin, atanh, ceil, cos, cosh, erfc, exp, exp2, exp10, expm1, fabs, floor, ilogb,
    lgamma, log, log10, log1p, log2, logb, sin, sinh, sqrt, tan, tanh, tgamma, y0, y1,
    // Added because the captured set is exactly what LLVM lowers to a single
    // instruction and `compiler_builtins` defines non-weak -- roundsd for
    // ceil/floor, andpd for fabs, sqrtsd for sqrt. `round`, `trunc`, `rint` and
    // `nearbyint` are ALSO roundsd lowerings and were not in the census, so the
    // screen could not have seen them captured. `cbrt`, `atan`, `asinh`, `erf`,
    // `j0` and `j1` are ordinary libm calls added to widen the clean side, so a
    // capture result is not read off a list stacked with likely positives.
    round, trunc, rint, nearbyint, cbrt, atan, asinh, erf, j0, j1,
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
    // The f32 and integer-returning members of the round-to-integer family.
    // These belong here rather than in a typed macro because arms are never
    // CALLED, only addressed for `dladdr`, so one uniform prototype suffices --
    // the same reasoning this block already uses for the errno surface.
    //
    // Added because three differentials (conformance_diff_fe_rounding,
    // conformance_diff_round_mode, conformance_diff_math_exact) declare these
    // alongside `rint`, which IS captured. Converting `rint` while leaving its
    // siblings unmeasured would fix the symbol I happened to census and leave
    // the rest hollow for exactly the same reason.
    cbrtf,
    llrint,
    llrintf,
    lrint,
    lrintf,
    // The remaining arms of conformance_diff_math_exact's extern block. Censused
    // as a set rather than one at a time, because that gate declares 33 symbols
    // and converting only the ones already measured would leave the rest hollow
    // for the same reason -- which is the mistake this bead exists to stop.
    frexp,
    frexpf,
    ilogbf,
    ldexp,
    ldexpf,
    llround,
    logbf,
    lround,
    lroundf,
    modf,
    modff,
    nextafter,
    nextafterf,
    remainder,
    remainderf,
    remquo,
    scalbn,
    scalbnf,
    significand,
    significandf,
    nearbyintf,
    rintf,
    roundf,
    truncf,
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

// TWO-ARGUMENT math, added after the one-arg census came back clean and a RED
// in `conformance_diff_math` turned out to point the other way. That gate
// reports `fmaxf(+0,-0)` as fl=-0.0 vs "glibc"=+0.0 -- but a live ctypes probe
// of libm.so.6 (glibc 2.42) returns **-0.0**, i.e. the SECOND operand, which is
// what fl returns. The gate's oracle therefore disagrees with real glibc, so the
// gate's oracle is not glibc. That is a captured arm producing a FALSE RED
// rather than the usual false green, and it is far more dangerous: acting on it
// means "fixing" fl to match a local provider and breaking real parity.
declare_binary_arms!(copysign, fdim, fmax, fmin, fmod, pow, atan2);

// The mem*/str* family. `compiler_builtins` supplies memcpy/memset/memmove/
// memcmp, and these are the symbols the fourth disguise reaches through
// `libc::<sym>`. Same rule as every other arm here: never called, only
// addressed, so one uniform prototype suffices for `dladdr`.
declare_mem_arms!(
    memcpy, memmove, memset, memcmp, memchr, strlen, strcmp, strncmp, strcpy, strchr, bcmp,
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
    arms.extend(binary_arm_addresses());
    arms.extend(mem_arm_addresses());
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

    // dladdr must have placed every arm. A silent zero must never be readable
    // as "clean", which is the failure mode this whole bead is about.
    let unresolved: Vec<_> = arms
        .iter()
        .map(|(name, addr)| (*name, owning_object(*addr)))
        .filter(|(_, object)| object == "<dladdr failed>")
        .collect();
    assert!(
        unresolved.is_empty(),
        "dladdr could not place these arms, so the census is incomplete: {unresolved:?}"
    );

    // THE RATCHET. Earlier revisions of this file asserted nothing about the
    // capture count, because a GUESSED threshold that passes is exactly the
    // hollow gate bd-v0388t exists to stamp out. That held while the set was
    // unknown. It is now measured and stable across four extensions of this
    // screen -- 29, 94, 101 and 112 arms, the same nine every time -- so this
    // pins a measurement rather than a guess.
    //
    // The pin is the exact SET, not the count: a new capture displacing an old
    // one would leave the count at nine while changing what is hollow.
    //
    // If this fires, a symbol changed provider. Do NOT widen the list to make it
    // pass. Find the gates that declare the new symbol and give them a real
    // oracle -- `dlsym_oracle::host_fn` -- as conformance_diff_math,
    // conformance_diff_round_special, conformance_diff_copysign_fdim_special and
    // conformance_diff_fp_exceptions already do.
    //
    // THE "LLVM LOWERS IT TO roundsd" EXPLANATION IS INCOMPLETE. It was written
    // when the census covered 112 symbols and held for all nine then known. The
    // census now covers 122 and the extra ten refute it in both directions:
    //
    //   round, trunc, rint  -- roundsd lowerings, and CAPTURED, as it predicts
    //   nearbyint           -- also a roundsd lowering, and CLEAN
    //   cbrt                -- not a roundsd lowering at all, and CAPTURED
    //
    // So the lowering is not the discriminator; what `compiler_builtins` happens
    // to define NON-weak is. Do not extend this list by reasoning from the
    // instruction a symbol lowers to -- add the symbol to the census and measure
    // it, which is how the four new entries below were found.
    //
    // memcpy/memset/memmove/memcmp are declared weak there and correctly lose to
    // libc.so.6 -- measured, not assumed.
    //
    // The f32 round-family members behave like their f64 counterparts (rintf,
    // roundf, truncf captured) while the INTEGER-returning ones do not
    // (lrint, llrint clean), and neither nearbyint nor nearbyintf is captured.
    // Another reason not to predict from the lowering: the same operation is
    // captured at one return type and clean at another.

    let mut captured_names: Vec<&str> = captured.iter().map(|(name, _)| *name).collect();
    captured_names.sort_unstable();
    assert_eq!(
        captured_names, KNOWN_CAPTURED,
        "the set of locally-captured oracle arms changed. New captures are gates \
         that silently stopped testing glibc; disappearances mean an arm that was \
         converted no longer needs to be. Either way, investigate before editing \
         this list (bd-v0388t)."
    );
}

/// Every differential that DECLARES a captured symbol at link time must also
/// resolve it through `dlsym`, or its "glibc" arm is a local provider.
///
/// The screen above measures WHICH symbols are captured. This one closes the
/// loop by checking that no gate binds one of them at link time -- which is the
/// actual defect bd-v0388t is about, and which was previously found by hand.
/// Three gates were converted that way (conformance_diff_fe_rounding,
/// conformance_diff_round_mode, conformance_diff_math_exact) after censusing
/// their siblings one set at a time; this makes the next one fail loudly instead
/// of waiting for someone to think of looking.
///
/// The check is deliberately conservative: a file that mentions `dlsym` anywhere
/// is trusted, because pinpointing WHICH arm a shim resolves would mean parsing
/// Rust, and a false failure here would train people to edit the list rather
/// than the gate.
#[test]
fn no_differential_binds_a_captured_symbol_at_link_time() {
    let dir = std::path::Path::new("tests");
    let entries = std::fs::read_dir(dir).expect("read tests/ -- test CWD is the package root");
    let mut offenders: Vec<String> = Vec::new();
    let mut scanned = 0usize;

    for entry in entries.flatten() {
        let path = entry.path();
        let name = path.file_name().and_then(|n| n.to_str()).unwrap_or_default();
        if !name.starts_with("conformance_diff_") || !name.ends_with(".rs") {
            continue;
        }
        let Ok(text) = std::fs::read_to_string(&path) else {
            continue;
        };
        scanned += 1;
        if text.contains("dlsym") {
            continue;
        }
        // Symbols declared inside an `extern "C" { ... }` block.
        let mut inside = false;
        for line in text.lines() {
            let trimmed = line.trim();
            if trimmed.starts_with("unsafe extern \"C\" {") || trimmed.starts_with("extern \"C\" {")
            {
                inside = true;
                continue;
            }
            if inside {
                if trimmed.starts_with('}') {
                    inside = false;
                    continue;
                }
                let declared = trimmed
                    .strip_prefix("fn ")
                    .or_else(|| trimmed.strip_prefix("pub fn "))
                    .and_then(|rest| rest.split(['(', '<', ' ']).next());
                if let Some(symbol) = declared
                    && KNOWN_CAPTURED.contains(&symbol)
                {
                    offenders.push(format!("{name} declares captured `{symbol}`"));
                }
            }
        }
    }

    assert!(scanned > 100, "only {scanned} differentials scanned; the glob is wrong");
    assert!(
        offenders.is_empty(),
        "these gates bind a locally-captured symbol at link time, so their \
         \"glibc\" arm is not glibc. Give the arm dlsym_oracle::host_fn, as \
         conformance_diff_math_exact and conformance_diff_round_mode do. Do NOT \
         remove the symbol from CAPTURED to silence this (bd-v0388t):\n{}",
        offenders.join("\n")
    );
}
