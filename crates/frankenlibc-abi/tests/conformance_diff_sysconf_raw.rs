#![cfg(target_os = "linux")]
#![allow(unsafe_code)] // live host-glibc sysconf oracle

//! Raw-integer-code differential gate for sysconf (bd-7qvvom). The existing
//! sysconf gates iterate NAMED libc::_SC_* constants, but the libc crate omits
//! some _SC_ codes — the same blind spot that once hid a wrong nl_langinfo
//! value. This walks the raw integer codes 0..=MAX_PROBED_CODE and asserts, vs
//! host glibc:
//!   * availability parity — fl answers a selector exactly when glibc does,
//!     keyed on `!= -1` (catches keys fl forgets to implement);
//!   * exact value parity for every code both support, except the handful of
//!     genuinely time-varying counters (free/online pages & CPUs);
//!   * errno parity wherever glibc returns -1, which is the only way to tell an
//!     INDETERMINATE limit (-1, errno untouched) from an UNKNOWN selector (-1 +
//!     EINVAL).
//! No mocks.
//!
//! The last two bullets were added after this gate passed over a build in which
//! 27 selectors reported the wrong one of those two answers, and _SC_MINSIGSTKSZ
//! was unimplemented. Both were invisible here: the range stopped at 130, and
//! comparing only return values cannot separate -1 from -1. When extending this
//! gate, prefer a NEW dimension over a wider range -- the range was the cheap
//! half.

use std::ffi::c_int;

unsafe extern "C" {
    fn sysconf(name: c_int) -> std::ffi::c_long;
}

// Codes whose value legitimately fluctuates between two back-to-back reads, so
// only availability (not the exact value) is compared:
//   _SC_AVPHYS_PAGES = 86, _SC_NPROCESSORS_ONLN = 84.
const DYNAMIC: &[c_int] = &[84, 86];

/// Upper bound of the probed range.
///
/// This gate originally stopped at 130, which made it structurally unable to
/// see _SC_MINSIGSTKSZ (249) -- a selector glibc answers and fl did not
/// implement. Codes in the gap that neither side knows agree trivially (both
/// -1 + EINVAL), so widening only adds coverage.
const MAX_PROBED_CODE: c_int = 260;

/// Seeded before every call so "errno untouched" is distinguishable from
/// "errno set to 0".
const SENTINEL_ERRNO: c_int = 4242;

/// Selectors this gate deliberately does NOT assert. It is EMPTY, and that is
/// the point: fl now answers every selector host glibc answers over the probed
/// range.
///
/// It exists rather than being deleted so that a future deferral has to be
/// written down here, next to the sweep that would otherwise have caught it.
/// The two entries it used to hold — the CPU cache band 185..=199 and
/// _SC_SIGSTKSZ (250) — were both closed by reading the incumbent instead of
/// guessing: the cache rows from the kernel's own topology, and 250 from the
/// arithmetic in libc.so.6's __sysconf.
const KNOWN_UNIMPLEMENTED: &[c_int] = &[];

// glibc selectors intentionally represented as raw numbers in the ABI match:
// the Rust libc crate does not publish this complete set on every target.
const RESTORED_GLIBC_CODES: &[c_int] = &[
    13, 20, 45, 77, 78, 79, 80, 81, 82, 88, 89, 90, 91, 93, 94, 95, 96, 98, 99, 100, 101, 102, 104,
    106, 107, 108, 109, 110, 111, 113, 115, 116, 118, 119, 120, 121, 122, 123, 124, 127, 129, 130,
];

#[test]
fn sysconf_raw_codes_match_glibc() {
    let mut value_mismatches = Vec::new();
    let mut avail_mismatches = Vec::new();
    let mut errno_mismatches = Vec::new();
    let mut declined = Vec::new();
    for code in 0..=MAX_PROBED_CODE {
        if KNOWN_UNIMPLEMENTED.contains(&code) {
            declined.push(code);
            continue;
        }
        // errno is compared only where glibc returns -1, because that is where
        // the ABI contract actually splits: glibc reports an INDETERMINATE
        // limit as -1 with errno untouched, and an UNKNOWN selector as -1 with
        // EINVAL. A gate that compares only the return value cannot tell those
        // apart -- both sides read -1 -- which is exactly how 27 such
        // divergences stayed invisible here while this test passed.
        let (g, g_errno) = unsafe {
            *libc::__errno_location() = SENTINEL_ERRNO;
            let r = sysconf(code);
            (r, *libc::__errno_location())
        };
        let (f, f_errno) = unsafe {
            *libc::__errno_location() = SENTINEL_ERRNO;
            let r = frankenlibc_abi::unistd_abi::sysconf(code);
            (r, *libc::__errno_location())
        };
        // Availability keys on -1, NOT on `>= 0`: the signed-minimum selectors
        // (_SC_CHAR_MIN -128, _SC_INT_MIN, _SC_SCHAR_MIN, _SC_SHRT_MIN) return
        // legitimate NEGATIVE values. Under a `>= 0` model those count as
        // "unavailable" on both sides and their values are never compared, so
        // fl could answer -1 for CHAR_MIN and still pass.
        let g_available = g != -1;
        let f_available = f != -1;
        if g_available != f_available {
            avail_mismatches.push(format!("code {code}: fl={f} glibc={g}"));
            continue;
        }
        if !g_available && g_errno != f_errno {
            errno_mismatches.push(format!(
                "code {code}: both returned -1 but errno differs: fl={f_errno} glibc={g_errno} \
                 (sentinel {SENTINEL_ERRNO} means untouched)"
            ));
        }
        if g_available && !DYNAMIC.contains(&code) && f != g {
            value_mismatches.push(format!("code {code}: fl={f} glibc={g}"));
        }
    }
    // Say out loud what was not asserted, so a passing run is not mistaken for
    // complete coverage of the range.
    println!(
        "sysconf raw sweep: probed 0..={MAX_PROBED_CODE}, declined {} selectors \
         (bd-fxu91j): {declined:?}",
        declined.len()
    );
    assert_eq!(
        declined.len(),
        KNOWN_UNIMPLEMENTED.len(),
        "every KNOWN_UNIMPLEMENTED selector must be inside the probed range; \
         shrinking the range to hide one would pass silently otherwise"
    );
    assert!(
        errno_mismatches.is_empty(),
        "sysconf errno divergences on -1 returns ({}):\n{}",
        errno_mismatches.len(),
        errno_mismatches.join("\n")
    );
    assert!(
        avail_mismatches.is_empty(),
        "sysconf availability divergences ({}):\n{}",
        avail_mismatches.len(),
        avail_mismatches.join("\n")
    );
    assert!(
        value_mismatches.is_empty(),
        "sysconf value divergences ({}):\n{}",
        value_mismatches.len(),
        value_mismatches.join("\n")
    );
}

#[test]
fn restored_raw_glibc_codes_match_host() {
    for &code in RESTORED_GLIBC_CODES {
        let host = unsafe { sysconf(code) };
        let implementation = unsafe { frankenlibc_abi::unistd_abi::sysconf(code) };
        assert!(
            host >= 0,
            "host glibc unexpectedly rejects raw sysconf code {code}"
        );
        assert_eq!(implementation, host, "raw sysconf code {code}");
    }
}

/// Selectors glibc answers as INDETERMINATE: -1 with errno left untouched.
///
/// Every one of these was measured on live glibc 2.42; fl reported -1 with
/// EINVAL for all of them because they fell through to the unknown-selector
/// arm. The return values agreed, so only an errno assertion can see it.
///
/// 60 is deliberately ABSENT from the run 53..=66: it is _SC_UIO_MAXIOV, which
/// glibc aliases to _SC_IOV_MAX and answers with 1024.
const INDETERMINATE_CODES: &[c_int] = &[
    6, 23, 24, 27, 32, 35, 49, 50, 53, 54, 55, 56, 57, 58, 59, 61, 62, 63, 64, 65, 66, 92, 97, 117,
    125, 126, 128,
];

#[test]
fn indeterminate_codes_return_minus_one_without_touching_errno() {
    // The host premise is asserted FIRST for every code, so this gate cannot
    // silently become a recording of fl's own behaviour if glibc changes.
    for &code in INDETERMINATE_CODES {
        let (g, g_errno) = unsafe {
            *libc::__errno_location() = SENTINEL_ERRNO;
            let r = sysconf(code);
            (r, *libc::__errno_location())
        };
        assert_eq!(g, -1, "host premise: glibc must report code {code} as -1");
        assert_eq!(
            g_errno, SENTINEL_ERRNO,
            "host premise: glibc must leave errno untouched for code {code}"
        );

        let (f, f_errno) = unsafe {
            *libc::__errno_location() = SENTINEL_ERRNO;
            let r = frankenlibc_abi::unistd_abi::sysconf(code);
            (r, *libc::__errno_location())
        };
        assert_eq!(f, -1, "fl must report code {code} as -1");
        assert_eq!(
            f_errno, SENTINEL_ERRNO,
            "fl must leave errno untouched for indeterminate code {code}: setting EINVAL here \
             tells the caller the selector is unknown, which is a different answer"
        );
    }
}

/// `_SC_MINSIGSTKSZ` (249) is a per-kernel value from the auxiliary vector, not
/// a constant, and it sits above this gate's original 130 ceiling.
#[test]
fn minsigstksz_matches_host_and_comes_from_auxv() {
    const SC_MINSIGSTKSZ: c_int = 249;
    const AT_MINSIGSTKSZ: usize = 51;

    let g = unsafe { sysconf(SC_MINSIGSTKSZ) };
    assert!(
        g > 0,
        "host premise: glibc must answer _SC_MINSIGSTKSZ with a positive value, got {g}"
    );
    let f = unsafe { frankenlibc_abi::unistd_abi::sysconf(SC_MINSIGSTKSZ) };
    assert_eq!(f, g, "fl _SC_MINSIGSTKSZ must match host glibc");

    // Read auxv directly rather than calling getauxval, so this assertion does
    // not depend on which object a `getauxval` reference binds to.
    let auxv = std::fs::read("/proc/self/auxv").expect("read /proc/self/auxv");
    let word = std::mem::size_of::<usize>();
    let mut published = None;
    for chunk in auxv.chunks_exact(word * 2) {
        let a_type = usize::from_ne_bytes(chunk[..word].try_into().unwrap());
        let a_val = usize::from_ne_bytes(chunk[word..word * 2].try_into().unwrap());
        if a_type == AT_MINSIGSTKSZ {
            published = Some(a_val);
            break;
        }
        if a_type == 0 {
            break;
        }
    }
    // Where the kernel publishes the entry, both sides must report exactly it —
    // this is the assertion a hardcoded arch constant fails, because the
    // compile-time MINSIGSTKSZ for x86_64 (2048) is not this kernel's value.
    if let Some(value) = published.filter(|v| *v != 0) {
        assert_eq!(
            f, value as std::ffi::c_long,
            "fl must report the kernel's AT_MINSIGSTKSZ, not a compile-time constant"
        );
    }
}

/// The value-bearing selectors added alongside the indeterminate set, kept as an
/// explicit named list because the sweep above would also accept them being
/// absent from BOTH sides if glibc ever stopped answering them.
///
/// The four signed minimums are the reason the sweep keys availability on `-1`
/// rather than on `>= 0`.
const RESTORED_VALUE_CODES: &[(c_int, &str)] = &[
    (103, "_SC_CHAR_MIN"),
    (105, "_SC_INT_MIN"),
    (112, "_SC_SCHAR_MIN"),
    (114, "_SC_SHRT_MIN"),
    (132, "_SC_ADVISORY_INFO"),
    (178, "_SC_V6_LP64_OFF64"),
    (235, "_SC_IPV6"),
    (236, "_SC_RAW_SOCKETS"),
    (239, "_SC_V7_LP64_OFF64"),
];

#[test]
fn restored_value_codes_match_host_exactly() {
    for &(code, name) in RESTORED_VALUE_CODES {
        let g = unsafe { sysconf(code) };
        assert_ne!(
            g, -1,
            "host premise: glibc must answer {name} ({code}) with a value"
        );
        let f = unsafe { frankenlibc_abi::unistd_abi::sysconf(code) };
        assert_eq!(f, g, "{name} ({code}): fl={f} glibc={g}");
    }
}

/// The CPU cache selectors, named, because they are the one family here served
/// from a DIFFERENT source than glibc uses: glibc walks CPUID with per-vendor
/// tables, fl reads the kernel's published topology under
/// /sys/devices/system/cpu/cpu0/cache/index*.
///
/// Two sources agreeing is the whole claim, so it gets its own test rather than
/// being buried in the sweep. On the machine this was written against (AMD Ryzen
/// Threadripper PRO 5975WX) they agree on 11 of the 12 rows the CPU has —
/// and disagree on exactly one, _SC_LEVEL1_ICACHE_ASSOC, where sysfs reports 8
/// ways and glibc reports -1. fl follows glibc there, by an explicit arm.
///
/// If this test fails on some other CPU, the useful question is WHICH row: a
/// failure on 186 means the special case needs to become conditional, and a
/// failure on any other row means the sysfs route itself does not track glibc
/// and the family needs CPUID after all.
///
/// IT HAS NOW RUN ON A SECOND CPU AND PASSED (bd-fxu91j): AMD EPYC-Genoa
/// (Zen 4) against glibc 2.43, where L2 is 1048576 rather than the 524288 of
/// the Zen 3 host it was written on. The differing value is the load-bearing
/// part -- had both machines quoted identical numbers, agreement would not
/// have distinguished "sysfs tracks glibc" from "both happen to hold this
/// host's constants". 186 reported -1 from glibc and 8 ways from sysfs on that
/// machine too, so the one special case generalised rather than being local.
const CACHE_SELECTORS: &[(c_int, &str)] = &[
    (185, "_SC_LEVEL1_ICACHE_SIZE"),
    (186, "_SC_LEVEL1_ICACHE_ASSOC"),
    (187, "_SC_LEVEL1_ICACHE_LINESIZE"),
    (188, "_SC_LEVEL1_DCACHE_SIZE"),
    (189, "_SC_LEVEL1_DCACHE_ASSOC"),
    (190, "_SC_LEVEL1_DCACHE_LINESIZE"),
    (191, "_SC_LEVEL2_CACHE_SIZE"),
    (192, "_SC_LEVEL2_CACHE_ASSOC"),
    (193, "_SC_LEVEL2_CACHE_LINESIZE"),
    (194, "_SC_LEVEL3_CACHE_SIZE"),
    (195, "_SC_LEVEL3_CACHE_ASSOC"),
    (196, "_SC_LEVEL3_CACHE_LINESIZE"),
    (197, "_SC_LEVEL4_CACHE_SIZE"),
    (198, "_SC_LEVEL4_CACHE_ASSOC"),
    (199, "_SC_LEVEL4_CACHE_LINESIZE"),
];

#[test]
fn cpu_cache_selectors_match_glibc() {
    let mut divergences = Vec::new();
    let mut real_values = 0usize;
    for &(code, name) in CACHE_SELECTORS {
        let g = unsafe { sysconf(code) };
        let f = unsafe { frankenlibc_abi::unistd_abi::sysconf(code) };
        if f != g {
            divergences.push(format!("{name} ({code}): fl={f} glibc={g}"));
        }
        if g > 0 {
            real_values += 1;
        }
    }
    // A machine reporting -1 for everything would make the comparison above
    // pass without testing anything. Every x86_64 host has at least an L1d
    // size, an L1d line size and an L2, so require several real values.
    assert!(
        real_values >= 6,
        "only {real_values} cache selectors returned a positive value from the HOST -- \
         the comparison is near-vacuous on this machine, so treat a pass as unproven"
    );
    assert!(
        divergences.is_empty(),
        "CPU cache selector divergences vs glibc ({} of {}):\n  {}",
        divergences.len(),
        CACHE_SELECTORS.len(),
        divergences.join("\n  ")
    );
}

/// `_SC_MINSIGSTKSZ`, `_SC_SIGSTKSZ` and `_SC_THREAD_STACK_MIN` all derive from
/// the SAME kernel-supplied value, `AT_MINSIGSTKSZ`, and this test pins the
/// RELATIONSHIP rather than the numbers.
///
/// That matters because on the machine this was written against the numbers are
/// uninformative: AT_MINSIGSTKSZ is 3376, so _SC_THREAD_STACK_MIN's MAX against
/// PTHREAD_STACK_MIN (16384) never engages and a hardcoded 16384 looks correct.
/// It stops looking correct on a CPU whose signal frame is larger — the value
/// grows with the XSAVE state the kernel must preserve — and there fl must
/// report the larger number, not the constant.
///
/// The formulas were read out of libc.so.6 2.42, not inferred from one host:
///   _SC_MINSIGSTKSZ    = dl_minsigstacksize          (returned directly)
///   _SC_SIGSTKSZ       = MAX(8192,  dl_minsigstacksize * 4)
///   _SC_THREAD_STACK_MIN = MAX(16384, dl_minsigstacksize)
/// and glibc seeds dl_minsigstacksize from AT_MINSIGSTKSZ.
#[test]
fn signal_stack_selectors_track_auxv() {
    const SC_MINSIGSTKSZ: c_int = 249;
    const SC_SIGSTKSZ: c_int = 250;
    const SC_THREAD_STACK_MIN: c_int = 75;
    const AT_MINSIGSTKSZ: usize = 51;

    let auxv = std::fs::read("/proc/self/auxv").expect("read /proc/self/auxv");
    let word = std::mem::size_of::<usize>();
    let mut published: Option<usize> = None;
    for chunk in auxv.chunks_exact(word * 2) {
        let a_type = usize::from_ne_bytes(chunk[..word].try_into().unwrap());
        let a_val = usize::from_ne_bytes(chunk[word..word * 2].try_into().unwrap());
        if a_type == AT_MINSIGSTKSZ {
            published = Some(a_val);
            break;
        }
        if a_type == 0 {
            break;
        }
    }
    let Some(minsig) = published.filter(|v| *v != 0) else {
        // Without the auxv entry there is no relationship to check; the plain
        // value comparisons in the sweep still apply. Say so rather than
        // passing silently.
        println!("kernel published no AT_MINSIGSTKSZ -- relationship not checked");
        return;
    };
    let minsig = minsig as std::ffi::c_long;

    for (code, name, expected) in [
        (SC_MINSIGSTKSZ, "_SC_MINSIGSTKSZ", minsig),
        (SC_SIGSTKSZ, "_SC_SIGSTKSZ", (minsig * 4).max(8192)),
        (
            SC_THREAD_STACK_MIN,
            "_SC_THREAD_STACK_MIN",
            minsig.max(16384),
        ),
    ] {
        // The host is the authority; assert it satisfies the relationship first,
        // so a glibc change shows up as a failure here rather than being
        // absorbed into fl's expectations.
        let g = unsafe { sysconf(code) };
        assert_eq!(
            g, expected,
            "host premise: glibc {name} should be {expected} for AT_MINSIGSTKSZ={minsig}, got {g}"
        );
        let f = unsafe { frankenlibc_abi::unistd_abi::sysconf(code) };
        assert_eq!(f, g, "{name}: fl={f} glibc={g}");
    }
}
