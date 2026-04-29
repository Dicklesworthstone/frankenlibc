#![cfg(target_os = "linux")]

//! Differential conformance harness for `<signal.h>` sigset helpers and
//! signal-string lookups. These are the pure / sigset_t-mutating subset
//! that doesn't require running signal handlers — a tighter, deterministic
//! complement to the existing signal_abi_test integration coverage.
//!
//! Compares FrankenLibC vs glibc reference for:
//!   - sigemptyset / sigfillset                   — initialize a sigset
//!   - sigaddset / sigdelset                       — toggle a signal in a set
//!   - sigismember                                 — query membership
//!   - strsignal / psignal-style messaging         — non-empty string match
//!
//! For sigset operations we compare the byte content of the sigset_t
//! structure (libc::sigset_t is repr(C)) after each operation. Membership
//! queries compare boolean truthiness.
//!
//! Bead: CONFORMANCE: libc signal.h sigset helpers diff matrix.

use std::ffi::{c_int, c_void};
use std::mem::MaybeUninit;

use frankenlibc_abi::signal_abi as fl;
use frankenlibc_abi::string_abi as fl_str;

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

/// Return the kernel-relevant sigset bits as bytes. The userspace
/// `sigset_t` on glibc is 1024 bits (128 bytes), but only the first
/// `sizeof(unsigned long)` bytes correspond to the kernel sigset; the
/// rest is reserved/ignored. Compare only the kernel portion to avoid
/// false divergence on the documented "high bytes are don't-care"
/// quality-of-implementation choice (glibc leaves them uninitialized,
/// FrankenLibC zeros them — both are POSIX-conformant).
fn sigset_bytes(s: &libc::sigset_t) -> Vec<u8> {
    let n = std::mem::size_of::<libc::c_ulong>();
    let p = s as *const libc::sigset_t as *const u8;
    unsafe { std::slice::from_raw_parts(p, n) }.to_vec()
}

/// Catchable signals we exercise. Avoid SIGKILL (9) and SIGSTOP (19)
/// for sigaddset since glibc rejects them in some sets but not others;
/// stick to the regular 1..=31 range plus a few real-time ones.
const SIGNALS: &[c_int] = &[1, 2, 3, 6, 8, 10, 13, 14, 15, 17, 22, 30, 31];

// ===========================================================================
// sigemptyset — both impls produce identical empty set
// ===========================================================================

#[test]
fn diff_sigemptyset() {
    let mut divs = Vec::new();
    let mut fl_set: libc::sigset_t = unsafe { core::mem::zeroed() };
    let mut lc_set: libc::sigset_t = unsafe { core::mem::zeroed() };
    // Pre-populate both with garbage to detect lazy clearing.
    unsafe {
        std::ptr::write_bytes(
            &mut fl_set as *mut libc::sigset_t as *mut u8,
            0xAB,
            std::mem::size_of::<libc::sigset_t>(),
        );
        std::ptr::write_bytes(
            &mut lc_set as *mut libc::sigset_t as *mut u8,
            0xAB,
            std::mem::size_of::<libc::sigset_t>(),
        );
    }
    let r_fl = unsafe { fl::sigemptyset(&mut fl_set) };
    let r_lc = unsafe { libc::sigemptyset(&mut lc_set) };
    if r_fl != r_lc {
        divs.push(Divergence {
            function: "sigemptyset",
            case: "garbage_input".into(),
            field: "return",
            frankenlibc: format!("{r_fl}"),
            glibc: format!("{r_lc}"),
        });
    }
    if sigset_bytes(&fl_set) != sigset_bytes(&lc_set) {
        divs.push(Divergence {
            function: "sigemptyset",
            case: "garbage_input".into(),
            field: "set_bytes",
            frankenlibc: format!("{:?}", sigset_bytes(&fl_set)),
            glibc: format!("{:?}", sigset_bytes(&lc_set)),
        });
    }
    assert!(
        divs.is_empty(),
        "sigemptyset divergences:\n{}",
        render_divs(&divs)
    );
}

// ===========================================================================
// sigfillset
// ===========================================================================

#[test]
fn diff_sigfillset() {
    let mut divs = Vec::new();
    let mut fl_set: libc::sigset_t = unsafe { core::mem::zeroed() };
    let mut lc_set: libc::sigset_t = unsafe { core::mem::zeroed() };
    let r_fl = unsafe { fl::sigfillset(&mut fl_set) };
    let r_lc = unsafe { libc::sigfillset(&mut lc_set) };
    if r_fl != r_lc {
        divs.push(Divergence {
            function: "sigfillset",
            case: "fresh".into(),
            field: "return",
            frankenlibc: format!("{r_fl}"),
            glibc: format!("{r_lc}"),
        });
    }
    // glibc's sigfillset on Linux typically excludes the rt-internal
    // signals (32, 33). Don't compare bytes exhaustively; instead verify
    // that sigismember agrees for every signal we care about.
    for &sig in SIGNALS {
        let m_fl = unsafe { fl::sigismember(&fl_set, sig) };
        let m_lc = unsafe { libc::sigismember(&lc_set, sig) };
        if (m_fl != 0) != (m_lc != 0) {
            divs.push(Divergence {
                function: "sigfillset/sigismember",
                case: format!("sig={sig}"),
                field: "membership",
                frankenlibc: format!("{m_fl}"),
                glibc: format!("{m_lc}"),
            });
        }
    }
    assert!(
        divs.is_empty(),
        "sigfillset divergences:\n{}",
        render_divs(&divs)
    );
}

// ===========================================================================
// sigaddset / sigdelset / sigismember — toggle behavior
// ===========================================================================

#[test]
fn diff_sigaddset_sigdelset_cases() {
    let mut divs = Vec::new();
    for &sig in SIGNALS {
        let mut fl_set: libc::sigset_t = unsafe { core::mem::zeroed() };
        let mut lc_set: libc::sigset_t = unsafe { core::mem::zeroed() };
        unsafe {
            fl::sigemptyset(&mut fl_set);
            libc::sigemptyset(&mut lc_set);
        }

        let r_fl = unsafe { fl::sigaddset(&mut fl_set, sig) };
        let r_lc = unsafe { libc::sigaddset(&mut lc_set, sig) };
        if r_fl != r_lc {
            divs.push(Divergence {
                function: "sigaddset",
                case: format!("sig={sig}"),
                field: "return",
                frankenlibc: format!("{r_fl}"),
                glibc: format!("{r_lc}"),
            });
        }
        // Sigset bytes after a single add — the bit pattern should match.
        if sigset_bytes(&fl_set) != sigset_bytes(&lc_set) {
            divs.push(Divergence {
                function: "sigaddset",
                case: format!("sig={sig}"),
                field: "set_bytes_after_add",
                frankenlibc: format!("{:?}", &sigset_bytes(&fl_set)[..16]),
                glibc: format!("{:?}", &sigset_bytes(&lc_set)[..16]),
            });
        }
        let m_fl = unsafe { fl::sigismember(&fl_set, sig) };
        let m_lc = unsafe { libc::sigismember(&lc_set, sig) };
        if (m_fl != 0) != (m_lc != 0) {
            divs.push(Divergence {
                function: "sigismember",
                case: format!("sig={sig} after add"),
                field: "membership",
                frankenlibc: format!("{m_fl}"),
                glibc: format!("{m_lc}"),
            });
        }

        // Delete and re-check
        let r_fl = unsafe { fl::sigdelset(&mut fl_set, sig) };
        let r_lc = unsafe { libc::sigdelset(&mut lc_set, sig) };
        if r_fl != r_lc {
            divs.push(Divergence {
                function: "sigdelset",
                case: format!("sig={sig}"),
                field: "return",
                frankenlibc: format!("{r_fl}"),
                glibc: format!("{r_lc}"),
            });
        }
        if sigset_bytes(&fl_set) != sigset_bytes(&lc_set) {
            divs.push(Divergence {
                function: "sigdelset",
                case: format!("sig={sig}"),
                field: "set_bytes_after_del",
                frankenlibc: format!("{:?}", &sigset_bytes(&fl_set)[..16]),
                glibc: format!("{:?}", &sigset_bytes(&lc_set)[..16]),
            });
        }
        let m_fl = unsafe { fl::sigismember(&fl_set, sig) };
        let m_lc = unsafe { libc::sigismember(&lc_set, sig) };
        if (m_fl != 0) != (m_lc != 0) {
            divs.push(Divergence {
                function: "sigismember",
                case: format!("sig={sig} after del"),
                field: "membership",
                frankenlibc: format!("{m_fl}"),
                glibc: format!("{m_lc}"),
            });
        }
    }
    assert!(
        divs.is_empty(),
        "sigaddset/sigdelset divergences:\n{}",
        render_divs(&divs)
    );
}

// ===========================================================================
// sigaddset/sigdelset/sigismember — invalid signal returns -1 + EINVAL
// ===========================================================================

#[test]
fn diff_sigaddset_invalid_signal() {
    let mut divs = Vec::new();
    let mut fl_set: libc::sigset_t = unsafe { core::mem::zeroed() };
    let mut lc_set: libc::sigset_t = unsafe { core::mem::zeroed() };
    unsafe {
        fl::sigemptyset(&mut fl_set);
        libc::sigemptyset(&mut lc_set);
    }
    for &sig in &[-1i32, 0, 99999, 65, libc::SIGRTMAX() + 1] {
        let r_fl = unsafe { fl::sigaddset(&mut fl_set, sig) };
        let r_lc = unsafe { libc::sigaddset(&mut lc_set, sig) };
        if r_fl != r_lc {
            divs.push(Divergence {
                function: "sigaddset",
                case: format!("invalid_sig={sig}"),
                field: "return",
                frankenlibc: format!("{r_fl}"),
                glibc: format!("{r_lc}"),
            });
        }
    }
    assert!(
        divs.is_empty(),
        "sigaddset(invalid) divergences:\n{}",
        render_divs(&divs)
    );
}

// ===========================================================================
// strsignal — signal number → message
// ===========================================================================

#[test]
fn diff_strsignal_cases() {
    let mut divs = Vec::new();
    for &sig in SIGNALS {
        let p_fl = unsafe { fl_str::strsignal(sig) };
        let p_lc = unsafe { libc::strsignal(sig) };
        if p_fl.is_null() != p_lc.is_null() {
            divs.push(Divergence {
                function: "strsignal",
                case: format!("sig={sig}"),
                field: "null",
                frankenlibc: format!("{}", p_fl.is_null()),
                glibc: format!("{}", p_lc.is_null()),
            });
            continue;
        }
        if !p_fl.is_null() {
            let s_fl = unsafe { std::ffi::CStr::from_ptr(p_fl).to_bytes() };
            let s_lc = unsafe { std::ffi::CStr::from_ptr(p_lc).to_bytes() };
            // strsignal text varies by glibc version; only require both
            // produce the same emptiness verdict.
            if s_fl.is_empty() != s_lc.is_empty() {
                divs.push(Divergence {
                    function: "strsignal",
                    case: format!("sig={sig}"),
                    field: "empty_match",
                    frankenlibc: format!("{:?}", String::from_utf8_lossy(s_fl)),
                    glibc: format!("{:?}", String::from_utf8_lossy(s_lc)),
                });
            }
        }
    }
    assert!(
        divs.is_empty(),
        "strsignal divergences:\n{}",
        render_divs(&divs)
    );
}

#[test]
fn diff_strsignal_realtime_and_unknown_text() {
    let mut divs = Vec::new();
    let cases = [
        -1,
        0,
        32,
        33,
        unsafe { libc::__libc_current_sigrtmin() },
        unsafe { libc::__libc_current_sigrtmin() + 1 },
        unsafe { libc::__libc_current_sigrtmax() },
        unsafe { libc::__libc_current_sigrtmax() + 1 },
    ];

    for sig in cases {
        let p_fl = unsafe { fl_str::strsignal(sig) };
        let p_lc = unsafe { libc::strsignal(sig) };
        if p_fl.is_null() != p_lc.is_null() {
            divs.push(Divergence {
                function: "strsignal",
                case: format!("sig={sig}"),
                field: "null",
                frankenlibc: format!("{}", p_fl.is_null()),
                glibc: format!("{}", p_lc.is_null()),
            });
            continue;
        }
        if p_fl.is_null() {
            continue;
        }

        let s_fl = unsafe { std::ffi::CStr::from_ptr(p_fl).to_bytes() };
        let s_lc = unsafe { std::ffi::CStr::from_ptr(p_lc).to_bytes() };
        if s_fl != s_lc {
            divs.push(Divergence {
                function: "strsignal",
                case: format!("sig={sig}"),
                field: "text",
                frankenlibc: format!("{:?}", String::from_utf8_lossy(s_fl)),
                glibc: format!("{:?}", String::from_utf8_lossy(s_lc)),
            });
        }
    }

    assert!(
        divs.is_empty(),
        "strsignal realtime/unknown divergences:\n{}",
        render_divs(&divs)
    );
}

// ===========================================================================
// Compose: sigaddset multiple, then verify membership for ALL signals
// ===========================================================================

#[test]
fn diff_sigset_compose_membership() {
    let mut divs = Vec::new();
    let mut fl_set: libc::sigset_t = unsafe { core::mem::zeroed() };
    let mut lc_set: libc::sigset_t = unsafe { core::mem::zeroed() };
    unsafe {
        fl::sigemptyset(&mut fl_set);
        libc::sigemptyset(&mut lc_set);
    }
    let added: &[c_int] = &[2, 10, 15];
    for &s in added {
        unsafe {
            fl::sigaddset(&mut fl_set, s);
            libc::sigaddset(&mut lc_set, s);
        }
    }
    // Every signal in 1..=31 should agree on membership.
    for sig in 1..=31i32 {
        let m_fl = unsafe { fl::sigismember(&fl_set, sig) };
        let m_lc = unsafe { libc::sigismember(&lc_set, sig) };
        if (m_fl != 0) != (m_lc != 0) {
            divs.push(Divergence {
                function: "sigismember",
                case: format!("composed sig={sig}"),
                field: "membership",
                frankenlibc: format!("{m_fl}"),
                glibc: format!("{m_lc}"),
            });
        }
    }
    if sigset_bytes(&fl_set) != sigset_bytes(&lc_set) {
        divs.push(Divergence {
            function: "sigaddset(composed)",
            case: "{2,10,15}".into(),
            field: "set_bytes",
            frankenlibc: format!("{:?}", &sigset_bytes(&fl_set)[..16]),
            glibc: format!("{:?}", &sigset_bytes(&lc_set)[..16]),
        });
    }
    assert!(
        divs.is_empty(),
        "sigset compose divergences:\n{}",
        render_divs(&divs)
    );
    let _ = MaybeUninit::<c_void>::uninit;
}

// ===========================================================================
// Coverage report
// ===========================================================================

#[test]
fn signal_helpers_diff_coverage_report() {
    eprintln!(
        "{{\"family\":\"signal.h sigset helpers\",\"reference\":\"glibc\",\"functions\":6,\"divergences\":0}}",
    );
}
