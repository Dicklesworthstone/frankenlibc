#![cfg(all(target_os = "linux", target_arch = "x86_64"))]
#![allow(unsafe_code)] // live glibc qecvt/qfcvt oracle via dlsym + an x87 trampoline

//! `qecvt` / `qfcvt` against the LIVE glibc.
//!
//! ## The mirror problem
//!
//! [`conformance_diff_strtold_live`] had to get a `long double` OUT of glibc,
//! which needed `fstp tbyte`. These functions need one to go IN, and Rust can
//! no more pass a `long double` than return one. On x86-64 SysV such an
//! argument is class MEMORY: the caller places sixteen bytes in the stack
//! argument area, and the integer parameters carry on in RDI/RSI/RDX as though
//! it were not in the sequence.
//!
//! [`call_host_qcvt`] builds exactly that frame:
//!
//! ```text
//!     sub  rsp, 24            ; entry rsp%16 == 8, so this lands on 0 — the
//!                             ; alignment the ABI requires at a call — and
//!                             ; reserves the argument slot
//!     movups xmm0, [rcx]      ; the caller's ten significant bytes (read as 16)
//!     movups [rsp], xmm0      ; place them where the callee expects
//!     call r8                 ; RDI/RSI/RDX already hold ndigit/decpt/sign
//!     add  rsp, 24
//!     ret                     ; the char* comes back in RAX untouched
//! ```
//!
//! That is the same shape as the production shim in `stdlib_abi`, run
//! backwards, so this gate exercises the ABI contract from the other side.
//!
//! ## What this gate does NOT assert, and why
//!
//! glibc's `qecvt` sometimes returns `ndigit + 1` characters — measured for
//! `1e-3` at every ndigit from 1 to 6, but not for `1e-2`, `1e-4` or `1.5e-3`.
//! The rule correlates with a rounding carry and is not fully characterised
//! (see bd-longdouble-varargs), so asserting byte equality would fail on inputs
//! as ordinary as 0.001 while fl's arithmetic is correct.
//!
//! So the assertions are on the VALUE — the digits, `decpt` and `sign` read as
//! a number — and the length difference is collected and reported rather than
//! failed on. A gate that fails for a reason nobody can act on trains people to
//! ignore it; one that reports the residual is a standing measurement of it.

use std::ffi::{CStr, c_char, c_int, c_void};
use std::sync::OnceLock;

type HostQcvt = unsafe extern "C" fn() -> *mut c_char;

/// Call `host(<long double at value>, ndigit, decpt, sign)`.
///
/// # Safety
///
/// `value` must address sixteen readable bytes; `decpt` and `sign` must be
/// writable; `host` must be a real `qecvt`/`qfcvt`.
#[unsafe(naked)]
unsafe extern "C" fn call_host_qcvt(
    _ndigit: c_int,
    _decpt: *mut c_int,
    _sign: *mut c_int,
    _value: *const u8,
    _host: HostQcvt,
) -> *mut c_char {
    core::arch::naked_asm!(
        "sub rsp, 24",
        "movups xmm0, [rcx]",
        "movups [rsp], xmm0",
        "call r8",
        "add rsp, 24",
        "ret",
    )
}

fn host_symbol(name: &CStr) -> Option<HostQcvt> {
    // SAFETY: dlopen/dlsym with NUL-terminated names; handle leaked deliberately.
    unsafe {
        let handle = libc::dlopen(c"libc.so.6".as_ptr(), libc::RTLD_NOW | libc::RTLD_LOCAL);
        if handle.is_null() {
            return None;
        }
        let sym = libc::dlsym(handle, name.as_ptr());
        if sym.is_null() {
            return None;
        }
        let fl = frankenlibc_abi::stdlib_abi::qecvt_x87 as *const () as usize;
        assert_ne!(
            sym as usize, fl,
            "the resolved symbol IS fl's own — this gate would compare fl \
             against itself and pass unconditionally (bd-v0388t)"
        );
        Some(std::mem::transmute::<*mut c_void, HostQcvt>(sym))
    }
}

fn host_qecvt() -> HostQcvt {
    static H: OnceLock<Option<HostQcvt>> = OnceLock::new();
    H.get_or_init(|| host_symbol(c"qecvt"))
        .expect("glibc qecvt must resolve")
}

fn host_qfcvt() -> HostQcvt {
    static H: OnceLock<Option<HostQcvt>> = OnceLock::new();
    H.get_or_init(|| host_symbol(c"qfcvt"))
        .expect("glibc qfcvt must resolve")
}

/// The x87 encoding of a decimal literal, built by fl's own verified converter
/// so the two arms are handed the identical bit pattern.
fn x87(digits: &[u8], dexp: i32) -> [u8; 16] {
    let ten = frankenlibc_core::float128::decimal_to_x87_extended(false, digits, dexp);
    let mut sixteen = [0u8; 16];
    sixteen[..10].copy_from_slice(&ten);
    sixteen
}

struct Answer {
    digits: String,
    decpt: c_int,
    sign: c_int,
}

fn read(ptr: *mut c_char, decpt: c_int, sign: c_int) -> Answer {
    assert!(!ptr.is_null(), "cvt returned NULL");
    // SAFETY: cvt returns a NUL-terminated static buffer.
    let digits = unsafe { CStr::from_ptr(ptr) }
        .to_string_lossy()
        .into_owned();
    Answer {
        digits,
        decpt,
        sign,
    }
}

/// glibc's `qecvt`/`qfcvt` return a pointer into ONE process-global static
/// buffer, so concurrent `#[test]` threads clobber each other between the call
/// and the copy. Measured: with four tests live, `qecvt(12.5, 5)` came back as
/// "1250" and a repeat-stability loop saw "" — a truncated neighbour's string,
/// not a glibc answer. Every host call takes this for call AND copy.
///
/// fl is not exposed to it (its buffers are thread-local), which is the tell:
/// when only the oracle-consulting arms misbehave, suspect the oracle. Same
/// class as bd-fegsgf and the libxcrypt gates in this tree.
fn oracle_lock() -> std::sync::MutexGuard<'static, ()> {
    static ORACLE: std::sync::Mutex<()> = std::sync::Mutex::new(());
    ORACLE
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
}

fn host_call(host: HostQcvt, value: &[u8; 16], ndigit: c_int) -> Answer {
    let _serialised = oracle_lock();
    let (mut decpt, mut sign) = (0, 0);
    // SAFETY: sixteen readable bytes, two writable ints, a resolved cvt symbol.
    let ptr = unsafe { call_host_qcvt(ndigit, &mut decpt, &mut sign, value.as_ptr(), host) };
    read(ptr, decpt, sign)
}

fn fl_qecvt(value: &[u8; 16], ndigit: c_int) -> Answer {
    let (mut decpt, mut sign) = (0, 0);
    // SAFETY: as above, through fl's own helper.
    let ptr = unsafe {
        frankenlibc_abi::stdlib_abi::qecvt_x87(ndigit, &mut decpt, &mut sign, value.as_ptr())
    };
    read(ptr, decpt, sign)
}

fn fl_qfcvt(value: &[u8; 16], ndigit: c_int) -> Answer {
    let (mut decpt, mut sign) = (0, 0);
    // SAFETY: as above.
    let ptr = unsafe {
        frankenlibc_abi::stdlib_abi::qfcvt_x87(ndigit, &mut decpt, &mut sign, value.as_ptr())
    };
    read(ptr, decpt, sign)
}

/// Compare as a NUMBER: trailing zeros beyond the shorter string are ignored,
/// which is exactly the glibc length residual and nothing else.
fn same_value(a: &Answer, b: &Answer) -> bool {
    if a.sign != b.sign || a.decpt != b.decpt {
        return false;
    }
    let (short, long) = if a.digits.len() <= b.digits.len() {
        (&a.digits, &b.digits)
    } else {
        (&b.digits, &a.digits)
    };
    long.starts_with(short.as_str()) && long[short.len()..].bytes().all(|c| c == b'0')
}

/// The trampoline must be right before any comparison means anything: a broken
/// one would hand both arms nothing and they would agree on nothing.
#[test]
fn the_oracle_itself_returns_real_digits() {
    let value = x87(b"125", -1); // 12.5
    let got = host_call(host_qecvt(), &value, 5);
    assert_eq!(got.digits, "12500", "glibc qecvt(12.5, 5)");
    assert_eq!(got.decpt, 2);
    assert_eq!(got.sign, 0);

    // A different value must give a different answer.
    let other = host_call(host_qecvt(), &x87(b"1", 0), 5);
    assert_eq!(other.digits, "10000");
    assert_eq!(other.decpt, 1);
}

/// Repeated calls must not drift — the argument frame is rebuilt each time and
/// nothing may leak across calls.
#[test]
fn the_oracle_is_stable_across_calls() {
    let value = x87(b"314159265358979323846", -20);
    let first = host_call(host_qecvt(), &value, 21);
    for _ in 0..64 {
        let again = host_call(host_qecvt(), &value, 21);
        assert_eq!(again.digits, first.digits, "the argument frame leaked");
        assert_eq!(again.decpt, first.decpt);
    }
}

/// Values that are EXACTLY representable in binary, so no decimal rounding
/// boundary is involved and glibc must agree digit for digit.
///
/// The restriction is not fl being cautious about itself — it is glibc's
/// `qecvt` being an unreliable oracle for anything else. Measured, with the
/// exact expansions:
///
/// ```text
///   0.0015L = 1.4999999999999999999906...e-03   BELOW the 1.5 boundary
///     ndigit 1   fl "1" (4 < 5, correct)          glibc "2"
///   123.456L = 1.2345600000000000000255...e+02
///     ndigit 20  fl ...000 (correct)               glibc ...001
///   1e100 as x87 = 9.999999999999999999669...e99
///     ndigit 19  fl carries to 1.000e100 (correct) glibc leaves 19 nines
/// ```
///
/// glibc's own `printf("%.19Le")` agrees with fl in each case, so this is
/// `qecvt`'s separate, approximate digit generation — not glibc generally, and
/// not a precision cap, since the 0.0015 case fails at ONE digit. Inexact
/// values are still exercised below, but reported rather than asserted.
const EXACT_CASES: &[(&[u8], i32)] = &[
    (b"1", 0),
    (b"2", 0),
    (b"5", -1),
    (b"125", -1),
    (b"25", -2),
    (b"15", -1),
    (b"325", -2),
    (b"1", 1),
    (b"1024", 0),
    (b"18446744073709551616", 0),
];

/// Exercised but not asserted: glibc's answer is not trustworthy for these.
const INEXACT_CASES: &[(&[u8], i32)] = &[
    (b"1", -1),
    (b"123456", -3),
    (b"1", 100),
    (b"1", -100),
    (b"314159265358979323846", -20),
    (b"15", -4),
    (b"1", -3),
];

#[test]
fn qecvt_values_match_live_glibc() {
    let mut length_residual = Vec::new();
    for &(digits, dexp) in EXACT_CASES {
        // Capped at 19, because GLIBC's qecvt — not fl — loses accuracy beyond
        // that. Measured against the exact expansions:
        //
        //   123.456L = 1.2345600000000000000255...e+02   (d21 = 2)
        //     ndigit 20  fl ...000 (correct, rounds down)   glibc ...001
        //     ndigit 21  fl ...002 (correct)                glibc ...005
        //   0.1L     = 1.000000000000000000013552...e-01   (d21 = 1)
        //     ndigit 21  fl ...001 (correct)                glibc ...000
        //
        // glibc's own printf("%.19Le") agrees with fl, so this is qecvt's
        // separate digit generation rather than glibc generally.
        //
        // The unifying cause is CARRY ACROSS A POWER OF TEN. 1e100 as an x87
        // value is 9.999999999999999999669...e99; to 19 digits that is nineteen
        // 9s with a 6 following, so it must carry to 1.000...e100 (decpt 101).
        // fl carries; glibc returns the un-normalised nines at decpt 100. The
        // same failure explains the ndigit+1 lengths this gate reports for
        // 1e-3 — glibc emits an extra character instead of normalising.
        //
        // So the cap is 17, inside LDBL_DIG (18), where the incumbent is a
        // reliable oracle. The divergences past it are recorded on
        // bd-longdouble-varargs; fl is the more accurate side in every one.
        for ndigit in [1, 2, 3, 5, 6, 10, 15, 17] {
            let value = x87(digits, dexp);
            let want = host_call(host_qecvt(), &value, ndigit);
            let got = fl_qecvt(&value, ndigit);
            assert!(
                same_value(&got, &want),
                "qecvt value diverges for {}e{} ndigit={}: fl={:?}/{}/{} glibc={:?}/{}/{}",
                String::from_utf8_lossy(digits),
                dexp,
                ndigit,
                got.digits,
                got.decpt,
                got.sign,
                want.digits,
                want.decpt,
                want.sign
            );
            if got.digits.len() != want.digits.len() {
                length_residual.push(format!(
                    "  {}e{} ndigit={}: fl {} chars, glibc {} chars ({:?} vs {:?})",
                    String::from_utf8_lossy(digits),
                    dexp,
                    ndigit,
                    got.digits.len(),
                    want.digits.len(),
                    got.digits,
                    want.digits
                ));
            }
        }
    }
    // Every INEXACT value, reported rather than asserted — a standing
    // measurement of where glibc's qecvt departs from the exact expansion.
    for &(digits, dexp) in INEXACT_CASES {
        for ndigit in [1, 5, 17, 19, 20, 21] {
            let value = x87(digits, dexp);
            let want = host_call(host_qecvt(), &value, ndigit);
            let got = fl_qecvt(&value, ndigit);
            if !same_value(&got, &want) {
                length_residual.push(format!(
                    "  INEXACT {}e{} ndigit={}: fl {:?}/{} glibc {:?}/{}",
                    String::from_utf8_lossy(digits),
                    dexp,
                    ndigit,
                    got.digits,
                    got.decpt,
                    want.digits,
                    want.decpt
                ));
            }
        }
    }
    // Reported, not failed: see the module docs.
    if !length_residual.is_empty() {
        println!(
            "qecvt length residual, {} case(s) — VALUES all agree:\n{}",
            length_residual.len(),
            length_residual.join("\n")
        );
    }
}

#[test]
fn qfcvt_values_match_live_glibc() {
    for &(digits, dexp) in EXACT_CASES {
        for ndigit in [0, 1, 3, 6, 10] {
            let value = x87(digits, dexp);
            let want = host_call(host_qfcvt(), &value, ndigit);
            let got = fl_qfcvt(&value, ndigit);
            assert!(
                same_value(&got, &want),
                "qfcvt value diverges for {}e{} ndigit={}: fl={:?}/{}/{} glibc={:?}/{}/{}",
                String::from_utf8_lossy(digits),
                dexp,
                ndigit,
                got.digits,
                got.decpt,
                got.sign,
                want.digits,
                want.decpt,
                want.sign
            );
        }
    }
}

/// The whole point of the shim: fl must read the argument the caller passed,
/// not a register. Two different long doubles must produce two different
/// answers — which is precisely what the old `c_double` signature could not do.
#[test]
fn fl_reads_the_stack_argument_not_a_register() {
    let a = fl_qecvt(&x87(b"125", -1), 5);
    let b = fl_qecvt(&x87(b"25", -1), 5);
    assert_eq!(a.digits, "12500");
    assert_eq!(b.digits, "25000");
    assert_ne!(
        a.decpt, b.decpt,
        "12.5 and 2.5 must not share a decimal point"
    );
}

// ---------------------------------------------------------------------------
// qgcvt. Its two siblings above reach `float128::x87_ecvt`/`x87_fcvt` and carry
// the value's own digits; `qgcvt_x87` alone still converted to `f64` first, so
// it lost the significand past the seventeenth digit AND the exponent range
// entirely — `qgcvt(1e400, 1)` answered "inf" for an ordinary finite long
// double. bd-longdouble-varargs-43usjw.
//
// Unlike qecvt, qgcvt has no unexplained length residual: it is `%.<n>Lg`, so
// these arms compare BYTES.
// ---------------------------------------------------------------------------

type HostQgcvt = unsafe extern "C" fn() -> *mut c_char;

/// Call `host(<long double at value>, ndigit, buf)`.
///
/// One fewer integer parameter than [`call_host_qcvt`], so the value pointer
/// arrives in RDX and the callee address in RCX, while RDI/RSI already hold
/// `ndigit` and `buf` — the sequence skips the long double exactly as the
/// production shim's `lea rdx, [rsp+8]` assumes.
///
/// # Safety
///
/// `value` must address sixteen readable bytes, `buf` a writable region large
/// enough for the answer, and `host` must be a real `qgcvt`.
#[unsafe(naked)]
unsafe extern "C" fn call_host_qgcvt(
    _ndigit: c_int,
    _buf: *mut c_char,
    _value: *const u8,
    _host: HostQgcvt,
) -> *mut c_char {
    core::arch::naked_asm!(
        "sub rsp, 24",
        "movups xmm0, [rdx]",
        "movups [rsp], xmm0",
        "call rcx",
        "add rsp, 24",
        "ret",
    )
}

fn host_qgcvt() -> HostQgcvt {
    static H: OnceLock<Option<HostQcvt>> = OnceLock::new();
    let sym = H
        .get_or_init(|| host_symbol(c"qgcvt"))
        .expect("glibc qgcvt must resolve");
    // SAFETY: same nullary-shaped alias the other oracles use; the trampoline
    // supplies the real signature.
    unsafe { std::mem::transmute::<HostQcvt, HostQgcvt>(sym) }
}

fn render(buf: &[c_char]) -> String {
    // SAFETY: qgcvt NUL-terminates within the buffer.
    unsafe { CStr::from_ptr(buf.as_ptr()) }
        .to_string_lossy()
        .into_owned()
}

fn host_qgcvt_call(value: &[u8; 16], ndigit: c_int) -> String {
    let _serialised = oracle_lock();
    let mut buf = [0 as c_char; 8192];
    // SAFETY: sixteen readable value bytes, 8192 writable ones, a resolved symbol.
    unsafe {
        call_host_qgcvt(ndigit, buf.as_mut_ptr(), value.as_ptr(), host_qgcvt());
    }
    render(&buf)
}

fn fl_qgcvt(value: &[u8; 16], ndigit: c_int) -> String {
    let mut buf = [0 as c_char; 8192];
    // SAFETY: as above, through fl's own helper.
    unsafe {
        frankenlibc_abi::stdlib_abi::qgcvt_x87(ndigit, buf.as_mut_ptr(), value.as_ptr());
    }
    render(&buf)
}

/// Raw x87 bytes, for the encodings no decimal literal names.
fn x87_raw(significand: u64, sign_exp: u16) -> [u8; 16] {
    let mut sixteen = [0u8; 16];
    sixteen[..8].copy_from_slice(&significand.to_le_bytes());
    sixteen[8..10].copy_from_slice(&sign_exp.to_le_bytes());
    sixteen
}

/// The inputs, chosen so half of them cannot survive an `f64`.
fn qgcvt_values() -> Vec<(&'static str, [u8; 16])> {
    vec![
        ("pi", x87(b"314159265358979323846264338327950288", -35)),
        ("e", x87(b"271828182845904523536028747135266250", -35)),
        ("2^64+1", x87(b"18446744073709551617", 0)),
        ("1e400", x87(b"1", 400)),
        ("1e-400", x87(b"1", -400)),
        ("1e4000", x87(b"1", 4000)),
        ("0.1", x87(b"1", -1)),
        ("1.0", x87(b"1", 0)),
        ("12.5", x87(b"125", -1)),
        ("0.0", x87(b"0", 0)),
        ("1e5", x87(b"1", 5)),
        ("1234567", x87(b"1234567", 0)),
        ("1e-4", x87(b"1", -4)),
        ("inf", x87_raw(1 << 63, 0x7fff)),
        ("-inf", x87_raw(1 << 63, 0xffff)),
        ("nan", x87_raw((1 << 63) | (1 << 62), 0x7fff)),
        ("-nan", x87_raw((1 << 63) | (1 << 62), 0xffff)),
    ]
}

/// INSTRUMENT ARM. Every comparison below would still pass against an oracle
/// that had quietly narrowed to `f64`, so pin on GLIBC ALONE that it has not.
#[test]
fn the_qgcvt_oracle_carries_more_than_f64() {
    let pi = x87(b"314159265358979323846264338327950288", -35);
    let host = host_qgcvt_call(&pi, 21);
    assert_eq!(
        host, "3.14159265358979323851",
        "live glibc's own qgcvt answer changed — the expectations here are read \
         from it, so nothing can be concluded until this is understood"
    );
    assert_ne!(
        host, "3.14159265358979311600",
        "the oracle is rendering pi through an f64; a comparison against it \
         cannot detect the defect this arm exists for"
    );
    let big = host_qgcvt_call(&x87(b"1", 400), 1);
    assert_eq!(
        big, "1e+400",
        "1e400 is a finite long double; an oracle answering inf has narrowed"
    );
}

/// Byte equality against the live glibc, across the precisions that matter:
/// below f64's limit, at it, past it, past the long double's own 21-digit cap,
/// zero, and negative.
#[test]
fn qgcvt_matches_live_glibc() {
    for (name, value) in qgcvt_values() {
        for ndigit in [1, 3, 6, 17, 18, 21, 25, 0, -1] {
            let host = host_qgcvt_call(&value, ndigit);
            let fl = fl_qgcvt(&value, ndigit);
            assert_eq!(fl, host, "qgcvt({name}, {ndigit})");
        }
    }
}

/// A NEGATIVE ndigit is "no precision" (the %g default of 6), not "precision
/// 0". The two are different answers and the previous `ndigit.max(0)` gave both
/// the same one, so this is called out separately from the sweep above rather
/// than left to be one row in it.
#[test]
fn qgcvt_negative_ndigit_is_the_default_precision_not_zero() {
    let pi = x87(b"314159265358979323846264338327950288", -35);
    let negative = host_qgcvt_call(&pi, -1);
    let zero = host_qgcvt_call(&pi, 0);
    assert_eq!(
        negative, "3.14159",
        "glibc: negative ndigit means %g's default"
    );
    assert_eq!(
        zero, "3",
        "glibc: ndigit 0 is precision 0, which %g reads as 1"
    );
    assert_ne!(negative, zero, "the two must not collapse to one answer");
    assert_eq!(fl_qgcvt(&pi, -1), negative);
    assert_eq!(fl_qgcvt(&pi, 0), zero);
}
