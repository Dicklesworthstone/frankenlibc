#![cfg(all(target_os = "linux", target_arch = "x86_64"))]
#![allow(unsafe_code)] // live glibc strtold oracle via dlsym + an x87 trampoline

//! `strtold` against the LIVE glibc, not against a pinned table.
//!
//! ## Why this gate needs assembly at all
//!
//! Every other differential gate in this tree can call its oracle directly,
//! because Rust can name the argument and return types. `strtold` returns a
//! `long double`, which on x86-64 SysV lives in **ST(0)** — the x87 register
//! stack. Rust has no `f80` type and no way to spell that convention, so a
//! plain `extern "C" { fn strtold(..) -> ?; }` cannot be written at all.
//!
//! The consequence is that fl's long-double work has been gated only by tables
//! of bytes captured from glibc by hand. That is weaker than it looks: a pinned
//! table cannot notice a libc upgrade, and it certifies the transcription as
//! much as the code. This file closes that by asking the running glibc every
//! time.
//!
//! ## The trampoline
//!
//! [`call_host_strtold`] is a naked function that calls glibc's `strtold`
//! through a pointer and then stores the x87 top-of-stack to memory:
//!
//! ```text
//!     push rdx                  ; save the out-pointer, AND align the stack:
//!                               ; entry rsp%16 == 8, so after the push it is 0,
//!                               ; which is what the ABI requires at a call
//!     call rcx                  ; glibc strtold(nptr, endptr) -> ST(0)
//!     pop  rdx
//!     fstp tbyte ptr [rdx]      ; store the 80-bit value and POP the x87 stack
//!     ret
//! ```
//!
//! `fstp` rather than `fst` matters: `strtold` pushed one value onto an
//! eight-deep register stack, and a gate that leaked one entry per call would
//! start returning NaNs after eight comparisons rather than failing outright.
//! This is the exact mirror of the `fld tbyte` the production shims use, and
//! that direction was validated separately under gcc and objdump.
//!
//! ## Provenance
//!
//! The oracle is `dlsym`'d rather than linked, and the resolved address is
//! asserted not to be fl's own. fl's exports are `no_mangle` only in release
//! builds, so a link-time reference from a debug test would bind to glibc
//! today and silently bind to fl the day someone changes that gating —
//! bd-v0388t is the record of that hazard producing hollow gates.

use std::ffi::{CStr, CString, c_char, c_void};
use std::sync::OnceLock;

/// `char *strtold(const char *, char **)` — as glibc exports it. Called only
/// through [`call_host_strtold`], never directly, because its true return type
/// is not expressible here.
type HostStrtold = unsafe extern "C" fn(*const c_char, *mut *mut c_char) -> *mut c_void;

/// Call `host(nptr, endptr)` and store the resulting `long double` to `out`.
///
/// # Safety
///
/// `out` must address ten writable bytes; `host` must be a real `strtold`.
#[unsafe(naked)]
unsafe extern "C" fn call_host_strtold(
    _nptr: *const c_char,
    _endptr: *mut *mut c_char,
    _out: *mut u8,
    _host: HostStrtold,
) {
    core::arch::naked_asm!(
        "push rdx",
        "call rcx",
        "pop rdx",
        "fstp tbyte ptr [rdx]",
        "ret",
    )
}

/// Resolve glibc's `strtold`, refusing to hand back fl's own definition.
fn host_strtold() -> Option<HostStrtold> {
    static H: OnceLock<Option<usize>> = OnceLock::new();
    (*H.get_or_init(|| {
        // SAFETY: dlopen/dlsym with NUL-terminated names; the handle is
        // intentionally leaked for the process lifetime.
        unsafe {
            let handle = libc::dlopen(c"libc.so.6".as_ptr(), libc::RTLD_NOW | libc::RTLD_LOCAL);
            if handle.is_null() {
                return None;
            }
            let sym = libc::dlsym(handle, c"strtold".as_ptr());
            if sym.is_null() {
                return None;
            }
            let fl = frankenlibc_abi::stdlib_abi::strtold_into as *const () as usize;
            assert_ne!(
                sym as usize, fl,
                "the resolved strtold IS fl's own — this gate would compare fl \
                 against itself and pass unconditionally (bd-v0388t)"
            );
            Some(sym as usize)
        }
    }))
    .map(|addr| {
        // SAFETY: the address came from dlsym on glibc's `strtold`.
        unsafe { std::mem::transmute::<usize, HostStrtold>(addr) }
    })
}

/// glibc's answer: the ten x87 bytes, and how far it consumed.
fn glibc(input: &CStr) -> ([u8; 10], isize) {
    let host = host_strtold().expect("glibc strtold must resolve");
    let mut out = [0u8; 10];
    let mut end: *mut c_char = std::ptr::null_mut();
    // SAFETY: `out` is ten writable bytes; `host` came from dlsym on strtold.
    unsafe { call_host_strtold(input.as_ptr(), &mut end, out.as_mut_ptr(), host) };
    // SAFETY: glibc sets endptr into the input buffer.
    let consumed = unsafe { end.offset_from(input.as_ptr()) };
    (out, consumed)
}

/// fl's answer, through the same code path the shim uses.
fn fl(input: &CStr) -> ([u8; 10], isize) {
    let mut out = [0u8; 10];
    let mut end: *mut c_char = std::ptr::null_mut();
    // SAFETY: NUL-terminated input, writable endptr, ten writable bytes.
    unsafe {
        frankenlibc_abi::stdlib_abi::strtold_into(input.as_ptr(), &mut end, out.as_mut_ptr())
    };
    // SAFETY: fl sets endptr into the input buffer.
    let consumed = unsafe { end.offset_from(input.as_ptr()) };
    (out, consumed)
}

fn show(bytes: &[u8; 10]) -> String {
    bytes.iter().rev().map(|b| format!("{b:02x}")).collect()
}

fn compare(text: &str) {
    let input = CString::new(text).expect("no interior NUL");
    let (want, want_end) = glibc(&input);
    let (got, got_end) = fl(&input);
    assert_eq!(
        show(&got),
        show(&want),
        "value for {text:?} (fl vs live glibc)"
    );
    assert_eq!(got_end, want_end, "endptr offset for {text:?}");
}

/// The trampoline has to be right before anything it reports means anything:
/// a wrong one would return the same wrong bytes for every input and the
/// comparisons would still agree with each other.
#[test]
fn the_oracle_itself_returns_real_values() {
    let one = glibc(&CString::new("1").unwrap()).0;
    assert_eq!(
        show(&one),
        "3fff8000000000000000",
        "glibc strtold(\"1\") must be exponent 0x3fff with the integer bit set; \
         if this fails the x87 trampoline is wrong, not fl"
    );
    let half = glibc(&CString::new("0.5").unwrap()).0;
    assert_eq!(show(&half), "3ffe8000000000000000");
    // Distinct inputs must give distinct answers — catches a trampoline that
    // returns a constant.
    assert_ne!(show(&one), show(&half));
}

/// Calling repeatedly must not leak x87 stack entries. The register stack is
/// eight deep, so a gate using `fst` instead of `fstp` would still pass a
/// handful of comparisons and then start reporting NaN.
#[test]
fn the_oracle_does_not_leak_the_x87_stack() {
    let input = CString::new("3.14159265358979323846").unwrap();
    let first = glibc(&input).0;
    for _ in 0..64 {
        assert_eq!(
            show(&glibc(&input).0),
            show(&first),
            "the x87 stack leaked: repeated calls stopped agreeing"
        );
    }
}

#[test]
fn decimal_values_match_live_glibc() {
    for text in [
        "1",
        "2",
        "0.5",
        "1.5",
        "0.1",
        "10",
        "-1",
        "-0.0",
        "0",
        "3.14159265358979323846",
        "1e100",
        "1e-100",
        "1e308",
        "1e-308",
        "18446744073709551617",
        "36893488147419103233",
        "123456789012345678901234567890",
        "  1.5xyz",
        "+.5",
        ".5e2",
        "5.",
        "1e",
        "1e+",
        "0x",
        "1_000",
    ] {
        compare(text);
    }
}

#[test]
fn boundaries_and_subnormals_match_live_glibc() {
    for text in [
        "1e4932",
        "1e4933",
        "1e-4950",
        "1e-4951",
        "1e-4966",
        "3.6451995318824746025e-4951",
        "1.8225997659412373012e-4951",
        "1.8225997659412373013e-4951",
        "3.3621031431120935063e-4932",
        "1e999999999",
        "-1e999999999",
        "1e-999999999",
    ] {
        compare(text);
    }
}

#[test]
fn hex_and_specials_match_live_glibc() {
    for text in [
        "0x1",
        "0x1p3",
        "0x1.8p1",
        "0x.8p0",
        "0x1p",
        "0x.p1",
        "0X1P4",
        "0x1.fffffffffffffffep16383",
        "0x8p-4",
        "0xabcdef.123456p-8",
        "inf",
        "INFINITY",
        "-inf",
        "iNfInItY",
        "infinit",
    ] {
        compare(text);
    }
}

/// The grammar corners, which are where a hand-written scanner drifts from the
/// incumbent. Each of these contradicts a reasonable reading of the standard.
#[test]
fn grammar_corners_match_live_glibc() {
    for text in [
        "1e",
        "1e+",
        "0x",
        "0x.p1",
        "0x1",
        "0x1p",
        "- 1",
        "-.e3",
        "  -  1",
        ".",
        "e5",
        "abc",
        "",
        "00.5",
        "0x0p0",
        "-0",
        "\t\n\x0b\x0c\r 2",
    ] {
        compare(text);
    }
}

/// Randomised decimals, so the gate is not limited to what I thought to write
/// down. Deterministic seed: a differential gate that changes inputs run to run
/// cannot be bisected.
#[test]
fn randomised_decimals_match_live_glibc() {
    let mut state = 0x2545_f491_4f6c_dd1du64;
    let mut next = move || {
        state ^= state << 13;
        state ^= state >> 7;
        state ^= state << 17;
        state
    };
    for _ in 0..2000 {
        let digits = 1 + (next() % 22) as usize;
        let mut text = String::new();
        if next() & 1 == 0 {
            text.push('-');
        }
        for _ in 0..digits {
            text.push((b'0' + (next() % 10) as u8) as char);
        }
        let exponent = (next() % 9900) as i64 - 4950;
        text.push('e');
        text.push_str(&exponent.to_string());
        compare(&text);
    }
}
