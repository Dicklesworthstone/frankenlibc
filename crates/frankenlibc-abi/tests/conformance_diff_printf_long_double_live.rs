#![cfg(all(target_os = "linux", target_arch = "x86_64"))]
#![allow(unsafe_code)] // live glibc snprintf oracle via dlsym + a vararg trampoline

//! `printf("%Lf")` against the LIVE glibc — value AND argument stream.
//!
//! ## Why a trampoline again
//!
//! A `long double` VARARG is class X87 on x86-64 SysV: the caller places
//! sixteen bytes in the overflow area and the integer parameters carry on in
//! registers as though it were not in the sequence. Rust cannot pass one, so
//! the call is built by hand — the same technique as the `qcvt` gate, with one
//! addition: `al` must carry the number of SSE registers used, and it is zero
//! here, because an X87 argument uses none.
//!
//! ## What is actually being tested
//!
//! Not just the digits. Reading a `%Lf` argument as a `double` leaves the
//! caller's sixteen stack bytes UNCONSUMED, so every following conversion reads
//! the wrong argument — one `%Lf` corrupts the rest of the format string. That
//! is a different and worse failure than printing a wrong number, and it is
//! invisible to a test whose format ends at the `%Lf`.
//!
//! So the formats here deliberately put conversions AFTER the long double, and
//! the assertions compare fl's whole output against glibc's whole output.

use std::ffi::{CStr, CString, c_char, c_int};
use std::sync::OnceLock;

type HostSnprintf = unsafe extern "C" fn() -> c_int;

/// `snprintf(buf, n, fmt, <long double>)`.
///
/// # Safety
///
/// `buf` must address `n` writable bytes; `value` sixteen readable ones.
#[unsafe(naked)]
unsafe extern "C" fn call_snprintf_ld(
    _buf: *mut c_char,
    _n: usize,
    _fmt: *const c_char,
    _value: *const u8,
    _host: HostSnprintf,
) -> c_int {
    core::arch::naked_asm!(
        "sub rsp, 24",
        "movups xmm0, [rcx]",
        "movups [rsp], xmm0",
        "xor eax, eax",
        "call r8",
        "add rsp, 24",
        "ret",
    )
}

/// `snprintf(buf, n, fmt, <long double>, trailing)` — a conversion AFTER the
/// long double, which is what catches an unconsumed stack slot.
///
/// # Safety
///
/// As [`call_snprintf_ld`].
#[unsafe(naked)]
unsafe extern "C" fn call_snprintf_ld_then_int(
    _buf: *mut c_char,
    _n: usize,
    _fmt: *const c_char,
    _value: *const u8,
    _trailing: c_int,
    _host: HostSnprintf,
) -> c_int {
    core::arch::naked_asm!(
        "sub rsp, 24",
        "movups xmm0, [rcx]",
        "movups [rsp], xmm0",
        // The long double occupies the stack slot, so the trailing int takes
        // the next INTEGER register — the sequence skips it entirely.
        "mov rcx, r8",
        "xor eax, eax",
        "call r9",
        "add rsp, 24",
        "ret",
    )
}

/// `snprintf(buf, n, fmt, <GP value>, trailing)`.
///
/// # Safety
///
/// `buf` must address `n` writable bytes. `value` is passed as the first
/// variadic general-purpose argument and `trailing` as the second.
#[unsafe(naked)]
unsafe extern "C" fn call_snprintf_gp_then_int(
    _buf: *mut c_char,
    _n: usize,
    _fmt: *const c_char,
    _value: usize,
    _trailing: c_int,
    _host: HostSnprintf,
) -> c_int {
    core::arch::naked_asm!("sub rsp, 8", "xor eax, eax", "call r9", "add rsp, 8", "ret",)
}

fn host_snprintf() -> HostSnprintf {
    static H: OnceLock<Option<usize>> = OnceLock::new();
    let addr = (*H.get_or_init(|| {
        // SAFETY: dlopen/dlsym with NUL-terminated names; handle leaked.
        unsafe {
            let handle = libc::dlopen(c"libc.so.6".as_ptr(), libc::RTLD_NOW | libc::RTLD_LOCAL);
            if handle.is_null() {
                return None;
            }
            let sym = libc::dlsym(handle, c"snprintf".as_ptr());
            if sym.is_null() {
                return None;
            }
            let fl = frankenlibc_abi::stdio_abi::snprintf as *const () as usize;
            assert_ne!(
                sym as usize, fl,
                "the resolved snprintf IS fl's own — this gate would compare fl \
                 against itself and pass unconditionally (bd-v0388t)"
            );
            Some(sym as usize)
        }
    }))
    .expect("glibc snprintf must resolve");
    // SAFETY: the address came from dlsym on glibc's snprintf.
    unsafe { std::mem::transmute::<usize, HostSnprintf>(addr) }
}

fn x87(digits: &[u8], dexp: i32, negative: bool) -> [u8; 16] {
    let ten = frankenlibc_core::float128::decimal_to_x87_extended(negative, digits, dexp);
    let mut sixteen = [0u8; 16];
    sixteen[..10].copy_from_slice(&ten);
    sixteen
}

fn render(out: &[c_char]) -> String {
    // SAFETY: snprintf NUL-terminates within the buffer.
    unsafe { CStr::from_ptr(out.as_ptr()) }
        .to_string_lossy()
        .into_owned()
}

/// glibc and fl, same format, same bytes, in one invocation.
fn both(fmt: &str, value: &[u8; 16]) -> (String, String) {
    let fmt_c = CString::new(fmt).expect("no interior NUL");
    let mut host_buf = [0 as c_char; 8192];
    let mut fl_buf = [0 as c_char; 8192];
    // SAFETY: 8192 writable bytes each; sixteen readable value bytes.
    unsafe {
        call_snprintf_ld(
            host_buf.as_mut_ptr(),
            host_buf.len(),
            fmt_c.as_ptr(),
            value.as_ptr(),
            host_snprintf(),
        );
        call_snprintf_ld(
            fl_buf.as_mut_ptr(),
            fl_buf.len(),
            fmt_c.as_ptr(),
            value.as_ptr(),
            std::mem::transmute::<*const (), HostSnprintf>(
                frankenlibc_abi::stdio_abi::snprintf as *const (),
            ),
        );
    }
    (render(&host_buf), render(&fl_buf))
}

fn both_with_trailing(fmt: &str, value: &[u8; 16], trailing: c_int) -> (String, String) {
    let fmt_c = CString::new(fmt).expect("no interior NUL");
    let mut host_buf = [0 as c_char; 8192];
    let mut fl_buf = [0 as c_char; 8192];
    // SAFETY: as above.
    unsafe {
        call_snprintf_ld_then_int(
            host_buf.as_mut_ptr(),
            host_buf.len(),
            fmt_c.as_ptr(),
            value.as_ptr(),
            trailing,
            host_snprintf(),
        );
        call_snprintf_ld_then_int(
            fl_buf.as_mut_ptr(),
            fl_buf.len(),
            fmt_c.as_ptr(),
            value.as_ptr(),
            trailing,
            std::mem::transmute::<*const (), HostSnprintf>(
                frankenlibc_abi::stdio_abi::snprintf as *const (),
            ),
        );
    }
    (render(&host_buf), render(&fl_buf))
}

fn both_gp_with_trailing(fmt: &str, value: usize, trailing: c_int) -> (String, String) {
    let fmt_c = CString::new(fmt).expect("no interior NUL");
    let mut host_buf = [0 as c_char; 8192];
    let mut fl_buf = [0 as c_char; 8192];
    // SAFETY: both output buffers are writable and the trampoline preserves
    // the SysV general-purpose vararg register layout.
    unsafe {
        call_snprintf_gp_then_int(
            host_buf.as_mut_ptr(),
            host_buf.len(),
            fmt_c.as_ptr(),
            value,
            trailing,
            host_snprintf(),
        );
        call_snprintf_gp_then_int(
            fl_buf.as_mut_ptr(),
            fl_buf.len(),
            fmt_c.as_ptr(),
            value,
            trailing,
            std::mem::transmute::<*const (), HostSnprintf>(
                frankenlibc_abi::stdio_abi::snprintf as *const (),
            ),
        );
    }
    (render(&host_buf), render(&fl_buf))
}

/// The trampoline must be right before any comparison means anything.
#[test]
fn the_vararg_trampoline_passes_a_real_long_double() {
    let (host, _fl) = both("%.2Lf", &x87(b"125", -1, false));
    assert_eq!(
        host, "12.50",
        "glibc must see 12.5 — if not, the trampoline is wrong"
    );
    let (host, _fl) = both("%.2Lf", &x87(b"25", -1, false));
    assert_eq!(host, "2.50", "distinct inputs must give distinct answers");
}

#[test]
fn long_double_values_match_live_glibc() {
    for (digits, dexp, negative) in [
        (&b"1"[..], 0, false),
        (b"125", -1, false),
        (b"125", -1, true),
        (b"5", -1, false),
        (b"3", 0, false),
        (b"1", 2, false),
        (b"0", 0, false),
    ] {
        let value = x87(digits, dexp, negative);
        for fmt in [
            "%Lf",
            "%.2Lf",
            "%Le",
            "%Lg",
            "%.0Lf",
            "%12.3Lf",
            "%-12.3Lf|",
        ] {
            let (host, fl) = both(fmt, &value);
            assert_eq!(
                fl,
                host,
                "{fmt} of {}e{} (negative={negative})",
                String::from_utf8_lossy(digits),
                dexp
            );
        }
    }
}

/// THE POINT OF THE FIX. A conversion after the long double must read ITS OWN
/// argument. If `%Lf` consumes a register instead of the sixteen-byte stack
/// slot, the trailing `%d` reads the wrong thing — and the value printed for
/// the long double is wrong too, so a test that only checked the number could
/// pass while the stream was corrupt.
#[test]
fn a_conversion_after_a_long_double_reads_its_own_argument() {
    let value = x87(b"125", -1, false);
    for fmt in ["%.2Lf|%d", "%Lf %d", "%.1Lf[%d]", "%.3Lf%d"] {
        let (host, fl) = both_with_trailing(fmt, &value, 4242);
        assert_eq!(fl, host, "argument stream diverges for {fmt:?}");
        assert!(
            fl.contains("4242"),
            "the trailing int was lost for {fmt:?}: {fl:?} — this is the \
             unconsumed-stack-slot bug"
        );
    }
}

#[test]
fn uppercase_l_aliases_consume_the_glibc_argument_shape() {
    let wide_hi = [b'h' as u32, b'i' as u32, 0];
    for (fmt, value, expected) in [
        ("[%Ld|%d]", 1_234_567_890_123usize, "[1234567890123|77]"),
        ("[%Lu|%d]", 42usize, "[42|77]"),
        ("[%Ls|%d]", wide_hi.as_ptr() as usize, "[hi|77]"),
        ("[%Lc|%d]", b'A' as usize, "[A|77]"),
    ] {
        let (host, fl) = both_gp_with_trailing(fmt, value, 77);
        assert_eq!(host, expected, "live glibc oracle changed for {fmt:?}");
        assert_eq!(fl, host, "fl argument stream diverges for {fmt:?}");
    }
}

/// THE POSITIONAL PATH, which the sequential fix above does not reach.
///
/// `positional_printf_arg_plan` returns a sequence of argument CLASSES, and
/// that enum had exactly two variants — Gp and Fp — so `%1$Lf` was
/// indistinguishable from `%1$f` at extraction time. Both extractors therefore
/// read a positional long double out of the SSE register save area: wrong
/// value, and the caller's sixteen stack bytes left unconsumed, so every later
/// positional argument is read from the wrong place too.
///
/// The trailing `%2$d` is the part that catches the unconsumed slot. A format
/// ending at the `%1$Lf` would print a wrong number and nothing else.
#[test]
fn positional_long_double_reads_its_own_argument() {
    let value = x87(b"125", -1, false);
    for fmt in [
        "%1$.2Lf|%2$d",
        "%1$Lf %2$d",
        "%2$d[%1$.1Lf]",
        "%2$d %2$d %1$.3Lf",
    ] {
        let (host, fl) = both_with_trailing(fmt, &value, 4242);
        assert_eq!(fl, host, "positional argument stream diverges for {fmt:?}");
        assert!(
            fl.contains("4242"),
            "the positional int was lost for {fmt:?}: {fl:?} — this is the \
             unconsumed-stack-slot bug on the positional path"
        );
        assert!(
            fl.contains("12.5"),
            "the positional long double was misread for {fmt:?}: {fl:?}"
        );
    }
}

/// Values, positionally. Separate from the stream arm because a plan that
/// classified X87 correctly but read the wrong ten bytes would pass the
/// stream check (the following argument would still line up) and fail here.
#[test]
fn positional_long_double_values_match_live_glibc() {
    for (digits, dexp, negative) in [
        (&b"1"[..], 0, false),
        (b"125", -1, false),
        (b"125", -1, true),
        (b"5", -1, false),
        (b"0", 0, false),
    ] {
        let value = x87(digits, dexp, negative);
        for fmt in ["%1$Lf", "%1$.2Lf", "%1$Le", "%1$Lg", "%1$12.3Lf"] {
            let (host, fl) = both(fmt, &value);
            assert_eq!(
                fl,
                host,
                "{fmt} of {}e{} (negative={negative})",
                String::from_utf8_lossy(digits),
                dexp
            );
        }
    }
}

// ---------------------------------------------------------------------------
// The WIDE side: swprintf has its own extraction macro and had the same bug.
// ---------------------------------------------------------------------------

type HostSwprintf = unsafe extern "C" fn() -> c_int;

fn host_swprintf() -> HostSwprintf {
    static H: OnceLock<Option<usize>> = OnceLock::new();
    let addr = (*H.get_or_init(|| {
        // SAFETY: dlopen/dlsym with NUL-terminated names; handle leaked.
        unsafe {
            let handle = libc::dlopen(c"libc.so.6".as_ptr(), libc::RTLD_NOW | libc::RTLD_LOCAL);
            if handle.is_null() {
                return None;
            }
            let sym = libc::dlsym(handle, c"swprintf".as_ptr());
            if sym.is_null() {
                return None;
            }
            let fl = frankenlibc_abi::wchar_abi::swprintf as *const () as usize;
            assert_ne!(
                sym as usize, fl,
                "resolved swprintf IS fl's own (bd-v0388t)"
            );
            Some(sym as usize)
        }
    }))
    .expect("glibc swprintf must resolve");
    // SAFETY: the address came from dlsym on glibc's swprintf.
    unsafe { std::mem::transmute::<usize, HostSwprintf>(addr) }
}

fn wide(text: &str) -> Vec<u32> {
    text.chars()
        .map(|c| c as u32)
        .chain(std::iter::once(0))
        .collect()
}

fn render_wide(buf: &[u32]) -> String {
    buf.iter()
        .take_while(|&&c| c != 0)
        .filter_map(|&c| char::from_u32(c))
        .collect()
}

/// Both arms of a wide format carrying a long double and a trailing int.
fn both_wide(fmt: &str, value: &[u8; 16], trailing: c_int) -> (String, String) {
    let fmt_w = wide(fmt);
    let mut host_buf = [0u32; 8192];
    let mut fl_buf = [0u32; 8192];
    // SAFETY: 8192 wide chars each; sixteen readable value bytes. swprintf has
    // the same register layout as snprintf, so the same trampoline applies.
    unsafe {
        call_snprintf_ld_then_int(
            host_buf.as_mut_ptr().cast::<c_char>(),
            host_buf.len(),
            fmt_w.as_ptr().cast::<c_char>(),
            value.as_ptr(),
            trailing,
            std::mem::transmute::<HostSwprintf, HostSnprintf>(host_swprintf()),
        );
        call_snprintf_ld_then_int(
            fl_buf.as_mut_ptr().cast::<c_char>(),
            fl_buf.len(),
            fmt_w.as_ptr().cast::<c_char>(),
            value.as_ptr(),
            trailing,
            std::mem::transmute::<*const (), HostSnprintf>(
                frankenlibc_abi::wchar_abi::swprintf as *const (),
            ),
        );
    }
    (render_wide(&host_buf), render_wide(&fl_buf))
}

/// The wide extraction macro is a separate copy of the same logic, so it had
/// the same bug and needs its own arm — fixing the narrow side proves nothing
/// about this one.
#[test]
fn wide_long_double_matches_live_glibc() {
    let value = x87(b"125", -1, false);
    for fmt in ["%.2Lf|%d", "%Lf %d", "%.1Lf[%d]"] {
        let (host, fl) = both_wide(fmt, &value, 4242);
        assert_eq!(fl, host, "wide argument stream diverges for {fmt:?}");
        assert!(
            fl.contains("4242"),
            "the trailing int was lost for wide {fmt:?}: {fl:?}"
        );
        assert!(
            fl.contains("12.5"),
            "the long double was misread for wide {fmt:?}: {fl:?}"
        );
    }
}

/// The wide extractor has its own copy of the plan loop, so it needs its own
/// positional arm for the same reason the sequential wide arm exists.
#[test]
fn wide_positional_long_double_reads_its_own_argument() {
    let value = x87(b"125", -1, false);
    for fmt in ["%1$.2Lf|%2$d", "%2$d[%1$.1Lf]"] {
        let (host, fl) = both_wide(fmt, &value, 4242);
        assert_eq!(
            fl, host,
            "wide positional argument stream diverges for {fmt:?}"
        );
        assert!(
            fl.contains("4242"),
            "the positional int was lost for wide {fmt:?}: {fl:?}"
        );
        assert!(
            fl.contains("12.5"),
            "the positional long double was misread for wide {fmt:?}: {fl:?}"
        );
    }
}

// ---------------------------------------------------------------------------
// PRECISION. Everything above uses values an `f64` holds exactly — 1, 12.5,
// 0.5, 3, 100 — which is why those arms passed while `%Lf` still rendered its
// argument as a `double`. The extracted-argument buffer is one `u64` per
// argument, so the eighty-bit value was rounded on the way in; the slot now
// carries the argument's ADDRESS and the renderer widens from the caller's own
// bytes. bd-longdouble-varargs-43usjw.
// ---------------------------------------------------------------------------

/// Values that no `f64` can hold, as x87 bytes.
///
/// The first three need more than 53 significand bits; the last three are
/// outside `f64`'s exponent range entirely, where a round trip does not merely
/// round — `1e400` is an ordinary finite `long double` and an `f64` infinity.
fn beyond_f64() -> Vec<(&'static str, [u8; 16])> {
    vec![
        (
            "pi",
            x87(b"314159265358979323846264338327950288", -35, false),
        ),
        (
            "e",
            x87(b"271828182845904523536028747135266250", -35, false),
        ),
        (
            "-pi",
            x87(b"314159265358979323846264338327950288", -35, true),
        ),
        ("2^64+1", x87(b"18446744073709551617", 0, false)),
        ("1e400", x87(b"1", 400, false)),
        ("1e-400", x87(b"1", -400, false)),
        ("1e4000", x87(b"1", 4000, false)),
    ]
}

/// INSTRUMENT ARM. Every comparison below would still pass if the oracle had
/// quietly become `f64`-shaped, so pin on GLIBC ALONE that it has not: `%.25Lf`
/// of pi must differ from the `f64` rounding of pi, and `1e400` must not be an
/// infinity. Without this the precision arms are vacuous.
#[test]
fn the_oracle_carries_more_than_f64_precision() {
    let (host, _fl) = both(
        "%.25Lf",
        &x87(b"314159265358979323846264338327950288", -35, false),
    );
    assert_eq!(
        host, "3.1415926535897932385128090",
        "live glibc's own answer changed — the expectations below are read \
         from it, so nothing can be concluded until this is understood"
    );
    assert_ne!(
        host,
        format!("{:.25}", std::f64::consts::PI),
        "the oracle is rendering pi at f64 precision, so a comparison against \
         it cannot detect the defect this file exists for"
    );
    let (host, _fl) = both("%Le", &x87(b"1", 400, false));
    assert_eq!(
        host, "1.000000e+400",
        "1e400 is a finite long double; an oracle answering inf has narrowed"
    );
}

/// `%Lf`/`%Le`/`%Lg` must carry the argument's own precision and range.
#[test]
fn long_double_precision_matches_live_glibc() {
    for (name, value) in beyond_f64() {
        for fmt in [
            "%.25Lf",
            "%.30Le",
            "%.30Lg",
            "%.21Lg",
            "%Lf",
            "%Le",
            "%Lg",
            "%.0Lf",
            "%LF",
            "%LE",
            "%LG",
            "%+.20Lg",
            "%#.0Lf",
            "%30.20Le",
            "%-30.20Le|",
        ] {
            let (host, fl) = both(fmt, &value);
            assert_eq!(fl, host, "{fmt} of {name}");
        }
    }
}

/// The same values with a conversion AFTER them: precision and the argument
/// stream are independent, and this file has already been burned once by a
/// format that ended at the `%Lf`.
#[test]
fn precision_does_not_disturb_the_argument_stream() {
    for (name, value) in beyond_f64() {
        for fmt in ["%.25Lf|%d", "%.30Le %d", "%1$.28Lg[%2$d]"] {
            let (host, fl) = both_with_trailing(fmt, &value, 4242);
            assert_eq!(fl, host, "{fmt} of {name}");
            assert!(fl.contains("4242"), "trailing int lost: {fmt} of {name}");
        }
    }
}

/// `%La` renders the ENCODING, and glibc renders a long double's from the x87
/// significand: `0xc.90fdaa22168c235p-2` for pi, where the same value widened
/// to binary128 and printed in the `0x1.<...>` form would be
/// `0x1.921fb54442d18468p+1`. Equal numbers, different strings.
#[test]
fn long_double_hex_matches_live_glibc() {
    let mut values = beyond_f64();
    values.push(("1.0", x87(b"1", 0, false)));
    values.push(("12.5", x87(b"125", -1, false)));
    values.push(("0.0", x87(b"0", 0, false)));
    values.push(("0.1", x87(b"1", -1, false)));
    for (name, value) in values {
        for fmt in ["%La", "%LA", "%.0La", "%.1La", "%.3La", "%.20La", "%#.0La"] {
            let (host, fl) = both(fmt, &value);
            assert_eq!(fl, host, "{fmt} of {name}");
        }
    }
}

/// The wide side reaches the same renderer, but through `wchar_abi`'s own copy
/// of the extractor — the copy that stayed broken for a day after the narrow
/// one was fixed (e9e2f45c1). It gets its own precision arm for that reason.
#[test]
fn wide_long_double_precision_matches_live_glibc() {
    for (name, value) in beyond_f64() {
        for fmt in ["%.25Lf|%d", "%.30Le %d", "%La[%d]"] {
            let (host, fl) = both_wide(fmt, &value, 4242);
            assert_eq!(fl, host, "wide {fmt} of {name}");
            assert!(
                fl.contains("4242"),
                "trailing int lost: wide {fmt} of {name}"
            );
        }
    }
}
