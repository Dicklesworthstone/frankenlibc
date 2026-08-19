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

use std::ffi::{CStr, CString, c_char, c_int, c_void};
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
    let mut host_buf = [0 as c_char; 512];
    let mut fl_buf = [0 as c_char; 512];
    // SAFETY: 512 writable bytes each; sixteen readable value bytes.
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
    let mut host_buf = [0 as c_char; 512];
    let mut fl_buf = [0 as c_char; 512];
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
