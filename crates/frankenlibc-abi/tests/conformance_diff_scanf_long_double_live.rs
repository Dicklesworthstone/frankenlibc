#![cfg(all(target_os = "linux", target_arch = "x86_64"))]
#![allow(unsafe_code)] // live glibc sscanf/swscanf oracles via dlsym

//! `sscanf("%Lf")` against the LIVE glibc — the whole x87 value, byte for byte.
//!
//! ## The defect this gate exists for
//!
//! `%Lf` stores a `long double`, and fl's scanf engine parsed EVERY float to
//! `f64` before the ABI writer saw it. The writer then widened that `f64` to
//! x87, which cannot recover what the parse had already discarded:
//!
//! ```text
//!   sscanf("1.0000000000000000001", "%Lf", &ld)   stored exactly 1.0
//!   sscanf("1e400",                 "%Lf", &ld)   stored +inf
//! ```
//!
//! The second is the loud one — `1e400` is an ordinary finite `long double`
//! (the format reaches ~1.19e4932) and the f64 round trip turned it into
//! infinity. Precision loss and range loss are the same defect: the value was
//! fixed at 53 bits and 11 exponent bits before anything long-double-shaped was
//! involved.
//!
//! ## Why the comparison is on BYTES
//!
//! Rust has no `long double`, so there is no value type to compare. Comparing
//! rendered decimal would fold the two libraries' *printf* through the gate as
//! well, and a printf bug could mask a scanf one (or invent one). The ten
//! significant bytes of the x87 encoding are the object glibc's scanf actually
//! wrote, so they are what gets compared; the six padding bytes of the 16-byte
//! storage slot are deliberately NOT compared, because a C store writes only
//! ten and what sits in the rest is not part of the value.
//!
//! ## The instrument arms come first
//!
//! [`the_oracle_carries_more_than_f64_precision`] asserts on GLIBC's answers
//! alone. Without it, every value comparison here would still pass if the
//! oracle had silently collapsed to something f64-shaped — which is the exact
//! failure the whole gate is about. It is the positive control for the premise.

use std::ffi::{CStr, CString, c_char, c_int, c_void};

#[path = "common/dlsym_oracle.rs"]
mod dlsym_oracle;
use dlsym_oracle::host_fn;

type SscanfFn = unsafe extern "C" fn(*const c_char, *const c_char, ...) -> c_int;
type SwscanfFn = unsafe extern "C" fn(*const libc::wchar_t, *const libc::wchar_t, ...) -> c_int;

/// A `long double` destination.
///
/// 16 bytes with 16-byte alignment is what x86-64 SysV gives the type, and the
/// alignment is not cosmetic: `fstpt` to a misaligned slot is legal but the
/// surrounding assumptions in both libraries are written for the real object.
/// Pre-filled with a poison byte so an untouched slot is visible as such rather
/// than reading as a plausible zero.
#[repr(C, align(16))]
#[derive(Clone, Copy)]
struct LongDouble([u8; 16]);

impl LongDouble {
    const POISON: u8 = 0x5a;

    fn poisoned() -> Self {
        LongDouble([Self::POISON; 16])
    }

    /// The ten bytes that are the value. See the module docs for why the
    /// padding is excluded.
    fn significant(&self) -> [u8; 10] {
        let mut out = [0u8; 10];
        out.copy_from_slice(&self.0[..10]);
        out
    }

    fn untouched(&self) -> bool {
        self.0[..10].iter().all(|&b| b == Self::POISON)
    }
}

fn hex(bytes: &[u8; 10]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

fn host_sscanf() -> SscanfFn {
    // SAFETY: the C declaration of `sscanf` is `int(const char*, const char*, ...)`.
    unsafe {
        host_fn(
            c"sscanf",
            frankenlibc_abi::stdio_abi::sscanf as *const (),
        )
    }
}

fn host_swscanf() -> SwscanfFn {
    // SAFETY: `int(const wchar_t*, const wchar_t*, ...)`.
    unsafe {
        host_fn(
            c"swscanf",
            frankenlibc_abi::wchar_abi::swscanf as *const (),
        )
    }
}

/// Scan one long double with `f`, returning `(rc, slot)`.
///
/// # Safety
///
/// `f` must be a `sscanf`-shaped variadic entry point.
unsafe fn scan_one(f: SscanfFn, input: &str, format: &str) -> (c_int, LongDouble) {
    let cin = CString::new(input).expect("input has an interior NUL");
    let cfmt = CString::new(format).expect("format has an interior NUL");
    let mut slot = LongDouble::poisoned();
    // SAFETY: the formats used here have exactly one conversion and it is
    // `%Lf`, whose destination is the `long double *` supplied.
    let rc = unsafe {
        f(
            cin.as_ptr(),
            cfmt.as_ptr(),
            (&raw mut slot).cast::<c_void>(),
        )
    };
    (rc, slot)
}

fn wide(s: &str) -> Vec<libc::wchar_t> {
    let mut v: Vec<libc::wchar_t> = s.chars().map(|c| c as u32 as libc::wchar_t).collect();
    v.push(0);
    v
}

/// # Safety
///
/// `f` must be a `swscanf`-shaped variadic entry point.
unsafe fn scan_one_wide(f: SwscanfFn, input: &str, format: &str) -> (c_int, LongDouble) {
    let win = wide(input);
    let wfmt = wide(format);
    let mut slot = LongDouble::poisoned();
    // SAFETY: one `%Lf` conversion, one `long double *`.
    let rc = unsafe {
        f(
            win.as_ptr(),
            wfmt.as_ptr(),
            (&raw mut slot).cast::<c_void>(),
        )
    };
    (rc, slot)
}

/// Inputs whose correctly-rounded `long double` differs from the f64 round
/// trip, plus the ordinary cases that must not regress.
///
/// Each row is `(input, why it is here)`. The "why" is printed on failure, so a
/// red row says which property broke rather than only which bytes differ.
const CASES: &[(&str, &str)] = &[
    // --- beyond f64's SIGNIFICAND: the digits an f64 parse throws away ---
    ("1.0000000000000000001", "64-bit significand: f64 rounds this to exactly 1.0"),
    ("1.00000000000000000011", "one more digit of the same"),
    ("3.14159265358979323846", "pi to long-double precision"),
    ("2.71828182845904523536", "e to long-double precision"),
    ("-1.0000000000000000001", "the same, negative"),
    ("0.10000000000000000001", "a fraction f64 cannot separate from 0.1"),
    ("18446744073709551617", "2^64+1: exact in x87, not in f64"),
    // --- beyond f64's EXPONENT: range loss, not precision loss ---
    ("1e400", "finite long double; an f64 parse gives +inf"),
    ("-1e400", "the same, negative"),
    ("1e4000", "still finite: the format reaches ~1.19e4932"),
    ("1e-400", "normal long double; an f64 parse underflows to 0"),
    ("1e-4000", "long-double subnormal; an f64 parse gives 0"),
    // --- hex floats: more significand bits than f64 holds ---
    ("0x1.23456789abcdefp+0", "60 significand bits through the hex path"),
    ("0x1fffffffffffffffp0", "65 bits: f64 must round, x87 need not"),
    ("0x1p-16400", "hex subnormal at the bottom of the format"),
    ("-0x0.8p+1", "hex with a fractional part and a sign"),
    // --- the specials, which must not become collateral damage ---
    ("inf", "infinity keyword"),
    ("-inf", "signed infinity"),
    ("infinity", "the long spelling"),
    ("nan", "quiet NaN — integer bit set, not a pseudo-NaN"),
    ("-nan", "signed NaN"),
    ("nan(0x10)", "an n-char-sequence payload, parsed base-0"),
    // --- ordinary values: the regression guard for the common path ---
    ("1", "an integer with no point at all"),
    ("0", "zero"),
    ("-0.0", "negative zero keeps its sign"),
    ("125e-1", "an exponent on a value f64 represents exactly"),
    ("  42.5", "leading whitespace is skipped"),
    ("7.25xyz", "trailing garbage ends the token"),
];

/// GLIBC ALONE: the oracle really carries 80-bit values.
///
/// If this fails, nothing else in this file means anything — every comparison
/// would be against an arm that had quietly become f64-shaped, and would pass
/// for the wrong reason. Asserting on glibc's own answers is what separates
/// "fl agrees with glibc" from "fl agrees with a broken probe".
#[test]
fn the_oracle_carries_more_than_f64_precision() {
    let host = host_sscanf();

    // SAFETY: one `%Lf`, one destination, for each call below.
    let (rc_one, one) = unsafe { scan_one(host, "1", "%Lf") };
    let (rc_eps, eps) = unsafe { scan_one(host, "1.0000000000000000001", "%Lf") };
    assert_eq!((rc_one, rc_eps), (1, 1), "glibc must convert both inputs");
    assert!(!one.untouched() && !eps.untouched(), "glibc wrote nothing");
    assert_ne!(
        hex(&one.significant()),
        hex(&eps.significant()),
        "glibc gave the SAME bytes for 1 and 1.0000000000000000001 — the oracle \
         is not carrying more than f64 precision, so this gate cannot detect the \
         defect it exists for"
    );

    // Range, the other half. An f64 parse of 1e400 is +inf; a long double's is
    // an ordinary finite number, and the two are trivially distinguishable.
    let (rc, big) = unsafe { scan_one(host, "1e400", "%Lf") };
    assert_eq!(rc, 1, "glibc must convert 1e400");
    let exponent = u16::from_le_bytes([big.0[8], big.0[9]]) & 0x7fff;
    assert_ne!(
        exponent, 0x7fff,
        "glibc made 1e400 an infinity — the oracle is f64-ranged and the range \
         half of this gate would pass vacuously"
    );
}

/// fl's `%Lf` must store the bytes glibc's `%Lf` stores.
#[test]
fn long_double_values_match_live_glibc() {
    let host = host_sscanf();
    let fl = frankenlibc_abi::stdio_abi::sscanf as SscanfFn;
    let mut failures = Vec::new();

    for (input, why) in CASES {
        // SAFETY: one `%Lf` conversion, one `long double *`, both arms.
        let (rc_host, host_slot) = unsafe { scan_one(host, input, "%Lf") };
        // SAFETY: as above.
        let (rc_fl, fl_slot) = unsafe { scan_one(fl, input, "%Lf") };

        if rc_host != rc_fl {
            failures.push(format!("{input:?} ({why}): rc fl={rc_fl} glibc={rc_host}"));
            continue;
        }
        if rc_host != 1 {
            continue; // no conversion: neither library wrote anything to compare
        }
        let (h, f) = (host_slot.significant(), fl_slot.significant());
        if h != f {
            failures.push(format!(
                "{input:?} ({why}): fl={} glibc={}",
                hex(&f),
                hex(&h)
            ));
        }
    }

    assert!(
        failures.is_empty(),
        "sscanf %Lf diverges from live glibc on {} of {} inputs:\n  {}",
        failures.len(),
        CASES.len(),
        failures.join("\n  ")
    );
}

/// The narrow fix must not have moved `%f` or `%lf`.
///
/// `%Lf` now leaves the engine as an x87 value rather than an `f64`, and the
/// two shorter conversions share every line of the parser with it. This arm is
/// what says the change was confined to the length modifier it was aimed at.
#[test]
fn plain_float_conversions_are_unchanged() {
    let host = host_sscanf();
    let fl = frankenlibc_abi::stdio_abi::sscanf as SscanfFn;
    let mut failures = Vec::new();

    for (input, why) in CASES {
        for (format, width) in [("%f", 4usize), ("%lf", 8usize)] {
            let cin = CString::new(*input).expect("interior NUL");
            let cfmt = CString::new(format).expect("interior NUL");
            let mut host_slot = LongDouble::poisoned();
            let mut fl_slot = LongDouble::poisoned();
            // SAFETY: `%f` writes a `float` and `%lf` a `double`; the 16-byte
            // aligned slot is large enough for either.
            let rc_host = unsafe {
                host(
                    cin.as_ptr(),
                    cfmt.as_ptr(),
                    (&raw mut host_slot).cast::<c_void>(),
                )
            };
            // SAFETY: as above.
            let rc_fl = unsafe {
                fl(
                    cin.as_ptr(),
                    cfmt.as_ptr(),
                    (&raw mut fl_slot).cast::<c_void>(),
                )
            };
            if rc_host != rc_fl {
                failures.push(format!(
                    "{input:?} {format} ({why}): rc fl={rc_fl} glibc={rc_host}"
                ));
                continue;
            }
            if rc_host != 1 {
                continue;
            }
            if host_slot.0[..width] != fl_slot.0[..width] {
                failures.push(format!(
                    "{input:?} {format} ({why}): fl={:02x?} glibc={:02x?}",
                    &fl_slot.0[..width],
                    &host_slot.0[..width]
                ));
            }
        }
    }

    assert!(
        failures.is_empty(),
        "%f/%lf diverge from live glibc on {} rows:\n  {}",
        failures.len(),
        failures.join("\n  ")
    );
}

/// A conversion AFTER the long double must read its own argument.
///
/// scanf takes POINTERS, so there is no stack-slot desync of the kind that
/// makes printf's `%Lf` corrupt the rest of its format — but the destination
/// WIDTH is a different hazard: writing eight bytes where a `long double` was
/// promised, or sixteen where a `double` was, is a silent overrun of the
/// neighbouring object. Two conversions with a trailing sentinel is what
/// detects it.
#[test]
fn a_conversion_after_a_long_double_writes_its_own_object() {
    let host = host_sscanf();
    let fl = frankenlibc_abi::stdio_abi::sscanf as SscanfFn;

    #[repr(C, align(16))]
    struct Pair {
        value: LongDouble,
        trailing: c_int,
    }

    let mut out = Vec::new();
    for f in [host, fl] {
        let cin = CString::new("3.5 4242").expect("interior NUL");
        let cfmt = CString::new("%Lf %d").expect("interior NUL");
        let mut pair = Pair {
            value: LongDouble::poisoned(),
            trailing: -1,
        };
        // SAFETY: two conversions, two destinations of the promised types.
        let rc = unsafe {
            f(
                cin.as_ptr(),
                cfmt.as_ptr(),
                (&raw mut pair.value).cast::<c_void>(),
                (&raw mut pair.trailing).cast::<c_void>(),
            )
        };
        out.push((rc, pair.value.significant(), pair.trailing));
    }

    assert_eq!(out[0].0, 2, "glibc must convert both fields");
    assert_eq!(out[0].2, 4242, "glibc must read the trailing int");
    assert_eq!(
        (out[1].0, hex(&out[1].1), out[1].2),
        (out[0].0, hex(&out[0].1), out[0].2),
        "fl diverges from glibc on `%Lf %d`"
    );
}

/// The wide side reaches the same engine, and must land the same bytes.
///
/// `wchar_abi` carries its OWN copy of the scanf writer — that is how the wide
/// `%Lf` store stayed broken for a day after the narrow one was fixed
/// (0eb086f31). A green narrow arm says nothing about this one.
#[test]
fn wide_long_double_matches_live_glibc() {
    let host = host_swscanf();
    let fl = frankenlibc_abi::wchar_abi::swscanf as SwscanfFn;
    let mut failures = Vec::new();

    for (input, why) in CASES {
        // SAFETY: one `%Lf`, one `long double *`, both arms.
        let (rc_host, host_slot) = unsafe { scan_one_wide(host, input, "%Lf") };
        // SAFETY: as above.
        let (rc_fl, fl_slot) = unsafe { scan_one_wide(fl, input, "%Lf") };

        if rc_host != rc_fl {
            failures.push(format!("{input:?} ({why}): rc fl={rc_fl} glibc={rc_host}"));
            continue;
        }
        if rc_host != 1 {
            continue;
        }
        let (h, f) = (host_slot.significant(), fl_slot.significant());
        if h != f {
            failures.push(format!(
                "{input:?} ({why}): fl={} glibc={}",
                hex(&f),
                hex(&h)
            ));
        }
    }

    assert!(
        failures.is_empty(),
        "swscanf %Lf diverges from live glibc on {} of {} inputs:\n  {}",
        failures.len(),
        CASES.len(),
        failures.join("\n  ")
    );
}

/// `vsscanf` reaches a SECOND writer — `vscanf_write_one`, not the macro.
///
/// The two write paths are separate code with separate match arms, and this
/// library has already been burned twice by fixing one copy of a scanf/printf
/// writer and assuming the others followed (the wide side, then err/warn). A
/// green variadic arm says nothing about this one.
///
/// The va_list is hand-built with every argument in the overflow area, which is
/// the technique `conformance_diff_vsscanf_fast_paths` established: `gp_offset`
/// 48 and `fp_offset` 304 mark all the argument registers consumed, so every
/// fetch reads a slot supplied here.
#[test]
fn the_va_list_writer_matches_live_glibc() {
    type VsscanfFn = unsafe extern "C" fn(*const c_char, *const c_char, *mut c_void) -> c_int;

    /// An x86_64 `__va_list_tag` whose arguments all live in the overflow area.
    #[repr(C)]
    struct VaListTag {
        gp_offset: u32,
        fp_offset: u32,
        overflow_arg_area: *mut c_void,
        reg_save_area: *mut c_void,
    }

    // SAFETY: `int(const char*, const char*, va_list)`.
    let host: VsscanfFn =
        unsafe { host_fn(c"vsscanf", frankenlibc_abi::stdio_abi::vsscanf as *const ()) };
    let fl = frankenlibc_abi::stdio_abi::vsscanf as VsscanfFn;

    let mut failures = Vec::new();
    for (input, why) in CASES {
        let mut out = Vec::new();
        for f in [host, fl] {
            let cin = CString::new(*input).expect("interior NUL");
            let cfmt = CString::new("%Lf").expect("interior NUL");
            let mut slot = LongDouble::poisoned();
            let mut slots: [*mut c_void; 1] = [(&raw mut slot).cast()];
            let mut tag = VaListTag {
                gp_offset: 48,
                fp_offset: 304,
                overflow_arg_area: slots.as_mut_ptr().cast(),
                reg_save_area: std::ptr::null_mut(),
            };
            // SAFETY: the tag describes a va_list holding exactly the one
            // `long double *` that `%Lf` consumes.
            let rc = unsafe { f(cin.as_ptr(), cfmt.as_ptr(), (&raw mut tag).cast()) };
            out.push((rc, slot.significant()));
        }
        if out[0].0 != out[1].0 {
            failures.push(format!(
                "{input:?} ({why}): rc fl={} glibc={}",
                out[1].0, out[0].0
            ));
            continue;
        }
        if out[0].0 != 1 {
            continue;
        }
        if out[0].1 != out[1].1 {
            failures.push(format!(
                "{input:?} ({why}): fl={} glibc={}",
                hex(&out[1].1),
                hex(&out[0].1)
            ));
        }
    }

    assert!(
        failures.is_empty(),
        "vsscanf %Lf diverges from live glibc on {} of {} inputs:\n  {}",
        failures.len(),
        CASES.len(),
        failures.join("\n  ")
    );
}

/// Names in the failure messages above must be real.
#[test]
fn the_oracle_symbols_resolve_to_glibc() {
    for (name, fl) in [
        (
            c"sscanf",
            frankenlibc_abi::stdio_abi::sscanf as *const (),
        ),
        (
            c"swscanf",
            frankenlibc_abi::wchar_abi::swscanf as *const (),
        ),
    ] {
        // SAFETY: NUL-terminated constant names; the helper only resolves them.
        let addr = unsafe { dlsym_oracle::host_addr(name, fl) };
        assert!(
            !addr.is_null(),
            "{:?} did not resolve in host glibc",
            <&CStr>::clone(&name)
        );
    }
}
