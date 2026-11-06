#![cfg(target_os = "linux")]
#![feature(f128)]
#![allow(unsafe_code)]
use frankenlibc_abi::{errno_abi, stdlib_abi as fl};
use std::ffi::{CString, c_char, c_int};

#[path = "common/dlsym_oracle.rs"]
mod dlsym_oracle;

type Errno = unsafe extern "C" fn() -> *mut c_int;
type ParseDouble = unsafe extern "C" fn(*const c_char, *mut *mut c_char) -> f64;

// Each implementation owns a distinct errno location in the integration build.
fn parse(engine: ParseDouble, errno: Errno, s: &CString) -> (u64, isize, i32) {
    let mut end: *mut c_char = std::ptr::null_mut();
    // SAFETY: the function pointers have the public C signatures, the input
    // is terminated, and the end pointer storage is writable.
    let (v, e) = unsafe {
        *errno() = 0;
        let value = engine(s.as_ptr(), &mut end);
        (value, *errno())
    };
    let consumed = (end as isize) - (s.as_ptr() as isize);
    // NaN payloads/signs are unspecified across impls — canonicalize to one NaN.
    let bits = if v.is_nan() {
        f64::NAN.to_bits()
    } else {
        v.to_bits()
    };
    (
        bits,
        consumed,
        if e == libc::ERANGE { libc::ERANGE } else { 0 },
    )
}

#[test]
fn strtod_edge_parity_vs_glibc() {
    // SAFETY: host_fn validates that neither oracle resolves to the native
    // definition; both function types match their C declarations.
    let (host_parse, host_errno): (ParseDouble, Errno) = unsafe {
        (
            dlsym_oracle::host_fn(c"strtod", fl::strtod as *const ()),
            dlsym_oracle::host_fn(
                c"__errno_location",
                errno_abi::__errno_location as *const (),
            ),
        )
    };
    let inputs: &[&str] = &[
        // basics
        "0",
        "-0",
        "1",
        "-1",
        "3.14159265358979323846",
        "  42.5xyz",
        "1e10",
        "1E-10",
        // hex floats
        "0x1p0",
        "0x1.8p1",
        "-0x1.fffffffffffffp+1023",
        "0x1p-1074",
        "0X1.0P0",
        "0x0.0000000000001p-1022",
        "0x1.0000000000001p0",
        "0xAbCp-4",
        // round-to-even ties (17-digit boundary)
        "1.0000000000000002",
        "0.99999999999999994",
        "2.2250738585072014e-308",
        "9007199254740993",
        "9007199254740992.5",
        // overflow / underflow (ERANGE)
        "1e309",
        "-1e309",
        "1e-400",
        "-1e-400",
        "1e-323",
        "4.9406564584124654e-324",
        "1.7976931348623159e308",
        "1e1000000",
        "1e-1000000",
        // subnormal round boundaries
        "2.4703282292062327e-324",
        "2.4703282292062328e-324",
        "7.4109846876186981e-323",
        // specials
        "inf",
        "-inf",
        "infinity",
        "INFINITY",
        "nan",
        "-nan",
        "NAN",
        "nan(123)",
        "nan(0xff)",
        // whitespace / signs / junk
        "   \t  -3.5",
        "+.5",
        ".5",
        "5.",
        "+",
        "-",
        ".",
        "e5",
        "0x",
        "1.5e",
        "1.5e+",
        // very long digit strings (precision stress)
        "0.10000000000000000000000000000000000000001",
        "12345678901234567890123456789012345678901234567890e-50",
        // leading zeros, exponent edges
        "000123.456",
        "1e+00",
        "0e0",
        "0.0e999999",
    ];
    let mut div = Vec::new();
    for s in inputs {
        let cs = CString::new(*s).unwrap();
        let (fb, fc, fe) = parse(fl::strtod, errno_abi::__errno_location, &cs);
        let (gb, gc, ge) = parse(host_parse, host_errno, &cs);
        if fb != gb || fc != gc || fe != ge {
            div.push(format!(
                "strtod({s:?}): fl=(bits {fb:#018x}={:?}, consumed {fc}, errno {fe}) glibc=(bits {gb:#018x}={:?}, consumed {gc}, errno {ge})",
                f64::from_bits(fb), f64::from_bits(gb)
            ));
        }
    }
    if !div.is_empty() {
        eprintln!("STRTOD EDGE DIVERGENCES ({}):", div.len());
        for d in div.iter().take(120) {
            eprintln!("  {d}");
        }
    }
    assert!(
        div.is_empty(),
        "{} strtod edge divergences vs glibc",
        div.len()
    );
}

/// Exercise the actual ABI under each rounding mode. Expected values and
/// exception state come from independently resolved GNU entry points; no
/// host parser or host errno location is used for the native observation.
#[cfg(target_arch = "x86_64")]
mod directed_rounding {
    use super::Errno;
    use super::dlsym_oracle::{host_addr, host_fn};
    use frankenlibc_abi::{
        errno_abi, fenv_abi, glibc_internal_abi as floatn, locale_abi as locale,
        stdlib_abi as narrow, wchar_abi as wide,
    };
    use std::ffi::{CString, c_char, c_int, c_void};

    type Narrow<T> = unsafe extern "C" fn(*const c_char, *mut *mut c_char) -> T;
    type Wide<T> = unsafe extern "C" fn(*const i32, *mut *mut i32) -> T;
    type SetRound = unsafe extern "C" fn(c_int) -> c_int;
    type GetRound = unsafe extern "C" fn() -> c_int;
    type Exceptions = unsafe extern "C" fn(c_int) -> c_int;
    type SaveEnv = unsafe extern "C" fn(*mut c_void) -> c_int;
    type RestoreEnv = unsafe extern "C" fn(*const c_void) -> c_int;
    type Locale = *mut c_void;
    type NewLocale = unsafe extern "C" fn(c_int, *const c_char, Locale) -> Locale;
    type UseLocale = unsafe extern "C" fn(Locale) -> Locale;
    type FreeLocale = unsafe extern "C" fn(Locale);

    // glibc x86-64's standard exception mask omits the nonstandard denormal
    // operand bit. Every test masks traps and restores the complete original
    // environment afterward; unmasked trap delivery is not qualified here.
    const FE_ALL_EXCEPT: c_int = 0x3d;
    const FE_DIVBYZERO: c_int = 0x04;
    const ERRNO_SENTINEL: c_int = 12345;
    const MODES: [c_int; 4] = [0, 0x400, 0x800, 0xc00];

    #[repr(C, align(16))]
    struct SavedEnv([u8; 128]);

    struct Environment {
        saved: SavedEnv,
        restore: RestoreEnv,
        set_round: SetRound,
        get_round: GetRound,
        clear: Exceptions,
        raise: Exceptions,
        test: Exceptions,
    }

    impl Environment {
        fn hold() -> Self {
            // SAFETY: each pointer has the symbol's public C signature and
            // host_fn checks independence from the native implementation.
            let (save, restore, set_round, get_round, clear, raise, test): (
                SaveEnv,
                RestoreEnv,
                SetRound,
                GetRound,
                Exceptions,
                Exceptions,
                Exceptions,
            ) = unsafe {
                (
                    host_fn(c"feholdexcept", fenv_abi::feholdexcept as *const ()),
                    host_fn(c"fesetenv", fenv_abi::fesetenv as *const ()),
                    host_fn(c"fesetround", fenv_abi::fesetround as *const ()),
                    host_fn(c"fegetround", fenv_abi::fegetround as *const ()),
                    host_fn(c"feclearexcept", fenv_abi::feclearexcept as *const ()),
                    host_fn(c"feraiseexcept", fenv_abi::feraiseexcept as *const ()),
                    host_fn(c"fetestexcept", fenv_abi::fetestexcept as *const ()),
                )
            };
            let mut saved = SavedEnv([0; 128]);
            // SAFETY: the aligned writable buffer is larger than glibc's
            // x86-64 fenv_t. feholdexcept saves state and masks all traps.
            assert_eq!(unsafe { save((&raw mut saved).cast()) }, 0);
            Self {
                saved,
                restore,
                set_round,
                get_round,
                clear,
                raise,
                test,
            }
        }

        fn prepare(&self, seeded_flags: c_int) {
            // SAFETY: these are valid standard exception masks. Traps were
            // masked by hold(), so raising the seed cannot signal the test.
            unsafe {
                assert_eq!((self.clear)(FE_ALL_EXCEPT), 0);
                assert_eq!((self.raise)(seeded_flags), 0);
                assert_eq!((self.test)(FE_ALL_EXCEPT), seeded_flags);
            }
        }
    }

    impl Drop for Environment {
        fn drop(&mut self) {
            // SAFETY: the saved record came from feholdexcept in this thread.
            // Restore rounding, masks, precision, and sticky flags on panic too.
            unsafe {
                (self.restore)((&raw const self.saved).cast());
            }
        }
    }

    struct CLocale {
        native: Locale,
        host: Locale,
        native_previous: Locale,
        host_previous: Locale,
        host_select: UseLocale,
        host_free: FreeLocale,
    }

    impl CLocale {
        fn select() -> Self {
            // SAFETY: signatures match the public locale APIs. Each library
            // creates its own handle; their internal object layouts may differ.
            let (host_new, host_select, host_free): (NewLocale, UseLocale, FreeLocale) = unsafe {
                (
                    host_fn(c"newlocale", locale::newlocale as *const ()),
                    host_fn(c"uselocale", locale::uselocale as *const ()),
                    host_fn(c"freelocale", locale::freelocale as *const ()),
                )
            };
            unsafe {
                let native =
                    locale::newlocale(libc::LC_ALL_MASK, c"C".as_ptr(), std::ptr::null_mut());
                let host = host_new(libc::LC_ALL_MASK, c"C".as_ptr(), std::ptr::null_mut());
                assert!(!native.is_null() && !host.is_null());
                let native_previous = locale::uselocale(native);
                let host_previous = host_select(host);
                assert!(!native_previous.is_null() && !host_previous.is_null());
                Self {
                    native,
                    host,
                    native_previous,
                    host_previous,
                    host_select,
                    host_free,
                }
            }
        }
    }

    impl Drop for CLocale {
        fn drop(&mut self) {
            // SAFETY: restore both per-thread selections before releasing the
            // corresponding live handles. No process-global locale is changed.
            unsafe {
                locale::uselocale(self.native_previous);
                (self.host_select)(self.host_previous);
                locale::freelocale(self.native);
                (self.host_free)(self.host);
            }
        }
    }

    #[derive(Clone, Copy)]
    enum Conversion {
        Narrow32(Narrow<f32>),
        Narrow64(Narrow<f64>),
        Narrow80(*const ()),
        Narrow128(Narrow<f128>),
        Wide32(Wide<f32>),
        Wide64(Wide<f64>),
        Wide80(*const ()),
        Wide128(Wide<f128>),
    }

    struct Parser {
        name: &'static str,
        native: Conversion,
        host: Conversion,
    }

    fn parsers() -> Vec<Parser> {
        let mut parsers = Vec::new();
        macro_rules! typed {
            ($variant:ident, $native:path, $symbol:literal) => {
                parsers.push(Parser {
                    name: stringify!($native),
                    native: Conversion::$variant($native),
                    // SAFETY: the enum variant fixes the exact C signature.
                    host: Conversion::$variant(unsafe { host_fn($symbol, $native as *const ()) }),
                });
            };
        }
        macro_rules! x87 {
            ($variant:ident, $native:path, $symbol:literal) => {
                parsers.push(Parser {
                    name: stringify!($native),
                    native: Conversion::$variant($native as *const ()),
                    // SAFETY: call_x87 implements the real st(0) return ABI.
                    host: Conversion::$variant(unsafe {
                        host_addr($symbol, $native as *const ()).cast()
                    }),
                });
            };
        }
        typed!(Narrow32, narrow::strtof, c"strtof");
        typed!(Narrow64, narrow::strtod, c"strtod");
        x87!(Narrow80, narrow::strtold, c"strtold");
        typed!(Narrow128, floatn::strtof128, c"strtof128");
        typed!(Wide32, wide::wcstof, c"wcstof");
        typed!(Wide64, wide::wcstod, c"wcstod");
        x87!(Wide80, wide::wcstold, c"wcstold");
        typed!(Wide128, floatn::wcstof128, c"wcstof128");
        // Representative FloatN forwarding aliases; the separate locale gate
        // exercises all 22 explicit-l variants under the same four modes.
        typed!(Narrow32, floatn::strtof32, c"strtof32");
        typed!(Wide32, floatn::wcstof32, c"wcstof32");
        x87!(Narrow80, floatn::strtof64x, c"strtof64x");
        x87!(Wide80, floatn::wcstof64x, c"wcstof64x");
        parsers
    }

    /// Invoke the public long-double entry point with a correctly aligned
    /// SysV stack and capture its 80 significant bits from st(0). Calling a
    /// Rust f64-typed declaration would observe the wrong return register.
    #[unsafe(naked)]
    unsafe extern "C" fn call_x87(
        _input: *const c_void,
        _end: *mut *mut c_void,
        _out: *mut u8,
        _function: *const (),
    ) {
        core::arch::naked_asm!(
            "push rdx",
            "call rcx",
            "pop rdx",
            "fstp tbyte ptr [rdx]",
            "ret"
        )
    }

    struct Input {
        text: String,
        narrow: CString,
        wide: Vec<i32>,
    }

    impl Input {
        fn new(text: String) -> Self {
            assert!(text.is_ascii());
            Self {
                narrow: CString::new(text.as_bytes()).unwrap(),
                wide: text.bytes().map(i32::from).chain([0]).collect(),
                text,
            }
        }
    }

    #[derive(Debug, PartialEq, Eq)]
    struct Observation {
        bits: u128,
        consumed: usize,
        errno: c_int,
        flags: c_int,
        rounding: c_int,
    }

    fn observe(
        parser: Conversion,
        input: &Input,
        errno: Errno,
        environment: &Environment,
        seeded_flags: c_int,
    ) -> Observation {
        let mut narrow_end = std::ptr::null_mut();
        let mut wide_end = std::ptr::null_mut();
        let mut x87_end = std::ptr::null_mut();
        let mut x87_bits = [0u8; 16];
        environment.prepare(seeded_flags);
        // SAFETY: every function has its exact public signature. Inputs are
        // NUL-terminated; output pointers and the x87 result are writable.
        let (bits, end, start, unit, error, flags, rounding) = unsafe {
            *errno() = ERRNO_SENTINEL;
            let bits = match parser {
                Conversion::Narrow32(f) => {
                    f(input.narrow.as_ptr(), &mut narrow_end).to_bits() as u128
                }
                Conversion::Narrow64(f) => {
                    f(input.narrow.as_ptr(), &mut narrow_end).to_bits() as u128
                }
                Conversion::Narrow128(f) => f(input.narrow.as_ptr(), &mut narrow_end).to_bits(),
                Conversion::Wide32(f) => f(input.wide.as_ptr(), &mut wide_end).to_bits() as u128,
                Conversion::Wide64(f) => f(input.wide.as_ptr(), &mut wide_end).to_bits() as u128,
                Conversion::Wide128(f) => f(input.wide.as_ptr(), &mut wide_end).to_bits(),
                Conversion::Narrow80(f) | Conversion::Wide80(f) => {
                    let start = if matches!(parser, Conversion::Wide80(_)) {
                        input.wide.as_ptr().cast()
                    } else {
                        input.narrow.as_ptr().cast()
                    };
                    call_x87(start, &mut x87_end, x87_bits.as_mut_ptr(), f);
                    u128::from_le_bytes(x87_bits)
                }
            };
            // Snapshot state before formatting, assertions, or floating-point
            // classification could add exception flags of their own.
            let error = *errno();
            let flags = (environment.test)(FE_ALL_EXCEPT);
            let rounding = (environment.get_round)();
            let (end, start, unit) = match parser {
                Conversion::Narrow80(_) => (x87_end as usize, input.narrow.as_ptr() as usize, 1),
                Conversion::Wide80(_) => (x87_end as usize, input.wide.as_ptr() as usize, 4),
                Conversion::Wide32(_) | Conversion::Wide64(_) | Conversion::Wide128(_) => {
                    (wide_end as usize, input.wide.as_ptr() as usize, 4)
                }
                _ => (narrow_end as usize, input.narrow.as_ptr() as usize, 1),
            };
            (bits, end, start, unit, error, flags, rounding)
        };
        let bytes = end.checked_sub(start).expect("end pointer precedes input");
        assert_eq!(bytes % unit, 0, "unaligned end pointer");
        let consumed = bytes / unit;
        assert!(consumed <= input.text.len(), "end pointer exceeds input");
        Observation {
            bits,
            consumed,
            errno: error,
            flags,
            rounding,
        }
    }

    fn inputs() -> Vec<Input> {
        let base = [
            "0",
            "0e999999999",
            "0e-999999999",
            "0.5",
            "0.1",
            // Exactly 2^-40 in every format. The initial 32-wchar window
            // ends at an inexact decimal prefix, so publishing its status
            // before the full token is parsed would leak FE_INEXACT.
            "0.0000000000009094947017729282379150390625",
            // Decimal halfway ties for each significand width.
            "1.000000059604644775390625",
            "1.00000000000000011102230246251565404236316680908203125",
            "1.0000000000000000000542101086242752217003726400434970855712890625",
            "0x1.00000000000000000000000000008p0",
            // The final nonzero digit must survive a float32 conversion. A
            // float64 intermediate loses it and creates a false halfway tie.
            "0x1.000000ffffffffffffffffffffp0",
            "0x1.000001p0",
            "0x1.000001000000000000000001p0",
            "16777217",
            "9007199254740991",
            "9007199254740992",
            "9007199254740993",
            "18446744073709551617",
            "10384593717069655257060992658440193",
            // Exact minsub, half minsub, and half/quarter-ulp below minnormal.
            // GNU distinguishes exact subnormals from inexact underflow, and
            // halfway from quarter-ulp cases even when both round to normal.
            "0x1p-149",
            "0x1p-150",
            "0x1.fffffep-127",
            "0x1.ffffffp-127",
            "0x1p-126",
            "0x1p-1074",
            "0x1p-1075",
            "0x1.fffffffffffffp-1023",
            "0x1.fffffffffffff8p-1023",
            "0x1p-1022",
            "0x1p-16445",
            "0x1p-16446",
            "0x1.fffffffffffffffep-16383",
            "0x1.ffffffffffffffffp-16383",
            "0x1p-16494",
            "0x1p-16495",
            "0x1.ffffffffffffffffffffffffffffp-16383",
            "0x1.ffffffffffffffffffffffffffff8p-16383",
            "0x1p-16382",
            // Max finite, just above it, the overflow midpoint, and an exact
            // exponent overflow distinguish directed values and range flags.
            "0x1.fffffep127",
            "0x1.fffffe00000000000001p127",
            "0x1.ffffffp127",
            "0x1p128",
            "0x1.fffffffffffffp1023",
            "0x1.fffffffffffff0001p1023",
            "0x1.fffffffffffff8p1023",
            "0x1p1024",
            "0x1.fffffffffffffffep16383",
            "0x1.fffffffffffffffe0001p16383",
            "0x1.ffffffffffffffffp16383",
            "0x1.ffffffffffffffffffffffffffffp16383",
            "0x1.ffffffffffffffffffffffffffff0001p16383",
            "0x1.ffffffffffffffffffffffffffff8p16383",
            "0x1p16384",
            "1e999999999",
            "1e-999999999",
            "10e2147483647",
            "10e-2147483648",
            "inf",
            "infinity",
            "nan(42)",
            // GNU parses numeric payloads as unsigned 64-bit integers for
            // every result width. Saturation sets ERANGE without raising an
            // FP exception; a nonnumeric tail discards the payload bits.
            "nan(18446744073709551615)",
            "nan(18446744073709551616)",
            "nan(0xffffffffffffffff)",
            "nan(0x123456789abcdef0123456789abcdef)",
            "nan(123xyz)",
            "nan(123_456)",
            "nan(089)",
            "nan(18446744073709551616xyz)",
            "1.25suffix",
            "1e+suffix",
            "0x1p+suffix",
            "0x",
            ".",
        ];
        let mut values: Vec<String> = base
            .into_iter()
            .flat_map(|text| [text.to_owned(), format!("-{text}")])
            .collect();
        values.extend([
            String::new(),
            "  +tail".to_owned(),
            "\t  -0.1tail".to_owned(),
            format!("0x1.000001{}1p0", "0".repeat(400)),
            format!("-0x1.000001{}1p0", "0".repeat(400)),
            format!("1.000000059604644775390625{}1", "0".repeat(400)),
            format!("-1.000000059604644775390625{}1", "0".repeat(400)),
            // The long mantissa's prefix rounds inexactly in narrower
            // formats, but the later exponent makes the complete value ±1.
            format!("1{}e-400", "0".repeat(400)),
            format!("-1{}e-400", "0".repeat(400)),
        ]);
        values.into_iter().map(Input::new).collect()
    }

    #[test]
    fn all_widths_match_glibc_rounding_errno_and_flags() {
        let environment = Environment::hold();
        let _locale = CLocale::select();
        let parsers = parsers();
        let inputs = inputs();
        assert_eq!(
            parsers.len(),
            12,
            "all canonical widths and aliases execute"
        );
        let host_errno: Errno = unsafe {
            host_fn(
                c"__errno_location",
                errno_abi::__errno_location as *const (),
            )
        };
        let mut comparisons = 0;
        let mut divergence_count = 0;
        let mut diagnostics = Vec::new();
        for mode in MODES {
            assert_eq!(unsafe { (environment.set_round)(mode) }, 0);
            for seeded_flags in [0, FE_DIVBYZERO] {
                for input in &inputs {
                    for parser in &parsers {
                        let expected =
                            observe(parser.host, input, host_errno, &environment, seeded_flags);
                        let actual = observe(
                            parser.native,
                            input,
                            errno_abi::__errno_location,
                            &environment,
                            seeded_flags,
                        );
                        comparisons += 1;
                        assert_eq!(expected.rounding, mode, "GNU changed rounding mode");
                        assert_eq!(actual.rounding, mode, "native changed rounding mode");
                        if actual != expected {
                            divergence_count += 1;
                            if diagnostics.len() < 40 {
                                diagnostics.push(format!(
                                    "{} round={mode:#x} seed={seeded_flags:#x} input={:?}: native=(bits {:#034x}, end {}, errno {}, flags {:#x}) GNU=(bits {:#034x}, end {}, errno {}, flags {:#x})",
                                    parser.name,
                                    input.text,
                                    actual.bits,
                                    actual.consumed,
                                    actual.errno,
                                    actual.flags,
                                    expected.bits,
                                    expected.consumed,
                                    expected.errno,
                                    expected.flags,
                                ));
                            }
                        }
                    }
                }
            }
        }
        assert_eq!(comparisons, parsers.len() * inputs.len() * MODES.len() * 2);
        assert!(comparisons > 0, "no numeric rounding comparisons executed");
        assert_eq!(
            divergence_count,
            0,
            "{divergence_count}/{comparisons} numeric divergences (first 40):\n{}",
            diagnostics.join("\n")
        );
        println!(
            "NUMERIC_ROUNDING_OK symbols={} inputs={} comparisons={comparisons}",
            parsers.len(),
            inputs.len(),
        );
    }
}
