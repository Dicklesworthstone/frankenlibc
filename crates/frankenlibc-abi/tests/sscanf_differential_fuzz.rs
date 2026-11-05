#![cfg(target_os = "linux")]
#![allow(unsafe_code)] // host-glibc sscanf oracle (libc, linked by std)

//! Randomized live differential fuzzer for `sscanf` vs host glibc. The existing
//! `scanf_differential_probe` tests the core scan engine against HARDCODED glibc
//! reference strings over a fixed battery; this calls the real fl ABI `sscanf`
//! (variadic) and the host `sscanf` with the SAME random format+input and
//! IDENTICAL C output types — so integer truncation, overflow clamping, sign /
//! whitespace / width / base / scanset parsing, and `%n` consumption are all
//! compared on equal footing against the live oracle, over random inputs (where
//! the fixed battery can't reach).
//!
//! Each case uses a single primary conversion plus a trailing `%n`, comparing:
//! the return value, the stored value (only when the conversion matched), and
//! the `%n` consumed count (only when reached).

use std::ffi::{CString, c_char, c_int, c_long, c_uint};

use frankenlibc_abi::stdio_abi::sscanf as fl_sscanf;

#[path = "common/dlsym_oracle.rs"]
mod dlsym_oracle;
type SscanfFn = unsafe extern "C" fn(*const c_char, *const c_char, ...) -> c_int;
static HOST_SSCANF: std::sync::OnceLock<SscanfFn> = std::sync::OnceLock::new();

struct Lcg(u64);
impl Lcg {
    fn next(&mut self) -> u64 {
        self.0 = self
            .0
            .wrapping_mul(6364136223846793005)
            .wrapping_add(1442695040888963407);
        self.0
    }
}

/// Result of one sscanf call, rendered to a comparable string. `val`/`n` are
/// only meaningful (and only compared) when the primary conversion matched
/// (`ret == 1`), mirroring C semantics where the output args and a trailing `%n`
/// are untouched on a match failure.
#[derive(PartialEq, Eq, Debug)]
struct Out {
    ret: c_int,
    val: Option<String>,
    n: Option<c_int>,
}

// Each macro runs the given sscanf (`$scanf`) on (`$s`, `$fmt`) with a typed
// primary output + a trailing `%n` int, and renders an `Out`.
macro_rules! run_int {
    ($scanf:path, $s:expr, $fmt:expr) => {{
        let mut v: c_int = 0;
        let mut n: c_int = -12345;
        let ret = unsafe { $scanf($s, $fmt, &mut v as *mut c_int, &mut n as *mut c_int) };
        Out {
            ret,
            val: (ret == 1).then(|| format!("i{v}")),
            n: (ret == 1).then_some(n),
        }
    }};
}
macro_rules! run_uint {
    ($scanf:path, $s:expr, $fmt:expr) => {{
        let mut v: c_uint = 0;
        let mut n: c_int = -12345;
        let ret = unsafe { $scanf($s, $fmt, &mut v as *mut c_uint, &mut n as *mut c_int) };
        Out {
            ret,
            val: (ret == 1).then(|| format!("u{v}")),
            n: (ret == 1).then_some(n),
        }
    }};
}
macro_rules! run_long {
    ($scanf:path, $s:expr, $fmt:expr) => {{
        let mut v: c_long = 0;
        let mut n: c_int = -12345;
        let ret = unsafe { $scanf($s, $fmt, &mut v as *mut c_long, &mut n as *mut c_int) };
        Out {
            ret,
            val: (ret == 1).then(|| format!("l{v}")),
            n: (ret == 1).then_some(n),
        }
    }};
}
macro_rules! run_dbl {
    ($scanf:path, $s:expr, $fmt:expr) => {{
        let mut v: f64 = 0.0;
        let mut n: c_int = -12345;
        let ret = unsafe { $scanf($s, $fmt, &mut v as *mut f64, &mut n as *mut c_int) };
        Out {
            ret,
            val: (ret == 1).then(|| format!("f{:016x}", v.to_bits())),
            n: (ret == 1).then_some(n),
        }
    }};
}
macro_rules! run_str {
    ($scanf:path, $s:expr, $fmt:expr) => {{
        let mut buf = [0u8; 64];
        let mut n: c_int = -12345;
        let ret = unsafe {
            $scanf(
                $s,
                $fmt,
                buf.as_mut_ptr() as *mut c_char,
                &mut n as *mut c_int,
            )
        };
        let m = buf.iter().position(|&b| b == 0).unwrap_or(buf.len());
        Out {
            ret,
            val: (ret == 1).then(|| format!("s{}", String::from_utf8_lossy(&buf[..m]))),
            n: (ret == 1).then_some(n),
        }
    }};
}

/// A format family: the format string (with a trailing `%n`) and the typed
/// runner that knows how to call sscanf and render the result.
#[derive(Clone, Copy)]
enum Kind {
    Int,
    UInt,
    Long,
    Dbl,
    Str,
}

const FORMATS: &[(&str, Kind)] = &[
    ("%d%n", Kind::Int),
    ("%i%n", Kind::Int),
    ("%3d%n", Kind::Int),
    ("%u%n", Kind::UInt),
    ("%x%n", Kind::UInt),
    ("%o%n", Kind::UInt),
    ("%ld%n", Kind::Long),
    ("%lx%n", Kind::Long),
    ("%lf%n", Kind::Dbl),
    ("%le%n", Kind::Dbl),
    ("%lg%n", Kind::Dbl),
    ("%s%n", Kind::Str),
    ("%9s%n", Kind::Str),
    ("%[0-9]%n", Kind::Str),
    ("%[^0-9]%n", Kind::Str),
    ("%[a-fA-F0-9]%n", Kind::Str),
    ("%[0-9.eE+-]%n", Kind::Str),
];

fn render(scanf_is_fl: bool, kind: Kind, s: &CString, fmt: &CString) -> Out {
    macro_rules! dispatch {
        ($m:ident) => {
            if scanf_is_fl {
                $m!(fl_sscanf, s.as_ptr(), fmt.as_ptr())
            } else {
                let host = *HOST_SSCANF.get_or_init(|| unsafe {
                    dlsym_oracle::host_fn(c"sscanf", fl_sscanf as *const ())
                });
                $m!(host, s.as_ptr(), fmt.as_ptr())
            }
        };
    }
    match kind {
        Kind::Int => dispatch!(run_int),
        Kind::UInt => dispatch!(run_uint),
        Kind::Long => dispatch!(run_long),
        Kind::Dbl => dispatch!(run_dbl),
        Kind::Str => dispatch!(run_str),
    }
}

/// Random numeric-ish input string: a mix of digits, signs, dot/exponent, hex
/// letters, whitespace, and a little garbage — to stress every parser path.
fn gen_input(r: &mut Lcg) -> String {
    let alphabet = b"0123456789+-.eExXaAbBcCdDfF  \tzZ:,";
    let len = (r.next() % 15) as usize;
    let mut v = Vec::with_capacity(len);
    for _ in 0..len {
        v.push(alphabet[(r.next() as usize) % alphabet.len()]);
    }
    String::from_utf8(v).unwrap()
}

#[test]
fn sscanf_differential_fuzz_vs_glibc() {
    let mut r = Lcg(0xc0ff_ee15_d00d_1234);
    let mut divs: Vec<String> = Vec::new();
    let mut compared: u64 = 0;

    for _ in 0..6000 {
        let input = gen_input(&mut r);
        let Ok(cs) = CString::new(input.as_str()) else {
            continue;
        };
        for &(fmt, kind) in FORMATS {
            let cf = CString::new(fmt).unwrap();
            let fl = render(true, kind, &cs, &cf);
            let host = render(false, kind, &cs, &cf);
            compared += 1;
            if fl != host && divs.len() < 40 {
                divs.push(format!(
                    "fmt={fmt:?} input={input:?}\n    fl   ={fl:?}\n    glibc={host:?}"
                ));
            }
        }
    }

    assert!(
        divs.is_empty(),
        "sscanf diverged from host glibc on {} cases (showing up to 40):\n{}",
        divs.len(),
        divs.join("\n")
    );
    eprintln!("sscanf differential fuzz: {compared} comparisons, 0 divergences vs host glibc");
}

#[derive(Clone, Copy)]
enum FloatKind {
    F32,
    F64,
    #[cfg(target_arch = "x86_64")]
    X87,
}

#[cfg(target_arch = "x86_64")]
#[repr(C, align(16))]
struct LongDouble([u8; 16]);

fn exponent_outcome(
    target: SscanfFn,
    input: &str,
    format: &str,
    kind: FloatKind,
) -> (c_int, [u8; 16], c_int, u8) {
    let input = CString::new(input).unwrap();
    let format = CString::new(format).unwrap();
    let mut consumed = -1;
    let mut tail = b'?';
    let mut bits = [0u8; 16];
    let result = match kind {
        FloatKind::F32 => {
            let mut value = -9.0_f32;
            let result = unsafe {
                target(
                    input.as_ptr(),
                    format.as_ptr(),
                    &mut value as *mut f32,
                    &mut consumed as *mut c_int,
                    (&mut tail as *mut u8).cast::<c_char>(),
                )
            };
            bits[..4].copy_from_slice(&value.to_ne_bytes());
            result
        }
        FloatKind::F64 => {
            let mut value = -9.0_f64;
            let result = unsafe {
                target(
                    input.as_ptr(),
                    format.as_ptr(),
                    &mut value as *mut f64,
                    &mut consumed as *mut c_int,
                    (&mut tail as *mut u8).cast::<c_char>(),
                )
            };
            bits[..8].copy_from_slice(&value.to_ne_bytes());
            result
        }
        #[cfg(target_arch = "x86_64")]
        FloatKind::X87 => {
            let mut value = LongDouble([0xA5; 16]);
            // x86_64 long double has 16-byte storage/alignment and a ten-byte
            // x87 payload. Padding is unspecified and is not compared.
            let result = unsafe {
                target(
                    input.as_ptr(),
                    format.as_ptr(),
                    &mut value as *mut LongDouble,
                    &mut consumed as *mut c_int,
                    (&mut tail as *mut u8).cast::<c_char>(),
                )
            };
            bits[..10].copy_from_slice(&value.0[..10]);
            result
        }
    };
    (result, bits, consumed, tail)
}

#[test]
fn incomplete_exponents_preserve_value_width_count_and_following_character() {
    use frankenlibc_abi::{isoc_abi as iso, stdio_abi as io};

    let cases = [
        ("27EeA7A9", ""),
        ("+9.e", ""),
        ("1e+", ""),
        ("1e-!", ""),
        ("-0e+!", ""),
        (".5E-!", ""),
        ("1e+7!", "1"),
        ("1e+7!", "2"),
        ("1e+7!", "3"),
        ("1e+7!", "4"),
        ("0x1p!", ""),
        ("0x1.8p-!", ""),
        ("0x.0p+", ""),
        ("0x2p-foo", ""),
        ("0x1p+7!", "3"),
        ("0x1p+7!", "4"),
        ("0x1p+7!", "5"),
        ("0x1p+7!", "6"),
        ("0x.p+", ""),
        ("0x", ""),
        ("-0x0p-!", ""),
        ("1.0000000000000000001e+!", ""),
        ("0x1.0000000000000002p+!", ""),
        ("1.5e+2!", ""),
        ("e+!", ""),
    ];
    let conversions = [
        ("f", FloatKind::F32),
        ("lf", FloatKind::F64),
        ("le", FloatKind::F64),
        ("lg", FloatKind::F64),
        ("la", FloatKind::F64),
        #[cfg(target_arch = "x86_64")]
        ("Lf", FloatKind::X87),
        #[cfg(target_arch = "x86_64")]
        ("La", FloatKind::X87),
    ];
    let mut comparisons = 0;
    for (name, target) in [
        (c"sscanf", io::sscanf as SscanfFn),
        (c"__isoc99_sscanf", io::__isoc99_sscanf as SscanfFn),
        (c"__isoc23_sscanf", iso::__isoc23_sscanf as SscanfFn),
    ] {
        let host: SscanfFn = unsafe { dlsym_oracle::host_fn(name, target as *const ()) };
        let control = exponent_outcome(host, "27E!", "%lf%n%c", FloatKind::F64);
        assert_eq!((control.0, control.2, control.3), (2, 3, b'!'));
        assert_eq!(&control.1[..8], &27.0_f64.to_ne_bytes());
        for (input, width) in cases {
            for (conversion, kind) in conversions {
                let format = format!("%{width}{conversion}%n%c");
                assert_eq!(
                    exponent_outcome(target, input, &format, kind),
                    exponent_outcome(host, input, &format, kind),
                    "{name:?}: input={input:?}, format={format:?}"
                );
                comparisons += 1;
            }
        }
        // The strict mixed-field fast path uses this same core float scanner.
        // Exercise it without `%n`, which would make that path decline.
        let mut integer = -1;
        let mut value = -9.0_f64;
        let count = unsafe {
            target(
                c"7 1e+".as_ptr(),
                c"%d %lf".as_ptr(),
                &mut integer as *mut c_int,
                &mut value as *mut f64,
            )
        };
        assert_eq!((count, integer, value), (2, 7, 1.0));
    }
    assert_eq!(comparisons, 3 * cases.len() * conversions.len());
    eprintln!("incomplete exponent differential: {comparisons} exact-symbol GNU comparisons");
}
