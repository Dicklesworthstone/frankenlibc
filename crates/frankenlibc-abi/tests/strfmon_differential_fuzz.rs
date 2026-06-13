#![cfg(target_os = "linux")]
#![allow(unsafe_code)] // host-glibc strfmon oracle (libc, linked by std)

//! Randomized live differential fuzzer for `strfmon` vs host glibc. fl's
//! `strfmon`/`strfmon_l`/`__strfmon_l` were stubs that ignored the format string
//! entirely (read one f64, emit `{:.2}`); this calls the real fl ABI `strfmon`
//! (variadic) and the host `strfmon` with the SAME format + value, comparing the
//! full contract (return value + the exact bytes written) in the C locale over
//! both a curated golden battery and randomly generated valid directives.

use std::ffi::{CString, c_char, c_int};

use frankenlibc_abi::unistd_abi::strfmon as fl_strfmon;

unsafe extern "C" {
    fn strfmon(s: *mut c_char, max: usize, fmt: *const c_char, ...) -> isize;
    fn setlocale(category: c_int, locale: *const c_char) -> *mut c_char;
}

struct Lcg(u64);
impl Lcg {
    fn next(&mut self) -> u64 {
        self.0 = self
            .0
            .wrapping_mul(6364136223846793005)
            .wrapping_add(1442695040888963407);
        self.0
    }
    fn below(&mut self, n: u64) -> u64 {
        self.next() % n
    }
}

#[derive(PartialEq, Eq, Debug)]
struct Out {
    ret: isize,
    out: Option<String>,
}

/// Run one strfmon (`$f`) with a single f64 value and render the result.
macro_rules! run {
    ($f:path, $fmt:expr, $val:expr) => {{
        let mut buf = [0u8; 256];
        let ret = unsafe { $f(buf.as_mut_ptr() as *mut c_char, buf.len(), $fmt, $val) };
        let out = if ret >= 0 {
            let n = buf.iter().position(|&b| b == 0).unwrap_or(buf.len());
            Some(String::from_utf8_lossy(&buf[..n]).into_owned())
        } else {
            None
        };
        Out { ret, out }
    }};
}

fn host(fmt: &CString, val: f64) -> Out {
    run!(strfmon, fmt.as_ptr(), val)
}
fn fl(fmt: &CString, val: f64) -> Out {
    run!(fl_strfmon, fmt.as_ptr(), val)
}

/// A randomly generated, syntactically valid strfmon directive plus surrounding
/// literal text. Returns `(format, contains_parens_flag)`.
fn gen_format(r: &mut Lcg) -> (String, bool) {
    let mut f = String::new();
    if r.below(3) == 0 {
        f.push_str("$ ");
    }
    f.push('%');
    if r.below(3) == 0 {
        f.push('=');
        f.push(b"*0x@"[r.below(4) as usize] as char);
    }
    if r.below(4) == 0 {
        f.push('^');
    }
    if r.below(5) == 0 {
        f.push('+');
    }
    let parens = r.below(4) == 0;
    if parens {
        f.push('(');
    }
    if r.below(5) == 0 {
        f.push('!');
    }
    if r.below(4) == 0 {
        f.push('-');
    }
    if r.below(2) == 0 {
        f.push_str(&r.below(18).to_string()); // field width
    }
    if r.below(2) == 0 {
        f.push('#');
        f.push_str(&r.below(10).to_string()); // left precision
    }
    if r.below(2) == 0 {
        f.push('.');
        f.push_str(&r.below(6).to_string()); // right precision
    }
    f.push(if r.below(2) == 0 { 'n' } else { 'i' });
    if r.below(3) == 0 {
        f.push_str(" only");
    }
    (f, parens)
}

/// A random finite monetary value across several magnitude scales.
fn gen_value(r: &mut Lcg) -> f64 {
    let m = r.below(100_000_000) as f64;
    let denom = [1.0, 10.0, 100.0, 1000.0][r.below(4) as usize];
    let v = m / denom;
    if m != 0.0 && r.next() & 1 == 0 { -v } else { v }
}

#[test]
fn strfmon_golden_c_locale() {
    unsafe { setlocale(libc::LC_ALL, c"C".as_ptr()) };
    // Bit-exact golden cases captured from host glibc in the C locale. These
    // pin behavior independent of the live oracle.
    let cases: &[(&str, f64, &str)] = &[
        ("%n", 1234.567, "1234.57"),
        ("%n", -1234.567, "-1234.57"),
        ("%n", 0.0, "0.00"),
        ("%i", 1_000_000.0, "1000000.00"),
        ("%11n", 1234.567, "    1234.57"),
        ("%11n", -1234.567, "   -1234.57"),
        ("%#6n", 1234.567, "   1234.57"),
        ("%#6n", -1234.567, "-  1234.57"),
        ("%#6.3n", -1234.567, "-  1234.567"),
        ("%.0n", 0.5, "0"),
        ("%.4n", 1234.567, "1234.5670"),
        ("Cost: %n!", 1234.567, "Cost: 1234.57!"),
        ("%%", 0.0, "%"),
        ("%-11n", -1234.567, "-1234.57   "),
        ("%(n", -1234.567, "(1234.57)"),
        ("%(#7.2n", -1234.567, "(   1234.57)"),
        ("%^#10.2i", -1234.567, "-      1234.57"),
        ("%^#10.2i", 12.0, "         12.00"),
    ];
    for &(fmt, val, want) in cases {
        let cf = CString::new(fmt).unwrap();
        let g = fl(&cf, val);
        assert_eq!(g.out.as_deref(), Some(want), "fmt={fmt:?} val={val}");
        // Also confirm the host oracle agrees with the golden string.
        assert_eq!(
            host(&cf, val).out.as_deref(),
            Some(want),
            "oracle fmt={fmt:?}"
        );
    }
}

#[test]
fn strfmon_differential_fuzz_vs_glibc() {
    unsafe { setlocale(libc::LC_ALL, c"C".as_ptr()) };
    let mut r = Lcg(0x5f37_59df_1234_abcd);
    let mut divs: Vec<String> = Vec::new();
    let mut compared: u64 = 0;

    for _ in 0..40000 {
        let (fmt, parens) = gen_format(&mut r);
        let mut val = gen_value(&mut r);
        // glibc has a quirk for negative amounts that round to exactly zero
        // under the `(` parens flag (it renders "-0.00" rather than "(0.00)").
        // Keep parens cases away from zero so the value is unambiguously signed.
        if parens && val.abs() < 1.0 {
            val = val.abs() + 1.0;
        }
        let Ok(cf) = CString::new(fmt.as_str()) else {
            continue;
        };
        let h = host(&cf, val);
        let l = fl(&cf, val);
        compared += 1;
        if h != l && divs.len() < 40 {
            divs.push(format!(
                "fmt={fmt:?} val={val}\n    fl   ={l:?}\n    glibc={h:?}"
            ));
        }
    }

    assert!(
        divs.is_empty(),
        "strfmon diverged from host glibc on {} cases (showing up to 40):\n{}",
        divs.len(),
        divs.join("\n")
    );
    eprintln!("strfmon differential fuzz: {compared} comparisons, 0 divergences vs host glibc");
}
