//! Live differential probe: FrankenLibC `snprintf("%a"/"%A")` vs host glibc,
//! the hand-written hex-float formatter. Focuses on PRECISION rounding
//! (`%.Na` rounds the hex significand to N fractional digits with
//! round-half-to-even, and a carry can propagate into the leading digit) plus
//! subnormals, powers of two, near-carry mantissas (`0x1.fff…`), and the
//! default (shortest-exact) form — sweeping each across many precisions and a
//! deterministic random f64 corpus. Output strings are compared verbatim.
#![allow(unsafe_code)]

use std::ffi::CString;

use frankenlibc_abi::stdio_abi as fl;

unsafe extern "C" {
    fn snprintf(buf: *mut libc::c_char, size: usize, fmt: *const libc::c_char, ...) -> libc::c_int;
}

fn host_fmt(fmt: &CString, val: f64) -> String {
    let mut buf = [0u8; 160];
    // SAFETY: buf is large enough for any %a rendering; fmt is a valid C string.
    let n = unsafe {
        snprintf(
            buf.as_mut_ptr() as *mut libc::c_char,
            buf.len(),
            fmt.as_ptr(),
            val,
        )
    };
    read_cstr(&buf, n)
}

fn fl_fmt(fmt: &CString, val: f64) -> String {
    let mut buf = [0u8; 160];
    // SAFETY: as above; fl::snprintf has the C ABI.
    let n = unsafe {
        fl::snprintf(
            buf.as_mut_ptr() as *mut std::ffi::c_char,
            buf.len(),
            fmt.as_ptr() as *const std::ffi::c_char,
            val,
        )
    };
    read_cstr(&buf, n)
}

fn read_cstr(buf: &[u8], n: libc::c_int) -> String {
    if n < 0 {
        return "<err>".to_string();
    }
    let n = (n as usize).min(buf.len() - 1);
    String::from_utf8_lossy(&buf[..n]).into_owned()
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
}

#[test]
fn printf_hexfloat_live_vs_glibc() {
    let mut values: Vec<f64> = vec![
        0.0,
        -0.0,
        1.0,
        -1.0,
        0.5,
        2.0,
        3.0,
        0.1,
        255.0,
        f64::MAX,
        f64::MIN_POSITIVE,
        f64::from_bits(1),                  // smallest subnormal
        f64::from_bits(0x000F_FFFF_FFFF_FFFF), // largest subnormal
        f64::from_bits(0x3FEF_FFFF_FFFF_FFFF), // 0x1.fff...p-1 (just below 1)
        f64::from_bits(0x3FFF_FFFF_FFFF_FFFF), // 0x1.fff...p+0 (just below 2) — carry stress
        f64::from_bits(0x4000_0000_0000_0001), // just above 2
        1.5,
        -2.5,
        1e300,
        1e-300,
        f64::from_bits(0x0008_0000_0000_0000), // mid subnormal
    ];
    // Deterministic random finite f64 corpus.
    let mut r = Lcg(0xdead_beef_cafe_1234);
    while values.len() < 2000 {
        let bits = r.next();
        let v = f64::from_bits(bits);
        if v.is_finite() {
            values.push(v);
        }
    }

    // Precision variants: default (no precision) + explicit %.Na for a range that
    // straddles the 13-hex-digit full mantissa (so both rounding and padding fire).
    let mut fmts: Vec<(CString, &str)> = Vec::new();
    for (spec, name) in [("a", "a"), ("A", "A")] {
        fmts.push((CString::new(format!("%{spec}")).unwrap(), name));
        for p in [0usize, 1, 2, 3, 4, 5, 6, 10, 12, 13, 14, 16, 20] {
            fmts.push((
                CString::new(format!("%.{p}{spec}")).unwrap(),
                Box::leak(format!(".{p}{name}").into_boxed_str()),
            ));
        }
    }

    let mut divergences: Vec<(String, f64, String, String)> = Vec::new();
    let mut compared = 0u64;
    for (fmt, fmt_name) in &fmts {
        for &v in &values {
            let h = host_fmt(fmt, v);
            let f = fl_fmt(fmt, v);
            compared += 1;
            if h != f {
                divergences.push((fmt_name.to_string(), v, h, f));
            }
        }
    }

    if !divergences.is_empty() {
        let shown: Vec<_> = divergences
            .iter()
            .take(30)
            .map(|(fmt, v, h, f)| format!("%{fmt} of {v:e} ({:#018x}): glibc={h:?} fl={f:?}", v.to_bits()))
            .collect();
        panic!(
            "printf %a diverged from host glibc on {}/{} cases (showing up to 30):\n{}",
            divergences.len(),
            compared,
            shown.join("\n")
        );
    }
    eprintln!("printf %a/%A: {compared} cases, 0 divergences vs host glibc");
}
