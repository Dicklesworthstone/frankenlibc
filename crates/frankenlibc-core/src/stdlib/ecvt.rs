//! Legacy floating-point to string conversion: `ecvt`, `fcvt`, `gcvt`.
//!
//! These are obsolete POSIX.1-2001 functions (removed in POSIX.1-2008)
//! but glibc still exports them for backward compatibility.

/// `ecvt` — convert double to string in scientific notation form.
///
/// Returns `(digits, decimal_point_position, is_negative)`.
/// `ndigit`: number of significant digits requested.
///
/// The returned string contains only digits (no sign, no decimal point).
/// `decpt` indicates where the decimal point goes relative to the start.
/// For example, 123.456 with ndigit=6 gives digits="123456", decpt=3.
pub fn ecvt(value: f64, ndigit: i32) -> (Vec<u8>, i32, bool) {
    let negative = value.is_sign_negative() && !value.is_nan();
    let abs_val = value.abs();

    if value.is_nan() {
        return (b"nan".to_vec(), 0, false);
    }
    if value.is_infinite() {
        return (b"inf".to_vec(), 0, negative);
    }

    let ndigit = ndigit.max(0) as usize;
    if ndigit == 0 {
        return (Vec::new(), 0, negative);
    }

    if abs_val == 0.0 {
        return (vec![b'0'; ndigit], 1, negative);
    }

    // Use Rust's formatting to get digits.
    // Format with enough precision.
    let formatted = format!("{:.prec$e}", abs_val, prec = ndigit.saturating_sub(1));
    // Parse the scientific notation: "d.dddde+dd"
    let mut digits = Vec::with_capacity(ndigit);
    let mut exponent: i32 = 0;
    let mut in_exp = false;
    let mut exp_sign: i32 = 1;
    let mut exp_str = String::new();

    for c in formatted.bytes() {
        if in_exp {
            if c == b'-' {
                exp_sign = -1;
            } else if c == b'+' {
                // skip
            } else if c.is_ascii_digit() {
                exp_str.push(c as char);
            }
        } else if c == b'e' || c == b'E' {
            in_exp = true;
        } else if c == b'.' {
            // skip decimal point
        } else if c.is_ascii_digit() {
            digits.push(c);
        }
    }

    if let Ok(e) = exp_str.parse::<i32>() {
        exponent = e * exp_sign;
    }

    // Trim or pad to exactly ndigit digits.
    while digits.len() < ndigit {
        digits.push(b'0');
    }
    digits.truncate(ndigit);

    // decpt = exponent + 1 (position of decimal point from left).
    let decpt = exponent + 1;

    (digits, decpt, negative)
}

/// `fcvt` — convert double to string in fixed-point form.
///
/// Returns `(digits, decimal_point_position, is_negative)`.
/// `ndigit`: number of digits after the decimal point.
pub fn fcvt(value: f64, ndigit: i32) -> (Vec<u8>, i32, bool) {
    let negative = value.is_sign_negative() && !value.is_nan();
    let abs_val = value.abs();

    if value.is_nan() {
        return (b"nan".to_vec(), 0, false);
    }
    if value.is_infinite() {
        return (b"inf".to_vec(), 0, negative);
    }

    let ndigit = ndigit.max(0) as usize;

    // Format in fixed-point notation.
    let formatted = format!("{:.prec$}", abs_val, prec = ndigit);

    let mut digits = Vec::new();
    let mut decpt: i32 = 0;
    let mut found_dot = false;

    for c in formatted.bytes() {
        if c == b'.' {
            found_dot = true;
            decpt = digits.len() as i32;
        } else if c.is_ascii_digit() {
            digits.push(c);
        }
    }

    if !found_dot {
        decpt = digits.len() as i32;
    }

    // Handle zero: ensure at least one digit.
    if digits.is_empty() {
        digits.push(b'0');
        decpt = 1;
    }

    (digits, decpt, negative)
}

/// `gcvt` — convert double to string using shortest representation.
///
/// `gcvt` — convert double to printable string using `%g` semantics.
///
/// Matches `printf("%.<ndigit>g", value)` per POSIX and glibc:
///
///   * `ndigit` is the number of *significant* digits (not fractional).
///   * Pick scientific format (`%e`) when `exp < -4` or `exp >= ndigit`,
///     where `exp = floor(log10(|value|))`. Otherwise pick fixed-point.
///   * Trailing zeros after the decimal point are stripped, and a
///     bare trailing decimal point is also stripped.
///   * Exponent uses C-style `e+02` / `e-10` with sign and a minimum
///     of two digits (so `gcvt(123.456, 1)` is `"1e+02"`, not Rust's
///     default `"1e2"`).
///   * `gcvt(0, *)` returns `"0"` (not `"0.0"`).
///
/// The previous implementation used `format!("{:.prec$}", value)` —
/// %.Nf fixed-point with N fractional digits — which diverged from
/// glibc on every input that wasn't a "nice" decimal: trailing zeros
/// were emitted, large magnitudes never switched to scientific, and
/// sub-1 magnitudes had the wrong precision. Empirical divergences
/// captured before this rewrite (probed against glibc 2.38 on
/// Linux/x86_64) included `gcvt(123.456, 1)` -> `"123.5"` (vs glibc's
/// `"1e+02"`) and `gcvt(0, 1)` -> `"0.0"` (vs `"0"`).
pub fn gcvt(value: f64, ndigit: i32, buf: &mut [u8]) -> usize {
    let ndigit = ndigit.max(1) as usize;
    let rendered = render_gcvt(value, ndigit);
    let bytes = rendered.as_bytes();
    let copy_len = bytes.len().min(buf.len().saturating_sub(1));
    buf[..copy_len].copy_from_slice(&bytes[..copy_len]);
    if copy_len < buf.len() {
        buf[copy_len] = 0;
    }
    copy_len
}

/// Pure formatting helper — no buffer concerns. Exposed for unit tests.
fn render_gcvt(value: f64, ndigit: usize) -> String {
    if value.is_nan() {
        return String::from("nan");
    }
    if value.is_infinite() {
        return if value < 0.0 {
            String::from("-inf")
        } else {
            String::from("inf")
        };
    }
    if value == 0.0 {
        // glibc emits "0" even for -0.0, no trailing decimal.
        return String::from("0");
    }

    // Pick format based on the decimal exponent of |value|. log10 of
    // a non-zero finite f64 is finite, but the floor cast can land off
    // by one near exact powers of 10 due to f64 rounding (e.g.
    // log10(1000.0) might compute to 2.9999...). Cross-check by
    // re-formatting once and see what string we get.
    let abs = value.abs();
    let exp = abs.log10().floor() as i32;
    let exp = correct_exp_via_check(abs, exp);

    if exp < -4 || exp >= ndigit as i32 {
        format_scientific(value, ndigit)
    } else {
        format_fixed(value, ndigit, exp)
    }
}

/// Verify and possibly correct the floor(log10) value: if 10^exp would
/// be larger than abs, decrement; if 10^(exp+1) would be ≤ abs,
/// increment. This handles f64 rounding quirks at exact powers of 10.
fn correct_exp_via_check(abs: f64, exp: i32) -> i32 {
    let lo = 10f64.powi(exp);
    if abs < lo {
        return exp - 1;
    }
    let hi = 10f64.powi(exp + 1);
    if abs >= hi {
        return exp + 1;
    }
    exp
}

fn format_fixed(value: f64, ndigit: usize, exp: i32) -> String {
    let frac = (ndigit as i32 - 1 - exp).max(0) as usize;
    let formatted = format!("{:.prec$}", value, prec = frac);
    strip_trailing_zeros(&formatted)
}

fn format_scientific(value: f64, ndigit: usize) -> String {
    let frac = ndigit.saturating_sub(1);
    let rust_form = format!("{:.prec$e}", value, prec = frac);
    rust_e_to_glibc_e(&rust_form)
}

/// Strip trailing zeros from a decimal string with a `.` separator.
/// `"1.500"` -> `"1.5"`, `"1.000"` -> `"1"`, `"100"` -> `"100"`.
fn strip_trailing_zeros(s: &str) -> String {
    if !s.contains('.') {
        return s.to_string();
    }
    s.trim_end_matches('0').trim_end_matches('.').to_string()
}

/// Convert Rust's `1.5e2` / `1e-10` mantissa-exponent form to glibc's
/// `1.5e+02` / `1e-10` (signed, ≥ 2-digit exponent). Also strips
/// trailing zeros from the mantissa: `"1.500e2"` -> `"1.5e+02"`.
fn rust_e_to_glibc_e(s: &str) -> String {
    let Some(e_pos) = s.find('e') else {
        return strip_trailing_zeros(s);
    };
    let mantissa = strip_trailing_zeros(&s[..e_pos]);
    let exp_part = &s[e_pos + 1..];
    let (sign, digits) = if let Some(rest) = exp_part.strip_prefix('-') {
        ('-', rest)
    } else if let Some(rest) = exp_part.strip_prefix('+') {
        ('+', rest)
    } else {
        ('+', exp_part)
    };
    let exp_val: i32 = digits.parse().unwrap_or(0);
    if exp_val.unsigned_abs() < 10 {
        format!("{mantissa}e{sign}0{}", exp_val.unsigned_abs())
    } else {
        format!("{mantissa}e{sign}{}", exp_val.unsigned_abs())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ecvt_basic() {
        let (digits, decpt, neg) = ecvt(123.456, 6);
        assert!(!neg);
        assert_eq!(decpt, 3);
        assert_eq!(&digits, b"123456");
    }

    #[test]
    fn test_ecvt_negative() {
        let (_, _, neg) = ecvt(-42.0, 4);
        assert!(neg);
    }

    #[test]
    fn test_ecvt_zero() {
        let (digits, decpt, neg) = ecvt(0.0, 4);
        assert!(!neg);
        assert_eq!(decpt, 1);
        assert_eq!(&digits, b"0000");
    }

    #[test]
    fn test_fcvt_basic() {
        let (digits, decpt, neg) = fcvt(123.456, 3);
        assert!(!neg);
        assert_eq!(decpt, 3);
        assert_eq!(&digits, b"123456");
    }

    #[test]
    fn test_gcvt_basic() {
        let mut buf = [0u8; 64];
        let len = gcvt(3.25, 4, &mut buf);
        let s = std::str::from_utf8(&buf[..len]).unwrap();
        assert!(s.contains("3.25") || s.starts_with("3.25"));
    }
}
