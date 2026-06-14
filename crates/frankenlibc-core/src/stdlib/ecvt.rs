//! Legacy floating-point to string conversion: `ecvt`, `fcvt`, `gcvt`.
//!
//! These are obsolete POSIX.1-2001 functions (removed in POSIX.1-2008)
//! but glibc still exports them for backward compatibility.

const MAX_LEGACY_CVT_DIGITS: usize = 512;

/// glibc's `gcvt` formats with `%.*g` after clamping the requested significant
/// digits to `DBL_DECIMAL_DIG` (17) — the most a `double` can carry — so a
/// caller asking for more never sees meaningless low-order garbage. (`ecvt`/
/// `fcvt` deliberately keep the wider cap: they emit a raw digit string and
/// have their own glibc-divergence story, bd-2g7oyh.101.)
const GCVT_MAX_SIG_DIGITS: usize = 17;

/// Render the digit string glibc emits for a non-finite `ecvt`/`fcvt` input.
///
/// glibc embeds the sign character directly in the returned buffer for NaN
/// and infinity (e.g. `"-inf"`, `"-nan"`) and leaves the out-param `*sign`
/// set to 0 — unlike finite values, where the sign is reported via `*sign`
/// and stripped from the digits. Mirroring that, the returned tuple here
/// always carries `is_negative = false` for non-finite inputs so the ABI
/// layer reports `sign = 0`. The sign bit is read directly (not via
/// `is_sign_negative() && !is_nan()`) so `-nan` keeps its leading `-`.
fn nonfinite_cvt(value: f64) -> (Vec<u8>, i32, bool) {
    let sign = if value.is_sign_negative() { "-" } else { "" };
    let body = if value.is_nan() { "nan" } else { "inf" };
    (format!("{sign}{body}").into_bytes(), 0, false)
}

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

    if !value.is_finite() {
        return nonfinite_cvt(value);
    }

    let ndigit = (ndigit.max(0) as usize).min(MAX_LEGACY_CVT_DIGITS);
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
/// Returns `(digits, decimal_point_position, is_negative)` matching glibc:
///
///   * `value == 0.0` (exact): emit `ndigit + 1` zero digits with
///     `decpt = 1` (one integer zero, then `ndigit` fractional zeros —
///     reads as "0.00…0").
///   * `|value| >= 1`: digits are the integer part concatenated with
///     `ndigit` rounded fractional digits, no leading zeros stripped.
///     `decpt = number of integer digits`.
///   * `0 < |value| < 1` and rounded fraction is non-zero: digits are
///     the significant fractional digits with leading zeros STRIPPED.
///     `decpt = -(count of stripped leading zeros)`.
///   * `0 < |value| < 1` but the rounding to `ndigit` fractional
///     places yields exactly zero: digits are EMPTY, `decpt = -ndigit`.
///
/// The previous implementation kept all leading zeros from the
/// formatted string and computed `decpt` as the position of the
/// decimal point in that retained-zeros string, which diverged from
/// glibc on every sub-1 magnitude. Empirical glibc samples (probed
/// against glibc 2.38 on Linux/x86_64):
///
///   fcvt(0.0001234, 4) -> digits="1"   decpt=-3   (was: "00001" decpt=1)
///   fcvt(0.0001234, 6) -> digits="123" decpt=-3   (was: "0000001" decpt=1)
///   fcvt(1e-10, 4)     -> digits=""    decpt=-4   (was: "00000" decpt=1)
///   fcvt(1e-10, 6)     -> digits=""    decpt=-6
pub fn fcvt(value: f64, ndigit: i32) -> (Vec<u8>, i32, bool) {
    let negative = value.is_sign_negative() && !value.is_nan();
    let abs_val = value.abs();

    if !value.is_finite() {
        return nonfinite_cvt(value);
    }

    let ndigit = (ndigit.max(0) as usize).min(MAX_LEGACY_CVT_DIGITS);

    // Special case: exact zero. Glibc emits ndigit+1 zeros with
    // decpt=1 — i.e., one integer zero plus ndigit fractional zeros.
    if abs_val == 0.0 {
        let digits = vec![b'0'; ndigit + 1];
        return (digits, 1, negative);
    }

    // Round to ndigit fractional places. Rust's "{:.N$}" rounds to
    // nearest-even at the boundary, matching glibc fcvt.
    let formatted = format!("{:.prec$}", abs_val, prec = ndigit);

    // Split at the decimal point. ndigit=0 produces no decimal point;
    // treat the whole string as integer in that case.
    let (int_part, frac_part) = match formatted.find('.') {
        Some(dot) => (&formatted[..dot], &formatted[dot + 1..]),
        None => (formatted.as_str(), ""),
    };

    if int_part != "0" {
        // |value| >= 1: digits = int + frac concatenated, decpt =
        // length of integer part.
        let mut digits = Vec::with_capacity(int_part.len() + frac_part.len());
        digits.extend_from_slice(int_part.as_bytes());
        digits.extend_from_slice(frac_part.as_bytes());
        return (digits, int_part.len() as i32, negative);
    }

    if ndigit == 0 {
        // Rounding a non-zero sub-unit value to zero fractional places
        // still returns the rounded integer digit.
        return (b"0".to_vec(), 1, negative);
    }

    // int_part == "0", so |value| < 1. Either rounding produced
    // significant fractional digits (in which case strip leading
    // zeros) or rounding yielded exactly zero.
    let first_nonzero = frac_part.bytes().position(|b| b != b'0');
    match first_nonzero {
        Some(idx) => {
            let digits = frac_part.as_bytes()[idx..].to_vec();
            (digits, -(idx as i32), negative)
        }
        None => {
            // Rounded to zero. Glibc convention: empty digits,
            // decpt = -ndigit (records "the rounded magnitude was
            // smaller than 10^-ndigit").
            (Vec::new(), -(ndigit as i32), negative)
        }
    }
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
    // glibc renders with `%.*g`: a NEGATIVE precision is taken as "omitted" and
    // falls back to the default 6 significant digits; 0 is bumped to 1 by `%g`;
    // anything above DBL_DECIMAL_DIG (17) is clamped (no meaningful extra
    // precision for a double).
    let ndigit = if ndigit < 0 {
        6
    } else {
        (ndigit as usize).clamp(1, GCVT_MAX_SIG_DIGITS)
    };
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
        // glibc's `%g` preserves the NaN sign bit: gcvt(-nan) -> "-nan".
        return if value.is_sign_negative() {
            String::from("-nan")
        } else {
            String::from("nan")
        };
    }
    if value.is_infinite() {
        return if value < 0.0 {
            String::from("-inf")
        } else {
            String::from("inf")
        };
    }
    if value == 0.0 {
        // glibc's %g preserves the sign of zero: gcvt(-0.0) -> "-0", gcvt(0.0)
        // -> "0" (no trailing decimal in either case). `value == 0.0` matches
        // both +0.0 and -0.0, so distinguish via the sign bit.
        return if value.is_sign_negative() {
            String::from("-0")
        } else {
            String::from("0")
        };
    }

    // Pick format based on the decimal exponent the value rounds to.
    // The C/glibc %g switch keys off X = the exponent a `%e` conversion
    // would emit — i.e. the exponent AFTER rounding to `ndigit`
    // significant digits, not floor(log10) of the raw value. Boundary
    // values whose rounding carries into a new power of ten must follow
    // their rounded magnitude: 9.9999e-5 rounds to 1e-4 (X = -4, fixed,
    // "0.0001"), 999999.9 rounds to 1e6 (X = 6, scientific, "1e+06").
    let abs = value.abs();
    let exp = rounded_decimal_exp(abs, ndigit);

    if exp < -4 || exp >= ndigit as i32 {
        format_scientific(value, ndigit)
    } else {
        format_fixed(value, ndigit, exp)
    }
}

/// Decimal exponent X of `abs` after rounding to `ndigit` significant
/// digits — exactly what a `%e` conversion would print. Computed by
/// formatting once in scientific notation (which performs the same
/// round-half-to-even at the boundary) and parsing the exponent field.
/// This sidesteps both the floor(log10) off-by-one near exact powers of
/// ten and the rounding-carry that shifts the exponent of the rounded
/// value relative to the raw one.
fn rounded_decimal_exp(abs: f64, ndigit: usize) -> i32 {
    let sci = format!("{:.prec$e}", abs, prec = ndigit.saturating_sub(1));
    match sci.find('e') {
        Some(pos) => sci[pos + 1..].parse::<i32>().unwrap_or(0),
        None => 0,
    }
}

/// A `core::fmt::Write` target backed by a fixed stack buffer, so the float
/// rendering below produces the same bytes as `format!` without the per-call
/// heap allocation. 384 bytes covers any gcvt-range fixed/scientific output
/// (≤ ~17 integer digits + '.' + ≤ 20 fraction digits); the leaf functions fall
/// back to a heap `format!` if it ever overflowed (it cannot in that range).
struct StackStr {
    buf: [u8; 384],
    len: usize,
}
impl StackStr {
    #[inline]
    fn new() -> Self {
        Self {
            buf: [0; 384],
            len: 0,
        }
    }
    #[inline]
    fn as_str(&self) -> &str {
        // Only `core::fmt` UTF-8 fragments are ever written here; the validation
        // over these few dozen ASCII bytes is negligible vs the saved heap alloc.
        core::str::from_utf8(&self.buf[..self.len]).unwrap_or("")
    }
}
impl core::fmt::Write for StackStr {
    #[inline]
    fn write_str(&mut self, s: &str) -> core::fmt::Result {
        let b = s.as_bytes();
        let end = self.len.checked_add(b.len()).ok_or(core::fmt::Error)?;
        if end > self.buf.len() {
            return Err(core::fmt::Error);
        }
        self.buf[self.len..end].copy_from_slice(b);
        self.len = end;
        Ok(())
    }
}

fn format_fixed(value: f64, ndigit: usize, exp: i32) -> String {
    use core::fmt::Write;
    let frac = (ndigit as i32 - 1 - exp).max(0) as usize;
    let mut sb = StackStr::new();
    if write!(sb, "{value:.frac$}").is_ok() {
        strip_trailing_zeros(sb.as_str())
    } else {
        strip_trailing_zeros(&format!("{value:.frac$}"))
    }
}

fn format_scientific(value: f64, ndigit: usize) -> String {
    use core::fmt::Write;
    let frac = ndigit.saturating_sub(1);
    let mut sb = StackStr::new();
    if write!(sb, "{value:.frac$e}").is_ok() {
        rust_e_to_glibc_e(sb.as_str())
    } else {
        rust_e_to_glibc_e(&format!("{value:.frac$e}"))
    }
}

/// Render `value` as printf-style `%.<ndigit>g` (significant digits +
/// auto fixed/scientific switch). Wraps the internal `render_gcvt` so
/// other stdlib code — `strfromd` in frankenlibc-abi — can reuse the
/// same exponent-switch + trailing-zero-strip logic without
/// duplicating it.
pub fn render_pct_g(value: f64, ndigit: usize) -> String {
    render_gcvt(value, ndigit.max(1))
}

/// Render `value` as printf-style `%.<ndigit>e` (always scientific,
/// fractional precision = ndigit, C-style `e+02` exponent). Trailing
/// zeros in the mantissa are NOT stripped — `%e` keeps explicit
/// zeros in its precision-padded output, unlike `%g` which strips.
pub fn render_pct_e(value: f64, ndigit: usize) -> String {
    let rust_form = format!("{:.prec$e}", value, prec = ndigit);
    rust_e_to_glibc_e_no_strip(&rust_form)
}

/// Like `rust_e_to_glibc_e` but does NOT strip trailing zeros from
/// the mantissa — `%e` callers want full padding, `%g` callers don't.
fn rust_e_to_glibc_e_no_strip(s: &str) -> String {
    let Some(e_pos) = s.find('e') else {
        return s.to_string();
    };
    let mantissa = &s[..e_pos];
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

    /// Pinned reference values captured from host glibc 2.38 on
    /// Linux/x86_64. Each row is `(value, ndigit, expected_digits,
    /// expected_decpt, expected_negative)`. These pin the fcvt
    /// rewrite (leading-zero strip + rounded-to-zero handling) at
    /// the unit-test level so future drift is caught even when the
    /// ABI conformance harness can't compile.
    #[test]
    fn fcvt_matches_glibc_reference_outputs() {
        let cases: &[(f64, i32, &[u8], i32, bool)] = &[
            (0.0, 0, b"0", 1, false),
            (0.0, 4, b"00000", 1, false),
            (1.0, 4, b"10000", 1, false),
            (-1.0, 4, b"10000", 1, true),
            (123.456, 4, b"1234560", 3, false),
            (-12345.0, 4, b"123450000", 5, true),
            (0.0001234, 0, b"0", 1, false), // rounded to integer zero
            (0.0001234, 2, b"", -2, false), // rounded to zero
            (0.0001234, 4, b"1", -3, false),
            (0.0001234, 6, b"123", -3, false),
            (1e10, 4, b"100000000000000", 11, false),
            (1e-10, 4, b"", -4, false), // rounded to zero
            (1e-10, 6, b"", -6, false), // rounded to zero
            (1e-10, 0, b"0", 1, false), // rounded to integer zero
        ];
        for &(value, ndigit, expected_digits, expected_decpt, expected_neg) in cases {
            let (digits, decpt, neg) = fcvt(value, ndigit);
            assert_eq!(digits, expected_digits, "fcvt({value}, {ndigit}) digits");
            assert_eq!(decpt, expected_decpt, "fcvt({value}, {ndigit}) decpt");
            assert_eq!(neg, expected_neg, "fcvt({value}, {ndigit}) sign");
        }
    }

    /// Pinned reference values for non-finite `ecvt`/`fcvt` inputs against
    /// host glibc 2.38 on Linux/x86_64. glibc embeds the sign in the returned
    /// digit buffer ("-inf"/"-nan") and reports `*sign = 0` for every
    /// NaN/infinity — including `-nan`. Each row is
    /// `(value, expected_digits)`; decpt is always 0 and the returned
    /// `is_negative` flag is always false (so the ABI emits sign=0).
    #[test]
    fn ecvt_fcvt_nonfinite_match_glibc() {
        let cases: &[(f64, &[u8])] = &[
            (f64::NAN, b"nan"),
            (-f64::NAN, b"-nan"),
            (f64::INFINITY, b"inf"),
            (f64::NEG_INFINITY, b"-inf"),
        ];
        for &(value, expected) in cases {
            for ndigit in [0, 1, 6, 17] {
                let (e_digits, e_decpt, e_neg) = ecvt(value, ndigit);
                assert_eq!(e_digits, expected, "ecvt({value}, {ndigit}) digits");
                assert_eq!(e_decpt, 0, "ecvt({value}, {ndigit}) decpt");
                assert!(!e_neg, "ecvt({value}, {ndigit}) reports sign=0");

                let (f_digits, f_decpt, f_neg) = fcvt(value, ndigit);
                assert_eq!(f_digits, expected, "fcvt({value}, {ndigit}) digits");
                assert_eq!(f_decpt, 0, "fcvt({value}, {ndigit}) decpt");
                assert!(!f_neg, "fcvt({value}, {ndigit}) reports sign=0");
            }
        }
    }

    /// Pinned reference values for gcvt against host glibc. Covers
    /// every branch of the new %g algorithm: zero special case,
    /// fixed-format, scientific-format (large + small magnitudes),
    /// trailing-zero stripping, exponent reshape (`e+02`, `e-10`).
    #[test]
    fn gcvt_matches_glibc_reference_outputs() {
        let cases: &[(f64, i32, &[u8])] = &[
            (0.0, 1, b"0"),
            (0.0, 6, b"0"),
            (1.0, 1, b"1"),
            (1.0, 6, b"1"),
            (-1.0, 6, b"-1"),
            (123.456, 1, b"1e+02"),
            (123.456, 2, b"1.2e+02"),
            (123.456, 6, b"123.456"),
            (123.456, 10, b"123.456"),
            (-12345.0, 1, b"-1e+04"),
            (-12345.0, 6, b"-12345"),
            (0.0001234, 1, b"0.0001"),
            (0.0001234, 6, b"0.0001234"),
            (1e10, 1, b"1e+10"),
            (1e10, 10, b"1e+10"),
            (1e-10, 1, b"1e-10"),
            (1.5e20, 1, b"2e+20"),
            (1.5e20, 2, b"1.5e+20"),
            // Rounding-carries-the-exponent cases: the %e-vs-%f switch
            // must key off the exponent AFTER rounding to `ndigit`
            // significant digits, not floor(log10) of the raw value.
            // glibc 2.38 / Linux-x86_64 (cross-checked with printf %g):
            (9.9999e-5, 1, b"0.0001"), // raw exp -5 → rounds to 1e-4 → fixed
            (9.9999e-5, 2, b"0.0001"), // rounds to 1.0e-4 → fixed
            (9.6e-5, 1, b"0.0001"),    // rounds up across the -4 boundary
            (9.5e-5, 1, b"0.0001"),    // ties-to-even up to 1e-4
            (999999.9, 6, b"1e+06"),   // raw exp 5 → rounds to 1e6 → sci
            (999999.5, 6, b"1e+06"),   // ties up to 1e6 → sci
            (99999.9, 5, b"1e+05"),    // raw exp 4 → rounds to 1e5 → sci
            (999999.0, 6, b"999999"),  // no carry: stays fixed
            (0.00012345, 2, b"0.00012"),
        ];
        for &(value, ndigit, expected) in cases {
            let mut buf = [0u8; 64];
            let len = gcvt(value, ndigit, &mut buf);
            assert_eq!(
                &buf[..len],
                expected,
                "gcvt({value}, {ndigit}) -> {:?}, expected {:?}",
                std::str::from_utf8(&buf[..len]).unwrap_or("<invalid utf8>"),
                std::str::from_utf8(expected).unwrap_or("<invalid utf8>"),
            );
        }
    }

    #[test]
    fn huge_precision_is_clamped_before_formatting() {
        let (digits, _, _) = ecvt(1.25, i32::MAX);
        assert_eq!(digits.len(), MAX_LEGACY_CVT_DIGITS);

        let (digits, _, _) = fcvt(1.25, i32::MAX);
        assert_eq!(digits.len(), MAX_LEGACY_CVT_DIGITS + 1);

        let mut buf = [0u8; 16];
        let len = gcvt(1.25, i32::MAX, &mut buf);
        assert!(len < buf.len());
        assert_eq!(buf[len], 0);
    }
}
