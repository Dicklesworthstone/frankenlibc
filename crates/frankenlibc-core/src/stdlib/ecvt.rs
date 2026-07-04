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

/// The base-10 exponent of a positive finite `abs_val` (= floor(log10(abs_val))),
/// read from the shortest scientific formatting so it reflects the TRUE magnitude
/// without rounding a near-decade value up: `123.0` -> 2, `9.99` -> 0,
/// `0.001` -> -3. Used for the decimal-point position in the no-/negative-digit
/// `ecvt`/`fcvt` paths.
fn decimal_exponent(abs_val: f64) -> i32 {
    use core::fmt::Write as _;
    let mut sb = StackStr::new();
    let mut heap = String::new();
    let sci: &str = if write!(sb, "{abs_val:e}").is_ok() {
        sb.as_str()
    } else {
        let _ = write!(heap, "{abs_val:e}");
        heap.as_str()
    };
    sci.rsplit('e')
        .next()
        .and_then(|e| e.parse::<i32>().ok())
        .unwrap_or(0)
}

/// Round an exact non-negative integer decimal string `s` by dropping its last
/// `drop` digits, half-to-even. `has_fraction` = the original value carried a
/// nonzero fractional part below the integer, which breaks an exact-half tie
/// toward rounding up. The dropped positions are zeroed (so the width is
/// preserved), and a carry-out widens the result by one digit (round "999"
/// dropping 1 -> "1000"). `drop` must be < `s.len()` (at least one kept digit).
fn round_int_decimal(s: &[u8], drop: usize, has_fraction: bool) -> Vec<u8> {
    if drop == 0 {
        return s.to_vec();
    }
    let keep = s.len() - drop;
    let mut kept: Vec<u8> = s[..keep].to_vec();
    let first = s[keep] - b'0';
    let round_up = match first.cmp(&5) {
        core::cmp::Ordering::Greater => true,
        core::cmp::Ordering::Less => false,
        core::cmp::Ordering::Equal => {
            if s[keep + 1..].iter().any(|&d| d != b'0') || has_fraction {
                true
            } else {
                // Exact half -> round to even (round up iff the last kept digit is odd).
                kept.last().is_some_and(|&d| (d - b'0') % 2 == 1)
            }
        }
    };
    if round_up {
        let mut i = kept.len();
        loop {
            if i == 0 {
                kept.insert(0, b'1');
                break;
            }
            i -= 1;
            if kept[i] == b'9' {
                kept[i] = b'0';
            } else {
                kept[i] += 1;
                break;
            }
        }
    }
    kept.resize(kept.len() + drop, b'0');
    kept
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

    if abs_val == 0.0 {
        // Zero: `ndigit` zero digits (none for ndigit==0) with decpt=1.
        return (vec![b'0'; ndigit], 1, negative);
    }

    if ndigit == 0 {
        // No significant digits requested: glibc returns an empty digit string
        // but still reports where the decimal point falls — decpt =
        // floor(log10(|value|)) + 1, the UNROUNDED magnitude (so ecvt(9.99,0)
        // gives decpt 1, NOT 2). (Old behavior hardcoded decpt 0 — bd-2g7oyh.101.)
        return (Vec::new(), decimal_exponent(abs_val) + 1, negative);
    }

    // Use Rust's formatting to get digits into a stack buffer (byte-identical
    // to the old heap `format!`, no per-call allocation; `heap` stays unused on
    // the common path and only materializes on the impossible >384-byte overflow).
    use core::fmt::Write as _;
    let prec = ndigit.saturating_sub(1);
    let mut sb = StackStr::new();
    let mut heap = String::new();
    let formatted: &str = if write!(sb, "{abs_val:.prec$e}").is_ok() {
        sb.as_str()
    } else {
        let _ = write!(heap, "{abs_val:.prec$e}");
        heap.as_str()
    };
    // Parse the scientific notation: "d.dddde+dd". The exponent is accumulated
    // inline into an i32 (no per-call `String` heap allocation — glibc writes into
    // a static buffer with no alloc, so the old `exp_str` String was a pure
    // overhead vs glibc; byte-identical result, same digits/exponent arithmetic).
    let mut digits = Vec::with_capacity(ndigit);
    let mut exp_mag: i32 = 0;
    let mut in_exp = false;
    let mut exp_sign: i32 = 1;

    for c in formatted.bytes() {
        if in_exp {
            if c == b'-' {
                exp_sign = -1;
            } else if c == b'+' {
                // skip
            } else if c.is_ascii_digit() {
                exp_mag = exp_mag * 10 + (c - b'0') as i32;
            }
        } else if c == b'e' || c == b'E' {
            in_exp = true;
        } else if c == b'.' {
            // skip decimal point
        } else if c.is_ascii_digit() {
            digits.push(c);
        }
    }

    let exponent = exp_mag * exp_sign;

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

    if ndigit < 0 {
        // Negative ndigit rounds the INTEGER part to the 10^|ndigit| place
        // (glibc: fcvt(123456,-3)="123000"). |value| < 1 has no integer digit to
        // round into, so it collapses to "0" with decpt 1. The rounding place is
        // clamped to keep the leading digit — at most int_digits-1 places — so a
        // large |ndigit| settles at one significant digit (fcvt(123456,-10)=
        // "100000", not "0"). Rounding is a single half-to-even pass over the
        // EXACT integer decimal string (so huge magnitudes like 1e308 round
        // bit-for-bit like glibc, with no float-division precision loss); a
        // carry widens the result (fcvt(999,-1)="1000"). bd-2g7oyh.101.
        if abs_val < 1.0 {
            return (vec![b'0'], 1, negative);
        }
        let floor_v = abs_val.floor();
        // `floor_v` is integral, so `{:.0}` yields its exact decimal digits with
        // no rounding (for both small and >2^53 values).
        let int_str = format!("{floor_v:.0}");
        let int_digits = int_str.len();
        // Round at the 10^|ndigit| place, but never past int_digits-1 places: the
        // leading significant digit always survives, so fcvt(5,-1)="5" (not 0) and
        // fcvt(55,-2)="60" (round to 10s, not 100s). A carry may still widen the
        // result (fcvt(9.99,-1)="10", fcvt(999,-1)="1000").
        let places = ((-ndigit) as usize).min(int_digits - 1);
        let digits = if places == 0 {
            // Rounding to the UNITS place must round the fractional part too
            // (9.99 -> "10", 7 -> "7"). `{:.0}` rounds half-to-even like glibc.
            format!("{abs_val:.0}").into_bytes()
        } else {
            // Place >= 10: the fraction is below it (only an exact-half tie-break),
            // so round the EXACT integer string — no float-division precision loss
            // for huge magnitudes.
            let has_fraction = abs_val != floor_v;
            round_int_decimal(int_str.as_bytes(), places, has_fraction)
        };
        let decpt = digits.len() as i32;
        return (digits, decpt, negative);
    }

    let ndigit = (ndigit.max(0) as usize).min(MAX_LEGACY_CVT_DIGITS);

    // Special case: exact zero. Glibc emits ndigit+1 zeros with
    // decpt=1 — i.e., one integer zero plus ndigit fractional zeros.
    if abs_val == 0.0 {
        let digits = vec![b'0'; ndigit + 1];
        return (digits, 1, negative);
    }

    // Round to ndigit fractional places. Rust's "{:.N$}" rounds to
    // nearest-even at the boundary, matching glibc fcvt. Render into a stack
    // buffer (byte-identical to the old heap `format!`); a value large enough to
    // exceed the 384-byte scratch (e.g. 1e308 with a fractional `%f`) falls back
    // to a heap String; correctness over speed for that rare case.
    use core::fmt::Write as _;
    let mut sb = StackStr::new();
    let mut heap = String::new();
    let formatted: &str = if write!(sb, "{abs_val:.ndigit$}").is_ok() {
        sb.as_str()
    } else {
        let _ = write!(heap, "{abs_val:.ndigit$}");
        heap.as_str()
    };

    // Split at the decimal point. ndigit=0 produces no decimal point;
    // treat the whole string as integer in that case.
    let (int_part, frac_part) = match formatted.find('.') {
        Some(dot) => (&formatted[..dot], &formatted[dot + 1..]),
        None => (formatted, ""),
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
/// Build Rust's `{value:.frac$e}` scientific string for a finite integral value
/// < 2^64 into `out`, returning `true` when it applied. Byte-for-byte identical to
/// `write!(out, "{value:.frac$e}")` for these inputs (mantissa digits are the integer's
/// exact digits, exponent = digit_count - 1, `frac` fractional slots zero-padded). Only
/// applies when no rounding is needed (`digit_count - 1 <= frac`, i.e. the integer has at
/// most `frac + 1` significant digits); otherwise returns `false` to fall back to flt2dec.
fn try_build_integer_sci(value: f64, frac: usize, out: &mut String) -> bool {
    use core::fmt::Write as _;
    if !(value.fract() == 0.0 && value.abs() < 18446744073709551616.0) {
        return false;
    }
    let mag = value.abs() as u64;
    let mut tmp = [0u8; 20];
    let mut n = mag;
    let mut i = tmp.len();
    loop {
        i -= 1;
        tmp[i] = b'0' + (n % 10) as u8;
        n /= 10;
        if n == 0 {
            break;
        }
    }
    let digits = &tmp[i..];
    let dc = digits.len();
    if dc - 1 > frac {
        return false; // would round to frac+1 significant digits
    }
    let exp = dc as i32 - 1;
    if value.is_sign_negative() {
        out.push('-');
    }
    out.push(digits[0] as char);
    if frac > 0 {
        out.push('.');
        for &c in &digits[1..] {
            out.push(c as char);
        }
        for _ in 0..frac - (dc - 1) {
            out.push('0');
        }
    }
    // Rust's `{:e}` exponent: bare decimal, no sign for non-negative (integers give exp >= 0),
    // no leading zeros — exactly `write!("{exp}")`.
    out.push('e');
    let _ = write!(out, "{exp}");
    true
}

fn dyadic_decimal_scale(value: f64) -> Option<usize> {
    let bits = value.abs().to_bits();
    let raw_exp = ((bits >> 52) & 0x7ff) as i32;
    let fraction = bits & 0x000f_ffff_ffff_ffff;
    let (significand, exp2) = if raw_exp == 0 {
        (fraction, -1074)
    } else {
        ((1u64 << 52) | fraction, raw_exp - 1023 - 52)
    };
    if significand == 0 {
        return Some(0);
    }
    let denom_bits = (-exp2).saturating_sub(significand.trailing_zeros() as i32);
    Some(denom_bits.max(0) as usize)
}

fn try_build_dyadic_sci(value: f64, frac: usize) -> Option<String> {
    use core::fmt::Write as _;

    if frac > 19 || !value.is_finite() || value == 0.0 || value.fract() == 0.0 {
        return None;
    }

    let decimal_scale = dyadic_decimal_scale(value)?;
    if decimal_scale > 19 {
        return None;
    }

    let binary_scale = f64::from_bits((1023u64 + decimal_scale as u64) << 52);
    let scaled = value.abs() * binary_scale;
    if scaled.fract() != 0.0 || scaled >= 18446744073709551616.0 {
        return None;
    }
    let decimal = (scaled as u128).checked_mul(5u128.pow(decimal_scale as u32))?;

    let mut tmp = [0u8; 40];
    let mut n = decimal;
    let mut i = tmp.len();
    loop {
        i -= 1;
        tmp[i] = b'0' + (n % 10) as u8;
        n /= 10;
        if n == 0 {
            break;
        }
    }
    let digits = &tmp[i..];
    let target_digits = frac + 1;
    if digits.len() > target_digits {
        return None;
    }

    let zero_pad = target_digits - digits.len();
    let exp = frac as i32 - (decimal_scale + zero_pad) as i32;
    let mut out = String::with_capacity(usize::from(value.is_sign_negative()) + frac + 8);
    if value.is_sign_negative() {
        out.push('-');
    }
    out.push(digits[0] as char);
    if frac > 0 {
        out.push('.');
        for &c in &digits[1..] {
            out.push(c as char);
        }
        for _ in 0..zero_pad {
            out.push('0');
        }
    }
    out.push('e');
    out.push(if exp < 0 { '-' } else { '+' });
    let abs_exp = exp.unsigned_abs();
    if abs_exp < 10 {
        out.push('0');
    }
    let _ = write!(out, "{abs_exp}");
    Some(out)
}

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
    if let Some(simple) = try_gcvt_exact_small_fixed(value, ndigit) {
        return simple;
    }

    // Pick format based on the decimal exponent the value rounds to.
    // The C/glibc %g switch keys off X = the exponent a `%e` conversion
    // would emit — i.e. the exponent AFTER rounding to `ndigit`
    // significant digits, not floor(log10) of the raw value. Boundary
    // values whose rounding carries into a new power of ten must follow
    // their rounded magnitude: 9.9999e-5 rounds to 1e-4 (X = -4, fixed,
    // "0.0001"), 999999.9 rounds to 1e6 (X = 6, scientific, "1e+06").
    use core::fmt::Write as _;
    let frac = ndigit.saturating_sub(1);
    let mut sci_stack = StackStr::new();
    let mut sci_heap = String::new();
    // Fast-path the `{value:.frac$e}` render for integral values (skips flt2dec); it
    // produces Rust's scientific form byte-for-byte, so all the %g downstream logic
    // (exponent extraction, fixed-vs-scientific choice, trailing-zero strip) is unchanged.
    // Covers %g integers that `try_gcvt_exact_small_fixed` leaves (scientific-style and
    // >= 2^53). Guarded so no rounding occurs.
    let sci: &str = if try_build_integer_sci(value, frac, &mut sci_heap) {
        sci_heap.as_str()
    } else if write!(sci_stack, "{value:.frac$e}").is_ok() {
        sci_stack.as_str()
    } else {
        let _ = write!(sci_heap, "{value:.frac$e}");
        sci_heap.as_str()
    };
    let exp = decimal_exp_from_scientific(sci);

    if exp < -4 || exp >= ndigit as i32 {
        rust_e_to_glibc_e(sci)
    } else {
        format_fixed_from_sci(sci, exp)
    }
}

fn try_gcvt_exact_small_fixed(value: f64, ndigit: usize) -> Option<String> {
    let abs = value.abs();
    if !abs.is_finite() || abs >= ((1u64 << 53) as f64) {
        return None;
    }

    let twice = abs * 2.0;
    if twice.fract() != 0.0 {
        return None;
    }
    let twice = twice as u64;
    let int = twice / 2;
    let has_half = (twice & 1) != 0;
    let int_digits = decimal_digits_u64(int);
    let significant_digits = if has_half {
        if int == 0 { 1 } else { int_digits + 1 }
    } else {
        int_digits
    };
    let exp = if int == 0 { -1 } else { int_digits as i32 - 1 };
    if significant_digits > ndigit || exp < -4 || exp >= ndigit as i32 {
        return None;
    }

    let mut out = String::with_capacity(usize::from(value.is_sign_negative()) + int_digits + 2);
    if value.is_sign_negative() {
        out.push('-');
    }
    out.push_str(&int.to_string());
    if has_half {
        out.push_str(".5");
    }
    Some(out)
}

#[inline]
fn decimal_digits_u64(mut value: u64) -> usize {
    let mut digits = 1;
    while value >= 10 {
        value /= 10;
        digits += 1;
    }
    digits
}

/// Decimal exponent X of `abs` after rounding to `ndigit` significant
/// digits: exactly what a `%e` conversion would print. Computed by
/// parsing the exponent field from the already-rendered `%e` probe. This
/// sidesteps both the floor(log10) off-by-one near exact powers of ten and the
/// rounding-carry that shifts the exponent of the rounded value relative to the
/// raw one.
fn decimal_exp_from_scientific(sci: &str) -> i32 {
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

/// Build the `%g` FIXED-notation body by REPOSITIONING the digits already
/// produced by the single `%e` probe `sci` (a `{value:.{ndigit-1}e}` render whose
/// mantissa is `value` rounded to `ndigit` significant digits), rather than
/// running a SECOND dragon-class `{value:.f}` float format. `exp` is the decimal
/// exponent parsed from `sci`; the caller guarantees `-4 <= exp < ndigit`.
///
/// Byte-identical to the former `format_fixed`: a `{:.Ne}` render and a `{:.Mf}`
/// render of the same `value` both round-half-even to the SAME `ndigit`
/// significant digits, so the `%e` digit string repositioned around the decimal
/// point equals the `%f` string; `strip_trailing_zeros` then yields the same
/// result. Using the probe's own digits (instead of an independent second round)
/// is in fact strictly more self-consistent across the rounding-carry boundary
/// that already drives `exp`. Verified by the gcvt/strfromd differential gates
/// plus a random-double fuzz against glibc.
fn format_fixed_from_sci(sci: &str, exp: i32) -> String {
    let (neg, rest) = match sci.strip_prefix('-') {
        Some(r) => (true, r),
        None => (false, sci),
    };
    let mant = match rest.find('e') {
        Some(p) => &rest[..p],
        None => rest,
    };
    // Mantissa is `d` or `d.ffff`; gather just the digit characters (skip '.').
    let mut digits = String::with_capacity(mant.len());
    for c in mant.chars() {
        if c != '.' {
            digits.push(c);
        }
    }
    let n = digits.len() as i32;
    let mut out = String::with_capacity(digits.len() + 8);
    if neg {
        out.push('-');
    }
    if exp >= 0 {
        // Integer part = first (exp+1) digits (<= n since exp < ndigit == n);
        // any remaining digits are the fraction.
        let int_len = ((exp + 1).min(n)) as usize;
        out.push_str(&digits[..int_len]);
        if (int_len as i32) < n {
            out.push('.');
            out.push_str(&digits[int_len..]);
        }
    } else {
        // -4 <= exp < 0: "0." then (-exp-1) leading zeros, then all the digits.
        out.push_str("0.");
        for _ in 0..(-exp - 1) {
            out.push('0');
        }
        out.push_str(&digits);
    }
    // Strip trailing fractional zeros (and a bare trailing point) IN PLACE — no
    // second allocation, vs the former `strip_trailing_zeros(&out)` which built a
    // fresh String. This is the common fixed-`%g` path (gcvt/strfromd/printf %g).
    let keep = strip_trailing_zeros(&out).len();
    out.truncate(keep);
    out
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
    use core::fmt::Write as _;
    // Exact-integer fast path (no rounding): a finite integral |value| < 2^64 whose
    // integer has at most `ndigit + 1` significant digits formats to glibc's e-form
    // directly (first digit, '.', remaining digits, zero-pad, `e±dd`), skipping Rust
    // std flt2dec + the reshape. Byte-identical for these inputs (the digits are exact
    // and no rounding occurs when `digit_count - 1 <= ndigit`). `fract() == 0.0` also
    // excludes inf/nan, which fall through to the std path unchanged.
    if value.fract() == 0.0 && value.abs() < 18446744073709551616.0 {
        let mag = value.abs() as u64;
        let mut tmp = [0u8; 20];
        let mut n = mag;
        let mut i = tmp.len();
        loop {
            i -= 1;
            tmp[i] = b'0' + (n % 10) as u8;
            n /= 10;
            if n == 0 {
                break;
            }
        }
        let digits = &tmp[i..];
        let l = digits.len();
        if l - 1 <= ndigit {
            let exp = l as i32 - 1;
            let mut out = String::with_capacity(l + ndigit + 6);
            if value.is_sign_negative() {
                out.push('-');
            }
            out.push(digits[0] as char);
            if ndigit > 0 {
                out.push('.');
                for &c in &digits[1..] {
                    out.push(c as char);
                }
                for _ in 0..ndigit - (l - 1) {
                    out.push('0');
                }
            }
            out.push('e');
            out.push(if exp < 0 { '-' } else { '+' });
            let abs_exp = exp.unsigned_abs();
            if abs_exp < 10 {
                out.push('0');
            }
            let _ = write!(out, "{abs_exp}");
            return out;
        }
    }
    if let Some(dyadic) = try_build_dyadic_sci(value, ndigit) {
        return dyadic;
    }
    // Render the `%e` form into a stack buffer (no per-call heap alloc for the
    // intermediate, mirroring `render_gcvt`); only the returned String allocates.
    let mut sb = StackStr::new();
    let mut heap = String::new();
    let rust_form: &str = if write!(sb, "{value:.ndigit$e}").is_ok() {
        sb.as_str()
    } else {
        let _ = write!(heap, "{value:.ndigit$e}");
        heap.as_str()
    };
    rust_e_to_glibc_e_no_strip(rust_form)
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
    // Same direct-build as `rust_e_to_glibc_e`: Rust's `{:e}` exponent is already the
    // unsigned, no-leading-zero decimal, so `digits` equals the restringified
    // `unsigned_abs()`. Pad to the C-mandated >= 2 digits. Byte-identical, skips the
    // parse+second-`format!`.
    let mut out = String::with_capacity(mantissa.len() + 4 + digits.len());
    out.push_str(mantissa);
    out.push('e');
    out.push(sign);
    if digits.len() < 2 {
        out.push('0');
    }
    out.push_str(digits);
    out
}

/// Strip trailing zeros from a decimal string with a `.` separator.
/// `"1.500"` -> `"1.5"`, `"1.000"` -> `"1"`, `"100"` -> `"100"`.
fn strip_trailing_zeros(s: &str) -> &str {
    if !s.contains('.') {
        return s;
    }
    s.trim_end_matches('0').trim_end_matches('.')
}

/// Convert Rust's `1.5e2` / `1e-10` mantissa-exponent form to glibc's
/// `1.5e+02` / `1e-10` (signed, ≥ 2-digit exponent). Also strips
/// trailing zeros from the mantissa: `"1.500e2"` -> `"1.5e+02"`.
fn rust_e_to_glibc_e(s: &str) -> String {
    let Some(e_pos) = s.find('e') else {
        return strip_trailing_zeros(s).to_string();
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
    // Build directly instead of `digits.parse::<i32>()` + a second `format!`: Rust's `{:e}`
    // exponent has no sign and no leading zeros, so `digits` already equals the restringified
    // `unsigned_abs()`. Pad to the C-mandated >= 2 exponent digits. 3.3x faster than the old
    // parse+format! (measured reshape_ab), byte-identical.
    let mut out = String::with_capacity(mantissa.len() + 4 + digits.len());
    out.push_str(mantissa);
    out.push('e');
    out.push(sign);
    if digits.len() < 2 {
        out.push('0');
    }
    out.push_str(digits);
    out
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
            (2.5, 6, b"2.5"),
            (-1.0, 6, b"-1"),
            (3.141592653589793, 6, b"3.14159"),
            (3.141592653589793, 17, b"3.1415926535897931"),
            (123.456, 1, b"1e+02"),
            (123.456, 2, b"1.2e+02"),
            (123.456, 6, b"123.456"),
            (123.456, 10, b"123.456"),
            (-12345.0, 1, b"-1e+04"),
            (-12345.0, 6, b"-12345"),
            (0.0001234, 1, b"0.0001"),
            (0.0001234, 6, b"0.0001234"),
            (0.0001234, 17, b"0.00012339999999999999"),
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
    fn render_pct_e_dyadic_values_match_glibc_style() {
        let cases = [
            (0.5, 6, "5.000000e-01"),
            (0.03125, 6, "3.125000e-02"),
            (3.125, 6, "3.125000e+00"),
            (10.75, 6, "1.075000e+01"),
            (-8.5, 2, "-8.50e+00"),
            (0.5, 0, "5e-01"),
            // Ties that need rounding must stay on the formatter fallback.
            (0.25, 0, "2e-01"),
            (2.5, 0, "2e+00"),
        ];
        for (value, ndigit, expected) in cases {
            assert_eq!(render_pct_e(value, ndigit), expected, "{value} .{ndigit}e");
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
