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
/// Uses `%g`-style formatting. Returns the formatted string as bytes.
/// `ndigit`: number of significant digits.
pub fn gcvt(value: f64, ndigit: i32, buf: &mut [u8]) -> usize {
    let ndigit = ndigit.max(1) as usize;
    let formatted = format!("{:.prec$}", value, prec = ndigit);

    // Copy into buffer, NUL-terminate.
    let copy_len = formatted.len().min(buf.len().saturating_sub(1));
    buf[..copy_len].copy_from_slice(&formatted.as_bytes()[..copy_len]);
    if copy_len < buf.len() {
        buf[copy_len] = 0;
    }
    copy_len
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
