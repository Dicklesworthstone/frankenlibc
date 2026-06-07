//! `strfmon` monetary formatting for the C/POSIX locale.
//!
//! Implements the directive grammar `%[flags][field width][#left precision]`
//! `[.right precision]{i|n|%}` exactly as glibc renders it in the C locale,
//! where the monetary `lconv` fields are all empty/unspecified:
//!   * no currency symbol (so `%i` international and `%n` national are identical);
//!   * decimal point `.`, no thousands grouping;
//!   * default fractional digits = 2 (`frac_digits`/`int_frac_digits` unset);
//!   * the negative sign is `-`, the positive sign is empty.
//!
//! Flag semantics (verified against host glibc via `strfmon_differential_fuzz`):
//!   * `=f` — the numeric fill character `f`; used ONLY to pad the `#` left
//!     precision. Field-width padding always uses spaces.
//!   * `^` — disable grouping (a no-op here: the C locale never groups).
//!   * `+` — use the locale sign pair (a no-op: C positive sign is empty and the
//!     default already renders `-` for negatives).
//!   * `(` — enclose negative amounts in parentheses (replaces the `-` sign).
//!   * `!` — suppress the currency symbol (a no-op: already empty).
//!   * `-` — left-justify within the field width (default is right-justify).
//!
//! Left-precision (`#n`) reserves at least `n` digit positions for the integer
//! part (fill-padded) AND always emits a one-character sign slot to its left
//! (`-` for negatives, a space for positives) so signed and unsigned values
//! line up. Without `#`, only negatives emit a leading `-`.

extern crate alloc;
use alloc::vec::Vec;

/// Parsed pieces of one `%` directive.
struct Spec {
    left_justify: bool,
    use_parens: bool,
    fill: u8,
    field_width: usize,
    left_prec: Option<usize>,
    right_prec: Option<usize>,
    conv: u8,
}

/// Format `format`, pulling one `f64` per `%i`/`%n` conversion from `pull`.
///
/// Returns the rendered bytes, or `None` on a malformed directive (the caller
/// maps that to a `-1` / `EINVAL` result, matching glibc). Literal text and
/// `%%` are copied verbatim.
pub fn strfmon_c(format: &[u8], mut pull: impl FnMut() -> f64) -> Option<Vec<u8>> {
    let mut out: Vec<u8> = Vec::with_capacity(format.len() + 16);
    let mut i = 0usize;
    while i < format.len() {
        let c = format[i];
        if c != b'%' {
            out.push(c);
            i += 1;
            continue;
        }
        // At '%': parse a directive.
        i += 1;
        match format.get(i) {
            None => return None, // trailing '%'
            Some(&b'%') => {
                out.push(b'%');
                i += 1;
                continue;
            }
            _ => {}
        }
        let spec = parse_spec(format, &mut i)?;
        let prec = match spec.conv {
            b'i' | b'n' => spec.right_prec.unwrap_or(2),
            _ => return None, // invalid conversion specifier
        };
        let value = pull();
        let field = render_value(value, prec, &spec);
        apply_field_width(&mut out, &field, spec.field_width, spec.left_justify);
    }
    Some(out)
}

/// Parse the directive body after the leading `%` (and not a `%%`). `i` points
/// at the first flag/width byte and is advanced past the conversion specifier.
fn parse_spec(format: &[u8], i: &mut usize) -> Option<Spec> {
    let mut left_justify = false;
    let mut use_parens = false;
    let mut use_plus = false;
    let mut fill = b' ';
    // Flags (any order, repeatable).
    loop {
        match format.get(*i) {
            Some(b'=') => {
                *i += 1;
                fill = *format.get(*i)?; // char after '=' is the fill char
                *i += 1;
            }
            Some(b'^') | Some(b'!') => *i += 1, // no-ops in the C locale
            Some(b'+') => {
                use_plus = true;
                *i += 1;
            }
            Some(b'(') => {
                use_parens = true;
                *i += 1;
            }
            Some(b'-') => {
                left_justify = true;
                *i += 1;
            }
            _ => break,
        }
    }
    // `+` and `(` are mutually exclusive negative-sign representations; glibc
    // rejects a directive that specifies both (returns -1 / EINVAL).
    if use_plus && use_parens {
        return None;
    }
    // Field width (optional decimal).
    let field_width = read_uint(format, i).unwrap_or(0);
    // Left precision `#n` (digits required after '#').
    let left_prec = if format.get(*i) == Some(&b'#') {
        *i += 1;
        Some(read_uint(format, i)?)
    } else {
        None
    };
    // Right precision `.p` (digits required after '.').
    let right_prec = if format.get(*i) == Some(&b'.') {
        *i += 1;
        Some(read_uint(format, i)?)
    } else {
        None
    };
    let conv = *format.get(*i)?;
    *i += 1;
    Some(Spec {
        left_justify,
        use_parens,
        fill,
        field_width,
        left_prec,
        right_prec,
        conv,
    })
}

/// Read a run of ASCII digits as an unsigned value; `None` if no digit is
/// present at `*i`. Advances `*i` past the digits on success.
fn read_uint(format: &[u8], i: &mut usize) -> Option<usize> {
    let start = *i;
    let mut v = 0usize;
    while let Some(&d) = format.get(*i) {
        if d.is_ascii_digit() {
            v = v.saturating_mul(10).saturating_add((d - b'0') as usize);
            *i += 1;
        } else {
            break;
        }
    }
    if *i == start { None } else { Some(v) }
}

/// Render the signed monetary value (without field-width padding).
fn render_value(value: f64, prec: usize, spec: &Spec) -> Vec<u8> {
    // Magnitude with `prec` fractional digits (round-half-to-even, as glibc).
    let mag = format_fixed(value.abs(), prec);
    let (int_part, frac_part) = match mag.iter().position(|&b| b == b'.') {
        Some(dot) => (&mag[..dot], &mag[dot..]),
        None => (&mag[..], &b""[..]),
    };
    let negative = value.is_sign_negative();

    // Fill-pad the integer part to the left precision.
    let mut intbuf: Vec<u8> = Vec::new();
    if let Some(lp) = spec.left_prec {
        for _ in int_part.len()..lp {
            intbuf.push(spec.fill);
        }
    }
    intbuf.extend_from_slice(int_part);

    let mut field: Vec<u8> = Vec::new();
    if spec.use_parens && negative {
        field.push(b'(');
        field.extend_from_slice(&intbuf);
        field.extend_from_slice(frac_part);
        field.push(b')');
    } else {
        if negative {
            field.push(b'-');
        } else if spec.left_prec.is_some() {
            field.push(b' '); // positive sign slot keeps alignment under `#`
        }
        field.extend_from_slice(&intbuf);
        field.extend_from_slice(frac_part);
    }
    field
}

/// Format a non-negative finite `f64` with exactly `prec` fractional digits,
/// rounding ties to even (matching glibc's `printf`-style conversion).
fn format_fixed(x: f64, prec: usize) -> Vec<u8> {
    // `alloc::format!` uses the same correctly-rounded, round-half-to-even
    // conversion as glibc's `%f`, so this is bit-for-bit comparable.
    alloc::format!("{x:.prec$}").into_bytes()
}

/// Append `field` to `out`, padded with spaces to `width` (right-justified
/// unless `left_justify`).
fn apply_field_width(out: &mut Vec<u8>, field: &[u8], width: usize, left_justify: bool) {
    if field.len() >= width {
        out.extend_from_slice(field);
        return;
    }
    let pad = width - field.len();
    if left_justify {
        out.extend_from_slice(field);
        out.extend(core::iter::repeat_n(b' ', pad));
    } else {
        out.extend(core::iter::repeat_n(b' ', pad));
        out.extend_from_slice(field);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Run `strfmon_c` with a single value and return the bytes as a String.
    fn one(fmt: &str, val: f64) -> String {
        let mut used = false;
        let bytes = strfmon_c(fmt.as_bytes(), || {
            used = true;
            val
        })
        .expect("valid format");
        String::from_utf8(bytes).unwrap()
    }

    #[test]
    fn golden_c_locale_matches_glibc() {
        // Values captured from host glibc strfmon in the C locale.
        assert_eq!(one("%n", 1234.567), "1234.57");
        assert_eq!(one("%n", -1234.567), "-1234.57");
        assert_eq!(one("%n", 0.0), "0.00");
        assert_eq!(one("%n", 0.005), "0.01");
        assert_eq!(one("%i", 1_000_000.0), "1000000.00");
        assert_eq!(one("%11n", 1234.567), "    1234.57");
        assert_eq!(one("%11n", -1234.567), "   -1234.57");
        assert_eq!(one("%#6n", 1234.567), "   1234.57");
        assert_eq!(one("%#6n", -1234.567), "-  1234.57");
        assert_eq!(one("%#6.3n", 1234.567), "   1234.567");
        assert_eq!(one("%#6.3n", -1234.567), "-  1234.567");
        assert_eq!(one("%.0n", 1234.567), "1235");
        assert_eq!(one("%.0n", 0.5), "0"); // round half to even
        assert_eq!(one("%.4n", 1234.567), "1234.5670");
        assert_eq!(one("Cost: %n!", 1234.567), "Cost: 1234.57!");
        assert_eq!(one("%%", 0.0), "%");
        assert_eq!(one("%-11n", 1234.567), "1234.57    ");
        assert_eq!(one("%-11n", -1234.567), "-1234.57   ");
        assert_eq!(one("%(n", -1234.567), "(1234.57)");
        assert_eq!(one("%(n", 1234.567), "1234.57");
        assert_eq!(one("%(#7.2n", -1234.567), "(   1234.57)");
        assert_eq!(one("%(#7.2n", 1234.567), "    1234.57");
        assert_eq!(one("%^#10.2i", 1234.567), "       1234.57");
        assert_eq!(one("%^#10.2i", -1234.567), "-      1234.57");
        assert_eq!(one("%^#10.2i", 12.0), "         12.00");
    }

    #[test]
    fn multiple_conversions_pull_in_order() {
        let vals = [1.0_f64, -2.5_f64];
        let mut it = vals.iter().copied();
        let bytes = strfmon_c(b"%n / %(n", || it.next().unwrap()).unwrap();
        assert_eq!(String::from_utf8(bytes).unwrap(), "1.00 / (2.50)");
    }

    #[test]
    fn fill_char_pads_left_precision_only() {
        // `=*` sets the fill for the `#` left precision: "12" padded to 6 with
        // '*' is "****12", preceded by the positive sign-slot space.
        assert_eq!(one("%=*#6n", 12.0), " ****12.00");
    }

    #[test]
    fn malformed_directives_rejected() {
        assert!(strfmon_c(b"%", || 0.0).is_none()); // trailing '%'
        assert!(strfmon_c(b"%z", || 0.0).is_none()); // bad conversion
        assert!(strfmon_c(b"%#n", || 0.0).is_none()); // '#' without digits
        assert!(strfmon_c(b"%+(n", || 0.0).is_none()); // '+' and '(' conflict
        assert!(strfmon_c(b"%(+n", || 0.0).is_none()); // order-independent
    }
}
