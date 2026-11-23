//! `strfmon` monetary formatting using immutable LC_MONETARY data.
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
use core::fmt::{self, Write as _};

use alloc::vec::Vec;

/// Fixed-capacity formatting sink used by the exact C-locale monetary path.
///
/// Keeping the sink caller-owned lets the ABI format the overwhelmingly common
/// `%n`/`%i` shape without constructing the general parser's output, field, and
/// floating-point `String` allocations.
struct FixedFormatBuffer<'a> {
    bytes: &'a mut [u8],
    len: usize,
}

impl fmt::Write for FixedFormatBuffer<'_> {
    fn write_str(&mut self, text: &str) -> fmt::Result {
        let end = self.len.checked_add(text.len()).ok_or(fmt::Error)?;
        let Some(dst) = self.bytes.get_mut(self.len..end) else {
            return Err(fmt::Error);
        };
        dst.copy_from_slice(text.as_bytes());
        self.len = end;
        Ok(())
    }
}

impl FixedFormatBuffer<'_> {
    fn write_bytes(&mut self, bytes: &[u8]) -> fmt::Result {
        let end = self.len.checked_add(bytes.len()).ok_or(fmt::Error)?;
        let Some(dst) = self.bytes.get_mut(self.len..end) else {
            return Err(fmt::Error);
        };
        dst.copy_from_slice(bytes);
        self.len = end;
        Ok(())
    }
}

/// Render the C-locale default monetary number directly into `out`.
///
/// This is the closed specialization for `%n`, `%i`, `%.2n`, and `%.2i`:
/// the C locale has no currency symbol or grouping and its default precision
/// is exactly two fractional digits. `None` means the caller-provided scratch
/// buffer was too small.
pub fn strfmon_c_default_into(out: &mut [u8], value: f64) -> Option<usize> {
    let mut writer = FixedFormatBuffer { bytes: out, len: 0 };
    if value.is_nan() {
        if value.is_sign_negative() {
            writer.write_char('-').ok()?;
        }
        writer.write_str("nan").ok()?;
    } else if let Some(scaled) = crate::stdio::printf::rounded_scaled_fixed(value, 2) {
        // The printf engine's integer scaler computes
        // round_ties_even(abs(value) * 100) exactly from the binary64 mantissa.
        // Emit that integer with a decimal point two places from the right:
        // no dtoa engine, parser, allocation, or intermediate String.
        if value.is_sign_negative() {
            writer.write_char('-').ok()?;
        }
        let mut digits_scratch = [0u8; 40];
        let digits = crate::stdio::printf::decimal_digits_u128(scaled, &mut digits_scratch);
        if digits.len() > 2 {
            let point = digits.len() - 2;
            writer.write_bytes(&digits[..point]).ok()?;
            writer.write_char('.').ok()?;
            writer.write_bytes(&digits[point..]).ok()?;
        } else {
            writer.write_str("0.").ok()?;
            for _ in digits.len()..2 {
                writer.write_char('0').ok()?;
            }
            writer.write_bytes(digits).ok()?;
        }
    } else {
        core::write!(&mut writer, "{value:.2}").ok()?;
    }
    Some(writer.len)
}

/// Parsed pieces of one `%` directive.
#[derive(Clone, Copy)]
struct Spec {
    left_justify: bool,
    use_parens: bool,
    grouping: bool,
    currency: bool,
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
    let mut grouping = true;
    let mut currency = true;
    let mut fill = b' ';
    // Flags (any order, repeatable).
    loop {
        match format.get(*i) {
            Some(b'=') => {
                *i += 1;
                fill = *format.get(*i)?; // char after '=' is the fill char
                *i += 1;
            }
            Some(b'^') => {
                grouping = false;
                *i += 1;
            }
            Some(b'!') => {
                currency = false;
                *i += 1;
            }
            Some(b'+') => {
                // glibc rejects a repeated '+' (EINVAL). Duplicate '=', '^',
                // '!', '-' are allowed; only '+' and '(' may not repeat.
                if use_plus {
                    return None;
                }
                use_plus = true;
                *i += 1;
            }
            Some(b'(') => {
                if use_parens {
                    return None; // glibc rejects a repeated '('
                }
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
        grouping,
        currency,
        fill,
        field_width,
        left_prec,
        right_prec,
        conv,
    })
}

/// Monetary strings and layout rules from one retained locale category.
/// Byte-valued fields use 127 for the C locale's unspecified conventions.
#[derive(Clone, Copy, Debug)]
pub struct MonetaryLocale<'a> {
    pub currency_symbol: &'a [u8],
    pub int_curr_symbol: &'a [u8],
    pub decimal_point: &'a [u8],
    pub thousands_sep: &'a [u8],
    pub grouping: &'a [u8],
    pub positive_sign: &'a [u8],
    pub negative_sign: &'a [u8],
    pub frac_digits: u8,
    pub int_frac_digits: u8,
    pub p_cs_precedes: u8,
    pub n_cs_precedes: u8,
    pub p_sep_by_space: u8,
    pub n_sep_by_space: u8,
    pub p_sign_posn: u8,
    pub n_sign_posn: u8,
    pub int_p_cs_precedes: u8,
    pub int_n_cs_precedes: u8,
    pub int_p_sep_by_space: u8,
    pub int_n_sep_by_space: u8,
    pub int_p_sign_posn: u8,
    pub int_n_sign_posn: u8,
}

impl MonetaryLocale<'static> {
    pub const C: Self = Self {
        currency_symbol: b"",
        int_curr_symbol: b"",
        decimal_point: b".",
        thousands_sep: b"",
        grouping: b"",
        positive_sign: b"",
        negative_sign: b"",
        frac_digits: 127,
        int_frac_digits: 127,
        p_cs_precedes: 127,
        n_cs_precedes: 127,
        p_sep_by_space: 127,
        n_sep_by_space: 127,
        p_sign_posn: 127,
        n_sign_posn: 127,
        int_p_cs_precedes: 127,
        int_n_cs_precedes: 127,
        int_p_sep_by_space: 127,
        int_n_sep_by_space: 127,
        int_p_sign_posn: 127,
        int_n_sign_posn: 127,
    };
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum MonetaryError {
    InvalidFormat,
    BufferTooSmall,
    NoMemory,
}

/// Bound every intermediate by the caller's actual output budget. In
/// particular a huge field width must return E2BIG without allocating it.
struct MonetaryBuffer {
    bytes: Vec<u8>,
    limit: usize,
    format_error: Option<MonetaryError>,
}

impl MonetaryBuffer {
    fn new(limit: usize) -> Self {
        Self {
            bytes: Vec::new(),
            limit,
            format_error: None,
        }
    }

    fn reserve(&mut self, count: usize) -> Result<(), MonetaryError> {
        if count > self.limit.saturating_sub(self.bytes.len()) {
            return Err(MonetaryError::BufferTooSmall);
        }
        self.bytes
            .try_reserve(count)
            .map_err(|_| MonetaryError::NoMemory)
    }

    fn append(&mut self, bytes: &[u8]) -> Result<(), MonetaryError> {
        self.reserve(bytes.len())?;
        self.bytes.extend_from_slice(bytes);
        Ok(())
    }

    fn fill(&mut self, byte: u8, count: usize) -> Result<(), MonetaryError> {
        self.reserve(count)?;
        self.bytes.resize(self.bytes.len() + count, byte);
        Ok(())
    }
}

impl fmt::Write for MonetaryBuffer {
    fn write_str(&mut self, text: &str) -> fmt::Result {
        self.append(text.as_bytes()).map_err(|error| {
            self.format_error = Some(error);
            fmt::Error
        })
    }
}

/// Count grouping boundaries from the right. Zero (including the terminating
/// NUL omitted from a category string) repeats the preceding size; CHAR_MAX
/// stops grouping. Division handles enormous left precisions in bounded time.
fn monetary_group_count(mut digits: usize, grouping: &[u8]) -> usize {
    let mut count = 0;
    let mut previous = 0usize;
    for &group in grouping {
        match group {
            0 => break,
            127..=255 => return count,
            _ => {
                let width = usize::from(group);
                if digits <= width {
                    return count;
                }
                digits -= width;
                count += 1;
                previous = width;
            }
        }
    }
    if previous != 0 && digits != 0 {
        count += (digits - 1) / previous;
    }
    count
}

/// A locale field consists of short strings before and after its number.
/// Keeping the pieces borrowed avoids allocation for signs and symbols.
struct MonetaryAffixes<'a> {
    prefix: [&'a [u8]; 6],
    suffix: [&'a [u8]; 6],
    before: usize,
    after: usize,
}

impl<'a> MonetaryAffixes<'a> {
    fn new() -> Self {
        Self {
            prefix: [b""; 6],
            suffix: [b""; 6],
            before: 0,
            after: 0,
        }
    }

    fn prefix(&mut self, bytes: &'a [u8]) {
        self.prefix[self.before] = bytes;
        self.before += 1;
    }

    fn suffix(&mut self, bytes: &'a [u8]) {
        self.suffix[self.after] = bytes;
        self.after += 1;
    }

    fn prefix_len(&self) -> Result<usize, MonetaryError> {
        self.prefix.iter().try_fold(0usize, |sum, part| {
            sum.checked_add(part.len())
                .ok_or(MonetaryError::BufferTooSmall)
        })
    }
}

fn monetary_affixes<'a>(
    locale: MonetaryLocale<'a>,
    spec: &Spec,
    negative: bool,
) -> MonetaryAffixes<'a> {
    let international = spec.conv == b'i';
    let (precedes, spacing, mut position) = match (international, negative) {
        (false, false) => (
            locale.p_cs_precedes,
            locale.p_sep_by_space,
            locale.p_sign_posn,
        ),
        (false, true) => (
            locale.n_cs_precedes,
            locale.n_sep_by_space,
            locale.n_sign_posn,
        ),
        (true, false) => (
            locale.int_p_cs_precedes,
            locale.int_p_sep_by_space,
            locale.int_p_sign_posn,
        ),
        (true, true) => (
            locale.int_n_cs_precedes,
            locale.int_n_sep_by_space,
            locale.int_n_sign_posn,
        ),
    };
    if spec.use_parens {
        position = if negative { 0 } else { 5 };
    } else if position > 4 {
        position = 1;
    }
    let sign = if negative {
        if locale.negative_sign.is_empty() {
            b"-".as_slice()
        } else {
            locale.negative_sign
        }
    } else {
        locale.positive_sign
    };
    let (symbol, space) = if international {
        let split = locale.int_curr_symbol.len().min(3);
        (
            &locale.int_curr_symbol[..split],
            locale.int_curr_symbol.get(3..4).unwrap_or(b" "),
        )
    } else {
        (locale.currency_symbol, b" ".as_slice())
    };
    let symbol = if spec.currency { symbol } else { b"" };
    let mut parts = MonetaryAffixes::new();
    if negative && position == 0 {
        parts.prefix(b"(");
        parts.suffix(b")");
    }
    // The cases describe the documented symbol/sign positions. In GNU's
    // empty-sign and ! forms, spacing attached to a sign position remains
    // observable even when that sign or the currency symbol is suppressed.
    if precedes != 0 {
        if matches!(position, 1 | 3) {
            parts.prefix(sign);
            if spacing == 2 {
                parts.prefix(b" ");
            }
        }
        parts.prefix(symbol);
        if position == 4 {
            if spacing == 2 && !symbol.is_empty() {
                parts.prefix(space);
            }
            parts.prefix(sign);
            if spacing == 1 {
                parts.prefix(b" ");
            }
        } else if spacing == 1 && !symbol.is_empty() {
            parts.prefix(space);
        }
        if position == 2 {
            parts.suffix(sign);
        }
    } else {
        if position == 1 {
            parts.prefix(sign);
        }
        // The closing parenthesis must follow the complete currency suffix.
        parts.after = 0;
        if position == 3 {
            if spacing == 1 {
                parts.suffix(b" ");
            }
            parts.suffix(sign);
        }
        if !symbol.is_empty() {
            if (position == 3 && spacing == 2) || (position != 3 && spacing == 1) {
                parts.suffix(space);
            }
            parts.suffix(symbol);
        }
        if matches!(position, 2 | 4) {
            if spacing == 2 {
                parts.suffix(b" ");
            }
            parts.suffix(sign);
        }
        if negative && position == 0 {
            parts.suffix(b")");
        }
    }
    parts
}

fn monetary_number(
    value: f64,
    precision: usize,
    spec: &Spec,
    locale: MonetaryLocale<'_>,
    limit: usize,
) -> Result<Vec<u8>, MonetaryError> {
    let grouping = if spec.grouping && !locale.thousands_sep.is_empty() {
        locale.grouping
    } else {
        b""
    };
    let left_width = spec.left_prec.map_or(Ok(0), |digits| {
        digits
            .checked_add(monetary_group_count(digits, grouping))
            .ok_or(MonetaryError::BufferTooSmall)
    })?;
    if left_width > limit || (value.is_finite() && precision > limit) {
        return Err(MonetaryError::BufferTooSmall);
    }
    let mut raw = MonetaryBuffer::new(limit);
    // The numeric string retains a negative zero or NaN sign, whereas
    // placement of the locale sign/parentheses uses the strict < 0 test.
    let magnitude = if value < 0.0 { value.abs() } else { value };
    if magnitude.is_nan() {
        if magnitude.is_sign_negative() {
            raw.append(b"-")?;
        }
        raw.append(b"nan")?;
    } else if magnitude.is_infinite() {
        raw.append(b"inf")?;
    } else {
        // A binary64 expansion is exact within 1074 fractional digits. Rust's
        // formatter rejects a precision above u16::MAX; render a bounded exact
        // body, then append every additional requested zero without truncation.
        let exact_precision = precision.min(1100);
        if core::write!(&mut raw, "{magnitude:.exact_precision$}").is_err() {
            return Err(raw.format_error.unwrap_or(MonetaryError::BufferTooSmall));
        }
        raw.fill(b'0', precision - exact_precision)?;
    }
    let mut number = MonetaryBuffer::new(limit);
    if !value.is_finite() {
        let width = if precision != 0 {
            left_width
                .checked_add(precision)
                .and_then(|n| n.checked_add(1))
                .ok_or(MonetaryError::BufferTooSmall)?
        } else {
            left_width
        };
        number.fill(b' ', width.saturating_sub(raw.bytes.len()))?;
        number.append(&raw.bytes)?;
        return Ok(number.bytes);
    }
    let point = raw.bytes.iter().position(|&byte| byte == b'.');
    let integer = &raw.bytes[..point.unwrap_or(raw.bytes.len())];
    let digit_count = integer.len() - usize::from(integer.first() == Some(&b'-'));
    let groups = monetary_group_count(digit_count, grouping);
    number.fill(spec.fill, left_width.saturating_sub(integer.len() + groups))?;
    // There are at most 309 integer digits in a double. Checking the number
    // of boundaries in each suffix avoids an allocation for group indices.
    let mut remaining_groups = groups;
    for (index, &byte) in integer.iter().enumerate() {
        number.append(core::slice::from_ref(&byte))?;
        let suffix = integer.len() - index - 1;
        if remaining_groups > 0 && monetary_group_count(suffix, grouping) < remaining_groups {
            number.append(locale.thousands_sep)?;
            remaining_groups -= 1;
        }
    }
    if let Some(point) = point {
        number.append(locale.decimal_point)?;
        number.append(&raw.bytes[point + 1..])?;
    }
    Ok(number.bytes)
}

/// Format against one LC_MONETARY snapshot, with a bound excluding the NUL.
/// The ABI owns the output pointer and locale selection; this engine performs
/// only safe, fallible byte construction and does not consult global state.
pub fn strfmon_locale(
    format: &[u8],
    mut pull: impl FnMut() -> f64,
    locale: MonetaryLocale<'_>,
    max_output: usize,
) -> Result<Vec<u8>, MonetaryError> {
    let mut output = MonetaryBuffer::new(max_output);
    let mut at = 0;
    while at < format.len() {
        if format[at] != b'%' {
            output.append(&format[at..at + 1])?;
            at += 1;
            continue;
        }
        at += 1;
        if format.get(at) == Some(&b'%') {
            output.append(b"%")?;
            at += 1;
            continue;
        }
        let spec = parse_spec(format, &mut at).ok_or(MonetaryError::InvalidFormat)?;
        let fractional = match spec.conv {
            b'n' => locale.frac_digits,
            b'i' => locale.int_frac_digits,
            _ => return Err(MonetaryError::InvalidFormat),
        };
        let precision = spec.right_prec.unwrap_or(if fractional >= 127 {
            2
        } else {
            usize::from(fractional)
        });
        let remaining = max_output - output.bytes.len();
        if spec.field_width > remaining {
            return Err(MonetaryError::BufferTooSmall);
        }
        let value = pull();
        let negative = value < 0.0;
        let parts = monetary_affixes(locale, &spec, negative);
        let align = if spec.left_prec.is_some() {
            // GNU's # alignment reserves the locale's full sign/currency
            // prefix even under !. This matters when the currency switches
            // sides between positive and negative amounts (for example VND).
            let alignment_spec = Spec {
                currency: true,
                ..spec
            };
            monetary_affixes(locale, &alignment_spec, !negative)
                .prefix_len()?
                .saturating_sub(monetary_affixes(locale, &alignment_spec, negative).prefix_len()?)
        } else {
            0
        };
        let number = monetary_number(value, precision, &spec, locale, remaining)?;
        let mut field = MonetaryBuffer::new(remaining);
        field.fill(b' ', align)?;
        for part in &parts.prefix[..parts.before] {
            field.append(part)?;
        }
        field.append(&number)?;
        for part in &parts.suffix[..parts.after] {
            field.append(part)?;
        }
        let padding = spec.field_width.saturating_sub(field.bytes.len());
        if !spec.left_justify {
            output.fill(b' ', padding)?;
        }
        output.append(&field.bytes)?;
        if spec.left_justify {
            output.fill(b' ', padding)?;
        }
    }
    Ok(output.bytes)
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
    // glibc renders NaN as the lowercase "nan" (Rust's `format!` gives "NaN"),
    // with a leading '-' iff the NaN's sign bit is set — never parenthesised,
    // since the parens branch keys off `value < 0.0` which is false for NaN
    // (e.g. `%(n` of -nan yields "-nan", not "(nan)"). Field-width padding is
    // applied by the caller. (glibc's left/right-precision interaction with NaN
    // uses an internal numeric-width computation that is not mirrored here.)
    if value.is_nan() {
        let mut field = Vec::new();
        if value.is_sign_negative() {
            field.push(b'-');
        }
        field.extend_from_slice(b"nan");
        return field;
    }
    // glibc classifies negativity by `value < 0.0` (a STRICT compare), so a
    // negative zero is treated as positive for the parenthesis/sign-placement
    // decision — yet its `-` still appears, because glibc renders the value's
    // own sign in the digit string. Mirror that: format the magnitude for a
    // strict negative, but the value itself otherwise, so `-0.0` keeps its sign
    // (`format!` renders -0.0 as "-0.00"). With `value.is_sign_negative()` +
    // `value.abs()`, fl wrongly parenthesised `-0.0` and mis-placed its sign.
    let negative = value < 0.0;
    let mag = format_fixed(if negative { value.abs() } else { value }, prec);
    let (int_part, frac_part) = match mag.iter().position(|&b| b == b'.') {
        Some(dot) => (&mag[..dot], &mag[dot..]),
        None => (&mag[..], &b""[..]),
    };

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

    #[test]
    fn exact_default_emitter_matches_general_formatter() {
        let values = [
            0.0,
            -0.0,
            0.005,
            1_234_567.891,
            -1_234.567,
            f64::INFINITY,
            f64::NEG_INFINITY,
            f64::NAN,
            -f64::NAN,
            f64::MAX,
            f64::MIN,
        ];
        for value in values {
            let expected = strfmon_c(b"%n", || value).unwrap();
            let mut out = [0u8; 384];
            let len = strfmon_c_default_into(&mut out, value).unwrap();
            assert_eq!(&out[..len], expected, "value={value:?}");
        }
    }

    #[test]
    fn exact_default_emitter_reports_small_output() {
        let mut out = [0u8; 3];
        assert_eq!(strfmon_c_default_into(&mut out, 12.0), None);
    }

    const DOLLAR: MonetaryLocale<'static> = MonetaryLocale {
        currency_symbol: b"$",
        int_curr_symbol: b"USD ",
        decimal_point: b".",
        thousands_sep: b",",
        grouping: &[3, 3],
        positive_sign: b"",
        negative_sign: b"-",
        frac_digits: 2,
        int_frac_digits: 2,
        p_cs_precedes: 1,
        n_cs_precedes: 1,
        p_sep_by_space: 0,
        n_sep_by_space: 0,
        p_sign_posn: 1,
        n_sign_posn: 1,
        int_p_cs_precedes: 1,
        int_n_cs_precedes: 1,
        int_p_sep_by_space: 1,
        int_n_sep_by_space: 1,
        int_p_sign_posn: 1,
        int_n_sign_posn: 1,
    };

    fn monetary(format: &str, value: f64, locale: MonetaryLocale<'_>) -> String {
        String::from_utf8(strfmon_locale(format.as_bytes(), || value, locale, 512).unwrap())
            .unwrap()
    }

    #[test]
    fn named_monetary_grouping_precision_and_symbols() {
        assert_eq!(monetary("%n", 1234567.89, DOLLAR), "$1,234,567.89");
        assert_eq!(monetary("%i", -1234567.89, DOLLAR), "-USD 1,234,567.89");
        assert_eq!(monetary("%^n", 1234567.89, DOLLAR), "$1234567.89");
        assert_eq!(monetary("%!(n", -1234567.89, DOLLAR), "(1,234,567.89)");
        assert_eq!(monetary("%=*#6n", 12.34, DOLLAR), " $*****12.34");
        assert_eq!(monetary("%=*#6n", -12.34, DOLLAR), "-$*****12.34");
        assert_eq!(monetary("%16n", 12.34, DOLLAR), "          $12.34");
        assert_eq!(monetary("%-16n", 12.34, DOLLAR), "$12.34          ");
        assert_eq!(monetary("%.0n", 12.5, DOLLAR), "$12");
        assert_eq!(monetary("%.3n", 0.005, DOLLAR), "$0.005");
        let indian = MonetaryLocale {
            currency_symbol: "₹".as_bytes(),
            grouping: &[3, 2, 0],
            ..DOLLAR
        };
        assert_eq!(monetary("%n", 1234567.89, indian), "₹12,34,567.89");
        assert_eq!(monetary("%=*#6n", 12.34, indian), " ₹******12.34");
        let limited = MonetaryLocale {
            grouping: &[3, 127],
            ..DOLLAR
        };
        assert_eq!(monetary("%n", 1234567.89, limited), "$1234,567.89");
    }

    #[test]
    fn named_monetary_multibyte_grouping_and_alignment() {
        let euro = MonetaryLocale {
            currency_symbol: "€".as_bytes(),
            decimal_point: b",",
            thousands_sep: "\u{202f}".as_bytes(),
            p_cs_precedes: 0,
            n_cs_precedes: 0,
            p_sep_by_space: 1,
            n_sep_by_space: 1,
            ..DOLLAR
        };
        assert_eq!(
            monetary("%n", 1234567.89, euro),
            "1\u{202f}234\u{202f}567,89 €"
        );
        // # counts separator positions once even when a separator has 3 bytes.
        assert_eq!(monetary("%=*#6n", 1234.0, euro), " **1\u{202f}234,00 €");
        let asymmetric = MonetaryLocale {
            currency_symbol: "₫".as_bytes(),
            frac_digits: 0,
            p_cs_precedes: 0,
            n_cs_precedes: 1,
            ..DOLLAR
        };
        // Alignment accounts for the entire opposite-sign prefix, including
        // a currency symbol that moves across the number for negative values.
        assert_eq!(monetary("%=*#6n", 12.34, asymmetric), "    *****12₫");
        assert_eq!(monetary("%=*#6n", -12.34, asymmetric), "-₫*****12");
        assert_eq!(monetary("%=*!#6n", 12.34, asymmetric), "    *****12");
        assert_eq!(monetary("%=*!#6n", -12.34, asymmetric), "-*****12");
        assert_eq!(monetary("%=*(!#6n", 12.34, asymmetric), "    *****12");
        let reversed = MonetaryLocale {
            p_cs_precedes: 1,
            n_cs_precedes: 0,
            ..asymmetric
        };
        assert_eq!(monetary("%=*!#6n", 12.34, reversed), "*****12");
        assert_eq!(monetary("%=*!#6n", -12.34, reversed), "  -*****12");
    }

    #[test]
    fn named_monetary_all_sign_positions_and_spacing_match_gnu() {
        // Captured from independent GNU strfmon with private localedef locales.
        // Order is currency-before 0/1, spacing 0/1/2, sign position 0..4.
        let expected = [
            ("12.34$", "(12.34$)"),
            ("12.34$", "-12.34$"),
            ("12.34$", "12.34$-"),
            ("12.34$", "12.34-$"),
            ("12.34$", "12.34$-"),
            ("12.34 $", "(12.34 $)"),
            ("12.34 $", "-12.34 $"),
            ("12.34 $", "12.34 $-"),
            ("12.34 $", "12.34 -$"),
            ("12.34 $", "12.34 $-"),
            ("12.34$", "(12.34$)"),
            ("12.34$", "-12.34$"),
            ("12.34$ ", "12.34$ -"),
            ("12.34 $", "12.34- $"),
            ("12.34$ ", "12.34$ -"),
            ("$12.34", "($12.34)"),
            ("$12.34", "-$12.34"),
            ("$12.34", "$12.34-"),
            ("$12.34", "-$12.34"),
            ("$12.34", "$-12.34"),
            ("$ 12.34", "($ 12.34)"),
            ("$ 12.34", "-$ 12.34"),
            ("$ 12.34", "$ 12.34-"),
            ("$ 12.34", "-$ 12.34"),
            ("$ 12.34", "$- 12.34"),
            ("$12.34", "($12.34)"),
            (" $12.34", "- $12.34"),
            ("$12.34", "$12.34-"),
            (" $12.34", "- $12.34"),
            ("$ 12.34", "$ -12.34"),
        ];
        let mut index = 0;
        for precedes in 0..=1 {
            for spacing in 0..=2 {
                for position in 0..=4 {
                    let locale = MonetaryLocale {
                        p_cs_precedes: precedes,
                        n_cs_precedes: precedes,
                        p_sep_by_space: spacing,
                        n_sep_by_space: spacing,
                        p_sign_posn: position,
                        n_sign_posn: position,
                        ..DOLLAR
                    };
                    assert_eq!(monetary("%n", 12.34, locale), expected[index].0);
                    assert_eq!(monetary("%n", -12.34, locale), expected[index].1);
                    index += 1;
                }
            }
        }
    }

    #[test]
    fn named_monetary_nonfinite_and_signed_zero() {
        assert_eq!(monetary("%=*#6n", f64::INFINITY, DOLLAR), " $       inf");
        assert_eq!(
            monetary("%=*#6n", f64::NEG_INFINITY, DOLLAR),
            "-$       inf"
        );
        assert_eq!(monetary("%=*#6n", f64::NAN, DOLLAR), " $       nan");
        assert_eq!(monetary("%=*#6n", -0.0, DOLLAR), " $*****-0.00");
        assert_eq!(monetary("%(n", -0.0, DOLLAR), "$-0.00");
        assert_eq!(monetary("%.4n", f64::INFINITY, DOLLAR), "$  inf");
        assert_eq!(monetary("%.4n", f64::NEG_INFINITY, DOLLAR), "-$  inf");
        assert_eq!(monetary("%.4n", f64::NAN, DOLLAR), "$  nan");
        assert_eq!(monetary("%.4n", -f64::NAN, DOLLAR), "$ -nan");
    }

    #[test]
    fn named_monetary_international_separator_is_distinct_from_sign_spacing() {
        let locale = MonetaryLocale {
            int_curr_symbol: b"XTS_",
            positive_sign: b"CR",
            negative_sign: b"",
            int_p_sep_by_space: 2,
            ..DOLLAR
        };
        assert_eq!(monetary("%i", 12.5, locale), "CR XTS12.50");
        assert_eq!(monetary("%i", -12.5, locale), "-XTS_12.50");
        assert_eq!(
            monetary(
                "%i",
                12.5,
                MonetaryLocale {
                    int_p_cs_precedes: 0,
                    int_p_sign_posn: 2,
                    ..locale
                }
            ),
            "12.50XTS CR"
        );
        assert_eq!(
            monetary(
                "%i",
                12.5,
                MonetaryLocale {
                    int_p_sign_posn: 4,
                    int_p_sep_by_space: 1,
                    ..locale
                }
            ),
            "XTSCR 12.50"
        );
        assert_eq!(
            monetary(
                "%i",
                12.5,
                MonetaryLocale {
                    int_p_cs_precedes: 0,
                    int_p_sign_posn: 3,
                    int_p_sep_by_space: 1,
                    ..locale
                }
            ),
            "12.50 CRXTS"
        );
    }

    #[test]
    fn named_monetary_multiple_values_and_bounds() {
        let format = b"%n / %(i / 100%%";
        let mut values = [12.5, -23.75].into_iter();
        let expected = b"$12.50 / (USD 23.75) / 100%";
        assert_eq!(
            strfmon_locale(format, || values.next().unwrap(), DOLLAR, expected.len()),
            Ok(expected.to_vec())
        );
        for limit in 0..expected.len() {
            let mut values = [12.5, -23.75].into_iter();
            assert_eq!(
                strfmon_locale(format, || values.next().unwrap(), DOLLAR, limit),
                Err(MonetaryError::BufferTooSmall)
            );
        }
        for format in [
            b"%999999999999999999999n".as_slice(),
            b"%#999999999999999999999n",
            b"%.999999999999999999999n",
        ] {
            assert_eq!(
                strfmon_locale(format, || 1.0, DOLLAR, 32),
                Err(MonetaryError::BufferTooSmall)
            );
        }
        for format in [b"%".as_slice(), b"%z", b"%#n", b"%+(n", b"%++n"] {
            assert_eq!(
                strfmon_locale(
                    format,
                    || panic!("invalid format pulled a value"),
                    DOLLAR,
                    64
                ),
                Err(MonetaryError::InvalidFormat)
            );
        }
    }

    #[test]
    fn named_monetary_large_precision_preserves_requested_digits() {
        let output = strfmon_locale(b"%.100000n", || 1.25, DOLLAR, 100003).unwrap();
        assert_eq!(output.len(), 100003);
        assert_eq!(&output[..5], b"$1.25");
        assert!(output[5..].iter().all(|&byte| byte == b'0'));
        assert_eq!(
            strfmon_locale(b"%.100000n", || 1.25, DOLLAR, 100002),
            Err(MonetaryError::BufferTooSmall)
        );
        for (value, label) in [(f64::INFINITY, b"inf".as_slice()), (-f64::NAN, b"-nan")] {
            let output = strfmon_locale(b"%.100000n", || value, DOLLAR, 100002).unwrap();
            assert_eq!(output.len(), 100002);
            assert_eq!(output[0], b'$');
            let number = output.len() - label.len();
            assert!(output[1..number].iter().all(|&byte| byte == b' '));
            assert_eq!(&output[number..], label);
        }
    }
}
