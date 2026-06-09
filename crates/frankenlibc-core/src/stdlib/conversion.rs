//! Numeric conversion functions (atoi, atol, strtol, strtoul).

/// Result of a string-to-number conversion.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConversionStatus {
    Success,
    Overflow,
    Underflow,
    InvalidBase,
}

// ----------------------------------------------------------------------------
// Concrete Implementations
// ----------------------------------------------------------------------------

/// Whitespace test matching C's `isspace` in the C locale, which the
/// C standard cites for the leading whitespace skipped by `strtol`,
/// `strtod`, and friends. The set is `' '` plus `\t \n \v \f \r`
/// (0x09..=0x0D).
///
/// Rust's `u8::is_ascii_whitespace` deliberately omits the vertical
/// tab `\v` (0x0B), so using it here would make `strtol("\x0b42")`
/// stop before the digits while glibc parses `42`.
#[inline]
const fn is_c_space(b: u8) -> bool {
    b == b' ' || (b >= b'\t' && b <= b'\r')
}

/// True iff all 8 bytes of a little-endian-loaded word are ASCII digits
/// `'0'..='9'`. SWAR test (simdjson `is_made_of_eight_digits_fast`): a byte `c`
/// is a digit iff `(c & 0xF0) | ((c + 6) & 0xF0) >> 4 == 0x33` — `c & 0xF0` is
/// `0x30` for `0x30..=0x3F`, and `c + 6` only keeps the high nibble at `0x30`
/// (so `>>4 == 3`) for `0x30..=0x39`, excluding `':'..='?'`.
#[inline]
pub(crate) fn is_eight_digits(word: u64) -> bool {
    ((word & 0xF0F0_F0F0_F0F0_F0F0)
        | ((word.wrapping_add(0x0606_0606_0606_0606) & 0xF0F0_F0F0_F0F0_F0F0) >> 4))
        == 0x3333_3333_3333_3333
}

/// Parse 8 ASCII decimal digits packed in a little-endian word into their
/// integer value (the classic Lemire/fast_float SWAR `parse_eight_digits`).
/// Caller must have validated the 8 bytes via [`is_eight_digits`]. `word`'s low
/// byte is the most-significant digit (i.e. the leftmost source character), so
/// the result is `d0·10^7 + d1·10^6 + … + d7`. Verified exhaustively against the
/// scalar reference by `swar_parse_eight_matches_scalar`.
#[inline]
pub(crate) fn parse_eight_digits(word: u64) -> u32 {
    const MASK: u64 = 0x0000_00FF_0000_00FF;
    const MUL1: u64 = 0x000F_4240_0000_0064; // 100 + (1_000_000 << 32)
    const MUL2: u64 = 0x0000_2710_0000_0001; // 1   + (10_000   << 32)
    let val = word.wrapping_sub(0x3030_3030_3030_3030);
    // Fold each pair of adjacent digit-bytes into a 2-digit value at the even
    // byte lanes: lane k becomes 10·d_k + d_{k+1} (max 99, no carry).
    let val = val.wrapping_mul(10).wrapping_add(val >> 8);
    let lo = (val & MASK).wrapping_mul(MUL1);
    let hi = (val >> 16 & MASK).wrapping_mul(MUL2);
    (lo.wrapping_add(hi) >> 32) as u32
}

/// Parse 8 ASCII hex digits packed in a little-endian word, returning their
/// 32-bit value, or `None` if any byte is not `[0-9A-Fa-f]`. The low byte is the
/// most-significant digit (leftmost source char). Letters are lowercased, each
/// byte decoded to a nibble, and validity checked two ways: no nibble may be
/// `>= 16` (rejects `g..z`), and re-encoding the nibble must reproduce the
/// lowercased input (rejects the `0x3a..0x60` gap, e.g. `:` decodes to nibble 10
/// but is not hex). Verified exhaustively by `swar_parse_eight_hex_matches_scalar`.
#[inline]
pub(crate) fn parse_eight_hex(word: u64) -> Option<u32> {
    // Reject any byte below '0' (0x30) up front: the `| 0x20` lowercasing below
    // folds control bytes 0x10..=0x19 onto '0'..='9' (e.g. 0x17|0x20 == '7'),
    // after which the re-encode check — which compares against the *already
    // folded* `lw`, not the original byte — would wrongly accept them and the
    // SWAR fast path would over-consume past a non-hex byte that the scalar loop
    // correctly stops at. Every valid hex char is >= 0x30, so this is exact.
    // (Classic "bytes-less-than-n" SWAR; valid for n <= 128.)
    if word.wrapping_sub(0x3030_3030_3030_3030) & !word & 0x8080_8080_8080_8080 != 0 {
        return None;
    }
    let lw = word | 0x2020_2020_2020_2020; // lowercase letters; digits unchanged
    let is_letter = (lw >> 6) & 0x0101_0101_0101_0101; // bit6 set on 'a'..='z'
    let nibbles = (lw & 0x0F0F_0F0F_0F0F_0F0F).wrapping_add(is_letter.wrapping_mul(9));
    if nibbles & 0xF0F0_F0F0_F0F0_F0F0 != 0 {
        return None; // some nibble >= 16
    }
    let ge10 = (nibbles.wrapping_add(0x0606_0606_0606_0606) >> 4) & 0x0101_0101_0101_0101;
    let reenc = nibbles
        .wrapping_add(0x3030_3030_3030_3030)
        .wrapping_add(ge10.wrapping_mul(0x27));
    if reenc != lw {
        return None; // a non-hex byte decoded into a valid nibble
    }
    // Combine: fold adjacent nibble-lanes into byte values, then pack the four
    // even lanes (the two-hex-digit bytes) big-endian.
    let paired = (nibbles << 4) | (nibbles >> 8);
    let m = paired & 0x00FF_00FF_00FF_00FF;
    let b0 = (m & 0xFF) as u32;
    let b1 = (m >> 16 & 0xFF) as u32;
    let b2 = (m >> 32 & 0xFF) as u32;
    let b3 = (m >> 48 & 0xFF) as u32;
    Some((b0 << 24) | (b1 << 16) | (b2 << 8) | b3)
}

pub fn atoi(s: &[u8]) -> i32 {
    let (val, _, _) = strtol_impl(s, 10);
    // POSIX SUSv4: atoi(str) ≡ (int) strtol(str, NULL, 10). The cast
    // on 2's-complement targets (all supported archs) is a
    // truncation, not a saturating clamp. The earlier clamp-to-
    // INT_MAX logic diverged from glibc's observable behavior on
    // overflow and tripped fuzz_stdlib's atoi-vs-strtol parity
    // assertion (bd-ie8zc). C standard leaves overflow UB; POSIX
    // pins it down to the (int)long_val cast result.
    val as i32
}

pub fn atol(s: &[u8]) -> i64 {
    let (val, _, _) = strtol_impl(s, 10);
    val
}

pub fn atoll(s: &[u8]) -> i64 {
    atol(s)
}

/// Helper for strtol: returns (value, consumed_bytes, status)
pub fn strtol_impl(s: &[u8], base: i32) -> (i64, usize, ConversionStatus) {
    let mut i = 0;
    let len = s.len();

    // glibc validates the base before inspecting the string: an invalid base
    // (not 0 and outside 2..=36) yields EINVAL with nothing consumed and the
    // caller's endptr left untouched — even for empty / sign-only input. This
    // MUST precede the whitespace/sign scan so those early-success returns do
    // not mask the invalid base.
    if base != 0 && !(2..=36).contains(&base) {
        return (0, 0, ConversionStatus::InvalidBase);
    }

    while i < len && is_c_space(s[i]) {
        i += 1;
    }
    if i == len {
        return (0, 0, ConversionStatus::Success);
    }

    let mut negative = false;
    if s[i] == b'-' {
        negative = true;
        i += 1;
    } else if s[i] == b'+' {
        i += 1;
    }

    if i == len {
        return (0, 0, ConversionStatus::Success);
    }

    let mut effective_base = base as u64;

    // Check for "0x"/"0X" and "0b"/"0B" prefixes
    let has_0x_prefix = i + 1 < len && s[i] == b'0' && (s[i + 1] == b'x' || s[i + 1] == b'X');
    let has_0b_prefix = i + 1 < len && s[i] == b'0' && (s[i + 1] == b'b' || s[i + 1] == b'B');
    let is_binary_digit = |c: u8| c == b'0' || c == b'1';

    if base == 0 {
        if has_0x_prefix && i + 2 < len && s[i + 2].is_ascii_hexdigit() {
            effective_base = 16;
            i += 2;
        } else if has_0b_prefix && i + 2 < len && is_binary_digit(s[i + 2]) {
            effective_base = 2;
            i += 2;
        } else if i < len && s[i] == b'0' {
            effective_base = 8;
        } else {
            effective_base = 10;
        }
    } else if (base == 16 && has_0x_prefix && i + 2 < len && s[i + 2].is_ascii_hexdigit())
        || (base == 2 && has_0b_prefix && i + 2 < len && is_binary_digit(s[i + 2]))
    {
        i += 2;
    }

    if !(2..=36).contains(&effective_base) {
        return (0, 0, ConversionStatus::InvalidBase);
    }

    let abs_max = if negative {
        9_223_372_036_854_775_808u64
    } else {
        9_223_372_036_854_775_807u64
    };
    let mut acc: u64 = 0;
    let mut any_digits = false;
    let mut overflow = false;

    // SWAR fast path (base 10): consume 8 decimal digits per step. `acc·10^8 +
    // parse8` is exactly what eight scalar iterations compute; on overflow we
    // flag and keep consuming (digit-exact end position), matching the scalar
    // tail. Only the *detection point* of an overflow can differ, which is
    // invisible: glibc returns LONG_MAX/MIN past all consumed digits either way.
    if effective_base == 10 {
        while i + 8 <= len {
            let word = u64::from_le_bytes(s[i..i + 8].try_into().unwrap());
            if !is_eight_digits(word) {
                break;
            }
            any_digits = true;
            if !overflow {
                let parsed = parse_eight_digits(word) as u64;
                match acc
                    .checked_mul(100_000_000)
                    .and_then(|a| a.checked_add(parsed))
                {
                    Some(v) if v <= abs_max => acc = v,
                    _ => overflow = true,
                }
            }
            i += 8;
        }
    } else if effective_base == 16 {
        // SWAR hex: consume 8 hex digits (32 bits) per step. `acc·16^8 + parse8`
        // equals eight scalar iterations; overflow flags and keeps consuming.
        while i + 8 <= len {
            let word = u64::from_le_bytes(s[i..i + 8].try_into().unwrap());
            let Some(parsed) = parse_eight_hex(word) else {
                break;
            };
            any_digits = true;
            if !overflow {
                match acc
                    .checked_mul(0x1_0000_0000)
                    .and_then(|a| a.checked_add(parsed as u64))
                {
                    Some(v) if v <= abs_max => acc = v,
                    _ => overflow = true,
                }
            }
            i += 8;
        }
    }

    while i < len {
        let c = s[i];
        let digit = match c {
            b'0'..=b'9' => c - b'0',
            b'a'..=b'z' => c - b'a' + 10,
            b'A'..=b'Z' => c - b'A' + 10,
            _ => break,
        };
        if (digit as u64) >= effective_base {
            break;
        }

        any_digits = true;

        if overflow {
            i += 1;
            continue;
        }

        // Exact overflow detection without a per-call `abs_max / base` division
        // (the old cutoff/cutlim form): `acc*base + digit > abs_max` iff the
        // checked arithmetic wraps u64 OR the result exceeds `abs_max`.
        match acc
            .checked_mul(effective_base)
            .and_then(|a| a.checked_add(digit as u64))
        {
            Some(v) if v <= abs_max => acc = v,
            _ => overflow = true,
        }
        i += 1;
    }

    if !any_digits {
        return (0, 0, ConversionStatus::Success);
    }

    if overflow {
        if negative {
            return (i64::MIN, i, ConversionStatus::Underflow);
        } else {
            return (i64::MAX, i, ConversionStatus::Overflow);
        }
    }

    let val = if negative {
        (acc as i64).wrapping_neg()
    } else {
        acc as i64
    };

    (val, i, ConversionStatus::Success)
}

pub fn strtol(s: &[u8], base: i32) -> (i64, usize) {
    let (val, len, _) = strtol_impl(s, base);
    (val, len)
}

/// Helper for strtoll
pub fn strtoll_impl(s: &[u8], base: i32) -> (i64, usize, ConversionStatus) {
    strtol_impl(s, base)
}

pub fn strtoll(s: &[u8], base: i32) -> (i64, usize) {
    strtol(s, base)
}

/// Helper for strtoimax
pub fn strtoimax_impl(s: &[u8], base: i32) -> (i64, usize, ConversionStatus) {
    strtol_impl(s, base)
}

pub fn strtoimax(s: &[u8], base: i32) -> (i64, usize) {
    strtol(s, base)
}

/// Helper for strtoul
pub fn strtoul_impl(s: &[u8], base: i32) -> (u64, usize, ConversionStatus) {
    let mut i = 0;
    let len = s.len();

    // glibc validates the base before inspecting the string: an invalid base
    // (not 0 and outside 2..=36) yields EINVAL with nothing consumed and the
    // caller's endptr left untouched — even for empty / sign-only input. This
    // MUST precede the whitespace/sign scan so those early-success returns do
    // not mask the invalid base.
    if base != 0 && !(2..=36).contains(&base) {
        return (0, 0, ConversionStatus::InvalidBase);
    }

    while i < len && is_c_space(s[i]) {
        i += 1;
    }
    if i == len {
        return (0, 0, ConversionStatus::Success);
    }

    let mut negative = false;
    if s[i] == b'-' {
        negative = true;
        i += 1;
    } else if s[i] == b'+' {
        i += 1;
    }

    if i == len {
        return (0, 0, ConversionStatus::Success);
    }

    let mut effective_base = base as u64;

    // Check for "0x"/"0X" and "0b"/"0B" prefixes
    let has_0x_prefix = i + 1 < len && s[i] == b'0' && (s[i + 1] == b'x' || s[i + 1] == b'X');
    let has_0b_prefix = i + 1 < len && s[i] == b'0' && (s[i + 1] == b'b' || s[i + 1] == b'B');
    let is_binary_digit = |c: u8| c == b'0' || c == b'1';

    if base == 0 {
        if has_0x_prefix && i + 2 < len && s[i + 2].is_ascii_hexdigit() {
            effective_base = 16;
            i += 2;
        } else if has_0b_prefix && i + 2 < len && is_binary_digit(s[i + 2]) {
            effective_base = 2;
            i += 2;
        } else if i < len && s[i] == b'0' {
            effective_base = 8;
        } else {
            effective_base = 10;
        }
    } else if (base == 16 && has_0x_prefix && i + 2 < len && s[i + 2].is_ascii_hexdigit())
        || (base == 2 && has_0b_prefix && i + 2 < len && is_binary_digit(s[i + 2]))
    {
        i += 2;
    }

    if !(2..=36).contains(&effective_base) {
        return (0, 0, ConversionStatus::InvalidBase);
    }

    let limit = u64::MAX;

    let mut acc: u64 = 0;
    let mut any_digits = false;
    let mut overflow = false;

    // SWAR fast path (base 10): 8 decimal digits per step via the same
    // exhaustively-verified helpers as strtol_impl. `acc·10^8 + parse8` equals
    // eight scalar iterations; overflow flags and keeps consuming (digit-exact
    // end), matching the scalar tail.
    if effective_base == 10 {
        while i + 8 <= len {
            let word = u64::from_le_bytes(s[i..i + 8].try_into().unwrap());
            if !is_eight_digits(word) {
                break;
            }
            any_digits = true;
            if !overflow {
                let parsed = parse_eight_digits(word) as u64;
                match acc
                    .checked_mul(100_000_000)
                    .and_then(|a| a.checked_add(parsed))
                {
                    Some(v) if v <= limit => acc = v,
                    _ => overflow = true,
                }
            }
            i += 8;
        }
    } else if effective_base == 16 {
        // SWAR hex: 8 hex digits (32 bits) per step via the same verified helper
        // as strtol_impl (acc·16^8 + parse8, checked overflow).
        while i + 8 <= len {
            let word = u64::from_le_bytes(s[i..i + 8].try_into().unwrap());
            let Some(parsed) = parse_eight_hex(word) else {
                break;
            };
            any_digits = true;
            if !overflow {
                match acc
                    .checked_mul(0x1_0000_0000)
                    .and_then(|a| a.checked_add(parsed as u64))
                {
                    Some(v) if v <= limit => acc = v,
                    _ => overflow = true,
                }
            }
            i += 8;
        }
    }

    while i < len {
        let c = s[i];
        let digit = match c {
            b'0'..=b'9' => c - b'0',
            b'a'..=b'z' => c - b'a' + 10,
            b'A'..=b'Z' => c - b'A' + 10,
            _ => break,
        };
        if (digit as u64) >= effective_base {
            break;
        }

        any_digits = true;
        if overflow {
            i += 1;
            continue;
        }

        // Exact overflow detection via checked arithmetic — no per-call
        // `limit / base` division (the old cutoff/cutlim form).
        match acc
            .checked_mul(effective_base)
            .and_then(|a| a.checked_add(digit as u64))
        {
            Some(v) if v <= limit => acc = v,
            _ => overflow = true,
        }
        i += 1;
    }

    if !any_digits {
        return (0, 0, ConversionStatus::Success);
    }

    if overflow {
        return (u64::MAX, i, ConversionStatus::Overflow);
    }

    let val = if negative { acc.wrapping_neg() } else { acc };

    (val, i, ConversionStatus::Success)
}

pub fn strtoul(s: &[u8], base: i32) -> (u64, usize) {
    let (val, len, _) = strtoul_impl(s, base);
    (val, len)
}

/// Helper for strtoull
pub fn strtoull_impl(s: &[u8], base: i32) -> (u64, usize, ConversionStatus) {
    strtoul_impl(s, base)
}

pub fn strtoull(s: &[u8], base: i32) -> (u64, usize) {
    strtoul(s, base)
}

/// NetBSD `strtoi(3)` rstatus codes. Mirrors `<inttypes.h>` returns
/// for bounded integer parsing.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BoundedStatus {
    /// Parsed value is in `[lo, hi]`.
    Success,
    /// Base is outside the valid range (0 or 2..=36).
    InvalidBase,
    /// No digits could be consumed.
    NoDigits,
    /// Value was outside `[lo, hi]` (or the underlying parser
    /// overflowed); the caller-visible value has been clamped.
    OutOfRange,
}

/// NetBSD `strtoi`-style bounded signed parse. Wraps
/// [`strtoimax_impl`], then validates the result against
/// `[lo, hi]` inclusive. On out-of-range or overflow the returned
/// value is clamped to the violated bound.
///
/// Returns `(value, consumed_bytes, status)`. When `status ==
/// NoDigits` the consumed count is 0 (matches NetBSD: `*endptr ==
/// nptr`). When `status == InvalidBase` no parsing was attempted.
pub fn strtoi_impl(s: &[u8], base: i32, lo: i64, hi: i64) -> (i64, usize, BoundedStatus) {
    let (val, n, status) = strtoimax_impl(s, base);
    match status {
        ConversionStatus::InvalidBase => (0, 0, BoundedStatus::InvalidBase),
        ConversionStatus::Overflow => {
            // Underlying parser saturated to i64::MAX; clamp again
            // to the caller's hi (which is at most i64::MAX).
            (hi, n, BoundedStatus::OutOfRange)
        }
        ConversionStatus::Underflow => (lo, n, BoundedStatus::OutOfRange),
        ConversionStatus::Success => {
            if n == 0 {
                (0, 0, BoundedStatus::NoDigits)
            } else if val < lo {
                (lo, n, BoundedStatus::OutOfRange)
            } else if val > hi {
                (hi, n, BoundedStatus::OutOfRange)
            } else {
                (val, n, BoundedStatus::Success)
            }
        }
    }
}

/// NetBSD `strtou`-style bounded unsigned parse. Wraps
/// [`strtoumax_impl`], then validates the result against
/// `[lo, hi]` inclusive (both u64). Out-of-range or overflow
/// clamps the returned value to the violated bound. Negative
/// inputs (a leading `-`) are passed through to
/// [`strtoumax_impl`], whose wrapping_neg behavior matches glibc;
/// the resulting wrapped value will simply fail the `> hi` check
/// for any reasonable `hi`.
pub fn strtou_impl(s: &[u8], base: i32, lo: u64, hi: u64) -> (u64, usize, BoundedStatus) {
    let (val, n, status) = strtoumax_impl(s, base);
    match status {
        ConversionStatus::InvalidBase => (0, 0, BoundedStatus::InvalidBase),
        ConversionStatus::Overflow => (hi, n, BoundedStatus::OutOfRange),
        ConversionStatus::Underflow => (lo, n, BoundedStatus::OutOfRange),
        ConversionStatus::Success => {
            if n == 0 {
                (0, 0, BoundedStatus::NoDigits)
            } else if val < lo {
                (lo, n, BoundedStatus::OutOfRange)
            } else if val > hi {
                (hi, n, BoundedStatus::OutOfRange)
            } else {
                (val, n, BoundedStatus::Success)
            }
        }
    }
}

/// Helper for strtoumax
pub fn strtoumax_impl(s: &[u8], base: i32) -> (u64, usize, ConversionStatus) {
    strtoul_impl(s, base)
}

pub fn strtoumax(s: &[u8], base: i32) -> (u64, usize) {
    strtoul(s, base)
}

// ---------------------------------------------------------------------------
// Wide-character (`wchar_t` / `u32`) integer conversion
// ---------------------------------------------------------------------------

/// True if `wc` is C-locale whitespace, the leading-space set
/// `wcstol`/`wcstoul`/`wcstod` skip. glibc's `iswspace` in the C locale (which
/// these conversions run under) recognizes ONLY the ASCII set
/// (space + `\t\n\v\f\r`); non-ASCII Unicode spaces (U+00A0, U+2003, U+3000, …)
/// are NOT skipped, so `char::is_whitespace()` (Unicode-aware) would over-skip
/// and diverge from glibc.
#[inline]
pub fn wide_is_space(wc: u32) -> bool {
    matches!(wc, 0x20 | 0x09..=0x0D)
}

/// Numeric value of an ASCII digit (`'0'-'9'`) or an ASCII letter
/// (`'a'-'z'` / `'A'-'Z'`, returning `10..=35`). Returns `None` for any
/// other code point — matching the lookup table that backs strtol's
/// digit handling.
#[inline]
pub fn wide_digit_value(wc: u32) -> Option<u32> {
    match wc {
        wc if (b'0' as u32..=b'9' as u32).contains(&wc) => Some(wc - b'0' as u32),
        wc if (b'a' as u32..=b'z' as u32).contains(&wc) => Some(wc - b'a' as u32 + 10),
        wc if (b'A' as u32..=b'Z' as u32).contains(&wc) => Some(wc - b'A' as u32 + 10),
        _ => None,
    }
}

#[inline]
fn wide_is_ascii_hexdigit(wc: u32) -> bool {
    matches!(wide_digit_value(wc), Some(0..=15))
}

/// Wide-char `wcstol_impl` — structurally identical to [`strtol_impl`]
/// but operating on `&[u32]` (one `wchar_t` per element) instead of
/// `&[u8]`.
///
/// Returns `(value, consumed_wchars, status)`. Semantics:
///   - Leading whitespace skipped via [`wide_is_space`] (ASCII / C-locale).
///   - Optional `+` / `-` sign consumed.
///   - `base == 0` auto-detects: `0x`/`0X` prefix → 16, leading `0` → 8,
///     otherwise 10.
///   - `base == 16` consumes a `0x`/`0X` prefix when followed by a
///     hex digit.
///   - Accumulator overflow returns `i64::MAX` / `i64::MIN` (with
///     status `Overflow` or `Underflow` respectively); the parser
///     continues consuming valid digits in the overflow tail to
///     advance the cursor past the full numeric run.
///   - Returns `(0, 0, Success)` for empty / whitespace-only / sign-
///     only inputs.
///   - Returns `(0, 0, InvalidBase)` for `base` outside `0` ∪ `2..=36`.
pub fn wcstol_impl(s: &[u32], base: i32) -> (i64, usize, ConversionStatus) {
    let mut i = 0usize;
    let len = s.len();

    // glibc validates the base before inspecting the string: an invalid base
    // (not 0 and outside 2..=36) yields EINVAL with nothing consumed and the
    // caller's endptr left untouched — even for empty / sign-only input. This
    // MUST precede the whitespace/sign scan so those early-success returns do
    // not mask the invalid base. (Wide analog of strtol_impl's check.)
    if base != 0 && !(2..=36).contains(&base) {
        return (0, 0, ConversionStatus::InvalidBase);
    }

    while i < len && wide_is_space(s[i]) {
        i += 1;
    }
    if i == len {
        return (0, 0, ConversionStatus::Success);
    }

    let mut negative = false;
    if s[i] == b'-' as u32 {
        negative = true;
        i += 1;
    } else if s[i] == b'+' as u32 {
        i += 1;
    }

    if i == len {
        return (0, 0, ConversionStatus::Success);
    }

    let mut effective_base = base as u64;
    let has_0x_prefix =
        i + 1 < len && s[i] == b'0' as u32 && (s[i + 1] == b'x' as u32 || s[i + 1] == b'X' as u32);
    let has_0b_prefix =
        i + 1 < len && s[i] == b'0' as u32 && (s[i + 1] == b'b' as u32 || s[i + 1] == b'B' as u32);
    let wide_is_binary_digit = |c: u32| c == b'0' as u32 || c == b'1' as u32;

    if base == 0 {
        if has_0x_prefix && i + 2 < len && wide_is_ascii_hexdigit(s[i + 2]) {
            effective_base = 16;
            i += 2;
        } else if has_0b_prefix && i + 2 < len && wide_is_binary_digit(s[i + 2]) {
            effective_base = 2;
            i += 2;
        } else if s[i] == b'0' as u32 {
            effective_base = 8;
        } else {
            effective_base = 10;
        }
    } else if (base == 16 && has_0x_prefix && i + 2 < len && wide_is_ascii_hexdigit(s[i + 2]))
        || (base == 2 && has_0b_prefix && i + 2 < len && wide_is_binary_digit(s[i + 2]))
    {
        i += 2;
    }

    if !(2..=36).contains(&effective_base) {
        return (0, 0, ConversionStatus::InvalidBase);
    }

    let abs_max = if negative {
        9_223_372_036_854_775_808u64
    } else {
        9_223_372_036_854_775_807u64
    };
    let limit = abs_max;

    let mut acc = 0u64;
    let mut any_digits = false;
    let mut overflow = false;

    while i < len {
        let Some(digit) = wide_digit_value(s[i]) else {
            break;
        };
        if (digit as u64) >= effective_base {
            break;
        }

        any_digits = true;
        if overflow {
            i += 1;
            continue;
        }

        // Exact overflow detection via checked arithmetic — no per-call
        // `limit / base` division (the old cutoff/cutlim form).
        match acc
            .checked_mul(effective_base)
            .and_then(|a| a.checked_add(digit as u64))
        {
            Some(v) if v <= limit => acc = v,
            _ => overflow = true,
        }
        i += 1;
    }

    if !any_digits {
        return (0, 0, ConversionStatus::Success);
    }

    if overflow {
        if negative {
            return (i64::MIN, i, ConversionStatus::Underflow);
        }
        return (i64::MAX, i, ConversionStatus::Overflow);
    }

    let value = if negative {
        (acc as i64).wrapping_neg()
    } else {
        acc as i64
    };
    (value, i, ConversionStatus::Success)
}

/// Wide-char `wcstoul_impl` — unsigned counterpart to
/// [`wcstol_impl`]. Negative inputs are accepted and the sign is
/// applied via two's-complement wrap (matching glibc's `wcstoul`).
pub fn wcstoul_impl(s: &[u32], base: i32) -> (u64, usize, ConversionStatus) {
    let mut i = 0usize;
    let len = s.len();

    // glibc validates the base before inspecting the string: an invalid base
    // (not 0 and outside 2..=36) yields EINVAL with nothing consumed and the
    // caller's endptr left untouched — even for empty / sign-only input. This
    // MUST precede the whitespace/sign scan so those early-success returns do
    // not mask the invalid base. (Wide analog of strtol_impl's check.)
    if base != 0 && !(2..=36).contains(&base) {
        return (0, 0, ConversionStatus::InvalidBase);
    }

    while i < len && wide_is_space(s[i]) {
        i += 1;
    }
    if i == len {
        return (0, 0, ConversionStatus::Success);
    }

    let mut negative = false;
    if s[i] == b'-' as u32 {
        negative = true;
        i += 1;
    } else if s[i] == b'+' as u32 {
        i += 1;
    }

    if i == len {
        return (0, 0, ConversionStatus::Success);
    }

    let mut effective_base = base as u64;
    let has_0x_prefix =
        i + 1 < len && s[i] == b'0' as u32 && (s[i + 1] == b'x' as u32 || s[i + 1] == b'X' as u32);
    let has_0b_prefix =
        i + 1 < len && s[i] == b'0' as u32 && (s[i + 1] == b'b' as u32 || s[i + 1] == b'B' as u32);
    let wide_is_binary_digit = |c: u32| c == b'0' as u32 || c == b'1' as u32;

    if base == 0 {
        if has_0x_prefix && i + 2 < len && wide_is_ascii_hexdigit(s[i + 2]) {
            effective_base = 16;
            i += 2;
        } else if has_0b_prefix && i + 2 < len && wide_is_binary_digit(s[i + 2]) {
            effective_base = 2;
            i += 2;
        } else if s[i] == b'0' as u32 {
            effective_base = 8;
        } else {
            effective_base = 10;
        }
    } else if (base == 16 && has_0x_prefix && i + 2 < len && wide_is_ascii_hexdigit(s[i + 2]))
        || (base == 2 && has_0b_prefix && i + 2 < len && wide_is_binary_digit(s[i + 2]))
    {
        i += 2;
    }

    if !(2..=36).contains(&effective_base) {
        return (0, 0, ConversionStatus::InvalidBase);
    }

    let limit = u64::MAX;

    let mut acc = 0u64;
    let mut any_digits = false;
    let mut overflow = false;

    while i < len {
        let Some(digit) = wide_digit_value(s[i]) else {
            break;
        };
        if (digit as u64) >= effective_base {
            break;
        }

        any_digits = true;
        if overflow {
            i += 1;
            continue;
        }

        // Exact overflow detection via checked arithmetic — no per-call
        // `limit / base` division (the old cutoff/cutlim form).
        match acc
            .checked_mul(effective_base)
            .and_then(|a| a.checked_add(digit as u64))
        {
            Some(v) if v <= limit => acc = v,
            _ => overflow = true,
        }
        i += 1;
    }

    if !any_digits {
        return (0, 0, ConversionStatus::Success);
    }
    if overflow {
        return (u64::MAX, i, ConversionStatus::Overflow);
    }

    let value = if negative { acc.wrapping_neg() } else { acc };
    (value, i, ConversionStatus::Success)
}

// ---------------------------------------------------------------------------
// Floating-point conversion
// ---------------------------------------------------------------------------

/// Convert a single ASCII hex digit to its numeric value (0-15).
/// Caller must ensure `c.is_ascii_hexdigit()`.
fn hex_digit_val(c: u8) -> u8 {
    match c {
        b'0'..=b'9' => c - b'0',
        b'a'..=b'f' => c - b'a' + 10,
        b'A'..=b'F' => c - b'A' + 10,
        _ => 0,
    }
}

/// Parses a floating-point number from a NUL-terminated byte slice.
///
/// Returns `(value, bytes_consumed)`. On failure, returns `(0.0, 0)`.
/// Parse a double, returning `(value, bytes_consumed, exact)`. The third field
/// is `true` when the result is EXACTLY representable (no rounding occurred) —
/// the ABI combines it with "is subnormal" to avoid raising the spurious
/// `ERANGE` glibc does not raise for exact subnormals, and `strtof` uses it to
/// decide f32 exactness. Currently only the hex path computes it precisely; the
/// decimal path conservatively returns `false` (decimal subnormals are inexact
/// in practice, and strtof's decimal branch parses f32 directly). (bd-2g7oyh.187)
pub fn strtod_impl(s: &[u8]) -> (f64, usize, bool) {
    let len = crate::string::strlen(s);
    let slice = &s[..len];

    let mut i = 0;
    while i < slice.len() && is_c_space(slice[i]) {
        i += 1;
    }
    if i >= slice.len() {
        return (0.0, 0, false);
    }

    // Try to parse using core::str::parse on the valid ASCII portion.
    // Collect chars that could be part of a float.
    let start = i;
    if i < slice.len() && (slice[i] == b'+' || slice[i] == b'-') {
        i += 1;
    }

    // Check for "inf", "infinity", "nan" (case-insensitive)
    if i + 3 <= slice.len() {
        let word = &slice[i..i + 3];
        let special_sign: f64 = if start < slice.len() && slice[start] == b'-' {
            -1.0
        } else {
            1.0
        };
        if word.eq_ignore_ascii_case(b"inf") {
            i += 3;
            if i + 5 <= slice.len() && slice[i..i + 5].eq_ignore_ascii_case(b"inity") {
                i += 5;
            }
            return (special_sign * f64::INFINITY, i, false);
        }
        if word.eq_ignore_ascii_case(b"nan") {
            i += 3;
            // glibc accepts an optional `(n-char-sequence)` payload after NaN
            // (alphanumerics + underscores, closing ')' required): it is parsed
            // as strtoull(seq, base 0) and OR'd into the significand.
            let mut payload = 0u64;
            if i < slice.len() && slice[i] == b'(' {
                let paren_start = i;
                let seq_start = i + 1;
                i += 1;
                while i < slice.len() && (slice[i].is_ascii_alphanumeric() || slice[i] == b'_') {
                    i += 1;
                }
                if i < slice.len() && slice[i] == b')' {
                    payload = parse_nan_payload(&slice[seq_start..i]);
                    i += 1; // consume closing paren
                } else {
                    // No closing paren — rewind to before the '('
                    i = paren_start;
                }
            }
            // -NaN and +NaN are distinct per IEEE 754; the payload sets the
            // significand exactly as glibc does.
            return (nan_f64(payload, special_sign < 0.0), i, false);
        }
    }

    // Check for hex float (0x...)
    let is_hex =
        i + 1 < slice.len() && slice[i] == b'0' && (slice[i + 1] == b'x' || slice[i + 1] == b'X');

    if is_hex {
        // Parse hex floating-point: [sign] 0x hex_significand [p binary_exponent]
        // sign was already consumed; `start` marks where sign (or first digit) began.
        let negative = start < slice.len() && slice[start] == b'-';
        i += 2; // skip "0x" / "0X"
        // Index just past the leading '0'. Used to rewind if no hex digits
        // follow the prefix — `i` may be advanced further (e.g. past a '.')
        // before the `has_digits` check, so `i - 1` is not reliable there.
        let zero_end = i - 1;

        // Parse the hex significand (integer then optional fractional part) into
        // an exact u128 mantissa rather than an f64 accumulator: the old
        // `significand * 16.0 + digit` rounded at EVERY step, so a significand
        // wider than 53 bits (> ~13 hex digits) lost precision and the final
        // value was off by up to 1 ULP vs glibc. A u128 holds 32 hex digits
        // (128 bits) exactly; further low digits only set the sticky bit (they
        // sit below the mantissa LSB). The single rounding then happens in the
        // correctly-rounded `u128 as f64` conversion below.
        let mut mantissa: u128 = 0;
        let mut sticky = false;
        let mut int_overflow_shift: i32 = 0;
        let mut frac_hex_digits: i32 = 0;
        let mut has_digits = false;
        let mut in_frac = false;

        loop {
            if i < slice.len() && slice[i].is_ascii_hexdigit() {
                has_digits = true;
                let d = hex_digit_val(slice[i]) as u128;
                if mantissa < (1u128 << 124) {
                    mantissa = (mantissa << 4) | d;
                    if in_frac {
                        frac_hex_digits = frac_hex_digits.saturating_add(1);
                    }
                } else {
                    // Mantissa is full; this digit is below the representable
                    // window. Track it as sticky; an integer-part digit still
                    // scales the magnitude (×16), a fractional one does not.
                    if d != 0 {
                        sticky = true;
                    }
                    if !in_frac {
                        int_overflow_shift = int_overflow_shift.saturating_add(4);
                    }
                }
                i += 1;
            } else if !in_frac && i < slice.len() && slice[i] == b'.' {
                in_frac = true;
                i += 1;
            } else {
                break;
            }
        }

        if !has_digits {
            // No hex digits after "0x" — the "0" before "x" is a valid
            // decimal number. Rewind to just past the leading '0' so the
            // consumed count covers only that '0' (and any sign/whitespace),
            // not the 'x'/'X' or a following '.'. The parsed value is zero, but
            // a leading '-' makes it NEGATIVE zero (glibc applies the sign to
            // the zero result; +0.0 here diverged in the bit pattern).
            return (if negative { -0.0 } else { 0.0 }, zero_end, false);
        }

        // Parse binary exponent (p/P followed by optional sign and decimal digits)
        let mut bin_exp: i32 = 0;
        if i < slice.len() && (slice[i] == b'p' || slice[i] == b'P') {
            // A 'p'/'P' with no exponent digits is a malformed exponent: the
            // 'p' (and any sign) is not part of the number, so rewind to it —
            // mirroring the decimal 'e'/'E' exponent handling below.
            let saved_i = i;
            i += 1;
            let mut exp_neg = false;
            if i < slice.len() && slice[i] == b'+' {
                i += 1;
            } else if i < slice.len() && slice[i] == b'-' {
                exp_neg = true;
                i += 1;
            }
            let mut has_exp_digits = false;
            while i < slice.len() && slice[i].is_ascii_digit() {
                has_exp_digits = true;
                bin_exp = bin_exp
                    .saturating_mul(10)
                    .saturating_add((slice[i] - b'0') as i32);
                i += 1;
            }
            if !has_exp_digits {
                i = saved_i;
            } else if exp_neg {
                bin_exp = -bin_exp;
            }
        }

        // Each hex fractional digit shifts by 4 binary positions, so adjust.
        // result = significand * 2^(bin_exp - 4 * frac_hex_digits)
        let effective_exp = bin_exp
            .saturating_sub(frac_hex_digits.saturating_mul(4))
            .saturating_add(int_overflow_shift);
        // Bit span of the true value (mantissa * 2^effective_exp), captured
        // BEFORE the sticky fold below. Used to decide whether the result is
        // EXACTLY representable in f64 — needed both for the ERANGE underflow
        // decision (glibc raises ERANGE only for INEXACT underflow) and for
        // strtof's f32 exactness. (bd-2g7oyh.187)
        let (lowest_bit_pos, span) = if mantissa == 0 {
            (i32::MAX, 0)
        } else {
            let lo = effective_exp.saturating_add(mantissa.trailing_zeros() as i32);
            let hi = effective_exp.saturating_add(127 - mantissa.leading_zeros() as i32);
            (lo, hi - lo)
        };
        // Fold the sticky bit into the mantissa LSB so the `u128 as f64`
        // round-to-nearest-even sees that low bits were truncated.
        if sticky {
            mantissa |= 1;
        }
        // `u128 as f64` is correctly rounded; ldexp by a power of two is exact
        // for normal results (one total rounding).
        let val = libm::ldexp(mantissa as f64, effective_exp);

        let val = if negative { -val } else { val };
        // EXACTLY representable iff nothing was truncated (no sticky), it fits
        // the 53-bit significand (span <= 52), no bit fell below the smallest
        // subnormal (>= 2^-1074), and it did not overflow to infinity.
        let exact =
            mantissa == 0 || (!sticky && val.is_finite() && lowest_bit_pos >= -1074 && span <= 52);
        return (val, i, exact);
    }

    // Decimal float path
    // Consume digits, decimal point, exponent.
    let mut has_digits = false;
    while i < slice.len() && slice[i].is_ascii_digit() {
        has_digits = true;
        i += 1;
    }
    if i < slice.len() && slice[i] == b'.' {
        i += 1;
        while i < slice.len() && slice[i].is_ascii_digit() {
            has_digits = true;
            i += 1;
        }
    }
    if !has_digits {
        return (0.0, 0, false);
    }
    // Exponent
    if i < slice.len() && (slice[i] == b'e' || slice[i] == b'E') {
        let saved_i = i;
        i += 1;
        if i < slice.len() && (slice[i] == b'+' || slice[i] == b'-') {
            i += 1;
        }
        let mut has_exp_digits = false;
        while i < slice.len() && slice[i].is_ascii_digit() {
            has_exp_digits = true;
            i += 1;
        }
        if !has_exp_digits {
            i = saved_i;
        }
    }

    let num_str = core::str::from_utf8(&slice[start..i]).unwrap_or("");
    match num_str.parse::<f64>() {
        Ok(val) => (val, i, false),
        Err(_) => (0.0, 0, false),
    }
}

/// C `strtod` -- parse double from string, returns (value, bytes_consumed).
pub fn strtod(s: &[u8]) -> (f64, usize) {
    let (v, c, _) = strtod_impl(s);
    (v, c)
}

fn parse_decimal_f32_prefix(slice: &[u8], consumed: usize) -> Option<f32> {
    let consumed = consumed.min(slice.len());
    let mut start = 0;
    while start < consumed && is_c_space(slice[start]) {
        start += 1;
    }
    if start >= consumed {
        return None;
    }

    let mut token_start = start;
    if matches!(slice[token_start], b'+' | b'-') {
        token_start += 1;
    }
    if token_start >= consumed {
        return None;
    }

    if matches!(slice[token_start], b'i' | b'I' | b'n' | b'N') {
        return None;
    }
    if token_start + 1 < consumed
        && slice[token_start] == b'0'
        && matches!(slice[token_start + 1], b'x' | b'X')
    {
        return None;
    }

    let text = core::str::from_utf8(&slice[start..consumed]).ok()?;
    text.parse::<f32>().ok()
}

/// Parses a C `float` from a NUL-terminated byte slice.
///
/// Decimal inputs must round directly to `f32`; parsing through `f64` first can
/// double-round halfway cases and drift from libc.
/// Parse a NaN `(n-char-sequence)` payload exactly as glibc's `__strtoX_nan`
/// does: `strtoull(seq, base 0)` (a `0x` prefix selects hex, a leading `0`
/// selects octal, otherwise decimal), saturating to `u64::MAX` on overflow and
/// stopping at the first character not valid for the base. The result is later
/// masked into the significand (52 bits for `double`, 23 for `float`).
pub fn parse_nan_payload(seq: &[u8]) -> u64 {
    let (radix, mut i): (u64, usize) = if seq.len() >= 2 && seq[0] == b'0' && (seq[1] | 0x20) == b'x'
    {
        (16, 2)
    } else if !seq.is_empty() && seq[0] == b'0' {
        (8, 1)
    } else {
        (10, 0)
    };
    let mut acc: u64 = 0;
    let mut overflow = false;
    while i < seq.len() {
        let d = match seq[i] {
            b'0'..=b'9' => (seq[i] - b'0') as u64,
            b'a'..=b'f' => (seq[i] - b'a' + 10) as u64,
            b'A'..=b'F' => (seq[i] - b'A' + 10) as u64,
            _ => break,
        };
        if d >= radix {
            break;
        }
        match acc.checked_mul(radix).and_then(|v| v.checked_add(d)) {
            Some(v) => acc = v,
            None => overflow = true,
        }
        i += 1;
    }
    if overflow { u64::MAX } else { acc }
}

/// Build an `f64` quiet NaN carrying `payload` (masked to the 52-bit
/// significand, quiet bit forced) and the given sign — matching glibc strtod.
pub fn nan_f64(payload: u64, negative: bool) -> f64 {
    let bits = 0x7ff8_0000_0000_0000u64
        | (payload & 0x000f_ffff_ffff_ffff)
        | ((negative as u64) << 63);
    f64::from_bits(bits)
}

/// Narrow an `f64` to `f32`, preserving a NaN's sign and low-23-bit payload the
/// way glibc's strtof does. A plain `as f32` cast does NOT preserve the payload
/// (LLVM `fptrunc` keeps the high mantissa bits; glibc uses the low ones), so a
/// NaN must be reconstructed from its bit pattern.
pub fn narrow_f64_to_f32(v: f64) -> f32 {
    if v.is_nan() {
        let b = v.to_bits();
        let sign = ((b >> 63) as u32) << 31;
        let payload = (b & 0x7f_ffff) as u32; // low 23 bits == the float payload
        f32::from_bits(0x7fc0_0000 | sign | payload)
    } else {
        v as f32
    }
}

pub fn strtof_impl(s: &[u8]) -> (f32, usize, bool) {
    let (wide, consumed, wide_exact) = strtod_impl(s);
    if consumed == 0 {
        return (wide as f32, consumed, false);
    }

    let len = crate::string::strlen(s);
    let slice = &s[..len];
    if let Some(value) = parse_decimal_f32_prefix(slice, consumed) {
        // Decimal subnormals are inexact in practice (a short decimal almost
        // never equals an exact f32 subnormal), so no exact-subnormal flag.
        return (value, consumed, false);
    }

    // Hex/special path: narrow preserving a NaN payload (plain `as f32` drops
    // it). The f32 result is an EXACT subnormal iff the f64 parse was lossless
    // AND the f64->f32 narrowing was lossless (`value as f64` — always exact
    // widening — round-trips to `wide`) AND the result is a nonzero f32
    // subnormal. (bd-2g7oyh.187)
    let value = narrow_f64_to_f32(wide);
    let exact_subnormal =
        wide_exact && (value as f64 == wide) && value != 0.0 && value.abs() < f32::MIN_POSITIVE;
    (value, consumed, exact_subnormal)
}

/// C `strtof` -- parse float from string, returns (value, bytes_consumed).
pub fn strtof(s: &[u8]) -> (f32, usize) {
    let (v, c, _) = strtof_impl(s);
    (v, c)
}

/// C `atof` -- equivalent to `strtod(s, NULL)`.
pub fn atof(s: &[u8]) -> f64 {
    strtod_impl(s).0
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;
    use proptest::test_runner::Config as ProptestConfig;

    #[test]
    fn swar_parse_eight_matches_scalar() {
        // Positional weights: a single digit d at position p (0 = leftmost /
        // most significant) must contribute d * 10^(7-p).
        for p in 0..8u32 {
            for d in 0..10u8 {
                let mut chars = [b'0'; 8];
                chars[p as usize] = b'0' + d;
                let word = u64::from_le_bytes(chars);
                assert!(is_eight_digits(word));
                let got = parse_eight_digits(word);
                let want = d as u32 * 10u32.pow(7 - p);
                assert_eq!(got, want, "digit {d} at pos {p}");
            }
        }
        // Deterministic xorshift fuzz over 5M random 8-digit values; the SWAR
        // parse must equal the value whose decimal rendering produced the chars.
        let mut st: u64 = 0x1234_5678_9abc_def1;
        let mut next = || {
            st ^= st << 13;
            st ^= st >> 7;
            st ^= st << 17;
            st
        };
        for _ in 0..5_000_000 {
            let n = (next() % 100_000_000) as u32; // 0..=99_999_999
            let s = format!("{n:08}");
            let word = u64::from_le_bytes(s.as_bytes().try_into().unwrap());
            assert!(is_eight_digits(word), "is_eight_digits failed for {s}");
            assert_eq!(parse_eight_digits(word), n, "parse mismatch for {s}");
        }
        // is_eight_digits rejects non-digits at every position.
        for p in 0..8usize {
            for &bad in &[b'/', b':', b' ', b'a', b'\0', 0x80] {
                let mut chars = [b'5'; 8];
                chars[p] = bad;
                assert!(
                    !is_eight_digits(u64::from_le_bytes(chars)),
                    "byte {bad:#x} at {p} wrongly accepted"
                );
            }
        }
    }

    #[test]
    fn swar_parse_eight_hex_matches_scalar() {
        // Positional weights: a single hex digit at position p (0 = leftmost)
        // contributes its nibble << 4*(7-p).
        for p in 0..8u32 {
            for d in 0..16u8 {
                let ch = if d < 10 { b'0' + d } else { b'a' + (d - 10) };
                let mut chars = [b'0'; 8];
                chars[p as usize] = ch;
                let word = u64::from_le_bytes(chars);
                let got = parse_eight_hex(word).expect("valid hex");
                assert_eq!(got, (d as u32) << (4 * (7 - p)), "hex {ch} at pos {p}");
                // uppercase form decodes identically
                let upper = if d < 10 { ch } else { b'A' + (d - 10) };
                let mut uchars = [b'0'; 8];
                uchars[p as usize] = upper;
                assert_eq!(parse_eight_hex(u64::from_le_bytes(uchars)), Some(got));
            }
        }
        // 5M random 32-bit values: format as 8 hex digits, SWAR-parse, compare.
        let mut st: u64 = 0x0f1e_2d3c_4b5a_6978;
        let mut next = || {
            st ^= st << 13;
            st ^= st >> 7;
            st ^= st << 17;
            st
        };
        for _ in 0..5_000_000 {
            let n = next() as u32;
            let s = format!("{n:08x}");
            let word = u64::from_le_bytes(s.as_bytes().try_into().unwrap());
            assert_eq!(parse_eight_hex(word), Some(n), "hex parse {s}");
        }
        // Reject EVERY non-hex byte (0..=255) at every lane — truly exhaustive.
        // (Previously this only spot-checked a handful of gap chars and MISSED
        // the control bytes 0x10..=0x19, which `| 0x20` folds onto '0'..='9' —
        // a real over-consumption bug surfaced by strtol_family_differential_fuzz.)
        let is_hex =
            |b: u8| b.is_ascii_digit() || (b'a'..=b'f').contains(&b) || (b'A'..=b'F').contains(&b);
        for p in 0..8usize {
            for bad in 0u8..=255 {
                if is_hex(bad) {
                    continue;
                }
                let mut chars = [b'a'; 8];
                chars[p] = bad;
                assert_eq!(
                    parse_eight_hex(u64::from_le_bytes(chars)),
                    None,
                    "byte {bad:#x} at {p} wrongly accepted"
                );
            }
        }
    }

    #[test]
    fn swar_strtol_hex_matches_scalar_reference() {
        // Independent scalar reference for strtol base 16 (no 0x prefix consumed
        // here — feed raw hex digits) to pin the SWAR hex fast path.
        fn scalar_ref(s: &[u8]) -> (i64, usize, ConversionStatus) {
            let mut i = 0;
            while i < s.len() && is_c_space(s[i]) {
                i += 1;
            }
            let mut neg = false;
            if i < s.len() && (s[i] == b'+' || s[i] == b'-') {
                neg = s[i] == b'-';
                i += 1;
            }
            let abs_max = if neg {
                9_223_372_036_854_775_808u64
            } else {
                9_223_372_036_854_775_807u64
            };
            let (mut acc, mut any, mut ovf) = (0u64, false, false);
            while i < s.len() {
                let d = match s[i] {
                    c @ b'0'..=b'9' => (c - b'0') as u64,
                    c @ b'a'..=b'f' => (c - b'a' + 10) as u64,
                    c @ b'A'..=b'F' => (c - b'A' + 10) as u64,
                    _ => break,
                };
                any = true;
                if !ovf {
                    match acc.checked_mul(16).and_then(|a| a.checked_add(d)) {
                        Some(v) if v <= abs_max => acc = v,
                        _ => ovf = true,
                    }
                }
                i += 1;
            }
            if !any {
                return (0, 0, ConversionStatus::Success);
            }
            if ovf {
                return if neg {
                    (i64::MIN, i, ConversionStatus::Underflow)
                } else {
                    (i64::MAX, i, ConversionStatus::Overflow)
                };
            }
            let v = if neg {
                (acc as i64).wrapping_neg()
            } else {
                acc as i64
            };
            (v, i, ConversionStatus::Success)
        }
        let mut st: u64 = 0xcafe_f00d_dead_beef;
        let mut next = || {
            st ^= st << 13;
            st ^= st >> 7;
            st ^= st << 17;
            st
        };
        let hexset = b"0123456789abcdefABCDEF";
        for _ in 0..1_000_000 {
            let len = (next() % 22) as usize;
            let mut buf = Vec::with_capacity(len + 2);
            match next() % 4 {
                0 => buf.push(b'-'),
                1 => buf.push(b'+'),
                _ => {}
            }
            for _ in 0..len {
                buf.push(hexset[(next() % 22) as usize]);
            }
            if next() % 3 == 0 {
                buf.push(b"xyz @"[(next() % 5) as usize]);
            }
            assert_eq!(
                strtol_impl(&buf, 16),
                scalar_ref(&buf),
                "strtol(16) divergence on {:?}",
                String::from_utf8_lossy(&buf)
            );
        }
    }

    #[test]
    fn swar_strtol_matches_scalar_reference() {
        // Scalar reference strtol(base 10) — the algorithm-independent oracle the
        // SWAR fast path must match bit-for-bit (value, consumed, status).
        fn scalar_ref(s: &[u8]) -> (i64, usize, ConversionStatus) {
            let mut i = 0;
            while i < s.len() && is_c_space(s[i]) {
                i += 1;
            }
            let mut neg = false;
            if i < s.len() && (s[i] == b'+' || s[i] == b'-') {
                neg = s[i] == b'-';
                i += 1;
            }
            let abs_max = if neg {
                9_223_372_036_854_775_808u64
            } else {
                9_223_372_036_854_775_807u64
            };
            let (mut acc, mut any, mut ovf) = (0u64, false, false);
            while i < s.len() {
                let d = match s[i] {
                    c @ b'0'..=b'9' => (c - b'0') as u64,
                    _ => break,
                };
                any = true;
                if !ovf {
                    match acc.checked_mul(10).and_then(|a| a.checked_add(d)) {
                        Some(v) if v <= abs_max => acc = v,
                        _ => ovf = true,
                    }
                }
                i += 1;
            }
            if !any {
                return (0, 0, ConversionStatus::Success);
            }
            if ovf {
                return if neg {
                    (i64::MIN, i, ConversionStatus::Underflow)
                } else {
                    (i64::MAX, i, ConversionStatus::Overflow)
                };
            }
            let v = if neg {
                (acc as i64).wrapping_neg()
            } else {
                acc as i64
            };
            (v, i, ConversionStatus::Success)
        }

        let mut st: u64 = 0x9e37_79b9_7f4a_7c15;
        let mut next = || {
            st ^= st << 13;
            st ^= st >> 7;
            st ^= st << 17;
            st
        };
        // Build varied-length decimal strings (incl. leading zeros, signs,
        // overflow-length 20+ digit runs, trailing non-digits) and compare the
        // SWAR-enabled strtol_impl to the scalar oracle.
        for _ in 0..1_000_000 {
            let len = (next() % 25) as usize;
            let mut buf = Vec::with_capacity(len + 2);
            match next() % 4 {
                0 => buf.push(b'-'),
                1 => buf.push(b'+'),
                _ => {}
            }
            for _ in 0..len {
                buf.push(b'0' + (next() % 10) as u8);
            }
            if next() % 3 == 0 {
                buf.push(b"xyz @"[(next() % 5) as usize]);
            }
            assert_eq!(
                strtol_impl(&buf, 10),
                scalar_ref(&buf),
                "strtol divergence on {:?}",
                String::from_utf8_lossy(&buf)
            );
        }
    }

    #[test]
    fn swar_strtoul_hex_matches_scalar_reference() {
        // Independent scalar oracle for unsigned base-16 strtoul.
        fn scalar_ref(s: &[u8]) -> (u64, usize, ConversionStatus) {
            let mut i = 0;
            while i < s.len() && is_c_space(s[i]) {
                i += 1;
            }
            if i == s.len() {
                return (0, 0, ConversionStatus::Success);
            }
            let mut neg = false;
            if s[i] == b'+' || s[i] == b'-' {
                neg = s[i] == b'-';
                i += 1;
            }
            let (mut acc, mut any, mut ovf) = (0u64, false, false);
            while i < s.len() {
                let d = match s[i] {
                    c @ b'0'..=b'9' => (c - b'0') as u64,
                    c @ b'a'..=b'f' => (c - b'a' + 10) as u64,
                    c @ b'A'..=b'F' => (c - b'A' + 10) as u64,
                    _ => break,
                };
                any = true;
                if !ovf {
                    match acc.checked_mul(16).and_then(|a| a.checked_add(d)) {
                        Some(v) => acc = v,
                        None => ovf = true,
                    }
                }
                i += 1;
            }
            if !any {
                return (0, 0, ConversionStatus::Success);
            }
            if ovf {
                return (u64::MAX, i, ConversionStatus::Overflow);
            }
            (
                if neg { acc.wrapping_neg() } else { acc },
                i,
                ConversionStatus::Success,
            )
        }
        let mut st: u64 = 0xfeed_face_8bad_f00d;
        let mut next = || {
            st ^= st << 13;
            st ^= st >> 7;
            st ^= st << 17;
            st
        };
        let hexset = b"0123456789abcdefABCDEF";
        for _ in 0..1_000_000 {
            let len = (next() % 22) as usize;
            let mut buf = Vec::with_capacity(len + 2);
            match next() % 4 {
                0 => buf.push(b'-'),
                1 => buf.push(b'+'),
                _ => {}
            }
            for _ in 0..len {
                buf.push(hexset[(next() % 22) as usize]);
            }
            if next() % 3 == 0 {
                buf.push(b"xyz @"[(next() % 5) as usize]);
            }
            assert_eq!(
                strtoul_impl(&buf, 16),
                scalar_ref(&buf),
                "strtoul(16) divergence on {:?}",
                String::from_utf8_lossy(&buf)
            );
        }
    }

    #[test]
    fn swar_strtoul_matches_scalar_reference() {
        // Independent scalar oracle for unsigned base-10 strtoul (sign negates
        // via wrapping_neg, overflow -> u64::MAX, end position digit-exact).
        fn scalar_ref(s: &[u8]) -> (u64, usize, ConversionStatus) {
            let mut i = 0;
            while i < s.len() && is_c_space(s[i]) {
                i += 1;
            }
            if i == s.len() {
                return (0, 0, ConversionStatus::Success);
            }
            let mut neg = false;
            if s[i] == b'+' || s[i] == b'-' {
                neg = s[i] == b'-';
                i += 1;
            }
            let (mut acc, mut any, mut ovf) = (0u64, false, false);
            while i < s.len() {
                let d = match s[i] {
                    c @ b'0'..=b'9' => (c - b'0') as u64,
                    _ => break,
                };
                any = true;
                if !ovf {
                    match acc.checked_mul(10).and_then(|a| a.checked_add(d)) {
                        Some(v) => acc = v,
                        None => ovf = true,
                    }
                }
                i += 1;
            }
            if !any {
                return (0, 0, ConversionStatus::Success);
            }
            if ovf {
                return (u64::MAX, i, ConversionStatus::Overflow);
            }
            (
                if neg { acc.wrapping_neg() } else { acc },
                i,
                ConversionStatus::Success,
            )
        }

        let mut st: u64 = 0xd1b5_4a32_d192_ed03;
        let mut next = || {
            st ^= st << 13;
            st ^= st >> 7;
            st ^= st << 17;
            st
        };
        for _ in 0..1_000_000 {
            let len = (next() % 25) as usize;
            let mut buf = Vec::with_capacity(len + 2);
            match next() % 4 {
                0 => buf.push(b'-'),
                1 => buf.push(b'+'),
                _ => {}
            }
            for _ in 0..len {
                buf.push(b'0' + (next() % 10) as u8);
            }
            if next() % 3 == 0 {
                buf.push(b"xyz @"[(next() % 5) as usize]);
            }
            assert_eq!(
                strtoul_impl(&buf, 10),
                scalar_ref(&buf),
                "strtoul divergence on {:?}",
                String::from_utf8_lossy(&buf)
            );
        }
    }

    fn property_proptest_config(default_cases: u32) -> ProptestConfig {
        let cases = std::env::var("FRANKENLIBC_PROPTEST_CASES")
            .ok()
            .and_then(|value| value.parse::<u32>().ok())
            .filter(|&value| value > 0)
            .unwrap_or(default_cases);

        ProptestConfig {
            cases,
            failure_persistence: None,
            ..ProptestConfig::default()
        }
    }

    #[test]
    fn test_atoi_basic() {
        assert_eq!(atoi(b"42"), 42);
        assert_eq!(atoi(b"-42"), -42);
        assert_eq!(atoi(b"   123"), 123);
    }

    #[test]
    fn test_atoll_aliases_atol() {
        assert_eq!(atoll(b"9223372036854775807"), i64::MAX);
        assert_eq!(atoll(b"-9223372036854775808"), i64::MIN);
    }

    #[test]
    fn test_strtol_base10() {
        let (val, len) = strtol(b"123456", 10);
        assert_eq!(val, 123456);
        assert_eq!(len, 6);
    }

    #[test]
    fn test_strtoimax_aliases_strtol() {
        let (val, len) = strtoimax(b"-9223372036854775808", 10);
        assert_eq!(val, i64::MIN);
        assert_eq!(len, 20);
    }

    #[test]
    fn test_strtoll_aliases_strtol() {
        let (val, len) = strtoll(b"-9223372036854775808", 10);
        assert_eq!(val, i64::MIN);
        assert_eq!(len, 20);
    }

    #[test]
    fn test_strtol_base16() {
        let (val, len) = strtol(b"0xFF", 16);
        assert_eq!(val, 255);
        assert_eq!(len, 4);

        let (val, len) = strtol(b"FF", 16);
        assert_eq!(val, 255);
        assert_eq!(len, 2);
    }

    #[test]
    fn test_strtol_auto_base() {
        let (val, _) = strtol(b"0x10", 0);
        assert_eq!(val, 16);
        let (val, _) = strtol(b"010", 0);
        assert_eq!(val, 8);
        let (val, _) = strtol(b"10", 0);
        assert_eq!(val, 10);
    }

    #[test]
    fn test_strtol_overflow() {
        let max = i64::MAX;
        let s = format!("{}", max);
        let (val, _, status) = strtol_impl(s.as_bytes(), 10);
        assert_eq!(val, max);
        assert_eq!(status, ConversionStatus::Success);

        let s_over = "9223372036854775808"; // MAX + 1
        let (val, _, status) = strtol_impl(s_over.as_bytes(), 10);
        assert_eq!(val, i64::MAX);
        assert_eq!(status, ConversionStatus::Overflow);

        let min = i64::MIN;
        let s_min = format!("{}", min);
        let (val, _, status) = strtol_impl(s_min.as_bytes(), 10);
        assert_eq!(val, min);
        assert_eq!(status, ConversionStatus::Success);

        let s_under = "-9223372036854775809"; // MIN - 1
        let (val, _, status) = strtol_impl(s_under.as_bytes(), 10);
        assert_eq!(val, i64::MIN);
        assert_eq!(status, ConversionStatus::Underflow);
    }

    #[test]
    fn test_strtoul_overflow() {
        let max = u64::MAX;
        let s = format!("{}", max);
        let (val, _, status) = strtoul_impl(s.as_bytes(), 10);
        assert_eq!(val, max);
        assert_eq!(status, ConversionStatus::Success);

        let s_over = "18446744073709551616"; // MAX + 1
        let (val, _, status) = strtoul_impl(s_over.as_bytes(), 10);
        assert_eq!(val, u64::MAX);
        assert_eq!(status, ConversionStatus::Overflow);
    }

    #[test]
    fn test_strtoumax_aliases_strtoul() {
        let (val, len) = strtoumax(b"18446744073709551615", 10);
        assert_eq!(val, u64::MAX);
        assert_eq!(len, 20);
    }

    #[test]
    fn test_strtoull_aliases_strtoul() {
        let (val, len) = strtoull(b"18446744073709551615", 10);
        assert_eq!(val, u64::MAX);
        assert_eq!(len, 20);
    }

    #[test]
    fn test_strtol_0x_edge_cases() {
        // "0xz" base 0 -> parses "0", stops at 'x'
        // expected: 0, len 1.
        let (val, len) = strtol(b"0xz", 0);
        assert_eq!(val, 0);
        assert_eq!(len, 1);

        // "0xz" base 16 -> parses "0", stops at 'x'
        let (val, len) = strtol(b"0xz", 16);
        assert_eq!(val, 0);
        assert_eq!(len, 1);

        // "0x" base 0 -> parses "0", stops at 'x'
        let (val, len) = strtol(b"0x", 0);
        assert_eq!(val, 0);
        assert_eq!(len, 1);

        // "0x1" base 0 -> parses "0x1" (16)
        let (val, len) = strtol(b"0x1", 0);
        assert_eq!(val, 1);
        assert_eq!(len, 3);
    }

    #[test]
    fn test_strtol_binary_prefix() {
        // "0b1010" base 0 -> parses as binary, returns 10
        let (val, len) = strtol(b"0b1010", 0);
        assert_eq!(val, 10);
        assert_eq!(len, 6);

        // "0B1111" uppercase also works
        let (val, len) = strtol(b"0B1111", 0);
        assert_eq!(val, 15);
        assert_eq!(len, 6);

        // "0b1010" base 2 -> skips prefix
        let (val, len) = strtol(b"0b1010", 2);
        assert_eq!(val, 10);
        assert_eq!(len, 6);

        // "0b" without digits -> parses "0", stops at 'b'
        let (val, len) = strtol(b"0b", 0);
        assert_eq!(val, 0);
        assert_eq!(len, 1);

        // "0bz" invalid digit after prefix -> parses "0"
        let (val, len) = strtol(b"0bz", 0);
        assert_eq!(val, 0);
        assert_eq!(len, 1);

        // "-0b1010" negative binary
        let (val, len) = strtol(b"-0b1010", 0);
        assert_eq!(val, -10);
        assert_eq!(len, 7);
    }

    #[test]
    fn test_strtoul_binary_prefix() {
        let (val, len) = strtoul(b"0b11111111", 0);
        assert_eq!(val, 255);
        assert_eq!(len, 10);
    }

    #[test]
    fn test_atof_basic() {
        assert!((atof(b"3.25\0") - 3.25).abs() < 1e-10);
        assert!((atof(b"-42.5\0") - (-42.5)).abs() < 1e-10);
        assert_eq!(atof(b"0\0"), 0.0);
    }

    #[test]
    fn test_strtod_basic() {
        let (val, consumed) = strtod(b"123.456abc\0");
        assert!((val - 123.456).abs() < 1e-10);
        assert_eq!(consumed, 7);
    }

    #[test]
    fn test_strtod_whitespace() {
        let (val, consumed) = strtod(b"  42.0\0");
        assert!((val - 42.0).abs() < 1e-10);
        assert_eq!(consumed, 6);
    }

    #[test]
    fn leading_c_isspace_set_matches_glibc() {
        // The C standard cites isspace() for the leading whitespace
        // skipped by strtol/strtoul/strtod. The C-locale isspace set
        // includes the vertical tab \x0b and form feed \x0c, which
        // Rust's u8::is_ascii_whitespace omits / includes inconsistently.
        // Verified against host glibc: strtol("\x0b\x0b42") == 42.
        for &ws in &[b' ', b'\t', b'\n', 0x0b, 0x0c, b'\r'] {
            let buf = [ws, ws, b'4', b'2'];
            let (v, consumed, status) = strtol_impl(&buf, 10);
            assert_eq!(v, 42, "strtol must skip leading {ws:#04x}");
            assert_eq!(consumed, 4);
            assert_eq!(status, ConversionStatus::Success);

            let (uv, uconsumed, _) = strtoul_impl(&buf, 10);
            assert_eq!(uv, 42, "strtoul must skip leading {ws:#04x}");
            assert_eq!(uconsumed, 4);

            let fbuf = [ws, b'4', b'2', b'.', b'0', 0];
            let (fv, fconsumed) = strtod(&fbuf);
            assert!((fv - 42.0).abs() < 1e-10, "strtod must skip {ws:#04x}");
            assert_eq!(fconsumed, 5);
        }
        // A non-isspace control byte must NOT be skipped.
        let (v, consumed, _) = strtol_impl(&[0x0e, b'4', b'2'], 10);
        assert_eq!((v, consumed), (0, 0), "0x0e is not whitespace");
    }

    #[test]
    fn test_strtod_infinity() {
        let (val, consumed) = strtod(b"inf\0");
        assert!(val.is_infinite() && val > 0.0);
        assert_eq!(consumed, 3);
    }

    #[test]
    fn test_strtod_nan() {
        let (val, _) = strtod(b"nan\0");
        assert!(val.is_nan());
        // Positive NaN: sign bit should be clear.
        assert_eq!(val.to_bits() >> 63, 0, "plain nan should be positive");
    }

    #[test]
    fn test_strtod_negative_nan() {
        let (val, consumed) = strtod(b"-nan\0");
        assert!(val.is_nan());
        assert_eq!(consumed, 4);
        // Negative NaN: sign bit must be set (IEEE 754 sign-bit semantics).
        assert_eq!(val.to_bits() >> 63, 1, "-nan must have sign bit set");
    }

    #[test]
    fn test_strtod_nan_payload() {
        // glibc accepts nan(n-char-sequence) forms.
        let (val, consumed) = strtod(b"nan(12345)\0");
        assert!(val.is_nan());
        assert_eq!(consumed, 10);

        let (val, consumed) = strtod(b"nan(abc)\0");
        assert!(val.is_nan());
        assert_eq!(consumed, 8);

        let (val, consumed) = strtod(b"nan()\0");
        assert!(val.is_nan());
        assert_eq!(consumed, 5);

        let (val, consumed) = strtod(b"nan(0x123)\0");
        assert!(val.is_nan());
        assert_eq!(consumed, 10);

        let (val, consumed) = strtod(b"nan(_foo_bar_)\0");
        assert!(val.is_nan());
        assert_eq!(consumed, 14);

        // Missing closing paren: don't consume the '('
        let (val, consumed) = strtod(b"nan(123\0");
        assert!(val.is_nan());
        assert_eq!(consumed, 3);

        // Invalid char in payload: stop at the invalid char, don't consume '('
        let (val, consumed) = strtod(b"nan(a-b)\0");
        assert!(val.is_nan());
        assert_eq!(consumed, 3);
    }

    #[test]
    fn test_strtof_basic() {
        let (val, consumed) = strtof(b"3.25\0");
        assert!((val - 3.25_f32).abs() < 1e-5);
        assert_eq!(consumed, 4);
    }

    #[test]
    fn test_strtof_decimal_rounds_directly_to_f32() {
        let input = b"1.0000000596046447753906251\0";
        let (val, consumed) = strtof(input);
        assert_eq!(val.to_bits(), 0x3f80_0001);
        assert_eq!(consumed, 27);
    }

    #[test]
    fn test_strtod_hex_float_basic() {
        // 0x1p0 = 1.0 * 2^0 = 1.0
        let (val, consumed) = strtod(b"0x1p0\0");
        assert_eq!(val, 1.0);
        assert_eq!(consumed, 5);

        // 0x1p1 = 1.0 * 2^1 = 2.0
        let (val, consumed) = strtod(b"0x1p1\0");
        assert_eq!(val, 2.0);
        assert_eq!(consumed, 5);

        // 0x1p-3 = 1.0 * 2^-3 = 0.125
        let (val, consumed) = strtod(b"0x1p-3\0");
        assert_eq!(val, 0.125);
        assert_eq!(consumed, 6);

        // 0xAp0 = 10.0
        let (val, _) = strtod(b"0xAp0\0");
        assert_eq!(val, 10.0);
    }

    #[test]
    fn test_strtod_hex_float_fractional() {
        // 0x1.0p0 = 1.0
        let (val, consumed) = strtod(b"0x1.0p0\0");
        assert_eq!(val, 1.0);
        assert_eq!(consumed, 7);

        // 0x1.8p0 = 1.5 (0x1 = 1, .8 = 8/16 = 0.5)
        let (val, _) = strtod(b"0x1.8p0\0");
        assert_eq!(val, 1.5);

        // 0x1.fp10 = (1 + 15/16) * 2^10 = 1.9375 * 1024 = 1984.0
        let (val, consumed) = strtod(b"0x1.fp10\0");
        assert_eq!(val, 1984.0);
        assert_eq!(consumed, 8);

        // 0xA.Bp5 = (10 + 11/16) * 2^5 = 10.6875 * 32 = 342.0
        let (val, consumed) = strtod(b"0xA.Bp5\0");
        assert_eq!(val, 342.0);
        assert_eq!(consumed, 7);
    }

    #[test]
    fn test_strtod_hex_float_negative() {
        // -0x1.0p0 = -1.0
        let (val, consumed) = strtod(b"-0x1.0p0\0");
        assert_eq!(val, -1.0);
        assert_eq!(consumed, 8);

        // -0x1.fp10 = -1984.0
        let (val, _) = strtod(b"-0x1.fp10\0");
        assert_eq!(val, -1984.0);
    }

    #[test]
    fn test_strtod_hex_float_no_exponent() {
        // 0xff = 255.0 (no p exponent, binary exponent defaults to 0)
        let (val, consumed) = strtod(b"0xff\0");
        assert_eq!(val, 255.0);
        assert_eq!(consumed, 4);

        // 0x1.8 = 1.5
        let (val, consumed) = strtod(b"0x1.8\0");
        assert_eq!(val, 1.5);
        assert_eq!(consumed, 5);
    }

    #[test]
    fn test_strtod_hex_float_uppercase() {
        // 0X1P10 = 1024.0
        let (val, consumed) = strtod(b"0X1P10\0");
        assert_eq!(val, 1024.0);
        assert_eq!(consumed, 6);

        // 0X1.FP10 = 1984.0
        let (val, _) = strtod(b"0X1.FP10\0");
        assert_eq!(val, 1984.0);
    }

    #[test]
    fn test_strtod_hex_float_trailing_chars() {
        // "0x1.8p1xyz" should parse "0x1.8p1" = 3.0, consumed = 7
        let (val, consumed) = strtod(b"0x1.8p1xyz\0");
        assert_eq!(val, 3.0);
        assert_eq!(consumed, 7);
    }

    #[test]
    fn test_strtod_hex_float_with_leading_whitespace() {
        let (val, consumed) = strtod(b"  0x1p2\0");
        assert_eq!(val, 4.0);
        assert_eq!(consumed, 7);
    }

    #[test]
    fn test_strtod_0x_without_hex_digits_parses_zero() {
        // "0x" with no hex digits: the '0' is a valid decimal number.
        // Per C standard, strtod should parse '0' and leave endptr at 'x'.
        let (val, consumed) = strtod(b"0x\0");
        assert_eq!(val, 0.0);
        assert_eq!(consumed, 1, "should consume only the '0', not the 'x'");
    }

    #[test]
    fn test_strtod_neg_0x_without_hex_digits_is_negative_zero() {
        // "-0x" with no hex digits parses the decimal '0', and the leading
        // '-' makes it NEGATIVE zero — glibc applies the sign to the zero
        // result. A bit-pattern check (not `== 0.0`, which ignores the sign).
        let (val, consumed) = strtod(b"-0x\0");
        assert_eq!(consumed, 2, "consume the '-' and '0', not the 'x'");
        assert_eq!(val.to_bits(), (-0.0f64).to_bits(), "expected negative zero");
        // A '+' sign yields positive zero.
        let (valp, _) = strtod(b"+0x\0");
        assert_eq!(valp.to_bits(), (0.0f64).to_bits(), "expected positive zero");
    }

    #[test]
    fn test_strtod_0x_trailing_non_hex() {
        let (val, consumed) = strtod(b"0xGHI\0");
        assert_eq!(val, 0.0);
        assert_eq!(consumed, 1, "no hex digits after 0x → parse '0' only");
    }

    #[test]
    fn test_strtod_0x_dot_without_hex_digits() {
        // "0x." has no hex digits: only the leading '0' is a valid number;
        // the consumed count must not swallow the 'x' or the '.'.
        let (val, consumed) = strtod(b"0x.\0");
        assert_eq!(val, 0.0);
        assert_eq!(consumed, 1, "should consume only the '0'");
    }

    #[test]
    fn test_strtod_hex_float_p_without_exponent_digits() {
        // A 'p' with no exponent digits is a malformed exponent: glibc
        // parses "0x1" = 1.0 and rewinds to the 'p'.
        let (val, consumed) = strtod(b"0x1p\0");
        assert_eq!(val, 1.0);
        assert_eq!(consumed, 3, "the 'p' must not be consumed");

        let (val, consumed) = strtod(b"0x1p+\0");
        assert_eq!(val, 1.0);
        assert_eq!(consumed, 3, "neither the 'p' nor the '+' is consumed");

        let (val, consumed) = strtod(b"0x2pZ\0");
        assert_eq!(val, 2.0);
        assert_eq!(consumed, 3);

        // A well-formed exponent still works.
        let (val, consumed) = strtod(b"0x1p4\0");
        assert_eq!(val, 16.0);
        assert_eq!(consumed, 5);
    }

    proptest! {
        #![proptest_config(property_proptest_config(256))]

        #[test]
        fn prop_strtol_round_trips_all_i64_values(value in any::<i64>()) {
            let text = value.to_string();
            let (parsed, consumed, status) = strtol_impl(text.as_bytes(), 10);
            prop_assert_eq!(parsed, value);
            prop_assert_eq!(consumed, text.len());
            prop_assert_eq!(status, ConversionStatus::Success);
        }

        #[test]
        fn prop_strtoul_round_trips_all_u64_values(value in any::<u64>()) {
            let text = value.to_string();
            let (parsed, consumed, status) = strtoul_impl(text.as_bytes(), 10);
            prop_assert_eq!(parsed, value);
            prop_assert_eq!(consumed, text.len());
            prop_assert_eq!(status, ConversionStatus::Success);
        }

        #[test]
        fn prop_invalid_bases_are_rejected(
            raw in any::<i32>(),
            input in proptest::collection::vec(any::<u8>(), 0..32)
        ) {
            let is_valid = raw == 0 || (2..=36).contains(&raw);
            prop_assume!(!is_valid);

            let mut idx = 0usize;
            while idx < input.len() && is_c_space(input[idx]) {
                idx += 1;
            }
            if idx < input.len() && (input[idx] == b'+' || input[idx] == b'-') {
                idx += 1;
            }
            // strto* implementations return Success before base validation when
            // no parseable body remains after whitespace/sign consumption.
            prop_assume!(idx < input.len());

            let (_, _, status_signed) = strtol_impl(&input, raw);
            let (_, _, status_unsigned) = strtoul_impl(&input, raw);

            prop_assert_eq!(status_signed, ConversionStatus::InvalidBase);
            prop_assert_eq!(status_unsigned, ConversionStatus::InvalidBase);
        }
    }

    // ---- wide_is_space / wide_digit_value ----

    #[test]
    fn wide_is_space_recognizes_ascii_whitespace() {
        for c in [' ', '\t', '\n', '\r', '\x0b', '\x0c'] {
            assert!(wide_is_space(c as u32), "{c:?} should be whitespace");
        }
        for c in ['a', '0', '+', '-', '.'] {
            assert!(!wide_is_space(c as u32));
        }
    }

    #[test]
    fn wide_is_space_rejects_unicode_whitespace() {
        // C-locale iswspace recognizes ONLY ASCII whitespace, so non-ASCII
        // Unicode spaces are NOT leading whitespace for wcstol/wcstoul/wcstod
        // (matching glibc — see bd-2g7oyh.253).
        assert!(!wide_is_space(0x00A0)); // NO-BREAK SPACE
        assert!(!wide_is_space(0x2000)); // EN QUAD
        assert!(!wide_is_space(0x2003)); // EM SPACE
        assert!(!wide_is_space(0x3000)); // IDEOGRAPHIC SPACE
    }

    #[test]
    fn wide_digit_value_decimal() {
        for d in 0..10u32 {
            assert_eq!(wide_digit_value(b'0' as u32 + d), Some(d));
        }
    }

    #[test]
    fn wide_digit_value_lowercase_alpha() {
        assert_eq!(wide_digit_value(b'a' as u32), Some(10));
        assert_eq!(wide_digit_value(b'f' as u32), Some(15));
        assert_eq!(wide_digit_value(b'z' as u32), Some(35));
    }

    #[test]
    fn wide_digit_value_uppercase_alpha() {
        assert_eq!(wide_digit_value(b'A' as u32), Some(10));
        assert_eq!(wide_digit_value(b'F' as u32), Some(15));
        assert_eq!(wide_digit_value(b'Z' as u32), Some(35));
    }

    #[test]
    fn wide_digit_value_rejects_non_digit() {
        assert_eq!(wide_digit_value(b'+' as u32), None);
        assert_eq!(wide_digit_value(b' ' as u32), None);
        assert_eq!(wide_digit_value(0x00A0), None);
    }

    // ---- wcstol_impl ----

    fn ws(s: &str) -> Vec<u32> {
        s.chars().map(|c| c as u32).collect()
    }

    #[test]
    fn wcstol_basic_decimal() {
        let s = ws("42");
        let (val, consumed, status) = wcstol_impl(&s, 10);
        assert_eq!(val, 42);
        assert_eq!(consumed, 2);
        assert_eq!(status, ConversionStatus::Success);
    }

    #[test]
    fn wcstol_negative() {
        let s = ws("-9223372036854775808");
        let (val, consumed, status) = wcstol_impl(&s, 10);
        assert_eq!(val, i64::MIN);
        assert_eq!(consumed, s.len());
        assert_eq!(status, ConversionStatus::Success);
    }

    #[test]
    fn wcstol_positive_max() {
        let s = ws("9223372036854775807");
        let (val, _, status) = wcstol_impl(&s, 10);
        assert_eq!(val, i64::MAX);
        assert_eq!(status, ConversionStatus::Success);
    }

    #[test]
    fn wcstol_overflow_clamps_to_max() {
        let s = ws("9223372036854775808"); // i64::MAX + 1
        let (val, _, status) = wcstol_impl(&s, 10);
        assert_eq!(val, i64::MAX);
        assert_eq!(status, ConversionStatus::Overflow);
    }

    #[test]
    fn wcstol_underflow_clamps_to_min() {
        let s = ws("-9223372036854775809"); // i64::MIN - 1
        let (val, _, status) = wcstol_impl(&s, 10);
        assert_eq!(val, i64::MIN);
        assert_eq!(status, ConversionStatus::Underflow);
    }

    #[test]
    fn wcstol_skips_leading_whitespace() {
        let s = ws("   42");
        let (val, consumed, _) = wcstol_impl(&s, 10);
        assert_eq!(val, 42);
        assert_eq!(consumed, s.len());
    }

    #[test]
    fn wcstol_does_not_skip_unicode_whitespace() {
        // glibc C-locale iswspace is ASCII-only, so a leading non-ASCII space is
        // a non-digit at position 0: no conversion (bd-2g7oyh.253).
        let s = ws("\u{00A0}\u{2000}42");
        let (val, consumed, _) = wcstol_impl(&s, 10);
        assert_eq!(val, 0);
        assert_eq!(consumed, 0);
        // ASCII leading whitespace is still skipped.
        let s = ws(" \t42");
        let (val, _, _) = wcstol_impl(&s, 10);
        assert_eq!(val, 42);
    }

    #[test]
    fn wcstol_auto_base_hex() {
        let s = ws("0xff");
        let (val, consumed, _) = wcstol_impl(&s, 0);
        assert_eq!(val, 255);
        assert_eq!(consumed, 4);
    }

    #[test]
    fn wcstol_auto_base_octal() {
        let s = ws("010");
        let (val, _, _) = wcstol_impl(&s, 0);
        assert_eq!(val, 8);
    }

    #[test]
    fn wcstol_auto_base_decimal() {
        let s = ws("42");
        let (val, _, _) = wcstol_impl(&s, 0);
        assert_eq!(val, 42);
    }

    #[test]
    fn wcstol_auto_base_binary() {
        let s = ws("0b1010");
        let (val, consumed, _) = wcstol_impl(&s, 0);
        assert_eq!(val, 10);
        assert_eq!(consumed, 6);

        let s = ws("0B1111");
        let (val, consumed, _) = wcstol_impl(&s, 0);
        assert_eq!(val, 15);
        assert_eq!(consumed, 6);
    }

    #[test]
    fn wcstol_explicit_base2_consumes_0b_prefix() {
        let s = ws("0b101");
        let (val, consumed, _) = wcstol_impl(&s, 2);
        assert_eq!(val, 5);
        assert_eq!(consumed, 5);
    }

    #[test]
    fn wcstol_explicit_base16_consumes_0x_prefix() {
        let s = ws("0xff");
        let (val, consumed, _) = wcstol_impl(&s, 16);
        assert_eq!(val, 255);
        assert_eq!(consumed, 4);
    }

    #[test]
    fn wcstol_invalid_base_returns_status() {
        let s = ws("42");
        let (_, _, status) = wcstol_impl(&s, 1);
        assert_eq!(status, ConversionStatus::InvalidBase);
        let (_, _, status) = wcstol_impl(&s, 37);
        assert_eq!(status, ConversionStatus::InvalidBase);
    }

    #[test]
    fn wcstol_empty_returns_zero() {
        let s = ws("");
        let (val, consumed, status) = wcstol_impl(&s, 10);
        assert_eq!(val, 0);
        assert_eq!(consumed, 0);
        assert_eq!(status, ConversionStatus::Success);
    }

    #[test]
    fn wcstol_sign_only_returns_zero() {
        for sign in ["+", "-"] {
            let s = ws(sign);
            let (val, consumed, status) = wcstol_impl(&s, 10);
            assert_eq!(val, 0);
            assert_eq!(consumed, 0);
            assert_eq!(status, ConversionStatus::Success);
        }
    }

    #[test]
    fn wcstol_stops_at_non_digit() {
        let s = ws("123abc");
        let (val, consumed, _) = wcstol_impl(&s, 10);
        assert_eq!(val, 123);
        assert_eq!(consumed, 3);
    }

    #[test]
    fn wcstol_stops_at_digit_above_base() {
        let s = ws("129"); // base 8 stops at '9'
        let (val, consumed, _) = wcstol_impl(&s, 8);
        assert_eq!(val, 0o12);
        assert_eq!(consumed, 2);
    }

    // ---- wcstoul_impl ----

    #[test]
    fn wcstoul_basic_decimal() {
        let s = ws("42");
        let (val, _, status) = wcstoul_impl(&s, 10);
        assert_eq!(val, 42);
        assert_eq!(status, ConversionStatus::Success);
    }

    #[test]
    fn wcstoul_max_round_trip() {
        let s = ws("18446744073709551615");
        let (val, _, status) = wcstoul_impl(&s, 10);
        assert_eq!(val, u64::MAX);
        assert_eq!(status, ConversionStatus::Success);
    }

    #[test]
    fn wcstoul_overflow_clamps_to_max() {
        let s = ws("18446744073709551616"); // u64::MAX + 1
        let (val, _, status) = wcstoul_impl(&s, 10);
        assert_eq!(val, u64::MAX);
        assert_eq!(status, ConversionStatus::Overflow);
    }

    #[test]
    fn wcstoul_negative_wraps_via_twos_complement() {
        // Matches glibc: wcstoul("-1", *, 10) == ULONG_MAX.
        let s = ws("-1");
        let (val, _, status) = wcstoul_impl(&s, 10);
        assert_eq!(val, u64::MAX);
        assert_eq!(status, ConversionStatus::Success);
    }

    #[test]
    fn wcstoul_auto_base_hex() {
        let s = ws("0xdeadbeef");
        let (val, _, _) = wcstoul_impl(&s, 0);
        assert_eq!(val, 0xdead_beef);
    }

    #[test]
    fn wcstoul_invalid_base_returns_status() {
        let s = ws("42");
        let (_, _, status) = wcstoul_impl(&s, 1);
        assert_eq!(status, ConversionStatus::InvalidBase);
    }

    // ---- parity with byte-slice strtol_impl/strtoul_impl ----

    #[test]
    fn wcstol_matches_strtol_on_ascii_decimal() {
        for input in [
            "0",
            "1",
            "42",
            "-1",
            "-42",
            "+5",
            " 17 trailing",
            "999999999",
            "9223372036854775807",
            "-9223372036854775808",
        ] {
            let bytes = input.as_bytes();
            let wide = ws(input);
            let (b_val, b_consumed, b_status) = strtol_impl(bytes, 10);
            let (w_val, w_consumed, w_status) = wcstol_impl(&wide, 10);
            assert_eq!(
                (w_val, w_consumed, w_status),
                (b_val, b_consumed, b_status),
                "input={input:?}"
            );
        }
    }

    #[test]
    fn wcstoul_matches_strtoul_on_ascii_decimal() {
        for input in [
            "0",
            "1",
            "42",
            "-1",
            "999999999",
            "18446744073709551615",
            "18446744073709551616",
        ] {
            let bytes = input.as_bytes();
            let wide = ws(input);
            let (b_val, b_consumed, b_status) = strtoul_impl(bytes, 10);
            let (w_val, w_consumed, w_status) = wcstoul_impl(&wide, 10);
            assert_eq!(
                (w_val, w_consumed, w_status),
                (b_val, b_consumed, b_status),
                "input={input:?}"
            );
        }
    }

    #[test]
    fn wcstol_matches_strtol_on_each_base_form() {
        let cases: &[(&str, i32)] = &[
            ("0xff", 0),
            ("0xff", 16),
            ("010", 0),
            ("10", 0),
            ("z", 36),
            ("ZZ", 36),
            ("FF", 16),
        ];
        for (input, base) in cases {
            let (b_val, b_consumed, b_status) = strtol_impl(input.as_bytes(), *base);
            let wide = ws(input);
            let (w_val, w_consumed, w_status) = wcstol_impl(&wide, *base);
            assert_eq!(
                (w_val, w_consumed, w_status),
                (b_val, b_consumed, b_status),
                "input={input:?} base={base}"
            );
        }
    }

    #[test]
    fn strtoul_negative_one_wraps_to_max_without_overflow() {
        // POSIX: strtoul("-1") should return ULONG_MAX via 2's complement
        // wrapping, WITHOUT setting ERANGE. The negative sign is valid and
        // the magnitude (1) is within range, so the result is u64::MAX.
        let (val, consumed, status) = strtoul_impl(b"-1", 10);
        assert_eq!(val, u64::MAX);
        assert_eq!(consumed, 2);
        assert_eq!(status, ConversionStatus::Success);
    }

    #[test]
    fn strtoul_negative_value_wraps_correctly() {
        // strtoul("-123") should return (u64::MAX - 122) = wrapping_neg(123)
        let (val, consumed, status) = strtoul_impl(b"-123", 10);
        assert_eq!(val, 123u64.wrapping_neg());
        assert_eq!(consumed, 4);
        assert_eq!(status, ConversionStatus::Success);
    }

    #[test]
    fn strtol_invalid_base_returns_zero() {
        // Base 1 and base 37 are invalid
        let (val, consumed, status) = strtol_impl(b"123", 1);
        assert_eq!(val, 0);
        assert_eq!(consumed, 0);
        assert_eq!(status, ConversionStatus::InvalidBase);

        let (val, consumed, status) = strtol_impl(b"123", 37);
        assert_eq!(val, 0);
        assert_eq!(consumed, 0);
        assert_eq!(status, ConversionStatus::InvalidBase);
    }

    #[test]
    fn strtol_whitespace_only_returns_zero() {
        // Just whitespace should return 0 with consumed=0
        let (val, consumed, _) = strtol_impl(b"   ", 10);
        assert_eq!(val, 0);
        assert_eq!(consumed, 0);
    }

    #[test]
    fn strtol_double_sign_returns_zero_no_consumption() {
        // glibc: "++42" returns 0 with consumed=0 (no conversion performed)
        // Only a single sign is allowed before digits
        let (val, consumed, status) = strtol_impl(b"++42", 10);
        assert_eq!(val, 0);
        assert_eq!(consumed, 0);
        assert_eq!(status, ConversionStatus::Success);

        let (val, consumed, _) = strtol_impl(b"+-42", 10);
        assert_eq!(val, 0);
        assert_eq!(consumed, 0);

        let (val, consumed, _) = strtol_impl(b"-+42", 10);
        assert_eq!(val, 0);
        assert_eq!(consumed, 0);

        let (val, consumed, _) = strtol_impl(b"--42", 10);
        assert_eq!(val, 0);
        assert_eq!(consumed, 0);
    }

    #[test]
    fn strtol_base10_stops_at_hex_prefix() {
        // glibc: strtol("0x10", base=10) returns 0, endp points to "x10"
        let (val, consumed, _) = strtol_impl(b"0x10", 10);
        assert_eq!(val, 0);
        assert_eq!(consumed, 1); // consumed only the '0'
    }

    #[test]
    fn strtol_base36_high_digits() {
        // glibc: "zz" in base 36 = 35*36 + 35 = 1295
        let (val, consumed, _) = strtol_impl(b"zz", 36);
        assert_eq!(val, 1295);
        assert_eq!(consumed, 2);

        // "ZZ" should be the same (case insensitive)
        let (val, consumed, _) = strtol_impl(b"ZZ", 36);
        assert_eq!(val, 1295);
        assert_eq!(consumed, 2);
    }

    // ===== glibc parity tests =====
    // Verified against glibc via scripts/c_probes/probe_strtox_edge.c

    #[test]
    fn glibc_strtoul_negative_wraps() {
        // strtoul("-1", 10) = ULONG_MAX (wraps via two's complement)
        let (val, consumed, _) = strtoul_impl(b"-1", 10);
        assert_eq!(val, u64::MAX);
        assert_eq!(consumed, 2);

        // strtoul("-2", 10) = ULONG_MAX - 1
        let (val, consumed, _) = strtoul_impl(b"-2", 10);
        assert_eq!(val, u64::MAX - 1);
        assert_eq!(consumed, 2);
    }

    #[test]
    fn glibc_strtol_binary_prefix_0b() {
        // strtol("0b1010", 0) = 10 (C23 binary prefix)
        let (val, consumed, _) = strtol_impl(b"0b1010", 0);
        assert_eq!(val, 10);
        assert_eq!(consumed, 6);

        // Also works with uppercase
        let (val, consumed, _) = strtol_impl(b"0B1111", 0);
        assert_eq!(val, 15);
        assert_eq!(consumed, 6);
    }

    #[test]
    fn glibc_strtol_overflow_returns_max() {
        // strtol(huge positive) returns LONG_MAX with Overflow status
        let (val, consumed, status) = strtol_impl(b"99999999999999999999", 10);
        assert_eq!(val, i64::MAX);
        assert!(consumed > 0);
        assert_eq!(status, ConversionStatus::Overflow);
    }

    #[test]
    fn glibc_strtol_underflow_returns_min() {
        // strtol(huge negative) returns LONG_MIN with Underflow status
        let (val, consumed, status) = strtol_impl(b"-99999999999999999999", 10);
        assert_eq!(val, i64::MIN);
        assert!(consumed > 0);
        assert_eq!(status, ConversionStatus::Underflow);
    }

    #[test]
    fn glibc_strtol_only_whitespace_no_consumption() {
        // strtol("   ", 10) returns 0 with endptr pointing to start
        let (val, consumed, _) = strtol_impl(b"   ", 10);
        assert_eq!(val, 0);
        assert_eq!(consumed, 0);
    }

    #[test]
    fn glibc_strtol_empty_no_consumption() {
        // strtol("", 10) returns 0 with endptr == nptr
        let (val, consumed, _) = strtol_impl(b"", 10);
        assert_eq!(val, 0);
        assert_eq!(consumed, 0);
    }

    #[test]
    fn glibc_strtol_no_digits_no_consumption() {
        // strtol("abc", 10) returns 0 with endptr pointing to "abc"
        let (val, consumed, _) = strtol_impl(b"abc", 10);
        assert_eq!(val, 0);
        assert_eq!(consumed, 0);
    }

    #[test]
    fn glibc_strtod_hex_float() {
        // strtod("0x1.8p1") = 3.0 (1.5 * 2^1)
        let (val, consumed) = strtod(b"0x1.8p1\0");
        assert!((val - 3.0).abs() < 1e-10);
        assert_eq!(consumed, 7);

        // strtod("0xABCp-4") = 2748 / 16 = 171.75
        let (val, consumed) = strtod(b"0xABCp-4\0");
        assert!((val - 171.75).abs() < 1e-10);
        assert_eq!(consumed, 8);
    }

    #[test]
    fn glibc_strtod_overflow_returns_inf() {
        // strtod("1e309") returns inf
        let (val, _consumed) = strtod(b"1e309\0");
        assert!(val.is_infinite() && val > 0.0);
    }

    #[test]
    fn glibc_strtod_underflow_returns_zero() {
        // strtod("1e-400") returns 0.0 (subnormal underflow)
        let (val, _consumed) = strtod(b"1e-400\0");
        assert_eq!(val, 0.0);
    }

    #[test]
    fn glibc_strtod_partial_parse() {
        // strtod("3.125abc") = 3.125, endptr points to "abc"
        let (val, consumed) = strtod(b"3.125abc\0");
        assert!((val - 3.125).abs() < 1e-10);
        assert_eq!(consumed, 5);
    }
}
