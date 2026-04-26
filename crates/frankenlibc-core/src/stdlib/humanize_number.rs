//! NetBSD/FreeBSD libutil `humanize_number` — render a byte count as
//! a human-readable string ("1.5K", "32 MiB", "12 PB").
//!
//! Pure-safe Rust port. The C ABI shim in
//! `frankenlibc-abi::stdlib_abi` handles raw-pointer plumbing and
//! the C-int `scale` argument's two sentinel values
//! ([`HN_AUTOSCALE`] / [`HN_GETSCALE`]).
//!
//! ## Algorithm
//!
//! With the divisor (1024 by default, or 1000 with
//! [`HumanizeFlags::DIVISOR_1000`]) and a six-step prefix table
//! (`""`, `K`, `M`, `G`, `T`, `P`, `E`):
//!
//! 1. If `scale == HN_GETSCALE`, return the auto-scale level (the
//!    largest power of `divisor` that still leaves the integer part
//!    below `divisor`) — without rendering.
//! 2. If `scale == HN_AUTOSCALE`, compute the same auto-scale level
//!    and continue to render.
//! 3. Render the value at the chosen scale. With
//!    [`HumanizeFlags::DECIMAL`] AND the integer part below 10,
//!    include a single fractional digit (truncated toward zero).
//! 4. Append the prefix (or the IEC variant `Ki`/`Mi`/… when
//!    [`HumanizeFlags::IEC_PREFIXES`] is set) plus the trailing
//!    suffix (typically `"B"`).
//!
//! Returns the number of bytes written (excluding NUL) on success,
//! or [`HumanizeError`] on failure.

/// Maximum recognized scale step (`E` / `Ei` — exa / exbi).
pub const HN_MAX_SCALE: i32 = 6;

/// Sentinel `scale` value: pick the largest scale automatically.
pub const HN_AUTOSCALE: i32 = -1;

/// Sentinel `scale` value: return the auto-scale level instead of
/// rendering. Selected as `-2` here for unambiguous distinction;
/// the C ABI shim maps NetBSD's overloaded `0x10` constant onto
/// this internal value.
pub const HN_GETSCALE: i32 = -2;

/// Flag set passed to [`format`]. Bit values match libutil's
/// `<libutil.h>` HN_* constants so the C ABI shim can pass the
/// caller's `int flags` through unchanged.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct HumanizeFlags(pub u32);

impl HumanizeFlags {
    /// Render one decimal digit when the integer part is < 10.
    pub const DECIMAL: Self = Self(0x01);
    /// Drop the space between the value and the prefix.
    pub const NOSPACE: Self = Self(0x02);
    /// Always append a trailing `B`.
    pub const B: Self = Self(0x04);
    /// Use 1000 instead of 1024 as the scale divisor.
    pub const DIVISOR_1000: Self = Self(0x08);
    /// Use IEC binary prefixes (`Ki`, `Mi`, `Gi`, …) instead of
    /// the bare SI letters.
    pub const IEC_PREFIXES: Self = Self(0x10);

    /// Empty flag set.
    pub const fn empty() -> Self {
        Self(0)
    }

    /// True when every bit of `other` is also set in `self`.
    #[inline]
    pub const fn contains(self, other: Self) -> bool {
        (self.0 & other.0) == other.0
    }
}

impl core::ops::BitOr for HumanizeFlags {
    type Output = Self;
    fn bitor(self, rhs: Self) -> Self {
        Self(self.0 | rhs.0)
    }
}

impl core::ops::BitOrAssign for HumanizeFlags {
    fn bitor_assign(&mut self, rhs: Self) {
        self.0 |= rhs.0;
    }
}

/// Reasons [`format`] rejects an input.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum HumanizeError {
    /// Caller-supplied buffer is too small to hold the rendered
    /// string + the trailing NUL.
    BufferTooSmall,
    /// `scale` is out of range (`< HN_GETSCALE` or `> HN_MAX_SCALE`).
    InvalidScale,
}

const PREFIXES_SI: [&str; 7] = ["", "K", "M", "G", "T", "P", "E"];
const PREFIXES_IEC: [&str; 7] = ["", "Ki", "Mi", "Gi", "Ti", "Pi", "Ei"];

/// Render `bytes` into the provided buffer per the libutil
/// `humanize_number(3)` contract. On success returns the number of
/// bytes written (excluding the trailing NUL); on failure returns
/// the matching [`HumanizeError`].
///
/// `buf` is sized including the NUL slot — i.e. the caller passes
/// the same `buf.len()` they would pass as the C `len` argument.
pub fn format(
    buf: &mut [u8],
    bytes: i64,
    suffix: &[u8],
    scale: i32,
    flags: HumanizeFlags,
) -> Result<usize, HumanizeError> {
    if !(HN_GETSCALE..=HN_MAX_SCALE).contains(&scale) {
        return Err(HumanizeError::InvalidScale);
    }

    let divisor: u64 = if flags.contains(HumanizeFlags::DIVISOR_1000) {
        1000
    } else {
        1024
    };

    // Work on the absolute magnitude so the auto-scale loop doesn't
    // misbehave for negative values; remember the sign for emission.
    let negative = bytes < 0;
    let magnitude: u128 = if negative {
        (bytes as i128).unsigned_abs()
    } else {
        bytes as u128
    };

    // Determine the scale.
    let chosen_scale: usize = match scale {
        HN_AUTOSCALE | HN_GETSCALE => {
            let mut s = 0usize;
            // Step up while magnitude >= divisor^(s+1) — i.e. while
            // dividing one more time would still leave a non-zero
            // integer part.
            let mut next = divisor as u128;
            while magnitude >= next && s < HN_MAX_SCALE as usize {
                s += 1;
                next = next.saturating_mul(divisor as u128);
            }
            s
        }
        n => n as usize,
    };

    if scale == HN_GETSCALE {
        // Special return: the C int written into the implicit "auto-
        // scale outcome" channel. We pass it back through the same
        // success-length channel; the C ABI shim repackages it as
        // the numeric return value.
        return Ok(chosen_scale);
    }

    // Compute scaled integer + remainder for fractional rendering.
    let scale_pow = (divisor as u128).pow(chosen_scale as u32);
    let int_part = magnitude / scale_pow;
    let remainder = magnitude - int_part * scale_pow;

    // Decide whether to render with a decimal digit.
    let use_decimal = flags.contains(HumanizeFlags::DECIMAL) && chosen_scale > 0 && int_part < 10;

    // Render the numeric part into a small scratch buffer so we can
    // measure it before committing to the caller's buffer.
    let mut digits = [0u8; 32];
    let mut dlen = 0usize;
    if negative {
        digits[dlen] = b'-';
        dlen += 1;
    }
    // Integer digits (LSB-first, then reverse below). int_part fits
    // in u64 since it's bounded by divisor (1024 max for AUTOSCALE,
    // or up to magnitude itself for explicit scale=0).
    let mut tmp = [0u8; 24];
    let mut tlen = 0usize;
    let mut v = int_part as u64;
    if v == 0 {
        tmp[0] = b'0';
        tlen = 1;
    } else {
        while v > 0 {
            tmp[tlen] = b'0' + (v % 10) as u8;
            tlen += 1;
            v /= 10;
        }
    }
    // Reverse into digits.
    for i in 0..tlen {
        digits[dlen + i] = tmp[tlen - 1 - i];
    }
    dlen += tlen;

    if use_decimal {
        digits[dlen] = b'.';
        dlen += 1;
        // ⌊remainder * 10 / scale_pow⌋ — single fractional digit.
        let frac_digit = ((remainder * 10) / scale_pow) as u8;
        digits[dlen] = b'0' + frac_digit;
        dlen += 1;
    }

    // Optional space, prefix, B, suffix.
    let prefix = if flags.contains(HumanizeFlags::IEC_PREFIXES) {
        PREFIXES_IEC[chosen_scale]
    } else {
        PREFIXES_SI[chosen_scale]
    };

    let want_space = !flags.contains(HumanizeFlags::NOSPACE);
    let want_b = flags.contains(HumanizeFlags::B);

    // Total byte count needed (excluding NUL).
    let mut total = dlen + prefix.len() + suffix.len();
    if want_space {
        total += 1;
    }
    if want_b {
        total += 1;
    }

    if buf.len() < total + 1 {
        return Err(HumanizeError::BufferTooSmall);
    }

    let mut o = 0usize;
    buf[..dlen].copy_from_slice(&digits[..dlen]);
    o += dlen;
    if want_space {
        buf[o] = b' ';
        o += 1;
    }
    buf[o..o + prefix.len()].copy_from_slice(prefix.as_bytes());
    o += prefix.len();
    if want_b {
        buf[o] = b'B';
        o += 1;
    }
    buf[o..o + suffix.len()].copy_from_slice(suffix);
    o += suffix.len();
    buf[o] = 0;

    Ok(o)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn s(buf: &[u8], n: usize) -> &str {
        std::str::from_utf8(&buf[..n]).unwrap()
    }

    // ---- explicit scale ----

    #[test]
    fn scale_0_renders_raw_bytes() {
        let mut buf = [0u8; 32];
        let n = format(&mut buf, 512, b"B", 0, HumanizeFlags::empty()).unwrap();
        // Default: insert space between number and the empty SI prefix at scale 0.
        assert_eq!(s(&buf, n), "512 B");
    }

    #[test]
    fn scale_1_renders_kilo() {
        let mut buf = [0u8; 32];
        let n = format(&mut buf, 1024, b"", 1, HumanizeFlags::empty()).unwrap();
        assert_eq!(s(&buf, n), "1 K");
    }

    #[test]
    fn scale_2_renders_mega() {
        let mut buf = [0u8; 32];
        let n = format(&mut buf, 4 * 1024 * 1024, b"", 2, HumanizeFlags::empty()).unwrap();
        assert_eq!(s(&buf, n), "4 M");
    }

    // ---- auto-scale ----

    #[test]
    fn autoscale_picks_kilo_for_4096() {
        let mut buf = [0u8; 32];
        let n = format(&mut buf, 4096, b"", HN_AUTOSCALE, HumanizeFlags::empty()).unwrap();
        assert_eq!(s(&buf, n), "4 K");
    }

    #[test]
    fn autoscale_picks_mega_for_2m() {
        let mut buf = [0u8; 32];
        let n = format(
            &mut buf,
            2 * 1024 * 1024,
            b"",
            HN_AUTOSCALE,
            HumanizeFlags::empty(),
        )
        .unwrap();
        assert_eq!(s(&buf, n), "2 M");
    }

    #[test]
    fn autoscale_with_b_suffix_and_iec_prefixes() {
        let mut buf = [0u8; 32];
        let n = format(
            &mut buf,
            32 * 1024 * 1024,
            b"",
            HN_AUTOSCALE,
            HumanizeFlags::IEC_PREFIXES | HumanizeFlags::B,
        )
        .unwrap();
        assert_eq!(s(&buf, n), "32 MiB");
    }

    #[test]
    fn autoscale_picks_byte_for_zero() {
        let mut buf = [0u8; 32];
        let n = format(&mut buf, 0, b"", HN_AUTOSCALE, HumanizeFlags::empty()).unwrap();
        assert_eq!(s(&buf, n), "0 ");
    }

    #[test]
    fn autoscale_picks_byte_for_small_values() {
        let mut buf = [0u8; 32];
        let n = format(&mut buf, 999, b"B", HN_AUTOSCALE, HumanizeFlags::empty()).unwrap();
        assert_eq!(s(&buf, n), "999 B");
    }

    #[test]
    fn autoscale_with_decimal_renders_one_fraction() {
        let mut buf = [0u8; 32];
        // 1536 bytes = 1.5 KiB.
        let n = format(&mut buf, 1536, b"", HN_AUTOSCALE, HumanizeFlags::DECIMAL).unwrap();
        assert_eq!(s(&buf, n), "1.5 K");
    }

    #[test]
    fn autoscale_decimal_truncates_toward_zero() {
        // 1791 bytes = 1.749 KiB → DECIMAL truncates to "1.7 K".
        let mut buf = [0u8; 32];
        let n = format(&mut buf, 1791, b"", HN_AUTOSCALE, HumanizeFlags::DECIMAL).unwrap();
        assert_eq!(s(&buf, n), "1.7 K");
    }

    #[test]
    fn decimal_suppressed_when_int_part_double_digit() {
        // 16 KiB: int part is 16, so DECIMAL has no fractional room.
        let mut buf = [0u8; 32];
        let n = format(
            &mut buf,
            16 * 1024,
            b"",
            HN_AUTOSCALE,
            HumanizeFlags::DECIMAL,
        )
        .unwrap();
        assert_eq!(s(&buf, n), "16 K");
    }

    // ---- HN_NOSPACE ----

    #[test]
    fn nospace_drops_space() {
        let mut buf = [0u8; 32];
        let n = format(&mut buf, 4096, b"", HN_AUTOSCALE, HumanizeFlags::NOSPACE).unwrap();
        assert_eq!(s(&buf, n), "4K");
    }

    // ---- HN_B ----

    #[test]
    fn b_appends_byte_letter() {
        let mut buf = [0u8; 32];
        let n = format(
            &mut buf,
            4096,
            b"",
            HN_AUTOSCALE,
            HumanizeFlags::B | HumanizeFlags::NOSPACE,
        )
        .unwrap();
        assert_eq!(s(&buf, n), "4KB");
    }

    // ---- HN_DIVISOR_1000 ----

    #[test]
    fn divisor_1000_uses_si_decimal() {
        let mut buf = [0u8; 32];
        // 4 MB at base-1000 = 4_000_000 bytes.
        let n = format(
            &mut buf,
            4_000_000,
            b"",
            HN_AUTOSCALE,
            HumanizeFlags::DIVISOR_1000,
        )
        .unwrap();
        assert_eq!(s(&buf, n), "4 M");
    }

    // ---- negative ----

    #[test]
    fn negative_renders_with_minus() {
        let mut buf = [0u8; 32];
        let n = format(&mut buf, -2048, b"", HN_AUTOSCALE, HumanizeFlags::empty()).unwrap();
        assert_eq!(s(&buf, n), "-2 K");
    }

    #[test]
    fn negative_with_decimal() {
        let mut buf = [0u8; 32];
        let n = format(&mut buf, -1536, b"", HN_AUTOSCALE, HumanizeFlags::DECIMAL).unwrap();
        assert_eq!(s(&buf, n), "-1.5 K");
    }

    // ---- HN_GETSCALE ----

    #[test]
    fn getscale_returns_scale_without_writing() {
        let mut buf = [0u8; 8];
        buf.fill(0xab);
        let scale = format(
            &mut buf,
            32 * 1024 * 1024,
            b"",
            HN_GETSCALE,
            HumanizeFlags::empty(),
        )
        .unwrap();
        assert_eq!(scale, 2, "32 MiB → scale 2");
        // Buffer must be untouched.
        for &b in &buf {
            assert_eq!(b, 0xab);
        }
    }

    #[test]
    fn getscale_for_byte_count() {
        let mut buf = [0u8; 8];
        let scale = format(&mut buf, 100, b"", HN_GETSCALE, HumanizeFlags::empty()).unwrap();
        assert_eq!(scale, 0);
    }

    // ---- error cases ----

    #[test]
    fn buffer_too_small_returns_error() {
        let mut buf = [0u8; 3]; // can fit "4K\0" but not space variant
        let r = format(&mut buf, 4096, b"", HN_AUTOSCALE, HumanizeFlags::empty());
        assert_eq!(r, Err(HumanizeError::BufferTooSmall));
    }

    #[test]
    fn invalid_scale_returns_error() {
        let mut buf = [0u8; 32];
        let r = format(&mut buf, 0, b"", HN_MAX_SCALE + 1, HumanizeFlags::empty());
        assert_eq!(r, Err(HumanizeError::InvalidScale));
        let r2 = format(&mut buf, 0, b"", HN_GETSCALE - 1, HumanizeFlags::empty());
        assert_eq!(r2, Err(HumanizeError::InvalidScale));
    }

    #[test]
    fn output_is_nul_terminated() {
        let mut buf = [0xffu8; 16];
        let n = format(&mut buf, 4096, b"", HN_AUTOSCALE, HumanizeFlags::empty()).unwrap();
        assert_eq!(buf[n], 0);
    }

    // ---- exa-scale boundary ----

    #[test]
    fn autoscale_caps_at_exa() {
        let mut buf = [0u8; 32];
        // Largest representable i64 → still gets put in the E bucket.
        // i64::MAX = 9223372036854775807; i64::MAX / 1024^6 ==
        // 7 (since 8 * 1024^6 = 9223372036854775808 > i64::MAX).
        let n = format(
            &mut buf,
            i64::MAX,
            b"B",
            HN_AUTOSCALE,
            HumanizeFlags::empty(),
        )
        .unwrap();
        assert_eq!(s(&buf, n), "7 EB");
    }

    #[test]
    fn suffix_appended_after_prefix() {
        let mut buf = [0u8; 32];
        let n = format(
            &mut buf,
            4096,
            b"/s",
            HN_AUTOSCALE,
            HumanizeFlags::IEC_PREFIXES | HumanizeFlags::B,
        )
        .unwrap();
        assert_eq!(s(&buf, n), "4 KiB/s");
    }
}
