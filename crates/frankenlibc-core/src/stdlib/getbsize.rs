//! BSD libutil `getbsize(headerlenp, blocksizep)` byte-level core.
//!
//! The C ABI shim in `frankenlibc-abi::stdlib_abi` reads the
//! `BLOCKSIZE` environment variable, hands the bytes to
//! [`resolve_preference`], and renders the matching header string via
//! [`format_preference_header`] into a process-static buffer for the
//! static-pointer return contract.

/// Lower bound on the resolved block size (BSD canonical default and
/// floor — values below this are clamped up).
pub const MIN_BLOCKSIZE: u64 = 512;

/// Upper bound on the resolved block size: 1 GiB. BSD getbsize accepts
/// values in the inclusive 512-byte..1-GiB range; callers above the
/// upper bound are rounded down to this value.
pub const MAX_BLOCKSIZE: u64 = 1 << 30;

/// Header suffix selected by the BLOCKSIZE spelling.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum HeaderUnit {
    None,
    Kilo,
    Mega,
    Giga,
}

impl HeaderUnit {
    #[inline]
    fn suffix(self) -> &'static [u8] {
        match self {
            Self::None => b"",
            Self::Kilo => b"K",
            Self::Mega => b"M",
            Self::Giga => b"G",
        }
    }
}

/// Fully resolved getbsize preference. `blocksize` is the byte count
/// stored through `blocksizep`; `header_value` and `header_unit` preserve
/// the display spelling used to render the returned header string.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct BlocksizePreference {
    pub blocksize: u64,
    pub header_value: u64,
    pub header_unit: HeaderUnit,
}

impl BlocksizePreference {
    #[inline]
    pub const fn default_512() -> Self {
        Self {
            blocksize: MIN_BLOCKSIZE,
            header_value: MIN_BLOCKSIZE,
            header_unit: HeaderUnit::None,
        }
    }
}

/// Warning side effects required by BSD `getbsize` for non-canonical
/// `BLOCKSIZE` inputs. The ABI layer owns emitting these through
/// `warnx(3)` so pure core parsing stays side-effect free.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum BlocksizeDiagnostic {
    None,
    Minimum,
    Maximum,
    Malformed,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct BlocksizeResolution {
    pub preference: BlocksizePreference,
    pub diagnostic: BlocksizeDiagnostic,
}

/// Parse a `BLOCKSIZE`-style env-var value (without the leading `=`)
/// into a clamped block size in bytes. Returns `None` to signal that
/// the caller should fall back to [`MIN_BLOCKSIZE`].
///
/// Accepted forms: a decimal number, optionally followed by one of
/// `k`/`K`/`m`/`M`/`g`/`G`. A bare one-character suffix is interpreted
/// the same way BSD's `strtol`-based parser treats it: as an implicit
/// `1K`, `1M`, or `1G`. The numeric prefix is multiplied by 1024^k
/// (k=1 for K, 2 for M, 3 for G). Trailing garbage after the suffix
/// triggers the fallback. The result is clamped to
/// `[MIN_BLOCKSIZE, MAX_BLOCKSIZE]`.
pub fn resolve_blocksize(input: &[u8]) -> Option<u64> {
    resolve_preference(input).map(|preference| preference.blocksize)
}

/// Parse `BLOCKSIZE` while preserving the header spelling semantics.
pub fn resolve_preference(input: &[u8]) -> Option<BlocksizePreference> {
    let parsed = resolve_preference_internal(input);
    if parsed.valid {
        Some(parsed.resolution.preference)
    } else {
        None
    }
}

/// Parse `BLOCKSIZE` and report the BSD warning class that should be emitted.
///
/// This always returns a concrete preference: malformed and empty values map
/// to the default 512-byte preference, while `diagnostic` tells the ABI layer
/// whether BSD would warn about the original spelling.
pub fn resolve_preference_with_diagnostic(input: &[u8]) -> BlocksizeResolution {
    resolve_preference_internal(input).resolution
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct PreferenceParse {
    resolution: BlocksizeResolution,
    valid: bool,
}

fn parsed_default(valid: bool, diagnostic: BlocksizeDiagnostic) -> PreferenceParse {
    PreferenceParse {
        resolution: BlocksizeResolution {
            preference: BlocksizePreference::default_512(),
            diagnostic,
        },
        valid,
    }
}

fn resolve_preference_internal(input: &[u8]) -> PreferenceParse {
    if input.is_empty() {
        return parsed_default(false, BlocksizeDiagnostic::None);
    }

    let mut i = 0usize;
    while i < input.len() && input[i].is_ascii_whitespace() {
        i += 1;
    }

    let negative = if i < input.len() && input[i] == b'+' {
        i += 1;
        false
    } else if i < input.len() && input[i] == b'-' {
        i += 1;
        true
    } else {
        false
    };

    // Parse the leading decimal digits.
    let mut value: u64 = 0;
    let digit_start = i;
    while i < input.len() {
        let b = input[i];
        if !b.is_ascii_digit() {
            break;
        }
        value = value.saturating_mul(10).saturating_add((b - b'0') as u64);
        i += 1;
    }
    let converted = i != digit_start;
    if !converted {
        // Match strtol(3): when no conversion happens, endptr remains at
        // the original input. This accepts a single bare K/M/G suffix as
        // implicit one-unit spelling but rejects leading-space or signed
        // unit-only strings as malformed.
        i = 0;
    }
    if converted && negative && value != 0 {
        return parsed_default(true, BlocksizeDiagnostic::Minimum);
    }
    if value == 0 {
        value = 1;
    }

    // Optional one-char unit suffix.
    let (multiplier, unit): (u64, HeaderUnit) = if i == input.len() {
        (1, HeaderUnit::None)
    } else if i + 1 == input.len() {
        match input[i] {
            b'k' | b'K' => (1024, HeaderUnit::Kilo),
            b'm' | b'M' => (1024 * 1024, HeaderUnit::Mega),
            b'g' | b'G' => (1024 * 1024 * 1024, HeaderUnit::Giga),
            _ => return parsed_default(false, BlocksizeDiagnostic::Malformed),
        }
    } else {
        // Anything past one suffix char is garbage.
        return parsed_default(false, BlocksizeDiagnostic::Malformed);
    };

    let max_value = MAX_BLOCKSIZE / multiplier;
    let mut diagnostic = BlocksizeDiagnostic::None;
    if value > max_value {
        value = max_value;
        diagnostic = BlocksizeDiagnostic::Maximum;
    }
    let blocksize = value.saturating_mul(multiplier);
    if blocksize < MIN_BLOCKSIZE {
        return parsed_default(true, BlocksizeDiagnostic::Minimum);
    }

    PreferenceParse {
        resolution: BlocksizeResolution {
            preference: BlocksizePreference {
                blocksize,
                header_value: value,
                header_unit: unit,
            },
            diagnostic,
        },
        valid: true,
    }
}

/// Clamp `value` into `[MIN_BLOCKSIZE, MAX_BLOCKSIZE]`.
#[inline]
pub fn clamp(value: u64) -> u64 {
    value.clamp(MIN_BLOCKSIZE, MAX_BLOCKSIZE)
}

/// Render the BSD getbsize header bytes for `blocksize`.
///
/// Returns a `(buffer, length)` pair: the buffer is sized to the
/// longest possible header ("1024G-blocks" plus a NUL slot). Callers
/// (the abi shim) copy the populated prefix into the static return
/// area.
///
/// This helper renders a raw byte count. To preserve `BLOCKSIZE`
/// suffix spelling, render [`BlocksizePreference`] with
/// [`format_preference_header`] instead.
pub fn format_header(blocksize: u64) -> ([u8; 32], usize) {
    format_header_parts(blocksize, HeaderUnit::None)
}

/// Render the BSD getbsize header bytes for a resolved preference.
pub fn format_preference_header(preference: BlocksizePreference) -> ([u8; 32], usize) {
    format_header_parts(preference.header_value, preference.header_unit)
}

fn format_header_parts(n: u64, unit: HeaderUnit) -> ([u8; 32], usize) {
    let mut buf = [0u8; 32];

    // Render `n` as decimal ASCII into a small scratch buffer. Keep this
    // independent of getbsize's normal clamp so the public formatting helper
    // cannot panic if a test or future caller passes an arbitrary u64.
    let mut digits = [0u8; 20];
    let mut d_len = 0usize;
    let mut v = n;
    if v == 0 {
        digits[0] = b'0';
        d_len = 1;
    } else {
        while v > 0 {
            digits[d_len] = b'0' + (v % 10) as u8;
            d_len += 1;
            v /= 10;
        }
    }
    // Reverse into `buf`.
    let mut o = 0usize;
    while d_len > 0 {
        d_len -= 1;
        buf[o] = digits[d_len];
        o += 1;
    }

    // Suffix.
    for &b in unit.suffix() {
        buf[o] = b;
        o += 1;
    }
    let tail = b"-blocks";
    for &b in tail {
        buf[o] = b;
        o += 1;
    }

    (buf, o)
}

#[cfg(test)]
mod tests {
    use super::*;

    // ---- resolve_blocksize ----

    #[test]
    fn resolve_empty_returns_none() {
        assert_eq!(resolve_blocksize(b""), None);
    }

    #[test]
    fn resolve_plain_512_matches_default() {
        assert_eq!(resolve_blocksize(b"512"), Some(512));
    }

    #[test]
    fn resolve_below_min_clamps_to_512() {
        assert_eq!(resolve_blocksize(b"100"), Some(MIN_BLOCKSIZE));
        assert_eq!(resolve_blocksize(b"0"), Some(MIN_BLOCKSIZE));
        assert_eq!(resolve_blocksize(b"1"), Some(MIN_BLOCKSIZE));
        assert_eq!(
            resolve_preference(b"-1"),
            Some(BlocksizePreference::default_512())
        );
    }

    #[test]
    fn resolve_kilo_suffix() {
        assert_eq!(resolve_blocksize(b"1k"), Some(1024));
        assert_eq!(resolve_blocksize(b"1K"), Some(1024));
        assert_eq!(
            resolve_preference(b"+1K"),
            Some(BlocksizePreference {
                blocksize: 1024,
                header_value: 1,
                header_unit: HeaderUnit::Kilo,
            })
        );
        assert_eq!(resolve_blocksize(b"4k"), Some(4096));
    }

    #[test]
    fn resolve_mega_suffix() {
        assert_eq!(resolve_blocksize(b"1m"), Some(1024 * 1024));
        assert_eq!(resolve_blocksize(b"1M"), Some(1024 * 1024));
        assert_eq!(resolve_blocksize(b"4M"), Some(4 * 1024 * 1024));
    }

    #[test]
    fn resolve_giga_suffix_at_max_clamps() {
        // 2G overflows the MAX (1G), clamps down.
        assert_eq!(resolve_blocksize(b"2G"), Some(MAX_BLOCKSIZE));
        // Exactly 1G is the max.
        assert_eq!(resolve_blocksize(b"1G"), Some(MAX_BLOCKSIZE));
    }

    #[test]
    fn resolve_unknown_suffix_returns_none() {
        assert_eq!(resolve_blocksize(b"512x"), None);
        assert_eq!(resolve_blocksize(b"1T"), None); // T not supported
    }

    #[test]
    fn resolve_bare_unit_suffix_uses_implicit_one() {
        assert_eq!(resolve_blocksize(b"k"), Some(1024));
        assert_eq!(
            resolve_preference(b"K"),
            Some(BlocksizePreference {
                blocksize: 1024,
                header_value: 1,
                header_unit: HeaderUnit::Kilo,
            })
        );
        assert_eq!(resolve_blocksize(b"M"), Some(1024 * 1024));
        assert_eq!(resolve_blocksize(b"G"), Some(MAX_BLOCKSIZE));
    }

    #[test]
    fn resolve_no_conversion_with_extra_bytes_returns_none() {
        assert_eq!(resolve_blocksize(b"K512"), None);
        assert_eq!(resolve_blocksize(b" K"), None);
        assert_eq!(resolve_blocksize(b"+K"), None);
        assert_eq!(resolve_blocksize(b" "), None);
        assert_eq!(
            resolve_preference_with_diagnostic(b" ").diagnostic,
            BlocksizeDiagnostic::Malformed
        );
    }

    #[test]
    fn resolve_allows_strtol_style_leading_space() {
        assert_eq!(
            resolve_preference(b" 512"),
            Some(BlocksizePreference {
                blocksize: 512,
                header_value: 512,
                header_unit: HeaderUnit::None,
            })
        );
        assert_eq!(
            resolve_preference(b"\t2M"),
            Some(BlocksizePreference {
                blocksize: 2 * 1024 * 1024,
                header_value: 2,
                header_unit: HeaderUnit::Mega,
            })
        );
    }

    #[test]
    fn resolve_trailing_garbage_returns_none() {
        assert_eq!(resolve_blocksize(b"512kb"), None);
        assert_eq!(resolve_blocksize(b"1024 "), None);
        assert_eq!(
            resolve_preference_with_diagnostic(b"512kb").diagnostic,
            BlocksizeDiagnostic::Malformed
        );
    }

    #[test]
    fn resolve_overflow_returns_none() {
        // u64::MAX-ish input clamps like strtol+range handling.
        let big = b"99999999999999999999";
        assert_eq!(resolve_blocksize(big), Some(MAX_BLOCKSIZE));
        assert_eq!(
            resolve_preference_with_diagnostic(big).diagnostic,
            BlocksizeDiagnostic::Maximum
        );
        // Overflow on the suffix multiply clamps to the max suffix count.
        let big_k = b"99999999999999999G";
        assert_eq!(
            resolve_preference(big_k),
            Some(BlocksizePreference {
                blocksize: MAX_BLOCKSIZE,
                header_value: 1,
                header_unit: HeaderUnit::Giga,
            })
        );
    }

    #[test]
    fn resolve_diagnostics_match_bsd_warning_classes() {
        assert_eq!(
            resolve_preference_with_diagnostic(b"").diagnostic,
            BlocksizeDiagnostic::None
        );
        assert_eq!(
            resolve_preference_with_diagnostic(b"K").diagnostic,
            BlocksizeDiagnostic::None
        );
        assert_eq!(
            resolve_preference_with_diagnostic(b"bad").diagnostic,
            BlocksizeDiagnostic::Malformed
        );
        assert_eq!(
            resolve_preference_with_diagnostic(b"-4K").diagnostic,
            BlocksizeDiagnostic::Minimum
        );
        assert_eq!(
            resolve_preference_with_diagnostic(b"100").diagnostic,
            BlocksizeDiagnostic::Minimum
        );
        assert_eq!(
            resolve_preference_with_diagnostic(b"2G").diagnostic,
            BlocksizeDiagnostic::Maximum
        );
        assert_eq!(
            resolve_preference_with_diagnostic(b"0K").diagnostic,
            BlocksizeDiagnostic::None
        );
    }

    #[test]
    fn resolve_negative_zero_suffix_uses_implicit_one() {
        assert_eq!(
            resolve_preference(b"-0K"),
            Some(BlocksizePreference {
                blocksize: 1024,
                header_value: 1,
                header_unit: HeaderUnit::Kilo,
            })
        );
        assert_eq!(
            resolve_preference_with_diagnostic(b"-0K").diagnostic,
            BlocksizeDiagnostic::None
        );
    }

    #[test]
    fn resolve_clamps_huge_to_max() {
        // 1024*1024*1024 - 1 is below max, max is exactly 2^30.
        assert_eq!(resolve_blocksize(b"1073741824"), Some(MAX_BLOCKSIZE));
        assert_eq!(resolve_blocksize(b"1073741823"), Some(1073741823));
    }

    // ---- format_header ----

    #[test]
    fn format_512_has_no_unit() {
        let (buf, n) = format_header(512);
        assert_eq!(&buf[..n], b"512-blocks");
    }

    #[test]
    fn format_1024_keeps_raw_byte_count() {
        let (buf, n) = format_header(1024);
        assert_eq!(&buf[..n], b"1024-blocks");
    }

    #[test]
    fn format_preference_1024_with_kilo_suffix_uses_kilo() {
        let (buf, n) = format_preference_header(BlocksizePreference {
            blocksize: 1024,
            header_value: 1,
            header_unit: HeaderUnit::Kilo,
        });
        assert_eq!(&buf[..n], b"1K-blocks");
    }

    #[test]
    fn format_4k() {
        let (buf, n) = format_preference_header(BlocksizePreference {
            blocksize: 4 * 1024,
            header_value: 4,
            header_unit: HeaderUnit::Kilo,
        });
        assert_eq!(&buf[..n], b"4K-blocks");
    }

    #[test]
    fn format_1m() {
        let (buf, n) = format_preference_header(BlocksizePreference {
            blocksize: 1024 * 1024,
            header_value: 1,
            header_unit: HeaderUnit::Mega,
        });
        assert_eq!(&buf[..n], b"1M-blocks");
    }

    #[test]
    fn format_512m() {
        let (buf, n) = format_preference_header(BlocksizePreference {
            blocksize: 512 * 1024 * 1024,
            header_value: 512,
            header_unit: HeaderUnit::Mega,
        });
        assert_eq!(&buf[..n], b"512M-blocks");
    }

    #[test]
    fn format_1g_at_max() {
        let (buf, n) = format_preference_header(BlocksizePreference {
            blocksize: 1024 * 1024 * 1024,
            header_value: 1,
            header_unit: HeaderUnit::Giga,
        });
        assert_eq!(&buf[..n], b"1G-blocks");
    }

    #[test]
    fn format_below_kilo_keeps_byte_count() {
        // BSD reality: blocks under 1024 are reported as raw bytes.
        let (buf, n) = format_header(800);
        assert_eq!(&buf[..n], b"800-blocks");
    }

    #[test]
    fn format_non_power_of_two_in_kilos() {
        let (buf, n) = format_header(1500);
        assert_eq!(&buf[..n], b"1500-blocks");
    }

    #[test]
    fn format_zero_blocksize() {
        // Defensive case: format_header should not panic on 0.
        let (buf, n) = format_header(0);
        assert_eq!(&buf[..n], b"0-blocks");
    }

    #[test]
    fn format_u64_max_does_not_panic() {
        let (buf, n) = format_header(u64::MAX);
        assert_eq!(&buf[..n], b"18446744073709551615-blocks");
    }

    // ---- end-to-end via resolve_blocksize + format_header ----

    #[test]
    fn end_to_end_default_512() {
        // No env var → caller falls back to MIN_BLOCKSIZE.
        let bs = resolve_blocksize(b"").unwrap_or(MIN_BLOCKSIZE);
        assert_eq!(bs, 512);
        let (buf, n) = format_header(bs);
        assert_eq!(&buf[..n], b"512-blocks");
    }

    #[test]
    fn end_to_end_4k_env() {
        let preference = resolve_preference(b"4k").unwrap_or(BlocksizePreference::default_512());
        assert_eq!(preference.blocksize, 4096);
        let (buf, n) = format_preference_header(preference);
        assert_eq!(&buf[..n], b"4K-blocks");
    }

    #[test]
    fn end_to_end_bare_1024_keeps_byte_header() {
        let preference = resolve_preference(b"1024").unwrap_or(BlocksizePreference::default_512());
        assert_eq!(preference.blocksize, 1024);
        let (buf, n) = format_preference_header(preference);
        assert_eq!(&buf[..n], b"1024-blocks");
    }

    #[test]
    fn end_to_end_clamps_below_min() {
        let bs = resolve_blocksize(b"100").unwrap_or(MIN_BLOCKSIZE);
        let (buf, n) = format_header(bs);
        assert_eq!(&buf[..n], b"512-blocks");
    }
}
