//! `<shadow.h>` line parser and serializer.
//!
//! `/etc/shadow` line shape:
//!   `name:passwd:lstchg:min:max:warn:inact:expire:flag`
//!
//! Per glibc's `putspent`, numeric fields with the sentinel value
//! `-1` are emitted as empty rather than the literal string `"-1"`.
//! The flag field (`reserved`, type `unsigned long` in struct spwd)
//! is also emitted as empty when its bit pattern is `~0` (`u64::MAX`,
//! the all-ones sentinel used by glibc).
//!
//! On the parser side, an empty numeric field decodes to `-1` (signed)
//! or `0` (flag) — the same convention every shadow consumer uses to
//! represent "field unset".

/// Parsed /etc/shadow entry.
///
/// All seven trailing numeric fields use the glibc convention:
/// `-1` for an unset signed field; the optional `flag` defaults to
/// `0` when the field is absent or unparseable.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ShadowEntry {
    pub name: Vec<u8>,
    pub passwd: Vec<u8>,
    pub lstchg: i64,
    pub min: i64,
    pub max: i64,
    pub warn: i64,
    pub inact: i64,
    pub expire: i64,
    pub flag: u64,
}

/// Parse a shadow numeric field per glibc convention.
///
/// Returns `-1` for an empty or non-numeric field — the canonical
/// "unset" sentinel that round-trips through [`format_shadow_line`].
pub fn parse_shadow_numeric(s: &[u8]) -> i64 {
    if s.is_empty() {
        return -1;
    }
    core::str::from_utf8(s)
        .ok()
        .and_then(|t| t.parse::<i64>().ok())
        .unwrap_or(-1)
}

fn parse_shadow_flag(s: &[u8]) -> u64 {
    if s.is_empty() {
        return u64::MAX;
    }
    core::str::from_utf8(s)
        .ok()
        .and_then(|t| t.parse::<u64>().ok())
        .unwrap_or(u64::MAX)
}

/// Parse a single line from /etc/shadow.
///
/// Returns `None` for blank lines, comment lines (first non-whitespace
/// byte is `#`), or lines with fewer than 8 colon-separated fields
/// (the `flag` field is optional). Trailing `\n` / `\r\n` is tolerated.
pub fn parse_shadow_line(line: &[u8]) -> Option<ShadowEntry> {
    let line = strip_trailing_eol(line);
    let trimmed = trim_leading_ws(line);
    if trimmed.is_empty() || trimmed.first() == Some(&b'#') {
        return None;
    }

    let parts: Vec<&[u8]> = line.split(|&b| b == b':').collect();
    if parts.len() < 8 {
        return None;
    }

    Some(ShadowEntry {
        name: parts[0].to_vec(),
        passwd: parts[1].to_vec(),
        lstchg: parse_shadow_numeric(parts[2]),
        min: parse_shadow_numeric(parts[3]),
        max: parse_shadow_numeric(parts[4]),
        warn: parse_shadow_numeric(parts[5]),
        inact: parse_shadow_numeric(parts[6]),
        expire: parse_shadow_numeric(parts[7]),
        flag: if parts.len() > 8 {
            parse_shadow_flag(parts[8])
        } else {
            // Glibc convention: missing reserved field decodes to ~0UL
            // ("field unset"), and format_shadow_line renders that as
            // empty. Round-trip identity is preserved.
            u64::MAX
        },
    })
}

/// Look up a shadow entry by login name in /etc/shadow content.
///
/// Name matching is case-sensitive (matches glibc — login names are
/// strictly case-sensitive on POSIX systems).
pub fn lookup_shadow_by_name(content: &[u8], name: &[u8]) -> Option<ShadowEntry> {
    for line in content.split(|&b| b == b'\n') {
        if let Some(entry) = parse_shadow_line(line)
            && entry.name == name
        {
            return Some(entry);
        }
    }
    None
}

fn strip_trailing_eol(s: &[u8]) -> &[u8] {
    let mut end = s.len();
    while end > 0 && (s[end - 1] == b'\n' || s[end - 1] == b'\r') {
        end -= 1;
    }
    &s[..end]
}

fn trim_leading_ws(s: &[u8]) -> &[u8] {
    let start = s
        .iter()
        .position(|&b| b != b' ' && b != b'\t')
        .unwrap_or(s.len());
    &s[start..]
}

/// Append a serialized shadow line to `out`.
///
/// All numeric fields use the glibc convention: `-1` (signed) or
/// `u64::MAX` (flag) renders as the empty string. Non-sentinel
/// values are written as decimal (with leading `-` for negatives).
/// Field bytes are written verbatim.
pub fn format_shadow_line(
    name: &[u8],
    passwd: &[u8],
    lstchg: i64,
    min: i64,
    max: i64,
    warn: i64,
    inact: i64,
    expire: i64,
    flag: u64,
    out: &mut Vec<u8>,
) {
    out.extend_from_slice(name);
    out.push(b':');
    out.extend_from_slice(passwd);
    out.push(b':');
    write_signed_or_empty(out, lstchg);
    out.push(b':');
    write_signed_or_empty(out, min);
    out.push(b':');
    write_signed_or_empty(out, max);
    out.push(b':');
    write_signed_or_empty(out, warn);
    out.push(b':');
    write_signed_or_empty(out, inact);
    out.push(b':');
    write_signed_or_empty(out, expire);
    out.push(b':');
    if flag != u64::MAX {
        write_u64_decimal(out, flag);
    }
    out.push(b'\n');
}

fn write_signed_or_empty(out: &mut Vec<u8>, n: i64) {
    if n == -1 {
        return;
    }
    write_i64_decimal(out, n);
}

fn write_i64_decimal(out: &mut Vec<u8>, n: i64) {
    if n == 0 {
        out.push(b'0');
        return;
    }
    let neg = n < 0;
    let mut v = n.unsigned_abs();
    let mut tmp = [0u8; 20];
    let mut i = 0;
    while v > 0 {
        tmp[i] = b'0' + (v % 10) as u8;
        v /= 10;
        i += 1;
    }
    if neg {
        out.push(b'-');
    }
    for j in 0..i {
        out.push(tmp[i - 1 - j]);
    }
}

fn write_u64_decimal(out: &mut Vec<u8>, mut n: u64) {
    if n == 0 {
        out.push(b'0');
        return;
    }
    let mut tmp = [0u8; 20];
    let mut i = 0;
    while n > 0 {
        tmp[i] = b'0' + (n % 10) as u8;
        n /= 10;
        i += 1;
    }
    for j in 0..i {
        out.push(tmp[i - 1 - j]);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn format_typical_locked_account() {
        let mut out = Vec::new();
        format_shadow_line(
            b"root",
            b"!locked",
            19500,
            0,
            99999,
            7,
            -1,
            -1,
            u64::MAX,
            &mut out,
        );
        // -1 fields and the all-ones flag render as empty
        assert_eq!(out, b"root:!locked:19500:0:99999:7:::\n".to_vec());
    }

    #[test]
    fn format_all_sentinels_render_empty() {
        let mut out = Vec::new();
        format_shadow_line(
            b"u",
            b"*",
            -1,
            -1,
            -1,
            -1,
            -1,
            -1,
            u64::MAX,
            &mut out,
        );
        assert_eq!(out, b"u:*:::::::\n".to_vec());
    }

    #[test]
    fn format_zero_is_not_empty() {
        let mut out = Vec::new();
        format_shadow_line(b"u", b"x", 0, 0, 0, 0, 0, 0, 0, &mut out);
        assert_eq!(out, b"u:x:0:0:0:0:0:0:0\n".to_vec());
    }

    #[test]
    fn format_with_explicit_flag() {
        let mut out = Vec::new();
        format_shadow_line(
            b"u",
            b"x",
            19000,
            0,
            -1,
            -1,
            -1,
            -1,
            42,
            &mut out,
        );
        assert_eq!(out, b"u:x:19000:0:::::42\n".to_vec());
    }

    #[test]
    fn format_handles_large_values() {
        let mut out = Vec::new();
        format_shadow_line(
            b"u",
            b"x",
            i64::MAX,
            0,
            -1,
            -1,
            -1,
            -1,
            u64::MAX - 1,
            &mut out,
        );
        // i64::MAX = 9223372036854775807
        // u64::MAX - 1 = 18446744073709551614
        assert_eq!(
            out,
            b"u:x:9223372036854775807:0:::::18446744073709551614\n".to_vec()
        );
    }

    #[test]
    fn format_appends_to_existing_buffer() {
        let mut out = b"prefix:".to_vec();
        format_shadow_line(b"u", b"x", -1, -1, -1, -1, -1, -1, u64::MAX, &mut out);
        assert_eq!(out, b"prefix:u:x:::::::\n".to_vec());
    }

    #[test]
    fn format_negative_non_sentinel_writes_minus_decimal() {
        // Only -1 is the sentinel — other negatives write through.
        let mut out = Vec::new();
        format_shadow_line(
            b"u", b"x", -2, -7, 99, 0, -1, -1, u64::MAX, &mut out,
        );
        assert_eq!(out, b"u:x:-2:-7:99:0:::\n".to_vec());
    }

    // ---- parse_shadow_numeric ----

    #[test]
    fn numeric_empty_is_minus_one() {
        assert_eq!(parse_shadow_numeric(b""), -1);
    }

    #[test]
    fn numeric_zero() {
        assert_eq!(parse_shadow_numeric(b"0"), 0);
    }

    #[test]
    fn numeric_positive() {
        assert_eq!(parse_shadow_numeric(b"19500"), 19500);
    }

    #[test]
    fn numeric_negative() {
        assert_eq!(parse_shadow_numeric(b"-7"), -7);
    }

    #[test]
    fn numeric_garbage_falls_back_to_minus_one() {
        assert_eq!(parse_shadow_numeric(b"abc"), -1);
        assert_eq!(parse_shadow_numeric(b"12x"), -1);
    }

    // ---- parse_shadow_line ----

    #[test]
    fn parse_typical_account_line() {
        let line = b"alice:!locked:19500:0:99999:7:::";
        let e = parse_shadow_line(line).unwrap();
        assert_eq!(e.name, b"alice");
        assert_eq!(e.passwd, b"!locked");
        assert_eq!(e.lstchg, 19500);
        assert_eq!(e.min, 0);
        assert_eq!(e.max, 99999);
        assert_eq!(e.warn, 7);
        assert_eq!(e.inact, -1);
        assert_eq!(e.expire, -1);
        // Empty 9th flag field decodes to ~0UL per glibc convention.
        assert_eq!(e.flag, u64::MAX);
    }

    #[test]
    fn parse_with_explicit_flag() {
        let line = b"u:x:19000:0:::::42";
        let e = parse_shadow_line(line).unwrap();
        assert_eq!(e.flag, 42);
        assert_eq!(e.lstchg, 19000);
    }

    #[test]
    fn parse_all_empty_numerics_decode_to_minus_one() {
        let line = b"u:*:::::::";
        let e = parse_shadow_line(line).unwrap();
        assert_eq!(e.lstchg, -1);
        assert_eq!(e.min, -1);
        assert_eq!(e.max, -1);
        assert_eq!(e.warn, -1);
        assert_eq!(e.inact, -1);
        assert_eq!(e.expire, -1);
        // Missing trailing flag field decodes to ~0UL per glibc convention.
        assert_eq!(e.flag, u64::MAX);
    }

    #[test]
    fn parse_skips_blank_line() {
        assert!(parse_shadow_line(b"").is_none());
        assert!(parse_shadow_line(b"   ").is_none());
    }

    #[test]
    fn parse_skips_comment_line() {
        assert!(parse_shadow_line(b"# this is a comment").is_none());
        assert!(parse_shadow_line(b"   # leading-ws comment").is_none());
    }

    #[test]
    fn parse_rejects_too_few_fields() {
        // 7 fields (no expire) — invalid
        assert!(parse_shadow_line(b"u:x:0:0:0:0:0").is_none());
    }

    #[test]
    fn parse_strips_trailing_newline() {
        let e = parse_shadow_line(b"u:x:0:0:0:0:0:0\n").unwrap();
        assert_eq!(e.expire, 0);
        let e = parse_shadow_line(b"u:x:0:0:0:0:0:0\r\n").unwrap();
        assert_eq!(e.expire, 0);
    }

    #[test]
    fn parse_garbage_numeric_falls_back_to_minus_one() {
        let e = parse_shadow_line(b"u:x:abc:xyz:99:0:0:0").unwrap();
        assert_eq!(e.lstchg, -1);
        assert_eq!(e.min, -1);
        assert_eq!(e.max, 99);
    }

    #[test]
    fn parse_format_round_trip_typical() {
        let line = b"alice:!locked:19500:0:99999:7:::\n";
        let e = parse_shadow_line(line).unwrap();
        let mut out = Vec::new();
        format_shadow_line(
            &e.name, &e.passwd, e.lstchg, e.min, e.max, e.warn, e.inact, e.expire, e.flag,
            &mut out,
        );
        assert_eq!(out, line.to_vec());
    }

    #[test]
    fn parse_format_round_trip_all_sentinels() {
        // Both -1 (signed) and u64::MAX (flag) sentinels round-trip
        // identity-preserving through format -> parse -> format.
        let mut out = Vec::new();
        format_shadow_line(
            b"u",
            b"*",
            -1,
            -1,
            -1,
            -1,
            -1,
            -1,
            u64::MAX,
            &mut out,
        );
        let e = parse_shadow_line(&out).unwrap();
        assert_eq!(e.lstchg, -1);
        assert_eq!(e.flag, u64::MAX);
        let mut out2 = Vec::new();
        format_shadow_line(
            &e.name, &e.passwd, e.lstchg, e.min, e.max, e.warn, e.inact, e.expire, e.flag,
            &mut out2,
        );
        assert_eq!(out2, out);
    }

    // ---- lookup_shadow_by_name ----

    #[test]
    fn lookup_finds_entry_by_name() {
        let content = b"root:!locked:19000:0:99999:7:::\nalice:x:19500:0:99999:7:::\n";
        let e = lookup_shadow_by_name(content, b"alice").unwrap();
        assert_eq!(e.lstchg, 19500);
        assert_eq!(e.passwd, b"x");
    }

    #[test]
    fn lookup_is_case_sensitive() {
        let content = b"alice:x:19500:0:99999:7:::\n";
        assert!(lookup_shadow_by_name(content, b"ALICE").is_none());
        assert!(lookup_shadow_by_name(content, b"alice").is_some());
    }

    #[test]
    fn lookup_skips_comment_and_blank_lines() {
        let content = b"# header\n\nalice:x:19500:0:99999:7:::\n";
        let e = lookup_shadow_by_name(content, b"alice").unwrap();
        assert_eq!(e.passwd, b"x");
    }

    #[test]
    fn lookup_returns_none_for_missing_name() {
        let content = b"alice:x:19500:0:99999:7:::\n";
        assert!(lookup_shadow_by_name(content, b"bob").is_none());
    }

    #[test]
    fn parse_real_world_shadow_line() {
        // Typical Debian /etc/shadow line for a normal user.
        let line = b"daemon:*:19500:0:99999:7:::";
        let e = parse_shadow_line(line).unwrap();
        assert_eq!(e.name, b"daemon");
        assert_eq!(e.passwd, b"*");
        assert_eq!(e.lstchg, 19500);
        assert_eq!(e.max, 99999);
    }
}
