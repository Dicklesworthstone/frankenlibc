//! `<shadow.h>` line serialization.
//!
//! `/etc/shadow` line shape:
//!   `name:passwd:lstchg:min:max:warn:inact:expire:flag`
//!
//! Per glibc's `putspent`, numeric fields with the sentinel value
//! `-1` are emitted as empty rather than the literal string `"-1"`.
//! The flag field (`reserved`, type `unsigned long` in struct spwd)
//! is also emitted as empty when its bit pattern is `~0` (`u64::MAX`,
//! the all-ones sentinel used by glibc).

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
}
