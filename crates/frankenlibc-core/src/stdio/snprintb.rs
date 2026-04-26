//! BSD `snprintb(3)` family — render a packed integer with a
//! human-readable list of named bits.
//!
//! Format string syntax (NetBSD "old" style):
//!
//! ```text
//!   <base-byte><bit-spec>*
//! ```
//!
//! where `base-byte` is `\010` (octal display) or `\020` (hex
//! display), and each bit-spec is `<bit-num-byte><name-bytes...>`
//! with `bit-num-byte` in `1..=63` (1-based bit index, where `1`
//! means bit 0). Name bytes run until the next bit-num-byte
//! (any byte `< 0x20`) or NUL.
//!
//! Output format:
//!
//! ```text
//!   <base-prefix><value>[<<name1,name2,...>>]
//! ```
//!
//! The angle-bracketed name list is omitted when no named bit is
//! set. Bits without a corresponding bit-spec in the format string
//! are silently ignored even when set.

/// Render `val` according to the BSD `snprintb` format string
/// `fmt` and return the result.
///
/// On unknown / invalid format strings (empty, or first byte is
/// neither `0o10` nor `0o20`) returns an empty `Vec`. This matches
/// NetBSD's permissive behavior: "garbage in, empty buffer out".
pub fn format_snprintb(fmt: &[u8], val: u64) -> Vec<u8> {
    if fmt.is_empty() {
        return Vec::new();
    }
    let base = fmt[0];
    let mut out = Vec::new();
    match base {
        0o10 => write_octal(&mut out, val),
        0o20 => write_hex(&mut out, val),
        _ => return Vec::new(),
    }

    let names = collect_set_names(&fmt[1..], val);
    if !names.is_empty() {
        out.push(b'<');
        for (i, name) in names.iter().enumerate() {
            if i > 0 {
                out.push(b',');
            }
            out.extend_from_slice(name);
        }
        out.push(b'>');
    }
    out
}

/// Multi-line variant: when the running output line would exceed
/// `max_per_line` bytes, close the current name-group with `>`,
/// emit `\n`, re-emit the base+value, and open a new group with
/// `<`. `max_per_line == 0` falls back to single-line behavior.
pub fn format_snprintb_m(fmt: &[u8], val: u64, max_per_line: usize) -> Vec<u8> {
    if fmt.is_empty() {
        return Vec::new();
    }
    if max_per_line == 0 {
        return format_snprintb(fmt, val);
    }
    let base = fmt[0];
    let mut prefix = Vec::new();
    match base {
        0o10 => write_octal(&mut prefix, val),
        0o20 => write_hex(&mut prefix, val),
        _ => return Vec::new(),
    }

    let names = collect_set_names(&fmt[1..], val);
    let mut out: Vec<u8> = Vec::new();
    out.extend_from_slice(&prefix);
    if names.is_empty() {
        return out;
    }

    let mut line_len = prefix.len();
    let mut group_open = false;

    for name in &names {
        // Length we'd add: '<' or ',' + name + ('>' if we need to
        // close before the boundary check). We compute the running
        // length after appending and decide to wrap if it exceeds.
        let separator: u8 = if group_open { b',' } else { b'<' };
        let added = 1 + name.len(); // separator + name
        // Does adding (and eventually closing with '>') push us
        // past max_per_line?
        let projected = line_len + added + 1; // +1 for the closing '>'
        if group_open && projected > max_per_line {
            // Close current group and start a new line.
            out.push(b'>');
            out.push(b'\n');
            out.extend_from_slice(&prefix);
            line_len = prefix.len();
            out.push(b'<');
            line_len += 1;
            out.extend_from_slice(name);
            line_len += name.len();
            // group_open stays true for the new line.
        } else {
            out.push(separator);
            line_len += 1;
            out.extend_from_slice(name);
            line_len += name.len();
            group_open = true;
        }
    }

    if group_open {
        out.push(b'>');
    }
    out
}

fn write_octal(out: &mut Vec<u8>, val: u64) {
    out.push(b'0');
    if val == 0 {
        return;
    }
    let mut digits: [u8; 22] = [0; 22];
    let mut n = 0;
    let mut v = val;
    while v != 0 {
        digits[n] = b'0' + (v & 0x7) as u8;
        v >>= 3;
        n += 1;
    }
    for i in (0..n).rev() {
        out.push(digits[i]);
    }
}

fn write_hex(out: &mut Vec<u8>, val: u64) {
    out.extend_from_slice(b"0x");
    if val == 0 {
        out.push(b'0');
        return;
    }
    let mut digits: [u8; 16] = [0; 16];
    let mut n = 0;
    let mut v = val;
    while v != 0 {
        let nibble = (v & 0xf) as u8;
        digits[n] = if nibble < 10 {
            b'0' + nibble
        } else {
            b'a' + (nibble - 10)
        };
        v >>= 4;
        n += 1;
    }
    for i in (0..n).rev() {
        out.push(digits[i]);
    }
}

/// Walk `body` (the format string after the base byte), collect the
/// names whose corresponding bit is set in `val`, and return them
/// in format-string order.
fn collect_set_names(body: &[u8], val: u64) -> Vec<&[u8]> {
    let mut names: Vec<&[u8]> = Vec::new();
    let mut i = 0usize;
    while i < body.len() {
        let b = body[i];
        if b == 0 {
            break;
        }
        if b < 0x20 {
            // Bit number byte.
            let bit = (b as u32).wrapping_sub(1);
            // Find name end: next byte < 0x20 (or NUL or EOF).
            let mut name_end = i + 1;
            while name_end < body.len() {
                let nb = body[name_end];
                if nb == 0 || nb < 0x20 {
                    break;
                }
                name_end += 1;
            }
            if bit < 64 && (val & (1u64 << bit)) != 0 {
                names.push(&body[i + 1..name_end]);
            }
            i = name_end;
        } else {
            // Stray non-control byte before any bit spec — skip.
            i += 1;
        }
    }
    names
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_format_returns_empty() {
        assert!(format_snprintb(b"", 5).is_empty());
    }

    #[test]
    fn unknown_base_returns_empty() {
        assert!(format_snprintb(b"\x01\x01FOO", 5).is_empty());
    }

    #[test]
    fn octal_base_renders_value_with_leading_zero() {
        let out = format_snprintb(b"\x08", 9);
        assert_eq!(out, b"011".to_vec());
    }

    #[test]
    fn hex_base_renders_value_with_0x() {
        let out = format_snprintb(b"\x10", 0xab);
        assert_eq!(out, b"0xab".to_vec());
    }

    #[test]
    fn zero_value_renders_base_only() {
        assert_eq!(format_snprintb(b"\x08", 0), b"0".to_vec());
        assert_eq!(format_snprintb(b"\x10", 0), b"0x0".to_vec());
    }

    #[test]
    fn named_bits_listed_in_format_order() {
        // \010 base, bit1=FOO, bit2=BAR, bit3=BAZ
        let fmt = b"\x10\x01FOO\x02BAR\x03BAZ";
        // Bits 0 and 2 set → val = 5 → "0x5<FOO,BAZ>"
        let out = format_snprintb(fmt, 5);
        assert_eq!(out, b"0x5<FOO,BAZ>".to_vec());
    }

    #[test]
    fn unset_bits_omit_names_and_brackets() {
        let fmt = b"\x10\x01FOO\x02BAR";
        let out = format_snprintb(fmt, 0);
        assert_eq!(out, b"0x0".to_vec());
    }

    #[test]
    fn bit_without_name_in_fmt_is_ignored() {
        // bit 3 (val 4) is set but not named — output should not
        // include angle-bracket section.
        let fmt = b"\x10\x01FOO\x02BAR";
        let out = format_snprintb(fmt, 4);
        assert_eq!(out, b"0x4".to_vec());
    }

    #[test]
    fn high_bits_handled() {
        let fmt = b"\x10\x40HIGH"; // bit 64 — out of range, ignored
        let out = format_snprintb(fmt, u64::MAX);
        assert_eq!(out, format!("0x{:x}", u64::MAX).into_bytes());
    }

    #[test]
    fn snprintb_m_zero_max_falls_back_to_single_line() {
        let fmt = b"\x10\x01A\x02B";
        let single = format_snprintb(fmt, 3);
        let multi = format_snprintb_m(fmt, 3, 0);
        assert_eq!(single, multi);
    }

    #[test]
    fn snprintb_m_splits_lines_when_exceeding_max() {
        // base "0x3" = 3 chars; with max_per_line=8 and names A,B,C,
        // each bit set, we get a line break before exceeding.
        let fmt = b"\x10\x01ABC\x02DEF\x03GHI";
        // val=7 → all three set
        let out = format_snprintb_m(fmt, 7, 10);
        // Single-line would be "0x7<ABC,DEF,GHI>" (16 chars).
        // With max=10: "0x7<ABC,DEF>\n0x7<GHI>" or similar.
        // Just verify there's a newline in the output and every
        // line begins with "0x7<...>".
        assert!(out.contains(&b'\n'));
        for line in out.split(|&b| b == b'\n') {
            assert!(line.starts_with(b"0x7<"));
            assert!(line.ends_with(b">"));
        }
    }

    #[test]
    fn snprintb_m_no_set_bits_emits_no_brackets() {
        let fmt = b"\x10\x01FOO";
        let out = format_snprintb_m(fmt, 0, 80);
        assert_eq!(out, b"0x0".to_vec());
    }
}
