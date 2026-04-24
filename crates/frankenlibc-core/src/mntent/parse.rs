//! Pure helpers for parsing and serializing fstab/mtab lines.

/// Borrowed view of one mount-table entry.
///
/// Each field is a byte slice into the underlying line buffer.
/// `freq` and `passno` default to `0` when the corresponding
/// fields are absent (an mtab line may legitimately have just the
/// first four fields).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct MntFields<'a> {
    pub fsname: &'a [u8],
    pub dir: &'a [u8],
    pub mtype: &'a [u8],
    pub opts: &'a [u8],
    pub freq: i32,
    pub passno: i32,
}

/// Parse a single fstab/mtab line into [`MntFields`].
///
/// Returns `None` for blank lines, comment lines (first non-whitespace
/// byte is `#`), or lines with fewer than four fields. The trailing
/// `\n`/`\r\n` (if present) is tolerated.
///
/// Field separators are runs of ASCII space or tab. Empty fields are
/// skipped (matching `getmntent_r`'s historical behavior).
pub fn parse_mntent_line(line: &[u8]) -> Option<MntFields<'_>> {
    let trimmed = strip_trailing_eol(line);

    let first_nonblank = trimmed
        .iter()
        .position(|&b| b != b' ' && b != b'\t')?;
    if trimmed[first_nonblank] == b'#' {
        return None;
    }

    let mut fields = trimmed
        .split(|&b| b == b' ' || b == b'\t')
        .filter(|f| !f.is_empty());

    let fsname = fields.next()?;
    let dir = fields.next()?;
    let mtype = fields.next()?;
    let opts = fields.next()?;
    let freq_s = fields.next().unwrap_or(b"0");
    let passno_s = fields.next().unwrap_or(b"0");

    let (freq, passno) = parse_mntent_freq_passno(freq_s, passno_s);

    Some(MntFields {
        fsname,
        dir,
        mtype,
        opts,
        freq,
        passno,
    })
}

/// Parse the freq/passno trailing fields, defaulting non-numeric
/// or empty inputs to `0` (matches glibc's behavior of treating
/// missing/garbage trailing fields as zero).
pub fn parse_mntent_freq_passno(freq_s: &[u8], passno_s: &[u8]) -> (i32, i32) {
    let parse = |bytes: &[u8]| -> i32 {
        std::str::from_utf8(bytes)
            .ok()
            .and_then(|s| s.parse().ok())
            .unwrap_or(0)
    };
    (parse(freq_s), parse(passno_s))
}

/// Search a comma-separated options string for `needle` as a whole token.
///
/// Returns the byte offset of the matching token within `opts`, or
/// `None` if not found. Tokens are bounded by `,`, the start of the
/// string, or its end. An empty needle never matches.
///
/// Examples:
///   has_mnt_opt(b"rw,noexec,nosuid", b"noexec") == Some(3)
///   has_mnt_opt(b"rw,noexec,nosuid", b"exec")   == None
///   has_mnt_opt(b"rw,exec",          b"exec")   == Some(3)
pub fn has_mnt_opt(opts: &[u8], needle: &[u8]) -> Option<usize> {
    if needle.is_empty() || needle.len() > opts.len() {
        return None;
    }
    for (i, window) in opts.windows(needle.len()).enumerate() {
        if window != needle {
            continue;
        }
        let at_start = i == 0 || opts[i - 1] == b',';
        let at_end = i + needle.len() == opts.len() || opts[i + needle.len()] == b',';
        if at_start && at_end {
            return Some(i);
        }
    }
    None
}

/// Append an fstab-style serialized line to `out`.
///
/// Produces `"<fsname> <dir> <type> <opts> <freq> <passno>\n"`.
/// Field bytes are written verbatim — the caller is responsible for
/// ensuring no embedded whitespace would corrupt the format.
pub fn format_mntent_line(fields: &MntFields<'_>, out: &mut Vec<u8>) {
    out.extend_from_slice(fields.fsname);
    out.push(b' ');
    out.extend_from_slice(fields.dir);
    out.push(b' ');
    out.extend_from_slice(fields.mtype);
    out.push(b' ');
    out.extend_from_slice(fields.opts);
    out.push(b' ');
    write_signed(out, fields.freq);
    out.push(b' ');
    write_signed(out, fields.passno);
    out.push(b'\n');
}

fn write_signed(out: &mut Vec<u8>, n: i32) {
    let mut buf = itoa_buf();
    let s = i32_to_decimal(n, &mut buf);
    out.extend_from_slice(s);
}

fn itoa_buf() -> [u8; 12] {
    [0u8; 12]
}

fn i32_to_decimal(n: i32, buf: &mut [u8; 12]) -> &[u8] {
    if n == 0 {
        buf[0] = b'0';
        return &buf[..1];
    }
    let neg = n < 0;
    // Use absolute value via i64 to handle i32::MIN safely.
    let mut v = (n as i64).unsigned_abs();
    let mut tmp = [0u8; 11];
    let mut i = 0;
    while v > 0 {
        tmp[i] = b'0' + (v % 10) as u8;
        v /= 10;
        i += 1;
    }
    let mut off = 0;
    if neg {
        buf[0] = b'-';
        off = 1;
    }
    for j in 0..i {
        buf[off + j] = tmp[i - 1 - j];
    }
    &buf[..off + i]
}

fn strip_trailing_eol(line: &[u8]) -> &[u8] {
    let mut end = line.len();
    while end > 0 && (line[end - 1] == b'\n' || line[end - 1] == b'\r') {
        end -= 1;
    }
    &line[..end]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_basic_line() {
        let line = b"/dev/sda1 / ext4 rw,relatime 0 1";
        let f = parse_mntent_line(line).expect("parsed");
        assert_eq!(f.fsname, b"/dev/sda1");
        assert_eq!(f.dir, b"/");
        assert_eq!(f.mtype, b"ext4");
        assert_eq!(f.opts, b"rw,relatime");
        assert_eq!(f.freq, 0);
        assert_eq!(f.passno, 1);
    }

    #[test]
    fn parse_with_trailing_newline() {
        let f = parse_mntent_line(b"a b c d 0 0\n").expect("parsed");
        assert_eq!(f.fsname, b"a");
        assert_eq!(f.passno, 0);
    }

    #[test]
    fn parse_with_crlf() {
        let f = parse_mntent_line(b"a b c d 0 0\r\n").expect("parsed");
        assert_eq!(f.dir, b"b");
    }

    #[test]
    fn parse_skips_blank_line() {
        assert!(parse_mntent_line(b"").is_none());
        assert!(parse_mntent_line(b"   ").is_none());
        assert!(parse_mntent_line(b"\t\t\n").is_none());
    }

    #[test]
    fn parse_skips_comment_line() {
        assert!(parse_mntent_line(b"# this is a comment").is_none());
        assert!(parse_mntent_line(b"   # leading whitespace OK").is_none());
        assert!(parse_mntent_line(b"\t# tab indent comment").is_none());
    }

    #[test]
    fn parse_returns_none_for_too_few_fields() {
        assert!(parse_mntent_line(b"a b c").is_none());
        assert!(parse_mntent_line(b"a").is_none());
    }

    #[test]
    fn parse_collapses_runs_of_whitespace() {
        let f = parse_mntent_line(b"a    b\t\tc   d 0 0").expect("parsed");
        assert_eq!(f.fsname, b"a");
        assert_eq!(f.dir, b"b");
        assert_eq!(f.mtype, b"c");
        assert_eq!(f.opts, b"d");
    }

    #[test]
    fn parse_defaults_freq_passno_to_zero_when_missing() {
        let f = parse_mntent_line(b"a b c d").expect("parsed");
        assert_eq!(f.freq, 0);
        assert_eq!(f.passno, 0);
    }

    #[test]
    fn parse_freq_only_then_default_passno() {
        let f = parse_mntent_line(b"a b c d 5").expect("parsed");
        assert_eq!(f.freq, 5);
        assert_eq!(f.passno, 0);
    }

    #[test]
    fn parse_garbage_freq_passno_fall_back_to_zero() {
        let f = parse_mntent_line(b"a b c d xyz qqq").expect("parsed");
        assert_eq!(f.freq, 0);
        assert_eq!(f.passno, 0);
    }

    #[test]
    fn freq_passno_negative_supported() {
        let (a, b) = parse_mntent_freq_passno(b"-3", b"-7");
        assert_eq!(a, -3);
        assert_eq!(b, -7);
    }

    #[test]
    fn has_opt_basic_match() {
        let opts = b"rw,noexec,nosuid";
        assert_eq!(has_mnt_opt(opts, b"rw"), Some(0));
        assert_eq!(has_mnt_opt(opts, b"noexec"), Some(3));
        assert_eq!(has_mnt_opt(opts, b"nosuid"), Some(10));
    }

    #[test]
    fn has_opt_no_match_for_substring() {
        // 'exec' is a substring of 'noexec' but not a token
        assert_eq!(has_mnt_opt(b"rw,noexec", b"exec"), None);
        // 'rw' is a substring of 'rwx' but not a token
        assert_eq!(has_mnt_opt(b"rwx,foo", b"rw"), None);
    }

    #[test]
    fn has_opt_at_string_start() {
        assert_eq!(has_mnt_opt(b"foo,bar", b"foo"), Some(0));
    }

    #[test]
    fn has_opt_at_string_end() {
        assert_eq!(has_mnt_opt(b"foo,bar", b"bar"), Some(4));
    }

    #[test]
    fn has_opt_only_token() {
        assert_eq!(has_mnt_opt(b"only", b"only"), Some(0));
    }

    #[test]
    fn has_opt_missing() {
        assert_eq!(has_mnt_opt(b"a,b,c", b"d"), None);
        assert_eq!(has_mnt_opt(b"", b"a"), None);
    }

    #[test]
    fn has_opt_empty_needle_never_matches() {
        assert_eq!(has_mnt_opt(b"a,b,c", b""), None);
        assert_eq!(has_mnt_opt(b"", b""), None);
    }

    #[test]
    fn has_opt_needle_longer_than_haystack_no_match() {
        assert_eq!(has_mnt_opt(b"a", b"abc"), None);
    }

    #[test]
    fn has_opt_value_form_match() {
        // hasmntopt also typically locates the start of "key=value" tokens.
        // Our function returns the first token-aligned occurrence; callers
        // can apply trailing parse if they want the value.
        assert_eq!(has_mnt_opt(b"rw,uid=1000,nosuid", b"uid=1000"), Some(3));
    }

    #[test]
    fn format_round_trip_basic() {
        let fields = MntFields {
            fsname: b"/dev/sda1",
            dir: b"/",
            mtype: b"ext4",
            opts: b"rw,relatime",
            freq: 0,
            passno: 1,
        };
        let mut out = Vec::new();
        format_mntent_line(&fields, &mut out);
        assert_eq!(out, b"/dev/sda1 / ext4 rw,relatime 0 1\n".to_vec());

        // Re-parse to verify byte-exact round-trip
        let reparsed = parse_mntent_line(&out).expect("reparsed");
        assert_eq!(reparsed, fields);
    }

    #[test]
    fn format_handles_negative_numbers() {
        let fields = MntFields {
            fsname: b"a",
            dir: b"b",
            mtype: b"c",
            opts: b"d",
            freq: -1,
            passno: -42,
        };
        let mut out = Vec::new();
        format_mntent_line(&fields, &mut out);
        assert_eq!(out, b"a b c d -1 -42\n".to_vec());
    }

    #[test]
    fn format_handles_zero_zero() {
        let fields = MntFields {
            fsname: b"x",
            dir: b"y",
            mtype: b"z",
            opts: b"w",
            freq: 0,
            passno: 0,
        };
        let mut out = Vec::new();
        format_mntent_line(&fields, &mut out);
        assert_eq!(out, b"x y z w 0 0\n".to_vec());
    }

    #[test]
    fn format_handles_i32_min() {
        let fields = MntFields {
            fsname: b"a",
            dir: b"b",
            mtype: b"c",
            opts: b"d",
            freq: i32::MIN,
            passno: i32::MAX,
        };
        let mut out = Vec::new();
        format_mntent_line(&fields, &mut out);
        // Verify both extremes serialize correctly
        assert_eq!(out, b"a b c d -2147483648 2147483647\n".to_vec());
    }

    #[test]
    fn format_appends_to_existing_buffer() {
        let mut out = b"prefix:".to_vec();
        let fields = MntFields {
            fsname: b"a",
            dir: b"b",
            mtype: b"c",
            opts: b"d",
            freq: 0,
            passno: 0,
        };
        format_mntent_line(&fields, &mut out);
        assert_eq!(out, b"prefix:a b c d 0 0\n".to_vec());
    }

    #[test]
    fn parse_real_world_proc_mounts_line() {
        let line = b"tmpfs /run tmpfs rw,nosuid,nodev,noexec,relatime,size=809456k,mode=755 0 0";
        let f = parse_mntent_line(line).expect("parsed");
        assert_eq!(f.fsname, b"tmpfs");
        assert_eq!(f.dir, b"/run");
        assert_eq!(f.mtype, b"tmpfs");
        assert!(f.opts.starts_with(b"rw,nosuid,nodev,noexec"));
        // "rw,nosuid,nodev," = 16 bytes, then "noexec" begins.
        assert_eq!(has_mnt_opt(f.opts, b"noexec"), Some(16));
        assert!(has_mnt_opt(f.opts, b"size=809456k").is_some());
    }
}
