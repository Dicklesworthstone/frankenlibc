//! `/proc/<pid>/maps` line parser.
//!
//! Pure-safe Rust port of the byte-level logic that previously lived
//! inline in frankenlibc-abi/src/host_resolve.rs::parse_maps_line and
//! frankenlibc-abi/src/pthread_abi.rs::parse_maps_range.
//!
//! Line shape (Linux kernel proc(5)):
//!   `<start>-<end> <perms> <offset> <dev> <inode> [<path>]`
//!
//! For example:
//!   `7f1234500000-7f1234600000 r-xp 00010000 fd:01 12345 /usr/lib/libfoo.so`
//!   `7ffd00000000-7ffd00021000 rw-p 00000000 00:00 0 [stack]`
//!   `7f8800000000-7f8800800000 ---p 00000000 00:00 0`
//!
//! Whitespace separators are runs of ASCII space — the kernel uses
//! variable-length padding to align the path column.

/// Parsed view of one /proc/self/maps line.
///
/// Field references borrow from the source line; the caller controls
/// the lifetime.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MapsEntry<'a> {
    /// Start virtual address (inclusive).
    pub start: usize,
    /// End virtual address (exclusive).
    pub end: usize,
    /// Permissions field (e.g. `"r-xp"`, `"rw-p"`).
    pub perms: &'a str,
    /// Page-aligned offset into the backing file (`0` for anonymous).
    pub offset: u64,
    /// Major:minor device of the backing file (e.g. `"fd:01"`).
    pub dev: &'a str,
    /// Backing file inode (`0` for anonymous mappings).
    pub inode: u64,
    /// Optional pathname / pseudo-name (`[stack]`, `[heap]`, `[vdso]`).
    pub path: Option<&'a str>,
}

/// Parse one `/proc/self/maps` line.
///
/// Returns `None` if any of the five mandatory fields is missing or
/// malformed. The path is optional — anonymous mappings and `---p`
/// regions have no trailing path.
pub fn parse_maps_line(line: &str) -> Option<MapsEntry<'_>> {
    let line = line.trim_end_matches(['\n', '\r']);
    let mut parts = line.split_whitespace();
    let range = parts.next()?;
    let perms = parts.next()?;
    let offset_s = parts.next()?;
    let dev = parts.next()?;
    let inode_s = parts.next()?;
    let path = parts.next();
    if parts.next().is_some() {
        // Path with embedded spaces would arrive as multiple tokens; the
        // kernel emits exactly one trailing field, so extra tokens mean
        // the line is malformed for our purposes.
        return None;
    }

    let dash = range.find('-')?;
    let start = usize::from_str_radix(&range[..dash], 16).ok()?;
    let end = usize::from_str_radix(&range[dash + 1..], 16).ok()?;
    let offset = u64::from_str_radix(offset_s, 16).ok()?;
    let inode = inode_s.parse::<u64>().ok()?;

    Some(MapsEntry {
        start,
        end,
        perms,
        offset,
        dev,
        inode,
        path,
    })
}

/// Shortcut for callers that only need the address range.
///
/// Equivalent to extracting `(start, end)` from [`parse_maps_line`],
/// but avoids parsing the trailing fields when only the range is
/// wanted.
pub fn parse_maps_range(line: &str) -> Option<(usize, usize)> {
    let range = line.split_whitespace().next()?;
    let dash = range.find('-')?;
    let start = usize::from_str_radix(&range[..dash], 16).ok()?;
    let end = usize::from_str_radix(&range[dash + 1..], 16).ok()?;
    Some((start, end))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_typical_mapped_library_line() {
        let line = "7f1234500000-7f1234600000 r-xp 00010000 fd:01 12345 /usr/lib/libfoo.so";
        let e = parse_maps_line(line).unwrap();
        assert_eq!(e.start, 0x7f1234500000);
        assert_eq!(e.end, 0x7f1234600000);
        assert_eq!(e.perms, "r-xp");
        assert_eq!(e.offset, 0x10000);
        assert_eq!(e.dev, "fd:01");
        assert_eq!(e.inode, 12345);
        assert_eq!(e.path, Some("/usr/lib/libfoo.so"));
    }

    #[test]
    fn parse_anonymous_no_path() {
        let line = "7f8800000000-7f8800800000 ---p 00000000 00:00 0";
        let e = parse_maps_line(line).unwrap();
        assert_eq!(e.start, 0x7f8800000000);
        assert_eq!(e.end, 0x7f8800800000);
        assert_eq!(e.perms, "---p");
        assert_eq!(e.offset, 0);
        assert_eq!(e.dev, "00:00");
        assert_eq!(e.inode, 0);
        assert_eq!(e.path, None);
    }

    #[test]
    fn parse_pseudo_named_regions() {
        for (line, name) in [
            (
                "7ffd00000000-7ffd00021000 rw-p 00000000 00:00 0 [stack]",
                "[stack]",
            ),
            (
                "55a000000000-55a000021000 rw-p 00000000 00:00 0 [heap]",
                "[heap]",
            ),
            (
                "7ffd12345000-7ffd12347000 r-xp 00000000 00:00 0 [vdso]",
                "[vdso]",
            ),
            (
                "7ffd12348000-7ffd1234a000 r--p 00000000 00:00 0 [vvar]",
                "[vvar]",
            ),
        ] {
            let e = parse_maps_line(line).expect(name);
            assert_eq!(e.path, Some(name));
        }
    }

    #[test]
    fn parse_strips_trailing_eol() {
        let e = parse_maps_line("400000-401000 r--p 0 00:00 0\n").unwrap();
        assert_eq!(e.start, 0x400000);
        let e = parse_maps_line("400000-401000 r--p 0 00:00 0\r\n").unwrap();
        assert_eq!(e.end, 0x401000);
    }

    #[test]
    fn parse_handles_extra_internal_whitespace() {
        // Kernel pads with spaces; split_whitespace collapses runs.
        let line = "400000-401000   r--p   00000000  00:00     0   /bin/cat";
        let e = parse_maps_line(line).unwrap();
        assert_eq!(e.path, Some("/bin/cat"));
        assert_eq!(e.inode, 0);
    }

    #[test]
    fn parse_rejects_missing_range_dash() {
        assert!(parse_maps_line("400000 r--p 0 00:00 0").is_none());
    }

    #[test]
    fn parse_rejects_non_hex_addresses() {
        assert!(parse_maps_line("xyz-401000 r--p 0 00:00 0").is_none());
        assert!(parse_maps_line("400000-xyz r--p 0 00:00 0").is_none());
    }

    #[test]
    fn parse_rejects_truncated_line() {
        assert!(parse_maps_line("400000-401000 r--p").is_none());
        assert!(parse_maps_line("400000-401000").is_none());
        assert!(parse_maps_line("").is_none());
    }

    #[test]
    fn parse_rejects_extra_trailing_tokens() {
        // path with embedded space arrives as two tokens — we treat
        // that as malformed (caller can re-parse if it needs to).
        assert!(parse_maps_line("400000-401000 r--p 0 00:00 0 /tmp/file with space").is_none());
    }

    #[test]
    fn parse_rejects_non_numeric_inode() {
        assert!(parse_maps_line("400000-401000 r--p 0 00:00 abc /bin/cat").is_none());
    }

    #[test]
    fn parse_rejects_non_hex_offset() {
        assert!(parse_maps_line("400000-401000 r--p XYZ 00:00 0 /bin/cat").is_none());
    }

    #[test]
    fn parse_handles_high_64bit_addresses() {
        let line = "ffffffff80000000-ffffffff80100000 r-xp 00000000 00:00 0 [kernel]";
        let e = parse_maps_line(line).unwrap();
        assert_eq!(e.start, 0xffff_ffff_8000_0000);
        assert_eq!(e.end, 0xffff_ffff_8010_0000);
    }

    #[test]
    fn parse_handles_each_perms_string() {
        for perms in ["r--p", "rw-p", "r-xp", "rwxp", "---p", "r--s", "rw-s"] {
            let line = format!("400000-401000 {perms} 0 00:00 0");
            let e = parse_maps_line(&line).expect(perms);
            assert_eq!(e.perms, perms);
        }
    }

    // ---- parse_maps_range ----

    #[test]
    fn range_basic() {
        assert_eq!(
            parse_maps_range("7f1234500000-7f1234600000 r-xp 0 fd:01 12345 /usr/lib/libfoo.so"),
            Some((0x7f1234500000, 0x7f1234600000))
        );
    }

    #[test]
    fn range_works_with_minimal_line() {
        // Just the range field is enough for parse_maps_range.
        assert_eq!(
            parse_maps_range("400000-401000"),
            Some((0x400000, 0x401000))
        );
    }

    #[test]
    fn range_rejects_missing_dash() {
        assert!(parse_maps_range("400000 r--p 0 00:00 0").is_none());
    }

    #[test]
    fn range_rejects_non_hex() {
        assert!(parse_maps_range("xyz-401000 r--p 0 00:00 0").is_none());
        assert!(parse_maps_range("400000-xyz r--p 0 00:00 0").is_none());
    }

    #[test]
    fn range_rejects_empty() {
        assert!(parse_maps_range("").is_none());
        assert!(parse_maps_range("   ").is_none());
    }

    #[test]
    fn range_handles_high_addresses() {
        assert_eq!(
            parse_maps_range("ffffffff80000000-ffffffff80100000"),
            Some((0xffff_ffff_8000_0000, 0xffff_ffff_8010_0000))
        );
    }

    #[test]
    fn range_matches_parse_maps_line_when_both_succeed() {
        let line = "7f1234500000-7f1234600000 r-xp 00010000 fd:01 12345 /usr/lib/libfoo.so";
        let entry = parse_maps_line(line).unwrap();
        let range = parse_maps_range(line).unwrap();
        assert_eq!(range, (entry.start, entry.end));
    }
}
