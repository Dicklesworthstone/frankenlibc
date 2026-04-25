//! `<netdb.h>` /etc/rpc database parser.
//!
//! Pure-safe Rust port of the byte-slice line parsing that previously
//! lived inline in frankenlibc-abi/src/unistd_abi.rs (parse_rpc_line_to_static
//! plus the duplicated parse+filter loops in getrpcbyname /
//! getrpcbynumber).
//!
//! `/etc/rpc` line shape:
//!   `<rpc-name> <program-number> [<alias>...]`
//!
//! Lines beginning with `#` (after leading whitespace) and blank lines
//! are skipped. Trailing inline `# ...` comments are stripped before
//! tokenization.

/// Parsed /etc/rpc entry.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RpcEntry {
    /// Canonical RPC service name.
    pub name: Vec<u8>,
    /// RPC program number (matches glibc's `int r_number`).
    pub number: i32,
    /// Additional aliases for the program name.
    pub aliases: Vec<Vec<u8>>,
}

/// Parse a single /etc/rpc line.
///
/// Returns `None` for blank, comment-only, or malformed lines (missing
/// name, missing number, or non-numeric number).
pub fn parse_rpc_line(line: &[u8]) -> Option<RpcEntry> {
    let line = if let Some(pos) = line.iter().position(|&b| b == b'#') {
        &line[..pos]
    } else {
        line
    };
    let mut fields = line
        .split(|&b| b == b' ' || b == b'\t' || b == b'\n' || b == b'\r')
        .filter(|f| !f.is_empty());
    let name = fields.next()?;
    let num_str = core::str::from_utf8(fields.next()?).ok()?;
    let number: i32 = num_str.parse().ok()?;
    let aliases: Vec<Vec<u8>> = fields.map(|f| f.to_vec()).collect();
    Some(RpcEntry {
        name: name.to_vec(),
        number,
        aliases,
    })
}

fn rpc_name_matches(entry: &RpcEntry, name: &[u8]) -> bool {
    eq_ignore_ascii_case(&entry.name, name)
        || entry
            .aliases
            .iter()
            .any(|alias| eq_ignore_ascii_case(alias, name))
}

/// Look up an RPC entry by name (or alias) in /etc/rpc content.
///
/// Name matching is case-insensitive (matches the glibc files-backend
/// behavior — the canonical `nfsd`/`portmapper`-style names are
/// lowercase but distros vary).
pub fn lookup_rpc_by_name(content: &[u8], name: &[u8]) -> Option<RpcEntry> {
    for line in content.split(|&b| b == b'\n') {
        if let Some(entry) = parse_rpc_line(line)
            && rpc_name_matches(&entry, name)
        {
            return Some(entry);
        }
    }
    None
}

/// Look up an RPC entry by program number in /etc/rpc content.
pub fn lookup_rpc_by_number(content: &[u8], number: i32) -> Option<RpcEntry> {
    for line in content.split(|&b| b == b'\n') {
        if let Some(entry) = parse_rpc_line(line)
            && entry.number == number
        {
            return Some(entry);
        }
    }
    None
}

fn eq_ignore_ascii_case(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    a.iter()
        .zip(b.iter())
        .all(|(x, y)| x.eq_ignore_ascii_case(y))
}

/// Map an RPC `clnt_stat` (`rpc/clnt_stat.h`) status code to the
/// canonical glibc human-readable description string.
///
/// Codes in `0..=17` map per `<rpc/clnt_stat.h>`; out-of-range values
/// return `"Unknown error"`. Used by the abi shims `clnt_perrno`,
/// `clnt_sperrno`, and `clnt_spcreateerror`.
pub fn status_message(stat: i32) -> &'static str {
    match stat {
        0 => "Success",
        1 => "Can't encode arguments",
        2 => "Can't decode results",
        3 => "Unable to send",
        4 => "Unable to receive",
        5 => "Timed out",
        6 => "Incompatible versions of RPC",
        7 => "Authentication error",
        8 => "Program unavailable",
        9 => "Program/version mismatch",
        10 => "Procedure unavailable",
        11 => "Server can't decode arguments",
        12 => "Remote system error",
        13 => "Unknown host",
        14 => "Port mapper failure",
        15 => "Program not registered",
        16 => "Failed (unspecified error)",
        17 => "Unknown protocol",
        _ => "Unknown error",
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_simple_line() {
        let e = parse_rpc_line(b"portmapper 100000 portmap sunrpc rpcbind").unwrap();
        assert_eq!(e.name, b"portmapper");
        assert_eq!(e.number, 100000);
        assert_eq!(
            e.aliases,
            vec![b"portmap".to_vec(), b"sunrpc".to_vec(), b"rpcbind".to_vec()]
        );
    }

    #[test]
    fn parse_no_aliases() {
        let e = parse_rpc_line(b"nfs 100003").unwrap();
        assert_eq!(e.name, b"nfs");
        assert_eq!(e.number, 100003);
        assert!(e.aliases.is_empty());
    }

    #[test]
    fn parse_strips_inline_comment() {
        let e = parse_rpc_line(b"foo 123 alpha # this is the alpha service").unwrap();
        assert_eq!(e.name, b"foo");
        assert_eq!(e.number, 123);
        assert_eq!(e.aliases, vec![b"alpha".to_vec()]);
    }

    #[test]
    fn parse_skips_full_comment() {
        assert!(parse_rpc_line(b"# header line").is_none());
        assert!(parse_rpc_line(b"   # leading-ws comment").is_none());
        assert!(parse_rpc_line(b"\t# tab indent").is_none());
    }

    #[test]
    fn parse_skips_blank_line() {
        assert!(parse_rpc_line(b"").is_none());
        assert!(parse_rpc_line(b"   \t  ").is_none());
        assert!(parse_rpc_line(b"\n").is_none());
    }

    #[test]
    fn parse_rejects_missing_number() {
        assert!(parse_rpc_line(b"orphan").is_none());
    }

    #[test]
    fn parse_rejects_non_numeric_number() {
        assert!(parse_rpc_line(b"foo bar baz").is_none());
        assert!(parse_rpc_line(b"foo 0x100").is_none());
    }

    #[test]
    fn parse_handles_tab_separated() {
        let e = parse_rpc_line(b"nfs\t100003\tportmap").unwrap();
        assert_eq!(e.name, b"nfs");
        assert_eq!(e.number, 100003);
        assert_eq!(e.aliases, vec![b"portmap".to_vec()]);
    }

    #[test]
    fn parse_strips_trailing_eol() {
        let e = parse_rpc_line(b"nfs 100003\n").unwrap();
        assert_eq!(e.number, 100003);
        let e = parse_rpc_line(b"nfs 100003\r\n").unwrap();
        assert_eq!(e.number, 100003);
    }

    #[test]
    fn parse_negative_program_number() {
        // glibc uses `int r_number` so negative is technically representable.
        let e = parse_rpc_line(b"weird -1").unwrap();
        assert_eq!(e.number, -1);
    }

    #[test]
    fn lookup_by_name_case_insensitive() {
        let content = b"nfs 100003\nmountd 100005\n";
        assert_eq!(lookup_rpc_by_name(content, b"NFS").unwrap().number, 100003);
        assert_eq!(
            lookup_rpc_by_name(content, b"MoUnTd").unwrap().number,
            100005
        );
    }

    #[test]
    fn lookup_by_alias() {
        let content = b"portmapper 100000 portmap sunrpc rpcbind\n";
        let e = lookup_rpc_by_name(content, b"sunrpc").unwrap();
        assert_eq!(e.name, b"portmapper");
        assert_eq!(e.number, 100000);
        let e = lookup_rpc_by_name(content, b"rpcbind").unwrap();
        assert_eq!(e.name, b"portmapper");
    }

    #[test]
    fn lookup_by_alias_case_insensitive() {
        let content = b"portmapper 100000 portmap\n";
        let e = lookup_rpc_by_name(content, b"PORTMAP").unwrap();
        assert_eq!(e.name, b"portmapper");
    }

    #[test]
    fn lookup_by_number() {
        let content = b"portmapper 100000 portmap\nnfs 100003\nmountd 100005\n";
        assert_eq!(lookup_rpc_by_number(content, 100003).unwrap().name, b"nfs");
        assert_eq!(
            lookup_rpc_by_number(content, 100005).unwrap().name,
            b"mountd"
        );
        assert!(lookup_rpc_by_number(content, 999).is_none());
    }

    #[test]
    fn lookup_returns_none_for_missing() {
        let content = b"nfs 100003\n";
        assert!(lookup_rpc_by_name(content, b"missing").is_none());
    }

    #[test]
    fn lookup_skips_comments_and_blanks() {
        let content = b"# RPC services\n\nportmapper 100000 portmap\n# more\nnfs 100003\n";
        assert_eq!(lookup_rpc_by_name(content, b"nfs").unwrap().number, 100003);
    }

    #[test]
    fn parse_real_world_rpc_lines() {
        // Lines from a typical /etc/rpc on Linux
        let cases = [
            (
                &b"portmapper      100000  portmap sunrpc rpcbind"[..],
                b"portmapper".as_slice(),
                100000,
                3,
            ),
            (b"nfs             100003  nfsprog", b"nfs", 100003, 1),
            (
                b"mountd          100005  mount showmount",
                b"mountd",
                100005,
                2,
            ),
            (b"ypserv          100004  ypprog", b"ypserv", 100004, 1),
        ];
        for (line, name, num, alias_count) in cases {
            let e = parse_rpc_line(line).unwrap_or_else(|| panic!("{:?}", line));
            assert_eq!(e.name, name);
            assert_eq!(e.number, num);
            assert_eq!(e.aliases.len(), alias_count);
        }
    }

    // ---- status_message ----

    #[test]
    fn status_message_zero_is_success() {
        assert_eq!(status_message(0), "Success");
    }

    #[test]
    fn status_message_covers_full_range() {
        // Spot-check each documented status code (0..=17) returns
        // a non-empty, non-fallback string.
        let unknown = status_message(99999);
        for code in 0..=17 {
            let msg = status_message(code);
            assert!(!msg.is_empty(), "code {code} returned empty");
            assert_ne!(msg, unknown, "code {code} aliased fallback");
        }
    }

    #[test]
    fn status_message_known_codes_match_glibc_text() {
        // A handful of the most-cited codes verbatim.
        assert_eq!(status_message(1), "Can't encode arguments");
        assert_eq!(status_message(5), "Timed out");
        assert_eq!(status_message(7), "Authentication error");
        assert_eq!(status_message(9), "Program/version mismatch");
        assert_eq!(status_message(13), "Unknown host");
        assert_eq!(status_message(17), "Unknown protocol");
    }

    #[test]
    fn status_message_out_of_range_returns_unknown() {
        assert_eq!(status_message(-1), "Unknown error");
        assert_eq!(status_message(18), "Unknown error");
        assert_eq!(status_message(99999), "Unknown error");
        assert_eq!(status_message(i32::MAX), "Unknown error");
        assert_eq!(status_message(i32::MIN), "Unknown error");
    }
}
