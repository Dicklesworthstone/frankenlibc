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

use std::collections::TryReserveError;
use std::ffi::CStr;

/// Bounded native ONC RPC message envelopes.
pub mod wire;

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
    // Rust's `str::parse::<i32>` is the wrong rule in BOTH directions here: it
    // accepts "-1", which glibc refuses, and refuses "2147483648", which glibc
    // yields as -2147483648. Shared with /etc/protocols, which has the same
    // rule and had drifted from it differently.
    let number = crate::resolv::parse_nss_int32_field(fields.next()?)?;
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
/// The terminating NUL and static lifetime support the public `clnt_sperrno`
/// contract without mutable scratch storage. These are the C-locale messages.
pub fn status_message(stat: i32) -> &'static CStr {
    match stat {
        0 => c"RPC: Success",
        1 => c"RPC: Can't encode arguments",
        2 => c"RPC: Can't decode result",
        3 => c"RPC: Unable to send",
        4 => c"RPC: Unable to receive",
        5 => c"RPC: Timed out",
        6 => c"RPC: Incompatible versions of RPC",
        7 => c"RPC: Authentication error",
        8 => c"RPC: Program unavailable",
        9 => c"RPC: Program/version mismatch",
        10 => c"RPC: Procedure unavailable",
        11 => c"RPC: Server can't decode arguments",
        12 => c"RPC: Remote system error",
        13 => c"RPC: Unknown host",
        14 => c"RPC: Port mapper failure",
        15 => c"RPC: Program not registered",
        16 => c"RPC: Failed (unspecified error)",
        17 => c"RPC: Unknown protocol",
        _ => c"RPC: (unknown error code)",
    }
}

fn diagnostic_start(prefix: &[u8], status: i32, extra: usize) -> Result<Vec<u8>, TryReserveError> {
    let mut output = Vec::new();
    // The fixed allowance covers the status, separators, two 20-digit words,
    // authentication text, newline and NUL. Reserve before any append so an
    // allocation failure is a Result, not an abort in the formatting path.
    output.try_reserve_exact(prefix.len().saturating_add(extra).saturating_add(256))?;
    output.extend_from_slice(prefix);
    output.extend_from_slice(b": ");
    output.extend_from_slice(status_message(status).to_bytes());
    Ok(output)
}

fn diagnostic_unsigned(output: &mut Vec<u8>, mut value: u64) {
    let mut digits = [0u8; 20];
    let mut start = digits.len();
    loop {
        start -= 1;
        digits[start] = b'0' + (value % 10) as u8;
        value /= 10;
        if value == 0 {
            break;
        }
    }
    output.extend_from_slice(&digits[start..]);
}

fn diagnostic_signed(output: &mut Vec<u8>, value: i32) {
    if value < 0 {
        output.push(b'-');
    }
    diagnostic_unsigned(output, i64::from(value).unsigned_abs());
}

fn diagnostic_errno(output: &mut Vec<u8>, value: i32, description: Option<&[u8]>) {
    if let Some(description) = description {
        output.extend_from_slice(description);
    } else {
        output.extend_from_slice(b"Unknown error ");
        diagnostic_signed(output, value);
    }
}

/// Format a GNU LP64 CLIENT last error as NUL-terminated C-locale bytes.
/// Prefixes remain arbitrary bytes. Version/unknown statuses omit a newline;
/// the other statuses include one. The two words are the copied error union.
pub fn client_error_message(
    prefix: &[u8],
    status: i32,
    words: [u64; 2],
    errno_description: Option<&[u8]>,
) -> Result<Vec<u8>, TryReserveError> {
    let mut output = diagnostic_start(prefix, status, errno_description.map_or(0, <[u8]>::len))?;
    match status {
        3 | 4 => {
            output.extend_from_slice(b"; errno = ");
            diagnostic_errno(&mut output, words[0] as i32, errno_description);
            output.push(b'\n');
        }
        6 | 9 => {
            output.extend_from_slice(b"; low version = ");
            diagnostic_unsigned(&mut output, words[0]);
            output.extend_from_slice(b", high version = ");
            diagnostic_unsigned(&mut output, words[1]);
        }
        7 => {
            output.extend_from_slice(b"; why = ");
            let why = words[0] as i32;
            let known: Option<&[u8]> = match why {
                0 => Some(b"Authentication OK"),
                1 => Some(b"Invalid client credential"),
                2 => Some(b"Server rejected credential"),
                3 => Some(b"Invalid client verifier"),
                4 => Some(b"Server rejected verifier"),
                5 => Some(b"Client credential too weak"),
                6 => Some(b"Invalid server verifier"),
                7 => Some(b"Failed (unspecified error)"),
                _ => None,
            };
            if let Some(message) = known {
                output.extend_from_slice(message);
            } else {
                output.extend_from_slice(b"(unknown authentication error - ");
                diagnostic_signed(&mut output, why);
                output.push(b')');
            }
            output.push(b'\n');
        }
        0..=17 => output.push(b'\n'),
        _ => {
            output.extend_from_slice(b"; s1 = ");
            diagnostic_unsigned(&mut output, words[0]);
            output.extend_from_slice(b", s2 = ");
            diagnostic_unsigned(&mut output, words[1]);
        }
    }
    output.push(0);
    Ok(output)
}

/// Format a GNU creation error, including its nested mapper/system failure.
/// The result includes a newline and terminating NUL, without prefix truncation.
pub fn creation_error_message(
    prefix: &[u8],
    status: i32,
    nested_status: i32,
    error_number: i32,
    errno_description: Option<&[u8]>,
) -> Result<Vec<u8>, TryReserveError> {
    let mut output = diagnostic_start(prefix, status, errno_description.map_or(0, <[u8]>::len))?;
    if status == 14 {
        output.extend_from_slice(b" - ");
        output.extend_from_slice(status_message(nested_status).to_bytes());
    } else if status == 12 {
        output.extend_from_slice(b" - ");
        diagnostic_errno(&mut output, error_number, errno_description);
    }
    output.extend_from_slice(b"\n\0");
    Ok(output)
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
    fn parse_rejects_negative_program_number() {
        // "technically representable" is not the same as "spellable". glibc
        // reads the field with strtoul, so a '-' fails the conversion and the
        // whole line is refused — measured by binding a synthetic /etc/rpc over
        // the real one and walking getrpcent: "negnum -1" never appears. The
        // field IS a signed int, and a negative value can only arrive there by
        // wrapping a large unsigned one (see the next test).
        assert!(parse_rpc_line(b"weird -1").is_none());
    }

    #[test]
    fn parse_program_number_limits() {
        assert_eq!(parse_rpc_line(b"max 2147483647").unwrap().number, i32::MAX);
        // 2^31 is ACCEPTED and arrives negative: the digits are read unsigned
        // and stored in an int. Measured on the host, "intmaxplus 2147483648"
        // comes back as -2147483648. This previously asserted `.is_none()`.
        assert_eq!(parse_rpc_line(b"min 2147483648").unwrap().number, i32::MIN);
        assert_eq!(parse_rpc_line(b"plus +123").unwrap().number, 123);
    }

    #[test]
    fn parse_rejects_program_number_past_32_bits_and_bare_sign() {
        // 2^32 and beyond do not fit and ARE refused — "overflow 4294967296"
        // and "huge 99999999999" are both absent from getrpcent's output, which
        // is what bounds the wrap above.
        assert!(parse_rpc_line(b"too-big 4294967296").is_none());
        assert!(parse_rpc_line(b"huge 99999999999").is_none());
        assert!(parse_rpc_line(b"too-small -2147483649").is_none());
        assert!(parse_rpc_line(b"bare-plus +").is_none());
        assert!(parse_rpc_line(b"bare-minus -").is_none());
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
        assert_eq!(status_message(0), c"RPC: Success");
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
        assert_eq!(status_message(1), c"RPC: Can't encode arguments");
        assert_eq!(status_message(5), c"RPC: Timed out");
        assert_eq!(status_message(7), c"RPC: Authentication error");
        assert_eq!(status_message(9), c"RPC: Program/version mismatch");
        assert_eq!(status_message(13), c"RPC: Unknown host");
        assert_eq!(status_message(17), c"RPC: Unknown protocol");
    }

    #[test]
    fn status_message_out_of_range_returns_unknown() {
        assert_eq!(status_message(-1), c"RPC: (unknown error code)");
        assert_eq!(status_message(18), c"RPC: (unknown error code)");
        assert_eq!(status_message(99999), c"RPC: (unknown error code)");
        assert_eq!(status_message(i32::MAX), c"RPC: (unknown error code)");
        assert_eq!(status_message(i32::MIN), c"RPC: (unknown error code)");
    }

    #[test]
    fn diagnostic_preserves_raw_long_prefixes_and_terminators() {
        let prefix = vec![0xff; 100_000];
        let message = client_error_message(&prefix, 2, [0; 2], None).unwrap();
        assert_eq!(&message[..prefix.len()], prefix);
        assert_eq!(&message[prefix.len()..], b": RPC: Can't decode result\n\0");
        let message = creation_error_message(&[], 14, 5, 0, None).unwrap();
        assert_eq!(message, b": RPC: Port mapper failure - RPC: Timed out\n\0");
    }

    #[test]
    fn diagnostic_integer_extremes_are_not_truncated_or_signed() {
        let message = client_error_message(b"v", 9, [u64::MAX, 0], None).unwrap();
        assert_eq!(message, b"v: RPC: Program/version mismatch; low version = 18446744073709551615, high version = 0\0");
        let message = client_error_message(b"a", 7, [i32::MIN as u32 as u64, 0], None).unwrap();
        assert_eq!(
            message,
            b"a: RPC: Authentication error; why = (unknown authentication error - -2147483648)\n\0"
        );
        let message = client_error_message(b"u", -1, [0, u64::MAX], None).unwrap();
        assert_eq!(
            message,
            b"u: RPC: (unknown error code); s1 = 0, s2 = 18446744073709551615\0"
        );
    }

    #[test]
    fn diagnostic_errno_and_creation_details_have_distinct_contracts() {
        let message = client_error_message(b"io", 3, [13, 0], Some(b"Permission denied")).unwrap();
        assert_eq!(
            message,
            b"io: RPC: Unable to send; errno = Permission denied\n\0"
        );
        let message = client_error_message(b"io", 4, [i32::MIN as u32 as u64, 0], None).unwrap();
        assert_eq!(
            message,
            b"io: RPC: Unable to receive; errno = Unknown error -2147483648\n\0"
        );
        let message = creation_error_message(b"create", 12, 0, -17, None).unwrap();
        assert_eq!(
            message,
            b"create: RPC: Remote system error - Unknown error -17\n\0"
        );
    }
}
