//! `<fmtmsg.h>` — XSI message classification and formatting.
//!
//! Pure-safe Rust port of the bit-decode and message-shape logic that
//! previously lived inline in frankenlibc-abi/src/unistd_abi.rs::fmtmsg.
//! The abi shim keeps responsibility for the variadic CStr decoding
//! and the actual stderr write.
//!
//! Output shape (matches XSI `fmtmsg`):
//!   `<label>: <SEVERITY>: <text>\nTO FIX: <action> <tag>\n`

/// Display the message on stderr (`MM_PRINT`).
pub const MM_PRINT: i64 = 0x100;
/// Display the message on the system console (`MM_CONSOLE`).
pub const MM_CONSOLE: i64 = 0x200;

/// Return `true` when [`format_fmtmsg_message`] should be written to
/// stderr for the given classification mask.
///
/// Per XSI: `MM_PRINT` selects stderr explicitly; `MM_CONSOLE` selects
/// the console. When the classification has neither output bit, the
/// caller still prints (the historical default).
#[inline]
pub fn should_print(classification: i64) -> bool {
    (classification & MM_PRINT) != 0 || (classification & (MM_PRINT | MM_CONSOLE)) == 0
}

/// Map an XSI severity code to its canonical uppercase name.
///
/// Returns the empty string for codes outside the documented range.
#[inline]
pub fn severity_name(severity: i32) -> &'static str {
    match severity {
        0 => "HALT",
        1 => "ERROR",
        2 => "WARNING",
        3 => "INFO",
        _ => "",
    }
}

/// Format a complete fmtmsg message body into a fresh `Vec<u8>`.
///
/// Empty input slices render as empty fields — the surrounding
/// `": "` separators and the `TO FIX:` line are emitted unconditionally
/// to match the XSI output shape produced by Solaris' reference
/// implementation. Field bytes are written verbatim.
pub fn format_fmtmsg_message(
    label: &[u8],
    severity: i32,
    text: &[u8],
    action: &[u8],
    tag: &[u8],
) -> Vec<u8> {
    let sev = severity_name(severity).as_bytes();
    let mut out = Vec::with_capacity(
        label.len() + 2 + sev.len() + 2 + text.len() + 1 + 7 + action.len() + 1 + tag.len() + 1,
    );
    out.extend_from_slice(label);
    out.extend_from_slice(b": ");
    out.extend_from_slice(sev);
    out.extend_from_slice(b": ");
    out.extend_from_slice(text);
    out.push(b'\n');
    out.extend_from_slice(b"TO FIX: ");
    out.extend_from_slice(action);
    out.push(b' ');
    out.extend_from_slice(tag);
    out.push(b'\n');
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn severity_names_for_known_codes() {
        assert_eq!(severity_name(0), "HALT");
        assert_eq!(severity_name(1), "ERROR");
        assert_eq!(severity_name(2), "WARNING");
        assert_eq!(severity_name(3), "INFO");
    }

    #[test]
    fn severity_unknown_codes_yield_empty() {
        assert_eq!(severity_name(-1), "");
        assert_eq!(severity_name(4), "");
        assert_eq!(severity_name(99), "");
    }

    #[test]
    fn should_print_explicit_print_bit() {
        assert!(should_print(MM_PRINT));
        assert!(should_print(MM_PRINT | MM_CONSOLE));
    }

    #[test]
    fn should_print_console_only_does_not_print_stderr() {
        // MM_CONSOLE alone selects console output, NOT stderr.
        assert!(!should_print(MM_CONSOLE));
    }

    #[test]
    fn should_print_neither_bit_defaults_to_print() {
        // Historical XSI behavior: with no output bits set, print to
        // stderr (the default). The reference fmtmsg uses this branch
        // when callers pass a classification of just severity bits.
        assert!(should_print(0));
        // Severity-bits-only (no output bits) still triggers default.
        assert!(should_print(0x10));
    }

    #[test]
    fn format_typical_message() {
        let out = format_fmtmsg_message(b"app", 2, b"disk full", b"free space", b"util:001");
        assert_eq!(
            out,
            b"app: WARNING: disk full\nTO FIX: free space util:001\n".to_vec()
        );
    }

    #[test]
    fn format_with_unknown_severity_yields_empty_sev_field() {
        let out = format_fmtmsg_message(b"app", 999, b"msg", b"do x", b"tag");
        assert_eq!(out, b"app: : msg\nTO FIX: do x tag\n".to_vec());
    }

    #[test]
    fn format_with_all_empty_optional_fields() {
        let out = format_fmtmsg_message(b"", 0, b"", b"", b"");
        // Empty fields: `: HALT: \nTO FIX:  \n`
        assert_eq!(out, b": HALT: \nTO FIX:  \n".to_vec());
    }

    #[test]
    fn format_with_only_label_and_text() {
        let out = format_fmtmsg_message(b"prog", 3, b"started", b"", b"");
        assert_eq!(out, b"prog: INFO: started\nTO FIX:  \n".to_vec());
    }

    #[test]
    fn format_always_ends_with_newline() {
        for sev in [-1, 0, 1, 2, 3, 4, 999] {
            let out = format_fmtmsg_message(b"x", sev, b"y", b"z", b"w");
            assert_eq!(out.last().copied(), Some(b'\n'));
        }
    }

    #[test]
    fn format_binary_safe_message_bytes() {
        // Embedded NULs and high bytes round-trip verbatim.
        let msg = &[1u8, 2, 0, 3, 0xff];
        let out = format_fmtmsg_message(b"app", 1, msg, b"", b"");
        assert_eq!(
            out,
            b"app: ERROR: \x01\x02\x00\x03\xff\nTO FIX:  \n".to_vec()
        );
    }
}
