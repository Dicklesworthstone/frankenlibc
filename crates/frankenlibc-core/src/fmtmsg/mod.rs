//! `<fmtmsg.h>` — XSI message classification and formatting.
//!
//! Pure-safe Rust port of the bit-decode and message-shape logic that
//! previously lived inline in frankenlibc-abi/src/unistd_abi.rs::fmtmsg.
//! The abi shim keeps responsibility for the variadic CStr decoding
//! and the actual stderr write.
//!
//! Output shape follows glibc `<fmtmsg.h>`:
//!   `<label>: <SEVERITY>: <text>\nTO FIX: <action>  <tag>\n`

/// Display the message on stderr (`MM_PRINT`).
pub const MM_PRINT: i64 = 0x100;
/// Display the message on the system console (`MM_CONSOLE`).
pub const MM_CONSOLE: i64 = 0x200;

/// Return `true` when [`format_fmtmsg_message`] should be written to
/// stderr for the given classification mask.
///
/// `MM_PRINT` selects stderr explicitly. `MM_CONSOLE` alone is not stderr,
/// and a null classification does not emit anything.
#[inline]
pub fn should_print(classification: i64) -> bool {
    (classification & MM_PRINT) != 0
}

/// Map an XSI severity code to its canonical uppercase name.
///
/// Returns `None` for `MM_NOSEV` and for codes outside the documented range.
#[inline]
pub fn severity_name(severity: i32) -> Option<&'static str> {
    match severity {
        1 => Some("HALT"),
        2 => Some("ERROR"),
        3 => Some("WARNING"),
        4 => Some("INFO"),
        _ => None,
    }
}

/// Return `true` for XSI-defined severity codes.
#[inline]
pub fn valid_severity(severity: i32) -> bool {
    (0..=4).contains(&severity)
}

/// Return `true` for labels accepted by glibc `fmtmsg`.
///
/// A non-null label must contain a `:` delimiter. The bytes before the first
/// delimiter are capped at 10 bytes; the bytes after it are capped at 14 bytes.
/// Empty components are valid (`":"`, `"cmd:"`, and `":sub"` all pass).
#[inline]
pub fn valid_label(label: &[u8]) -> bool {
    if label.is_empty() {
        return false;
    }
    let Some(colon) = label.iter().position(|b| *b == b':') else {
        return false;
    };
    let right_len = label.get(colon + 1..).map_or(usize::MAX, <[u8]>::len);
    colon <= 10 && right_len <= 14
}

/// Format a complete fmtmsg message body into a fresh `Vec<u8>`.
///
/// `None` fields follow the glibc null-field shape. Empty non-null fields are
/// emitted as empty content. Field bytes are written verbatim.
pub fn format_fmtmsg_message(
    label: Option<&[u8]>,
    severity: i32,
    text: Option<&[u8]>,
    action: Option<&[u8]>,
    tag: Option<&[u8]>,
) -> Vec<u8> {
    let sev = severity_name(severity).map(str::as_bytes);
    format_fmtmsg_message_named(label, sev, text, action, tag)
}

/// Same as [`format_fmtmsg_message`] but with the severity LABEL resolved by the
/// caller, so that custom severities registered via `addseverity` (which live in
/// the ABI layer, not this crate) can supply their own name. Pass `None` for
/// `MM_NOSEV` (severity 0), where no severity component is emitted.
pub fn format_fmtmsg_message_named(
    label: Option<&[u8]>,
    sev: Option<&[u8]>,
    text: Option<&[u8]>,
    action: Option<&[u8]>,
    tag: Option<&[u8]>,
) -> Vec<u8> {
    let later_after_label = sev.is_some() || text.is_some() || action.is_some() || tag.is_some();
    let later_after_severity = text.is_some() || action.is_some() || tag.is_some();
    let mut out = Vec::with_capacity(
        label.map_or(0, <[u8]>::len)
            + sev.map_or(0, <[u8]>::len)
            + text.map_or(0, <[u8]>::len)
            + action.map_or(0, <[u8]>::len)
            + tag.map_or(0, <[u8]>::len)
            + 32,
    );

    if let Some(label) = label {
        out.extend_from_slice(label);
        if later_after_label {
            out.extend_from_slice(b": ");
        }
    }
    if let Some(sev) = sev {
        out.extend_from_slice(sev);
        if later_after_severity {
            out.extend_from_slice(b": ");
        }
    }
    if let Some(text) = text {
        out.extend_from_slice(text);
        out.push(b'\n');
    }
    if let Some(action) = action {
        out.extend_from_slice(b"TO FIX: ");
        out.extend_from_slice(action);
        if let Some(tag) = tag {
            out.extend_from_slice(b"  ");
            out.extend_from_slice(tag);
        }
        out.push(b'\n');
    } else if let Some(tag) = tag {
        out.extend_from_slice(tag);
        out.push(b'\n');
    } else if text.is_none() {
        out.push(b'\n');
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn severity_names_for_known_codes() {
        assert_eq!(severity_name(1), Some("HALT"));
        assert_eq!(severity_name(2), Some("ERROR"));
        assert_eq!(severity_name(3), Some("WARNING"));
        assert_eq!(severity_name(4), Some("INFO"));
    }

    #[test]
    fn severity_unknown_codes_yield_empty() {
        assert_eq!(severity_name(-1), None);
        assert_eq!(severity_name(0), None);
        assert_eq!(severity_name(5), None);
        assert_eq!(severity_name(99), None);
    }

    #[test]
    fn severity_validation_accepts_xsi_range_only() {
        for severity in 0..=4 {
            assert!(valid_severity(severity));
        }
        assert!(!valid_severity(-1));
        assert!(!valid_severity(5));
    }

    #[test]
    fn label_validation_matches_glibc_shape() {
        for label in [b":".as_slice(), b"a:", b":b", b"a:b", b"a:b:c"] {
            assert!(valid_label(label), "{label:?}");
        }
        assert!(!valid_label(b""));
        assert!(!valid_label(b"app"));
        assert!(!valid_label(b"aaaaaaaaaaa:x"));
        assert!(!valid_label(b"aaaaaaaaaa:bbbbbbbbbbbbbbb"));
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
    fn should_print_neither_bit_does_not_print_stderr() {
        assert!(!should_print(0));
        assert!(!should_print(0x10));
    }

    #[test]
    fn format_typical_message() {
        let out = format_fmtmsg_message(
            Some(b"UX:app"),
            3,
            Some(b"disk full"),
            Some(b"free space"),
            Some(b"util:001"),
        );
        assert_eq!(
            out,
            b"UX:app: WARNING: disk full\nTO FIX: free space  util:001\n".to_vec()
        );
    }

    #[test]
    fn format_with_no_severity_omits_severity_field() {
        let out = format_fmtmsg_message(
            Some(b"UX:app"),
            0,
            Some(b"msg"),
            Some(b"do x"),
            Some(b"tag"),
        );
        assert_eq!(out, b"UX:app: msg\nTO FIX: do x  tag\n".to_vec());
    }

    #[test]
    fn format_with_all_empty_optional_fields() {
        let out = format_fmtmsg_message(Some(b":"), 1, Some(b""), Some(b""), Some(b""));
        assert_eq!(out, b":: HALT: \nTO FIX:   \n".to_vec());
    }

    #[test]
    fn format_with_only_label_and_text() {
        let out = format_fmtmsg_message(Some(b"prog:msg"), 4, Some(b"started"), None, None);
        assert_eq!(out, b"prog:msg: INFO: started\n".to_vec());
    }

    #[test]
    fn format_with_null_text_places_action_on_same_line() {
        let out = format_fmtmsg_message(
            Some(b"UX:app"),
            2,
            None,
            Some(b"free space"),
            Some(b"util:001"),
        );
        assert_eq!(
            out,
            b"UX:app: ERROR: TO FIX: free space  util:001\n".to_vec()
        );
    }

    #[test]
    fn format_with_action_or_tag_null_matches_glibc() {
        let action_null =
            format_fmtmsg_message(Some(b"UX:app"), 2, Some(b"msg"), None, Some(b"tag"));
        assert_eq!(action_null, b"UX:app: ERROR: msg\ntag\n".to_vec());

        let tag_null = format_fmtmsg_message(Some(b"UX:app"), 2, Some(b"msg"), Some(b"act"), None);
        assert_eq!(tag_null, b"UX:app: ERROR: msg\nTO FIX: act\n".to_vec());
    }

    #[test]
    fn format_all_null_fields_is_single_newline() {
        let out = format_fmtmsg_message(None, 0, None, None, None);
        assert_eq!(out, b"\n".to_vec());
    }

    #[test]
    fn format_label_only_has_no_separator() {
        let out = format_fmtmsg_message(Some(b"UX:app"), 0, None, None, None);
        assert_eq!(out, b"UX:app\n".to_vec());
    }

    #[test]
    fn format_with_label_null_starts_at_severity() {
        let out = format_fmtmsg_message(None, 2, Some(b"started"), Some(b"restart"), Some(b"t:1"));
        assert_eq!(out, b"ERROR: started\nTO FIX: restart  t:1\n".to_vec());
    }

    #[test]
    fn format_always_ends_with_newline() {
        for sev in 0..=4 {
            let out = format_fmtmsg_message(Some(b"x:y"), sev, Some(b"y"), Some(b"z"), Some(b"w"));
            assert_eq!(out.last().copied(), Some(b'\n'));
        }
    }

    #[test]
    fn format_binary_safe_message_bytes() {
        // Embedded NULs and high bytes round-trip verbatim.
        let msg = &[1u8, 2, 0, 3, 0xff];
        let out = format_fmtmsg_message(Some(b"a:b"), 2, Some(msg), Some(b""), Some(b""));
        assert_eq!(
            out,
            b"a:b: ERROR: \x01\x02\x00\x03\xff\nTO FIX:   \n".to_vec()
        );
    }
}
