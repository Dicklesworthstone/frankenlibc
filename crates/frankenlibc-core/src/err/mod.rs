//! BSD/GNU `<err.h>` diagnostic message formatting.
//!
//! Pure-safe Rust port of the message-shape logic that previously
//! lived in frankenlibc-abi/src/err_abi.rs::write_err_message. The
//! abi layer keeps responsibility for the variadic + printf
//! integration, the strerror lookup, the fd-2 write, and the exit()
//! dispatch for `err`/`errx`. This module produces the formatted
//! bytes only.
//!
//! Output shape (matches glibc/BSD <err.h>):
//!   `<progname>: <message>: <errno_msg>\n`     (warn/err)
//!   `<progname>: <message>\n`                  (warnx/errx)
//!   `<progname>: <errno_msg>\n`                (warn with empty fmt)
//!   `<progname>: \n`                           (warnx with empty fmt)

/// Strip the path prefix from a basename-like sequence of bytes.
///
/// Returns the slice after the last `/` byte, or the whole input
/// if there is no `/`. Used by progname resolution to convert
/// argv[0] = "/usr/bin/foo" → "foo".
pub fn basename_bytes(bytes: &[u8]) -> &[u8] {
    bytes
        .iter()
        .rposition(|&b| b == b'/')
        .map_or(bytes, |idx| &bytes[idx + 1..])
}

/// Format an err.h-style diagnostic message.
///
/// `progname` is the (already-basenamed) program name.
/// `message` is the user's pre-rendered printf result; pass an
/// empty slice to suppress the message portion.
/// `errno_msg`, when `Some`, is appended after the message with a
/// `": "` separator (or directly after `progname: ` when message
/// is empty). Pass `None` for warnx/errx-style "no errno" output.
///
/// Always appends a trailing `\n`.
pub fn format_err_message(
    progname: &[u8],
    message: &[u8],
    errno_msg: Option<&[u8]>,
) -> Vec<u8> {
    let mut out =
        Vec::with_capacity(progname.len() + 2 + message.len() + 2 + errno_msg.map_or(0, |s| s.len()) + 1);
    out.extend_from_slice(progname);
    out.extend_from_slice(b": ");
    if !message.is_empty() {
        out.extend_from_slice(message);
    }
    if let Some(errno_str) = errno_msg {
        if !message.is_empty() {
            out.extend_from_slice(b": ");
        }
        out.extend_from_slice(errno_str);
    }
    out.push(b'\n');
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn basename_strips_dirs() {
        assert_eq!(basename_bytes(b"/usr/bin/foo"), b"foo");
        assert_eq!(basename_bytes(b"foo"), b"foo");
        assert_eq!(basename_bytes(b"a/b/c/d"), b"d");
        assert_eq!(basename_bytes(b""), b"");
        assert_eq!(basename_bytes(b"/"), b"");
        assert_eq!(basename_bytes(b"/foo"), b"foo");
    }

    #[test]
    fn warnx_message_only() {
        let out = format_err_message(b"prog", b"some message", None);
        assert_eq!(out, b"prog: some message\n");
    }

    #[test]
    fn warn_message_with_errno() {
        let out = format_err_message(b"prog", b"open failed", Some(b"No such file or directory"));
        assert_eq!(
            out,
            b"prog: open failed: No such file or directory\n".to_vec()
        );
    }

    #[test]
    fn warn_empty_message_with_errno_no_double_separator() {
        let out = format_err_message(b"prog", b"", Some(b"Permission denied"));
        // No ": " between progname's ': ' and the errno message
        assert_eq!(out, b"prog: Permission denied\n".to_vec());
    }

    #[test]
    fn warnx_empty_message_no_errno() {
        let out = format_err_message(b"prog", b"", None);
        assert_eq!(out, b"prog: \n".to_vec());
    }

    #[test]
    fn always_ends_with_newline() {
        for msg in [&b""[..], b"x", b"hello world"] {
            for errno_msg in [None, Some(&b""[..]), Some(b"err".as_slice())] {
                let out = format_err_message(b"prog", msg, errno_msg);
                assert_eq!(out.last().copied(), Some(b'\n'));
            }
        }
    }

    #[test]
    fn empty_progname_still_produces_separator() {
        let out = format_err_message(b"", b"x", None);
        assert_eq!(out, b": x\n".to_vec());
    }

    #[test]
    fn binary_safe_message_bytes() {
        let msg = &[1u8, 2, 0, 3, 4]; // embedded NUL is preserved
        let out = format_err_message(b"prog", msg, None);
        assert_eq!(out, b"prog: \x01\x02\x00\x03\x04\n".to_vec());
    }
}
