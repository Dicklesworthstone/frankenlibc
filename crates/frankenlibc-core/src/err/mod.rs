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

    // bd-err-3: structural property tests

    #[test]
    fn property_output_starts_with_progname() {
        for progname in [&b"a"[..], b"prog", b"long_program_name_here"] {
            let out = format_err_message(progname, b"msg", None);
            assert!(
                out.starts_with(progname),
                "output {:?} should start with progname {:?}",
                String::from_utf8_lossy(&out),
                String::from_utf8_lossy(progname)
            );
        }
    }

    #[test]
    fn property_output_has_progname_separator() {
        // Every non-empty output should contain ": " somewhere after
        // the progname.
        for progname in [&b"prog"[..], b"foo"] {
            for msg in [&b""[..], b"msg"] {
                for errno in [None, Some(b"err".as_slice())] {
                    let out = format_err_message(progname, msg, errno);
                    let head_sep = &out[progname.len()..progname.len() + 2];
                    assert_eq!(
                        head_sep, b": ",
                        "expected ': ' separator after progname in {:?}",
                        String::from_utf8_lossy(&out)
                    );
                }
            }
        }
    }

    #[test]
    fn property_no_double_separator_on_empty_message_with_errno() {
        // Specifically: "prog: : err\n" (double ': ') is forbidden.
        let out = format_err_message(b"prog", b"", Some(b"e"));
        let txt = String::from_utf8(out).unwrap();
        assert!(!txt.contains(": : "), "got: {txt:?}");
        assert_eq!(txt, "prog: e\n");
    }

    #[test]
    fn property_total_length_predictable() {
        // Length = progname + 2 + (msg.len if non-empty) + (sep ": " if msg+errno) + (errno.len if any) + 1 (newline)
        for (progname, msg, errno) in [
            (&b"prog"[..], &b""[..], None),
            (b"prog", b"hi", None),
            (b"prog", b"", Some(b"e".as_slice())),
            (b"prog", b"hi", Some(b"e".as_slice())),
        ] {
            let mut expected = progname.len() + 2 + msg.len();
            if !msg.is_empty() && errno.is_some() {
                expected += 2; // ": " separator
            }
            if let Some(e) = errno {
                expected += e.len();
            }
            expected += 1; // newline
            let out = format_err_message(progname, msg, errno);
            assert_eq!(
                out.len(),
                expected,
                "len mismatch for ({:?}, {:?}, {:?}): got {:?}",
                String::from_utf8_lossy(progname),
                String::from_utf8_lossy(msg),
                errno.map(|e| String::from_utf8_lossy(e).into_owned()),
                String::from_utf8_lossy(&out)
            );
        }
    }
}
