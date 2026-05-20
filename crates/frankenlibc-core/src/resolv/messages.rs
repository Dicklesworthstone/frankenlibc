//! Resolver error-message lookup tables.
//!
//! Pure-safe Rust port of two small constant-table message lookups
//! that previously lived inline in the abi:
//!   - `gai_strerror` (resolv_abi.rs) — EAI_* code → glibc message
//!   - `hstrerror_message_ptr` (unistd_abi.rs) — h_errno code →
//!     glibc message
//!
//! The abi shims wrap these strings in static `*const c_char` storage
//! at the boundary; this module returns plain `&'static str`.

// --- getaddrinfo / EAI_* constants -----------------------------------------
// Values match glibc's <netdb.h>.

pub const EAI_BADFLAGS: i32 = -1;
pub const EAI_NONAME: i32 = -2;
pub const EAI_AGAIN: i32 = -3;
pub const EAI_FAIL: i32 = -4;
pub const EAI_NODATA: i32 = -5;
pub const EAI_FAMILY: i32 = -6;
pub const EAI_SOCKTYPE: i32 = -7;
pub const EAI_SERVICE: i32 = -8;
pub const EAI_ADDRFAMILY: i32 = -9;
pub const EAI_MEMORY: i32 = -10;
pub const EAI_SYSTEM: i32 = -11;
pub const EAI_OVERFLOW: i32 = -12;

/// Canonical glibc message for a `getaddrinfo` error code.
///
/// Returns `"Success"` for `0`, the matching message for each known
/// `EAI_*` code, and `"Unknown error"` for any other value — exactly
/// what glibc's `gai_strerror` returns.
pub fn gai_strerror_text(errcode: i32) -> &'static str {
    match errcode {
        0 => "Success",
        EAI_AGAIN => "Temporary failure in name resolution",
        EAI_BADFLAGS => "Bad value for ai_flags",
        EAI_FAIL => "Non-recoverable failure in name resolution",
        EAI_NODATA => "No address associated with hostname",
        EAI_FAMILY => "ai_family not supported",
        EAI_ADDRFAMILY => "Address family for hostname not supported",
        EAI_NONAME => "Name or service not known",
        EAI_SERVICE => "Servname not supported for ai_socktype",
        EAI_SOCKTYPE => "ai_socktype not supported",
        EAI_MEMORY => "Memory allocation failure",
        EAI_SYSTEM => "System error",
        EAI_OVERFLOW => "Result too large for supplied buffer",
        _ => "Unknown error",
    }
}

// --- h_errno / H_ERR_* constants -------------------------------------------
// Values match glibc's <netdb.h>.

pub const H_ERR_HOST_NOT_FOUND: i32 = 1;
pub const H_ERR_TRY_AGAIN: i32 = 2;
pub const H_ERR_NO_RECOVERY: i32 = 3;
pub const H_ERR_NO_DATA: i32 = 4;

/// Canonical glibc message for a legacy resolver `h_errno` value.
///
/// Mirrors glibc's `hstrerror` exactly: negative codes are the
/// `"Resolver internal error"` case, `0` is `"Resolver Error 0 (no
/// error)"`, codes `1..=4` have their documented descriptions, and
/// anything `>= 5` is `"Unknown resolver error"`.
pub fn hstrerror_text(err: i32) -> &'static str {
    match err {
        H_ERR_HOST_NOT_FOUND => "Unknown host",
        H_ERR_TRY_AGAIN => "Host name lookup failure",
        H_ERR_NO_RECOVERY => "Unknown server error",
        H_ERR_NO_DATA => "No address associated with name",
        0 => "Resolver Error 0 (no error)",
        n if n < 0 => "Resolver internal error",
        _ => "Unknown resolver error",
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // ---- gai_strerror_text ----

    #[test]
    fn gai_zero_is_success() {
        assert_eq!(gai_strerror_text(0), "Success");
    }

    #[test]
    fn gai_known_codes_match_glibc_text() {
        assert_eq!(
            gai_strerror_text(EAI_AGAIN),
            "Temporary failure in name resolution"
        );
        assert_eq!(gai_strerror_text(EAI_BADFLAGS), "Bad value for ai_flags");
        assert_eq!(
            gai_strerror_text(EAI_FAIL),
            "Non-recoverable failure in name resolution"
        );
        assert_eq!(
            gai_strerror_text(EAI_NODATA),
            "No address associated with hostname"
        );
        assert_eq!(gai_strerror_text(EAI_FAMILY), "ai_family not supported");
        assert_eq!(
            gai_strerror_text(EAI_ADDRFAMILY),
            "Address family for hostname not supported"
        );
        assert_eq!(gai_strerror_text(EAI_NONAME), "Name or service not known");
        assert_eq!(
            gai_strerror_text(EAI_SERVICE),
            "Servname not supported for ai_socktype"
        );
        assert_eq!(gai_strerror_text(EAI_SOCKTYPE), "ai_socktype not supported");
        assert_eq!(gai_strerror_text(EAI_MEMORY), "Memory allocation failure");
        assert_eq!(gai_strerror_text(EAI_SYSTEM), "System error");
        assert_eq!(
            gai_strerror_text(EAI_OVERFLOW),
            "Result too large for supplied buffer"
        );
    }

    #[test]
    fn gai_unknown_code_returns_fallback() {
        for code in [-99, 1, 100, i32::MIN, i32::MAX] {
            assert_eq!(
                gai_strerror_text(code),
                "Unknown error",
                "code {code} did not return fallback"
            );
        }
    }

    #[test]
    fn gai_eai_constants_match_glibc_values() {
        // Pin the constant values so future maintainers don't drift
        // them silently away from <netdb.h>.
        assert_eq!(EAI_BADFLAGS, -1);
        assert_eq!(EAI_NONAME, -2);
        assert_eq!(EAI_AGAIN, -3);
        assert_eq!(EAI_FAIL, -4);
        assert_eq!(EAI_FAMILY, -6);
        assert_eq!(EAI_SOCKTYPE, -7);
        assert_eq!(EAI_SERVICE, -8);
        assert_eq!(EAI_ADDRFAMILY, -9);
        assert_eq!(EAI_OVERFLOW, -12);
    }

    // ---- hstrerror_text ----

    #[test]
    fn hstrerror_known_codes_match_glibc_text() {
        assert_eq!(hstrerror_text(H_ERR_HOST_NOT_FOUND), "Unknown host");
        assert_eq!(hstrerror_text(H_ERR_TRY_AGAIN), "Host name lookup failure");
        assert_eq!(hstrerror_text(H_ERR_NO_RECOVERY), "Unknown server error");
        assert_eq!(
            hstrerror_text(H_ERR_NO_DATA),
            "No address associated with name"
        );
    }

    #[test]
    fn hstrerror_zero_is_resolver_error_zero() {
        // glibc `hstrerror(0)` is its own distinct string, not the
        // negative-code internal-error fallback.
        assert_eq!(hstrerror_text(0), "Resolver Error 0 (no error)");
    }

    #[test]
    fn hstrerror_negative_codes_are_internal_error() {
        for code in [-1, -2, -99, i32::MIN] {
            assert_eq!(
                hstrerror_text(code),
                "Resolver internal error",
                "negative code {code} should be the internal-error case"
            );
        }
    }

    #[test]
    fn hstrerror_codes_above_four_are_unknown_resolver_error() {
        // glibc returns "Unknown resolver error" for h_errno >= 5,
        // distinct from the negative-code "Resolver internal error".
        for code in [5, 6, 99, i32::MAX] {
            assert_eq!(
                hstrerror_text(code),
                "Unknown resolver error",
                "code {code} should be the unknown-resolver-error case"
            );
        }
    }

    #[test]
    fn h_err_constants_match_glibc_values() {
        assert_eq!(H_ERR_HOST_NOT_FOUND, 1);
        assert_eq!(H_ERR_TRY_AGAIN, 2);
        assert_eq!(H_ERR_NO_RECOVERY, 3);
        assert_eq!(H_ERR_NO_DATA, 4);
    }
}
