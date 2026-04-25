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
pub const EAI_FAMILY: i32 = -6;
pub const EAI_SOCKTYPE: i32 = -7;
pub const EAI_SERVICE: i32 = -8;
pub const EAI_OVERFLOW: i32 = -12;

/// Canonical glibc message for a `getaddrinfo` error code.
///
/// Returns `"Success"` for `0`, the matching message for each known
/// `EAI_*` code, and `"Unknown getaddrinfo error"` for any other
/// value.
pub fn gai_strerror_text(errcode: i32) -> &'static str {
    match errcode {
        0 => "Success",
        EAI_AGAIN => "Temporary failure in name resolution",
        EAI_BADFLAGS => "Invalid value for ai_flags",
        EAI_FAIL => "Non-recoverable failure in name resolution",
        EAI_FAMILY => "ai_family not supported",
        EAI_NONAME => "Name or service not known",
        EAI_SERVICE => "Service not supported for socket type",
        EAI_SOCKTYPE => "Socket type not supported",
        EAI_OVERFLOW => "Argument buffer overflow",
        _ => "Unknown getaddrinfo error",
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
/// Returns the matching description for each documented code and
/// `"Resolver internal error"` for any other value (including the 0
/// "no error" case, since `hstrerror(0)` historically returned the
/// internal-error fallback rather than success).
pub fn hstrerror_text(err: i32) -> &'static str {
    match err {
        H_ERR_HOST_NOT_FOUND => "Unknown host",
        H_ERR_TRY_AGAIN => "Host name lookup failure",
        H_ERR_NO_RECOVERY => "Unknown server error",
        H_ERR_NO_DATA => "No address associated with name",
        _ => "Resolver internal error",
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
        assert_eq!(
            gai_strerror_text(EAI_BADFLAGS),
            "Invalid value for ai_flags"
        );
        assert_eq!(
            gai_strerror_text(EAI_FAIL),
            "Non-recoverable failure in name resolution"
        );
        assert_eq!(gai_strerror_text(EAI_FAMILY), "ai_family not supported");
        assert_eq!(gai_strerror_text(EAI_NONAME), "Name or service not known");
        assert_eq!(
            gai_strerror_text(EAI_SERVICE),
            "Service not supported for socket type"
        );
        assert_eq!(gai_strerror_text(EAI_SOCKTYPE), "Socket type not supported");
        assert_eq!(gai_strerror_text(EAI_OVERFLOW), "Argument buffer overflow");
    }

    #[test]
    fn gai_unknown_code_returns_fallback() {
        for code in [-99, 1, 100, i32::MIN, i32::MAX] {
            assert_eq!(
                gai_strerror_text(code),
                "Unknown getaddrinfo error",
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
    fn hstrerror_unknown_code_returns_fallback() {
        // Including 0 — historical hstrerror(0) returns the internal-error fallback.
        for code in [0, -1, 5, 99, i32::MIN, i32::MAX] {
            assert_eq!(
                hstrerror_text(code),
                "Resolver internal error",
                "code {code} did not return fallback"
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
