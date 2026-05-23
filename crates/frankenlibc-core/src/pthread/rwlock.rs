//! POSIX reader-writer lock operations.
//!
//! Implements pthread rwlock constants and validators.
//! Actual locking is performed via libc syscalls at the ABI layer;
//! this module provides the safe-Rust validation logic.

// ---------------------------------------------------------------------------
// Rwlock kind constants
// ---------------------------------------------------------------------------

/// Default rwlock — writer preference is implementation-defined.
pub const PTHREAD_RWLOCK_DEFAULT_NP: i32 = 0;
/// Prefer readers — writers may starve.
pub const PTHREAD_RWLOCK_PREFER_READER_NP: i32 = 0;
/// Prefer writers — readers may starve.
pub const PTHREAD_RWLOCK_PREFER_WRITER_NP: i32 = 1;
/// Prefer writers, non-recursive — prevents writer starvation.
pub const PTHREAD_RWLOCK_PREFER_WRITER_NONRECURSIVE_NP: i32 = 2;

// ---------------------------------------------------------------------------
// Validators
// ---------------------------------------------------------------------------

/// Returns true if `kind` is a recognized rwlock preference.
#[must_use]
pub const fn valid_rwlock_kind(kind: i32) -> bool {
    matches!(kind, 0..=2)
}

/// Sanitize rwlock kind: if unknown, default to DEFAULT (0).
#[must_use]
pub const fn sanitize_rwlock_kind(kind: i32) -> i32 {
    if valid_rwlock_kind(kind) {
        kind
    } else {
        PTHREAD_RWLOCK_DEFAULT_NP
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rwlock_kind_constants() {
        assert_eq!(PTHREAD_RWLOCK_DEFAULT_NP, 0);
        assert_eq!(PTHREAD_RWLOCK_PREFER_READER_NP, 0);
        assert_eq!(PTHREAD_RWLOCK_PREFER_WRITER_NP, 1);
        assert_eq!(PTHREAD_RWLOCK_PREFER_WRITER_NONRECURSIVE_NP, 2);
    }

    #[test]
    fn valid_rwlock_kind_check() {
        assert!(valid_rwlock_kind(0));
        assert!(valid_rwlock_kind(1));
        assert!(valid_rwlock_kind(2));
        assert!(!valid_rwlock_kind(3));
        assert!(!valid_rwlock_kind(-1));
    }

    #[test]
    fn sanitize_rwlock_kind_check() {
        assert_eq!(sanitize_rwlock_kind(1), 1);
        assert_eq!(sanitize_rwlock_kind(99), PTHREAD_RWLOCK_DEFAULT_NP);
    }

    #[test]
    fn sanitize_rwlock_kind_extremes_default_to_default_np() {
        assert_eq!(sanitize_rwlock_kind(i32::MIN), PTHREAD_RWLOCK_DEFAULT_NP);
        assert_eq!(sanitize_rwlock_kind(i32::MAX), PTHREAD_RWLOCK_DEFAULT_NP);
    }

    // ===== glibc parity tests =====
    // Verified against glibc <pthread.h> (GNU extension constants)

    #[test]
    fn glibc_rwlock_kind_constants() {
        // rwlock preference constants must match glibc values
        assert_eq!(PTHREAD_RWLOCK_PREFER_READER_NP, 0);
        assert_eq!(PTHREAD_RWLOCK_PREFER_WRITER_NP, 1);
        assert_eq!(PTHREAD_RWLOCK_PREFER_WRITER_NONRECURSIVE_NP, 2);
        assert_eq!(PTHREAD_RWLOCK_DEFAULT_NP, 0);
    }
}
