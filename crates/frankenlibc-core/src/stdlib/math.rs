//! Integer math utility functions.
//!
//! Implements `abs`, `labs`, `llabs`, `div`, `ldiv`, `lldiv`,
//! `ffs`, `ffsl`, `ffsll` from `<stdlib.h>` and `<strings.h>`.

/// Result of integer division (quotient and remainder).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(C)]
pub struct DivResult {
    pub quot: i32,
    pub rem: i32,
}

/// Result of long integer division.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(C)]
pub struct LdivResult {
    pub quot: i64,
    pub rem: i64,
}

/// Result of long long integer division.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(C)]
pub struct LldivResult {
    pub quot: i64,
    pub rem: i64,
}

/// Returns the absolute value of `n`.
pub fn abs(n: i32) -> i32 {
    n.wrapping_abs()
}

/// Returns the absolute value of `n` (long version).
pub fn labs(n: i64) -> i64 {
    n.wrapping_abs()
}

/// Returns the absolute value of `n` (long long version).
pub fn llabs(n: i64) -> i64 {
    n.wrapping_abs()
}

/// Computes quotient and remainder of `numer / denom`.
pub fn div(numer: i32, denom: i32) -> DivResult {
    if denom == 0 {
        return DivResult { quot: 0, rem: 0 };
    }
    DivResult {
        quot: numer.wrapping_div(denom),
        rem: numer.wrapping_rem(denom),
    }
}

/// Computes quotient and remainder of `numer / denom` (long version).
pub fn ldiv(numer: i64, denom: i64) -> LdivResult {
    if denom == 0 {
        return LdivResult { quot: 0, rem: 0 };
    }
    LdivResult {
        quot: numer.wrapping_div(denom),
        rem: numer.wrapping_rem(denom),
    }
}

/// Computes quotient and remainder of `numer / denom` (long long version).
pub fn lldiv(numer: i64, denom: i64) -> LldivResult {
    if denom == 0 {
        return LldivResult { quot: 0, rem: 0 };
    }
    LldivResult {
        quot: numer.wrapping_div(denom),
        rem: numer.wrapping_rem(denom),
    }
}

/// Finds the first (lowest) set bit. Returns 0 if `i` is 0.
pub fn ffs(i: i32) -> i32 {
    if i == 0 {
        0
    } else {
        i.trailing_zeros() as i32 + 1
    }
}

/// Finds the first set bit in a long. Returns 0 if `i` is 0.
pub fn ffsl(i: i64) -> i32 {
    if i == 0 {
        0
    } else {
        i.trailing_zeros() as i32 + 1
    }
}

/// Finds the first set bit in a long long. Returns 0 if `i` is 0.
pub fn ffsll(i: i64) -> i32 {
    if i == 0 {
        0
    } else {
        i.trailing_zeros() as i32 + 1
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_abs_basic() {
        assert_eq!(abs(42), 42);
        assert_eq!(abs(-42), 42);
        assert_eq!(abs(0), 0);
    }

    #[test]
    fn test_abs_min() {
        // wrapping_abs of i32::MIN wraps to i32::MIN (undefined in C, defined in Rust)
        assert_eq!(abs(i32::MIN), i32::MIN);
    }

    #[test]
    fn test_labs_basic() {
        assert_eq!(labs(42), 42);
        assert_eq!(labs(-42), 42);
    }

    #[test]
    fn test_div_basic() {
        let r = div(7, 3);
        assert_eq!(r.quot, 2);
        assert_eq!(r.rem, 1);
    }

    #[test]
    fn test_div_negative() {
        let r = div(-7, 3);
        assert_eq!(r.quot, -2);
        assert_eq!(r.rem, -1);
    }

    #[test]
    fn test_div_zero_denom() {
        let r = div(7, 0);
        assert_eq!(r.quot, 0);
        assert_eq!(r.rem, 0);
    }

    #[test]
    fn test_ldiv_basic() {
        let r = ldiv(100, 7);
        assert_eq!(r.quot, 14);
        assert_eq!(r.rem, 2);
    }

    #[test]
    fn test_ffs_basic() {
        assert_eq!(ffs(0), 0);
        assert_eq!(ffs(1), 1);
        assert_eq!(ffs(2), 2);
        assert_eq!(ffs(0b1000), 4);
        assert_eq!(ffs(0b1010), 2);
    }

    #[test]
    fn test_ffsl_basic() {
        assert_eq!(ffsl(0), 0);
        assert_eq!(ffsl(1i64 << 32), 33);
    }

    #[test]
    fn test_ffsll_basic() {
        assert_eq!(ffsll(0), 0);
        assert_eq!(ffsll(1i64 << 63), 64);
    }
}
