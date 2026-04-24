//! Resource usage and limits — validators and constants.
//!
//! Implements `<sys/resource.h>` pure-logic helpers. Actual syscall
//! invocations live in the ABI crate.

/// Resource limit identifiers (Linux numbering — see `<sys/resource.h>`).
pub const RLIMIT_CPU: i32 = 0;
pub const RLIMIT_FSIZE: i32 = 1;
pub const RLIMIT_DATA: i32 = 2;
pub const RLIMIT_STACK: i32 = 3;
pub const RLIMIT_CORE: i32 = 4;
pub const RLIMIT_RSS: i32 = 5;
pub const RLIMIT_NPROC: i32 = 6;
pub const RLIMIT_NOFILE: i32 = 7;
pub const RLIMIT_MEMLOCK: i32 = 8;
pub const RLIMIT_AS: i32 = 9;
pub const RLIMIT_LOCKS: i32 = 10;
pub const RLIMIT_SIGPENDING: i32 = 11;
pub const RLIMIT_MSGQUEUE: i32 = 12;
pub const RLIMIT_NICE: i32 = 13;
pub const RLIMIT_RTPRIO: i32 = 14;
pub const RLIMIT_RTTIME: i32 = 15;
/// Highest valid Linux rlimit value (exclusive of the count).
pub const RLIMIT_MAX_VALID: i32 = RLIMIT_RTTIME;

/// Infinity sentinel for resource limits.
pub const RLIM_INFINITY: u64 = u64::MAX;

/// Resource limit values (like `struct rlimit`).
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct Rlimit {
    /// Soft limit.
    pub rlim_cur: u64,
    /// Hard limit (ceiling for soft limit).
    pub rlim_max: u64,
}

/// Returns `true` if `resource` is a known Linux rlimit identifier.
///
/// Linux defines RLIMIT_CPU..RLIMIT_RTTIME (0..=15) as the contiguous
/// valid range. Earlier versions of this checker only accepted a sparse
/// subset (CPU/FSIZE/DATA/STACK/CORE/NOFILE/AS) and rejected RLIMIT_RSS,
/// RLIMIT_NPROC, RLIMIT_MEMLOCK, RLIMIT_LOCKS, RLIMIT_SIGPENDING,
/// RLIMIT_MSGQUEUE, RLIMIT_NICE, RLIMIT_RTPRIO, and RLIMIT_RTTIME — all
/// of which the host kernel/glibc accept and report. This caused
/// FrankenLibC's getrlimit/setrlimit to return EINVAL for legitimate
/// resources where glibc returns success. (CONFORMANCE: sys/resource.h
/// diff matrix caught getrlimit(RLIMIT_NPROC) divergence.)
#[inline]
pub fn valid_resource(resource: i32) -> bool {
    (RLIMIT_CPU..=RLIMIT_MAX_VALID).contains(&resource)
}

/// Returns `true` if the rlimit has a valid relationship (soft <= hard).
#[inline]
pub fn valid_rlimit(rlim: &Rlimit) -> bool {
    rlim.rlim_cur <= rlim.rlim_max
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_valid_resource() {
        assert!(valid_resource(RLIMIT_CPU));
        assert!(valid_resource(RLIMIT_FSIZE));
        assert!(valid_resource(RLIMIT_DATA));
        assert!(valid_resource(RLIMIT_STACK));
        assert!(valid_resource(RLIMIT_CORE));
        assert!(valid_resource(RLIMIT_RSS));
        assert!(valid_resource(RLIMIT_NPROC));
        assert!(valid_resource(RLIMIT_NOFILE));
        assert!(valid_resource(RLIMIT_MEMLOCK));
        assert!(valid_resource(RLIMIT_AS));
        assert!(valid_resource(RLIMIT_LOCKS));
        assert!(valid_resource(RLIMIT_SIGPENDING));
        assert!(valid_resource(RLIMIT_MSGQUEUE));
        assert!(valid_resource(RLIMIT_NICE));
        assert!(valid_resource(RLIMIT_RTPRIO));
        assert!(valid_resource(RLIMIT_RTTIME));
        assert!(!valid_resource(-1));
        assert!(!valid_resource(16)); // one past RLIMIT_RTTIME
        assert!(!valid_resource(100));
    }

    #[test]
    fn test_valid_rlimit() {
        assert!(valid_rlimit(&Rlimit {
            rlim_cur: 100,
            rlim_max: 200,
        }));
        assert!(valid_rlimit(&Rlimit {
            rlim_cur: 200,
            rlim_max: 200,
        }));
        assert!(valid_rlimit(&Rlimit {
            rlim_cur: RLIM_INFINITY,
            rlim_max: RLIM_INFINITY,
        }));
        assert!(!valid_rlimit(&Rlimit {
            rlim_cur: 201,
            rlim_max: 200,
        }));
    }
}
