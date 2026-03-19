//! POSIX virtual memory management.
//!
//! Implements constants and validators for `<sys/mman.h>` functions:
//! mmap, munmap, mprotect, msync, madvise.

// ---------------------------------------------------------------------------
// Protection flags (PROT_*)
// ---------------------------------------------------------------------------

/// No access permitted.
pub const PROT_NONE: i32 = 0x0;
/// Pages can be read.
pub const PROT_READ: i32 = 0x1;
/// Pages can be written.
pub const PROT_WRITE: i32 = 0x2;
/// Pages can be executed.
pub const PROT_EXEC: i32 = 0x4;

const PROT_MASK: i32 = PROT_READ | PROT_WRITE | PROT_EXEC;

// ---------------------------------------------------------------------------
// Mapping flags (MAP_*)
// ---------------------------------------------------------------------------

/// Share changes with other processes mapping the same region.
pub const MAP_SHARED: i32 = 0x01;
/// Create a private copy-on-write mapping.
pub const MAP_PRIVATE: i32 = 0x02;
/// Place the mapping at exactly the specified address.
pub const MAP_FIXED: i32 = 0x10;
/// The mapping is not backed by any file; contents are initialized to zero.
pub const MAP_ANONYMOUS: i32 = 0x20;

// Common Linux mmap flags
/// Stack-like growth.
pub const MAP_GROWSDOWN: i32 = 0x0100;
/// Ignored (compatibility).
pub const MAP_DENYWRITE: i32 = 0x0800;
/// Ignored (compatibility).
pub const MAP_EXECUTABLE: i32 = 0x1000;
/// Lock the mapping into memory.
pub const MAP_LOCKED: i32 = 0x2000;
/// Do not reserve swap space.
pub const MAP_NORESERVE: i32 = 0x4000;
/// Populate (prefault) page tables.
pub const MAP_POPULATE: i32 = 0x8000;
/// Do not block on I/O.
pub const MAP_NONBLOCK: i32 = 0x10000;
/// Allocation suitable for a stack.
pub const MAP_STACK: i32 = 0x20000;
/// Create mapping using huge pages.
pub const MAP_HUGETLB: i32 = 0x40000;
/// Perform synchronous writes.
pub const MAP_SYNC: i32 = 0x80000;
/// MAP_FIXED but do not overwrite existing mapping.
pub const MAP_FIXED_NOREPLACE: i32 = 0x100000;

/// Returned by mmap on failure (equivalent to `(void *)-1`).
pub const MAP_FAILED: usize = usize::MAX;

const MAP_VISIBILITY_MASK: i32 = MAP_SHARED | MAP_PRIVATE;
const MAP_FLAGS_MASK: i32 = MAP_SHARED
    | MAP_PRIVATE
    | MAP_FIXED
    | MAP_ANONYMOUS
    | MAP_GROWSDOWN
    | MAP_DENYWRITE
    | MAP_EXECUTABLE
    | MAP_LOCKED
    | MAP_NORESERVE
    | MAP_POPULATE
    | MAP_NONBLOCK
    | MAP_STACK
    | MAP_HUGETLB
    | MAP_SYNC
    | MAP_FIXED_NOREPLACE;

// ---------------------------------------------------------------------------
// msync flags (MS_*)
// ---------------------------------------------------------------------------

/// Schedule an asynchronous write.
pub const MS_ASYNC: i32 = 1;
/// Request a synchronous write; block until complete.
pub const MS_SYNC: i32 = 4;
/// Invalidate caches so future accesses re-read from the file.
pub const MS_INVALIDATE: i32 = 2;

const MS_MASK: i32 = MS_ASYNC | MS_SYNC | MS_INVALIDATE;

// ---------------------------------------------------------------------------
// madvise advice values (MADV_*)
// ---------------------------------------------------------------------------

/// No special treatment (default).
pub const MADV_NORMAL: i32 = 0;
/// Expect random page references.
pub const MADV_RANDOM: i32 = 1;
/// Expect sequential page references.
pub const MADV_SEQUENTIAL: i32 = 2;
/// Expect access in the near future.
pub const MADV_WILLNEED: i32 = 3;
/// Do not expect access in the near future.
pub const MADV_DONTNEED: i32 = 4;
/// Use huge pages.
pub const MADV_HUGEPAGE: i32 = 14;
/// Do not use huge pages.
pub const MADV_NOHUGEPAGE: i32 = 15;

// ---------------------------------------------------------------------------
// Validators
// ---------------------------------------------------------------------------

/// Returns true if `prot` contains only recognized PROT_* bits.
#[must_use]
pub const fn valid_prot(prot: i32) -> bool {
    (prot & !PROT_MASK) == 0
}

/// Returns true if `flags` contains exactly one of MAP_SHARED/MAP_PRIVATE
/// and only recognized bits.
#[must_use]
pub const fn valid_map_flags(flags: i32) -> bool {
    let vis = flags & MAP_VISIBILITY_MASK;
    // Must have exactly one of SHARED or PRIVATE.
    let has_one_vis = vis == MAP_SHARED || vis == MAP_PRIVATE;
    // Must not have unknown bits.
    let known_only = (flags & !MAP_FLAGS_MASK) == 0;
    has_one_vis && known_only
}

/// Returns true if `advice` is a recognized MADV_* value.
#[must_use]
pub const fn valid_madvise(advice: i32) -> bool {
    matches!(
        advice,
        MADV_NORMAL
            | MADV_RANDOM
            | MADV_SEQUENTIAL
            | MADV_WILLNEED
            | MADV_DONTNEED
            | MADV_HUGEPAGE
            | MADV_NOHUGEPAGE
    )
}

/// Returns true if `flags` contains only recognized MS_* bits, has exactly
/// one of MS_ASYNC or MS_SYNC (required by POSIX), and does not combine both.
#[must_use]
pub const fn valid_msync_flags(flags: i32) -> bool {
    let known = (flags & !MS_MASK) == 0;
    let has_async = (flags & MS_ASYNC) != 0;
    let has_sync = (flags & MS_SYNC) != 0;
    // Exactly one of MS_ASYNC or MS_SYNC must be set.
    let exactly_one = has_async ^ has_sync;
    known && exactly_one
}

/// Returns true if the mmap length is non-zero.
#[must_use]
pub const fn valid_mmap_length(len: usize) -> bool {
    len > 0
}

/// Sanitize protection flags: mask to recognized bits.
#[must_use]
pub const fn sanitize_prot(prot: i32) -> i32 {
    prot & PROT_MASK
}

/// Sanitize map flags: ensure visibility bit is present.
/// If neither SHARED nor PRIVATE is set, default to MAP_PRIVATE.
#[must_use]
pub const fn sanitize_map_flags(flags: i32) -> i32 {
    let cleaned = flags & MAP_FLAGS_MASK;
    let vis = cleaned & MAP_VISIBILITY_MASK;
    if vis == 0 {
        cleaned | MAP_PRIVATE
    } else if vis == MAP_VISIBILITY_MASK {
        // Both set — keep only PRIVATE.
        cleaned & !MAP_SHARED
    } else {
        cleaned
    }
}

/// Sanitize msync flags: if invalid, default to MS_ASYNC.
#[must_use]
pub const fn sanitize_msync_flags(flags: i32) -> i32 {
    if valid_msync_flags(flags) {
        flags
    } else {
        MS_ASYNC
    }
}

/// Sanitize madvise advice: if unknown, default to MADV_NORMAL.
#[must_use]
pub const fn sanitize_madvise(advice: i32) -> i32 {
    if valid_madvise(advice) {
        advice
    } else {
        MADV_NORMAL
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn prot_constants_match_linux() {
        assert_eq!(PROT_NONE, 0);
        assert_eq!(PROT_READ, 1);
        assert_eq!(PROT_WRITE, 2);
        assert_eq!(PROT_EXEC, 4);
    }

    #[test]
    fn map_constants_match_linux() {
        assert_eq!(MAP_SHARED, 0x01);
        assert_eq!(MAP_PRIVATE, 0x02);
        assert_eq!(MAP_FIXED, 0x10);
        assert_eq!(MAP_ANONYMOUS, 0x20);
        assert_eq!(MAP_GROWSDOWN, 0x0100);
        assert_eq!(MAP_POPULATE, 0x8000);
        assert_eq!(MAP_STACK, 0x20000);
    }

    #[test]
    fn valid_prot_recognizes_combinations() {
        assert!(valid_prot(PROT_NONE));
        assert!(valid_prot(PROT_READ));
        assert!(valid_prot(PROT_READ | PROT_WRITE));
        assert!(valid_prot(PROT_READ | PROT_WRITE | PROT_EXEC));
        assert!(!valid_prot(0x8));
        assert!(!valid_prot(-1));
    }

    #[test]
    fn valid_map_flags_check() {
        assert!(valid_map_flags(MAP_PRIVATE));
        assert!(valid_map_flags(MAP_SHARED));
        assert!(valid_map_flags(MAP_PRIVATE | MAP_ANONYMOUS));
        assert!(valid_map_flags(MAP_PRIVATE | MAP_FIXED));
        assert!(valid_map_flags(MAP_PRIVATE | MAP_POPULATE | MAP_STACK));
        // Both SHARED and PRIVATE is invalid.
        assert!(!valid_map_flags(MAP_SHARED | MAP_PRIVATE));
        // Neither is invalid.
        assert!(!valid_map_flags(0));
        // Unknown bits.
        assert!(!valid_map_flags(MAP_PRIVATE | 0x200000));
    }

    #[test]
    fn valid_madvise_check() {
        assert!(valid_madvise(MADV_NORMAL));
        assert!(valid_madvise(MADV_RANDOM));
        assert!(valid_madvise(MADV_SEQUENTIAL));
        assert!(valid_madvise(MADV_WILLNEED));
        assert!(valid_madvise(MADV_DONTNEED));
        assert!(valid_madvise(MADV_HUGEPAGE));
        assert!(valid_madvise(MADV_NOHUGEPAGE));
        assert!(!valid_madvise(100));
        assert!(!valid_madvise(-1));
    }

    #[test]
    fn valid_msync_flags_check() {
        assert!(valid_msync_flags(MS_ASYNC));
        assert!(valid_msync_flags(MS_SYNC));
        assert!(valid_msync_flags(MS_ASYNC | MS_INVALIDATE));
        assert!(valid_msync_flags(MS_SYNC | MS_INVALIDATE));
        // Both ASYNC and SYNC is invalid.
        assert!(!valid_msync_flags(MS_ASYNC | MS_SYNC));
        // Unknown bits.
        assert!(!valid_msync_flags(0x100));
        // Neither ASYNC nor SYNC: POSIX requires exactly one.
        assert!(!valid_msync_flags(0));
        assert!(!valid_msync_flags(MS_INVALIDATE));
    }

    #[test]
    fn valid_mmap_length_check() {
        assert!(!valid_mmap_length(0));
        assert!(valid_mmap_length(1));
        assert!(valid_mmap_length(4096));
    }

    #[test]
    fn sanitize_prot_strips_unknown() {
        assert_eq!(sanitize_prot(0xff), PROT_MASK);
        assert_eq!(sanitize_prot(PROT_READ), PROT_READ);
    }

    #[test]
    fn sanitize_map_flags_defaults_to_private() {
        // No visibility → adds MAP_PRIVATE.
        assert_eq!(
            sanitize_map_flags(MAP_ANONYMOUS),
            MAP_ANONYMOUS | MAP_PRIVATE
        );
        // Both → keeps only PRIVATE.
        let both = MAP_SHARED | MAP_PRIVATE | MAP_ANONYMOUS;
        let sanitized = sanitize_map_flags(both);
        assert_eq!(sanitized & MAP_VISIBILITY_MASK, MAP_PRIVATE);
    }

    #[test]
    fn sanitize_msync_defaults_to_async() {
        assert_eq!(sanitize_msync_flags(MS_ASYNC | MS_SYNC), MS_ASYNC);
        assert_eq!(sanitize_msync_flags(0x100), MS_ASYNC);
        assert_eq!(sanitize_msync_flags(MS_SYNC), MS_SYNC);
    }

    #[test]
    fn sanitize_madvise_defaults_to_normal() {
        assert_eq!(sanitize_madvise(100), MADV_NORMAL);
        assert_eq!(sanitize_madvise(MADV_WILLNEED), MADV_WILLNEED);
    }
}
