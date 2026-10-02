//! Dynamic linking — validators and constants.
//!
//! Implements `<dlfcn.h>` pure-logic helpers. Actual dlopen/dlsym/dlclose
//! invocations live in the ABI crate.

/// dlopen mode flags.
pub const RTLD_LAZY: i32 = 0x00001;
pub const RTLD_NOW: i32 = 0x00002;
pub const RTLD_GLOBAL: i32 = 0x00100;
pub const RTLD_LOCAL: i32 = 0x00000;
pub const RTLD_NOLOAD: i32 = 0x00004;
pub const RTLD_DEEPBIND: i32 = 0x00008;
pub const RTLD_NODELETE: i32 = 0x01000;

/// Special pseudo-handles for dlsym.
pub const RTLD_DEFAULT: usize = 0;
pub const RTLD_NEXT: usize = usize::MAX;

/// Valid binding mode bits (exactly one of LAZY or NOW must be set).
const BINDING_MASK: i32 = RTLD_LAZY | RTLD_NOW;

/// Valid modifier bits.
///
/// `RTLD_DEEPBIND` is accepted here and forwarded unchanged to the loader.
/// Omitting it made `dlopen(path, RTLD_NOW | RTLD_DEEPBIND)` fail with
/// "invalid mode for dlopen" where glibc succeeds — and that is the very mode
/// `incumbent_coverage_ab` uses to load FrankenLibC, so fl rejected the way its
/// own benchmark harness loads it.
const MODIFIER_MASK: i32 = RTLD_GLOBAL | RTLD_LOCAL | RTLD_NOLOAD | RTLD_DEEPBIND | RTLD_NODELETE;

/// glibc's `__RTLD_SPROF`, which dlopen also accepts (sprof's profiling mode).
const RTLD_SPROF: i32 = 0x4000_0000;

/// Returns `true` if `flags` represent a valid dlopen mode, by glibc's rule
/// (measured on 2.43): some binding bit set -- `RTLD_LAZY | RTLD_NOW` is
/// accepted -- and no modifier outside NOLOAD/DEEPBIND/GLOBAL/LOCAL/NODELETE
/// and `__RTLD_SPROF` ("invalid mode parameter").
#[inline]
pub fn valid_flags(flags: i32) -> bool {
    let binding = flags & BINDING_MASK;
    let modifiers = flags & !BINDING_MASK;
    binding != 0 && (modifiers & !(MODIFIER_MASK | RTLD_SPROF)) == 0
}

/// Returns `true` if `handle` is a recognized pseudo-handle.
#[inline]
pub fn is_pseudo_handle(handle: usize) -> bool {
    handle == RTLD_DEFAULT || handle == RTLD_NEXT
}

/// Error message strings for common dlfcn errors.
pub const ERR_INVALID_FLAGS: &[u8] = b"invalid mode for dlopen\0";
pub const ERR_NOT_FOUND: &[u8] = b"shared object not found\0";
pub const ERR_SYMBOL_NOT_FOUND: &[u8] = b"undefined symbol\0";
pub const ERR_INVALID_HANDLE: &[u8] = b"invalid handle\0";
pub const ERR_OPERATION_UNAVAILABLE: &[u8] = b"operation unavailable in native dlfcn path\0";

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_valid_flags() {
        assert!(valid_flags(RTLD_LAZY));
        assert!(valid_flags(RTLD_NOW));
        assert!(valid_flags(RTLD_LAZY | RTLD_GLOBAL));
        assert!(valid_flags(RTLD_NOW | RTLD_NODELETE));
        assert!(!valid_flags(0));
        assert!(!valid_flags(RTLD_GLOBAL), "a modifier without a binding");
        assert!(!valid_flags(RTLD_LAZY | 0x80000));
        // glibc 2.43 accepts both binding bits together, and __RTLD_SPROF.
        assert!(valid_flags(RTLD_LAZY | RTLD_NOW));
        assert!(valid_flags(RTLD_NOW | 0x4000_0000));
    }

    #[test]
    fn valid_flags_accepts_deepbind() {
        // glibc accepts RTLD_DEEPBIND; rejecting it made every
        // `dlopen(path, RTLD_NOW | RTLD_DEEPBIND)` fail under fl with
        // "invalid mode for dlopen", including the load performed by this
        // repository's own `incumbent_coverage_ab` harness.
        assert!(valid_flags(RTLD_NOW | RTLD_DEEPBIND));
        assert!(valid_flags(RTLD_LAZY | RTLD_DEEPBIND));
        // and in combination with the other modifiers
        assert!(valid_flags(RTLD_NOW | RTLD_LOCAL | RTLD_DEEPBIND));
        assert!(valid_flags(
            RTLD_NOW | RTLD_GLOBAL | RTLD_DEEPBIND | RTLD_NODELETE
        ));
        // still exactly one binding bit, DEEPBIND does not substitute for it
        assert!(!valid_flags(RTLD_DEEPBIND));
    }

    #[test]
    fn test_is_pseudo_handle() {
        assert!(is_pseudo_handle(RTLD_DEFAULT));
        assert!(is_pseudo_handle(RTLD_NEXT));
        assert!(!is_pseudo_handle(0x12345678));
    }

    // ===== glibc parity tests =====
    // Verified against glibc <dlfcn.h>

    #[test]
    fn glibc_rtld_flag_constants() {
        // RTLD_* mode flags must match glibc
        assert_eq!(RTLD_LAZY, 0x00001);
        assert_eq!(RTLD_NOW, 0x00002);
        assert_eq!(RTLD_GLOBAL, 0x00100);
        assert_eq!(RTLD_LOCAL, 0x00000);
        assert_eq!(RTLD_NOLOAD, 0x00004);
        assert_eq!(RTLD_DEEPBIND, 0x00008);
        assert_eq!(RTLD_NODELETE, 0x01000);
    }

    #[test]
    fn glibc_rtld_pseudo_handles() {
        // RTLD_DEFAULT = NULL (0), RTLD_NEXT = (void*)-1
        assert_eq!(RTLD_DEFAULT, 0);
        assert_eq!(RTLD_NEXT, usize::MAX);
    }
}
