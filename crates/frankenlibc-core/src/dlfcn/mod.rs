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
pub const RTLD_NODELETE: i32 = 0x01000;

/// Special pseudo-handles for dlsym.
pub const RTLD_DEFAULT: usize = 0;
pub const RTLD_NEXT: usize = usize::MAX;

/// Valid binding mode bits (exactly one of LAZY or NOW must be set).
const BINDING_MASK: i32 = RTLD_LAZY | RTLD_NOW;

/// Valid modifier bits.
const MODIFIER_MASK: i32 = RTLD_GLOBAL | RTLD_LOCAL | RTLD_NOLOAD | RTLD_NODELETE;

/// Returns `true` if `flags` represent a valid dlopen mode.
///
/// POSIX requires exactly one of RTLD_LAZY or RTLD_NOW to be set.
#[inline]
pub fn valid_flags(flags: i32) -> bool {
    let binding = flags & BINDING_MASK;
    let modifiers = flags & !BINDING_MASK;
    (binding == RTLD_LAZY || binding == RTLD_NOW) && (modifiers & !MODIFIER_MASK) == 0
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
        assert!(!valid_flags(RTLD_LAZY | RTLD_NOW));
        assert!(!valid_flags(RTLD_LAZY | 0x80000));
    }

    #[test]
    fn test_is_pseudo_handle() {
        assert!(is_pseudo_handle(RTLD_DEFAULT));
        assert!(is_pseudo_handle(RTLD_NEXT));
        assert!(!is_pseudo_handle(0x12345678));
    }
}
