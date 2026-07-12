#![cfg(target_os = "linux")]
#![allow(unsafe_code)]
//! Focused guard for the realloc shrink/same-size in-place lever
//! (`if size <= old_size { return ptr }`). The existing `test_realloc_shrink`
//! only checks that byte 0 survives and never asserts that the block is reused
//! in place — so it would still pass if realloc silently moved or dropped data
//! past byte 0. This pins both properties the lever guarantees:
//!   * shrinking (or realloc to the same size) returns the SAME pointer
//!     (no alloc/copy/free), and
//!   * the entire surviving prefix is preserved intact.

use frankenlibc_abi::malloc_abi as fl;
use std::ffi::c_void;

#[test]
fn realloc_shrink_is_in_place_and_preserves_data() {
    unsafe {
        let p = fl::malloc(256) as *mut u8;
        assert!(!p.is_null());

        // Fill the whole block with a position-dependent pattern.
        for i in 0..256usize {
            *p.add(i) = (i as u8).wrapping_mul(31).wrapping_add(7);
        }

        // Shrink: the lever must reuse the block in place.
        let q = fl::realloc(p as *mut c_void, 32) as *mut u8;
        assert!(!q.is_null(), "shrink realloc should succeed");
        assert_eq!(q, p, "shrink must reuse the block in place (same pointer)");

        // The full surviving 32-byte prefix must be intact (not just byte 0).
        for i in 0..32usize {
            assert_eq!(
                *q.add(i),
                (i as u8).wrapping_mul(31).wrapping_add(7),
                "byte {i} not preserved across in-place shrink"
            );
        }

        // Same-size realloc is also in place.
        let r = fl::realloc(q as *mut c_void, 32) as *mut u8;
        assert_eq!(r, q, "same-size realloc must reuse the block in place");

        // The block remains fully usable after the in-place shrink.
        for i in 0..32usize {
            *r.add(i) = 0xA5;
        }
        for i in 0..32usize {
            assert_eq!(
                *r.add(i),
                0xA5,
                "byte {i} not writable after in-place shrink"
            );
        }

        fl::free(r as *mut c_void);
    }
}
