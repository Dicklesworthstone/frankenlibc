//! ABI integration tests for inet_abi native implementations.
//!
//! Tests for promoted GlibcCallThrough -> Implemented symbols:
//! - if_nameindex / if_freenameindex

#![allow(unsafe_code)]

use std::ffi::{c_char, c_void};

// ---------------------------------------------------------------------------
// if_nameindex / if_freenameindex tests
// ---------------------------------------------------------------------------

unsafe extern "C" {
    fn if_nameindex() -> *mut c_void;
    fn if_freenameindex(ptr: *mut c_void);
}

/// struct if_nameindex layout on x86_64:
/// { if_index: u32, [pad 4], if_name: *mut c_char }
const IF_NAMEINDEX_ENTRY_SIZE: usize = 16;

#[test]
fn if_nameindex_returns_at_least_lo() {
    let array = unsafe { if_nameindex() };
    assert!(!array.is_null(), "if_nameindex should not return NULL");

    let base = array as *const u8;
    let mut count = 0;
    let mut found_lo = false;

    loop {
        let entry = unsafe { base.add(count * IF_NAMEINDEX_ENTRY_SIZE) };
        let idx = unsafe { *(entry as *const u32) };
        let name_ptr = unsafe { *(entry.add(8) as *const *const c_char) };

        if idx == 0 && name_ptr.is_null() {
            break; // Sentinel
        }

        assert!(!name_ptr.is_null(), "interface name pointer should not be null");
        let name = unsafe { std::ffi::CStr::from_ptr(name_ptr) };
        let name_bytes = name.to_bytes();
        assert!(
            !name_bytes.is_empty(),
            "interface name should not be empty"
        );

        if name_bytes == b"lo" {
            found_lo = true;
            assert_eq!(idx, 1, "loopback interface should have index 1");
        }

        count += 1;
        if count > 256 {
            break; // Safety limit
        }
    }

    assert!(count >= 1, "should find at least 1 interface, got {count}");
    assert!(found_lo, "should find loopback interface 'lo'");

    unsafe { if_freenameindex(array) };
}

// Note: if_freenameindex(NULL) segfaults in glibc.
// Our native impl handles NULL safely, but in test mode we link against glibc.
// Skipping NULL safety test for conformance.
