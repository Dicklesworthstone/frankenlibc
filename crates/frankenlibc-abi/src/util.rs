//! Shared internal utilities for ABI adapters.

use std::ffi::c_char;

#[inline]
fn allocation_bound(ptr: *const c_char) -> Option<usize> {
    #[cfg(not(test))]
    {
        crate::malloc_abi::known_remaining(ptr as usize)
    }

    #[cfg(test)]
    {
        test_allocation_bound(ptr as usize)
    }
}

/// Scan a C string with an optional hard bound.
///
/// Returns `(len, terminated)` where:
/// - `len` is the byte length before the first NUL or before the bound.
/// - `terminated` indicates whether a NUL byte was observed.
///
/// # Safety
///
/// `ptr` must be valid to read up to the discovered length (and bound when given).
pub unsafe fn scan_c_string(ptr: *const c_char, bound: Option<usize>) -> (usize, bool) {
    let effective_bound = match (bound, allocation_bound(ptr)) {
        (Some(limit), Some(alloc)) => Some(limit.min(alloc)),
        (Some(limit), None) => Some(limit),
        (None, Some(alloc)) => Some(alloc),
        (None, None) => None,
    };

    match effective_bound {
        Some(limit) => {
            for i in 0..limit {
                if unsafe { *ptr.add(i) } == 0 {
                    return (i, true);
                }
            }
            (limit, false)
        }
        None => {
            let mut i = 0usize;
            while unsafe { *ptr.add(i) } != 0 {
                i += 1;
            }
            (i, true)
        }
    }
}

#[cfg(test)]
static TEST_ALLOC_BOUNDS: std::sync::Mutex<Vec<(usize, usize)>> = std::sync::Mutex::new(Vec::new());

#[cfg(test)]
fn test_allocation_bound(addr: usize) -> Option<usize> {
    let guard = TEST_ALLOC_BOUNDS.lock().unwrap_or_else(|e| e.into_inner());
    guard.iter().find_map(|(base, len)| {
        let end = base.saturating_add(*len);
        (addr >= *base && addr < end).then_some(end - addr)
    })
}

#[cfg(test)]
mod tests {
    use super::{TEST_ALLOC_BOUNDS, scan_c_string};

    struct TestBoundGuard {
        base: usize,
        len: usize,
    }

    impl TestBoundGuard {
        fn new(bytes: &[u8]) -> Self {
            let base = bytes.as_ptr() as usize;
            let len = bytes.len();
            TEST_ALLOC_BOUNDS
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .push((base, len));
            Self { base, len }
        }
    }

    impl Drop for TestBoundGuard {
        fn drop(&mut self) {
            TEST_ALLOC_BOUNDS
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .retain(|entry| *entry != (self.base, self.len));
        }
    }

    #[test]
    fn scan_c_string_intersects_explicit_bound_with_tracked_allocation() {
        let bytes = *b"hello";
        let _guard = TestBoundGuard::new(&bytes);

        assert_eq!(
            unsafe { scan_c_string(bytes.as_ptr().cast::<std::ffi::c_char>(), Some(64)) },
            (5, false)
        );
    }

    #[test]
    fn scan_c_string_keeps_smaller_explicit_bound() {
        let bytes = *b"hello";
        let _guard = TestBoundGuard::new(&bytes);

        assert_eq!(
            unsafe { scan_c_string(bytes.as_ptr().cast::<std::ffi::c_char>(), Some(2)) },
            (2, false)
        );
    }
}
