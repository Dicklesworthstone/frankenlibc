#![cfg(target_os = "linux")]

//! Compile the production importer in a real integration-test target. io_abi is
//! cfg(not(test)), so filtering its unit tests in the library runs zero tests.
//! The only adapter exposes the same allocator lookup used by production.
mod malloc_abi {
    pub(crate) fn known_remaining(address: usize) -> Option<usize> {
        frankenlibc_abi::malloc_abi::malloc_known_remaining_for_tests(
            address as *const std::ffi::c_void,
        )
    }
}

#[path = "../src/iov_snapshot.rs"]
mod iov_snapshot;

#[test]
fn full_width_segment_counts_never_truncate_into_an_import() {
    let invalid = std::ptr::without_provenance::<libc::iovec>(1);
    for count in [0, 1025, i32::MAX as usize + 1, usize::MAX] {
        let prepared =
            iov_snapshot::PreparedIovecs::prepare_unsigned(invalid, count, true).unwrap();
        assert_eq!(prepared.as_ptr(), invalid);
    }
    let strict = iov_snapshot::PreparedIovecs::prepare_unsigned(invalid, 1, false).unwrap();
    assert_eq!(strict.as_ptr(), invalid);
}
