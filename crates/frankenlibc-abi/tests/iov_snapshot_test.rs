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
