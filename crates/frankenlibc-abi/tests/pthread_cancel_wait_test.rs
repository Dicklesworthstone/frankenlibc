#![cfg(target_os = "linux")]

//! Exercise the production native cancellation adapters in a real test target.
//! `pthread_abi` is excluded from library unit tests, so filtering its nested
//! tests with `--lib` would silently execute no tests.

mod malloc_abi {
    pub(crate) fn known_remaining(address: usize) -> Option<usize> {
        frankenlibc_abi::malloc_abi::malloc_known_remaining_for_tests(
            address as *const std::ffi::c_void,
        )
    }
}
#[path = "../src/iov_snapshot.rs"]
mod iov_snapshot;
mod io_abi {
    pub(crate) use crate::iov_snapshot;
}

#[path = "../src/pthread_cancel_poll.rs"]
#[expect(
    dead_code,
    reason = "production adapter entrypoints are unused in this helper test target"
)]
mod cancel_poll;
#[path = "../src/pthread_cancel_wait.rs"]
#[expect(
    dead_code,
    reason = "production adapter entrypoints are unused in this helper test target"
)]
mod cancel_wait;
