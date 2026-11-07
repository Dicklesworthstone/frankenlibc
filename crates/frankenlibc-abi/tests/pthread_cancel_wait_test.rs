#![cfg(target_os = "linux")]

//! Exercise the production native cancellation adapters in a real test target.
//! `pthread_abi` is excluded from library unit tests, so filtering its nested
//! tests with `--lib` would silently execute no tests.

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
