//! Named semaphore regressions against the public ABI, not a model.
#![cfg(all(target_os = "linux", target_pointer_width = "64"))]
use frankenlibc_abi::{errno_abi, unistd_abi as sem};
use std::ffi::CString;
use std::sync::atomic::{AtomicUsize, Ordering};
static NEXT: AtomicUsize = AtomicUsize::new(0);
fn name() -> CString {
    CString::new(format!(
        "/fl-named-{}-{}",
        std::process::id(),
        NEXT.fetch_add(1, Ordering::Relaxed)
    ))
    .unwrap()
}
#[test]
fn public_named_reopen_does_not_reset_tokens_and_retains_address() {
    let name = name();
    unsafe {
        let first = sem::sem_open(name.as_ptr(), libc::O_CREAT | libc::O_EXCL, 0o600u32, 3u32);
        assert!(!first.is_null() && first != libc::MAP_FAILED);
        assert_eq!(sem::sem_trywait(first), 0);
        let second = sem::sem_open(name.as_ptr(), libc::O_CREAT, 0o600u32, 9u32);
        let mut value = -1;
        assert_eq!(sem::sem_getvalue(first, &mut value), 0);
        let same = first == second;
        assert_eq!(sem::sem_unlink(name.as_ptr()), 0);
        assert_eq!(sem::sem_close(second), 0);
        assert_eq!(sem::sem_close(first), 0);
        assert_eq!(value, 2, "O_CREAT must not reinitialize a live semaphore");
        assert!(same, "open references to one inode must share one address");
    }
}
#[test]
fn public_named_error_is_the_platform_sem_failed() {
    let name = name();
    unsafe {
        let result = sem::sem_open(name.as_ptr(), 0);
        assert_eq!(result, libc::SEM_FAILED.cast());
        assert_eq!(*errno_abi::__errno_location(), libc::ENOENT);
    }
}
