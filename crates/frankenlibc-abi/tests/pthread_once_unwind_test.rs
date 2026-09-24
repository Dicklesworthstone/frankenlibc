//! Exercise the real ABI module, which is excluded from the crate's unit-test
//! build by cfg(not(test)). Foreign C++ exceptions and contended wakeups are
//! covered separately by scripts/check_pthread_once_unwind.sh.
#![cfg(all(
    target_os = "linux",
    panic = "unwind",
    not(all(feature = "standalone", feature = "owned-unwind-stub"))
))]

use frankenlibc_abi::pthread_abi::pthread_once;

unsafe extern "C-unwind" fn fail_init() {
    std::panic::panic_any(0x51c0_u32);
}

unsafe extern "C-unwind" fn complete_init() {}

#[test]
fn once_retries_after_unwind_and_does_not_swallow_the_payload() {
    let mut once = libc::PTHREAD_ONCE_INIT;
    for _ in 0..2 {
        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| unsafe {
            pthread_once(&mut once, Some(fail_init))
        }));
        let payload = result.expect_err("initializer unwind was swallowed");
        assert_eq!(payload.downcast_ref::<u32>(), Some(&0x51c0_u32));
        assert_eq!(once, libc::PTHREAD_ONCE_INIT);
    }
    assert_eq!(unsafe { pthread_once(&mut once, Some(complete_init)) }, 0);
    // A completed once must not call even an initializer that would panic.
    assert_eq!(unsafe { pthread_once(&mut once, Some(fail_init)) }, 0);
}

#[test]
fn invalid_arguments_do_not_invoke_the_initializer_or_change_the_once() {
    assert_eq!(
        unsafe { pthread_once(std::ptr::null_mut(), Some(fail_init)) },
        libc::EINVAL
    );
    let mut once = libc::PTHREAD_ONCE_INIT;
    assert_eq!(unsafe { pthread_once(&mut once, None) }, libc::EINVAL);
    assert_eq!(once, libc::PTHREAD_ONCE_INIT);
    assert_eq!(unsafe { pthread_once(&mut once, Some(complete_init)) }, 0);
}
