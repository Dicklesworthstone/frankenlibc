//! Explicit-clock waits select a kernel clock without rewriting condition state.
#![cfg(all(target_os = "linux", target_pointer_width = "64"))]
use frankenlibc_abi::pthread_abi as p;

#[test]
fn expired_cross_clock_deadlines_are_timeouts_with_the_mutex_reacquired() {
    for configured in [libc::CLOCK_REALTIME, libc::CLOCK_MONOTONIC] {
        for requested in [libc::CLOCK_REALTIME, libc::CLOCK_MONOTONIC] {
            for seconds in [0, -1, i64::MIN] {
                // SAFETY: caller-owned aligned storage is initialized before use;
                // no pointer escapes and every held mutex is unlocked on return.
                unsafe {
                    let mut attr: libc::pthread_condattr_t = std::mem::zeroed();
                    let mut cond: libc::pthread_cond_t = std::mem::zeroed();
                    let mut mutex: libc::pthread_mutex_t = std::mem::zeroed();
                    assert_eq!(p::pthread_condattr_init(&mut attr), 0);
                    assert_eq!(p::pthread_condattr_setclock(&mut attr, configured), 0);
                    assert_eq!(p::pthread_cond_init(&mut cond, &attr), 0);
                    assert_eq!(p::pthread_condattr_destroy(&mut attr), 0);
                    assert_eq!(p::pthread_mutex_init(&mut mutex, std::ptr::null()), 0);
                    assert_eq!(p::pthread_mutex_lock(&mut mutex), 0);
                    let deadline = libc::timespec {
                        tv_sec: seconds,
                        tv_nsec: 0,
                    };
                    let result =
                        p::pthread_cond_clockwait(&mut cond, &mut mutex, requested, &deadline);
                    let ownership = p::pthread_mutex_trylock(&mut mutex);
                    assert_eq!(p::pthread_mutex_unlock(&mut mutex), 0);
                    assert_eq!(p::pthread_cond_destroy(&mut cond), 0);
                    assert_eq!(p::pthread_mutex_destroy(&mut mutex), 0);
                    assert_eq!(
                        result,
                        libc::ETIMEDOUT,
                        "configured={configured}, requested={requested}, seconds={seconds}"
                    );
                    assert_eq!(ownership, libc::EBUSY, "wait must return holding the mutex");
                }
            }
        }
    }
}

#[test]
fn invalid_clock_and_nanoseconds_leave_owned_mutex_state_untouched() {
    // SAFETY: initialized local POSIX storage with no concurrent access.
    unsafe {
        let mut cond: libc::pthread_cond_t = std::mem::zeroed();
        let mut mutex: libc::pthread_mutex_t = std::mem::zeroed();
        assert_eq!(p::pthread_cond_init(&mut cond, std::ptr::null()), 0);
        assert_eq!(p::pthread_mutex_init(&mut mutex, std::ptr::null()), 0);
        assert_eq!(p::pthread_mutex_lock(&mut mutex), 0);
        for (clock, nanos) in [
            (libc::CLOCK_BOOTTIME, 0),
            (libc::CLOCK_REALTIME, -1),
            (libc::CLOCK_MONOTONIC, 1_000_000_000),
        ] {
            let deadline = libc::timespec {
                tv_sec: 0,
                tv_nsec: nanos,
            };
            assert_eq!(
                p::pthread_cond_clockwait(&mut cond, &mut mutex, clock, &deadline),
                libc::EINVAL
            );
            assert_eq!(p::pthread_mutex_trylock(&mut mutex), libc::EBUSY);
        }
        assert_eq!(p::pthread_mutex_unlock(&mut mutex), 0);
        assert_eq!(p::pthread_cond_destroy(&mut cond), 0);
        assert_eq!(p::pthread_mutex_destroy(&mut mutex), 0);
    }
}
