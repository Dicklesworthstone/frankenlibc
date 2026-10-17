//! Native-plugin thread attributes, recovery, deadlines and cancellation.
//!
//! Use the same ABI backend as the basic pthread bindings, not a second set
//! of host synchronization objects. Native clone-backend limitations remain
//! the responsibility of those frontends; this does not claim to remove them.

use crate::pthread_abi as pthread;
#[cfg(not(debug_assertions))]
use crate::setjmp_abi;

pub(super) fn address(name: &str, version: Option<&str>) -> Option<u64> {
    macro_rules! entry {
        ($function:ident, $first:literal, $merged:literal) => {
            (pthread::$function as *const (), $first, $merged)
        };
    }
    let (function, first, merged) = match name {
        "pthread_attr_init" => entry!(pthread_attr_init, "GLIBC_2.2.5", false),
        "pthread_attr_destroy" => entry!(pthread_attr_destroy, "GLIBC_2.2.5", false),
        "pthread_attr_getdetachstate" => entry!(pthread_attr_getdetachstate, "GLIBC_2.2.5", false),
        "pthread_attr_setdetachstate" => entry!(pthread_attr_setdetachstate, "GLIBC_2.2.5", false),
        "pthread_attr_getstacksize" => entry!(pthread_attr_getstacksize, "GLIBC_2.2.5", true),
        "pthread_attr_setstacksize" => entry!(pthread_attr_setstacksize, "GLIBC_2.2.5", true),
        "pthread_attr_getguardsize" => entry!(pthread_attr_getguardsize, "GLIBC_2.2.5", true),
        "pthread_attr_setguardsize" => entry!(pthread_attr_setguardsize, "GLIBC_2.2.5", true),
        "pthread_attr_getstack" => entry!(pthread_attr_getstack, "GLIBC_2.2.5", true),
        "pthread_attr_setstack" => entry!(pthread_attr_setstack, "GLIBC_2.2.5", true),
        "pthread_attr_getinheritsched" => {
            entry!(pthread_attr_getinheritsched, "GLIBC_2.2.5", false)
        }
        "pthread_attr_setinheritsched" => {
            entry!(pthread_attr_setinheritsched, "GLIBC_2.2.5", false)
        }
        "pthread_attr_getschedpolicy" => entry!(pthread_attr_getschedpolicy, "GLIBC_2.2.5", false),
        "pthread_attr_setschedpolicy" => entry!(pthread_attr_setschedpolicy, "GLIBC_2.2.5", false),
        "pthread_attr_getschedparam" => entry!(pthread_attr_getschedparam, "GLIBC_2.2.5", false),
        "pthread_attr_setschedparam" => entry!(pthread_attr_setschedparam, "GLIBC_2.2.5", false),
        "pthread_attr_getscope" => entry!(pthread_attr_getscope, "GLIBC_2.2.5", false),
        "pthread_attr_setscope" => entry!(pthread_attr_setscope, "GLIBC_2.2.5", false),
        "pthread_mutexattr_init" => entry!(pthread_mutexattr_init, "GLIBC_2.2.5", true),
        "pthread_mutexattr_destroy" => entry!(pthread_mutexattr_destroy, "GLIBC_2.2.5", true),
        "pthread_mutexattr_gettype" => entry!(pthread_mutexattr_gettype, "GLIBC_2.2.5", true),
        "pthread_mutexattr_settype" => entry!(pthread_mutexattr_settype, "GLIBC_2.2.5", true),
        "pthread_mutexattr_getpshared" => entry!(pthread_mutexattr_getpshared, "GLIBC_2.2.5", true),
        "pthread_mutexattr_setpshared" => entry!(pthread_mutexattr_setpshared, "GLIBC_2.2.5", true),
        "pthread_mutexattr_getprotocol" => entry!(pthread_mutexattr_getprotocol, "GLIBC_2.4", true),
        "pthread_mutexattr_setprotocol" => entry!(pthread_mutexattr_setprotocol, "GLIBC_2.4", true),
        "pthread_mutexattr_getrobust" => entry!(pthread_mutexattr_getrobust, "GLIBC_2.12", true),
        "pthread_mutexattr_setrobust" => entry!(pthread_mutexattr_setrobust, "GLIBC_2.12", true),
        "pthread_mutex_consistent" => entry!(pthread_mutex_consistent, "GLIBC_2.12", true),
        "pthread_cond_clockwait" => entry!(pthread_cond_clockwait, "GLIBC_2.30", true),
        "pthread_condattr_init" => entry!(pthread_condattr_init, "GLIBC_2.2.5", false),
        "pthread_condattr_destroy" => entry!(pthread_condattr_destroy, "GLIBC_2.2.5", false),
        "pthread_condattr_getclock" => entry!(pthread_condattr_getclock, "GLIBC_2.3.3", true),
        "pthread_condattr_setclock" => entry!(pthread_condattr_setclock, "GLIBC_2.3.3", true),
        "pthread_condattr_getpshared" => entry!(pthread_condattr_getpshared, "GLIBC_2.2.5", true),
        "pthread_condattr_setpshared" => entry!(pthread_condattr_setpshared, "GLIBC_2.2.5", true),
        "pthread_rwlockattr_init" => entry!(pthread_rwlockattr_init, "GLIBC_2.2.5", true),
        "pthread_rwlockattr_destroy" => entry!(pthread_rwlockattr_destroy, "GLIBC_2.2.5", true),
        "pthread_rwlockattr_getpshared" => {
            entry!(pthread_rwlockattr_getpshared, "GLIBC_2.2.5", true)
        }
        "pthread_rwlockattr_setpshared" => {
            entry!(pthread_rwlockattr_setpshared, "GLIBC_2.2.5", true)
        }
        "pthread_rwlock_timedrdlock" => entry!(pthread_rwlock_timedrdlock, "GLIBC_2.2.5", true),
        "pthread_rwlock_timedwrlock" => entry!(pthread_rwlock_timedwrlock, "GLIBC_2.2.5", true),
        "pthread_cancel" => entry!(pthread_cancel, "GLIBC_2.2.5", true),
        "pthread_testcancel" => entry!(pthread_testcancel, "GLIBC_2.2.5", true),
        "pthread_setcancelstate" => entry!(pthread_setcancelstate, "GLIBC_2.2.5", false),
        "pthread_setcanceltype" => entry!(pthread_setcanceltype, "GLIBC_2.2.5", false),
        "__pthread_register_cancel" => entry!(__pthread_register_cancel, "GLIBC_2.3.3", true),
        "__pthread_unregister_cancel" => entry!(__pthread_unregister_cancel, "GLIBC_2.3.3", true),
        "__pthread_register_cancel_defer" => {
            entry!(__pthread_register_cancel_defer, "GLIBC_2.3.3", true)
        }
        "__pthread_unregister_cancel_restore" => {
            entry!(__pthread_unregister_cancel_restore, "GLIBC_2.3.3", true)
        }
        "__pthread_cleanup_routine" => entry!(__pthread_cleanup_routine, "GLIBC_2.3.3", true),
        "__pthread_unwind_next" => entry!(__pthread_unwind_next, "GLIBC_2.3.3", true),
        // C pthread_cleanup_push saves this exact ABI buffer before linking it
        // into the thread cleanup chain. Never replace a returns-twice entry
        // with an ordinary wrapper frame.
        "__sigsetjmp" => (cleanup_setjmp_address(), "GLIBC_2.2.5", false),
        _ => return None,
    };
    // Explicit-clock waits postdate AArch64's baseline as well.
    let first = if cfg!(target_arch = "aarch64") && first != "GLIBC_2.30" {
        "GLIBC_2.17"
    } else {
        first
    };
    if version.is_some_and(|requested| requested != first && !(merged && requested == "GLIBC_2.34"))
    {
        return None;
    }
    Some(function as usize as u64)
}

fn cleanup_setjmp_address() -> *const () {
    #[cfg(not(debug_assertions))]
    {
        setjmp_abi::__sigsetjmp as *const ()
    }
    #[cfg(debug_assertions)]
    {
        // The debug rlib deliberately omits the naked owned setjmp exports.
        // Its tests run on host threads. Use the actual returns-twice host
        // entry, NOT setjmp_abi's ordinary debug Rust wrapper, whose frame
        // would be gone when a C cleanup handler later restores the buffer.
        unsafe extern "C" {
            #[link_name = "__sigsetjmp"]
            fn debug_sigsetjmp(
                env: *mut std::ffi::c_void,
                save: std::ffi::c_int,
            ) -> std::ffi::c_int;
        }
        debug_sigsetjmp as *const ()
    }
}
