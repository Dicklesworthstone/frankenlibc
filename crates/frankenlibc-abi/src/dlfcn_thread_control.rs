//! Native-plugin thread attributes, names, affinity, scheduling and lifecycle.
//!
//! Use the same ABI backend as the basic pthread bindings, not a second set
//! of host synchronization objects. Native clone-backend limitations remain
//! the responsibility of those frontends; this does not claim to remove them.

use crate::pthread_abi as pthread;
#[cfg(any(target_arch = "x86_64", not(debug_assertions)))]
use crate::setjmp_abi;

pub(super) fn address(name: &str, version: Option<&str>) -> Option<u64> {
    macro_rules! entry {
        ($function:ident, $first:literal, $merged:literal) => {
            (
                pthread::$function as *const (),
                $first,
                if $merged { Some("GLIBC_2.34") } else { None },
            )
        };
    }
    let (function, first, additional) = match name {
        "nanosleep" => (crate::time_abi::nanosleep as *const (), "GLIBC_2.2.5", None),
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
        // The GLIBC_2.3.3 affinity entries omit cpusetsize. They require
        // separate adapters and must not resolve to these current frontends.
        "pthread_attr_getaffinity_np" => entry!(pthread_attr_getaffinity_np, "GLIBC_2.3.4", true),
        "pthread_attr_setaffinity_np" => (
            pthread::pthread_attr_setaffinity_np as *const (),
            "GLIBC_2.3.4",
            Some("GLIBC_2.32"),
        ),
        "pthread_attr_getsigmask_np" => entry!(pthread_attr_getsigmask_np, "GLIBC_2.32", false),
        "pthread_attr_setsigmask_np" => entry!(pthread_attr_setsigmask_np, "GLIBC_2.32", false),
        "pthread_getattr_np" => (
            pthread::pthread_getattr_np as *const (),
            "GLIBC_2.2.5",
            Some("GLIBC_2.32"),
        ),
        "pthread_getattr_default_np" => entry!(pthread_getattr_default_np, "GLIBC_2.18", true),
        "pthread_setattr_default_np" => entry!(pthread_setattr_default_np, "GLIBC_2.18", true),
        "pthread_getaffinity_np" => (
            pthread::pthread_getaffinity_np as *const (),
            "GLIBC_2.3.4",
            Some("GLIBC_2.32"),
        ),
        "pthread_setaffinity_np" => entry!(pthread_setaffinity_np, "GLIBC_2.3.4", true),
        "pthread_getname_np" => entry!(pthread_getname_np, "GLIBC_2.12", true),
        "pthread_setname_np" => entry!(pthread_setname_np, "GLIBC_2.12", true),
        "pthread_getschedparam" => (
            crate::unistd_abi::pthread_getschedparam as *const (),
            "GLIBC_2.2.5",
            None,
        ),
        "pthread_setschedparam" => (
            crate::unistd_abi::pthread_setschedparam as *const (),
            "GLIBC_2.2.5",
            None,
        ),
        "pthread_setschedprio" => (
            crate::glibc_internal_abi::pthread_setschedprio as *const (),
            "GLIBC_2.3.4",
            Some("GLIBC_2.34"),
        ),
        "pthread_getcpuclockid" => entry!(pthread_getcpuclockid, "GLIBC_2.2.5", true),
        "pthread_sigqueue" => entry!(pthread_sigqueue, "GLIBC_2.11", true),
        "pthread_tryjoin_np" => entry!(pthread_tryjoin_np, "GLIBC_2.3.3", true),
        "pthread_timedjoin_np" => entry!(pthread_timedjoin_np, "GLIBC_2.3.3", true),
        "pthread_clockjoin_np" => entry!(pthread_clockjoin_np, "GLIBC_2.31", true),
        "pthread_barrier_init" => entry!(pthread_barrier_init, "GLIBC_2.2.5", true),
        "pthread_barrier_destroy" => entry!(pthread_barrier_destroy, "GLIBC_2.2.5", true),
        "pthread_barrier_wait" => entry!(pthread_barrier_wait, "GLIBC_2.2.5", true),
        "pthread_barrierattr_init" => entry!(pthread_barrierattr_init, "GLIBC_2.2.5", true),
        "pthread_barrierattr_destroy" => entry!(pthread_barrierattr_destroy, "GLIBC_2.2.5", true),
        "pthread_barrierattr_getpshared" => {
            entry!(pthread_barrierattr_getpshared, "GLIBC_2.3.3", true)
        }
        "pthread_barrierattr_setpshared" => {
            entry!(pthread_barrierattr_setpshared, "GLIBC_2.2.5", true)
        }
        "pthread_spin_init" => entry!(pthread_spin_init, "GLIBC_2.2.5", true),
        "pthread_spin_destroy" => entry!(pthread_spin_destroy, "GLIBC_2.2.5", true),
        "pthread_spin_lock" => entry!(pthread_spin_lock, "GLIBC_2.2.5", true),
        "pthread_spin_trylock" => entry!(pthread_spin_trylock, "GLIBC_2.2.5", true),
        "pthread_spin_unlock" => entry!(pthread_spin_unlock, "GLIBC_2.2.5", true),
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
        "pthread_rwlock_clockrdlock" => entry!(pthread_rwlock_clockrdlock, "GLIBC_2.30", true),
        "pthread_rwlock_clockwrlock" => entry!(pthread_rwlock_clockwrlock, "GLIBC_2.30", true),
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
        "__sigsetjmp" => (cleanup_setjmp_address(), "GLIBC_2.2.5", None),
        _ => return None,
    };
    // Only older entries move to AArch64's baseline. Default attributes,
    // explicit-clock waits, and attribute signal masks were added later.
    let first = if cfg!(target_arch = "aarch64")
        && matches!(
            first,
            "GLIBC_2.2.5"
                | "GLIBC_2.3.3"
                | "GLIBC_2.3.4"
                | "GLIBC_2.4"
                | "GLIBC_2.11"
                | "GLIBC_2.12"
        ) {
        "GLIBC_2.17"
    } else {
        first
    };
    if version.is_some_and(|requested| requested != first && Some(requested) != additional) {
        return None;
    }
    Some(function as usize as u64)
}

fn cleanup_setjmp_address() -> *const () {
    #[cfg(any(target_arch = "x86_64", not(debug_assertions)))]
    {
        // x86-64 has the matched naked capture/restore backend in every
        // build. Release AArch64 retains its existing native capture.
        setjmp_abi::__sigsetjmp as *const ()
    }
    #[cfg(all(target_arch = "aarch64", debug_assertions))]
    {
        // Preserve the ARM debug host capture contract. Its owned format
        // uses a different pointer guard; extending that path requires a
        // separately verified host/native cancellation boundary.
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
