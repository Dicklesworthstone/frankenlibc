//! ABI layer for selected `<pthread.h>` functions.
//!
//! This bootstrap implementation provides runtime-math routed threading surfaces
//! while full POSIX pthread coverage is still in progress.

#![allow(clippy::missing_safety_doc)]

use std::cell::Cell;
use std::collections::HashMap;
use std::ffi::{c_int, c_void};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Mutex, OnceLock};
use std::thread;

use glibc_rs_membrane::runtime_math::{ApiFamily, MembraneAction};

use crate::runtime_policy;

type JoinTable = HashMap<libc::pthread_t, thread::JoinHandle<usize>>;
type StartRoutine = unsafe extern "C" fn(*mut c_void) -> *mut c_void;

static NEXT_THREAD_ID: AtomicU64 = AtomicU64::new(1);

thread_local! {
    static SELF_ID: Cell<libc::pthread_t> = const { Cell::new(0) };
}

fn join_table() -> &'static Mutex<JoinTable> {
    static TABLE: OnceLock<Mutex<JoinTable>> = OnceLock::new();
    TABLE.get_or_init(|| Mutex::new(HashMap::new()))
}

fn lock_join_table() -> std::sync::MutexGuard<'static, JoinTable> {
    match join_table().lock() {
        Ok(guard) => guard,
        Err(poisoned) => poisoned.into_inner(),
    }
}

fn fresh_thread_id() -> libc::pthread_t {
    NEXT_THREAD_ID.fetch_add(1, Ordering::Relaxed) as libc::pthread_t
}

fn current_thread_id() -> libc::pthread_t {
    SELF_ID.with(|slot| {
        let existing = slot.get();
        if existing != 0 {
            return existing;
        }
        let new_id = fresh_thread_id();
        slot.set(new_id);
        new_id
    })
}

/// POSIX `pthread_self`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn pthread_self() -> libc::pthread_t {
    let (_, decision) = runtime_policy::decide(ApiFamily::Threading, 0, 0, false, false, 0);
    if matches!(decision.action, MembraneAction::Deny) {
        runtime_policy::observe(ApiFamily::Threading, decision.profile, 4, true);
        return 0;
    }
    let id = current_thread_id();
    runtime_policy::observe(ApiFamily::Threading, decision.profile, 4, false);
    id
}

/// POSIX `pthread_equal`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn pthread_equal(a: libc::pthread_t, b: libc::pthread_t) -> c_int {
    let (_, decision) =
        runtime_policy::decide(ApiFamily::Threading, a as usize, 0, false, false, 0);
    let equal = if a == b { 1 } else { 0 };
    runtime_policy::observe(
        ApiFamily::Threading,
        decision.profile,
        4,
        matches!(decision.action, MembraneAction::Deny),
    );
    equal
}

/// POSIX `pthread_create`.
///
/// Returns `0` on success, otherwise an errno-style integer.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn pthread_create(
    thread_out: *mut libc::pthread_t,
    _attr: *const libc::pthread_attr_t,
    start_routine: Option<StartRoutine>,
    arg: *mut c_void,
) -> c_int {
    if thread_out.is_null() || start_routine.is_none() {
        return libc::EINVAL;
    }
    let (_, decision) =
        runtime_policy::decide(ApiFamily::Threading, arg as usize, 0, true, false, 0);
    if matches!(decision.action, MembraneAction::Deny) {
        runtime_policy::observe(ApiFamily::Threading, decision.profile, 16, true);
        return libc::EAGAIN;
    }

    let tid = fresh_thread_id();
    let start = match start_routine {
        Some(start) => start,
        None => return libc::EINVAL,
    };
    let arg_addr = arg as usize;
    let spawned = thread::Builder::new().spawn(move || {
        SELF_ID.with(|slot| slot.set(tid));
        let arg_ptr = arg_addr as *mut c_void;
        // SAFETY: pthread_create contract supplies valid start routine pointer.
        let retval = unsafe { start(arg_ptr) };
        retval as usize
    });

    match spawned {
        Ok(handle) => {
            // SAFETY: `thread_out` was validated non-null above.
            unsafe { *thread_out = tid };
            lock_join_table().insert(tid, handle);
            runtime_policy::observe(ApiFamily::Threading, decision.profile, 40, false);
            0
        }
        Err(_) => {
            runtime_policy::observe(ApiFamily::Threading, decision.profile, 40, true);
            libc::EAGAIN
        }
    }
}

/// POSIX `pthread_join`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn pthread_join(thread: libc::pthread_t, retval: *mut *mut c_void) -> c_int {
    let (_, decision) =
        runtime_policy::decide(ApiFamily::Threading, thread as usize, 0, true, false, 0);
    if matches!(decision.action, MembraneAction::Deny) {
        runtime_policy::observe(ApiFamily::Threading, decision.profile, 24, true);
        return libc::EINVAL;
    }

    let handle = lock_join_table().remove(&thread);
    let Some(handle) = handle else {
        runtime_policy::observe(ApiFamily::Threading, decision.profile, 24, true);
        return libc::ESRCH;
    };

    match handle.join() {
        Ok(rv) => {
            if !retval.is_null() {
                // SAFETY: caller-provided output pointer.
                unsafe { *retval = rv as *mut c_void };
            }
            runtime_policy::observe(ApiFamily::Threading, decision.profile, 24, false);
            0
        }
        Err(_) => {
            runtime_policy::observe(ApiFamily::Threading, decision.profile, 24, true);
            libc::EDEADLK
        }
    }
}

/// POSIX `pthread_detach`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn pthread_detach(thread: libc::pthread_t) -> c_int {
    let (_, decision) =
        runtime_policy::decide(ApiFamily::Threading, thread as usize, 0, true, false, 0);
    if matches!(decision.action, MembraneAction::Deny) {
        runtime_policy::observe(ApiFamily::Threading, decision.profile, 8, true);
        return libc::EINVAL;
    }

    let removed = lock_join_table().remove(&thread);
    let adverse = removed.is_none();
    runtime_policy::observe(ApiFamily::Threading, decision.profile, 8, adverse);
    if adverse { libc::ESRCH } else { 0 }
}
