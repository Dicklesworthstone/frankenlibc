//! Global state for the Transparent Safety Membrane.
//!
//! This module holds the singleton `ValidationPipeline` instance used by
//! all ABI entrypoints (`malloc`, `string`, etc.). This ensures that
//! allocations made by `malloc` are visible to the validation logic used
//! by `memcpy` and other functions.
//!
//! Uses manual atomic init instead of OnceLock to prevent deadlock under
//! LD_PRELOAD (OnceLock's futex waits on same-thread reentrant init).

use std::sync::atomic::{AtomicPtr, AtomicU8, Ordering};

use frankenlibc_membrane::ptr_validator::ValidationPipeline;

const STATE_UNINIT: u8 = 0;
const STATE_INITIALIZING: u8 = 1;
const STATE_READY: u8 = 2;

static PIPELINE_STATE: AtomicU8 = AtomicU8::new(STATE_UNINIT);
static PIPELINE_PTR: AtomicPtr<ValidationPipeline> = AtomicPtr::new(std::ptr::null_mut());

/// Global validation pipeline instance.
///
/// Returns `None` during initialization (reentrant guard) to allow
/// ABI functions to fall through to raw C behavior under LD_PRELOAD.
pub(crate) fn try_global_pipeline() -> Option<&'static ValidationPipeline> {
    let state = PIPELINE_STATE.load(Ordering::Acquire);

    if state == STATE_READY {
        let ptr = PIPELINE_PTR.load(Ordering::Acquire);
        return Some(unsafe { &*ptr });
    }

    if state == STATE_INITIALIZING {
        return None;
    }

    if PIPELINE_STATE
        .compare_exchange(
            STATE_UNINIT,
            STATE_INITIALIZING,
            Ordering::SeqCst,
            Ordering::Relaxed,
        )
        .is_err()
    {
        return if PIPELINE_STATE.load(Ordering::Acquire) == STATE_READY {
            let ptr = PIPELINE_PTR.load(Ordering::Acquire);
            Some(unsafe { &*ptr })
        } else {
            None
        };
    }

    let pipeline = Box::new(ValidationPipeline::new());
    let ptr = Box::into_raw(pipeline);
    PIPELINE_PTR.store(ptr, Ordering::Release);
    PIPELINE_STATE.store(STATE_READY, Ordering::Release);

    Some(unsafe { &*ptr })
}

/// Global validation pipeline — panics if called during init.
///
/// Use this from paths that cannot handle None (e.g., malloc where we
/// must return a pointer). These paths should only run after init completes.
#[allow(dead_code)]
pub(crate) fn global_pipeline() -> &'static ValidationPipeline {
    try_global_pipeline().expect("ValidationPipeline not initialized (reentrant LD_PRELOAD call)")
}
