#![cfg(all(feature = "standalone", feature = "owned-unwind-stub"))]

use frankenlibc_abi::owned_unwind_abi::{
    __deregister_frame, __deregister_frame_info, __register_frame, __register_frame_info,
    _Unwind_Backtrace, _Unwind_GetIP, UnwindContext, owned_frame_is_registered_for_tests,
    owned_frame_object_for_tests,
};
use std::ffi::c_void;

const URC_NO_REASON: i32 = 0;

unsafe extern "C" fn collect_frame_ip(ctx: *mut UnwindContext, arg: *mut c_void) -> i32 {
    let frames = unsafe { &mut *(arg.cast::<Vec<usize>>()) };
    let ip = unsafe { _Unwind_GetIP(ctx) };
    if ip != 0 {
        frames.push(ip);
    }
    URC_NO_REASON
}

#[inline(never)]
fn walk_from_inner(frames: &mut Vec<usize>) -> i32 {
    unsafe { _Unwind_Backtrace(Some(collect_frame_ip), (frames as *mut Vec<usize>).cast()) }
}

#[inline(never)]
fn walk_from_outer(frames: &mut Vec<usize>) -> i32 {
    walk_from_inner(frames)
}

#[test]
fn backtrace_walk_reports_real_instruction_pointers() {
    let mut frames = Vec::new();
    let reason = walk_from_outer(&mut frames);

    assert_eq!(reason, 5, "walk should finish with _URC_END_OF_STACK");
    assert!(
        frames.len() >= 2,
        "frame-pointer walk should discover real caller frames, got {frames:?}"
    );
    assert!(
        frames.iter().all(|ip| *ip != 0),
        "reported instruction pointers must be nonzero: {frames:?}"
    );
}

#[test]
fn frame_registration_records_and_removes_fde_sources() {
    let mut fake_fde = 0usize;
    let mut fake_object = 0usize;
    let fde = (&mut fake_fde as *mut usize).cast::<c_void>();
    let object = (&mut fake_object as *mut usize).cast::<c_void>();

    assert!(!owned_frame_is_registered_for_tests(fde.cast_const()));
    assert!(owned_frame_object_for_tests(fde.cast_const()).is_null());

    unsafe { __register_frame(fde) };
    assert!(owned_frame_is_registered_for_tests(fde.cast_const()));
    assert!(owned_frame_object_for_tests(fde.cast_const()).is_null());

    unsafe { __register_frame_info(fde, object) };
    assert!(owned_frame_is_registered_for_tests(fde.cast_const()));
    assert_eq!(owned_frame_object_for_tests(fde.cast_const()), object);

    let removed = unsafe { __deregister_frame_info(fde) };
    assert_eq!(removed, object);
    assert!(!owned_frame_is_registered_for_tests(fde.cast_const()));
    assert!(owned_frame_object_for_tests(fde.cast_const()).is_null());

    unsafe { __register_frame(fde) };
    assert!(owned_frame_is_registered_for_tests(fde.cast_const()));

    unsafe { __deregister_frame(fde) };
    assert!(!owned_frame_is_registered_for_tests(fde.cast_const()));
}
