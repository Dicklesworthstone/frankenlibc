//! Direct tests of FrankenLibC's raw-send ABI guard, not host libc.

use std::ffi::c_void;

use frankenlibc_abi::errno_abi::__errno_location;
use frankenlibc_abi::glibc_internal_abi::__res_send;

fn query() -> [u8; 17] {
    // Root, A, IN: a valid single-question QUERY.
    [0x32, 0x10, 1, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 1]
}

#[test]
fn short_raw_send_output_is_rejected_without_any_write() {
    let sent = query();
    for capacity in 0..12 {
        let mut output = [0xa5u8; 64];
        // SAFETY: the message and output are valid buffers. The deliberately
        // small advertised output must be rejected before network activity.
        let result = unsafe {
            *__errno_location() = 0;
            __res_send(
                sent.as_ptr().cast(),
                sent.len() as _,
                output.as_mut_ptr().cast(),
                capacity,
            )
        };
        assert_eq!(result, -1);
        assert_eq!(unsafe { *__errno_location() }, libc::EINVAL);
        assert_eq!(output, [0xa5; 64]);
    }
}

#[test]
fn invalid_raw_send_pointer_and_wire_lengths_do_not_touch_output() {
    let sent = query();
    for (message, length) in [
        (std::ptr::null::<c_void>(), sent.len() as i32),
        (sent.as_ptr().cast(), -1),
        (sent.as_ptr().cast(), 11),
        (sent.as_ptr().cast(), 65536),
    ] {
        let mut output = [0xa5u8; 64];
        // SAFETY: invalid pointer/length combinations are intentionally
        // rejected before dereference; the output always has its full extent.
        let result = unsafe {
            *__errno_location() = 0;
            __res_send(
                message,
                length,
                output.as_mut_ptr().cast(),
                output.len() as _,
            )
        };
        assert_eq!(result, -1);
        assert_eq!(unsafe { *__errno_location() }, libc::EINVAL);
        assert_eq!(output, [0xa5; 64]);
    }
}

#[test]
fn null_raw_send_output_is_rejected_before_network_activity() {
    let sent = query();
    // SAFETY: a valid message and deliberately null output exercise the guard.
    let result = unsafe {
        *__errno_location() = 0;
        __res_send(
            sent.as_ptr().cast(),
            sent.len() as _,
            std::ptr::null_mut(),
            512,
        )
    };
    assert_eq!(result, -1);
    assert_eq!(unsafe { *__errno_location() }, libc::EINVAL);
}
