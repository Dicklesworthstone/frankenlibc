//! Differential gate for the public `strncpy`/`stpncpy` ABI after replacing the
//! byte-at-a-time copy+pad loop with SWAR scan + wide block copy + wide NUL pad.
//! fl must produce byte-identical destination buffers (full n bytes, incl. the
//! NUL padding) to host glibc across source lengths, `n` straddling the NUL, and
//! both source and destination alignments — the regime where the wide copy and
//! wide pad replace the old scalar loop.
#![cfg(target_os = "linux")]
#![allow(unsafe_code)]

use frankenlibc_abi::string_abi::{stpncpy as fl_stpncpy, strncpy as fl_strncpy};
use std::os::raw::c_char;

#[test]
fn strncpy_stpncpy_match_glibc() {
    let mut checked = 0u64;
    let lengths = [0usize, 1, 7, 8, 15, 16, 17, 31, 33, 63, 64, 100, 128, 255, 300];
    let ns = [0usize, 1, 8, 16, 33, 64, 100, 128, 256, 301];

    for &src_off in &[0usize, 1, 3, 7] {
        for &dst_off in &[0usize, 1, 3, 7] {
            for &len in &lengths {
                // src: `len` non-NUL bytes (incl high-bit) then NUL.
                let mut src_buf = vec![0u8; src_off + len + 1];
                for k in 0..len {
                    let b = (k as u8).wrapping_mul(53).wrapping_add(1);
                    src_buf[src_off + k] = if b == 0 { 0x80 } else { b };
                }
                src_buf[src_off + len] = 0;
                let src = unsafe { src_buf.as_ptr().add(src_off) } as *const c_char;

                for &n in &ns {
                    // Destination buffers preset to 0xAA so any unwritten byte shows.
                    let mut fl = vec![0xAAu8; dst_off + n + 1];
                    let mut gl = vec![0xAAu8; dst_off + n + 1];
                    let fl_end = unsafe { fl_strncpy(fl.as_mut_ptr().add(dst_off) as *mut c_char, src, n) };
                    let gl_ret = unsafe {
                        libc::strncpy(gl.as_mut_ptr().add(dst_off) as *mut c_char, src, n)
                    };
                    let _ = (fl_end, gl_ret);
                    assert_eq!(
                        fl, gl,
                        "strncpy src_off={src_off} dst_off={dst_off} len={len} n={n}"
                    );

                    // stpncpy: same buffer result + the returned end offset.
                    let mut fl2 = vec![0xAAu8; dst_off + n + 1];
                    let mut gl2 = vec![0xAAu8; dst_off + n + 1];
                    let fl_base = unsafe { fl2.as_mut_ptr().add(dst_off) };
                    let gl_base = unsafe { gl2.as_mut_ptr().add(dst_off) };
                    let fe = unsafe { fl_stpncpy(fl_base as *mut c_char, src, n) };
                    let ge = unsafe { libc::stpncpy(gl_base as *mut c_char, src, n) };
                    assert_eq!(fl2, gl2, "stpncpy buf src_off={src_off} dst_off={dst_off} len={len} n={n}");
                    assert_eq!(
                        fe as usize - fl_base as usize,
                        ge as usize - gl_base as usize,
                        "stpncpy end off src_off={src_off} dst_off={dst_off} len={len} n={n}"
                    );
                    checked += 1;
                }
            }
        }
    }
    assert!(checked >= 2400, "corpus unexpectedly small: {checked}");
}
