//! Differential gate: sched_getaffinity mask zero-fill vs live host glibc.
//!
//! The kernel only writes the leading bytes of the cpu mask; glibc zero-fills
//! the remainder of the caller's buffer (so high CPUs read clear), but fl left
//! stale contents. With a 0xFF-prefilled buffer, fl's tail stayed 0xFF while
//! glibc's was zeroed. We compare the full mask buffer + return code. glibc via
//! dlsym.
#![cfg(target_os = "linux")]
#![allow(unsafe_code)]

use frankenlibc_abi::unistd_abi as fl;
use std::ffi::{c_int, c_void};

unsafe extern "C" {
    fn dlopen(filename: *const i8, flag: c_int) -> *mut c_void;
    fn dlsym(handle: *mut c_void, symbol: *const i8) -> *mut c_void;
}
type Fn_ = unsafe extern "C" fn(c_int, usize, *mut c_void) -> c_int;

fn glibc() -> Fn_ {
    unsafe {
        let h = dlopen(c"libc.so.6".as_ptr(), 2);
        assert!(!h.is_null());
        std::mem::transmute(dlsym(h, c"sched_getaffinity".as_ptr()))
    }
}

#[test]
fn sched_getaffinity_zerofills_mask_like_glibc() {
    let g = glibc();
    let mut mism = Vec::new();
    // A few buffer sizes (all multiples of sizeof(long), as the syscall requires)
    // larger than the kernel will actually write on a normal machine.
    for &sz in &[64usize, 128, 256] {
        let mut gb = vec![0xFFu8; sz];
        let mut fb = vec![0xFFu8; sz];
        let gr = unsafe { g(0, sz, gb.as_mut_ptr().cast()) };
        let fr = unsafe { fl::sched_getaffinity(0, sz, fb.as_mut_ptr().cast()) };
        if gr != fr {
            mism.push(format!("sz={sz}: rc glibc={gr} fl={fr}"));
        } else if gr == 0 && gb != fb {
            mism.push(format!(
                "sz={sz}: mask differs glibc={} fl={}",
                gb.iter().map(|b| format!("{b:02x}")).collect::<String>(),
                fb.iter().map(|b| format!("{b:02x}")).collect::<String>()
            ));
        }
    }
    assert!(mism.is_empty(), "sched_getaffinity diverged:\n{}", mism.join("\n"));
}
