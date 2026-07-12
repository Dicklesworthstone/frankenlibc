#![cfg(target_os = "linux")]
#![allow(unsafe_code)] // live host-glibc wmempcpy oracle

//! Differential gate for wmempcpy (bd-k8gugp) — previously uncovered. wmempcpy
//! copies n wide chars and returns dst + n (a pointer PAST the last copied
//! wchar, in wchar units — the wide analog of mempcpy). fl must match host
//! glibc on the returned offset and the copied contents. No mocks.

use std::os::raw::c_int;

type Wch = c_int; // wchar_t == int on Linux

unsafe extern "C" {
    fn wmempcpy(dst: *mut Wch, src: *const Wch, n: usize) -> *mut Wch;
}

fn off(ret: *mut Wch, base: *const Wch) -> isize {
    if ret.is_null() {
        -1
    } else {
        // pointer difference in wchar_t units
        (ret as isize - base as isize) / std::mem::size_of::<Wch>() as isize
    }
}

#[test]
fn wmempcpy_matches_glibc() {
    let src: Vec<Wch> = (0..16).map(|i| (0x4000 + i) as Wch).collect();
    for n in [0usize, 1, 5, 16] {
        let fill: Wch = 0x7e7e;
        let mut gd = vec![fill; 20];
        let mut fd = vec![fill; 20];
        let rg = unsafe { wmempcpy(gd.as_mut_ptr(), src.as_ptr(), n) };
        let rf = unsafe {
            frankenlibc_abi::glibc_internal_abi::wmempcpy(
                fd.as_mut_ptr() as *mut _,
                src.as_ptr() as *const _,
                n,
            ) as *mut Wch
        };
        assert_eq!(
            off(rf, fd.as_ptr()),
            off(rg, gd.as_ptr()),
            "wmempcpy(n={n}) return"
        );
        assert_eq!(
            off(rg, gd.as_ptr()),
            n as isize,
            "wmempcpy must return dst+n"
        );
        assert_eq!(fd, gd, "wmempcpy(n={n}) buffer contents");
    }
}
