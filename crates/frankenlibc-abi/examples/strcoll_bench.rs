// strcoll head-to-head: fl strcoll vs host glibc strcoll (dlmopen, C locale). In the C
// locale strcoll == strcmp, but glibc's strcoll carries locale-dispatch overhead. Sign
// verified equal.
use std::ffi::{CString, c_void};
use std::hint::black_box;
use std::time::Instant;

use frankenlibc_core::string::str::strcoll;

fn main() {
    unsafe {
        let h = libc::dlmopen(
            libc::LM_ID_NEWLM,
            b"libc.so.6\0".as_ptr().cast(),
            libc::RTLD_LAZY | libc::RTLD_LOCAL,
        );
        assert!(!h.is_null(), "dlmopen libc failed");
        type StrcollFn = unsafe extern "C" fn(*const libc::c_char, *const libc::c_char) -> i32;
        let gl_strcoll: StrcollFn = std::mem::transmute::<*mut c_void, StrcollFn>(libc::dlsym(
            h,
            b"strcoll\0".as_ptr().cast(),
        ));

        // Differ near the end -> a (near) full-length compare.
        let a = "the quick brown fox jumps over the lazy dog A";
        let b = "the quick brown fox jumps over the lazy dog B";
        let mut ab: Vec<u8> = a.as_bytes().to_vec();
        ab.push(0);
        let mut bb: Vec<u8> = b.as_bytes().to_vec();
        bb.push(0);
        let ca = CString::new(a).unwrap();
        let cb = CString::new(b).unwrap();

        let fl_r = strcoll(&ab, &bb);
        let gl_r = gl_strcoll(ca.as_ptr(), cb.as_ptr());
        assert_eq!(
            fl_r.signum(),
            gl_r.signum(),
            "strcoll sign: fl={fl_r} glibc={gl_r}"
        );

        let iters = 2_000_000usize;
        let t0 = Instant::now();
        for _ in 0..iters {
            black_box(strcoll(black_box(&ab), black_box(&bb)));
        }
        let fl = t0.elapsed().as_nanos() as f64 / iters as f64;
        let t1 = Instant::now();
        for _ in 0..iters {
            black_box(gl_strcoll(black_box(ca.as_ptr()), black_box(cb.as_ptr())));
        }
        let gl = t1.elapsed().as_nanos() as f64 / iters as f64;
        println!(
            "STRCOLL len={} fl={fl:.1}ns glibc={gl:.1}ns fl/glibc={:.3}x",
            a.len(),
            fl / gl
        );
    }
}
