// Large-buffer head-to-head: fl core mem/str SIMD vs host glibc (dlmopen, same process
// so worker load cancels in the ratio). Tests whether safe-Rust SIMD beats glibc at
// sizes where memory bandwidth / wide-SIMD throughput dominates (the survey only covers
// ~200-byte moderate buffers where SIMD setup overhead makes fl lose).
use std::ffi::c_void;
use std::hint::black_box;
use std::time::Instant;

fn main() {
    unsafe {
        let h = libc::dlmopen(
            libc::LM_ID_NEWLM,
            b"libc.so.6\0".as_ptr().cast(),
            libc::RTLD_LAZY | libc::RTLD_LOCAL,
        );
        assert!(!h.is_null(), "dlmopen libc failed");
        type MemchrFn = unsafe extern "C" fn(*const c_void, i32, usize) -> *const c_void;
        type StrlenFn = unsafe extern "C" fn(*const c_void) -> usize;
        type MemcmpFn = unsafe extern "C" fn(*const c_void, *const c_void, usize) -> i32;
        let gl_memchr: MemchrFn =
            std::mem::transmute::<*mut c_void, MemchrFn>(libc::dlsym(h, b"memchr\0".as_ptr().cast()));
        let gl_strlen: StrlenFn =
            std::mem::transmute::<*mut c_void, StrlenFn>(libc::dlsym(h, b"strlen\0".as_ptr().cast()));
        let gl_memcmp: MemcmpFn =
            std::mem::transmute::<*mut c_void, MemcmpFn>(libc::dlsym(h, b"memcmp\0".as_ptr().cast()));

        for &size in &[4096usize, 65536, 1_048_576] {
            let iters = (2_000_000_000usize / size).max(200);

            // memchr: byte 'X' only at the very end → full scan.
            let mut buf = vec![b'a'; size];
            buf[size - 1] = b'X';
            let t0 = Instant::now();
            for _ in 0..iters {
                black_box(frankenlibc_core::string::mem::memchr(black_box(&buf), b'X', size));
            }
            let fl = t0.elapsed().as_nanos() as f64 / iters as f64;
            let t1 = Instant::now();
            for _ in 0..iters {
                black_box(gl_memchr(black_box(buf.as_ptr().cast()), b'X' as i32, size));
            }
            let gl = t1.elapsed().as_nanos() as f64 / iters as f64;
            println!("MEM memchr size={size} fl={fl:.0}ns glibc={gl:.0}ns fl/glibc={:.2}x", fl / gl);

            // strlen: NUL only at the end → full scan.
            let mut sbuf = vec![b'a'; size];
            sbuf[size - 1] = 0;
            let t2 = Instant::now();
            for _ in 0..iters {
                black_box(frankenlibc_core::string::str::strlen(black_box(&sbuf)));
            }
            let fls = t2.elapsed().as_nanos() as f64 / iters as f64;
            let t3 = Instant::now();
            for _ in 0..iters {
                black_box(gl_strlen(black_box(sbuf.as_ptr().cast())));
            }
            let gls = t3.elapsed().as_nanos() as f64 / iters as f64;
            println!("MEM strlen size={size} fl={fls:.0}ns glibc={gls:.0}ns fl/glibc={:.2}x", fls / gls);

            // memcmp: equal buffers except the last byte → full scan.
            let a = vec![b'a'; size];
            let mut b = vec![b'a'; size];
            b[size - 1] = b'b';
            let t4 = Instant::now();
            for _ in 0..iters {
                black_box(frankenlibc_core::string::mem::memcmp(black_box(&a), black_box(&b), size));
            }
            let flc = t4.elapsed().as_nanos() as f64 / iters as f64;
            let t5 = Instant::now();
            for _ in 0..iters {
                black_box(gl_memcmp(black_box(a.as_ptr().cast()), black_box(b.as_ptr().cast()), size));
            }
            let glc = t5.elapsed().as_nanos() as f64 / iters as f64;
            println!("MEM memcmp size={size} fl={flc:.0}ns glibc={glc:.0}ns fl/glibc={:.2}x", flc / glc);
        }
    }
}
