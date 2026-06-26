// memccpy head-to-head: fl SIMD memchr(find c) + SIMD memcpy(prefix) vs host glibc
// memccpy. Stop-byte at the end so the whole buffer is scanned + copied. Output verified.
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
        type MemccpyFn = unsafe extern "C" fn(*mut c_void, *const c_void, i32, usize) -> *mut c_void;
        let gl_memccpy: MemccpyFn =
            std::mem::transmute::<*mut c_void, MemccpyFn>(libc::dlsym(h, b"memccpy\0".as_ptr().cast()));

        for &n in &[256usize, 4096, 65536] {
            let mut src = vec![b'a'; n];
            src[n - 1] = b'Z'; // stop byte at the end -> copies all n bytes
            let c = b'Z';
            let mut dst_fl = vec![0u8; n];
            let mut dst_gl = vec![0u8; n];
            let fl_r = frankenlibc_core::string::mem::memccpy(&mut dst_fl, &src, c, n);
            let gl_r = gl_memccpy(dst_gl.as_mut_ptr().cast(), src.as_ptr().cast(), c as i32, n);
            assert!(fl_r.is_some() && !gl_r.is_null(), "memccpy n={n}: c not found");
            assert_eq!(dst_fl, dst_gl, "memccpy n={n}: output mismatch");

            let iters = (200_000_000usize / n).max(2000);
            let t0 = Instant::now();
            for _ in 0..iters {
                black_box(frankenlibc_core::string::mem::memccpy(black_box(&mut dst_fl), black_box(&src), c, n));
            }
            let fl = t0.elapsed().as_nanos() as f64 / iters as f64;
            let t1 = Instant::now();
            for _ in 0..iters {
                black_box(gl_memccpy(
                    black_box(dst_gl.as_mut_ptr().cast()),
                    black_box(src.as_ptr().cast()),
                    c as i32,
                    n,
                ));
            }
            let gl = t1.elapsed().as_nanos() as f64 / iters as f64;
            println!("MEMCCPY n={n} fl={fl:.0}ns glibc={gl:.0}ns fl/glibc={:.3}x", fl / gl);
        }
    }
}
