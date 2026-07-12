// gcvt (%g float->string) takes a caller buffer but core render_gcvt still returns
// a per-call String (deployed→interposed malloc) that gcvt copies out. Measure fl
// vs host glibc to size an alloc-elimination refactor.
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
        type Gcvt = unsafe extern "C" fn(f64, i32, *mut libc::c_char) -> *mut libc::c_char;
        let gl_gcvt: Gcvt =
            std::mem::transmute::<*mut c_void, Gcvt>(libc::dlsym(h, b"gcvt\0".as_ptr().cast()));

        let iters = 5_000_000usize;
        let mut fbuf = [0i8; 64];
        let mut gbuf = [0i8; 64];

        for (name, val, nd) in [
            ("g_pi17", 3.141592653589793f64, 17),
            ("g_pi6", 3.141592653589793f64, 6),
            ("g_big", 1.23456789e20f64, 15),
        ] {
            let t = Instant::now();
            for _ in 0..iters {
                black_box(frankenlibc_abi::stdlib_abi::gcvt(
                    black_box(val), nd, fbuf.as_mut_ptr(),
                ));
            }
            let fl = t.elapsed().as_nanos() as f64 / iters as f64;
            let t = Instant::now();
            for _ in 0..iters {
                black_box(gl_gcvt(black_box(val), nd, gbuf.as_mut_ptr()));
            }
            let gl = t.elapsed().as_nanos() as f64 / iters as f64;
            println!("{name} fl={fl:.1}ns glibc={gl:.1}ns  fl/glibc={:.2}x", fl / gl);
        }
    }
}
