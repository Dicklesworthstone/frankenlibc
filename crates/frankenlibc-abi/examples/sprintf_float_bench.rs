// printf %e/%g go through format_float's general path which calls format_e/format_g
// -> a per-call String (deployed->interposed malloc) copied into the output buffer.
// %f is mostly fast-pathed. Measure fl sprintf vs host glibc to size the gap.
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
        type Snp = unsafe extern "C" fn(*mut libc::c_char, usize, *const libc::c_char, ...) -> i32;
        let gl_snprintf: Snp =
            std::mem::transmute::<*mut c_void, Snp>(libc::dlsym(h, b"snprintf\0".as_ptr().cast()));

        let iters = 3_000_000usize;
        let val = 3.141592653589793f64;
        let mut fb = [0i8; 64];
        let mut gb = [0i8; 64];

        for (name, fmt) in [
            ("g", b"%.15g\0".as_ptr()),
            ("e", b"%.15e\0".as_ptr()),
            ("f", b"%.10f\0".as_ptr()),
        ] {
            let fmtc = fmt as *const libc::c_char;
            let t = Instant::now();
            for _ in 0..iters {
                frankenlibc_abi::stdio_abi::snprintf(
                    fb.as_mut_ptr(), 64, black_box(fmtc), black_box(val),
                );
            }
            let fl = t.elapsed().as_nanos() as f64 / iters as f64;
            let t = Instant::now();
            for _ in 0..iters {
                gl_snprintf(gb.as_mut_ptr(), 64, black_box(fmtc), black_box(val));
            }
            let gl = t.elapsed().as_nanos() as f64 / iters as f64;
            println!("SPRINTF %{name} fl={fl:.1}ns glibc={gl:.1}ns  fl/glibc={:.2}x", fl / gl);
        }
    }
}
