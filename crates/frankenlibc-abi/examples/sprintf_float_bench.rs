// printf %e/%g go through format_float's general path which calls format_e/format_g
// -> a per-call String (deployed->interposed malloc) copied into the output buffer.
// %f is mostly fast-pathed. Measure fl sprintf vs host glibc to size the gap.
use std::ffi::c_void;
use std::hint::black_box;
use std::time::Instant;

#[allow(clippy::approx_constant)]
fn main() {
    unsafe {
        let h = libc::dlmopen(
            libc::LM_ID_NEWLM,
            c"libc.so.6".as_ptr(),
            libc::RTLD_LAZY | libc::RTLD_LOCAL,
        );
        assert!(!h.is_null(), "dlmopen libc failed");
        type Snp = unsafe extern "C" fn(*mut libc::c_char, usize, *const libc::c_char, ...) -> i32;
        let gl_snprintf: Snp =
            std::mem::transmute::<*mut c_void, Snp>(libc::dlsym(h, c"snprintf".as_ptr()));

        let iters = 3_000_000usize;
        let val = 3.141592653589793f64;
        let mut fb = [0i8; 64];
        let mut gb = [0i8; 64];

        for (name, fmt) in [
            ("g", c"%.15g".as_ptr()),
            ("e", c"%.15e".as_ptr()),
            ("f", c"%.10f".as_ptr()),
        ] {
            let fmtc = fmt;
            let t = Instant::now();
            for _ in 0..iters {
                frankenlibc_abi::stdio_abi::snprintf(
                    fb.as_mut_ptr(),
                    64,
                    black_box(fmtc),
                    black_box(val),
                );
            }
            let fl = t.elapsed().as_nanos() as f64 / iters as f64;
            let t = Instant::now();
            for _ in 0..iters {
                gl_snprintf(gb.as_mut_ptr(), 64, black_box(fmtc), black_box(val));
            }
            let gl = t.elapsed().as_nanos() as f64 / iters as f64;
            println!(
                "SPRINTF %{name} fl={fl:.1}ns glibc={gl:.1}ns  fl/glibc={:.2}x",
                fl / gl
            );
        }
    }
}
