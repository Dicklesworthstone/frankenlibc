// Measure the legacy cvt family against glibc, including the reentrant ecvt_r
// path whose caller-owned buffer makes allocation unnecessary.
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
        type Cvt = unsafe extern "C" fn(f64, i32, *mut i32, *mut i32) -> *mut libc::c_char;
        type CvtR = unsafe extern "C" fn(
            f64,
            i32,
            *mut i32,
            *mut i32,
            *mut libc::c_char,
            usize,
        ) -> i32;
        let gl_ecvt: Cvt =
            std::mem::transmute::<*mut c_void, Cvt>(libc::dlsym(h, b"ecvt\0".as_ptr().cast()));
        let gl_fcvt: Cvt =
            std::mem::transmute::<*mut c_void, Cvt>(libc::dlsym(h, b"fcvt\0".as_ptr().cast()));
        let gl_ecvt_r: CvtR = std::mem::transmute::<*mut c_void, CvtR>(libc::dlsym(
            h,
            b"ecvt_r\0".as_ptr().cast(),
        ));

        let iters = 5_000_000usize;
        let val = 3.141592653589793f64;
        let (mut dp, mut sg) = (0i32, 0i32);

        for (name, ndigit) in [("ecvt17", 17), ("ecvt6", 6)] {
            let t = Instant::now();
            for _ in 0..iters {
                black_box(frankenlibc_abi::stdlib_abi::ecvt(
                    black_box(val), ndigit, &mut dp, &mut sg,
                ));
            }
            let fl = t.elapsed().as_nanos() as f64 / iters as f64;
            let t = Instant::now();
            for _ in 0..iters {
                black_box(gl_ecvt(black_box(val), ndigit, &mut dp, &mut sg));
            }
            let gl = t.elapsed().as_nanos() as f64 / iters as f64;
            println!("{name} fl={fl:.1}ns glibc={gl:.1}ns  fl/glibc={:.2}x", fl / gl);
        }
        for (name, ndigit) in [("fcvt10", 10)] {
            let t = Instant::now();
            for _ in 0..iters {
                black_box(frankenlibc_abi::stdlib_abi::fcvt(
                    black_box(val), ndigit, &mut dp, &mut sg,
                ));
            }
            let fl = t.elapsed().as_nanos() as f64 / iters as f64;
            let t = Instant::now();
            for _ in 0..iters {
                black_box(gl_fcvt(black_box(val), ndigit, &mut dp, &mut sg));
            }
            let gl = t.elapsed().as_nanos() as f64 / iters as f64;
            println!("{name} fl={fl:.1}ns glibc={gl:.1}ns  fl/glibc={:.2}x", fl / gl);
        }
        let mut fl_buf = [0 as libc::c_char; 520];
        let mut gl_buf = [0 as libc::c_char; 520];
        for (name, ndigit) in [("ecvt_r17", 17), ("ecvt_r6", 6)] {
            let t = Instant::now();
            for _ in 0..iters {
                black_box(frankenlibc_abi::stdlib_abi::ecvt_r(
                    black_box(val),
                    ndigit,
                    &mut dp,
                    &mut sg,
                    fl_buf.as_mut_ptr(),
                    fl_buf.len(),
                ));
            }
            let fl = t.elapsed().as_nanos() as f64 / iters as f64;
            let t = Instant::now();
            for _ in 0..iters {
                black_box(gl_ecvt_r(
                    black_box(val),
                    ndigit,
                    &mut dp,
                    &mut sg,
                    gl_buf.as_mut_ptr(),
                    gl_buf.len(),
                ));
            }
            let gl = t.elapsed().as_nanos() as f64 / iters as f64;
            println!("{name} fl={fl:.1}ns glibc={gl:.1}ns  fl/glibc={:.2}x", fl / gl);
        }
    }
}
