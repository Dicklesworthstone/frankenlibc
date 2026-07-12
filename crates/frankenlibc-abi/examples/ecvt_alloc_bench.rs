// ecvt/fcvt convert a double to a digit string. fl's core ecvt/fcvt return a
// per-call Vec<u8> (heap alloc) that the ABI copies into a static buffer and
// drops; glibc writes digits straight into its static buffer (no alloc). Measure
// the gap to size an alloc-elimination refactor.
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
        let gl_ecvt: Cvt =
            std::mem::transmute::<*mut c_void, Cvt>(libc::dlsym(h, b"ecvt\0".as_ptr().cast()));
        let gl_fcvt: Cvt =
            std::mem::transmute::<*mut c_void, Cvt>(libc::dlsym(h, b"fcvt\0".as_ptr().cast()));

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
    }
}
