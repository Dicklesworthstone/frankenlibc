// sscanf head-to-head: fl (interposed) vs host glibc (dlmopen). Variadic.
// Return value + parsed outputs verified equal first.
use std::ffi::{c_char, c_int, c_void};
use std::hint::black_box;
use std::time::Instant;

unsafe extern "C" {
    fn sscanf(s: *const c_char, fmt: *const c_char, ...) -> c_int;
}

fn main() {
    unsafe {
        let h = libc::dlmopen(
            libc::LM_ID_NEWLM,
            b"libc.so.6\0".as_ptr().cast(),
            libc::RTLD_LAZY | libc::RTLD_LOCAL,
        );
        assert!(!h.is_null(), "dlmopen libc failed");
        type SsFn = unsafe extern "C" fn(*const c_char, *const c_char, ...) -> c_int;
        let gl: SsFn =
            std::mem::transmute::<*mut c_void, SsFn>(libc::dlsym(h, b"sscanf\0".as_ptr().cast()));

        macro_rules! probe_int3 {
            ($label:expr, $input:expr, $fmt:expr) => {{
                let inp = concat!($input, "\0").as_ptr() as *const c_char;
                let fmt = concat!($fmt, "\0").as_ptr() as *const c_char;
                let (mut a, mut b, mut c) = (0i32, 0i32, 0i32);
                let (mut ga, mut gb, mut gc) = (0i32, 0i32, 0i32);
                let fr = sscanf(inp, fmt, &mut a, &mut b, &mut c);
                let gr = gl(inp, fmt, &mut ga, &mut gb, &mut gc);
                assert_eq!((fr, a, b, c), (gr, ga, gb, gc), "sscanf {} mismatch", $label);
                let iters = 3_000_000usize;
                let t0 = Instant::now();
                for _ in 0..iters {
                    black_box(sscanf(black_box(inp), black_box(fmt), &mut a, &mut b, &mut c));
                }
                let fl = t0.elapsed().as_nanos() as f64 / iters as f64;
                let t1 = Instant::now();
                for _ in 0..iters {
                    black_box(gl(black_box(inp), black_box(fmt), &mut ga, &mut gb, &mut gc));
                }
                let g = t1.elapsed().as_nanos() as f64 / iters as f64;
                println!("SSCANF {} fl={:.1}ns glibc={:.1}ns fl/glibc={:.3}x", $label, fl, g, fl / g);
            }};
        }

        probe_int3!("3int", "10 20 30", "%d %d %d");
        probe_int3!("csv", "10,20,30", "%d,%d,%d");

        // float
        {
            let inp = b"3.14159 2.71828\0".as_ptr() as *const c_char;
            let fmt = b"%lf %lf\0".as_ptr() as *const c_char;
            let (mut a, mut b) = (0f64, 0f64);
            let (mut ga, mut gb) = (0f64, 0f64);
            let fr = sscanf(inp, fmt, &mut a, &mut b);
            let gr = gl(inp, fmt, &mut ga, &mut gb);
            assert_eq!((fr, a, b), (gr, ga, gb), "sscanf float mismatch");
            let iters = 3_000_000usize;
            let t0 = Instant::now();
            for _ in 0..iters {
                black_box(sscanf(black_box(inp), black_box(fmt), &mut a, &mut b));
            }
            let fl = t0.elapsed().as_nanos() as f64 / iters as f64;
            let t1 = Instant::now();
            for _ in 0..iters {
                black_box(gl(black_box(inp), black_box(fmt), &mut ga, &mut gb));
            }
            let g = t1.elapsed().as_nanos() as f64 / iters as f64;
            println!("SSCANF float fl={fl:.1}ns glibc={g:.1}ns fl/glibc={:.3}x", fl / g);
        }
    }
}
