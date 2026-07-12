//! fl fputs/fwrite vs glibc (dlmopen), each writing to its OWN fopen'd /dev/null (full-buffered).
use std::hint::black_box;
use std::time::Instant;
fn pctl(s: &[f64], q: f64) -> f64 {
    let mut v = s.to_vec();
    v.sort_by(|a, b| a.partial_cmp(b).unwrap());
    v[((q * (v.len() - 1) as f64).round() as usize).min(v.len() - 1)]
}
type FopenFn = unsafe extern "C" fn(*const i8, *const i8) -> *mut core::ffi::c_void;
type FputsFn = unsafe extern "C" fn(*const i8, *mut core::ffi::c_void) -> i32;
type FwriteFn =
    unsafe extern "C" fn(*const core::ffi::c_void, usize, usize, *mut core::ffi::c_void) -> usize;
fn main() {
    let h = unsafe {
        libc::dlmopen(
            libc::LM_ID_NEWLM,
            b"libc.so.6\0".as_ptr().cast(),
            libc::RTLD_LAZY | libc::RTLD_LOCAL,
        )
    };
    assert!(!h.is_null());
    let g_fopen: FopenFn =
        unsafe { std::mem::transmute(libc::dlsym(h, b"fopen\0".as_ptr().cast())) };
    let g_fputs: FputsFn =
        unsafe { std::mem::transmute(libc::dlsym(h, b"fputs\0".as_ptr().cast())) };
    let g_fwrite: FwriteFn =
        unsafe { std::mem::transmute(libc::dlsym(h, b"fwrite\0".as_ptr().cast())) };
    use frankenlibc_abi::stdio_abi as fa;
    let path = b"/dev/null\0".as_ptr() as *const i8;
    let mode = b"w\0".as_ptr() as *const i8;
    let gf = unsafe { g_fopen(path, mode) };
    assert!(!gf.is_null());
    let ff = unsafe { fa::fopen(path, mode) } as *mut core::ffi::c_void;
    assert!(!ff.is_null());
    let msg = b"hello world\n\0".as_ptr() as *const i8;
    let msgb = b"hello world\n".as_ptr() as *const core::ffi::c_void;
    let msglen = 12usize;
    // warm up (populate fl write cache)
    for _ in 0..1000 {
        unsafe {
            fa::fputs(msg, ff);
        }
        unsafe {
            g_fputs(msg, gf);
        }
    }
    let iters = 2_000_000u64;
    for (tag, is_fputs) in [("fputs", true), ("fwrite", false)] {
        let (mut fl, mut gl) = (Vec::new(), Vec::new());
        for r in 0..60 {
            let run_fl = || {
                if is_fputs {
                    for _ in 0..iters {
                        black_box(unsafe { fa::fputs(msg, ff) });
                    }
                } else {
                    for _ in 0..iters {
                        black_box(unsafe { fa::fwrite(msgb, 1, msglen, ff) });
                    }
                }
            };
            let run_gl = || {
                if is_fputs {
                    for _ in 0..iters {
                        black_box(unsafe { g_fputs(msg, gf) });
                    }
                } else {
                    for _ in 0..iters {
                        black_box(unsafe { g_fwrite(msgb, 1, msglen, gf) });
                    }
                }
            };
            if r % 2 == 0 {
                let t = Instant::now();
                run_fl();
                fl.push(t.elapsed().as_nanos() as f64 / iters as f64);
                let t = Instant::now();
                run_gl();
                gl.push(t.elapsed().as_nanos() as f64 / iters as f64);
            } else {
                let t = Instant::now();
                run_gl();
                gl.push(t.elapsed().as_nanos() as f64 / iters as f64);
                let t = Instant::now();
                run_fl();
                fl.push(t.elapsed().as_nanos() as f64 / iters as f64);
            }
        }
        let (f, gg) = (pctl(&fl, 0.1), pctl(&gl, 0.1));
        println!(
            "{tag:<8} fl={f:6.2} glibc={gg:6.2} fl/glibc={:.3}{}",
            f / gg,
            if f / gg > 1.25 {
                "  <-- LOSS"
            } else if f / gg < 0.95 {
                "  win"
            } else {
                "  ~par"
            }
        );
    }
}
