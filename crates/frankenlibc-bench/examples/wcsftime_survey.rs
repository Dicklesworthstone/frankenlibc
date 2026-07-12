//! Survey fl wcsftime vs glibc (dlmopen) for common wide formats.
use std::hint::black_box;
use std::time::Instant;
fn pctl(s: &[f64], q: f64) -> f64 {
    let mut v = s.to_vec();
    v.sort_by(|a, b| a.partial_cmp(b).unwrap());
    v[((q * (v.len() - 1) as f64).round() as usize).min(v.len() - 1)]
}
type WsfFn = unsafe extern "C" fn(*mut i32, usize, *const i32, *const libc::tm) -> usize;
fn bench2<A: Fn(), B: Fn()>(a: A, b: B) -> (f64, f64) {
    let (mut fa, mut fb) = (Vec::new(), Vec::new());
    for r in 0..50 {
        if r % 2 == 0 {
            let t = Instant::now();
            a();
            fa.push(t.elapsed().as_nanos() as f64);
            let t = Instant::now();
            b();
            fb.push(t.elapsed().as_nanos() as f64);
        } else {
            let t = Instant::now();
            b();
            fb.push(t.elapsed().as_nanos() as f64);
            let t = Instant::now();
            a();
            fa.push(t.elapsed().as_nanos() as f64);
        }
    }
    (pctl(&fa, 0.1), pctl(&fb, 0.1))
}
fn tag(r: f64) -> &'static str {
    if r > 1.25 {
        "  <-- LOSS"
    } else if r < 0.9 {
        "  win"
    } else {
        "  ~par"
    }
}
fn main() {
    let h = unsafe {
        libc::dlmopen(
            libc::LM_ID_NEWLM,
            b"libc.so.6\0".as_ptr().cast(),
            libc::RTLD_LAZY | libc::RTLD_LOCAL,
        )
    };
    assert!(!h.is_null());
    unsafe {
        let sl: unsafe extern "C" fn(i32, *const i8) -> *mut i8 =
            std::mem::transmute(libc::dlsym(h, b"setlocale\0".as_ptr().cast()));
        sl(6, b"C\0".as_ptr().cast());
    }
    let g_wsf: WsfFn =
        unsafe { std::mem::transmute(libc::dlsym(h, b"wcsftime\0".as_ptr().cast())) };
    use frankenlibc_abi::time_abi as ta;
    use frankenlibc_abi::wchar_abi as wa;
    let e: i64 = 1_700_000_000;
    let mut tm: libc::tm = unsafe { std::mem::zeroed() };
    unsafe {
        ta::gmtime_r(&e, &mut tm);
    }
    let tmp = tm;
    let tmpp = &tmp as *const libc::tm;
    let iters = 50_000u64;
    let mut fb = [0i32; 256];
    let mut gb = [0i32; 256];
    let fbp = fb.as_mut_ptr();
    let gbp = gb.as_mut_ptr();
    let mk = |s: &str| -> Vec<i32> {
        s.chars()
            .map(|c| c as i32)
            .chain(std::iter::once(0))
            .collect()
    };
    for fmt in [
        "%Y-%m-%d %H:%M:%S",
        "%H:%M",
        "%A",
        "just text no directives",
    ] {
        let w = mk(fmt);
        let fp = w.as_ptr();
        // byte check
        let fn2 = unsafe {
            wa::wcsftime(
                fbp as *mut i32,
                256,
                fp as *const i32,
                tmpp as *const std::ffi::c_void,
            )
        };
        let gn = unsafe { g_wsf(gbp, 256, fp, tmpp) };
        let same = fn2 == gn && fb[..fn2].iter().zip(gb[..gn].iter()).all(|(a, b)| a == b);
        let (f, g) = bench2(
            || {
                for _ in 0..iters {
                    black_box(unsafe {
                        wa::wcsftime(
                            black_box(fbp as *mut i32),
                            256,
                            fp as *const i32,
                            tmpp as *const std::ffi::c_void,
                        )
                    });
                }
            },
            || {
                for _ in 0..iters {
                    black_box(unsafe { g_wsf(black_box(gbp), 256, fp, tmpp) });
                }
            },
        );
        println!(
            "wcsftime {:<24} fl={:7.2}ns glibc={:7.2}ns fl/glibc={:.3}{} match={}",
            fmt,
            f / iters as f64,
            g / iters as f64,
            f / g,
            tag(f / g),
            same
        );
    }
}
