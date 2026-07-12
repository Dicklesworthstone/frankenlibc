//! Survey fl narrow strtod/atof vs glibc (dlmopen).
use std::hint::black_box;
use std::time::Instant;
fn pctl(s: &[f64], q: f64) -> f64 {
    let mut v = s.to_vec();
    v.sort_by(|a, b| a.partial_cmp(b).unwrap());
    v[((q * (v.len() - 1) as f64).round() as usize).min(v.len() - 1)]
}
type DFn = unsafe extern "C" fn(*const i8, *mut *mut i8) -> f64;
type AFn = unsafe extern "C" fn(*const i8) -> f64;
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
    let g_strtod: DFn = unsafe { std::mem::transmute(libc::dlsym(h, b"strtod\0".as_ptr().cast())) };
    let g_atof: AFn = unsafe { std::mem::transmute(libc::dlsym(h, b"atof\0".as_ptr().cast())) };
    use frankenlibc_abi::stdlib_abi as sa;
    let iters = 200_000u64;
    for txt in [
        "0",
        "42",
        "-1.5e10",
        "3.14159",
        "2.5",
        "123456.789",
        "1e-300",
        "1000000",
    ] {
        let s: Vec<i8> = txt
            .bytes()
            .map(|b| b as i8)
            .chain(std::iter::once(0))
            .collect();
        let p = s.as_ptr();
        let (f, g) = bench2(
            || {
                for _ in 0..iters {
                    black_box(unsafe { sa::strtod(black_box(p), std::ptr::null_mut()) });
                }
            },
            || {
                for _ in 0..iters {
                    black_box(unsafe { g_strtod(black_box(p), std::ptr::null_mut()) });
                }
            },
        );
        println!(
            "strtod {:<14} fl={:6.2}ns glibc={:6.2}ns fl/glibc={:.3}{}",
            txt,
            f / iters as f64,
            g / iters as f64,
            f / g,
            tag(f / g)
        );
    }
    for txt in ["0", "42", "3.14159"] {
        let s: Vec<i8> = txt
            .bytes()
            .map(|b| b as i8)
            .chain(std::iter::once(0))
            .collect();
        let p = s.as_ptr();
        let (f, g) = bench2(
            || {
                for _ in 0..iters {
                    black_box(unsafe { sa::atof(black_box(p)) });
                }
            },
            || {
                for _ in 0..iters {
                    black_box(unsafe { g_atof(black_box(p)) });
                }
            },
        );
        println!(
            "atof   {:<14} fl={:6.2}ns glibc={:6.2}ns fl/glibc={:.3}{}",
            txt,
            f / iters as f64,
            g / iters as f64,
            f / g,
            tag(f / g)
        );
    }
}
