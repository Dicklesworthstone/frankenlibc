//! Survey fl non-reentrant gmtime/localtime + localtime_r vs glibc (dlmopen).
use std::hint::black_box;
use std::time::Instant;
fn pctl(s: &[f64], q: f64) -> f64 {
    let mut v = s.to_vec();
    v.sort_by(|a, b| a.partial_cmp(b).unwrap());
    v[((q * (v.len() - 1) as f64).round() as usize).min(v.len() - 1)]
}
type GmFn = unsafe extern "C" fn(*const i64) -> *mut libc::tm;
type LrFn = unsafe extern "C" fn(*const i64, *mut libc::tm) -> *mut libc::tm;
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
        std::env::set_var("TZ", "UTC");
    }
    let g_gm: GmFn = unsafe { std::mem::transmute(libc::dlsym(h, b"gmtime\0".as_ptr().cast())) };
    let g_lt: GmFn = unsafe { std::mem::transmute(libc::dlsym(h, b"localtime\0".as_ptr().cast())) };
    let g_ltr: LrFn =
        unsafe { std::mem::transmute(libc::dlsym(h, b"localtime_r\0".as_ptr().cast())) };
    use frankenlibc_abi::time_abi as ta;
    let iters = 200_000u64;
    let e: i64 = 1_700_000_000;
    let ep = &e as *const i64;
    let (f, g) = bench2(
        || {
            for _ in 0..iters {
                black_box(unsafe { ta::gmtime(ep) });
            }
        },
        || {
            for _ in 0..iters {
                black_box(unsafe { g_gm(ep) });
            }
        },
    );
    println!(
        "gmtime      fl={:6.2}ns glibc={:6.2}ns fl/glibc={:.3}{}",
        f / iters as f64,
        g / iters as f64,
        f / g,
        tag(f / g)
    );
    let (f, g) = bench2(
        || {
            for _ in 0..iters {
                black_box(unsafe { ta::localtime(ep) });
            }
        },
        || {
            for _ in 0..iters {
                black_box(unsafe { g_lt(ep) });
            }
        },
    );
    println!(
        "localtime   fl={:6.2}ns glibc={:6.2}ns fl/glibc={:.3}{}",
        f / iters as f64,
        g / iters as f64,
        f / g,
        tag(f / g)
    );
    let mut ft: libc::tm = unsafe { std::mem::zeroed() };
    let mut gt: libc::tm = unsafe { std::mem::zeroed() };
    let ftp = &mut ft as *mut libc::tm;
    let gtp = &mut gt as *mut libc::tm;
    let (f, g) = bench2(
        || {
            for _ in 0..iters {
                black_box(unsafe { ta::localtime_r(ep, ftp) });
            }
        },
        || {
            for _ in 0..iters {
                black_box(unsafe { g_ltr(ep, gtp) });
            }
        },
    );
    println!(
        "localtime_r fl={:6.2}ns glibc={:6.2}ns fl/glibc={:.3}{}",
        f / iters as f64,
        g / iters as f64,
        f / g,
        tag(f / g)
    );
}
