//! fl wcstol vs glibc on a short integer followed by a long tail (over-scan test).
use std::hint::black_box;
use std::time::Instant;
fn pctl(s: &[f64], q: f64) -> f64 {
    let mut v = s.to_vec();
    v.sort_by(|a, b| a.partial_cmp(b).unwrap());
    v[((q * (v.len() - 1) as f64).round() as usize).min(v.len() - 1)]
}
type WlFn = unsafe extern "C" fn(*const i32, *mut *mut i32, i32) -> i64;
fn main() {
    let h = unsafe {
        libc::dlmopen(
            libc::LM_ID_NEWLM,
            b"libc.so.6\0".as_ptr().cast(),
            libc::RTLD_LAZY | libc::RTLD_LOCAL,
        )
    };
    assert!(!h.is_null());
    let g: WlFn = unsafe { std::mem::transmute(libc::dlsym(h, b"wcstol\0".as_ptr().cast())) };
    use frankenlibc_abi::wchar_abi as wa;
    for &tail in &[0usize, 64, 512, 4096] {
        let mut w: Vec<i32> = "12345".chars().map(|c| c as i32).collect();
        for _ in 0..tail {
            w.push(b' ' as i32);
        }
        w.push(0);
        let p = w.as_ptr();
        let mut fe = std::ptr::null_mut();
        let mut ge = std::ptr::null_mut();
        let fv = unsafe { wa::wcstol(p, &mut fe, 10) };
        let gv = unsafe { g(p, &mut ge, 10) };
        let foff = (fe as usize).wrapping_sub(p as usize) / 4;
        let goff = (ge as usize).wrapping_sub(p as usize) / 4;
        assert!(
            fv == gv && foff == goff,
            "mismatch tail={tail}: fv={fv} gv={gv} foff={foff} goff={goff}"
        );
        let iters = 300_000u64;
        let (mut fl, mut gl) = (Vec::new(), Vec::new());
        for r in 0..40 {
            if r % 2 == 0 {
                let t = Instant::now();
                for _ in 0..iters {
                    black_box(unsafe { wa::wcstol(p, std::ptr::null_mut(), 10) });
                }
                fl.push(t.elapsed().as_nanos() as f64 / iters as f64);
                let t = Instant::now();
                for _ in 0..iters {
                    black_box(unsafe { g(p, std::ptr::null_mut(), 10) });
                }
                gl.push(t.elapsed().as_nanos() as f64 / iters as f64);
            } else {
                let t = Instant::now();
                for _ in 0..iters {
                    black_box(unsafe { g(p, std::ptr::null_mut(), 10) });
                }
                gl.push(t.elapsed().as_nanos() as f64 / iters as f64);
                let t = Instant::now();
                for _ in 0..iters {
                    black_box(unsafe { wa::wcstol(p, std::ptr::null_mut(), 10) });
                }
                fl.push(t.elapsed().as_nanos() as f64 / iters as f64);
            }
        }
        let (f, gg) = (pctl(&fl, 0.1), pctl(&gl, 0.1));
        println!(
            "wcstol tail={tail:<6} fl={f:8.1} glibc={gg:7.1} fl/glibc={:.3}{}",
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
