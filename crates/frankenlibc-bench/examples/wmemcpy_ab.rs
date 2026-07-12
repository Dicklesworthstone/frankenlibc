//! DIRECT fl wmemcpy vs glibc wmemcpy (dlmopen). Sizes in wchars (bytes = 4x).
use std::hint::black_box;
use std::time::Instant;
fn pctl(s: &[f64], q: f64) -> f64 {
    let mut v = s.to_vec();
    v.sort_by(|a, b| a.partial_cmp(b).unwrap());
    v[((q * (v.len() - 1) as f64).round() as usize).min(v.len() - 1)]
}
type WcFn = unsafe extern "C" fn(*mut u32, *const u32, usize) -> *mut u32;
fn main() {
    let h = unsafe {
        libc::dlmopen(
            libc::LM_ID_NEWLM,
            b"libc.so.6\0".as_ptr().cast(),
            libc::RTLD_LAZY | libc::RTLD_LOCAL,
        )
    };
    assert!(!h.is_null());
    let g: WcFn = unsafe { std::mem::transmute(libc::dlsym(h, b"wmemcpy\0".as_ptr().cast())) };
    use frankenlibc_abi::wchar_abi as wa;
    for &n in &[8usize, 32, 128, 512, 1024, 2048, 4096, 8192, 16384, 32768] {
        let src = vec![0x41424344u32; n + 16];
        let mut dst = vec![0u32; n + 16];
        let (dp, sp) = (dst.as_mut_ptr(), src.as_ptr());
        let iters = if n <= 512 { 2_000_000u64 } else { 300_000 };
        let (mut fl, mut gl) = (Vec::new(), Vec::new());
        for r in 0..60 {
            if r % 2 == 0 {
                let t = Instant::now();
                for _ in 0..iters {
                    black_box(unsafe { wa::wmemcpy(dp, sp, n) });
                }
                fl.push(t.elapsed().as_nanos() as f64 / iters as f64);
                let t = Instant::now();
                for _ in 0..iters {
                    black_box(unsafe { g(dp, sp, n) });
                }
                gl.push(t.elapsed().as_nanos() as f64 / iters as f64);
            } else {
                let t = Instant::now();
                for _ in 0..iters {
                    black_box(unsafe { g(dp, sp, n) });
                }
                gl.push(t.elapsed().as_nanos() as f64 / iters as f64);
                let t = Instant::now();
                for _ in 0..iters {
                    black_box(unsafe { wa::wmemcpy(dp, sp, n) });
                }
                fl.push(t.elapsed().as_nanos() as f64 / iters as f64);
            }
        }
        let (f, gg) = (pctl(&fl, 0.1), pctl(&gl, 0.1));
        println!(
            "wmemcpy nw={n:<6}({:>6}B) fl={f:8.1} glibc={gg:8.1} fl/glibc={:.3}{}",
            n * 4,
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
