//! DIRECT fl memset symbol vs glibc memset (dlmopen): correctness sweep + perf A/B.
use std::hint::black_box;
use std::time::Instant;
fn pctl(s: &[f64], q: f64) -> f64 {
    let mut v = s.to_vec();
    v.sort_by(|a, b| a.partial_cmp(b).unwrap());
    v[((q * (v.len() - 1) as f64).round() as usize).min(v.len() - 1)]
}
type MsFn = unsafe extern "C" fn(*mut core::ffi::c_void, i32, usize) -> *mut core::ffi::c_void;
fn main() {
    let h = unsafe {
        libc::dlmopen(
            libc::LM_ID_NEWLM,
            b"libc.so.6\0".as_ptr().cast(),
            libc::RTLD_LAZY | libc::RTLD_LOCAL,
        )
    };
    assert!(!h.is_null());
    let g: MsFn = unsafe { std::mem::transmute(libc::dlsym(h, b"memset\0".as_ptr().cast())) };
    use frankenlibc_abi::string_abi as fa;
    // --- Correctness: byte-exact vs glibc across sizes, alignments, values (incl. sentinel) ---
    let mut checks = 0u64;
    for n in [
        1usize, 7, 8, 15, 16, 17, 31, 32, 33, 47, 48, 63, 64, 65, 79, 95, 96, 127, 128, 129, 255,
        256, 257, 512, 1023, 1024, 2047, 2048, 2049, 4096,
    ]
    .iter()
    .copied()
    {
        for align in 0..16usize {
            for &val in &[0u8, 0x5a, 0xff, 1] {
                let mut fb = vec![0xa5u8; n + align + 32];
                let mut gb = vec![0xa5u8; n + align + 32];
                unsafe {
                    fa::memset(fb.as_mut_ptr().add(align).cast(), val as i32, n);
                }
                unsafe {
                    g(gb.as_mut_ptr().add(align).cast(), val as i32, n);
                }
                assert_eq!(fb, gb, "MISMATCH n={n} align={align} val={val:#x}");
                checks += 1;
            }
        }
    }
    println!("correctness: {checks} (size×align×val) combos fl == glibc byte-for-byte ✓");
    // --- Perf ---
    for &n in &[32usize, 64, 96, 127, 256, 1024, 4096, 8192, 16384, 65536] {
        let mut buf = vec![0u8; n + 64];
        let p = buf.as_mut_ptr() as *mut core::ffi::c_void;
        let iters = if n <= 1024 { 2_000_000u64 } else { 300_000 };
        let (mut fl, mut gl) = (Vec::new(), Vec::new());
        for r in 0..60 {
            if r % 2 == 0 {
                let t = Instant::now();
                for _ in 0..iters {
                    black_box(unsafe { fa::memset(p, 0x5a, n) });
                }
                fl.push(t.elapsed().as_nanos() as f64 / iters as f64);
                let t = Instant::now();
                for _ in 0..iters {
                    black_box(unsafe { g(p, 0x5a, n) });
                }
                gl.push(t.elapsed().as_nanos() as f64 / iters as f64);
            } else {
                let t = Instant::now();
                for _ in 0..iters {
                    black_box(unsafe { g(p, 0x5a, n) });
                }
                gl.push(t.elapsed().as_nanos() as f64 / iters as f64);
                let t = Instant::now();
                for _ in 0..iters {
                    black_box(unsafe { fa::memset(p, 0x5a, n) });
                }
                fl.push(t.elapsed().as_nanos() as f64 / iters as f64);
            }
        }
        let (f, gg) = (pctl(&fl, 0.1), pctl(&gl, 0.1));
        println!(
            "memset n={n:<6} fl={f:7.1} glibc={gg:7.1} fl/glibc={:.3}{}",
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
