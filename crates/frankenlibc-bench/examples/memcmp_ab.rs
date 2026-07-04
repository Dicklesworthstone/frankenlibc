//! fl memcmp vs glibc (dlmopen): correctness sweep plus equal-buffer perf.
use std::hint::black_box;
use std::time::Instant;
fn pctl(s: &[f64], q: f64) -> f64 {
    let mut v = s.to_vec();
    v.sort_by(|a, b| a.partial_cmp(b).unwrap());
    v[((q * (v.len() - 1) as f64).round() as usize).min(v.len() - 1)]
}
type CmpFn = unsafe extern "C" fn(*const core::ffi::c_void, *const core::ffi::c_void, usize) -> i32;
fn main() {
    let h = unsafe {
        libc::dlmopen(
            libc::LM_ID_NEWLM,
            b"libc.so.6\0".as_ptr().cast(),
            libc::RTLD_LAZY | libc::RTLD_LOCAL,
        )
    };
    assert!(!h.is_null());
    let g: CmpFn = unsafe { std::mem::transmute(libc::dlsym(h, b"memcmp\0".as_ptr().cast())) };
    use frankenlibc_abi::string_abi as fa;
    // Sizes cross the 128B asm loop. Sweep several alignments, equal buffers,
    // and differing bytes in both sign directions, comparing only sign because
    // C specifies memcmp ordering, not exact difference magnitude.
    let sgn = |x: i32| (x > 0) as i32 - (x < 0) as i32;
    let mut checks = 0u64;
    for n in [
        1usize, 31, 32, 33, 64, 127, 128, 129, 160, 255, 256, 300, 384, 512,
    ]
    .iter()
    .copied()
    {
        for al in [0usize, 1, 7, 15, 31].iter().copied() {
            let a = vec![0x5au8; n + al + 8];
            let b = vec![0x5au8; n + al + 8];
            let fm = unsafe { fa::memcmp(a.as_ptr().add(al).cast(), b.as_ptr().add(al).cast(), n) };
            let gm = unsafe { g(a.as_ptr().add(al).cast(), b.as_ptr().add(al).cast(), n) };
            assert_eq!(sgn(fm), sgn(gm), "EQ n={n} al={al}");
            checks += 1;
            let step = if n <= 64 { 1 } else { 7 };
            let mut p = 0;
            while p < n {
                for delta in [1i16, -1] {
                    let mut b2 = a.clone();
                    b2[al + p] = (0x5a as i16 + delta) as u8;
                    let fm = unsafe {
                        fa::memcmp(a.as_ptr().add(al).cast(), b2.as_ptr().add(al).cast(), n)
                    };
                    let gm = unsafe { g(a.as_ptr().add(al).cast(), b2.as_ptr().add(al).cast(), n) };
                    assert_eq!(
                        sgn(fm),
                        sgn(gm),
                        "DIFF n={n} al={al} p={p} delta={delta} fl={fm} g={gm}"
                    );
                    checks += 1;
                }
                p += step;
            }
        }
    }
    println!("memcmp correctness: {checks} sign checks fl==glibc");
    for &n in &[16usize, 64, 256, 1024, 4096, 16384, 65536] {
        let a = vec![0x5au8; n + 16];
        let b = vec![0x5au8; n + 16];
        let (ap, bp) = (
            a.as_ptr() as *const core::ffi::c_void,
            b.as_ptr() as *const core::ffi::c_void,
        );
        let iters = if n <= 1024 { 2_000_000u64 } else { 300_000 };
        let (mut fl, mut gl) = (Vec::new(), Vec::new());
        for r in 0..60 {
            if r % 2 == 0 {
                let t = Instant::now();
                for _ in 0..iters {
                    black_box(unsafe { fa::memcmp(ap, bp, n) });
                }
                fl.push(t.elapsed().as_nanos() as f64 / iters as f64);
                let t = Instant::now();
                for _ in 0..iters {
                    black_box(unsafe { g(ap, bp, n) });
                }
                gl.push(t.elapsed().as_nanos() as f64 / iters as f64);
            } else {
                let t = Instant::now();
                for _ in 0..iters {
                    black_box(unsafe { g(ap, bp, n) });
                }
                gl.push(t.elapsed().as_nanos() as f64 / iters as f64);
                let t = Instant::now();
                for _ in 0..iters {
                    black_box(unsafe { fa::memcmp(ap, bp, n) });
                }
                fl.push(t.elapsed().as_nanos() as f64 / iters as f64);
            }
        }
        let (f, gg) = (pctl(&fl, 0.1), pctl(&gl, 0.1));
        println!(
            "memcmp n={n:<6} fl={f:8.1} glibc={gg:8.1} fl/glibc={:.3}{}",
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
