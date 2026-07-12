//! Does fl strcmp lose to glibc on long EQUAL strings at unaligned offsets? scan_strcmp loads
//! both pointers unaligned (page-guarded). Test aligned vs unaligned at len 256/1024/4096.
use std::hint::black_box;
use std::time::Instant;
fn pctl(s: &[f64], q: f64) -> f64 {
    let mut v = s.to_vec();
    v.sort_by(|a, b| a.partial_cmp(b).unwrap());
    v[((q * (v.len() - 1) as f64).round() as usize).min(v.len() - 1)]
}
type CmpFn = unsafe extern "C" fn(*const i8, *const i8) -> i32;
fn main() {
    let h = unsafe {
        libc::dlmopen(
            libc::LM_ID_NEWLM,
            b"libc.so.6\0".as_ptr().cast(),
            libc::RTLD_LAZY | libc::RTLD_LOCAL,
        )
    };
    assert!(!h.is_null());
    let g: CmpFn = unsafe { std::mem::transmute(libc::dlsym(h, b"strcmp\0".as_ptr().cast())) };
    use frankenlibc_abi::string_abi as fa;
    // two equal buffers 'a'*L + NUL, at chosen offsets
    let mut b1 = vec![b'a'; 8192 + 64];
    let mut b2 = vec![b'a'; 8192 + 64];
    let base1 = b1.as_mut_ptr();
    let base2 = b2.as_mut_ptr();
    for &n in &[256usize, 1024, 4096] {
        for (tag, o1, o2) in [
            ("aligned", 0usize, 0usize),
            ("both+16", 16, 16),
            ("skew", 0, 16),
        ] {
            let p1 = unsafe { (((base1 as usize + 31) & !31) + o1) as *mut u8 };
            let p2 = unsafe { (((base2 as usize + 31) & !31) + o2) as *mut u8 };
            unsafe {
                for i in 0..n {
                    *p1.add(i) = b'a';
                    *p2.add(i) = b'a';
                }
                *p1.add(n) = 0;
                *p2.add(n) = 0;
            }
            let (c1, c2) = (p1 as *const i8, p2 as *const i8);
            // verify equal
            assert_eq!(
                unsafe { fa::strcmp(c1, c2) }.signum(),
                unsafe { g(c1, c2) }.signum(),
                "strcmp {tag} n={n}"
            );
            let iters = 400_000u64;
            let (mut fl, mut gl) = (Vec::new(), Vec::new());
            for r in 0..50 {
                if r % 2 == 0 {
                    let t = Instant::now();
                    for _ in 0..iters {
                        black_box(unsafe { fa::strcmp(c1, c2) });
                    }
                    fl.push(t.elapsed().as_nanos() as f64 / iters as f64);
                    let t = Instant::now();
                    for _ in 0..iters {
                        black_box(unsafe { g(c1, c2) });
                    }
                    gl.push(t.elapsed().as_nanos() as f64 / iters as f64);
                } else {
                    let t = Instant::now();
                    for _ in 0..iters {
                        black_box(unsafe { g(c1, c2) });
                    }
                    gl.push(t.elapsed().as_nanos() as f64 / iters as f64);
                    let t = Instant::now();
                    for _ in 0..iters {
                        black_box(unsafe { fa::strcmp(c1, c2) });
                    }
                    fl.push(t.elapsed().as_nanos() as f64 / iters as f64);
                }
            }
            let (f, gg) = (pctl(&fl, 0.1), pctl(&gl, 0.1));
            println!(
                "strcmp n={n:<5} {tag:<8} fl={f:8.1} glibc={gg:8.1} fl/glibc={:.3}{}",
                f / gg,
                if f / gg > 1.2 { "  <-- LOSS" } else { "" }
            );
        }
    }
}
