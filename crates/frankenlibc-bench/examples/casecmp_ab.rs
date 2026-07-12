//! fl strcasecmp/strncasecmp vs glibc (dlmopen). Equal strings (full scan), mixed case.
use std::hint::black_box;
use std::time::Instant;
fn pctl(s: &[f64], q: f64) -> f64 {
    let mut v = s.to_vec();
    v.sort_by(|a, b| a.partial_cmp(b).unwrap());
    v[((q * (v.len() - 1) as f64).round() as usize).min(v.len() - 1)]
}
type Cs2 = unsafe extern "C" fn(*const i8, *const i8) -> i32;
type Cs3 = unsafe extern "C" fn(*const i8, *const i8, usize) -> i32;
fn main() {
    let h = unsafe {
        libc::dlmopen(
            libc::LM_ID_NEWLM,
            b"libc.so.6\0".as_ptr().cast(),
            libc::RTLD_LAZY | libc::RTLD_LOCAL,
        )
    };
    assert!(!h.is_null());
    let gsc: Cs2 = unsafe { std::mem::transmute(libc::dlsym(h, b"strcasecmp\0".as_ptr().cast())) };
    let gsn: Cs3 = unsafe { std::mem::transmute(libc::dlsym(h, b"strncasecmp\0".as_ptr().cast())) };
    use frankenlibc_abi::string_abi as fa;
    for &n in &[8usize, 16, 32, 64, 128, 256] {
        // two equal strings differing only in case (force full scan + case-fold work)
        let a: Vec<i8> = (0..n)
            .map(|i| (b'A' + (i % 26) as u8) as i8)
            .chain(std::iter::once(0))
            .collect();
        let b: Vec<i8> = (0..n)
            .map(|i| (b'a' + (i % 26) as u8) as i8)
            .chain(std::iter::once(0))
            .collect();
        let (ap, bp) = (a.as_ptr(), b.as_ptr());
        let iters = 2_000_000u64;
        // strcasecmp
        {
            let (mut fl, mut gl) = (Vec::new(), Vec::new());
            for r in 0..60 {
                if r % 2 == 0 {
                    let t = Instant::now();
                    for _ in 0..iters {
                        black_box(unsafe { fa::strcasecmp(ap, bp) });
                    }
                    fl.push(t.elapsed().as_nanos() as f64 / iters as f64);
                    let t = Instant::now();
                    for _ in 0..iters {
                        black_box(unsafe { gsc(ap, bp) });
                    }
                    gl.push(t.elapsed().as_nanos() as f64 / iters as f64);
                } else {
                    let t = Instant::now();
                    for _ in 0..iters {
                        black_box(unsafe { gsc(ap, bp) });
                    }
                    gl.push(t.elapsed().as_nanos() as f64 / iters as f64);
                    let t = Instant::now();
                    for _ in 0..iters {
                        black_box(unsafe { fa::strcasecmp(ap, bp) });
                    }
                    fl.push(t.elapsed().as_nanos() as f64 / iters as f64);
                }
            }
            let (f, gg) = (pctl(&fl, 0.1), pctl(&gl, 0.1));
            println!(
                "strcasecmp  n={n:<4} fl={f:6.1} glibc={gg:6.1} fl/glibc={:.3}{}",
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
        // strncasecmp
        {
            let (mut fl, mut gl) = (Vec::new(), Vec::new());
            for r in 0..60 {
                if r % 2 == 0 {
                    let t = Instant::now();
                    for _ in 0..iters {
                        black_box(unsafe { fa::strncasecmp(ap, bp, n) });
                    }
                    fl.push(t.elapsed().as_nanos() as f64 / iters as f64);
                    let t = Instant::now();
                    for _ in 0..iters {
                        black_box(unsafe { gsn(ap, bp, n) });
                    }
                    gl.push(t.elapsed().as_nanos() as f64 / iters as f64);
                } else {
                    let t = Instant::now();
                    for _ in 0..iters {
                        black_box(unsafe { gsn(ap, bp, n) });
                    }
                    gl.push(t.elapsed().as_nanos() as f64 / iters as f64);
                    let t = Instant::now();
                    for _ in 0..iters {
                        black_box(unsafe { fa::strncasecmp(ap, bp, n) });
                    }
                    fl.push(t.elapsed().as_nanos() as f64 / iters as f64);
                }
            }
            let (f, gg) = (pctl(&fl, 0.1), pctl(&gl, 0.1));
            println!(
                "strncasecmp n={n:<4} fl={f:6.1} glibc={gg:6.1} fl/glibc={:.3}{}",
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
}
