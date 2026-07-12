//! Survey fl wide copy/cat/set primitives vs glibc (dlmopen), across sizes.
//! Finds the biggest per-size gap for a follow-up SIMD lever.
use std::hint::black_box;
use std::time::Instant;
fn pctl(s: &[f64], q: f64) -> f64 {
    let mut v = s.to_vec();
    v.sort_by(|a, b| a.partial_cmp(b).unwrap());
    v[((q * (v.len() - 1) as f64).round() as usize).min(v.len() - 1)]
}
type Cpy = unsafe extern "C" fn(*mut i32, *const i32) -> *mut i32;
type Ncpy = unsafe extern "C" fn(*mut i32, *const i32, usize) -> *mut i32;
type Set = unsafe extern "C" fn(*mut i32, i32, usize) -> *mut i32;
type Mcpy = unsafe extern "C" fn(*mut i32, *const i32, usize) -> *mut i32;
fn bench2<A: Fn(), B: Fn()>(a: A, b: B, rounds: usize) -> (f64, f64) {
    let (mut fa, mut fb) = (Vec::new(), Vec::new());
    for r in 0..rounds {
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
fn main() {
    let h = unsafe {
        libc::dlmopen(
            libc::LM_ID_NEWLM,
            b"libc.so.6\0".as_ptr().cast(),
            libc::RTLD_LAZY | libc::RTLD_LOCAL,
        )
    };
    assert!(!h.is_null());
    macro_rules! sym {
        ($n:literal,$t:ty) => {
            unsafe {
                std::mem::transmute::<_, $t>(libc::dlsym(h, concat!($n, "\0").as_ptr().cast()))
            }
        };
    }
    let g_wcscpy: Cpy = sym!("wcscpy", Cpy);
    let g_wcpcpy: Cpy = sym!("wcpcpy", Cpy);
    let g_wcsncpy: Ncpy = sym!("wcsncpy", Ncpy);
    let g_wmemset: Set = sym!("wmemset", Set);
    let g_wmemcpy: Mcpy = sym!("wmemcpy", Mcpy);
    use frankenlibc_abi::wchar_abi as wa;
    let iters = 200_000u64;
    for &n in &[16usize, 64, 256, 1024] {
        let src: Vec<u32> = (0..n as u32)
            .map(|x| b'a' as u32 + (x % 26))
            .chain(std::iter::once(0))
            .collect();
        let sp = src.as_ptr();
        let mut d1 = vec![0u32; n + 2];
        let mut d2 = vec![0u32; n + 2];
        let p1 = d1.as_mut_ptr();
        let p2 = d2.as_mut_ptr();
        // wcscpy
        let (f, g) = bench2(
            || {
                for _ in 0..iters {
                    black_box(unsafe { wa::wcscpy(p1, black_box(sp)) });
                }
            },
            || {
                for _ in 0..iters {
                    black_box(unsafe { g_wcscpy(p2 as *mut i32, black_box(sp) as *const i32) });
                }
            },
            40,
        );
        assert_eq!(&d1[..n], &src[..n]);
        println!(
            "wcscpy  n={n:<5} fl={:6.2} glibc={:6.2} fl/glibc={:.3}{}",
            f / iters as f64,
            g / iters as f64,
            f / g,
            if f / g > 1.2 {
                "  LOSS"
            } else if f / g < 0.9 {
                "  win"
            } else {
                ""
            }
        );
        // wcpcpy
        let (f, g) = bench2(
            || {
                for _ in 0..iters {
                    black_box(unsafe { wa::wcpcpy(p1, black_box(sp)) });
                }
            },
            || {
                for _ in 0..iters {
                    black_box(unsafe { g_wcpcpy(p2 as *mut i32, black_box(sp) as *const i32) });
                }
            },
            40,
        );
        println!(
            "wcpcpy  n={n:<5} fl={:6.2} glibc={:6.2} fl/glibc={:.3}{}",
            f / iters as f64,
            g / iters as f64,
            f / g,
            if f / g > 1.2 {
                "  LOSS"
            } else if f / g < 0.9 {
                "  win"
            } else {
                ""
            }
        );
        // wcsncpy (exact n, no pad)
        let (f, g) = bench2(
            || {
                for _ in 0..iters {
                    black_box(unsafe { wa::wcsncpy(p1, black_box(sp), n) });
                }
            },
            || {
                for _ in 0..iters {
                    black_box(unsafe { g_wcsncpy(p2 as *mut i32, black_box(sp) as *const i32, n) });
                }
            },
            40,
        );
        println!(
            "wcsncpy n={n:<5} fl={:6.2} glibc={:6.2} fl/glibc={:.3}{}",
            f / iters as f64,
            g / iters as f64,
            f / g,
            if f / g > 1.2 {
                "  LOSS"
            } else if f / g < 0.9 {
                "  win"
            } else {
                ""
            }
        );
        // wmemset
        let (f, g) = bench2(
            || {
                for _ in 0..iters {
                    black_box(unsafe { wa::wmemset(p1, black_box(b'x' as u32), n) });
                }
            },
            || {
                for _ in 0..iters {
                    black_box(unsafe { g_wmemset(p2 as *mut i32, black_box(b'x' as i32), n) });
                }
            },
            40,
        );
        println!(
            "wmemset n={n:<5} fl={:6.2} glibc={:6.2} fl/glibc={:.3}{}",
            f / iters as f64,
            g / iters as f64,
            f / g,
            if f / g > 1.2 {
                "  LOSS"
            } else if f / g < 0.9 {
                "  win"
            } else {
                ""
            }
        );
        // wmemcpy
        let (f, g) = bench2(
            || {
                for _ in 0..iters {
                    black_box(unsafe { wa::wmemcpy(p1, black_box(sp), n) });
                }
            },
            || {
                for _ in 0..iters {
                    black_box(unsafe { g_wmemcpy(p2 as *mut i32, black_box(sp) as *const i32, n) });
                }
            },
            40,
        );
        println!(
            "wmemcpy n={n:<5} fl={:6.2} glibc={:6.2} fl/glibc={:.3}{}",
            f / iters as f64,
            g / iters as f64,
            f / g,
            if f / g > 1.2 {
                "  LOSS"
            } else if f / g < 0.9 {
                "  win"
            } else {
                ""
            }
        );
    }
}
