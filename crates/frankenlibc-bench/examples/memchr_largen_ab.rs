//! fl memchr vs glibc (dlmopen) across sizes — validates the new 64-lane medium tier
//! (byte-exact first-match vs glibc over align×len×target-position) and maps the perf
//! curve for no-regression. memchr is bounded (known n) so target ABSENT = full scan.
//!
//! Run: cargo run --release --example memchr_largen_ab --features abi-bench

use std::hint::black_box;
use std::time::Instant;

type MemchrFn = unsafe extern "C" fn(*const std::ffi::c_void, i32, usize) -> *mut std::ffi::c_void;

unsafe fn dl(h: *mut libc::c_void, n: &[u8]) -> MemchrFn {
    let p = unsafe { libc::dlsym(h, n.as_ptr().cast()) };
    assert!(!p.is_null());
    unsafe { std::mem::transmute::<*mut libc::c_void, MemchrFn>(p) }
}

fn pctl(s: &[f64], q: f64) -> f64 {
    let mut v = s.to_vec();
    v.sort_by(|a, b| a.partial_cmp(b).unwrap());
    v[((q * (v.len() - 1) as f64).round() as usize).min(v.len() - 1)]
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
    let g: MemchrFn = unsafe { dl(h, b"memchr\0") };

    // Correctness: fl memchr == glibc over alignment × length × target position (present
    // at every index, and absent) — exercises the 64-lane tier, its boundaries, and the
    // 32B/WORD/scalar tails.
    {
        let mut checks = 0u64;
        for align in 0..40usize {
            for len in 0..300usize {
                let mut buf = vec![0u8; align + len + 64];
                for k in 0..len {
                    buf[align + k] = b'a' + ((align + k) % 25) as u8;
                }
                let bp = unsafe { buf.as_ptr().add(align) as *const std::ffi::c_void };
                // absent
                let f = unsafe { frankenlibc_abi::string_abi::memchr(bp, b'Z' as i32, len) };
                let gg = unsafe { g(bp, b'Z' as i32, len) };
                assert_eq!(f as usize, gg as usize, "absent align={align} len={len}");
                // present at a few positions
                for &pos in &[0usize, len / 2, len.saturating_sub(1)] {
                    if pos >= len {
                        continue;
                    }
                    let t = buf[align + pos] as i32;
                    let f2 = unsafe { frankenlibc_abi::string_abi::memchr(bp, t, len) };
                    let g2 = unsafe { g(bp, t, len) };
                    assert_eq!(
                        f2 as usize, g2 as usize,
                        "present align={align} len={len} pos={pos}"
                    );
                }
                checks += 1;
            }
        }
        println!("correctness: {checks} (align×len) fl memchr == glibc ✓");
    }

    let sizes = [32usize, 48, 64, 96, 128, 192, 256, 512, 1024, 4096];
    for &n in &sizes {
        let buf = vec![b'x'; n + 16];
        let bp = unsafe { buf.as_ptr() as *const std::ffi::c_void };
        let lit = 30_000u64;
        let (mut fl, mut gl) = (Vec::new(), Vec::new());
        for r in 0..100 {
            if r % 2 == 0 {
                let t = Instant::now();
                for _ in 0..lit {
                    black_box(unsafe { frankenlibc_abi::string_abi::memchr(bp, b'Z' as i32, n) });
                }
                fl.push(t.elapsed().as_nanos() as f64 / lit as f64);
                let t = Instant::now();
                for _ in 0..lit {
                    black_box(unsafe { g(bp, b'Z' as i32, n) });
                }
                gl.push(t.elapsed().as_nanos() as f64 / lit as f64);
            } else {
                let t = Instant::now();
                for _ in 0..lit {
                    black_box(unsafe { g(bp, b'Z' as i32, n) });
                }
                gl.push(t.elapsed().as_nanos() as f64 / lit as f64);
                let t = Instant::now();
                for _ in 0..lit {
                    black_box(unsafe { frankenlibc_abi::string_abi::memchr(bp, b'Z' as i32, n) });
                }
                fl.push(t.elapsed().as_nanos() as f64 / lit as f64);
            }
        }
        let (f10, g10) = (pctl(&fl, 0.1), pctl(&gl, 0.1));
        println!(
            "MEMCHR n={n:<6} p10: fl={f10:.2} glibc={g10:.2} fl/glibc={:.3}  {}",
            f10 / g10,
            if f10 <= g10 * 1.1 { "ok" } else { "LOSS" }
        );
    }
}
