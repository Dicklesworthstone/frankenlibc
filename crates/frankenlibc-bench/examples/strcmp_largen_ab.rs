//! fl strcmp vs glibc (dlmopen) over equal-prefix strings (worst-case full scan to NUL)
//! across sizes — checks whether scan_strcmp's 32B-only panel leaves a kernel gap at
//! large equal prefixes (common in sorted-data / shared-prefix compares).
//!
//! Run: cargo run --release --example strcmp_largen_ab --features abi-bench

use std::hint::black_box;
use std::time::Instant;

type StrcmpFn = unsafe extern "C" fn(*const i8, *const i8) -> i32;

unsafe fn dl(h: *mut libc::c_void, n: &[u8]) -> StrcmpFn {
    let p = unsafe { libc::dlsym(h, n.as_ptr().cast()) };
    assert!(!p.is_null());
    unsafe { std::mem::transmute::<*mut libc::c_void, StrcmpFn>(p) }
}

fn pctl(s: &[f64], q: f64) -> f64 {
    let mut v = s.to_vec();
    v.sort_by(|a, b| a.partial_cmp(b).unwrap());
    v[((q * (v.len() - 1) as f64).round() as usize).min(v.len() - 1)]
}

fn main() {
    let h = unsafe {
        libc::dlmopen(libc::LM_ID_NEWLM, b"libc.so.6\0".as_ptr().cast(), libc::RTLD_LAZY | libc::RTLD_LOCAL)
    };
    assert!(!h.is_null());
    let g: StrcmpFn = unsafe { dl(h, b"strcmp\0") };

    // Correctness: fl strcmp sign == glibc sign over align × len × (equal / differ-at-k).
    {
        let mut checks = 0u64;
        for align in 0..40usize {
            for len in 0..200usize {
                let mut a = vec![0u8; align + len + 1 + 96];
                for k in 0..len { a[align + k] = b'a' + ((align + k) % 25) as u8; }
                a[align + len] = 0;
                let ap = unsafe { a.as_ptr().add(align) as *const i8 };
                // equal
                let mut b = a.clone();
                let bp = unsafe { b.as_ptr().add(align) as *const i8 };
                let f = unsafe { frankenlibc_abi::string_abi::strcmp(ap, bp) };
                let gg = unsafe { g(ap, bp) };
                assert_eq!(f.signum(), gg.signum(), "equal align={align} len={len}");
                // differ at k
                if len > 0 {
                    for &k in &[0usize, len / 2, len - 1] {
                        b[align + k] = b[align + k].wrapping_add(1).max(1);
                        let f2 = unsafe { frankenlibc_abi::string_abi::strcmp(ap, bp) };
                        let g2 = unsafe { g(ap, bp) };
                        assert_eq!(f2.signum(), g2.signum(), "differ align={align} len={len} k={k}");
                        b[align + k] = a[align + k];
                    }
                }
                checks += 1;
            }
        }
        println!("correctness: {checks} (align×len) fl strcmp sign == glibc ✓");
    }

    let sizes = [32usize, 64, 128, 256, 512, 1024, 4096];
    for &l in &sizes {
        let mut a = vec![b'x'; l + 16]; a[l] = 0;
        let b = a.clone();
        let ap = a.as_ptr() as *const i8;
        let bp = b.as_ptr() as *const i8;
        let lit = 30_000u64;
        let (mut fl, mut gl) = (Vec::new(), Vec::new());
        for r in 0..100 {
            if r % 2 == 0 {
                let t = Instant::now();
                for _ in 0..lit { black_box(unsafe { frankenlibc_abi::string_abi::strcmp(ap, bp) }); }
                fl.push(t.elapsed().as_nanos() as f64 / lit as f64);
                let t = Instant::now();
                for _ in 0..lit { black_box(unsafe { g(ap, bp) }); }
                gl.push(t.elapsed().as_nanos() as f64 / lit as f64);
            } else {
                let t = Instant::now();
                for _ in 0..lit { black_box(unsafe { g(ap, bp) }); }
                gl.push(t.elapsed().as_nanos() as f64 / lit as f64);
                let t = Instant::now();
                for _ in 0..lit { black_box(unsafe { frankenlibc_abi::string_abi::strcmp(ap, bp) }); }
                fl.push(t.elapsed().as_nanos() as f64 / lit as f64);
            }
        }
        let (f10, g10) = (pctl(&fl, 0.1), pctl(&gl, 0.1));
        println!("STRCMP l={l:<6} p10: fl={f10:.2} glibc={g10:.2} fl/glibc={:.3}  {}",
            f10 / g10, if f10 <= g10 * 1.1 { "ok" } else { "LOSS" });
    }
}
