//! fl strnlen vs glibc (dlmopen) across sizes — validates the new bounded-path 64B tier
//! (byte-exact min(strlen,n) vs glibc over align×len×n) and maps the perf curve. strnlen
//! goes through scan_c_string's Some(limit) path.
//!
//! Run: cargo run --release --example strnlen_largen_ab --features abi-bench

use std::hint::black_box;
use std::time::Instant;

type StrnlenFn = unsafe extern "C" fn(*const i8, usize) -> usize;

unsafe fn dl(h: *mut libc::c_void, n: &[u8]) -> StrnlenFn {
    let p = unsafe { libc::dlsym(h, n.as_ptr().cast()) };
    assert!(!p.is_null());
    unsafe { std::mem::transmute::<*mut libc::c_void, StrnlenFn>(p) }
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
    let g: StrnlenFn = unsafe { dl(h, b"strnlen\0") };

    // Correctness: fl strnlen == glibc == min(strlen, n) over align × len × n (n<len,
    // n==len, n>len, and 64/32-byte-window edges).
    {
        let mut checks = 0u64;
        for align in 0..70usize {
            for len in 0..260usize {
                let mut buf = vec![0u8; align + len + 1 + 160];
                for k in 0..len {
                    buf[align + k] = 1 + ((align + k) % 200) as u8;
                }
                buf[align + len] = 0;
                let sp = unsafe { buf.as_ptr().add(align) as *const i8 };
                for &nn in &[0usize, len / 3, len, len + 1, len + 40, 300] {
                    let f = unsafe { frankenlibc_abi::string_abi::strnlen(sp, nn) };
                    let gg = unsafe { g(sp, nn) };
                    assert_eq!(f, gg, "align={align} len={len} n={nn}");
                }
                checks += 1;
            }
        }
        println!("correctness: {checks} (align×len) fl strnlen == glibc ✓");
    }

    let sizes = [32usize, 48, 64, 96, 128, 192, 256, 512, 1024, 4096];
    for &l in &sizes {
        let mut buf = vec![b'x'; l + 16];
        buf[l] = 0;
        let scp = unsafe { buf.as_ptr() as *const i8 };
        let lit = 30_000u64;
        let (mut fl, mut gl) = (Vec::new(), Vec::new());
        for r in 0..100 {
            if r % 2 == 0 {
                let t = Instant::now();
                for _ in 0..lit {
                    black_box(unsafe { frankenlibc_abi::string_abi::strnlen(scp, l) });
                }
                fl.push(t.elapsed().as_nanos() as f64 / lit as f64);
                let t = Instant::now();
                for _ in 0..lit {
                    black_box(unsafe { g(scp, l) });
                }
                gl.push(t.elapsed().as_nanos() as f64 / lit as f64);
            } else {
                let t = Instant::now();
                for _ in 0..lit {
                    black_box(unsafe { g(scp, l) });
                }
                gl.push(t.elapsed().as_nanos() as f64 / lit as f64);
                let t = Instant::now();
                for _ in 0..lit {
                    black_box(unsafe { frankenlibc_abi::string_abi::strnlen(scp, l) });
                }
                fl.push(t.elapsed().as_nanos() as f64 / lit as f64);
            }
        }
        let (f10, g10) = (pctl(&fl, 0.1), pctl(&gl, 0.1));
        println!(
            "STRNLEN l={l:<6} p10: fl={f10:.2} glibc={g10:.2} fl/glibc={:.3}  {}",
            f10 / g10,
            if f10 <= g10 * 1.1 { "ok" } else { "LOSS" }
        );
    }
}
