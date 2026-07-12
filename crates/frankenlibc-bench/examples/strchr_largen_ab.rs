//! Characterize fl strchr vs glibc strchr (dlmopen) across sizes, target ABSENT (full
//! scan to NUL = throughput). The probe showed n=256 at ~2.9x; this maps the curve so a
//! scanner change can be validated for no-regression at every size.
//!
//! Run: cargo run --release --example strchr_largen_ab --features abi-bench

use std::hint::black_box;
use std::time::Instant;

type StrchrFn = unsafe extern "C" fn(*const i8, i32) -> *mut i8;

unsafe fn dl(h: *mut libc::c_void, n: &[u8]) -> StrchrFn {
    let p = unsafe { libc::dlsym(h, n.as_ptr().cast()) };
    assert!(!p.is_null());
    unsafe { std::mem::transmute::<*mut libc::c_void, StrchrFn>(p) }
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
    let g_strchr: StrchrFn = unsafe { dl(h, b"strchr\0") };

    // Correctness cross-check (present + absent) vs glibc across alignments/lengths.
    {
        let mut checks = 0u64;
        for align in 0..70usize {
            for len in 0..300usize {
                let mut buf = vec![0u8; align + len + 1 + 160];
                for k in 0..len {
                    buf[align + k] = b'a' + ((align + k) % 25) as u8;
                }
                buf[align + len] = 0;
                let sp = unsafe { buf.as_ptr().add(align) as *const i8 };
                // absent target 'Z'
                let f = unsafe { frankenlibc_abi::string_abi::strchr(sp, b'Z' as i32) };
                let g = unsafe { g_strchr(sp, b'Z' as i32) };
                assert_eq!(f as usize, g as usize, "absent align={align} len={len}");
                // present target: last char (if any)
                if len > 0 {
                    let t = buf[align + len - 1] as i32;
                    let f2 = unsafe { frankenlibc_abi::string_abi::strchr(sp, t) };
                    let g2 = unsafe { g_strchr(sp, t) };
                    assert_eq!(f2 as usize, g2 as usize, "present align={align} len={len}");
                }
                checks += 1;
            }
        }
        println!("correctness: {checks} (align×len) fl strchr == glibc ✓");
    }

    let sizes = [64usize, 128, 256, 512, 1024, 2048, 4096, 16384];
    for &n in &sizes {
        let mut buf = vec![b'x'; n + 16];
        buf[n] = 0;
        let scp = unsafe { buf.as_ptr().add(0) as *const i8 };
        let lit = 20_000u64;
        let (mut fl, mut gl) = (Vec::new(), Vec::new());
        for r in 0..100 {
            if r % 2 == 0 {
                let t = Instant::now();
                for _ in 0..lit {
                    black_box(unsafe { frankenlibc_abi::string_abi::strchr(scp, b'Z' as i32) });
                }
                fl.push(t.elapsed().as_nanos() as f64 / lit as f64);
                let t = Instant::now();
                for _ in 0..lit {
                    black_box(unsafe { g_strchr(scp, b'Z' as i32) });
                }
                gl.push(t.elapsed().as_nanos() as f64 / lit as f64);
            } else {
                let t = Instant::now();
                for _ in 0..lit {
                    black_box(unsafe { g_strchr(scp, b'Z' as i32) });
                }
                gl.push(t.elapsed().as_nanos() as f64 / lit as f64);
                let t = Instant::now();
                for _ in 0..lit {
                    black_box(unsafe { frankenlibc_abi::string_abi::strchr(scp, b'Z' as i32) });
                }
                fl.push(t.elapsed().as_nanos() as f64 / lit as f64);
            }
        }
        let (f10, g10) = (pctl(&fl, 0.1), pctl(&gl, 0.1));
        println!(
            "STRCHR n={n:<6} p10: fl={f10:.2} glibc={g10:.2} fl/glibc={:.3}  {}",
            f10 / g10,
            if f10 <= g10 * 1.1 { "ok" } else { "LOSS" }
        );
    }
}
