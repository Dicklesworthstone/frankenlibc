//! Characterize fl strlen vs glibc strlen (dlmopen) across sizes — where does the
//! *kernel* (floor amortized) lose? The probe showed n=1024 at 1.89x; this maps the
//! full curve so a kernel change can be validated for no-regression at every size.
//!
//! Run: cargo run --release --example strlen_largen_ab --features abi-bench

use std::hint::black_box;
use std::time::Instant;

type StrlenFn = unsafe extern "C" fn(*const i8) -> usize;

unsafe fn dl(h: *mut libc::c_void, n: &[u8]) -> StrlenFn {
    let p = unsafe { libc::dlsym(h, n.as_ptr().cast()) };
    assert!(!p.is_null());
    unsafe { std::mem::transmute::<*mut libc::c_void, StrlenFn>(p) }
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
    assert!(!h.is_null(), "dlmopen libc");
    let g_strlen: StrlenFn = unsafe { dl(h, b"strlen\0") };

    let sizes = [64usize, 128, 256, 512, 1024, 2048, 4096, 16384];
    for &n in &sizes {
        // Typical (non-128-aligned) buffer: a Vec is 8/16-aligned, offset by 8 bytes so
        // it is NOT 128-aligned (the common real-world case).
        let mut buf = vec![b'x'; n + 16];
        buf[n] = 0;
        let scp = unsafe { buf.as_ptr().add(0) as *const i8 };
        let lit = 20_000u64;
        let (mut fl, mut gl) = (Vec::new(), Vec::new());
        for r in 0..100 {
            if r % 2 == 0 {
                let t = Instant::now();
                for _ in 0..lit { black_box(unsafe { frankenlibc_abi::string_abi::strlen(scp) }); }
                fl.push(t.elapsed().as_nanos() as f64 / lit as f64);
                let t = Instant::now();
                for _ in 0..lit { black_box(unsafe { g_strlen(scp) }); }
                gl.push(t.elapsed().as_nanos() as f64 / lit as f64);
            } else {
                let t = Instant::now();
                for _ in 0..lit { black_box(unsafe { g_strlen(scp) }); }
                gl.push(t.elapsed().as_nanos() as f64 / lit as f64);
                let t = Instant::now();
                for _ in 0..lit { black_box(unsafe { frankenlibc_abi::string_abi::strlen(scp) }); }
                fl.push(t.elapsed().as_nanos() as f64 / lit as f64);
            }
        }
        let (f10, g10) = (pctl(&fl, 0.1), pctl(&gl, 0.1));
        println!(
            "STRLEN n={n:<6} p10: fl={f10:.2} glibc={g10:.2} fl/glibc={:.3}  {}",
            f10 / g10,
            if f10 <= g10 * 1.1 { "ok" } else { "LOSS" }
        );
    }
}
