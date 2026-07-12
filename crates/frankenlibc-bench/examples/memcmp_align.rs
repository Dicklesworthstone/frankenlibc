//! Test whether the memcmp gap is alignment-driven: 32-aligned vs unaligned buffers.
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
    let big = vec![0x5au8; 131072 + 128];
    let base = big.as_ptr();
    for &n in &[4096usize, 16384] {
        for (tag, o1, o2) in [
            ("aligned32", 0usize, 0usize),
            ("both+16", 16, 16),
            ("skew", 0, 16),
        ] {
            // align base to 32 then add offsets
            let a0 = ((base as usize + 31) & !31) as *const u8;
            let ap = unsafe { a0.add(o1) } as *const core::ffi::c_void;
            let bp = unsafe { a0.add(o2) } as *const core::ffi::c_void; // same buffer, equal region
            let iters = 300_000u64;
            let (mut fl, mut gl) = (Vec::new(), Vec::new());
            for r in 0..50 {
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
                "memcmp n={n:<6} {tag:<10} fl={f:8.1} glibc={gg:8.1} fl/glibc={:.3}",
                f / gg
            );
        }
    }
}
