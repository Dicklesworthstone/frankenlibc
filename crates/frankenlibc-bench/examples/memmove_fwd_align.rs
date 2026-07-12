//! Does fl memmove FORWARD-OVERLAP (dst<src, overlapping) lose to glibc on unaligned dst?
//! raw_avx_copy_forward uses vmovdqu stores. shift=64 (>=32 ⇒ a dest-peel would be safe).
use std::hint::black_box;
use std::time::Instant;
fn pctl(s: &[f64], q: f64) -> f64 {
    let mut v = s.to_vec();
    v.sort_by(|a, b| a.partial_cmp(b).unwrap());
    v[((q * (v.len() - 1) as f64).round() as usize).min(v.len() - 1)]
}
type MvFn = unsafe extern "C" fn(
    *mut core::ffi::c_void,
    *const core::ffi::c_void,
    usize,
) -> *mut core::ffi::c_void;
fn main() {
    let h = unsafe {
        libc::dlmopen(
            libc::LM_ID_NEWLM,
            b"libc.so.6\0".as_ptr().cast(),
            libc::RTLD_LAZY | libc::RTLD_LOCAL,
        )
    };
    assert!(!h.is_null());
    let g: MvFn = unsafe { std::mem::transmute(libc::dlsym(h, b"memmove\0".as_ptr().cast())) };
    use frankenlibc_abi::string_abi as fa;
    let mut buf = vec![0x5au8; 262144];
    let base = buf.as_mut_ptr();
    let shift = 64usize; // src = dst + 64 (forward overlap, distance 64 >= 32)
    // correctness: fl vs a reference (byte-wise) forward move
    for (od, n) in [(0usize, 4096usize), (16, 16384), (3, 8192)] {
        let d0 = (((base as usize + 31) & !31) + od) as *mut u8;
        let s0 = unsafe { d0.add(shift) };
        let mut refbuf = vec![0u8; n];
        for i in 0..n {
            refbuf[i] = unsafe { *s0.add(i) };
        }
        unsafe {
            fa::memmove(d0 as *mut _, s0 as *const _, n);
        }
        for i in 0..n {
            assert_eq!(
                unsafe { *d0.add(i) },
                refbuf[i],
                "memmove fwd correctness od={od} n={n} i={i}"
            );
        }
        // restore
        for (i, b) in buf.iter_mut().enumerate() {
            *b = 0x5au8;
            let _ = (i,);
        }
    }
    println!("memmove fwd correctness OK");
    for &n in &[4096usize, 16384] {
        for (tag, od) in [("dstalign", 0usize), ("dst+16", 16), ("dst+8", 8)] {
            let d0 = ((((base as usize + 31) & !31) + od) as *mut u8) as *mut core::ffi::c_void;
            let s0 = unsafe { (d0 as *const u8).add(shift) } as *const core::ffi::c_void;
            let iters = 200_000u64;
            let (mut fl, mut gl) = (Vec::new(), Vec::new());
            for r in 0..50 {
                if r % 2 == 0 {
                    let t = Instant::now();
                    for _ in 0..iters {
                        black_box(unsafe { fa::memmove(d0, s0, n) });
                    }
                    fl.push(t.elapsed().as_nanos() as f64 / iters as f64);
                    let t = Instant::now();
                    for _ in 0..iters {
                        black_box(unsafe { g(d0, s0, n) });
                    }
                    gl.push(t.elapsed().as_nanos() as f64 / iters as f64);
                } else {
                    let t = Instant::now();
                    for _ in 0..iters {
                        black_box(unsafe { g(d0, s0, n) });
                    }
                    gl.push(t.elapsed().as_nanos() as f64 / iters as f64);
                    let t = Instant::now();
                    for _ in 0..iters {
                        black_box(unsafe { fa::memmove(d0, s0, n) });
                    }
                    fl.push(t.elapsed().as_nanos() as f64 / iters as f64);
                }
            }
            let (f, gg) = (pctl(&fl, 0.1), pctl(&gl, 0.1));
            println!(
                "memmove-fwd n={n:<6} {tag:<9} fl={f:8.1} glibc={gg:8.1} fl/glibc={:.3}",
                f / gg
            );
        }
    }
}
