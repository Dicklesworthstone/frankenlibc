//! Does fl memmove BACKWARD-OVERLAP (dst>src, overlapping) lose to glibc on unaligned dst?
//! raw_avx_copy_backward uses vmovdqu stores (descending). shift=64 (dst=src+64).
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
    let shift = 64usize; // dst = src + 64 (backward overlap, dst > src)
    // correctness vs byte-wise ref (descending semantics): dst[i]=orig src[i]
    for (osrc, n) in [(0usize, 4096usize), (16, 16384), (3, 8192)] {
        let s0 = (((base as usize + 31) & !31) + osrc) as *mut u8;
        let d0 = unsafe { s0.add(shift) };
        let mut refbuf = vec![0u8; n];
        for i in 0..n {
            refbuf[i] = unsafe { *d0.sub(0).add(i).sub(0) };
            let _ = &mut refbuf;
        }
        // capture original src region first
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
                "memmove bwd correctness osrc={osrc} n={n} i={i}"
            );
        }
        for b in buf.iter_mut() {
            *b = 0x5au8;
        }
    }
    println!("memmove bwd correctness OK");
    for &n in &[4096usize, 16384] {
        for (tag, osrc) in [("end_al", 0usize), ("end+16", 16), ("end+8", 8)] {
            // src at osrc, dst = src+shift; vary osrc so (dst+n) alignment varies
            let s0 = ((((base as usize + 31) & !31) + osrc) as *mut u8);
            let d0 = unsafe { s0.add(shift) } as *mut core::ffi::c_void;
            let sp = s0 as *const core::ffi::c_void;
            let iters = 200_000u64;
            let (mut fl, mut gl) = (Vec::new(), Vec::new());
            for r in 0..50 {
                if r % 2 == 0 {
                    let t = Instant::now();
                    for _ in 0..iters {
                        black_box(unsafe { fa::memmove(d0, sp, n) });
                    }
                    fl.push(t.elapsed().as_nanos() as f64 / iters as f64);
                    let t = Instant::now();
                    for _ in 0..iters {
                        black_box(unsafe { g(d0, sp, n) });
                    }
                    gl.push(t.elapsed().as_nanos() as f64 / iters as f64);
                } else {
                    let t = Instant::now();
                    for _ in 0..iters {
                        black_box(unsafe { g(d0, sp, n) });
                    }
                    gl.push(t.elapsed().as_nanos() as f64 / iters as f64);
                    let t = Instant::now();
                    for _ in 0..iters {
                        black_box(unsafe { fa::memmove(d0, sp, n) });
                    }
                    fl.push(t.elapsed().as_nanos() as f64 / iters as f64);
                }
            }
            let (f, gg) = (pctl(&fl, 0.1), pctl(&gl, 0.1));
            println!(
                "memmove-bwd n={n:<6} {tag:<7} (dst+n)&31={:2} fl={f:8.1} glibc={gg:8.1} fl/glibc={:.3}",
                (d0 as usize + n) & 31,
                f / gg
            );
        }
    }
}
