//! Does fl memset lose to glibc on UNALIGNED dst? raw_avx_memset uses vmovdqu stores;
//! glibc aligns the dest. Test aligned vs unaligned dst at n=4096/16384 vs glibc (dlmopen).
use std::hint::black_box;
use std::time::Instant;
fn pctl(s: &[f64], q: f64) -> f64 {
    let mut v = s.to_vec();
    v.sort_by(|a, b| a.partial_cmp(b).unwrap());
    v[((q * (v.len() - 1) as f64).round() as usize).min(v.len() - 1)]
}
type SetFn = unsafe extern "C" fn(*mut core::ffi::c_void, i32, usize) -> *mut core::ffi::c_void;
fn main() {
    let h = unsafe {
        libc::dlmopen(
            libc::LM_ID_NEWLM,
            b"libc.so.6\0".as_ptr().cast(),
            libc::RTLD_LAZY | libc::RTLD_LOCAL,
        )
    };
    assert!(!h.is_null());
    let g: SetFn = unsafe { std::mem::transmute(libc::dlsym(h, b"memset\0".as_ptr().cast())) };
    use frankenlibc_abi::string_abi as fa;
    let mut buf = vec![0u8; 131072 + 128];
    let base = buf.as_mut_ptr();
    // correctness on a few configs
    for (od, n) in [(0usize, 4096usize), (16, 4096), (3, 16384), (31, 8192)] {
        let dp = unsafe { (((base as usize + 31) & !31) as *mut u8).add(od) };
        unsafe {
            fa::memset(dp as *mut _, 0xab, n);
        }
        assert!(
            unsafe { std::slice::from_raw_parts(dp, n) }
                .iter()
                .all(|&b| b == 0xab),
            "memset correctness od={od} n={n}"
        );
        unsafe {
            fa::memset(dp as *mut _, 0x00, n);
        }
    }
    println!("memset correctness OK");
    for &n in &[4096usize, 16384] {
        for (tag, od) in [
            ("dstalign", 0usize),
            ("dst+16", 16),
            ("dst+3", 3),
            ("dst+1", 1),
        ] {
            let dp = unsafe { (((base as usize + 31) & !31) as *mut u8).add(od) }
                as *mut core::ffi::c_void;
            let iters = 300_000u64;
            let (mut fl, mut gl) = (Vec::new(), Vec::new());
            for r in 0..50 {
                if r % 2 == 0 {
                    let t = Instant::now();
                    for _ in 0..iters {
                        black_box(unsafe { fa::memset(dp, 0xab, n) });
                    }
                    fl.push(t.elapsed().as_nanos() as f64 / iters as f64);
                    let t = Instant::now();
                    for _ in 0..iters {
                        black_box(unsafe { g(dp, 0xab, n) });
                    }
                    gl.push(t.elapsed().as_nanos() as f64 / iters as f64);
                } else {
                    let t = Instant::now();
                    for _ in 0..iters {
                        black_box(unsafe { g(dp, 0xab, n) });
                    }
                    gl.push(t.elapsed().as_nanos() as f64 / iters as f64);
                    let t = Instant::now();
                    for _ in 0..iters {
                        black_box(unsafe { fa::memset(dp, 0xab, n) });
                    }
                    fl.push(t.elapsed().as_nanos() as f64 / iters as f64);
                }
            }
            let (f, gg) = (pctl(&fl, 0.1), pctl(&gl, 0.1));
            println!(
                "memset n={n:<6} {tag:<9} fl={f:8.1} glibc={gg:8.1} fl/glibc={:.3}",
                f / gg
            );
        }
    }
}
