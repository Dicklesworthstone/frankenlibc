//! Does fl memcpy lose to glibc on UNALIGNED dest? fl raw_avx_copy uses vmovdqu stores;
//! glibc aligns the dest. Test aligned vs unaligned dst/src at n=4096/16384 vs glibc (dlmopen).
use std::hint::black_box;
use std::time::Instant;
fn pctl(s: &[f64], q: f64) -> f64 {
    let mut v = s.to_vec();
    v.sort_by(|a, b| a.partial_cmp(b).unwrap());
    v[((q * (v.len() - 1) as f64).round() as usize).min(v.len() - 1)]
}
type CpFn = unsafe extern "C" fn(
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
    let g: CpFn = unsafe { std::mem::transmute(libc::dlsym(h, b"memcpy\0".as_ptr().cast())) };
    use frankenlibc_abi::string_abi as fa;
    let src = vec![0x5au8; 131072 + 128];
    let mut dst = vec![0u8; 131072 + 128];
    let sbase = src.as_ptr();
    let dbase = dst.as_mut_ptr();
    // verify correctness on a few configs first
    for (o_d, o_s, n) in [
        (0usize, 0usize, 4096usize),
        (16, 16, 4096),
        (16, 0, 4096),
        (0, 16, 16384),
    ] {
        let dp = unsafe { ((dbase as usize + 31) & !31) as *mut u8 };
        let dp = unsafe { dp.add(o_d) };
        let sp = unsafe { ((sbase as usize + 31) & !31) as *const u8 };
        let sp = unsafe { sp.add(o_s) };
        unsafe {
            fa::memcpy(dp as *mut _, sp as *const _, n);
        }
        assert!(
            unsafe { std::slice::from_raw_parts(dp, n) }
                .iter()
                .all(|&b| b == 0x5a),
            "memcpy correctness {o_d} {o_s} {n}"
        );
    }
    println!("memcpy correctness OK");
    for &n in &[4096usize, 16384] {
        for (tag, od, os) in [
            ("dstalign", 0usize, 0usize),
            ("dst+16", 16, 0),
            ("both+16", 16, 16),
            ("src+16", 0, 16),
        ] {
            let dp = unsafe { (((dbase as usize + 31) & !31) as *mut u8).add(od) }
                as *mut core::ffi::c_void;
            let sp = unsafe { (((sbase as usize + 31) & !31) as *const u8).add(os) }
                as *const core::ffi::c_void;
            let iters = 300_000u64;
            let (mut fl, mut gl) = (Vec::new(), Vec::new());
            for r in 0..50 {
                if r % 2 == 0 {
                    let t = Instant::now();
                    for _ in 0..iters {
                        black_box(unsafe { fa::memcpy(dp, sp, n) });
                    }
                    fl.push(t.elapsed().as_nanos() as f64 / iters as f64);
                    let t = Instant::now();
                    for _ in 0..iters {
                        black_box(unsafe { g(dp, sp, n) });
                    }
                    gl.push(t.elapsed().as_nanos() as f64 / iters as f64);
                } else {
                    let t = Instant::now();
                    for _ in 0..iters {
                        black_box(unsafe { g(dp, sp, n) });
                    }
                    gl.push(t.elapsed().as_nanos() as f64 / iters as f64);
                    let t = Instant::now();
                    for _ in 0..iters {
                        black_box(unsafe { fa::memcpy(dp, sp, n) });
                    }
                    fl.push(t.elapsed().as_nanos() as f64 / iters as f64);
                }
            }
            let (f, gg) = (pctl(&fl, 0.1), pctl(&gl, 0.1));
            println!(
                "memcpy n={n:<6} {tag:<9} fl={f:8.1} glibc={gg:8.1} fl/glibc={:.3}",
                f / gg
            );
        }
    }
}
