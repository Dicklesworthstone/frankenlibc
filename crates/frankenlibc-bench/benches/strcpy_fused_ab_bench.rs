//! strcpy two-pass vs fused single-pass, all in one process (worker variance cancels in
//! new/old). The deployed strcpy strict path does scan_c_string + raw_memcpy_bytes (reads
//! src twice); this measures whether a fused single-pass SIMD copy is actually faster
//! before deploying — via the string_abi bench hooks (real internal fns, not replicas).
//!
//! ARM A (old) = bench_strcpy_two_pass (scan + raw_memcpy_bytes).
//! ARM B (new) = bench_strcpy_fused (fused_strcpy_bytes).
//! ARM C       = host glibc strcpy via dlmopen.
use std::os::raw::c_char;
use std::sync::OnceLock;
use std::time::Instant;
use criterion::{black_box, criterion_group, criterion_main, Criterion};

type CpyFn = unsafe extern "C" fn(*mut c_char, *const c_char) -> *mut c_char;
fn host() -> CpyFn {
    static H: OnceLock<usize> = OnceLock::new();
    let a = *H.get_or_init(|| unsafe {
        let h = libc::dlmopen(libc::LM_ID_NEWLM, b"libc.so.6\0".as_ptr().cast(), libc::RTLD_LAZY | libc::RTLD_LOCAL);
        assert!(!h.is_null()); libc::dlsym(h, b"strcpy\0".as_ptr().cast()) as usize
    });
    unsafe { std::mem::transmute::<usize, CpyFn>(a) }
}

fn pctl(s: &[f64], q: f64) -> f64 { let mut v=s.to_vec(); v.sort_by(|a,b|a.partial_cmp(b).unwrap()); let r=q*(v.len()-1) as f64; let(lo,hi)=(r.floor() as usize,r.ceil() as usize); if lo==hi{v[lo]}else{v[lo]*(1.0-(r-lo as f64))+v[hi]*(r-lo as f64)} }

fn bench(c: &mut Criterion) {
    let g = host();
    let mut grp = c.benchmark_group("strcpy_fused"); grp.sample_size(10);
    let it = 4000u64;
    for &n in &[4usize, 8, 16, 32, 64, 128, 256, 1024] {
        let mut src: Vec<u8> = std::iter::repeat(b'a').take(n).collect(); src.push(0);
        let sp = src.as_ptr();
        let (mut a, mut b, mut cc) = (vec![0u8; n + 40], vec![0u8; n + 40], vec![0u8; n + 40]);
        let la = unsafe { frankenlibc_abi::string_abi::bench_strcpy_two_pass(a.as_mut_ptr(), sp) };
        let lb = unsafe { frankenlibc_abi::string_abi::bench_strcpy_fused(b.as_mut_ptr(), sp) };
        unsafe { g(cc.as_mut_ptr() as *mut c_char, sp as *const c_char); }
        assert_eq!(la, n, "two_pass len n={n}"); assert_eq!(lb, n, "fused len n={n}");
        assert_eq!(a[..=n], b[..=n], "fused bytes n={n}"); assert_eq!(a[..=n], cc[..=n], "glibc bytes n={n}");
        let (mut os, mut ns, mut gs) = (Vec::new(), Vec::new(), Vec::new());
        for _ in 0..80 {
            let t = Instant::now(); for _ in 0..it { unsafe { black_box(frankenlibc_abi::string_abi::bench_strcpy_two_pass(black_box(a.as_mut_ptr()), black_box(sp))); } } os.push(t.elapsed().as_nanos() as f64 / it as f64);
            let t = Instant::now(); for _ in 0..it { unsafe { black_box(frankenlibc_abi::string_abi::bench_strcpy_fused(black_box(b.as_mut_ptr()), black_box(sp))); } } ns.push(t.elapsed().as_nanos() as f64 / it as f64);
            let t = Instant::now(); for _ in 0..it { unsafe { black_box(g(black_box(cc.as_mut_ptr() as *mut c_char), black_box(sp as *const c_char))); } } gs.push(t.elapsed().as_nanos() as f64 / it as f64);
        }
        let (op,np,gp)=(pctl(&os,0.5),pctl(&ns,0.5),pctl(&gs,0.5));
        println!("STRCPY_FUSED n={n} two_pass={op:.2} fused={np:.2} glibc={gp:.2} fused/two_pass={:.3} fused/glibc={:.3} two_pass/glibc={:.3}", np/op, np/gp, op/gp);
    }
    grp.bench_function("noop", |b| b.iter(|| black_box(1u8))); grp.finish();
}
criterion_group!(benches, bench); criterion_main!(benches);
