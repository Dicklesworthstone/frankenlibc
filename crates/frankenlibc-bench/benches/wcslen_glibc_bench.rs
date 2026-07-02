//! wcslen A/B: deployed FrankenLibC vs host glibc (untracked wide string → new
//! strict fast path). glibc via dlmopen. Default strict mode.
use std::ffi::c_void;
use std::sync::OnceLock;
use std::time::Instant;
use criterion::{black_box, criterion_group, criterion_main, Criterion};
type Fn_ = unsafe extern "C" fn(*const u32) -> usize;
fn host() -> Fn_ {
    static H: OnceLock<usize> = OnceLock::new();
    let a = *H.get_or_init(|| unsafe {
        let h = libc::dlmopen(libc::LM_ID_NEWLM, b"libc.so.6\0".as_ptr().cast(), libc::RTLD_LAZY | libc::RTLD_LOCAL);
        assert!(!h.is_null()); libc::dlsym(h, b"wcslen\0".as_ptr().cast()) as usize
    });
    unsafe { std::mem::transmute::<usize, Fn_>(a) }
}
fn pctl(s: &[f64], q: f64) -> f64 { let mut v=s.to_vec(); v.sort_by(|a,b|a.partial_cmp(b).unwrap()); let r=q*(v.len()-1) as f64; let(lo,hi)=(r.floor() as usize,r.ceil() as usize); if lo==hi{v[lo]}else{v[lo]*(1.0-(r-lo as f64))+v[hi]*(r-lo as f64)} }
fn bench(c: &mut Criterion) {
    let g = host();
    let mut grp = c.benchmark_group("wcslen"); grp.sample_size(30);
    for &n in &[4usize, 16, 64, 1024] {
        let mut buf: Vec<u32> = std::iter::repeat(b'a' as u32).take(n).collect(); buf.push(0);
        let p = buf.as_ptr();
        assert_eq!(unsafe { frankenlibc_abi::wchar_abi::wcslen(p) }, unsafe { g(p) }, "wcslen fl!=glibc n={n}");
        let it = 2000u64; let (mut fs, mut gs) = (Vec::new(), Vec::new());
        for _ in 0..100 {
            let t = Instant::now();
            for _ in 0..it { black_box(unsafe { frankenlibc_abi::wchar_abi::wcslen(black_box(p)) }); }
            fs.push(t.elapsed().as_nanos() as f64 / it as f64);
            let t = Instant::now();
            for _ in 0..it { black_box(unsafe { g(black_box(p)) }); }
            gs.push(t.elapsed().as_nanos() as f64 / it as f64);
        }
        let (fp,gp)=(pctl(&fs,0.5),pctl(&gs,0.5));
        println!("WCSLEN n={n} fl_p50={fp:.2}ns glibc_p50={gp:.2}ns ratio_fl_over_glibc={:.2}", fp/gp);
    }
    grp.bench_function("noop", |b| b.iter(|| black_box(1u8))); grp.finish();
}
criterion_group!(benches, bench); criterion_main!(benches);
