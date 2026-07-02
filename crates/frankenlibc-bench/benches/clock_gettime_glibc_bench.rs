//! Deployed fl vs host glibc (dlmopen) for the hot vDSO time fns: clock_gettime,
//! gettimeofday, time. Both fl and glibc use the kernel vDSO; this measures the fl
//! per-call overhead (OnceLock get_or_init + vdso_resolution_enabled + clock_id
//! validation + membrane output-fits) ON TOP of the shared vDSO call.
use std::os::raw::{c_int, c_void};
use std::sync::OnceLock;
use std::time::Instant;
use criterion::{black_box, criterion_group, criterion_main, Criterion};

fn handle() -> usize {
    static H: OnceLock<usize> = OnceLock::new();
    *H.get_or_init(|| unsafe {
        let h = libc::dlmopen(libc::LM_ID_NEWLM, b"libc.so.6\0".as_ptr().cast(), libc::RTLD_LAZY | libc::RTLD_LOCAL);
        assert!(!h.is_null()); h as usize
    })
}
fn dl<T: Copy>(name: &[u8]) -> T {
    let p = unsafe { libc::dlsym(handle() as *mut _, name.as_ptr().cast()) };
    assert!(!p.is_null(), "dlsym failed");
    unsafe { std::mem::transmute_copy::<usize, T>(&(p as usize)) }
}
fn pctl(s: &[f64], q: f64) -> f64 { let mut v=s.to_vec(); v.sort_by(|a,b|a.partial_cmp(b).unwrap()); let r=q*(v.len()-1) as f64; let(lo,hi)=(r.floor() as usize,r.ceil() as usize); if lo==hi{v[lo]}else{v[lo]*(1.0-(r-lo as f64))+v[hi]*(r-lo as f64)} }

type CgFn = unsafe extern "C" fn(c_int, *mut libc::timespec) -> c_int;
type GtodFn = unsafe extern "C" fn(*mut libc::timeval, *mut c_void) -> c_int;

fn bench(c: &mut Criterion) {
    let g_cg: CgFn = dl(b"clock_gettime\0");
    let g_gtod: GtodFn = dl(b"gettimeofday\0");
    let mut grp = c.benchmark_group("clock_gettime"); grp.sample_size(10);
    let it = 20000u64;
    let mut ts = libc::timespec { tv_sec: 0, tv_nsec: 0 };
    let mut tv = libc::timeval { tv_sec: 0, tv_usec: 0 };

    for &clk in &[libc::CLOCK_REALTIME, libc::CLOCK_MONOTONIC] {
        let (mut fs, mut gs) = (Vec::new(), Vec::new());
        for _ in 0..100 {
            let t = Instant::now(); for _ in 0..it { black_box(unsafe { frankenlibc_abi::time_abi::clock_gettime(black_box(clk), &mut ts) }); } fs.push(t.elapsed().as_nanos() as f64 / it as f64);
            let t = Instant::now(); for _ in 0..it { black_box(unsafe { g_cg(black_box(clk), &mut ts) }); } gs.push(t.elapsed().as_nanos() as f64 / it as f64);
        }
        println!("CLOCK_GETTIME clk={clk} fl={:.2} glibc={:.2} fl/glibc={:.3}", pctl(&fs,0.5), pctl(&gs,0.5), pctl(&fs,0.5)/pctl(&gs,0.5));
    }
    {
        let (mut fs, mut gs) = (Vec::new(), Vec::new());
        for _ in 0..100 {
            let t = Instant::now(); for _ in 0..it { black_box(unsafe { frankenlibc_abi::time_abi::gettimeofday(&mut tv, std::ptr::null_mut()) }); } fs.push(t.elapsed().as_nanos() as f64 / it as f64);
            let t = Instant::now(); for _ in 0..it { black_box(unsafe { g_gtod(&mut tv, std::ptr::null_mut()) }); } gs.push(t.elapsed().as_nanos() as f64 / it as f64);
        }
        println!("GETTIMEOFDAY fl={:.2} glibc={:.2} fl/glibc={:.3}", pctl(&fs,0.5), pctl(&gs,0.5), pctl(&fs,0.5)/pctl(&gs,0.5));
    }
    grp.bench_function("noop", |b| b.iter(|| black_box(1u8))); grp.finish();
}
criterion_group!(benches, bench); criterion_main!(benches);
