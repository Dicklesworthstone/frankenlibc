//! strrchr A/B: deployed FrankenLibC vs host glibc. Measures the new strict
//! fast-path (membrane removal) at small sizes + scan throughput at large sizes.
//! glibc via dlmopen(LM_ID_NEWLM). Default strict mode.
use std::ffi::{c_char, c_int, c_void};
use std::sync::OnceLock;
use std::time::Instant;
use criterion::{black_box, criterion_group, criterion_main, Criterion};

type Fn_ = unsafe extern "C" fn(*const c_char, c_int) -> *mut c_char;
fn host() -> Fn_ {
    static H: OnceLock<usize> = OnceLock::new();
    let a = *H.get_or_init(|| unsafe {
        let h = libc::dlmopen(libc::LM_ID_NEWLM, b"libc.so.6\0".as_ptr().cast(),
            libc::RTLD_LAZY | libc::RTLD_LOCAL);
        assert!(!h.is_null());
        libc::dlsym(h, b"strrchr\0".as_ptr().cast()) as usize
    });
    unsafe { std::mem::transmute::<usize, Fn_>(a) }
}
fn pctl(s: &[f64], q: f64) -> f64 {
    let mut v = s.to_vec(); v.sort_by(|a,b| a.partial_cmp(b).unwrap());
    let r = q*(v.len()-1) as f64; let (lo,hi)=(r.floor() as usize, r.ceil() as usize);
    if lo==hi { v[lo] } else { v[lo]*(1.0-(r-lo as f64))+v[hi]*(r-lo as f64) }
}
fn bench(c: &mut Criterion) {
    let g = host();
    let mut grp = c.benchmark_group("strrchr"); grp.sample_size(30);
    for &size in &[8usize, 16, 64, 1024, 65536] {
        // 'a' buffer with a '/' near the middle (a real last-match), NUL-terminated.
        let mut buf = vec![b'a'; size]; if size > 2 { buf[size/2] = b'/'; } buf.push(0);
        let p = buf.as_ptr().cast::<c_char>();
        let fp = unsafe { frankenlibc_abi::string_abi::strrchr(p, b'/' as c_int) };
        let gp = unsafe { g(p, b'/' as c_int) };
        assert_eq!(fp as usize, gp as usize, "strrchr fl!=glibc size={size}");
        let it = 2000u64; let (mut fs, mut gs) = (Vec::new(), Vec::new());
        for _ in 0..100 {
            let t = Instant::now();
            for _ in 0..it { black_box(unsafe { frankenlibc_abi::string_abi::strrchr(black_box(p), black_box(b'/' as c_int)) }); }
            fs.push(t.elapsed().as_nanos() as f64 / it as f64);
            let t = Instant::now();
            for _ in 0..it { black_box(unsafe { g(black_box(p), black_box(b'/' as c_int)) }); }
            gs.push(t.elapsed().as_nanos() as f64 / it as f64);
        }
        let (fp, gp) = (pctl(&fs,0.50), pctl(&gs,0.50));
        println!("STRRCHR size={size} fl_p50={fp:.2}ns glibc_p50={gp:.2}ns ratio_fl_over_glibc={:.2}", fp/gp);
    }
    grp.bench_function("noop", |b| b.iter(|| black_box(1u8))); grp.finish();
}
criterion_group!(benches, bench); criterion_main!(benches);
