//! wcstok full-tokenization A/B: deployed FrankenLibC vs host glibc. Measures the
//! new strict fast-path (wide write membrane removal). glibc via dlmopen.
use criterion::{Criterion, black_box, criterion_group, criterion_main};
use std::ffi::c_void;
use std::sync::OnceLock;
use std::time::Instant;
type Fn_ = unsafe extern "C" fn(*mut u32, *const u32, *mut *mut u32) -> *mut u32;
fn host() -> Fn_ {
    static H: OnceLock<usize> = OnceLock::new();
    let a = *H.get_or_init(|| unsafe {
        let h = libc::dlmopen(
            libc::LM_ID_NEWLM,
            b"libc.so.6\0".as_ptr().cast(),
            libc::RTLD_LAZY | libc::RTLD_LOCAL,
        );
        assert!(!h.is_null());
        libc::dlsym(h, b"wcstok\0".as_ptr().cast()) as usize
    });
    unsafe { std::mem::transmute::<usize, Fn_>(a) }
}
fn pctl(s: &[f64], q: f64) -> f64 {
    let mut v = s.to_vec();
    v.sort_by(|a, b| a.partial_cmp(b).unwrap());
    let r = q * (v.len() - 1) as f64;
    let (lo, hi) = (r.floor() as usize, r.ceil() as usize);
    if lo == hi {
        v[lo]
    } else {
        v[lo] * (1.0 - (r - lo as f64)) + v[hi] * (r - lo as f64)
    }
}
fn make(k: usize) -> Vec<u32> {
    let mut v = Vec::new();
    for i in 0..k {
        if i > 0 {
            v.push(b';' as u32);
        }
        for _ in 0..6 {
            v.push(b'a' as u32);
        }
    }
    v.push(0);
    v
}
fn run_fl(t: &[u32], d: *const u32) -> usize {
    let mut b = t.to_vec();
    let mut sp: *mut u32 = std::ptr::null_mut();
    let mut cur = b.as_mut_ptr();
    let mut n = 0;
    loop {
        let tk = unsafe { frankenlibc_abi::wchar_abi::wcstok(cur, d, &mut sp) };
        if tk.is_null() {
            break;
        }
        cur = std::ptr::null_mut();
        n += 1;
    }
    black_box(b.as_ptr());
    n
}
fn run_g(f: Fn_, t: &[u32], d: *const u32) -> usize {
    let mut b = t.to_vec();
    let mut sp: *mut u32 = std::ptr::null_mut();
    let mut cur = b.as_mut_ptr();
    let mut n = 0;
    loop {
        let tk = unsafe { f(cur, d, &mut sp) };
        if tk.is_null() {
            break;
        }
        cur = std::ptr::null_mut();
        n += 1;
    }
    black_box(b.as_ptr());
    n
}
fn bench(c: &mut Criterion) {
    let g = host();
    let delim: [u32; 2] = [b';' as u32, 0];
    let mut grp = c.benchmark_group("wcstok");
    grp.sample_size(30);
    for &k in &[8usize, 64, 512] {
        let t = make(k);
        assert_eq!(
            run_fl(&t, delim.as_ptr()),
            run_g(g, &t, delim.as_ptr()),
            "wcstok count fl!=glibc k={k}"
        );
        let it = 200u64;
        let (mut fs, mut gs) = (Vec::new(), Vec::new());
        for _ in 0..80 {
            let tt = Instant::now();
            for _ in 0..it {
                black_box(run_fl(&t, black_box(delim.as_ptr())));
            }
            fs.push(tt.elapsed().as_nanos() as f64 / it as f64);
            let tt = Instant::now();
            for _ in 0..it {
                black_box(run_g(g, &t, black_box(delim.as_ptr())));
            }
            gs.push(tt.elapsed().as_nanos() as f64 / it as f64);
        }
        let (fp, gp) = (pctl(&fs, 0.5), pctl(&gs, 0.5));
        println!(
            "WCSTOK k={k} fl_p50={fp:.1}ns glibc_p50={gp:.1}ns ns_per_tok_fl={:.2} ratio_fl_over_glibc={:.2}",
            fp / k as f64,
            fp / gp
        );
    }
    grp.bench_function("noop", |b| b.iter(|| black_box(1u8)));
    grp.finish();
}
criterion_group!(benches, bench);
criterion_main!(benches);
