//! wcsdup A/B: deployed FrankenLibC vs host glibc (dup+free). glibc via dlmopen.
use criterion::{Criterion, black_box, criterion_group, criterion_main};
use std::ffi::c_void;
use std::sync::OnceLock;
use std::time::Instant;
type Dup = unsafe extern "C" fn(*const u32) -> *mut u32;
type Free = unsafe extern "C" fn(*mut c_void);
fn hsym(s: &[u8]) -> usize {
    static H: OnceLock<usize> = OnceLock::new();
    let h = *H.get_or_init(|| unsafe {
        let x = libc::dlmopen(
            libc::LM_ID_NEWLM,
            b"libc.so.6\0".as_ptr().cast(),
            libc::RTLD_LAZY | libc::RTLD_LOCAL,
        );
        assert!(!x.is_null());
        x as usize
    });
    unsafe { libc::dlsym(h as *mut c_void, s.as_ptr().cast()) as usize }
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
fn bench(c: &mut Criterion) {
    let gdup: Dup = unsafe { std::mem::transmute(hsym(b"wcsdup\0")) };
    let gfree: Free = unsafe { std::mem::transmute(hsym(b"free\0")) };
    let mut grp = c.benchmark_group("wcsdup");
    grp.sample_size(30);
    for &n in &[8usize, 32] {
        let mut buf: Vec<u32> = std::iter::repeat(b'a' as u32).take(n).collect();
        buf.push(0);
        let p = buf.as_ptr();
        // byte-identity (len)
        let a = unsafe { frankenlibc_abi::wchar_abi::wcsdup(p) };
        assert!(!a.is_null());
        unsafe {
            frankenlibc_abi::malloc_abi::free(a.cast());
        }
        let it = 1000u64;
        let (mut fs, mut gs) = (Vec::new(), Vec::new());
        for _ in 0..100 {
            let t = Instant::now();
            for _ in 0..it {
                let d = unsafe { frankenlibc_abi::wchar_abi::wcsdup(black_box(p)) };
                black_box(d);
                unsafe {
                    frankenlibc_abi::malloc_abi::free(d.cast());
                }
            }
            fs.push(t.elapsed().as_nanos() as f64 / it as f64);
            let t = Instant::now();
            for _ in 0..it {
                let d = unsafe { gdup(black_box(p)) };
                black_box(d);
                unsafe {
                    gfree(d.cast());
                }
            }
            gs.push(t.elapsed().as_nanos() as f64 / it as f64);
        }
        let (fp, gp) = (pctl(&fs, 0.5), pctl(&gs, 0.5));
        println!(
            "WCSDUP n={n} fl_p50={fp:.2}ns glibc_p50={gp:.2}ns ratio_fl_over_glibc={:.2}",
            fp / gp
        );
    }
    grp.bench_function("noop", |b| b.iter(|| black_box(1u8)));
    grp.finish();
}
criterion_group!(benches, bench);
criterion_main!(benches);
