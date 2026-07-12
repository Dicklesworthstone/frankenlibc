//! wcswcs A/B: deployed FrankenLibC vs host glibc. ADVERSARIAL input (many partial
//! matches) exposes the old naive O(n*m); the deployed wcsstr delegation is O(n+m).
use criterion::{Criterion, black_box, criterion_group, criterion_main};
use std::ffi::c_void;
use std::sync::OnceLock;
use std::time::Instant;
type Fn_ = unsafe extern "C" fn(*const u32, *const u32) -> *mut u32;
fn host() -> Fn_ {
    static H: OnceLock<usize> = OnceLock::new();
    let a = *H.get_or_init(|| unsafe {
        let h = libc::dlmopen(
            libc::LM_ID_NEWLM,
            b"libc.so.6\0".as_ptr().cast(),
            libc::RTLD_LAZY | libc::RTLD_LOCAL,
        );
        assert!(!h.is_null());
        let mut p = libc::dlsym(h, b"wcswcs\0".as_ptr().cast());
        if p.is_null() {
            p = libc::dlsym(h, b"wcsstr\0".as_ptr().cast());
        }
        assert!(!p.is_null());
        p as usize
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
fn bench(c: &mut Criterion) {
    let g = host();
    let mut grp = c.benchmark_group("wcswcs");
    grp.sample_size(20);
    for &n in &[4096usize, 16384] {
        // adversarial: haystack all 'a' (no NUL until end), needle 'a'*16 + 'b' (absent) → many partial matches.
        let mut hay: Vec<u32> = std::iter::repeat(b'a' as u32).take(n).collect();
        hay.push(0);
        let mut ndl: Vec<u32> = std::iter::repeat(b'a' as u32).take(16).collect();
        ndl.push(b'b' as u32);
        ndl.push(0);
        let (hp, np) = (hay.as_ptr(), ndl.as_ptr());
        let fp = unsafe { frankenlibc_abi::glibc_internal_abi::wcswcs(hp.cast(), np.cast()) };
        let gp = unsafe { g(hp, np) };
        assert_eq!(fp as usize, gp as usize, "wcswcs fl!=glibc n={n}");
        let it = 200u64;
        let (mut fs, mut gs) = (Vec::new(), Vec::new());
        for _ in 0..60 {
            let t = Instant::now();
            for _ in 0..it {
                black_box(unsafe {
                    frankenlibc_abi::glibc_internal_abi::wcswcs(
                        black_box(hp.cast()),
                        black_box(np.cast()),
                    )
                });
            }
            fs.push(t.elapsed().as_nanos() as f64 / it as f64);
            let t = Instant::now();
            for _ in 0..it {
                black_box(unsafe { g(black_box(hp), black_box(np)) });
            }
            gs.push(t.elapsed().as_nanos() as f64 / it as f64);
        }
        let (fp, gp) = (pctl(&fs, 0.5), pctl(&gs, 0.5));
        println!(
            "WCSWCS_ADV n={n} fl_p50={fp:.1}ns glibc_p50={gp:.1}ns ratio_fl_over_glibc={:.2}",
            fp / gp
        );
    }
    grp.bench_function("noop", |b| b.iter(|| black_box(1u8)));
    grp.finish();
}
criterion_group!(benches, bench);
criterion_main!(benches);
