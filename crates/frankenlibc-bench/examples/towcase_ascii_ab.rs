//! ASCII `towupper`/`towlower` survey: FrankenLibC core vs host glibc.

use std::hint::black_box;
use std::time::Instant;

type TowFn = unsafe extern "C" fn(i32) -> i32;

fn pctl(samples: &[f64], q: f64) -> f64 {
    let mut v = samples.to_vec();
    v.sort_by(|a, b| a.partial_cmp(b).unwrap());
    v[((q * (v.len() - 1) as f64).round() as usize).min(v.len() - 1)]
}

fn bench_pair<F, G>(fl: F, glibc: G) -> (f64, f64)
where
    F: Fn(u32) -> u32,
    G: Fn(i32) -> i32,
{
    for wc in 0..128u32 {
        assert_eq!(fl(wc) as i32, glibc(wc as i32), "ASCII mismatch U+{wc:04X}");
    }

    let iters = 100_000u64;
    let mut fl_samples = Vec::new();
    let mut glibc_samples = Vec::new();
    for round in 0..36 {
        let fl_run = || {
            let start = Instant::now();
            for _ in 0..iters {
                for wc in 0..128u32 {
                    black_box(fl(black_box(wc)));
                }
            }
            start.elapsed().as_nanos() as f64 / (iters as f64 * 128.0)
        };
        let glibc_run = || {
            let start = Instant::now();
            for _ in 0..iters {
                for wc in 0..128i32 {
                    black_box(glibc(black_box(wc)));
                }
            }
            start.elapsed().as_nanos() as f64 / (iters as f64 * 128.0)
        };

        if round % 2 == 0 {
            fl_samples.push(fl_run());
            glibc_samples.push(glibc_run());
        } else {
            glibc_samples.push(glibc_run());
            fl_samples.push(fl_run());
        }
    }

    (pctl(&fl_samples, 0.10), pctl(&glibc_samples, 0.10))
}

fn tag(ratio: f64) -> &'static str {
    if ratio > 1.25 {
        "  <-- LOSS"
    } else if ratio < 0.90 {
        "  win"
    } else {
        "  ~par"
    }
}

fn main() {
    let handle = unsafe {
        libc::dlmopen(
            libc::LM_ID_NEWLM,
            b"libc.so.6\0".as_ptr().cast(),
            libc::RTLD_LAZY | libc::RTLD_LOCAL,
        )
    };
    assert!(!handle.is_null(), "dlmopen libc.so.6");
    unsafe {
        let setlocale: unsafe extern "C" fn(i32, *const i8) -> *mut i8 =
            std::mem::transmute(libc::dlsym(handle, b"setlocale\0".as_ptr().cast()));
        let _ = setlocale(libc::LC_ALL, b"C.UTF-8\0".as_ptr().cast());
    }

    let glibc_towupper: TowFn =
        unsafe { std::mem::transmute(libc::dlsym(handle, b"towupper\0".as_ptr().cast())) };
    let glibc_towlower: TowFn =
        unsafe { std::mem::transmute(libc::dlsym(handle, b"towlower\0".as_ptr().cast())) };

    let (fl, glibc) = bench_pair(frankenlibc_core::string::wchar::towupper, |wc| unsafe {
        glibc_towupper(wc)
    });
    println!(
        "towupper_ascii fl={fl:.3}ns glibc={glibc:.3}ns fl/glibc={:.3}{}",
        fl / glibc,
        tag(fl / glibc)
    );

    let (fl, glibc) = bench_pair(frankenlibc_core::string::wchar::towlower, |wc| unsafe {
        glibc_towlower(wc)
    });
    println!(
        "towlower_ascii fl={fl:.3}ns glibc={glibc:.3}ns fl/glibc={:.3}{}",
        fl / glibc,
        tag(fl / glibc)
    );
}
