//! Standalone SINGLE-THREADED malloc/free probe (no criterion threads -> MULTI_THREADED
//! stays false, so the ST fast paths are live). Measures deployed fl malloc/free vs host
//! glibc (dlmopen), and isolates the fallback-table insert-lock cost.
//!
//! Run: cargo run --release --example malloc_st_probe --features abi-bench
use std::time::Instant;

type MallocFn = unsafe extern "C" fn(usize) -> *mut libc::c_void;
type FreeFn = unsafe extern "C" fn(*mut libc::c_void);

fn dl<T: Copy>(h: *mut libc::c_void, n: &[u8]) -> T {
    let p = unsafe { libc::dlsym(h, n.as_ptr().cast()) };
    assert!(!p.is_null(), "dlsym {:?}", std::str::from_utf8(n));
    unsafe { std::mem::transmute_copy::<usize, T>(&(p as usize)) }
}
fn pctl(s: &[f64], q: f64) -> f64 {
    let mut v = s.to_vec();
    v.sort_by(|a, b| a.partial_cmp(b).unwrap());
    v[((q * (v.len() - 1) as f64).round() as usize).min(v.len() - 1)]
}

fn main() {
    let h = unsafe {
        libc::dlmopen(
            libc::LM_ID_NEWLM,
            c"libc.so.6".as_ptr().cast(),
            libc::RTLD_LAZY | libc::RTLD_LOCAL,
        )
    };
    assert!(!h.is_null());
    let g_malloc: MallocFn = dl(h, b"malloc\0");
    let g_free: FreeFn = dl(h, b"free\0");

    use frankenlibc_abi::malloc_abi as fl;

    let it = 100_000u64;
    // malloc+free round-trip (the common churn pattern), various small sizes.
    for &sz in &[16usize, 64, 256, 1024] {
        // warm
        for _ in 0..1000 {
            unsafe {
                let p = fl::malloc(sz);
                fl::free(p);
                let q = g_malloc(sz);
                g_free(q);
            }
        }
        let (mut fs, mut gs) = (Vec::new(), Vec::new());
        for _ in 0..80 {
            let t = Instant::now();
            for _ in 0..it {
                unsafe {
                    let p = fl::malloc(sz);
                    std::hint::black_box(p);
                    fl::free(p);
                }
            }
            fs.push(t.elapsed().as_nanos() as f64 / it as f64);
            let t = Instant::now();
            for _ in 0..it {
                unsafe {
                    let p = g_malloc(sz);
                    std::hint::black_box(p);
                    g_free(p);
                }
            }
            gs.push(t.elapsed().as_nanos() as f64 / it as f64);
        }
        let (fp, gp) = (pctl(&fs, 0.5), pctl(&gs, 0.5));
        println!(
            "MALLOC_FREE sz={sz} fl={fp:.2} glibc={gp:.2} fl/glibc={:.3}",
            fp / gp
        );
    }

    // `free(NULL)` is specified as a no-op, but it is a realistic hot-path shape in
    // cleanup-heavy C code. Call both sides through function pointers so the compiler
    // cannot fold a direct null free away inside this benchmark.
    let fl_free: FreeFn = std::hint::black_box(fl::free as FreeFn);
    let old_fl_free_null: fn() = std::hint::black_box(fl::bench_free_null_old_strict_path);
    let null_ptr: *mut libc::c_void = std::hint::black_box(std::ptr::null_mut());
    for _ in 0..1000 {
        unsafe {
            old_fl_free_null();
            fl_free(null_ptr);
            g_free(null_ptr);
        }
    }
    let (mut old_fs, mut fs, mut gs) = (Vec::new(), Vec::new(), Vec::new());
    let null_it = 1_000_000u64;
    for _ in 0..80 {
        let t = Instant::now();
        for _ in 0..null_it {
            old_fl_free_null();
        }
        old_fs.push(t.elapsed().as_nanos() as f64 / null_it as f64);

        let t = Instant::now();
        for _ in 0..null_it {
            unsafe { fl_free(null_ptr) };
        }
        fs.push(t.elapsed().as_nanos() as f64 / null_it as f64);

        let t = Instant::now();
        for _ in 0..null_it {
            unsafe { g_free(null_ptr) };
        }
        gs.push(t.elapsed().as_nanos() as f64 / null_it as f64);
    }
    let old_fp = pctl(&old_fs, 0.5);
    let (fp, gp) = (pctl(&fs, 0.5), pctl(&gs, 0.5));
    println!("FREE_NULL fl={fp:.2} glibc={gp:.2} fl/glibc={:.3}", fp / gp);
    println!(
        "FREE_NULL_AB old={old_fp:.2} new={fp:.2} new/old={:.3} saves={:.2}ns/call",
        fp / old_fp,
        old_fp - fp
    );
}
