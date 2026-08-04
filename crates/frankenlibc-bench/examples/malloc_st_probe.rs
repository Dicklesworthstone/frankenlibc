//! Standalone SINGLE-THREADED malloc/free probe (no criterion threads -> MULTI_THREADED
//! stays false, so the ST fast paths are live). Measures deployed fl malloc/free vs host
//! glibc (dlmopen), and isolates the fallback-table insert-lock cost.
//!
//! Run: cargo run --release --example malloc_st_probe --features abi-bench
//!
//! HARNESS CONTRACT (fleet campaign 2026-07-25 §2, adopted here):
//!   1. line 1 of stdout is the SHA-256 of *this* binary, hashed by the binary
//!      itself. A hash computed by a shell step next to the run proves nothing
//!      about which ELF actually executed — rch builds into an opaque per-worker
//!      pool target dir, and agents edit crates mid-benchmark in this fleet.
//!   2. `paired()` interleaves both arms inside one round and alternates which
//!      arm goes first every round; the statistic is the MEDIAN of per-round
//!      ratios, not a ratio of medians.
//!   3. every decision ratio is printed next to an A/A null control measured in
//!      the SAME invocation (`paired(fl, fl)`). Gate on the median against that
//!      null, never on `cv` — `cv < 5%` is unreachable on this hardware.
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

/// SHA-256 of the running executable (contract part 1).
fn self_elf_sha256() -> String {
    use sha2::{Digest, Sha256};
    let path = match std::env::current_exe() {
        Ok(p) => p,
        Err(e) => return format!("unavailable: {e}"),
    };
    match std::fs::read(&path) {
        Ok(bytes) => {
            let mut h = Sha256::new();
            h.update(&bytes);
            let digest = h.finalize();
            let mut out = String::with_capacity(64);
            for byte in digest.iter() {
                out.push_str(&format!("{byte:02x}"));
            }
            out
        }
        Err(e) => format!("unavailable: {e}"),
    }
}

/// Outcome of one interleaved paired comparison.
struct Paired {
    p50_a: f64,
    p50_b: f64,
    /// Median of the per-round a/b ratios — the decision statistic.
    ratio_p50: f64,
    /// Dispersion of the ratio series, reported as provenance only.
    cv_pct: f64,
    /// Median absolute deviation of the ratio series.
    mad: f64,
    checksum: u64,
}

impl Paired {
    fn line(&self, tag: &str) -> String {
        format!(
            "{tag} a={:.2} b={:.2} ratio_p50={:.4} cv={:.2}% mad={:.4} ck={:#x}",
            self.p50_a, self.p50_b, self.ratio_p50, self.cv_pct, self.mad, self.checksum
        )
    }
}

/// Time two arms interleaved inside every round, alternating arm order per round.
///
/// Both arms run `iters` operations per round and return a checksum that is folded
/// into the result, so neither can be optimised away. Order alternation is what
/// makes the per-round ratio robust to slow drift (frequency, thermal, a noisy
/// neighbour): both arms see the same drift within a round.
fn paired<A, B>(mut arm_a: A, mut arm_b: B, rounds: usize, iters: u64) -> Paired
where
    A: FnMut(u64) -> u64,
    B: FnMut(u64) -> u64,
{
    // Warm both arms (allocator slow paths, icache, branch predictors).
    let mut checksum = arm_a(iters.min(2000)) ^ arm_b(iters.min(2000));

    let (mut sa, mut sb, mut ratios) = (Vec::new(), Vec::new(), Vec::new());
    for round in 0..rounds {
        let (ta, tb);
        if round % 2 == 0 {
            let t = Instant::now();
            checksum ^= arm_a(iters);
            ta = t.elapsed().as_nanos() as f64 / iters as f64;
            let t = Instant::now();
            checksum ^= arm_b(iters);
            tb = t.elapsed().as_nanos() as f64 / iters as f64;
        } else {
            let t = Instant::now();
            checksum ^= arm_b(iters);
            tb = t.elapsed().as_nanos() as f64 / iters as f64;
            let t = Instant::now();
            checksum ^= arm_a(iters);
            ta = t.elapsed().as_nanos() as f64 / iters as f64;
        }
        sa.push(ta);
        sb.push(tb);
        ratios.push(ta / tb);
    }

    let ratio_p50 = pctl(&ratios, 0.5);
    let mean = ratios.iter().sum::<f64>() / ratios.len() as f64;
    let var = ratios.iter().map(|r| (r - mean).powi(2)).sum::<f64>() / ratios.len() as f64;
    let cv_pct = if mean != 0.0 {
        var.sqrt() / mean * 100.0
    } else {
        f64::NAN
    };
    let devs: Vec<f64> = ratios.iter().map(|r| (r - ratio_p50).abs()).collect();
    Paired {
        p50_a: pctl(&sa, 0.5),
        p50_b: pctl(&sb, 0.5),
        ratio_p50,
        cv_pct,
        mad: pctl(&devs, 0.5),
        checksum,
    }
}

fn main() {
    println!("ELF_SHA256 {}", self_elf_sha256());

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

    // Contract-compliant section: interleaved, order-alternating, A/A-controlled.
    // The A/A arm is fl-vs-fl (identical code, both arms), so it measures exactly
    // the floor this harness can resolve for the fl arm on this host. Any
    // MALLOC_FREE_PAIRED ratio must beat that floor with margin to be a claim.
    for &sz in &[16usize, 64, 256, 1024] {
        let fl_arm = |n: u64| -> u64 {
            let mut ck = 0u64;
            for _ in 0..n {
                unsafe {
                    let p = fl::malloc(sz);
                    ck ^= p as u64;
                    fl::free(std::hint::black_box(p));
                }
            }
            ck
        };
        let glibc_arm = |n: u64| -> u64 {
            let mut ck = 0u64;
            for _ in 0..n {
                unsafe {
                    let p = g_malloc(sz);
                    ck ^= p as u64;
                    g_free(std::hint::black_box(p));
                }
            }
            ck
        };
        let null = paired(fl_arm, fl_arm, 61, 100_000);
        println!("{}", null.line(&format!("MALLOC_FREE_NULL sz={sz}")));
        let dec = paired(fl_arm, glibc_arm, 61, 100_000);
        println!("{}", dec.line(&format!("MALLOC_FREE_PAIRED sz={sz}")));
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
