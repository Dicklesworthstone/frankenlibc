//! In-process fread-fmemopen A/B under thread contention (cc_fl/MagentaCondor,
//! cc-fread-mem-2026-07-11 retry round 2).
//!
//! WHY THIS EXISTS. The parked fread-fmemopen pointer-cursor lever cannot be resolved by
//! `stdio_mt_contention_bench`: that harness spawns N threads, allocates the source Vec,
//! and opens/closes N `fmemopen` streams inside EVERY measured iteration, so spawn +
//! allocator noise dominate. Its 2026-07-22 12-round two-binary A/B FAILED ITS NULL
//! CONTROL (the identical-code fgetc arm "moved" 8.4% at 8 threads, per-arm CVs 33-43%)
//! and 7/12 base runs died in the fl-malloc NULL-return abort (bd-ummyux) triggered by
//! that same churn. This harness follows `stdio_mapper_mt_ab.rs`: threads spawned ONCE,
//! barrier-synced rounds, per-thread timing, source buffers allocated ONCE — the drain
//! workload (fmemopen + 64 freads + fclose) stays intact because stream lifecycle IS the
//! workload the lever targets, but nothing else churns.
//!
//! WHAT IS MEASURED. Per round, each thread performs `K` cycles of: open its OWN
//! `fmemopen(_, N, "r")` stream over a pre-allocated buffer, drain it with `N/CHUNK`
//! calls to `fread(buf, 1, CHUNK, fp)`, close it. Arms:
//!   * `fl`    - the deployed FrankenLibC `fread` path (whatever is linked in this binary;
//!               old-vs-new is compared ACROSS two binaries built with/without the lever,
//!               alternated at the process level by the runner).
//!   * `glibc` - host glibc via `dlmopen(LM_ID_NEWLM)` (immune to symbol interposition),
//!               the within-binary substrate canary: the cross-binary comparator is the
//!               fl/glibc RATIO, which cancels worker drift and code-layout luck.
//!
//! `verify()` runs first: one fl drain and one glibc drain over the same content must
//! agree on every returned byte and every per-call return count — a dead-code arm or a
//! divergent fast path aborts before any timing.
//!
//! Run: `cargo run --release -p frankenlibc-bench --features abi-bench --example stdio_fread_mem_mt_ab`

use std::ffi::{c_char, c_int, c_void};
use std::hint::black_box;
use std::sync::{Barrier, OnceLock};
use std::time::Instant;

use frankenlibc_abi::stdio_abi as fl;

/// Stream size in bytes; matches the parked lever's original bench arm.
const N: usize = 4096;
/// fread element count per call ⇒ N/CHUNK = 64 fread calls per drain.
const CHUNK: usize = 64;
/// Open-drain-close cycles per thread per round (amortizes barrier + timer overhead).
const K: usize = 25;
/// Timed rounds per arm (first `WARMUP` discarded).
const ROUNDS: usize = 60;
const WARMUP: usize = 5;

type FmemopenFn = unsafe extern "C" fn(*mut c_void, usize, *const c_char) -> *mut c_void;
type FreadFn = unsafe extern "C" fn(*mut c_void, usize, usize, *mut c_void) -> usize;
type FcloseFn = unsafe extern "C" fn(*mut c_void) -> c_int;

struct HostStdio {
    fmemopen: FmemopenFn,
    fread: FreadFn,
    fclose: FcloseFn,
}

fn host() -> &'static HostStdio {
    static H: OnceLock<HostStdio> = OnceLock::new();
    H.get_or_init(|| unsafe {
        let h = libc::dlmopen(
            libc::LM_ID_NEWLM,
            c"libc.so.6".as_ptr(),
            libc::RTLD_LAZY | libc::RTLD_LOCAL,
        );
        assert!(!h.is_null(), "dlmopen libc.so.6 failed");
        let sym = |n: &[u8]| {
            let p = libc::dlsym(h, n.as_ptr().cast());
            assert!(!p.is_null(), "dlsym {:?} failed", std::str::from_utf8(n));
            p
        };
        HostStdio {
            fmemopen: std::mem::transmute::<*mut c_void, FmemopenFn>(sym(b"fmemopen\0")),
            fread: std::mem::transmute::<*mut c_void, FreadFn>(sym(b"fread\0")),
            fclose: std::mem::transmute::<*mut c_void, FcloseFn>(sym(b"fclose\0")),
        }
    })
}

/// One full drain cycle on the given arm. Returns total bytes read (must equal N).
fn drain_fl(data: &mut [u8]) -> usize {
    let fp = unsafe { fl::fmemopen(data.as_mut_ptr().cast(), N, c"r".as_ptr()) };
    assert!(!fp.is_null(), "fl fmemopen failed");
    let mut buf = [0u8; CHUNK];
    let mut got = 0usize;
    for _ in 0..(N / CHUNK) {
        // size=1 ⇒ the return value is the byte count for this call.
        got += unsafe { fl::fread(buf.as_mut_ptr().cast(), 1, CHUNK, fp) };
        black_box(&buf);
    }
    unsafe { fl::fclose(fp) };
    got
}

fn drain_glibc(data: &mut [u8], h: &'static HostStdio) -> usize {
    let fp = unsafe { (h.fmemopen)(data.as_mut_ptr().cast(), N, c"r".as_ptr()) };
    assert!(!fp.is_null(), "glibc fmemopen failed");
    let mut buf = [0u8; CHUNK];
    let mut got = 0usize;
    for _ in 0..(N / CHUNK) {
        got += unsafe { (h.fread)(buf.as_mut_ptr().cast(), 1, CHUNK, fp) };
        black_box(&buf);
    }
    unsafe { (h.fclose)(fp) };
    got
}

/// Byte-identity proof before any timing: fl and glibc drains over identical content must
/// return the same bytes with the same per-call counts (incl. a partial tail read).
fn verify(h: &'static HostStdio) {
    let mut data: Vec<u8> = (0..N).map(|i| (i % 251) as u8).collect();
    let fp_f = unsafe { fl::fmemopen(data.as_mut_ptr().cast(), N, c"r".as_ptr()) };
    let fp_g = unsafe { (h.fmemopen)(data.as_mut_ptr().cast(), N, c"r".as_ptr()) };
    assert!(!fp_f.is_null() && !fp_g.is_null());
    let mut bf = [0u8; CHUNK];
    let mut bg = [0u8; CHUNK];
    // Full drain plus one extra call at EOF (ret must be 0 on both).
    for call in 0..=(N / CHUNK) {
        let rf = unsafe { fl::fread(bf.as_mut_ptr().cast(), 1, CHUNK, fp_f) };
        let rg = unsafe { (h.fread)(bg.as_mut_ptr().cast(), 1, CHUNK, fp_g) };
        assert_eq!(rf, rg, "fread return diverged at call {call}");
        assert_eq!(&bf[..rf], &bg[..rg], "fread bytes diverged at call {call}");
    }
    unsafe { fl::fclose(fp_f) };
    unsafe { (h.fclose)(fp_g) };
    println!("verify: OK (fl fread == glibc fread, bytes + counts, incl. EOF call)");
}

fn median(xs: &[f64]) -> f64 {
    let mut v = xs.to_vec();
    v.sort_by(|a, b| a.partial_cmp(b).expect("no NaN timings"));
    let n = v.len();
    if n % 2 == 0 { (v[n / 2 - 1] + v[n / 2]) / 2.0 } else { v[n / 2] }
}

fn cv_pct(xs: &[f64]) -> f64 {
    let m = xs.iter().sum::<f64>() / xs.len() as f64;
    if m == 0.0 {
        return 0.0;
    }
    let var = xs.iter().map(|x| (x - m) * (x - m)).sum::<f64>() / xs.len() as f64;
    100.0 * var.sqrt() / m
}

/// Run one arm at `threads`: workers spawned once, `ROUNDS` barrier-synced rounds, each
/// thread times its own K drains per round. Returns per-round ns/drain, averaged across
/// threads, warmup discarded.
fn run_arm(threads: usize, use_glibc: bool, h: &'static HostStdio) -> Vec<f64> {
    let barrier = Barrier::new(threads);
    let mut per_thread: Vec<Vec<f64>> = Vec::new();

    std::thread::scope(|s| {
        let mut handles = Vec::with_capacity(threads);
        for _ in 0..threads {
            let barrier = &barrier;
            handles.push(s.spawn(move || {
                let mut data = vec![b'x'; N]; // allocated ONCE per thread
                let mut rounds = Vec::with_capacity(ROUNDS);
                let mut got_total = 0usize;
                for _ in 0..ROUNDS {
                    barrier.wait();
                    let start = Instant::now();
                    for _ in 0..K {
                        got_total += if use_glibc {
                            drain_glibc(&mut data, h)
                        } else {
                            drain_fl(&mut data)
                        };
                    }
                    rounds.push(start.elapsed().as_nanos() as f64 / K as f64);
                }
                // Execution proof: every drain returned all N bytes.
                assert_eq!(got_total, N * K * ROUNDS, "short drain detected");
                rounds
            }));
        }
        for hnd in handles {
            per_thread.push(hnd.join().expect("worker panicked"));
        }
    });

    (WARMUP..ROUNDS)
        .map(|r| {
            per_thread.iter().map(|t| t[r]).sum::<f64>() / per_thread.len() as f64
        })
        .collect()
}

fn main() {
    let h = host();
    verify(h);
    let maxt: usize = std::thread::available_parallelism().map(|n| n.get().min(8)).unwrap_or(8);
    for &threads in &[1usize, maxt] {
        // Warm both arms once (first-touch, dlmopen init, allocator warm).
        run_arm(threads, false, h);
        run_arm(threads, true, h);
        let fl_r = run_arm(threads, false, h);
        let gl_r = run_arm(threads, true, h);
        let (fm, gm) = (median(&fl_r), median(&gl_r));
        println!(
            "FREAD_MEM_AB threads={threads} arm=fl ns_drain={fm:.1} cv={:.2}",
            cv_pct(&fl_r)
        );
        println!(
            "FREAD_MEM_AB threads={threads} arm=glibc ns_drain={gm:.1} cv={:.2}",
            cv_pct(&gl_r)
        );
        println!(
            "FREAD_MEM_AB threads={threads} ratio_fl_over_glibc={:.4}",
            fm / gm
        );
    }
}
