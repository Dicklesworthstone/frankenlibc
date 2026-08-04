#![cfg(target_os = "linux")]
#![allow(unsafe_code)] // host-glibc random/initstate/setstate oracle (libc)

//! Randomized live differential fuzzer for the System V `random()` family vs
//! host glibc.
//!
//! glibc's BSD `random()` is not a single generator: `initstate(seed, buf, n)`
//! selects one of FIVE additive-feedback polynomials by the state-buffer size
//! `n` — TYPE_0 (deg 0, pure LCG) for 8..32, TYPE_1 (deg 7) for 32..64, TYPE_2
//! (deg 15) for 64..128, TYPE_3 (deg 31) for 128..256, TYPE_4 (deg 63) for 256
//! bytes and up. The default `random()` (no initstate) is TYPE_3. This sweeps random
//! seeds across all five size classes and compares the exact output sequence
//! against the host C library.
//!
//! We drive the **core** (pure-safe-Rust) entry points directly rather than the
//! C-ABI wrappers: the ABI layer routes through the frankenlibc membrane
//! allocator, and exercising that allocator alongside the host glibc allocator
//! in one process corrupts the shared heap (a known test-harness coexistence
//! artifact, not a frankenlibc bug — see bd-2g7oyh.212). The core functions use
//! the Rust global allocator (= system malloc), so there is no collision and the
//! generator logic — which is what this test pins — is exercised faithfully.
//!
//! Both libraries keep `random()` state process-global, so the whole sweep is
//! serialized behind a single lock and each library is seeded independently.

use std::ffi::{c_char, c_uint};
use std::sync::{Mutex, MutexGuard};

use frankenlibc_core::stdlib::{initstate as fl_initstate, srandom as fl_srandom, sv_random};

unsafe extern "C" {
    fn random() -> std::ffi::c_long;
    fn srandom(seed: c_uint);
    fn initstate(seed: c_uint, statebuf: *mut c_char, statelen: usize) -> *mut c_char;
}

fn lock() -> MutexGuard<'static, ()> {
    static L: Mutex<()> = Mutex::new(());
    L.lock().unwrap_or_else(|e| e.into_inner())
}

struct Lcg(u64);
impl Lcg {
    fn next(&mut self) -> u64 {
        self.0 = self
            .0
            .wrapping_mul(6364136223846793005)
            .wrapping_add(1442695040888963407);
        self.0
    }
}

#[test]
fn random_initstate_differential_fuzz_vs_glibc() {
    let _g = lock();
    let mut r = Lcg(0x5eed_1234_abcd_0001);
    // One representative size per glibc TYPE class plus boundary values that
    // straddle the 8/32/64/128/256 breakpoints.
    const SIZES: &[usize] = &[8, 16, 31, 32, 48, 63, 64, 96, 127, 128, 192, 255, 256, 512];
    const CALLS: usize = 32;
    let mut divs: Vec<String> = Vec::new();
    let mut compared: u64 = 0;

    // Reusable host buffer (max size) to keep allocation churn low and avoid
    // freeing a buffer the glibc global still points at mid-sweep.
    let mut hostbuf = vec![0u8; *SIZES.iter().max().unwrap()];

    for _ in 0..3000 {
        let seed = (r.next() >> 32) as c_uint;
        for &size in SIZES {
            // ---- host glibc reference sequence ----
            let host_v: Vec<i64> = unsafe {
                initstate(seed, hostbuf.as_mut_ptr() as *mut c_char, size);
                (0..CALLS).map(|_| random() as i64).collect()
            };
            // ---- frankenlibc core sequence ----
            let mut flbuf = vec![0u8; size];
            fl_initstate(seed, &mut flbuf);
            let fl_v: Vec<i64> = (0..CALLS).map(|_| sv_random()).collect();

            compared += 1;
            if fl_v != host_v && divs.len() < 20 {
                let idx = fl_v.iter().zip(&host_v).position(|(a, b)| a != b).unwrap_or(0);
                divs.push(format!(
                    "seed={seed} size={size}: first diff at call {idx}\n    fl   ={:?}\n    glibc={:?}",
                    &fl_v[idx..(idx + 4).min(fl_v.len())],
                    &host_v[idx..(idx + 4).min(host_v.len())],
                ));
            }
        }
    }

    assert!(
        divs.is_empty(),
        "random/initstate diverged from host glibc on {} cases (showing up to 20):\n{}",
        divs.len(),
        divs.join("\n")
    );
    eprintln!("random/initstate fuzz: {compared} comparisons, 0 divergences vs host glibc");
}

#[test]
fn random_default_and_srandom_sequence_vs_glibc() {
    // The default generator (no initstate) and srandom() must both be TYPE_3
    // and match glibc bit-for-bit across random seeds.
    let _g = lock();
    let mut r = Lcg(0x0042_dead_beef_0001);
    const CALLS: usize = 64;
    let mut divs: Vec<String> = Vec::new();
    let mut compared: u64 = 0;

    for _ in 0..5000 {
        let seed = (r.next() >> 32) as c_uint;
        unsafe { srandom(seed) };
        fl_srandom(seed);
        let host_v: Vec<i64> = (0..CALLS).map(|_| unsafe { random() } as i64).collect();
        let fl_v: Vec<i64> = (0..CALLS).map(|_| sv_random()).collect();
        compared += 1;
        if fl_v != host_v && divs.len() < 20 {
            let idx = fl_v.iter().zip(&host_v).position(|(a, b)| a != b).unwrap_or(0);
            divs.push(format!(
                "seed={seed}: first diff at call {idx}\n    fl   ={:?}\n    glibc={:?}",
                &fl_v[idx..(idx + 4).min(fl_v.len())],
                &host_v[idx..(idx + 4).min(host_v.len())],
            ));
        }
    }

    assert!(
        divs.is_empty(),
        "srandom/random diverged from host glibc on {} cases (showing up to 20):\n{}",
        divs.len(),
        divs.join("\n")
    );
    eprintln!("srandom/random default fuzz: {compared} comparisons, 0 divergences vs host glibc");
}
