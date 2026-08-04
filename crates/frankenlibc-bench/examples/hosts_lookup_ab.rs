//! Same-invocation A/A + A/B for the allocation-free `/etc/hosts` scanner.
//!
//! Prior deployed-ABI reruns mixed the scanner with environment, metadata, and
//! file-backed cache work. Their source-identical null arms had real dispersion
//! even with 500 ms blocks. This workload isolates the shipped lever on one
//! immutable in-memory hosts snapshot while rotating hit, multi-hit, case-folded,
//! and miss queries. It reconstructs the old allocating `lookup_hosts` scanner
//! and compares it with the deployed allocation-free `for_each_hosts_match`.
//!
//! The binary prints its own SHA-256 before any oracle or timing output. A
//! source-identical candidate/candidate null is measured in the same invocation.
//! Bootstrap median CIs and the 2x null-half-width rule decide the result; CV is
//! descriptive only.
//!
//! Run: `RCH_REQUIRE_REMOTE=1 RCH_WORKER=<worker> rch exec -- cargo bench -j4 --profile release \
//!       -p frankenlibc-bench --features abi-bench --bench hosts_lookup_ab -- --noplot`

use std::fmt::Write as _;
use std::hint::black_box;
use std::time::Instant;

use frankenlibc_core::resolv::{for_each_hosts_match, lookup_hosts};
use sha2::{Digest, Sha256};

const SAMPLES: usize = 37;
const WARMUP: usize = 4;
const REPS: usize = 50_000;
const BOOTSTRAP_RESAMPLES: usize = 4096;
const FNV_OFFSET: u64 = 0xcbf2_9ce4_8422_2325;
const FNV_PRIME: u64 = 0x0000_0100_0000_01b3;
const QUERIES: [&[u8]; 8] = [
    b"localhost",
    b"cache",
    b"gateway",
    b"API",
    b"database",
    b"edge",
    b"dual",
    b"absent",
];
const HOSTS_FIXTURE: &[u8] = b"\
# deterministic in-memory /etc/hosts snapshot
127.0.0.1 localhost localhost.localdomain
::1 localhost ip6-localhost
10.0.0.1 gateway gw
10.0.0.2 cache cache-a
10.0.0.3 cache cache-b
10.0.0.4 api API.internal
10.0.0.5 database db
10.0.0.6 worker-01
10.0.0.7 worker-02
10.0.0.8 worker-03
192.0.2.10 edge edge-v4
2001:db8::10 edge edge-v6
192.0.2.11 dual
2001:db8::11 dual
198.51.100.12 metrics
198.51.100.13 logs
203.0.113.14 auth
203.0.113.15 queue
203.0.113.16 object-store
203.0.113.17 mail
203.0.113.18 ntp
bad-address ignored-host
192.0.2.19
";

fn median(xs: &[f64]) -> f64 {
    let mut v = xs.to_vec();
    v.sort_by(f64::total_cmp);
    let n = v.len();
    if n % 2 == 0 {
        (v[n / 2 - 1] + v[n / 2]) / 2.0
    } else {
        v[n / 2]
    }
}

fn mean(xs: &[f64]) -> f64 {
    xs.iter().sum::<f64>() / xs.len() as f64
}

fn self_identity() -> String {
    let Ok(path) = std::env::current_exe() else {
        return "unavailable".into();
    };
    let Ok(bytes) = std::fs::read(&path) else {
        return "unavailable".into();
    };
    let mut hasher = Sha256::new();
    hasher.update(&bytes);
    let mut digest_hex = String::with_capacity(64);
    for byte in hasher.finalize() {
        write!(&mut digest_hex, "{byte:02x}").expect("write SHA-256 hex");
    }
    format!("{} ({} bytes) {}", digest_hex, bytes.len(), path.display())
}

fn median_absolute_deviation(xs: &[f64], center: f64) -> f64 {
    median(
        &xs.iter()
            .map(|value| (value - center).abs())
            .collect::<Vec<_>>(),
    )
}

fn bootstrap_median_ci95(xs: &[f64]) -> (f64, f64) {
    let mut state = 0x9e37_79b9_7f4a_7c15u64 ^ xs.len() as u64;
    let mut medians = Vec::with_capacity(BOOTSTRAP_RESAMPLES);
    let mut resample = vec![0.0; xs.len()];
    for _ in 0..BOOTSTRAP_RESAMPLES {
        for value in &mut resample {
            state ^= state << 13;
            state ^= state >> 7;
            state ^= state << 17;
            *value = xs[(state as usize) % xs.len()];
        }
        medians.push(median(&resample));
    }
    medians.sort_by(f64::total_cmp);
    let low = (BOOTSTRAP_RESAMPLES * 25) / 1000;
    let high = ((BOOTSTRAP_RESAMPLES * 975) / 1000).min(BOOTSTRAP_RESAMPLES - 1);
    (medians[low], medians[high])
}

fn cv_pct(xs: &[f64]) -> f64 {
    let m = mean(xs);
    if m == 0.0 {
        return 0.0;
    }
    let var = xs.iter().map(|x| (x - m) * (x - m)).sum::<f64>() / xs.len() as f64;
    100.0 * var.sqrt() / m
}

fn fold_address(mut fingerprint: u64, address: &[u8]) -> u64 {
    for &byte in address {
        fingerprint ^= u64::from(byte);
        fingerprint = fingerprint.wrapping_mul(FNV_PRIME);
    }
    fingerprint ^ 0xff
}

fn scan_orig(content: &[u8], query: &[u8]) -> (usize, u64) {
    let addresses = lookup_hosts(content, query);
    let mut fingerprint = FNV_OFFSET;
    for address in &addresses {
        fingerprint = fold_address(fingerprint, address);
    }
    black_box(&addresses);
    (addresses.len(), fingerprint)
}

fn scan_candidate(content: &[u8], query: &[u8]) -> (usize, u64) {
    let mut count = 0usize;
    let mut fingerprint = FNV_OFFSET;
    for_each_hosts_match(content, query, |address| {
        count += 1;
        fingerprint = fold_address(fingerprint, address);
        false
    });
    (count, fingerprint)
}

#[inline(never)]
fn run_orig() -> u64 {
    let mut accumulator = 0u64;
    for index in 0..REPS {
        let query = black_box(QUERIES[index & (QUERIES.len() - 1)]);
        let (count, fingerprint) = scan_orig(black_box(HOSTS_FIXTURE), query);
        accumulator = accumulator.rotate_left(7) ^ fingerprint ^ count as u64;
    }
    black_box(accumulator)
}

#[inline(never)]
fn run_candidate() -> u64 {
    let mut accumulator = 0u64;
    for index in 0..REPS {
        let query = black_box(QUERIES[index & (QUERIES.len() - 1)]);
        let (count, fingerprint) = scan_candidate(black_box(HOSTS_FIXTURE), query);
        accumulator = accumulator.rotate_left(7) ^ fingerprint ^ count as u64;
    }
    black_box(accumulator)
}

fn verify() {
    for query in QUERIES {
        let expected = lookup_hosts(HOSTS_FIXTURE, query);
        let mut actual = Vec::new();
        for_each_hosts_match(HOSTS_FIXTURE, query, |address| {
            actual.push(address.to_vec());
            false
        });
        assert_eq!(actual, expected, "scanner mismatch for query {query:?}");
        assert_eq!(
            scan_candidate(HOSTS_FIXTURE, query),
            scan_orig(HOSTS_FIXTURE, query),
            "consumed outcome mismatch for query {query:?}"
        );
    }
    assert_eq!(run_candidate(), run_orig(), "batched consumption mismatch");
    println!(
        "verify: OK (allocation-free scanner == allocating lookup_hosts for {} rotating queries)",
        QUERIES.len()
    );
}

fn main() {
    println!("BENCH_ELF_SHA256 {}", self_identity());
    verify();

    let mut orig = Vec::with_capacity(SAMPLES - WARMUP);
    let mut candidate = Vec::with_capacity(SAMPLES - WARMUP);
    let mut null_a = Vec::with_capacity(SAMPLES - WARMUP);
    let mut null_b = Vec::with_capacity(SAMPLES - WARMUP);

    for sample in 0..SAMPLES {
        let (t_null_a, t_null_b) = if sample % 2 == 0 {
            let start = Instant::now();
            black_box(run_candidate());
            let a = start.elapsed();
            let start = Instant::now();
            black_box(run_candidate());
            let b = start.elapsed();
            (a, b)
        } else {
            let start = Instant::now();
            black_box(run_candidate());
            let b = start.elapsed();
            let start = Instant::now();
            black_box(run_candidate());
            let a = start.elapsed();
            (a, b)
        };
        let (t_orig, t_candidate) = if sample % 2 == 0 {
            let start = Instant::now();
            black_box(run_orig());
            let a = start.elapsed();
            let start = Instant::now();
            black_box(run_candidate());
            let b = start.elapsed();
            (a, b)
        } else {
            let start = Instant::now();
            black_box(run_candidate());
            let b = start.elapsed();
            let start = Instant::now();
            black_box(run_orig());
            let a = start.elapsed();
            (a, b)
        };

        if sample >= WARMUP {
            orig.push(t_orig.as_nanos() as f64 / REPS as f64);
            candidate.push(t_candidate.as_nanos() as f64 / REPS as f64);
            null_a.push(t_null_a.as_nanos() as f64 / REPS as f64);
            null_b.push(t_null_b.as_nanos() as f64 / REPS as f64);
        }
    }

    let paired: Vec<f64> = candidate
        .iter()
        .zip(&orig)
        .map(|(candidate_ns, orig_ns)| candidate_ns / orig_ns)
        .collect();
    let null_paired: Vec<f64> = null_b
        .iter()
        .zip(&null_a)
        .map(|(b_ns, a_ns)| b_ns / a_ns)
        .collect();
    let paired_median = median(&paired);
    let null_median = median(&null_paired);
    let (paired_low, paired_high) = bootstrap_median_ci95(&paired);
    let (null_low, null_high) = bootstrap_median_ci95(&null_paired);
    let null_half_width = (1.0 - null_low).abs().max((null_high - 1.0).abs());
    let paired_clears_null = (paired_median - 1.0).abs() > 2.0 * null_half_width;
    let paired_excludes_one = paired_high < 1.0 || paired_low > 1.0;
    let verdict = if paired_clears_null && paired_excludes_one && paired_median < 1.0 {
        "KEEP"
    } else if paired_clears_null && paired_excludes_one {
        "REJECT"
    } else {
        "UNDECIDABLE"
    };

    println!(
        "HOSTS_LOOKUP_IN_MEMORY_AB samples={} reps/arm={REPS} queries={} \
         (immutable snapshot, interleaved, order alternated)",
        orig.len(),
        QUERIES.len()
    );
    println!(
        "  orig(allocating lookup_hosts) median {:8.2} ns/call  mean {:8.2}  cv={:5.2}%",
        median(&orig),
        mean(&orig),
        cv_pct(&orig)
    );
    println!(
        "  candidate(allocation-free)    median {:8.2} ns/call  mean {:8.2}  cv={:5.2}%",
        median(&candidate),
        mean(&candidate),
        cv_pct(&candidate)
    );
    println!(
        "HOSTS_LOOKUP_IN_MEMORY_CONTRACT kind=null_candidate_candidate \
         ratio_median={null_median:.6} ratio_ci95=[{null_low:.6},{null_high:.6}] \
         ratio_cv_pct={:.3} ratio_mad={:.6}",
        cv_pct(&null_paired),
        median_absolute_deviation(&null_paired, null_median),
    );
    println!(
        "HOSTS_LOOKUP_IN_MEMORY_CONTRACT kind=candidate_orig \
         ratio_median={paired_median:.6} ratio_ci95=[{paired_low:.6},{paired_high:.6}] \
         ratio_cv_pct={:.3} ratio_mad={:.6} null_half_width={null_half_width:.6} \
         clears_2x_null={paired_clears_null} verdict={verdict}",
        cv_pct(&paired),
        median_absolute_deviation(&paired, paired_median),
    );
}
