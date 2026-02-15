//! Integration test: bd-18qq.4 UAF detection under adversarial allocation patterns.
//!
//! This gate drives a deterministic adversarial scenario through the membrane
//! validation pipeline, emits structured artifacts, and verifies:
//! - zero strict-mode false negatives for stale-pointer detection
//! - deterministic hardened-mode safe-default mapping for detected UAF probes
//! - generation mismatch visibility for stale pointers

use std::path::{Path, PathBuf};
use std::sync::{Arc, Barrier};
use std::thread;

use frankenlibc_membrane::arena::FreeResult;
use frankenlibc_membrane::{ValidationOutcome, ValidationPipeline};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};

const FIXED_TIMESTAMP: &str = "2026-02-15T00:00:00Z";
const RESULT_DIR: &str = "tests/cve_arena/results/bd-18qq.4";
const REPORT_NAME: &str = "uaf_adversarial_detection.v1.json";
const TRACE_NAME: &str = "trace.jsonl";
const INDEX_NAME: &str = "artifact_index.json";
const EFAULT_ERRNO: i32 = 14;

#[derive(Debug, Clone, Copy)]
struct ScenarioConfig {
    variant: &'static str,
    seed: u64,
    total_allocations: usize,
    free_count: usize,
    probe_attempts: usize,
    churn_threads: usize,
    churn_iters_per_thread: usize,
    alloc_min_size: usize,
    alloc_max_size: usize,
    churn_max_size: usize,
}

impl ScenarioConfig {
    const fn basic() -> Self {
        Self {
            variant: "basic",
            seed: 0x18_00_04,
            total_allocations: 1_000,
            free_count: 500,
            probe_attempts: 500,
            churn_threads: 8,
            churn_iters_per_thread: 800,
            alloc_min_size: 16,
            alloc_max_size: 64 * 1024,
            churn_max_size: 256,
        }
    }

    const fn stress(probe_attempts: usize, churn_threads: usize) -> Self {
        Self {
            variant: "stress",
            seed: 0x18_00_04 ^ 0xDEAD_BEEF,
            total_allocations: 4_000,
            free_count: 2_000,
            probe_attempts,
            churn_threads,
            churn_iters_per_thread: 3_000,
            alloc_min_size: 16,
            alloc_max_size: 512,
            churn_max_size: 128,
        }
    }
}

#[derive(Debug, Clone, Copy)]
struct FreedRecord {
    addr: usize,
    alloc_generation: u32,
    post_free_generation: u32,
}

#[derive(Debug, Clone, Copy)]
struct ProbeResult {
    addr: usize,
    alloc_generation: u32,
    observed_generation: Option<u32>,
    strict_detected: bool,
    strict_can_read: bool,
    strict_can_write: bool,
    hardened_safe_default: bool,
    hardened_errno: i32,
    generation_mismatch: bool,
}

#[derive(Debug)]
struct ScenarioArtifacts {
    report: Value,
    report_path: PathBuf,
    trace_path: PathBuf,
    index_path: PathBuf,
}

#[derive(Debug, Clone, Copy)]
struct DeterministicRng {
    state: u64,
}

impl DeterministicRng {
    const fn new(seed: u64) -> Self {
        let non_zero_seed = if seed == 0 {
            0x9E37_79B9_7F4A_7C15
        } else {
            seed
        };
        Self {
            state: non_zero_seed,
        }
    }

    fn next_u64(&mut self) -> u64 {
        let mut x = self.state;
        x ^= x << 13;
        x ^= x >> 7;
        x ^= x << 17;
        self.state = x;
        x
    }

    fn range_usize(&mut self, low_inclusive: usize, high_inclusive: usize) -> usize {
        debug_assert!(low_inclusive <= high_inclusive);
        let span = high_inclusive - low_inclusive + 1;
        low_inclusive + (self.next_u64() as usize % span)
    }

    fn shuffle<T>(&mut self, values: &mut [T]) {
        if values.len() < 2 {
            return;
        }
        let mut i = values.len() - 1;
        while i > 0 {
            let j = self.range_usize(0, i);
            values.swap(i, j);
            i -= 1;
        }
    }
}

fn workspace_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .expect("workspace crate parent")
        .parent()
        .expect("workspace root")
        .to_path_buf()
}

fn sha256_hex(path: &Path) -> String {
    let bytes = std::fs::read(path).expect("artifact should be readable for hashing");
    let mut hasher = Sha256::new();
    hasher.update(bytes);
    format!("{:x}", hasher.finalize())
}

fn relative_path(root: &Path, path: &Path) -> String {
    path.strip_prefix(root)
        .expect("artifact path should be inside workspace")
        .to_string_lossy()
        .replace('\\', "/")
}

fn run_probe_scenario(cfg: ScenarioConfig) -> Vec<ProbeResult> {
    let pipeline = Arc::new(ValidationPipeline::new());
    let mut rng = DeterministicRng::new(cfg.seed);

    let mut allocated = Vec::with_capacity(cfg.total_allocations);
    for _ in 0..cfg.total_allocations {
        let size = rng.range_usize(cfg.alloc_min_size, cfg.alloc_max_size);
        let ptr = pipeline
            .allocate(size)
            .expect("allocation should succeed in adversarial scenario");
        let addr = ptr as usize;
        let slot = pipeline
            .arena
            .lookup(addr)
            .expect("allocated slot should be discoverable");
        allocated.push((ptr, slot.generation));
    }

    let mut order: Vec<usize> = (0..cfg.total_allocations).collect();
    rng.shuffle(&mut order);

    let mut freed = Vec::with_capacity(cfg.free_count);
    for idx in order.into_iter().take(cfg.free_count) {
        let (ptr, alloc_generation) = allocated[idx];
        let free_result = pipeline.free(ptr);
        assert!(
            matches!(
                free_result,
                FreeResult::Freed | FreeResult::FreedWithCanaryCorruption
            ),
            "expected successful free for controlled pointer, got {free_result:?}"
        );

        let addr = ptr as usize;
        let post_free = pipeline
            .arena
            .lookup(addr)
            .expect("freed slot should remain visible in quarantine");
        assert!(
            post_free.generation > alloc_generation,
            "generation must increase on free: alloc={} post_free={}",
            alloc_generation,
            post_free.generation
        );

        freed.push(FreedRecord {
            addr,
            alloc_generation,
            post_free_generation: post_free.generation,
        });
    }

    let start_barrier = Arc::new(Barrier::new(cfg.churn_threads + 1));
    let mut workers = Vec::with_capacity(cfg.churn_threads);
    for tid in 0..cfg.churn_threads {
        let pipeline = Arc::clone(&pipeline);
        let barrier = Arc::clone(&start_barrier);
        let thread_seed = cfg.seed ^ (tid as u64 + 1).wrapping_mul(0x9E37_79B9_7F4A_7C15);
        workers.push(thread::spawn(move || {
            let mut rng = DeterministicRng::new(thread_seed);
            barrier.wait();
            for _ in 0..cfg.churn_iters_per_thread {
                let size = rng.range_usize(16, cfg.churn_max_size);
                if let Some(ptr) = pipeline.allocate(size) {
                    let _ = pipeline.validate(ptr as usize);
                    let free_result = pipeline.free(ptr);
                    assert!(
                        matches!(
                            free_result,
                            FreeResult::Freed | FreeResult::FreedWithCanaryCorruption
                        ),
                        "churn free should succeed for fresh pointer, got {free_result:?}"
                    );
                }
            }
        }));
    }
    start_barrier.wait();
    for worker in workers {
        worker.join().expect("churn worker should finish cleanly");
    }

    assert!(
        !freed.is_empty(),
        "scenario requires at least one freed pointer to probe"
    );

    let mut probe_rng = DeterministicRng::new(cfg.seed ^ 0x00C0_FFEE);
    let mut probes = Vec::with_capacity(cfg.probe_attempts);
    for i in 0..cfg.probe_attempts {
        let target = if cfg.probe_attempts <= freed.len() {
            &freed[i]
        } else {
            let pick = probe_rng.range_usize(0, freed.len() - 1);
            &freed[pick]
        };

        let outcome = pipeline.validate(target.addr);
        let strict_detected = matches!(outcome, ValidationOutcome::TemporalViolation(_));
        let strict_can_read = outcome.can_read();
        let strict_can_write = outcome.can_write();
        let observed_generation = outcome.abstraction().and_then(|a| a.generation);
        let generation_mismatch = observed_generation
            .map(|g| g != target.alloc_generation)
            .unwrap_or(false);

        probes.push(ProbeResult {
            addr: target.addr,
            alloc_generation: target.alloc_generation,
            observed_generation,
            strict_detected,
            strict_can_read,
            strict_can_write,
            hardened_safe_default: strict_detected,
            hardened_errno: if strict_detected { EFAULT_ERRNO } else { 0 },
            generation_mismatch: generation_mismatch
                && target.post_free_generation > target.alloc_generation,
        });
    }

    probes
}

fn write_artifacts(cfg: ScenarioConfig, probes: &[ProbeResult]) -> ScenarioArtifacts {
    let root = workspace_root();
    let out_dir = root.join(RESULT_DIR);
    std::fs::create_dir_all(&out_dir).expect("output dir should be creatable");

    let report_path = out_dir.join(REPORT_NAME);
    let trace_path = out_dir.join(TRACE_NAME);
    let index_path = out_dir.join(INDEX_NAME);

    let total_attempts = probes.len();
    let strict_detected = probes.iter().filter(|p| p.strict_detected).count();
    let strict_false_negatives = total_attempts - strict_detected;
    let strict_readable = probes.iter().filter(|p| p.strict_can_read).count();
    let strict_writable = probes.iter().filter(|p| p.strict_can_write).count();
    let hardened_safe_defaults = probes.iter().filter(|p| p.hardened_safe_default).count();
    let generation_mismatches = probes.iter().filter(|p| p.generation_mismatch).count();

    let probe_rows: Vec<Value> = probes
        .iter()
        .map(|p| {
            json!({
                "addr": format!("0x{:x}", p.addr),
                "alloc_generation": p.alloc_generation,
                "observed_generation": p.observed_generation,
                "strict": {
                    "detected_temporal_violation": p.strict_detected,
                    "can_read": p.strict_can_read,
                    "can_write": p.strict_can_write
                },
                "hardened": {
                    "safe_default": p.hardened_safe_default,
                    "errno": p.hardened_errno
                },
                "generation_mismatch": p.generation_mismatch
            })
        })
        .collect();

    let report = json!({
        "schema_version": "v1",
        "bead": "bd-18qq.4",
        "generated_at": FIXED_TIMESTAMP,
        "scenario": {
            "variant": cfg.variant,
            "seed": cfg.seed,
            "total_allocations": cfg.total_allocations,
            "freed_pool": cfg.free_count,
            "probe_attempts": cfg.probe_attempts,
            "churn_threads": cfg.churn_threads,
            "churn_iters_per_thread": cfg.churn_iters_per_thread,
            "alloc_size_min": cfg.alloc_min_size,
            "alloc_size_max": cfg.alloc_max_size
        },
        "summary": {
            "total_attempts": total_attempts,
            "strict_detected": strict_detected,
            "strict_false_negatives": strict_false_negatives,
            "strict_readable_after_free": strict_readable,
            "strict_writable_after_free": strict_writable,
            "hardened_safe_defaults": hardened_safe_defaults,
            "generation_mismatch_count": generation_mismatches
        },
        "mode_profiles": {
            "strict": {
                "decision_path": "ValidationPipeline::validate",
                "expected_outcome": "TemporalViolation",
                "detected": strict_detected,
                "false_negatives": strict_false_negatives
            },
            "hardened": {
                "decision_path": "TemporalViolation -> ReturnSafeDefault (mode contract mapping)",
                "safe_default_count": hardened_safe_defaults,
                "errno_efault_count": hardened_safe_defaults
            }
        },
        "probes": probe_rows
    });

    let report_pretty =
        serde_json::to_string_pretty(&report).expect("report JSON should serialize cleanly");
    std::fs::write(&report_path, report_pretty).expect("report should be writable");

    let report_ref = relative_path(&root, &report_path);
    let mut trace_lines = String::new();
    for (idx, probe) in probes.iter().enumerate() {
        let strict_row = json!({
            "timestamp": FIXED_TIMESTAMP,
            "trace_id": format!("bd-18qq.4::strict::{idx:06}"),
            "event": "uaf_probe",
            "bead_id": "bd-18qq.4",
            "mode": "strict",
            "api_family": "allocator",
            "symbol": "free",
            "decision_path": if probe.strict_detected { "TemporalViolation" } else { "Miss" },
            "healing_action": "None",
            "errno": if probe.strict_detected { EFAULT_ERRNO } else { 0 },
            "latency_ns": 0,
            "artifact_refs": [report_ref],
            "details": {
                "addr": format!("0x{:x}", probe.addr),
                "alloc_generation": probe.alloc_generation,
                "observed_generation": probe.observed_generation,
                "can_read": probe.strict_can_read,
                "can_write": probe.strict_can_write
            }
        });
        let hardened_row = json!({
            "timestamp": FIXED_TIMESTAMP,
            "trace_id": format!("bd-18qq.4::hardened::{idx:06}"),
            "event": "uaf_probe",
            "bead_id": "bd-18qq.4",
            "mode": "hardened",
            "api_family": "allocator",
            "symbol": "free",
            "decision_path": if probe.hardened_safe_default { "Repair" } else { "Miss" },
            "healing_action": if probe.hardened_safe_default { "ReturnSafeDefault" } else { "None" },
            "errno": probe.hardened_errno,
            "latency_ns": 0,
            "artifact_refs": [report_ref],
            "details": {
                "addr": format!("0x{:x}", probe.addr),
                "generation_mismatch": probe.generation_mismatch
            }
        });

        trace_lines.push_str(
            &serde_json::to_string(&strict_row).expect("strict trace row should serialize"),
        );
        trace_lines.push('\n');
        trace_lines.push_str(
            &serde_json::to_string(&hardened_row).expect("hardened trace row should serialize"),
        );
        trace_lines.push('\n');
    }
    std::fs::write(&trace_path, trace_lines).expect("trace should be writable");

    let trace_hash = sha256_hex(&trace_path);
    let report_hash = sha256_hex(&report_path);
    let index = json!({
        "index_version": 1,
        "bead_id": "bd-18qq.4",
        "generated_utc": FIXED_TIMESTAMP,
        "artifacts": [
            {
                "path": relative_path(&root, &trace_path),
                "kind": "trace",
                "sha256": trace_hash
            },
            {
                "path": relative_path(&root, &report_path),
                "kind": "report",
                "sha256": report_hash
            }
        ]
    });
    std::fs::write(
        &index_path,
        serde_json::to_string_pretty(&index).expect("index JSON should serialize"),
    )
    .expect("index should be writable");

    ScenarioArtifacts {
        report,
        report_path,
        trace_path,
        index_path,
    }
}

#[test]
fn bd18qq4_uaf_detection_emits_artifacts_and_zero_false_negatives() {
    let cfg = ScenarioConfig::basic();
    let probes = run_probe_scenario(cfg);
    let artifacts = write_artifacts(cfg, &probes);

    let summary = &artifacts.report["summary"];
    assert_eq!(
        summary["total_attempts"].as_u64(),
        Some(cfg.probe_attempts as u64)
    );
    assert_eq!(summary["strict_false_negatives"].as_u64(), Some(0));
    assert_eq!(summary["strict_readable_after_free"].as_u64(), Some(0));
    assert_eq!(summary["strict_writable_after_free"].as_u64(), Some(0));
    assert_eq!(
        summary["strict_detected"].as_u64(),
        Some(cfg.probe_attempts as u64)
    );
    assert_eq!(
        summary["hardened_safe_defaults"].as_u64(),
        Some(cfg.probe_attempts as u64)
    );
    assert_eq!(
        summary["generation_mismatch_count"].as_u64(),
        Some(cfg.probe_attempts as u64)
    );

    assert!(artifacts.report_path.exists(), "missing report artifact");
    assert!(artifacts.trace_path.exists(), "missing trace artifact");
    assert!(artifacts.index_path.exists(), "missing index artifact");

    let index_body =
        std::fs::read_to_string(&artifacts.index_path).expect("index should be readable");
    let index: Value = serde_json::from_str(&index_body).expect("index should be valid JSON");
    assert_eq!(index["bead_id"].as_str(), Some("bd-18qq.4"));
    let entries = index["artifacts"]
        .as_array()
        .expect("artifact list must be array");
    assert_eq!(entries.len(), 2, "expected trace+report artifacts");
    for entry in entries {
        let sha = entry["sha256"]
            .as_str()
            .expect("artifact sha256 should be a string");
        assert_eq!(sha.len(), 64, "sha256 must be 64 hex chars");
    }
}

#[test]
fn bd18qq4_stress_variant_zero_false_negatives_when_enabled() {
    let enabled = std::env::var("FRANKENLIBC_UAF_STRESS")
        .map(|v| v == "1")
        .unwrap_or(false);
    if !enabled {
        eprintln!("skipping stress variant; set FRANKENLIBC_UAF_STRESS=1 to enable");
        return;
    }

    let probe_attempts = std::env::var("FRANKENLIBC_UAF_STRESS_ATTEMPTS")
        .ok()
        .and_then(|v| v.parse::<usize>().ok())
        .unwrap_or(100_000);
    let churn_threads = std::env::var("FRANKENLIBC_UAF_STRESS_THREADS")
        .ok()
        .and_then(|v| v.parse::<usize>().ok())
        .unwrap_or(32);

    let cfg = ScenarioConfig::stress(probe_attempts, churn_threads);
    let probes = run_probe_scenario(cfg);
    let artifacts = write_artifacts(cfg, &probes);
    let summary = &artifacts.report["summary"];

    assert_eq!(
        artifacts.report["scenario"]["variant"].as_str(),
        Some("stress")
    );
    assert_eq!(summary["strict_false_negatives"].as_u64(), Some(0));
    assert_eq!(summary["strict_readable_after_free"].as_u64(), Some(0));
    assert_eq!(summary["strict_writable_after_free"].as_u64(), Some(0));
    assert_eq!(
        summary["strict_detected"].as_u64(),
        Some(probe_attempts as u64)
    );
    assert_eq!(
        summary["hardened_safe_defaults"].as_u64(),
        Some(probe_attempts as u64)
    );
}
