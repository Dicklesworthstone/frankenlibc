use std::env;
use std::hint::black_box;
use std::path::PathBuf;
use std::process::Command;
use std::sync::Mutex;
use std::time::Instant;

use frankenlibc_bench::{
    STRICT_HARDENED_OVERHEAD_MODES, StrictHardenedOverheadFamily, StrictHardenedOverheadLane,
    StrictHardenedOverheadMode, StrictHardenedOverheadRecord, mean_latency_ns,
    required_strict_hardened_overhead_families, summarize_latency_samples,
    validate_strict_hardened_overhead_records, write_strict_hardened_overhead_artifacts,
};
use frankenlibc_membrane::config::SafetyLevel;
use frankenlibc_membrane::runtime_math::{
    ApiFamily, RuntimeContext, RuntimeDecisionTelemetrySnapshot, RuntimeMathKernel,
};

fn main() {
    let lane = selected_lane();
    let out_dir = output_dir(lane);
    let artifact_refs = artifact_refs(&out_dir);
    let command = command_label(lane);
    let worker_id = worker_id();
    let cpu_model = cpu_model();
    let source_commit = source_commit();
    let target_dir = target_dir_label();
    let run_context = HarnessRunContext {
        command,
        worker_id,
        cpu_model,
        source_commit,
        target_dir,
        artifact_refs,
    };

    let mut records = Vec::new();
    for mode in STRICT_HARDENED_OVERHEAD_MODES {
        for family in required_strict_hardened_overhead_families(lane) {
            records.push(measure_family(lane, mode, *family, &run_context));
        }
    }

    validate_strict_hardened_overhead_records(&records, lane)
        .expect("strict/hardened overhead harness produced invalid evidence");
    let written = write_strict_hardened_overhead_artifacts(&records, &out_dir)
        .expect("failed to write strict/hardened overhead artifacts");

    println!(
        "STRICT_HARDENED_OVERHEAD_HARNESS lane={} worker={} cpu=\"{}\" records={} artifacts={}",
        lane.as_str(),
        run_context.worker_id,
        run_context.cpu_model,
        records.len(),
        written.join(",")
    );
    for record in &records {
        println!(
            "STRICT_HARDENED_OVERHEAD_RECORD lane={} mode={} family={} symbol={} samples={} p50_ns={:.3} p95_ns={:.3} p99_ns={:.3} mean_ns={:.3} throughput_ops_s={:.3} decisions={} artifact_refs={}",
            record.lane.as_str(),
            record.runtime_mode.as_str(),
            record.api_family.as_str(),
            record.symbol,
            record.sample_count,
            record.p50_ns_op,
            record.p95_ns_op,
            record.p99_ns_op,
            record.mean_ns_op,
            record.throughput_ops_s,
            record.decision_count,
            record.artifact_refs.join(",")
        );
    }
}

struct HarnessRunContext {
    command: String,
    worker_id: String,
    cpu_model: String,
    source_commit: String,
    target_dir: String,
    artifact_refs: Vec<String>,
}

fn selected_lane() -> StrictHardenedOverheadLane {
    let env_lane = env::var("FRANKENLIBC_OVERHEAD_HARNESS_LANE").ok();
    let arg_lane = env::args().find_map(|arg| match arg.as_str() {
        "--full" | "full" => Some(StrictHardenedOverheadLane::Full),
        "--smoke" | "smoke" => Some(StrictHardenedOverheadLane::Smoke),
        _ => None,
    });

    arg_lane.unwrap_or_else(|| {
        env_lane
            .as_deref()
            .map(StrictHardenedOverheadLane::from_str_loose)
            .unwrap_or(StrictHardenedOverheadLane::Smoke)
    })
}

fn measure_family(
    lane: StrictHardenedOverheadLane,
    mode: StrictHardenedOverheadMode,
    family: StrictHardenedOverheadFamily,
    run_context: &HarnessRunContext,
) -> StrictHardenedOverheadRecord {
    let safety_level = safety_level_for_mode(mode);
    let kernel = RuntimeMathKernel::new_for_mode(safety_level);
    let before = kernel.decision_telemetry_snapshot();
    let mut samples = Vec::with_capacity(lane.sample_count());

    for sample_idx in 0..lane.sample_count() {
        let start = Instant::now();
        let mut accumulator = 0usize;
        for iter_idx in 0..lane.inner_iterations() {
            let ctx = runtime_context_for_family(family, sample_idx, iter_idx);
            let decision = kernel.decide(safety_level, ctx);
            accumulator ^= usize::from(decision.requires_full_validation());
            accumulator = accumulator.wrapping_add(representative_workload(family, iter_idx));
        }
        black_box(accumulator);
        let elapsed_ns = start.elapsed().as_nanos();
        let ns_per_op = (elapsed_ns / lane.inner_iterations() as u128).max(1) as u64;
        samples.push(ns_per_op);
    }

    let after = kernel.decision_telemetry_snapshot();
    let (p50_ns_op, p95_ns_op, p99_ns_op, cv_pct) = summarize_latency_samples(&samples);
    let mean_ns_op = mean_latency_ns(&samples);
    let throughput_ops_s = if mean_ns_op <= f64::EPSILON {
        0.0
    } else {
        1_000_000_000.0 / mean_ns_op
    };

    StrictHardenedOverheadRecord {
        trace_id: format!("bd-wpr1n-{}-{}", mode.as_str(), family.as_str()),
        lane,
        runtime_mode: mode,
        api_family: family,
        symbol: String::from(family.symbol()),
        workload: String::from(family.workload()),
        raw_timings_ns: samples,
        sample_count: lane.sample_count(),
        p50_ns_op,
        p95_ns_op,
        p99_ns_op,
        mean_ns_op,
        cv_pct,
        throughput_ops_s,
        command: run_context.command.clone(),
        worker_id: run_context.worker_id.clone(),
        cpu_model: run_context.cpu_model.clone(),
        source_commit: run_context.source_commit.clone(),
        target_dir: run_context.target_dir.clone(),
        artifact_refs: run_context.artifact_refs.clone(),
        decision_count: after.decisions.saturating_sub(before.decisions),
        missing_decision_telemetry: after.missing_decision_telemetry(),
    }
}

fn safety_level_for_mode(mode: StrictHardenedOverheadMode) -> SafetyLevel {
    match mode {
        StrictHardenedOverheadMode::Strict => SafetyLevel::Strict,
        StrictHardenedOverheadMode::Hardened => SafetyLevel::Hardened,
    }
}

fn runtime_context_for_family(
    family: StrictHardenedOverheadFamily,
    sample_idx: usize,
    iter_idx: usize,
) -> RuntimeContext {
    RuntimeContext {
        family: api_family(family),
        addr_hint: 0x1000usize
            .wrapping_add(sample_idx.wrapping_mul(257))
            .wrapping_add(iter_idx.wrapping_mul(17)),
        requested_bytes: requested_bytes(family),
        is_write: is_write_family(family),
        contention_hint: contention_hint(family, iter_idx),
        bloom_negative: false,
    }
}

fn api_family(family: StrictHardenedOverheadFamily) -> ApiFamily {
    match family {
        StrictHardenedOverheadFamily::StringMemory => ApiFamily::StringMemory,
        StrictHardenedOverheadFamily::Allocator => ApiFamily::Allocator,
        StrictHardenedOverheadFamily::StdioBuffer => ApiFamily::Stdio,
        StrictHardenedOverheadFamily::PthreadSync => ApiFamily::Threading,
        StrictHardenedOverheadFamily::Ctype => ApiFamily::Ctype,
        StrictHardenedOverheadFamily::MathFenv => ApiFamily::MathFenv,
        StrictHardenedOverheadFamily::RuntimeMath => ApiFamily::PointerValidation,
    }
}

fn requested_bytes(family: StrictHardenedOverheadFamily) -> usize {
    match family {
        StrictHardenedOverheadFamily::StringMemory => 64,
        StrictHardenedOverheadFamily::Allocator => 128,
        StrictHardenedOverheadFamily::StdioBuffer => 128,
        StrictHardenedOverheadFamily::PthreadSync => 8,
        StrictHardenedOverheadFamily::Ctype => 1,
        StrictHardenedOverheadFamily::MathFenv => 8,
        StrictHardenedOverheadFamily::RuntimeMath => 0,
    }
}

fn is_write_family(family: StrictHardenedOverheadFamily) -> bool {
    matches!(
        family,
        StrictHardenedOverheadFamily::StringMemory
            | StrictHardenedOverheadFamily::Allocator
            | StrictHardenedOverheadFamily::StdioBuffer
            | StrictHardenedOverheadFamily::PthreadSync
    )
}

fn contention_hint(family: StrictHardenedOverheadFamily, iter_idx: usize) -> u16 {
    if matches!(family, StrictHardenedOverheadFamily::PthreadSync) {
        (iter_idx % 8) as u16
    } else {
        0
    }
}

fn representative_workload(family: StrictHardenedOverheadFamily, iter_idx: usize) -> usize {
    match family {
        StrictHardenedOverheadFamily::StringMemory => {
            let src = [iter_idx as u8; 64];
            let mut dst = [0u8; 64];
            dst.copy_from_slice(&src);
            black_box(dst[iter_idx % dst.len()] as usize)
        }
        StrictHardenedOverheadFamily::Allocator => {
            let mut value = Vec::with_capacity(16);
            value.push((iter_idx & 0xff) as u8);
            black_box(value.len() + value.capacity())
        }
        StrictHardenedOverheadFamily::StdioBuffer => {
            let mut buffer = Vec::with_capacity(128);
            buffer.extend_from_slice(b"frankenlibc");
            black_box(buffer.len())
        }
        StrictHardenedOverheadFamily::PthreadSync => {
            let lock = Mutex::new(iter_idx);
            let guard = match lock.lock() {
                Ok(guard) => guard,
                Err(poisoned) => poisoned.into_inner(),
            };
            black_box(*guard)
        }
        StrictHardenedOverheadFamily::Ctype => {
            let byte = b'A' + (iter_idx % 26) as u8;
            black_box(usize::from(byte.is_ascii_alphabetic()))
        }
        StrictHardenedOverheadFamily::MathFenv => {
            let bits = ((iter_idx as f64) + 1.0).sin().to_bits();
            black_box(bits as usize)
        }
        StrictHardenedOverheadFamily::RuntimeMath => black_box(iter_idx.rotate_left(3)),
    }
}

fn output_dir(lane: StrictHardenedOverheadLane) -> PathBuf {
    env::var_os("FRANKENLIBC_OVERHEAD_HARNESS_OUT_DIR")
        .map(PathBuf::from)
        .unwrap_or_else(|| {
            PathBuf::from(target_dir_label())
                .join("conformance")
                .join("bd-wpr1n")
                .join(lane.as_str())
        })
}

fn artifact_refs(out_dir: &std::path::Path) -> Vec<String> {
    [
        "strict_hardened_membrane_overhead.v1.json",
        "strict_hardened_membrane_overhead.v1.jsonl",
        "strict_hardened_membrane_overhead_summary.dat",
    ]
    .into_iter()
    .map(|name| out_dir.join(name).display().to_string())
    .collect()
}

fn command_label(lane: StrictHardenedOverheadLane) -> String {
    env::var("FRANKENLIBC_OVERHEAD_HARNESS_COMMAND").unwrap_or_else(|_| {
        format!(
            "cargo bench -p frankenlibc-bench --bench strict_hardened_overhead_harness -- --{}",
            lane.as_str()
        )
    })
}

fn worker_id() -> String {
    ["RCH_WORKER", "RCH_WORKER_ID", "RCH_HOST", "HOSTNAME"]
        .into_iter()
        .find_map(|key| env::var(key).ok().filter(|value| !value.trim().is_empty()))
        .or_else(|| {
            std::fs::read_to_string("/etc/hostname")
                .ok()
                .map(|value| value.trim().to_owned())
                .filter(|value| !value.is_empty())
        })
        .unwrap_or_else(|| String::from("unknown-worker"))
}

fn cpu_model() -> String {
    std::fs::read_to_string("/proc/cpuinfo")
        .ok()
        .and_then(|cpuinfo| {
            cpuinfo.lines().find_map(|line| {
                line.strip_prefix("model name")
                    .and_then(|rest| {
                        rest.split_once(':')
                            .map(|(_, value)| value.trim().to_owned())
                    })
                    .filter(|value| !value.is_empty())
            })
        })
        .unwrap_or_else(|| format!("unknown-{}", env::consts::ARCH))
}

fn source_commit() -> String {
    env::var("FRANKENLIBC_SOURCE_COMMIT")
        .ok()
        .filter(|value| !value.trim().is_empty())
        .unwrap_or_else(|| {
            Command::new("git")
                .args(["rev-parse", "--short=12", "HEAD"])
                .output()
                .ok()
                .and_then(|output| {
                    if output.status.success() {
                        String::from_utf8(output.stdout).ok()
                    } else {
                        None
                    }
                })
                .map(|value| value.trim().to_owned())
                .filter(|value| !value.is_empty())
                .unwrap_or_else(|| String::from("unknown-source-commit"))
        })
}

fn target_dir_label() -> String {
    env::var("CARGO_TARGET_DIR")
        .ok()
        .filter(|value| !value.trim().is_empty())
        .unwrap_or_else(|| String::from("target"))
}

#[allow(dead_code)]
fn _assert_telemetry_snapshot_is_linked(_: RuntimeDecisionTelemetrySnapshot) {}
