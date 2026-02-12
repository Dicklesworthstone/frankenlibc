//! Deterministic snapshot capture for `glibc-rs-membrane` runtime_math kernels.
//!
//! Output is intended for fixture diffing and sha256 gating:
//! - no timestamps
//! - stable ordering
//! - seed + step count included for reproducibility

use frankenlibc_membrane::{ApiFamily, RuntimeContext, RuntimeMathKernel, SafetyLevel};
use serde::{Deserialize, Serialize};

const FIXTURE_VERSION: &str = "v1";
const SCENARIO_ID: &str = "runtime_math_kernel_snapshot_smoke";

const SCENARIO_FAMILIES: &[ApiFamily] = &[
    ApiFamily::PointerValidation,
    ApiFamily::Allocator,
    ApiFamily::StringMemory,
    ApiFamily::Threading,
    ApiFamily::Socket,
    ApiFamily::Inet,
    ApiFamily::Time,
];

/// Snapshot mode selection for the capture command.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SnapshotMode {
    Strict,
    Hardened,
    Both,
}

impl SnapshotMode {
    #[must_use]
    pub fn from_str_loose(raw: &str) -> Option<Self> {
        match raw.to_ascii_lowercase().as_str() {
            "strict" => Some(Self::Strict),
            "hardened" => Some(Self::Hardened),
            "both" => Some(Self::Both),
            _ => None,
        }
    }
}

/// Deterministic snapshot fixture schema (v1).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct RuntimeKernelSnapshotFixtureV1 {
    pub version: String,
    pub scenario: KernelSnapshotScenarioV1,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub strict: Option<ModeSnapshotV1>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub hardened: Option<ModeSnapshotV1>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct KernelSnapshotScenarioV1 {
    pub id: String,
    pub seed: u64,
    pub steps: u32,
    pub families: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ModeSnapshotV1 {
    pub mode: String,
    pub snapshot_lines: Vec<String>,
}

#[must_use]
pub fn build_kernel_snapshot_fixture(
    seed: u64,
    steps: u32,
    mode: SnapshotMode,
) -> RuntimeKernelSnapshotFixtureV1 {
    let scenario = KernelSnapshotScenarioV1 {
        id: String::from(SCENARIO_ID),
        seed,
        steps,
        families: SCENARIO_FAMILIES
            .iter()
            .map(|family| api_family_name(*family).to_string())
            .collect(),
    };

    let strict = matches!(mode, SnapshotMode::Strict | SnapshotMode::Both)
        .then(|| capture_for_mode(seed, steps, SafetyLevel::Strict));
    let hardened = matches!(mode, SnapshotMode::Hardened | SnapshotMode::Both)
        .then(|| capture_for_mode(seed, steps, SafetyLevel::Hardened));

    RuntimeKernelSnapshotFixtureV1 {
        version: String::from(FIXTURE_VERSION),
        scenario,
        strict,
        hardened,
    }
}

fn capture_for_mode(seed: u64, steps: u32, mode: SafetyLevel) -> ModeSnapshotV1 {
    // NOTE: `RuntimeKernelSnapshot` is intentionally large, and debug rendering may
    // require a larger-than-default stack in `libtest` threads. Capture the fixture
    // on a dedicated thread with an explicit stack size for determinism and safety.
    let snapshot_lines = std::thread::Builder::new()
        .name(format!("kernel-snapshot-{:?}", mode))
        .stack_size(32 * 1024 * 1024)
        .spawn(move || {
            let kernel = RuntimeMathKernel::new();
            run_scenario(&kernel, seed, steps, mode);
            let snap = kernel.snapshot(mode);
            format!("{snap:#?}").lines().map(str::to_string).collect()
        })
        .expect("spawn kernel snapshot capture")
        .join()
        .expect("join kernel snapshot capture");

    ModeSnapshotV1 {
        mode: match mode {
            SafetyLevel::Strict => String::from("strict"),
            SafetyLevel::Hardened => String::from("hardened"),
            SafetyLevel::Off => String::from("off"),
        },
        snapshot_lines,
    }
}

fn run_scenario(kernel: &RuntimeMathKernel, seed: u64, steps: u32, mode: SafetyLevel) {
    let mode_tag = match mode {
        SafetyLevel::Strict => 1u64,
        SafetyLevel::Hardened => 2u64,
        SafetyLevel::Off => 3u64,
    };
    let mut rng = seed ^ mode_tag;

    for i in 0..steps {
        let family = SCENARIO_FAMILIES[(i as usize) % SCENARIO_FAMILIES.len()];
        let r = next_u64(&mut rng);

        let ctx = RuntimeContext {
            family,
            addr_hint: (r as usize) & !0xfff,
            requested_bytes: ((r >> 16) as usize) & 0x3fff,
            is_write: (r & 1) == 0,
            contention_hint: ((r >> 32) as u16) & 0x03ff,
            bloom_negative: (r & 0x10) != 0,
        };

        let _ = kernel.decide(mode, ctx);

        // Deterministically exercise overlap-consistency monitoring.
        if i % 17 == 0 {
            let left = (r as usize) & 0x0f;
            let right = ((r >> 8) as usize) & 0x0f;
            let witness = next_u64(&mut rng);
            let _ = kernel.note_overlap(left, right, witness);
        }
    }
}

fn next_u64(state: &mut u64) -> u64 {
    // PCG-style LCG; deterministic and cheap.
    *state = state
        .wrapping_mul(6364136223846793005)
        .wrapping_add(1442695040888963407);
    *state
}

fn api_family_name(family: ApiFamily) -> &'static str {
    match family {
        ApiFamily::PointerValidation => "pointer_validation",
        ApiFamily::Allocator => "allocator",
        ApiFamily::StringMemory => "string_memory",
        ApiFamily::Stdio => "stdio",
        ApiFamily::Threading => "threading",
        ApiFamily::Resolver => "resolver",
        ApiFamily::MathFenv => "math_fenv",
        ApiFamily::Loader => "loader",
        ApiFamily::Stdlib => "stdlib",
        ApiFamily::Ctype => "ctype",
        ApiFamily::Time => "time",
        ApiFamily::Signal => "signal",
        ApiFamily::IoFd => "io_fd",
        ApiFamily::Socket => "socket",
        ApiFamily::Locale => "locale",
        ApiFamily::Termios => "termios",
        ApiFamily::Inet => "inet",
        ApiFamily::Process => "process",
        ApiFamily::VirtualMemory => "virtual_memory",
        ApiFamily::Poll => "poll",
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fixture_is_stable_for_same_seed_steps() {
        let a = build_kernel_snapshot_fixture(0xDEAD_BEEF, 128, SnapshotMode::Both);
        let b = build_kernel_snapshot_fixture(0xDEAD_BEEF, 128, SnapshotMode::Both);
        assert_eq!(a, b);
    }
}
