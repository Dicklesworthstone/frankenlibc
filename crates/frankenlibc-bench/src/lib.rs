//! Benchmark support for FrankenLibC.
//!
//! Individual Criterion entrypoints live in `benches/`. This library keeps
//! the benchmark artifact/report plumbing testable from ordinary unit tests.

use std::collections::{BTreeMap, BTreeSet};
use std::fs::{File, create_dir_all};
use std::io::{self, ErrorKind, Write};
use std::path::{Path, PathBuf};
use std::thread;
use std::time::{Duration, Instant};

pub const METADATA_BENCH_SCHEMA_VERSION: &str = "v1";
pub const METADATA_BENCH_BEAD_ID: &str = "bd-3aof.3";
pub const GLIBC_BASELINE_SCHEMA_VERSION: &str = "v1";
pub const GLIBC_BASELINE_BEAD_ID: &str = "bd-bp8fl.8.3";
pub const STRICT_HARDENED_OVERHEAD_SCHEMA_VERSION: &str = "v1";
pub const STRICT_HARDENED_OVERHEAD_BEAD_ID: &str = "bd-wpr1n";
pub const HOST_WIDE_CPU_SAMPLE_INTERVAL: Duration = Duration::from_secs(1);
pub const HOST_WIDE_MAX_BUSY_FRACTION: f64 = 0.20;
pub const HOST_WIDE_REQUIRED_CLEAR_SAMPLES: usize = 5;
pub const HOST_WIDE_QUIET_TIMEOUT: Duration = Duration::from_secs(300);
/// Eight-round order that balances two arms across a drifting shared host.
///
/// `false` denotes arm A first and `true` denotes arm B first. Each arm owns
/// four positions overall and two positions in each half of the square, so a
/// monotonic load change is applied equally to both arms rather than being
/// confounded with a fixed run order.
pub const BALANCED_SQUARE_ABBA: [bool; 8] = [false, true, true, false, false, true, true, false];

/// Return the first-arm reversal for a balanced-square round.
///
/// The sequence repeats deliberately: a measurement may contain more than
/// eight raw samples, but every complete square retains equal arm exposure.
#[must_use]
pub const fn balanced_square_reverse_at(round: usize) -> bool {
    BALANCED_SQUARE_ABBA[round % BALANCED_SQUARE_ABBA.len()]
}
/// Loader flags that make a locally opened FrankenLibC artifact bind its own
/// exported symbols, matching the relevant `LD_PRELOAD` interposition order.
pub const DEPLOYED_PRELOAD_DLOPEN_FLAGS: libc::c_int =
    libc::RTLD_NOW | libc::RTLD_LOCAL | libc::RTLD_DEEPBIND;

#[derive(Clone, Copy, Debug)]
struct HostCpuTicks {
    total: u64,
    idle: u64,
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct HostPlatformProvenance {
    physical_cores: usize,
    logical_threads: usize,
    ram_bytes: u64,
    numa_nodes: usize,
    runtime_isa: String,
    cpufreq_driver: String,
    governor: String,
    energy_performance_preference: String,
}

/// Proof token for the cpuset whose host-wide quiescence is checked before a
/// benchmark proceeds.
///
/// Constructing the token does not claim that a host is quiet. Call
/// [`Self::check_quiet`] immediately before every timed measurement phase. The
/// check fails closed if the process affinity changes, a CPU disappears, or
/// the allowed cpuset does not produce five consecutive one-second samples
/// below the fleet's 20% busy threshold within five minutes.
#[derive(Debug)]
pub struct HostWideBenchmarkGuard {
    hostname: String,
    allowed_cpus: BTreeSet<usize>,
    affinity_mask: String,
    platform: HostPlatformProvenance,
}

/// Auditable evidence from one host-wide quiescence check.
#[derive(Debug)]
pub struct HostWideQuiescenceEvidence {
    hostname: String,
    allowed_cpus: BTreeSet<usize>,
    affinity_mask: String,
    platform: HostPlatformProvenance,
    maximum_observed_busy_fraction: f64,
    samples_observed: usize,
    wait_ms: u64,
}

impl HostWideQuiescenceEvidence {
    /// Render one stable, machine-readable provenance row.
    #[must_use]
    pub fn contract_line(&self, phase: &str) -> String {
        format!(
            "BENCH_HOST_WIDE_EXCLUSIVITY phase={phase} host={} \
             physical_cores={} logical_threads={} ram_bytes={} numa_nodes={} isa={} \
             cpufreq_driver={} governor={} energy_performance_preference={} \
             allowed_cpu_count={} allowed_cpus={} affinity_mask={} sample_ms={} \
             required_consecutive_clear_samples={} samples_observed={} wait_ms={} \
             timeout_ms={} maximum_busy_fraction={:.3} observed_maximum_busy_fraction={:.3} \
             busy_cpu_count_above_limit=0 verdict=clear",
            self.hostname,
            self.platform.physical_cores,
            self.platform.logical_threads,
            self.platform.ram_bytes,
            self.platform.numa_nodes,
            self.platform.runtime_isa,
            self.platform.cpufreq_driver,
            self.platform.governor,
            self.platform.energy_performance_preference,
            self.allowed_cpus.len(),
            format_cpu_list(&self.allowed_cpus),
            self.affinity_mask,
            HOST_WIDE_CPU_SAMPLE_INTERVAL.as_millis(),
            HOST_WIDE_REQUIRED_CLEAR_SAMPLES,
            self.samples_observed,
            self.wait_ms,
            HOST_WIDE_QUIET_TIMEOUT.as_millis(),
            HOST_WIDE_MAX_BUSY_FRACTION,
            self.maximum_observed_busy_fraction,
        )
    }
}

impl HostWideBenchmarkGuard {
    /// Capture the process's allowed cpuset. This is the identity against which
    /// every subsequent quiet-host check is validated.
    pub fn new() -> Result<Self, String> {
        let (allowed_cpus, affinity_mask) = self_cpu_affinity()?;
        let hostname = std::fs::read_to_string("/proc/sys/kernel/hostname")
            .map_err(|error| format!("read host identity: {error}"))?
            .trim()
            .to_owned();
        if hostname.is_empty() {
            return Err("host identity is empty".to_owned());
        }
        let platform = host_platform_provenance(&allowed_cpus)?;
        Ok(Self {
            hostname,
            allowed_cpus,
            affinity_mask,
            platform,
        })
    }

    /// Require the entire allowed cpuset to be quiet before measurement.
    ///
    /// This deliberately mirrors FrankenFS's host-wide harness gate: require
    /// five consecutive one-second `/proc/stat` samples with every allowed CPU
    /// accounted for and no allowed CPU above 20% busy. A contaminated sample
    /// resets the clear streak. Callers must treat `Err` as BLOCKED and exit 2
    /// rather than emitting timing evidence.
    pub fn check_quiet(&self) -> Result<HostWideQuiescenceEvidence, String> {
        let started = Instant::now();
        let mut samples_observed = 0;
        let mut consecutive_clear_samples = 0;
        let mut clear_window_maximum = 0.0_f64;
        let mut last_busy_cpus = Vec::new();

        loop {
            let (current_allowed_cpus, current_affinity_mask) = self_cpu_affinity()?;
            if current_allowed_cpus != self.allowed_cpus
                || current_affinity_mask != self.affinity_mask
            {
                return Err(format!(
                    "process CPU affinity changed: expected cpus={} mask={}, observed cpus={} mask={}",
                    format_cpu_list(&self.allowed_cpus),
                    self.affinity_mask,
                    format_cpu_list(&current_allowed_cpus),
                    current_affinity_mask,
                ));
            }
            let current_platform = host_platform_provenance(&current_allowed_cpus)?;
            if current_platform != self.platform {
                return Err(format!(
                    "host platform policy changed: expected {:?}, observed {:?}",
                    self.platform, current_platform,
                ));
            }

            let before = read_cpu_ticks()?;
            thread::sleep(HOST_WIDE_CPU_SAMPLE_INTERVAL);
            let after = read_cpu_ticks()?;
            let busy = calculate_cpu_busy(&before, &after)?;
            let (sample_maximum, busy_cpus) =
                inspect_host_wide_quiescence(&self.allowed_cpus, &busy)?;
            samples_observed += 1;

            if busy_cpus.is_empty() {
                consecutive_clear_samples += 1;
                clear_window_maximum = clear_window_maximum.max(sample_maximum);
                if consecutive_clear_samples >= HOST_WIDE_REQUIRED_CLEAR_SAMPLES {
                    return Ok(HostWideQuiescenceEvidence {
                        hostname: self.hostname.clone(),
                        allowed_cpus: self.allowed_cpus.clone(),
                        affinity_mask: self.affinity_mask.clone(),
                        platform: self.platform.clone(),
                        maximum_observed_busy_fraction: clear_window_maximum,
                        samples_observed,
                        wait_ms: u64::try_from(started.elapsed().as_millis()).unwrap_or(u64::MAX),
                    });
                }
            } else {
                consecutive_clear_samples = 0;
                clear_window_maximum = 0.0;
                last_busy_cpus = busy_cpus;
            }

            if started.elapsed() >= HOST_WIDE_QUIET_TIMEOUT {
                let last_busy = if last_busy_cpus.is_empty() {
                    "none".to_owned()
                } else {
                    last_busy_cpus.join(",")
                };
                return Err(format!(
                    "host-wide benchmark did not obtain {} consecutive clear samples within {} ms after {} samples; last CPUs above {:.1}% busy: {}",
                    HOST_WIDE_REQUIRED_CLEAR_SAMPLES,
                    HOST_WIDE_QUIET_TIMEOUT.as_millis(),
                    samples_observed,
                    HOST_WIDE_MAX_BUSY_FRACTION * 100.0,
                    last_busy,
                ));
            }
        }
    }
}

fn host_platform_provenance(
    allowed_cpus: &BTreeSet<usize>,
) -> Result<HostPlatformProvenance, String> {
    let (cpufreq_driver, governor, energy_performance_preference) =
        cpu_frequency_policy(allowed_cpus)?;
    Ok(HostPlatformProvenance {
        physical_cores: physical_core_count(allowed_cpus)?,
        logical_threads: allowed_cpus.len(),
        ram_bytes: total_memory_bytes()?,
        numa_nodes: numa_node_count()?,
        runtime_isa: runtime_isa_label(),
        cpufreq_driver,
        governor,
        energy_performance_preference,
    })
}

fn cpu_topology_id(cpu: usize, name: &str) -> Result<usize, String> {
    let path = PathBuf::from(format!("/sys/devices/system/cpu/cpu{cpu}/topology/{name}"));
    std::fs::read_to_string(&path)
        .map_err(|error| format!("read CPU topology {}: {error}", path.display()))?
        .trim()
        .parse::<usize>()
        .map_err(|error| format!("parse CPU topology {}: {error}", path.display()))
}

fn physical_core_count(cpus: &BTreeSet<usize>) -> Result<usize, String> {
    let mut cores = BTreeSet::new();
    for cpu in cpus {
        cores.insert((
            cpu_topology_id(*cpu, "physical_package_id")?,
            cpu_topology_id(*cpu, "core_id")?,
        ));
    }
    if cores.is_empty() {
        return Err("host exposes no physical CPU cores".to_owned());
    }
    Ok(cores.len())
}

fn total_memory_bytes() -> Result<u64, String> {
    let meminfo = std::fs::read_to_string("/proc/meminfo")
        .map_err(|error| format!("read /proc/meminfo: {error}"))?;
    let kib = meminfo
        .lines()
        .find_map(|line| line.strip_prefix("MemTotal:"))
        .and_then(|value| value.split_ascii_whitespace().next())
        .ok_or_else(|| "MemTotal is missing from /proc/meminfo".to_owned())?
        .parse::<u64>()
        .map_err(|error| format!("parse MemTotal KiB: {error}"))?;
    kib.checked_mul(1024)
        .ok_or_else(|| "MemTotal byte count overflow".to_owned())
}

fn numa_node_count() -> Result<usize, String> {
    let online = std::fs::read_to_string("/sys/devices/system/node/online")
        .map_err(|error| format!("read online NUMA node list: {error}"))?;
    Ok(parse_cpu_list(&online)?.len())
}

fn runtime_isa_label() -> String {
    let mut features = vec![std::env::consts::ARCH];
    #[cfg(target_arch = "x86_64")]
    {
        for (name, present) in [
            ("sse4.2", std::arch::is_x86_feature_detected!("sse4.2")),
            ("avx", std::arch::is_x86_feature_detected!("avx")),
            ("avx2", std::arch::is_x86_feature_detected!("avx2")),
            ("avx512f", std::arch::is_x86_feature_detected!("avx512f")),
            ("fma", std::arch::is_x86_feature_detected!("fma")),
            ("bmi1", std::arch::is_x86_feature_detected!("bmi1")),
            ("bmi2", std::arch::is_x86_feature_detected!("bmi2")),
        ] {
            if present {
                features.push(name);
            }
        }
    }
    features.join("+")
}

fn read_optional_trimmed(path: &Path) -> Result<Option<String>, String> {
    match std::fs::read_to_string(path) {
        Ok(value) => {
            let value = value.trim();
            if value.is_empty() {
                Err(format!("CPU policy attribute {} is empty", path.display()))
            } else {
                Ok(Some(value.to_owned()))
            }
        }
        Err(error) if error.kind() == ErrorKind::NotFound => Ok(None),
        Err(error) => Err(format!(
            "read CPU policy attribute {}: {error}",
            path.display()
        )),
    }
}

fn summarize_cpu_attribute(
    name: &str,
    values: &[(usize, Option<String>)],
) -> Result<String, String> {
    let present = values
        .iter()
        .filter_map(|(_, value)| value.as_deref())
        .collect::<BTreeSet<_>>();
    if present.is_empty() {
        return Ok("unavailable".to_owned());
    }
    let missing = values
        .iter()
        .filter_map(|(cpu, value)| value.is_none().then_some(*cpu))
        .collect::<Vec<_>>();
    if !missing.is_empty() {
        return Err(format!(
            "{name} is visible on only part of the allowed cpuset; missing CPUs: {}",
            missing
                .iter()
                .map(usize::to_string)
                .collect::<Vec<_>>()
                .join(":"),
        ));
    }
    if present.len() != 1 {
        return Err(format!(
            "allowed CPUs expose heterogeneous {name} values: {}",
            present.into_iter().collect::<Vec<_>>().join(":"),
        ));
    }
    Ok(present
        .into_iter()
        .next()
        .expect("one CPU policy value")
        .to_owned())
}

fn cpu_frequency_policy(
    allowed_cpus: &BTreeSet<usize>,
) -> Result<(String, String, String), String> {
    let mut drivers = Vec::with_capacity(allowed_cpus.len());
    let mut governors = Vec::with_capacity(allowed_cpus.len());
    let mut preferences = Vec::with_capacity(allowed_cpus.len());
    for cpu in allowed_cpus {
        let root = PathBuf::from(format!("/sys/devices/system/cpu/cpu{cpu}/cpufreq"));
        drivers.push((*cpu, read_optional_trimmed(&root.join("scaling_driver"))?));
        governors.push((*cpu, read_optional_trimmed(&root.join("scaling_governor"))?));
        preferences.push((
            *cpu,
            read_optional_trimmed(&root.join("energy_performance_preference"))?,
        ));
    }
    Ok((
        summarize_cpu_attribute("cpufreq driver", &drivers)?,
        summarize_cpu_attribute("scaling governor", &governors)?,
        summarize_cpu_attribute("energy-performance preference", &preferences)?,
    ))
}

fn parse_cpu_list(value: &str) -> Result<BTreeSet<usize>, String> {
    let mut cpus = BTreeSet::new();
    for range in value.trim().split(',').filter(|part| !part.is_empty()) {
        if let Some((start, end)) = range.split_once('-') {
            let start = start
                .parse::<usize>()
                .map_err(|error| format!("parse CPU range start {start:?}: {error}"))?;
            let end = end
                .parse::<usize>()
                .map_err(|error| format!("parse CPU range end {end:?}: {error}"))?;
            if start > end {
                return Err(format!("descending CPU range {range:?}"));
            }
            cpus.extend(start..=end);
        } else {
            cpus.insert(
                range
                    .parse::<usize>()
                    .map_err(|error| format!("parse CPU index {range:?}: {error}"))?,
            );
        }
    }
    if cpus.is_empty() {
        return Err("CPU list is empty".to_owned());
    }
    Ok(cpus)
}

fn format_cpu_list(cpus: &BTreeSet<usize>) -> String {
    cpus.iter()
        .map(usize::to_string)
        .collect::<Vec<_>>()
        .join(":")
}

fn self_cpu_affinity() -> Result<(BTreeSet<usize>, String), String> {
    let status = std::fs::read_to_string("/proc/self/status")
        .map_err(|error| format!("read /proc/self/status: {error}"))?;
    let allowed_list = status
        .lines()
        .find_map(|line| {
            let (key, value) = line.split_once(':')?;
            (key.trim() == "Cpus_allowed_list").then(|| value.trim())
        })
        .ok_or_else(|| "Cpus_allowed_list missing from /proc/self/status".to_owned())?;
    let affinity_mask = status
        .lines()
        .find_map(|line| {
            let (key, value) = line.split_once(':')?;
            (key.trim() == "Cpus_allowed").then(|| value.trim().to_owned())
        })
        .ok_or_else(|| "Cpus_allowed missing from /proc/self/status".to_owned())?;
    Ok((parse_cpu_list(allowed_list)?, affinity_mask))
}

fn parse_cpu_ticks(stat: &str) -> Result<BTreeMap<usize, HostCpuTicks>, String> {
    let mut cpus = BTreeMap::new();
    for line in stat.lines() {
        let mut fields = line.split_ascii_whitespace();
        let Some(label) = fields.next() else {
            continue;
        };
        let Some(suffix) = label.strip_prefix("cpu") else {
            continue;
        };
        if suffix.is_empty() || !suffix.bytes().all(|byte| byte.is_ascii_digit()) {
            continue;
        }
        let cpu = suffix
            .parse::<usize>()
            .map_err(|error| format!("parse CPU index {suffix:?}: {error}"))?;
        let ticks = fields
            .map(|value| {
                value.parse::<u64>().map_err(|error| {
                    format!("parse /proc/stat ticks for cpu{cpu} value {value:?}: {error}")
                })
            })
            .collect::<Result<Vec<_>, _>>()?;
        if ticks.len() < 5 {
            return Err(format!("cpu{cpu} /proc/stat row is too short"));
        }
        let total = ticks.iter().try_fold(0_u64, |sum, value| {
            sum.checked_add(*value)
                .ok_or_else(|| format!("cpu{cpu} total tick count overflow"))
        })?;
        let idle = ticks[3]
            .checked_add(ticks[4])
            .ok_or_else(|| format!("cpu{cpu} idle tick count overflow"))?;
        cpus.insert(cpu, HostCpuTicks { total, idle });
    }
    if cpus.is_empty() {
        return Err("no per-CPU rows in /proc/stat".to_owned());
    }
    Ok(cpus)
}

fn read_cpu_ticks() -> Result<BTreeMap<usize, HostCpuTicks>, String> {
    let stat = std::fs::read_to_string("/proc/stat")
        .map_err(|error| format!("read /proc/stat: {error}"))?;
    parse_cpu_ticks(&stat)
}

fn calculate_cpu_busy(
    before: &BTreeMap<usize, HostCpuTicks>,
    after: &BTreeMap<usize, HostCpuTicks>,
) -> Result<BTreeMap<usize, f64>, String> {
    let mut busy = BTreeMap::new();
    for (cpu, start) in before {
        let end = after
            .get(cpu)
            .ok_or_else(|| format!("cpu{cpu} disappeared during load sample"))?;
        let total = end
            .total
            .checked_sub(start.total)
            .ok_or_else(|| format!("cpu{cpu} total ticks moved backwards"))?;
        let idle = end
            .idle
            .checked_sub(start.idle)
            .ok_or_else(|| format!("cpu{cpu} idle ticks moved backwards"))?;
        let fraction = if total == 0 {
            1.0
        } else {
            total
                .checked_sub(idle)
                .ok_or_else(|| format!("cpu{cpu} idle delta exceeds total delta"))?
                as f64
                / total as f64
        };
        busy.insert(*cpu, fraction);
    }
    Ok(busy)
}

#[cfg(test)]
fn validate_host_wide_quiescence(
    allowed_cpus: &BTreeSet<usize>,
    busy: &BTreeMap<usize, f64>,
) -> Result<f64, String> {
    let (maximum, busy_cpus) = inspect_host_wide_quiescence(allowed_cpus, busy)?;
    if !busy_cpus.is_empty() {
        return Err(format!(
            "host-wide benchmark requires an exclusive quiet cpuset; CPUs above {:.1}% busy: {}",
            HOST_WIDE_MAX_BUSY_FRACTION * 100.0,
            busy_cpus.join(","),
        ));
    }
    Ok(maximum)
}

fn inspect_host_wide_quiescence(
    allowed_cpus: &BTreeSet<usize>,
    busy: &BTreeMap<usize, f64>,
) -> Result<(f64, Vec<String>), String> {
    let mut maximum = 0.0_f64;
    let mut busy_cpus = Vec::new();
    for cpu in allowed_cpus {
        let fraction = busy
            .get(cpu)
            .copied()
            .ok_or_else(|| format!("allowed cpu{cpu} was not sampled"))?;
        if !fraction.is_finite() || !(0.0..=1.0).contains(&fraction) {
            return Err(format!(
                "cpu{cpu} produced invalid busy fraction {fraction}"
            ));
        }
        maximum = maximum.max(fraction);
        if fraction > HOST_WIDE_MAX_BUSY_FRACTION {
            busy_cpus.push(format!("cpu{cpu}={:.1}%", fraction * 100.0));
        }
    }
    Ok((maximum, busy_cpus))
}

/// Concrete implementation under comparison for metadata-read benchmarks.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum MetadataImplementation {
    Rcu,
    Mutex,
}

impl MetadataImplementation {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Rcu => "rcu",
            Self::Mutex => "mutex",
        }
    }
}

/// Metadata workload family exercised by the RCU-vs-mutex benchmark matrix.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum MetadataOperation {
    ThreadMetadata,
    SizeClassLookup,
    TlsCacheLookup,
}

impl MetadataOperation {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::ThreadMetadata => "thread_metadata",
            Self::SizeClassLookup => "size_class_lookup",
            Self::TlsCacheLookup => "tls_cache_lookup",
        }
    }
}

/// One measured configuration from the metadata benchmark matrix.
#[derive(Debug, Clone)]
pub struct MetadataBenchRecord {
    pub implementation: MetadataImplementation,
    pub operation: MetadataOperation,
    pub read_ratio_pct: u8,
    pub thread_count: usize,
    pub total_ops: u64,
    pub read_ops: u64,
    pub write_ops: u64,
    pub throughput_ops_s: f64,
    pub p50_ns_op: f64,
    pub p95_ns_op: f64,
    pub p99_ns_op: f64,
    pub cv_pct: f64,
    pub sample_count: usize,
}

/// Break-even point for one operation/thread-count slice.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MetadataBreakEven {
    pub operation: MetadataOperation,
    pub thread_count: usize,
    pub break_even_read_ratio_pct: Option<u8>,
}

/// Percentile helper for a sorted sample set.
#[must_use]
pub fn percentile_sorted(samples: &[u64], percentile: f64) -> f64 {
    debug_assert!((0.0..=1.0).contains(&percentile));
    if samples.is_empty() {
        return 0.0;
    }
    let idx = ((samples.len() - 1) as f64 * percentile).round() as usize;
    samples[idx.min(samples.len() - 1)] as f64
}

/// Coefficient of variation in percent for the provided samples.
#[must_use]
pub fn coefficient_of_variation_pct(samples: &[u64]) -> f64 {
    if samples.len() <= 1 {
        return 0.0;
    }
    let mean = samples.iter().map(|&value| value as f64).sum::<f64>() / samples.len() as f64;
    if mean <= f64::EPSILON {
        return 0.0;
    }
    let variance = samples
        .iter()
        .map(|&value| {
            let delta = value as f64 - mean;
            delta * delta
        })
        .sum::<f64>()
        / samples.len() as f64;
    variance.sqrt() / mean * 100.0
}

/// Summarize latency samples into p50/p95/p99/CV.
#[must_use]
pub fn summarize_latency_samples(samples: &[u64]) -> (f64, f64, f64, f64) {
    if samples.is_empty() {
        return (0.0, 0.0, 0.0, 0.0);
    }

    let mut sorted = samples.to_vec();
    sorted.sort_unstable();
    (
        percentile_sorted(&sorted, 0.50),
        percentile_sorted(&sorted, 0.95),
        percentile_sorted(&sorted, 0.99),
        coefficient_of_variation_pct(&sorted),
    )
}

/// Build the read-ratio threshold where RCU first beats mutex throughput.
#[must_use]
pub fn build_break_even_summary(records: &[MetadataBenchRecord]) -> Vec<MetadataBreakEven> {
    let mut grouped =
        BTreeMap::<(MetadataOperation, usize), BTreeMap<u8, (Option<f64>, Option<f64>)>>::new();

    for record in records {
        let entry = grouped
            .entry((record.operation, record.thread_count))
            .or_default()
            .entry(record.read_ratio_pct)
            .or_default();

        match record.implementation {
            MetadataImplementation::Rcu => entry.0 = Some(record.throughput_ops_s),
            MetadataImplementation::Mutex => entry.1 = Some(record.throughput_ops_s),
        }
    }

    grouped
        .into_iter()
        .map(|((operation, thread_count), ratios)| {
            let break_even_read_ratio_pct =
                ratios
                    .into_iter()
                    .find_map(|(read_ratio_pct, pair)| match pair {
                        (Some(rcu), Some(mutex)) if rcu >= mutex => Some(read_ratio_pct),
                        _ => None,
                    });

            MetadataBreakEven {
                operation,
                thread_count,
                break_even_read_ratio_pct,
            }
        })
        .collect()
}

#[must_use]
pub fn metadata_bench_json(
    records: &[MetadataBenchRecord],
    break_even: &[MetadataBreakEven],
) -> String {
    let mut body = format!(
        "{{\n  \"schema_version\": \"{}\",\n  \"bead_id\": \"{}\",\n  \"record_count\": {},\n  \"break_even_count\": {},\n  \"records\": [\n",
        METADATA_BENCH_SCHEMA_VERSION,
        METADATA_BENCH_BEAD_ID,
        records.len(),
        break_even.len()
    );
    for (idx, record) in records.iter().enumerate() {
        let comma = if idx + 1 == records.len() { "" } else { "," };
        body.push_str(&format!(
            "    {{\"implementation\":\"{}\",\"operation\":\"{}\",\"read_ratio_pct\":{},\"thread_count\":{},\"total_ops\":{},\"read_ops\":{},\"write_ops\":{},\"throughput_ops_s\":{:.3},\"p50_ns_op\":{:.3},\"p95_ns_op\":{:.3},\"p99_ns_op\":{:.3},\"cv_pct\":{:.3},\"sample_count\":{}}}{}\n",
            record.implementation.as_str(),
            record.operation.as_str(),
            record.read_ratio_pct,
            record.thread_count,
            record.total_ops,
            record.read_ops,
            record.write_ops,
            record.throughput_ops_s,
            record.p50_ns_op,
            record.p95_ns_op,
            record.p99_ns_op,
            record.cv_pct,
            record.sample_count,
            comma
        ));
    }
    body.push_str("  ],\n  \"break_even\": [\n");
    for (idx, summary) in break_even.iter().enumerate() {
        let comma = if idx + 1 == break_even.len() { "" } else { "," };
        let threshold = summary
            .break_even_read_ratio_pct
            .map_or(String::from("null"), |value| value.to_string());
        body.push_str(&format!(
            "    {{\"operation\":\"{}\",\"thread_count\":{},\"break_even_read_ratio_pct\":{}}}{}\n",
            summary.operation.as_str(),
            summary.thread_count,
            threshold,
            comma
        ));
    }
    body.push_str("  ]\n}\n");
    body
}

#[must_use]
pub fn throughput_dat(records: &[MetadataBenchRecord]) -> String {
    let mut body =
        String::from("# impl operation read_ratio_pct thread_count throughput_ops_s total_ops\n");
    for record in records {
        body.push_str(&format!(
            "{} {} {} {} {:.3} {}\n",
            record.implementation.as_str(),
            record.operation.as_str(),
            record.read_ratio_pct,
            record.thread_count,
            record.throughput_ops_s,
            record.total_ops
        ));
    }
    body
}

#[must_use]
pub fn latency_dat(records: &[MetadataBenchRecord]) -> String {
    let mut body = String::from(
        "# impl operation read_ratio_pct thread_count p50_ns p95_ns p99_ns cv_pct sample_count\n",
    );
    for record in records {
        body.push_str(&format!(
            "{} {} {} {} {:.3} {:.3} {:.3} {:.3} {}\n",
            record.implementation.as_str(),
            record.operation.as_str(),
            record.read_ratio_pct,
            record.thread_count,
            record.p50_ns_op,
            record.p95_ns_op,
            record.p99_ns_op,
            record.cv_pct,
            record.sample_count
        ));
    }
    body
}

#[must_use]
pub fn break_even_dat(summary: &[MetadataBreakEven]) -> String {
    let mut body = String::from("# operation thread_count break_even_read_ratio_pct\n");
    for record in summary {
        let threshold = record.break_even_read_ratio_pct.unwrap_or(0);
        body.push_str(&format!(
            "{} {} {}\n",
            record.operation.as_str(),
            record.thread_count,
            threshold
        ));
    }
    body
}

fn svg_shell(title: &str, subtitle: &str, rows: &[String]) -> String {
    let height = 140 + rows.len().saturating_mul(22);
    let mut body = format!(
        "<svg xmlns=\"http://www.w3.org/2000/svg\" width=\"1280\" height=\"{height}\" viewBox=\"0 0 1280 {height}\">\n\
<rect width=\"1280\" height=\"{height}\" fill=\"#f8fafc\"/>\n\
<text x=\"32\" y=\"40\" font-family=\"monospace\" font-size=\"26\" fill=\"#0f172a\">{title}</text>\n\
<text x=\"32\" y=\"68\" font-family=\"monospace\" font-size=\"14\" fill=\"#334155\">{subtitle}</text>\n"
    );

    for (idx, row) in rows.iter().enumerate() {
        let y = 102 + idx * 22;
        body.push_str(&format!(
            "<text x=\"32\" y=\"{y}\" font-family=\"monospace\" font-size=\"13\" fill=\"#1e293b\">{row}</text>\n"
        ));
    }
    body.push_str("</svg>\n");
    body
}

#[must_use]
pub fn throughput_svg(records: &[MetadataBenchRecord]) -> String {
    let rows = records
        .iter()
        .map(|record| {
            format!(
                "{} {} ratio={} threads={} ops/s={:.3}",
                record.implementation.as_str(),
                record.operation.as_str(),
                record.read_ratio_pct,
                record.thread_count,
                record.throughput_ops_s
            )
        })
        .collect::<Vec<_>>();
    svg_shell(
        "RCU vs Mutex Metadata Throughput",
        "One row per implementation/operation/read-ratio/thread-count sample.",
        &rows,
    )
}

#[must_use]
pub fn latency_svg(records: &[MetadataBenchRecord]) -> String {
    let rows = records
        .iter()
        .map(|record| {
            format!(
                "{} {} ratio={} threads={} p50={:.3}ns p95={:.3}ns p99={:.3}ns cv={:.3}%",
                record.implementation.as_str(),
                record.operation.as_str(),
                record.read_ratio_pct,
                record.thread_count,
                record.p50_ns_op,
                record.p95_ns_op,
                record.p99_ns_op,
                record.cv_pct
            )
        })
        .collect::<Vec<_>>();
    svg_shell(
        "RCU vs Mutex Metadata Latency Percentiles",
        "Per-configuration latency summary used by the artifact gate.",
        &rows,
    )
}

#[must_use]
pub fn break_even_svg(summary: &[MetadataBreakEven]) -> String {
    let rows = summary
        .iter()
        .map(|record| {
            format!(
                "{} threads={} break_even_read_ratio={}",
                record.operation.as_str(),
                record.thread_count,
                record
                    .break_even_read_ratio_pct
                    .map_or(String::from("none"), |ratio| format!("{ratio}%"))
            )
        })
        .collect::<Vec<_>>();
    svg_shell(
        "RCU Break-even Read Ratio by Thread Count",
        "Lowest read ratio where RCU throughput meets or beats mutex throughput.",
        &rows,
    )
}

#[must_use]
pub fn throughput_gnuplot_script() -> &'static str {
    r#"set terminal svg size 1280,720 dynamic enhanced
set output "throughput_vs_threads.svg"
set title "RCU vs Mutex Metadata Throughput"
set xlabel "Threads"
set ylabel "Ops/s"
set key left top
set grid
plot "throughput_vs_threads.dat" using 4:5 with linespoints title "all configurations"
"#
}

#[must_use]
pub fn latency_gnuplot_script() -> &'static str {
    r#"set terminal svg size 1280,720 dynamic enhanced
set output "latency_percentiles.svg"
set title "RCU vs Mutex Metadata Latency Percentiles"
set xlabel "Threads"
set ylabel "ns/op"
set key left top
set grid
plot \
  "latency_percentiles.dat" using 4:5 with linespoints title "p50", \
  "latency_percentiles.dat" using 4:6 with linespoints title "p95", \
  "latency_percentiles.dat" using 4:7 with linespoints title "p99"
"#
}

#[must_use]
pub fn break_even_gnuplot_script() -> &'static str {
    r#"set terminal svg size 1280,720 dynamic enhanced
set output "break_even_ratio.svg"
set title "RCU Break-even Read Ratio by Thread Count"
set xlabel "Threads"
set ylabel "Read ratio (%)"
set yrange [0:100]
set key left top
set grid
plot "break_even.dat" using 2:3 with linespoints title "break-even read ratio"
"#
}

/// Write the full metadata benchmark artifact bundle into `out_dir`.
pub fn write_metadata_bench_artifacts(
    records: &[MetadataBenchRecord],
    out_dir: &Path,
) -> io::Result<Vec<MetadataBreakEven>> {
    create_dir_all(out_dir)?;
    let break_even = build_break_even_summary(records);

    write_file(
        &out_dir.join("metadata_benchmark_report.v1.json"),
        &metadata_bench_json(records, &break_even),
    )?;
    write_file(
        &out_dir.join("throughput_vs_threads.dat"),
        &throughput_dat(records),
    )?;
    write_file(
        &out_dir.join("latency_percentiles.dat"),
        &latency_dat(records),
    )?;
    write_file(
        &out_dir.join("break_even.dat"),
        &break_even_dat(&break_even),
    )?;
    write_file(
        &out_dir.join("throughput_vs_threads.gp"),
        throughput_gnuplot_script(),
    )?;
    write_file(
        &out_dir.join("latency_percentiles.gp"),
        latency_gnuplot_script(),
    )?;
    write_file(&out_dir.join("break_even.gp"), break_even_gnuplot_script())?;
    write_file(
        &out_dir.join("throughput_vs_threads.svg"),
        &throughput_svg(records),
    )?;
    write_file(
        &out_dir.join("latency_percentiles.svg"),
        &latency_svg(records),
    )?;
    write_file(
        &out_dir.join("break_even_ratio.svg"),
        &break_even_svg(&break_even),
    )?;

    Ok(break_even)
}

fn write_file(path: &Path, body: &str) -> io::Result<()> {
    let mut file = File::create(path)?;
    file.write_all(body.as_bytes())
}

/// One profile row comparing a FrankenLibC hot path with an explicit host glibc baseline.
#[derive(Debug, Clone, PartialEq)]
pub struct GlibcBaselineRecord {
    pub profile_id: String,
    pub api_family: String,
    pub symbol: String,
    pub workload: String,
    pub runtime_mode: String,
    pub replacement_level: String,
    pub profile_tool: String,
    pub sample_count: usize,
    pub frankenlibc_ns_op: f64,
    pub host_glibc_ns_op: f64,
    pub hotness_score: f64,
    pub baseline_artifact: String,
    pub parity_proof_ref: String,
    pub source_commit: String,
    pub target_dir: String,
    pub generated_at_unix: u64,
}

/// Validate that a committed glibc-baseline report is current enough to support claims.
///
/// The caller supplies the expected source commit and the oldest acceptable
/// generation timestamp, so tests and gates can reject stale copied reports.
pub fn validate_glibc_baseline_records(
    records: &[GlibcBaselineRecord],
    expected_source_commit: &str,
    min_generated_at_unix: u64,
) -> Result<(), String> {
    if records.is_empty() {
        return Err(String::from("profile record set is empty"));
    }

    for record in records {
        if record.source_commit != expected_source_commit {
            return Err(format!(
                "{} source_commit mismatch: expected {}, actual {}",
                record.profile_id, expected_source_commit, record.source_commit
            ));
        }
        if record.generated_at_unix < min_generated_at_unix {
            return Err(format!("{} profile is stale", record.profile_id));
        }
        if record.parity_proof_ref.trim().is_empty() {
            return Err(format!("{} missing parity_proof_ref", record.profile_id));
        }
        if record.baseline_artifact.trim().is_empty() {
            return Err(format!("{} missing baseline_artifact", record.profile_id));
        }
        if record.sample_count == 0 {
            return Err(format!("{} has zero samples", record.profile_id));
        }
        if !record.hotness_score.is_finite()
            || !record.frankenlibc_ns_op.is_finite()
            || !record.host_glibc_ns_op.is_finite()
        {
            return Err(format!("{} contains non-finite metric", record.profile_id));
        }
    }

    Ok(())
}

/// Rank profile records by optimization priority, with stable tie-breaks for reproducibility.
#[must_use]
pub fn rank_glibc_baseline_records(records: &[GlibcBaselineRecord]) -> Vec<GlibcBaselineRecord> {
    let mut ranked = records.to_vec();
    ranked.sort_by(|left, right| {
        right
            .hotness_score
            .partial_cmp(&left.hotness_score)
            .unwrap_or(std::cmp::Ordering::Equal)
            .then_with(|| left.api_family.cmp(&right.api_family))
            .then_with(|| left.symbol.cmp(&right.symbol))
            .then_with(|| left.profile_id.cmp(&right.profile_id))
    });
    ranked
}

#[must_use]
pub fn glibc_baseline_markdown(records: &[GlibcBaselineRecord]) -> String {
    let ranked = rank_glibc_baseline_records(records);
    let mut body = format!(
        "# Host glibc baseline profile\n\nSchema: `{}`  \nBead: `{}`\n\n",
        GLIBC_BASELINE_SCHEMA_VERSION, GLIBC_BASELINE_BEAD_ID
    );
    body.push_str("| Rank | Profile | API family | Symbol | Workload | FL ns/op | glibc ns/op | Ratio | Hotness | Samples | Parity proof |\n");
    body.push_str("|---:|---|---|---|---|---:|---:|---:|---:|---:|---|\n");
    for (idx, record) in ranked.iter().enumerate() {
        let ratio = if record.host_glibc_ns_op <= f64::EPSILON {
            0.0
        } else {
            record.frankenlibc_ns_op / record.host_glibc_ns_op
        };
        body.push_str(&format!(
            "| {} | `{}` | `{}` | `{}` | {} | {:.3} | {:.3} | {:.2}x | {:.3} | {} | {} |\n",
            idx + 1,
            record.profile_id,
            record.api_family,
            record.symbol,
            record.workload,
            record.frankenlibc_ns_op,
            record.host_glibc_ns_op,
            ratio,
            record.hotness_score,
            record.sample_count,
            record.parity_proof_ref
        ));
    }
    body
}

/// Runtime mode covered by the strict/hardened membrane-overhead harness.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum StrictHardenedOverheadMode {
    Strict,
    Hardened,
}

impl StrictHardenedOverheadMode {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Strict => "strict",
            Self::Hardened => "hardened",
        }
    }
}

pub const STRICT_HARDENED_OVERHEAD_MODES: [StrictHardenedOverheadMode; 2] = [
    StrictHardenedOverheadMode::Strict,
    StrictHardenedOverheadMode::Hardened,
];

/// Execution lane for the membrane-overhead harness.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum StrictHardenedOverheadLane {
    Smoke,
    Full,
}

impl StrictHardenedOverheadLane {
    #[must_use]
    pub fn from_str_loose(value: &str) -> Self {
        match value.to_ascii_lowercase().as_str() {
            "full" | "release" => Self::Full,
            _ => Self::Smoke,
        }
    }

    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Smoke => "smoke",
            Self::Full => "full",
        }
    }

    #[must_use]
    pub const fn sample_count(self) -> usize {
        match self {
            Self::Smoke => 8,
            Self::Full => 64,
        }
    }

    #[must_use]
    pub const fn inner_iterations(self) -> usize {
        match self {
            Self::Smoke => 128,
            Self::Full => 1024,
        }
    }
}

/// Representative ABI family measured by the overhead harness.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum StrictHardenedOverheadFamily {
    StringMemory,
    Allocator,
    StdioBuffer,
    PthreadSync,
    Ctype,
    MathFenv,
    RuntimeMath,
}

impl StrictHardenedOverheadFamily {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::StringMemory => "string_memory",
            Self::Allocator => "allocator",
            Self::StdioBuffer => "stdio_buffer",
            Self::PthreadSync => "pthread_sync",
            Self::Ctype => "ctype",
            Self::MathFenv => "math_fenv",
            Self::RuntimeMath => "runtime_math",
        }
    }

    #[must_use]
    pub const fn symbol(self) -> &'static str {
        match self {
            Self::StringMemory => "memcpy",
            Self::Allocator => "malloc/free",
            Self::StdioBuffer => "fwrite",
            Self::PthreadSync => "pthread_mutex_lock",
            Self::Ctype => "isalpha",
            Self::MathFenv => "sin",
            Self::RuntimeMath => "RuntimeMathKernel::decide",
        }
    }

    #[must_use]
    pub const fn workload(self) -> &'static str {
        match self {
            Self::StringMemory => "64-byte copy plus membrane decision",
            Self::Allocator => "small allocation lifetime plus membrane decision",
            Self::StdioBuffer => "buffer append plus membrane decision",
            Self::PthreadSync => "mutex fast path plus membrane decision",
            Self::Ctype => "ASCII classifier plus membrane decision",
            Self::MathFenv => "scalar f64 math plus membrane decision",
            Self::RuntimeMath => "pointer-validation control decision",
        }
    }
}

pub const STRICT_HARDENED_OVERHEAD_FAMILIES: [StrictHardenedOverheadFamily; 7] = [
    StrictHardenedOverheadFamily::StringMemory,
    StrictHardenedOverheadFamily::Allocator,
    StrictHardenedOverheadFamily::StdioBuffer,
    StrictHardenedOverheadFamily::PthreadSync,
    StrictHardenedOverheadFamily::Ctype,
    StrictHardenedOverheadFamily::MathFenv,
    StrictHardenedOverheadFamily::RuntimeMath,
];

#[must_use]
pub const fn required_strict_hardened_overhead_families(
    _lane: StrictHardenedOverheadLane,
) -> &'static [StrictHardenedOverheadFamily] {
    &STRICT_HARDENED_OVERHEAD_FAMILIES
}

/// One strict/hardened overhead harness measurement row.
#[derive(Debug, Clone, PartialEq)]
pub struct StrictHardenedOverheadRecord {
    pub trace_id: String,
    pub lane: StrictHardenedOverheadLane,
    pub runtime_mode: StrictHardenedOverheadMode,
    pub api_family: StrictHardenedOverheadFamily,
    pub symbol: String,
    pub workload: String,
    pub raw_timings_ns: Vec<u64>,
    pub sample_count: usize,
    pub p50_ns_op: f64,
    pub p95_ns_op: f64,
    pub p99_ns_op: f64,
    pub mean_ns_op: f64,
    pub cv_pct: f64,
    pub throughput_ops_s: f64,
    pub command: String,
    pub worker_id: String,
    pub cpu_model: String,
    pub source_commit: String,
    pub target_dir: String,
    pub artifact_refs: Vec<String>,
    pub decision_count: u64,
    pub missing_decision_telemetry: bool,
}

#[must_use]
pub fn mean_latency_ns(samples: &[u64]) -> f64 {
    if samples.is_empty() {
        return 0.0;
    }

    samples.iter().map(|&value| value as f64).sum::<f64>() / samples.len() as f64
}

pub fn validate_strict_hardened_overhead_records(
    records: &[StrictHardenedOverheadRecord],
    lane: StrictHardenedOverheadLane,
) -> Result<(), String> {
    if records.is_empty() {
        return Err(String::from("strict/hardened overhead record set is empty"));
    }

    let mut coverage = BTreeSet::new();
    for record in records {
        if record.lane != lane {
            return Err(format!(
                "{} has lane {}, expected {}",
                record.trace_id,
                record.lane.as_str(),
                lane.as_str()
            ));
        }
        if record.trace_id.trim().is_empty() {
            return Err(String::from("record has empty trace_id"));
        }
        if record.symbol.trim().is_empty() {
            return Err(format!("{} missing symbol", record.trace_id));
        }
        if record.workload.trim().is_empty() {
            return Err(format!("{} missing workload", record.trace_id));
        }
        if record.command.trim().is_empty() {
            return Err(format!("{} missing command transcript", record.trace_id));
        }
        if record.worker_id.trim().is_empty() {
            return Err(format!("{} missing worker_id", record.trace_id));
        }
        if record.cpu_model.trim().is_empty() {
            return Err(format!("{} missing cpu_model", record.trace_id));
        }
        if record.source_commit.trim().is_empty() {
            return Err(format!("{} missing source_commit", record.trace_id));
        }
        if record.target_dir.trim().is_empty() {
            return Err(format!("{} missing target_dir", record.trace_id));
        }
        if record.artifact_refs.is_empty()
            || record
                .artifact_refs
                .iter()
                .any(|path| path.trim().is_empty())
        {
            return Err(format!("{} missing artifact refs", record.trace_id));
        }
        if record.sample_count == 0 || record.raw_timings_ns.is_empty() {
            return Err(format!("{} has no timing samples", record.trace_id));
        }
        if record.sample_count != record.raw_timings_ns.len() {
            return Err(format!(
                "{} sample_count {} does not match raw timing length {}",
                record.trace_id,
                record.sample_count,
                record.raw_timings_ns.len()
            ));
        }
        if record.raw_timings_ns.contains(&0) {
            return Err(format!(
                "{} contains zero-ns timing sample",
                record.trace_id
            ));
        }
        if !record.p50_ns_op.is_finite()
            || !record.p95_ns_op.is_finite()
            || !record.p99_ns_op.is_finite()
            || !record.mean_ns_op.is_finite()
            || !record.cv_pct.is_finite()
            || !record.throughput_ops_s.is_finite()
        {
            return Err(format!("{} contains non-finite metric", record.trace_id));
        }
        if record.mean_ns_op <= 0.0 || record.throughput_ops_s <= 0.0 {
            return Err(format!(
                "{} contains non-positive throughput",
                record.trace_id
            ));
        }
        if record.decision_count < record.sample_count as u64 {
            return Err(format!(
                "{} decision telemetry count {} is below sample count {}",
                record.trace_id, record.decision_count, record.sample_count
            ));
        }
        if record.missing_decision_telemetry {
            return Err(format!(
                "{} reports missing decision telemetry",
                record.trace_id
            ));
        }

        coverage.insert((record.runtime_mode, record.api_family));
    }

    for mode in STRICT_HARDENED_OVERHEAD_MODES {
        for family in required_strict_hardened_overhead_families(lane) {
            if !coverage.contains(&(mode, *family)) {
                return Err(format!(
                    "missing {} {} overhead row",
                    mode.as_str(),
                    family.as_str()
                ));
            }
        }
    }

    Ok(())
}

#[must_use]
pub fn strict_hardened_overhead_json(records: &[StrictHardenedOverheadRecord]) -> String {
    let mut body = format!(
        "{{\n  \"schema_version\": \"{}\",\n  \"bead_id\": \"{}\",\n  \"record_count\": {},\n  \"required_modes\": [\"strict\", \"hardened\"],\n  \"records\": [\n",
        STRICT_HARDENED_OVERHEAD_SCHEMA_VERSION,
        STRICT_HARDENED_OVERHEAD_BEAD_ID,
        records.len()
    );
    for (idx, record) in records.iter().enumerate() {
        let comma = if idx + 1 == records.len() { "" } else { "," };
        body.push_str("    ");
        body.push_str(&strict_hardened_overhead_record_json(record));
        body.push_str(comma);
        body.push('\n');
    }
    body.push_str("  ]\n}\n");
    body
}

#[must_use]
pub fn strict_hardened_overhead_jsonl(records: &[StrictHardenedOverheadRecord]) -> String {
    let mut body = String::new();
    for record in records {
        body.push_str(&strict_hardened_overhead_record_json(record));
        body.push('\n');
    }
    body
}

#[must_use]
pub fn strict_hardened_overhead_dat(records: &[StrictHardenedOverheadRecord]) -> String {
    let mut body = String::from(
        "# lane mode family symbol samples p50_ns p95_ns p99_ns mean_ns throughput_ops_s decisions\n",
    );
    for record in records {
        body.push_str(&format!(
            "{} {} {} {} {} {:.3} {:.3} {:.3} {:.3} {:.3} {}\n",
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
            record.decision_count
        ));
    }
    body
}

/// Write the strict/hardened membrane-overhead artifact bundle into `out_dir`.
pub fn write_strict_hardened_overhead_artifacts(
    records: &[StrictHardenedOverheadRecord],
    out_dir: &Path,
) -> io::Result<Vec<String>> {
    create_dir_all(out_dir)?;
    let json_path = out_dir.join("strict_hardened_membrane_overhead.v1.json");
    let jsonl_path = out_dir.join("strict_hardened_membrane_overhead.v1.jsonl");
    let dat_path = out_dir.join("strict_hardened_membrane_overhead_summary.dat");

    write_file(&json_path, &strict_hardened_overhead_json(records))?;
    write_file(&jsonl_path, &strict_hardened_overhead_jsonl(records))?;
    write_file(&dat_path, &strict_hardened_overhead_dat(records))?;

    Ok(vec![
        json_path.display().to_string(),
        jsonl_path.display().to_string(),
        dat_path.display().to_string(),
    ])
}

fn strict_hardened_overhead_record_json(record: &StrictHardenedOverheadRecord) -> String {
    format!(
        "{{\"trace_id\":{},\"schema_version\":\"{}\",\"bead_id\":\"{}\",\"lane\":\"{}\",\"runtime_mode\":\"{}\",\"api_family\":\"{}\",\"symbol\":{},\"workload\":{},\"raw_timings_ns\":{},\"sample_count\":{},\"p50_ns_op\":{:.3},\"p95_ns_op\":{:.3},\"p99_ns_op\":{:.3},\"mean_ns_op\":{:.3},\"cv_pct\":{:.3},\"throughput_ops_s\":{:.3},\"command\":{},\"worker_id\":{},\"cpu_model\":{},\"source_commit\":{},\"target_dir\":{},\"artifact_refs\":{},\"decision_count\":{},\"missing_decision_telemetry\":{}}}",
        json_string(&record.trace_id),
        STRICT_HARDENED_OVERHEAD_SCHEMA_VERSION,
        STRICT_HARDENED_OVERHEAD_BEAD_ID,
        record.lane.as_str(),
        record.runtime_mode.as_str(),
        record.api_family.as_str(),
        json_string(&record.symbol),
        json_string(&record.workload),
        json_u64_array(&record.raw_timings_ns),
        record.sample_count,
        record.p50_ns_op,
        record.p95_ns_op,
        record.p99_ns_op,
        record.mean_ns_op,
        record.cv_pct,
        record.throughput_ops_s,
        json_string(&record.command),
        json_string(&record.worker_id),
        json_string(&record.cpu_model),
        json_string(&record.source_commit),
        json_string(&record.target_dir),
        json_string_array(&record.artifact_refs),
        record.decision_count,
        record.missing_decision_telemetry
    )
}

fn json_u64_array(values: &[u64]) -> String {
    let mut body = String::from("[");
    for (idx, value) in values.iter().enumerate() {
        if idx > 0 {
            body.push(',');
        }
        body.push_str(&value.to_string());
    }
    body.push(']');
    body
}

fn json_string_array(values: &[String]) -> String {
    let mut body = String::from("[");
    for (idx, value) in values.iter().enumerate() {
        if idx > 0 {
            body.push(',');
        }
        body.push_str(&json_string(value));
    }
    body.push(']');
    body
}

fn json_string(value: &str) -> String {
    let mut body = String::from("\"");
    for ch in value.chars() {
        match ch {
            '"' => body.push_str("\\\""),
            '\\' => body.push_str("\\\\"),
            '\n' => body.push_str("\\n"),
            '\r' => body.push_str("\\r"),
            '\t' => body.push_str("\\t"),
            c if c.is_control() => body.push_str(&format!("\\u{:04x}", c as u32)),
            c => body.push(c),
        }
    }
    body.push('"');
    body
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn balanced_square_gives_each_arm_equal_early_late_and_total_exposure() {
        assert_eq!(
            BALANCED_SQUARE_ABBA,
            [false, true, true, false, false, true, true, false]
        );
        for half in BALANCED_SQUARE_ABBA.chunks_exact(4) {
            assert_eq!(half.iter().filter(|&&reverse| reverse).count(), 2);
            assert_eq!(half.iter().filter(|&&reverse| !reverse).count(), 2);
        }
        assert_eq!(
            (0..BALANCED_SQUARE_ABBA.len())
                .filter(|&round| balanced_square_reverse_at(round))
                .count(),
            4
        );
        assert_eq!(
            (0..BALANCED_SQUARE_ABBA.len())
                .map(|round| balanced_square_reverse_at(round))
                .collect::<Vec<_>>(),
            BALANCED_SQUARE_ABBA
        );
    }

    #[test]
    fn deployed_preload_loader_flags_keep_frankenlibc_symbols_self_bound() {
        assert_eq!(
            DEPLOYED_PRELOAD_DLOPEN_FLAGS,
            libc::RTLD_NOW | libc::RTLD_LOCAL | libc::RTLD_DEEPBIND,
        );
    }

    #[test]
    fn host_wide_cpu_list_parser_accepts_ranges_and_singletons() {
        assert_eq!(
            parse_cpu_list("0-2,5,8-9").expect("valid CPU list"),
            BTreeSet::from([0, 1, 2, 5, 8, 9])
        );
    }

    #[test]
    fn host_wide_busy_fraction_and_threshold_are_fail_closed() {
        let before = parse_cpu_ticks("cpu 0 0 0 0 0\ncpu0 10 0 10 80 0\ncpu1 20 0 10 70 0\n")
            .expect("valid starting ticks");
        let after = parse_cpu_ticks("cpu 0 0 0 0 0\ncpu0 15 0 15 170 0\ncpu1 35 0 15 150 0\n")
            .expect("valid ending ticks");
        let busy = calculate_cpu_busy(&before, &after).expect("monotonic CPU ticks");
        assert!((busy[&0] - 0.10).abs() < f64::EPSILON);
        assert!((busy[&1] - 0.20).abs() < f64::EPSILON);
        assert_eq!(
            validate_host_wide_quiescence(&BTreeSet::from([0, 1]), &busy).expect("20% is admitted"),
            0.20
        );

        let mut contaminated = busy;
        contaminated.insert(1, 0.21);
        let error = validate_host_wide_quiescence(&BTreeSet::from([0, 1]), &contaminated)
            .expect_err("greater than 20% must be blocked");
        assert!(error.contains("cpu1=21.0%"));
    }

    #[test]
    fn host_wide_quiescence_rejects_an_unobserved_allowed_cpu() {
        let error =
            validate_host_wide_quiescence(&BTreeSet::from([0, 1]), &BTreeMap::from([(0, 0.0)]))
                .expect_err("missing allowed CPU must fail closed");
        assert!(error.contains("allowed cpu1 was not sampled"));
    }

    #[test]
    fn cpu_policy_summary_requires_one_complete_uniform_value() {
        assert_eq!(
            summarize_cpu_attribute("governor", &[(0, None), (1, None)])
                .expect("uniform absence is explicit provenance"),
            "unavailable"
        );
        assert_eq!(
            summarize_cpu_attribute(
                "governor",
                &[
                    (0, Some("performance".to_owned())),
                    (1, Some("performance".to_owned())),
                ],
            )
            .expect("uniform policy"),
            "performance"
        );

        let partial = summarize_cpu_attribute(
            "governor",
            &[(0, Some("performance".to_owned())), (1, None)],
        )
        .expect_err("partial visibility must fail closed");
        assert!(partial.contains("missing CPUs: 1"));

        let heterogeneous = summarize_cpu_attribute(
            "governor",
            &[
                (0, Some("performance".to_owned())),
                (1, Some("powersave".to_owned())),
            ],
        )
        .expect_err("heterogeneous policy must fail closed");
        assert!(heterogeneous.contains("performance:powersave"));
    }

    #[test]
    fn host_wide_contract_records_topology_isa_and_governor() {
        let evidence = HostWideQuiescenceEvidence {
            hostname: "bench-host".to_owned(),
            allowed_cpus: BTreeSet::from([0, 1, 2, 3]),
            affinity_mask: "f".to_owned(),
            platform: HostPlatformProvenance {
                physical_cores: 2,
                logical_threads: 4,
                ram_bytes: 16 * 1024 * 1024 * 1024,
                numa_nodes: 1,
                runtime_isa: "x86_64+avx2".to_owned(),
                cpufreq_driver: "amd-pstate-epp".to_owned(),
                governor: "powersave".to_owned(),
                energy_performance_preference: "balance_performance".to_owned(),
            },
            maximum_observed_busy_fraction: 0.125,
            samples_observed: 7,
            wait_ms: 7_043,
        };
        let contract = evidence.contract_line("baseline");
        for required in [
            "physical_cores=2",
            "logical_threads=4",
            "ram_bytes=17179869184",
            "numa_nodes=1",
            "isa=x86_64+avx2",
            "cpufreq_driver=amd-pstate-epp",
            "governor=powersave",
            "energy_performance_preference=balance_performance",
            "affinity_mask=f",
            "sample_ms=1000",
            "required_consecutive_clear_samples=5",
            "samples_observed=7",
            "wait_ms=7043",
            "timeout_ms=300000",
            "verdict=clear",
        ] {
            assert!(
                contract.contains(required),
                "contract missing {required:?}: {contract}"
            );
        }
    }

    fn sample_records() -> Vec<MetadataBenchRecord> {
        vec![
            MetadataBenchRecord {
                implementation: MetadataImplementation::Rcu,
                operation: MetadataOperation::ThreadMetadata,
                read_ratio_pct: 50,
                thread_count: 8,
                total_ops: 100,
                read_ops: 50,
                write_ops: 50,
                throughput_ops_s: 1200.0,
                p50_ns_op: 10.0,
                p95_ns_op: 20.0,
                p99_ns_op: 30.0,
                cv_pct: 1.0,
                sample_count: 16,
            },
            MetadataBenchRecord {
                implementation: MetadataImplementation::Mutex,
                operation: MetadataOperation::ThreadMetadata,
                read_ratio_pct: 50,
                thread_count: 8,
                total_ops: 100,
                read_ops: 50,
                write_ops: 50,
                throughput_ops_s: 1100.0,
                p50_ns_op: 11.0,
                p95_ns_op: 21.0,
                p99_ns_op: 31.0,
                cv_pct: 2.0,
                sample_count: 16,
            },
            MetadataBenchRecord {
                implementation: MetadataImplementation::Rcu,
                operation: MetadataOperation::ThreadMetadata,
                read_ratio_pct: 90,
                thread_count: 8,
                total_ops: 100,
                read_ops: 90,
                write_ops: 10,
                throughput_ops_s: 1500.0,
                p50_ns_op: 8.0,
                p95_ns_op: 16.0,
                p99_ns_op: 24.0,
                cv_pct: 1.5,
                sample_count: 16,
            },
            MetadataBenchRecord {
                implementation: MetadataImplementation::Mutex,
                operation: MetadataOperation::ThreadMetadata,
                read_ratio_pct: 90,
                thread_count: 8,
                total_ops: 100,
                read_ops: 90,
                write_ops: 10,
                throughput_ops_s: 1400.0,
                p50_ns_op: 9.0,
                p95_ns_op: 17.0,
                p99_ns_op: 25.0,
                cv_pct: 2.5,
                sample_count: 16,
            },
        ]
    }

    #[test]
    fn summarize_latency_samples_reports_percentiles_and_cv() {
        let (p50, p95, p99, cv) = summarize_latency_samples(&[10, 20, 30, 40, 50]);
        assert_eq!(p50, 30.0);
        assert_eq!(p95, 50.0);
        assert_eq!(p99, 50.0);
        assert!(cv > 0.0);
    }

    #[test]
    fn break_even_summary_prefers_lowest_ratio_that_wins() {
        let summary = build_break_even_summary(&sample_records());
        assert_eq!(
            summary,
            vec![MetadataBreakEven {
                operation: MetadataOperation::ThreadMetadata,
                thread_count: 8,
                break_even_read_ratio_pct: Some(50),
            }]
        );
    }

    #[test]
    fn json_and_plot_scripts_reference_expected_sections() {
        let summary = build_break_even_summary(&sample_records());
        let json = metadata_bench_json(&sample_records(), &summary);
        assert!(json.contains(METADATA_BENCH_SCHEMA_VERSION));
        assert!(json.contains(METADATA_BENCH_BEAD_ID));
        assert!(json.contains("\"records\""));
        assert!(json.contains("\"break_even\""));
        assert!(throughput_svg(&sample_records()).contains("<svg"));
        assert!(latency_svg(&sample_records()).contains("<svg"));
        assert!(break_even_svg(&summary).contains("<svg"));
        assert!(throughput_gnuplot_script().contains("set terminal svg"));
        assert!(latency_gnuplot_script().contains("latency_percentiles.svg"));
        assert!(break_even_gnuplot_script().contains("break_even_ratio.svg"));
    }

    fn sample_glibc_records() -> Vec<GlibcBaselineRecord> {
        vec![
            GlibcBaselineRecord {
                profile_id: String::from("strlen_4096"),
                api_family: String::from("string"),
                symbol: String::from("strlen"),
                workload: String::from("4096 byte nul-terminated scan"),
                runtime_mode: String::from("strict"),
                replacement_level: String::from("L0"),
                profile_tool: String::from("criterion"),
                sample_count: 12,
                frankenlibc_ns_op: 120.0,
                host_glibc_ns_op: 24.0,
                hotness_score: 5.0,
                baseline_artifact: String::from("artifacts/perf/glibc-baseline.md"),
                parity_proof_ref: String::from("tests/conformance/fixtures/string_ops"),
                source_commit: String::from("abc123"),
                target_dir: String::from("/tmp/target"),
                generated_at_unix: 1_777_000_000,
            },
            GlibcBaselineRecord {
                profile_id: String::from("memcpy_4096"),
                api_family: String::from("string"),
                symbol: String::from("memcpy"),
                workload: String::from("4096 byte copy"),
                runtime_mode: String::from("strict"),
                replacement_level: String::from("L0"),
                profile_tool: String::from("criterion"),
                sample_count: 12,
                frankenlibc_ns_op: 48.0,
                host_glibc_ns_op: 24.0,
                hotness_score: 2.0,
                baseline_artifact: String::from("artifacts/perf/glibc-baseline.md"),
                parity_proof_ref: String::from("tests/conformance/fixtures/string_memory_full"),
                source_commit: String::from("abc123"),
                target_dir: String::from("/tmp/target"),
                generated_at_unix: 1_777_000_000,
            },
        ]
    }

    #[test]
    fn glibc_baseline_ranking_is_deterministic() {
        let ranked = rank_glibc_baseline_records(&sample_glibc_records());
        assert_eq!(ranked[0].profile_id, "strlen_4096");
        assert_eq!(ranked[1].profile_id, "memcpy_4096");
    }

    #[test]
    fn glibc_baseline_validation_rejects_stale_source_commit() {
        let err = validate_glibc_baseline_records(&sample_glibc_records(), "def456", 1)
            .expect_err("source commit mismatch should be rejected");
        assert!(err.contains("source_commit mismatch"));
    }

    #[test]
    fn glibc_baseline_validation_requires_parity_proof() {
        let mut records = sample_glibc_records();
        records[0].parity_proof_ref.clear();
        let err = validate_glibc_baseline_records(&records, "abc123", 1)
            .expect_err("missing parity proof should be rejected");
        assert!(err.contains("missing parity_proof_ref"));
    }

    #[test]
    fn glibc_baseline_markdown_contains_required_columns() {
        let report = glibc_baseline_markdown(&sample_glibc_records());
        assert!(report.contains(GLIBC_BASELINE_BEAD_ID));
        assert!(report.contains("| Rank | Profile | API family | Symbol |"));
        assert!(report.contains("`strlen_4096`"));
        assert!(report.contains("tests/conformance/fixtures/string_ops"));
    }

    fn sample_overhead_records() -> Vec<StrictHardenedOverheadRecord> {
        let mut records = Vec::new();
        for mode in STRICT_HARDENED_OVERHEAD_MODES {
            for family in
                required_strict_hardened_overhead_families(StrictHardenedOverheadLane::Smoke)
            {
                records.push(StrictHardenedOverheadRecord {
                    trace_id: format!("bd-wpr1n-{}-{}", mode.as_str(), family.as_str()),
                    lane: StrictHardenedOverheadLane::Smoke,
                    runtime_mode: mode,
                    api_family: *family,
                    symbol: String::from(family.symbol()),
                    workload: String::from(family.workload()),
                    raw_timings_ns: vec![10, 11, 12, 13],
                    sample_count: 4,
                    p50_ns_op: 12.0,
                    p95_ns_op: 13.0,
                    p99_ns_op: 13.0,
                    mean_ns_op: 11.5,
                    cv_pct: 10.0,
                    throughput_ops_s: 86_956_521.739,
                    command: String::from(
                        "cargo bench -p frankenlibc-bench --bench strict_hardened_overhead_harness -- --smoke",
                    ),
                    worker_id: String::from("rch-worker-a"),
                    cpu_model: String::from("test-cpu"),
                    source_commit: String::from("abc123"),
                    target_dir: String::from("/tmp/frankenlibc-target"),
                    artifact_refs: vec![String::from(
                        "/tmp/frankenlibc-target/conformance/bd-wpr1n/report.json",
                    )],
                    decision_count: 512,
                    missing_decision_telemetry: false,
                });
            }
        }
        records
    }

    #[test]
    fn strict_hardened_overhead_validation_requires_complete_matrix() {
        let records = sample_overhead_records();
        validate_strict_hardened_overhead_records(&records, StrictHardenedOverheadLane::Smoke)
            .expect("complete strict/hardened matrix should validate");

        let mut incomplete = records.clone();
        incomplete.pop();
        let err = validate_strict_hardened_overhead_records(
            &incomplete,
            StrictHardenedOverheadLane::Smoke,
        )
        .expect_err("missing mode/family row should be rejected");
        assert!(err.contains("missing hardened runtime_math overhead row"));
    }

    #[test]
    fn strict_hardened_overhead_validation_rejects_missing_evidence() {
        let mut records = sample_overhead_records();
        records[0].missing_decision_telemetry = true;
        let err =
            validate_strict_hardened_overhead_records(&records, StrictHardenedOverheadLane::Smoke)
                .expect_err("telemetry mismatch should be rejected");
        assert!(err.contains("reports missing decision telemetry"));

        records[0].missing_decision_telemetry = false;
        records[0].artifact_refs.clear();
        let err =
            validate_strict_hardened_overhead_records(&records, StrictHardenedOverheadLane::Smoke)
                .expect_err("missing artifact refs should be rejected");
        assert!(err.contains("missing artifact refs"));
    }

    #[test]
    fn strict_hardened_overhead_json_contains_audit_fields() {
        let records = sample_overhead_records();
        let json = strict_hardened_overhead_json(&records);
        assert!(json.contains(STRICT_HARDENED_OVERHEAD_BEAD_ID));
        assert!(json.contains("\"required_modes\": [\"strict\", \"hardened\"]"));
        assert!(json.contains("\"raw_timings_ns\":[10,11,12,13]"));
        assert!(json.contains("\"command\""));
        assert!(json.contains("\"worker_id\""));
        assert!(json.contains("\"artifact_refs\""));
        assert!(json.contains("\"missing_decision_telemetry\":false"));
        assert!(strict_hardened_overhead_jsonl(&records).contains("\"runtime_mode\":\"strict\""));
        assert!(strict_hardened_overhead_dat(&records).contains("# lane mode family"));
    }
}
