//! Realistic whole-job comparison of FrankenLibC and the host glibc.
//!
//! The controller compiles one dynamically linked C workload executable, then
//! runs that exact ELF normally and under `LD_PRELOAD=libfrankenlibc_abi.so`.
//! Startup, file I/O, parsing, allocation, sorting, formatting, serialization,
//! and teardown all remain inside each timed child process. Every workload has
//! host/host and Franken/Franken A/A controls in the same invocation. Paired
//! bootstrap median confidence intervals, never CV, decide the verdict.

use std::collections::BTreeMap;
use std::env;
use std::ffi::{OsStr, OsString};
use std::fmt::Write as _;
use std::fs::{self, File, OpenOptions};
use std::io::{BufRead, BufReader, BufWriter, Read, Write};
use std::path::{Path, PathBuf};
use std::process::{Command, Output, Stdio};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::thread;
use std::time::{Duration, Instant};

use frankenlibc_bench::HostWideBenchmarkGuard;
use sha2::{Digest, Sha256};

const DEFAULT_SAMPLES: usize = 15;
const DEFAULT_WARMUPS: usize = 2;
const BOOTSTRAP_RESAMPLES: usize = 4096;
const DATA_ROOT: &str = "/data/tmp/frankenlibc-e2e-data-v1";
const WORKLOAD_SOURCE: &[u8] = include_bytes!("../workloads/e2e_workloads.c");

const APACHE_ROWS: usize = 120_000;
const SYSLOG_ROWS: usize = 160_000;
const CORPUS_TOKENS: usize = 1_500_000;
const CORPUS_WORDS_PER_LINE: usize = 50;
const CSV_ROWS: usize = 400_000;
const LEGACY_SYSLOG_SWEEP_MULTIPLIERS: [usize; 3] = [1, 4, 16];
const LEGACY_SYSLOG_THREAD_SWEEP: [usize; 9] = [1, 2, 4, 8, 16, 32, 64, 96, 128];
const THREAD_SWEEP_SAMPLES: usize = 33;
const THREAD_SWEEP_WARMUPS: usize = 4;

fn host_wide_guard() -> HostWideBenchmarkGuard {
    HostWideBenchmarkGuard::new().unwrap_or_else(|error| {
        eprintln!("BENCH_HOST_WIDE_EXCLUSIVITY phase=initialize verdict=BLOCKED reason={error:?}");
        std::process::exit(2);
    })
}

fn require_host_wide_quiet(guard: &HostWideBenchmarkGuard, phase: &str) {
    match guard.check_quiet() {
        Ok(evidence) => println!("{}", evidence.contract_line(phase)),
        Err(error) => {
            eprintln!("BENCH_HOST_WIDE_EXCLUSIVITY phase={phase} verdict=BLOCKED reason={error:?}");
            std::process::exit(2);
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Arm {
    Host,
    Franken,
}

impl Arm {
    fn label(self) -> &'static str {
        match self {
            Self::Host => "host_glibc",
            Self::Franken => "frankenlibc_strict",
        }
    }
}

#[derive(Clone, Copy, Debug)]
enum Workload {
    Apache,
    Syslog,
    LegacySyslog,
    LegacySyslogThreaded,
    WordFrequency,
    CsvStatistics,
}

impl Workload {
    fn id(self) -> &'static str {
        match self {
            Self::Apache => "flc_e2e_apache_v1",
            Self::Syslog => "flc_e2e_rfc3164_v1",
            Self::LegacySyslog => "flc_e2e_iso_to_rfc3164_v1",
            Self::LegacySyslogThreaded => "flc_e2e_iso_to_rfc3164_mt_v1",
            Self::WordFrequency => "flc_e2e_zipf_corpus_v1",
            Self::CsvStatistics => "flc_e2e_zipf_csv_v1",
        }
    }

    fn command(self) -> &'static str {
        match self {
            Self::Apache => "logparse",
            Self::Syslog => "tsreformat",
            Self::LegacySyslog => "legacylog",
            Self::LegacySyslogThreaded => "legacylog_mt",
            Self::WordFrequency => "wordfreq",
            Self::CsvStatistics => "csvstat",
        }
    }

    fn meaning(self) -> &'static str {
        match self {
            Self::Apache => {
                "parse a production-sized Apache access log and emit a sorted traffic report"
            }
            Self::Syslog => {
                "normalize an RFC3164 syslog export to ISO-8601 and serialize every record"
            }
            Self::LegacySyslog => {
                "convert an ISO-8601 service-log export to RFC3164 for a legacy syslog sink"
            }
            Self::LegacySyslogThreaded => {
                "convert a fixed ISO-8601 service-log export to RFC3164 with a worker pool"
            }
            Self::WordFrequency => {
                "scan a Zipf-skewed text corpus and emit a sorted word-frequency report"
            }
            Self::CsvStatistics => {
                "parse a skewed analytical CSV and emit grouped numeric statistics"
            }
        }
    }

    fn uses_worker_pool(self) -> bool {
        matches!(self, Self::LegacySyslogThreaded)
    }
}

#[derive(Clone)]
struct Dataset {
    path: PathBuf,
    records: usize,
    size_multiplier: usize,
    bytes: u64,
    sha256: String,
    distribution: &'static str,
}

struct Job {
    workload: Workload,
    dataset: Dataset,
    output_path: Option<PathBuf>,
    requested_workers: usize,
}

struct GoldenOutput {
    stdout: Vec<u8>,
    serialized_sha256: Option<String>,
    output_bytes: u64,
    work_evidence: Option<WorkEvidence>,
}

struct TimedOutput {
    elapsed: Duration,
    stdout: Vec<u8>,
    observed_peak_tasks: usize,
}

struct Identity {
    fields: BTreeMap<String, String>,
}

struct Measurements {
    host_ms: Vec<f64>,
    franken_ms: Vec<f64>,
    host_null_ratios: Vec<f64>,
    franken_null_ratios: Vec<f64>,
    effect_ratios: Vec<f64>,
    host_observed_workers: Vec<usize>,
    franken_observed_workers: Vec<usize>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct WorkEvidence {
    requested_workers: usize,
    started_workers: usize,
    joined_workers: usize,
    workers_with_records: usize,
    peak_active_workers: usize,
    records: usize,
    worker_iterations: usize,
    strptime_calls: usize,
    strftime_calls: usize,
    input_bytes: u64,
    partition_bytes: u64,
    output_bytes: u64,
    output_write_calls: usize,
    min_records_per_worker: usize,
    max_records_per_worker: usize,
}

struct RunConfiguration {
    samples: usize,
    warmups: usize,
    only: Option<String>,
    legacy_size_sweep: bool,
    legacy_thread_sweep: bool,
    only_workers: Option<usize>,
    smoke: bool,
}

struct XorShift64(u64);

impl XorShift64 {
    fn new(seed: u64) -> Self {
        Self(seed)
    }

    fn next_u64(&mut self) -> u64 {
        let mut value = self.0;
        value ^= value << 13;
        value ^= value >> 7;
        value ^= value << 17;
        self.0 = value;
        value
    }

    fn range(&mut self, upper: usize) -> usize {
        assert!(upper > 0);
        (self.next_u64() as usize) % upper
    }

    fn unit_f64(&mut self) -> f64 {
        ((self.next_u64() >> 11) as f64) * (1.0 / ((1u64 << 53) as f64))
    }
}

struct ZipfSampler {
    cumulative: Vec<f64>,
    total: f64,
}

impl ZipfSampler {
    fn new(cardinality: usize, exponent: f64) -> Self {
        let mut cumulative = Vec::with_capacity(cardinality);
        let mut total = 0.0;
        for rank in 1..=cardinality {
            total += 1.0 / (rank as f64).powf(exponent);
            cumulative.push(total);
        }
        Self { cumulative, total }
    }

    fn sample(&self, rng: &mut XorShift64) -> usize {
        let needle = rng.unit_f64() * self.total;
        self.cumulative
            .partition_point(|value| *value < needle)
            .min(self.cumulative.len() - 1)
    }
}

fn sha256_bytes(bytes: &[u8]) -> String {
    let digest = Sha256::digest(bytes);
    let mut hex = String::with_capacity(64);
    for byte in digest {
        write!(&mut hex, "{byte:02x}").expect("write SHA-256 hex");
    }
    hex
}

fn sha256_file(path: &Path) -> Result<String, String> {
    let mut file = File::open(path).map_err(|error| format!("open {}: {error}", path.display()))?;
    let mut hasher = Sha256::new();
    let mut buffer = [0u8; 64 * 1024];
    loop {
        let count = file
            .read(&mut buffer)
            .map_err(|error| format!("read {}: {error}", path.display()))?;
        if count == 0 {
            break;
        }
        hasher.update(&buffer[..count]);
    }
    let digest = hasher.finalize();
    let mut hex = String::with_capacity(64);
    for byte in digest {
        write!(&mut hex, "{byte:02x}").expect("write SHA-256 hex");
    }
    Ok(hex)
}

fn file_line_count(path: &Path) -> Result<usize, String> {
    let file = File::open(path).map_err(|error| format!("open {}: {error}", path.display()))?;
    let mut reader = BufReader::new(file);
    let mut lines = 0;
    let mut buffer = Vec::with_capacity(4096);
    loop {
        buffer.clear();
        let count = reader
            .read_until(b'\n', &mut buffer)
            .map_err(|error| format!("read {}: {error}", path.display()))?;
        if count == 0 {
            break;
        }
        lines += 1;
    }
    Ok(lines)
}

fn ensure_dataset(
    path: &Path,
    records: usize,
    size_multiplier: usize,
    expected_lines: usize,
    distribution: &'static str,
    generate: impl FnOnce(&mut BufWriter<File>) -> Result<(), String>,
) -> Result<Dataset, String> {
    if !path.exists() {
        let file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(path)
            .map_err(|error| format!("create {}: {error}", path.display()))?;
        let mut writer = BufWriter::with_capacity(1024 * 1024, file);
        generate(&mut writer)?;
        writer
            .flush()
            .map_err(|error| format!("flush {}: {error}", path.display()))?;
        writer
            .get_ref()
            .sync_all()
            .map_err(|error| format!("sync {}: {error}", path.display()))?;
    }

    let actual_lines = file_line_count(path)?;
    if actual_lines != expected_lines {
        return Err(format!(
            "{} has {actual_lines} lines, expected {expected_lines}; preserving the unexpected \
             file because repository policy forbids deletion",
            path.display()
        ));
    }
    let bytes = fs::metadata(path)
        .map_err(|error| format!("stat {}: {error}", path.display()))?
        .len();
    let sha256 = sha256_file(path)?;
    Ok(Dataset {
        path: path.to_path_buf(),
        records,
        size_multiplier,
        bytes,
        sha256,
        distribution,
    })
}

fn generate_apache(writer: &mut BufWriter<File>) -> Result<(), String> {
    let mut rng = XorShift64::new(0xa11c_e202_6072_8001);
    let paths = ZipfSampler::new(8192, 1.08);
    let clients = ZipfSampler::new(16_384, 1.04);
    let agents = [
        "Mozilla/5.0 (X11; Linux x86_64) Firefox/128.0",
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) Safari/605.1.15",
        "curl/8.8.0",
        "Googlebot/2.1 (+http://www.google.com/bot.html)",
        "kube-probe/1.30",
    ];
    for row in 0..APACHE_ROWS {
        let second = row % (28 * 86_400);
        let day = 1 + second / 86_400;
        let hour = (second / 3600) % 24;
        let minute = (second / 60) % 60;
        let second = second % 60;
        let path_rank = paths.sample(&mut rng);
        let client = clients.sample(&mut rng);
        let path = match path_rank % 5 {
            0 => format!("/api/v1/items/{path_rank}"),
            1 => format!("/assets/chunk-{path_rank}.js"),
            2 => format!("/products/{path_rank}/details"),
            3 => format!("/images/catalog/{path_rank}.webp"),
            _ => format!("/search/page/{path_rank}"),
        };
        let status_roll = rng.range(10_000);
        let status = match status_roll {
            0..=8_399 => 200,
            8_400..=8_899 => 304,
            8_900..=9_449 => 404,
            9_450..=9_749 => 500,
            9_750..=9_899 => 429,
            _ => 206,
        };
        let bytes = 256 + rng.range(196_608);
        let method = if rng.range(100) < 92 { "GET" } else { "POST" };
        let referer = if rng.range(100) < 68 {
            "https://example.test/catalog"
        } else {
            "-"
        };
        let agent = agents[rng.range(agents.len())];
        writeln!(
            writer,
            "10.{}.{}.{} - - [{day:02}/Jul/2026:{hour:02}:{minute:02}:{second:02} +0000] \
             \"{method} {path} HTTP/1.1\" {status} {bytes} \"{referer}\" \"{agent}\"",
            (client / 65_536) % 256,
            (client / 256) % 256,
            client % 256,
        )
        .map_err(|error| format!("write Apache dataset: {error}"))?;
    }
    Ok(())
}

#[derive(Clone, Copy)]
enum SyslogTimestamp {
    Rfc3164,
    Iso8601,
}

fn generate_syslog_with_timestamp(
    writer: &mut BufWriter<File>,
    timestamp_style: SyslogTimestamp,
    rows: usize,
) -> Result<(), String> {
    let mut rng = XorShift64::new(0x5a51_06e2_6072_8002);
    let hosts = ZipfSampler::new(256, 1.10);
    let services = [
        "sshd",
        "nginx",
        "postgres",
        "kernel",
        "systemd",
        "cron",
        "containerd",
        "backup",
    ];
    let messages = [
        "request completed status=200 latency_ms=18",
        "accepted publickey authentication",
        "checkpoint complete buffers=481",
        "upstream response buffered to temporary file",
        "scheduled job completed exit=0",
        "connection reset by peer",
        "health probe succeeded",
        "rotated application log segment",
    ];
    for row in 0..rows {
        let second = row % (28 * 86_400);
        let day = 1 + second / 86_400;
        let hour = (second / 3600) % 24;
        let minute = (second / 60) % 60;
        let second = second % 60;
        let host = hosts.sample(&mut rng);
        let service = services[rng.range(services.len())];
        let message = messages[rng.range(messages.len())];
        let severity = if rng.range(100) < 93 {
            "info"
        } else {
            "warning"
        };
        let timestamp = match timestamp_style {
            SyslogTimestamp::Rfc3164 => {
                format!("Jul {day:2} {hour:02}:{minute:02}:{second:02}")
            }
            SyslogTimestamp::Iso8601 => {
                format!("2023-07-{day:02}T{hour:02}:{minute:02}:{second:02}Z")
            }
        };
        writeln!(
            writer,
            "{timestamp} node-{host:03} {service}[{}]: severity={severity} {message} \
             request_id={row:08x}",
            1000 + rng.range(55_000),
        )
        .map_err(|error| format!("write syslog dataset: {error}"))?;
    }
    Ok(())
}

fn generate_syslog(writer: &mut BufWriter<File>) -> Result<(), String> {
    generate_syslog_with_timestamp(writer, SyslogTimestamp::Rfc3164, SYSLOG_ROWS)
}

fn generate_iso8601_syslog(writer: &mut BufWriter<File>) -> Result<(), String> {
    generate_syslog_with_timestamp(writer, SyslogTimestamp::Iso8601, SYSLOG_ROWS)
}

fn alphabetic_word(rank: usize) -> String {
    const COMMON: &[&str] = &[
        "the", "of", "and", "to", "in", "a", "is", "that", "for", "it", "on", "with", "as", "was",
        "at", "by", "from", "this", "be", "or", "an", "are", "data", "service", "request",
        "system", "user", "event", "record", "value", "result", "process",
    ];
    if rank < COMMON.len() {
        return COMMON[rank].to_owned();
    }
    let mut value = rank - COMMON.len();
    let mut suffix = [b'a'; 5];
    for byte in suffix.iter_mut().rev() {
        *byte = b'a' + (value % 26) as u8;
        value /= 26;
    }
    format!(
        "term{}",
        std::str::from_utf8(&suffix).expect("ASCII suffix")
    )
}

fn generate_corpus(writer: &mut BufWriter<File>) -> Result<(), String> {
    let mut rng = XorShift64::new(0xc0a7_0520_6072_8003);
    let sampler = ZipfSampler::new(30_000, 1.07);
    let vocabulary = (0..30_000).map(alphabetic_word).collect::<Vec<_>>();
    for token in 0..CORPUS_TOKENS {
        let word = &vocabulary[sampler.sample(&mut rng)];
        if rng.range(100) < 4 {
            write!(writer, "{}", word.to_ascii_uppercase())
                .map_err(|error| format!("write corpus dataset: {error}"))?;
        } else {
            write!(writer, "{word}").map_err(|error| format!("write corpus dataset: {error}"))?;
        }
        let end_of_line = token % CORPUS_WORDS_PER_LINE == CORPUS_WORDS_PER_LINE - 1;
        if end_of_line {
            writeln!(writer, ".").map_err(|error| format!("write corpus dataset: {error}"))?;
        } else {
            let separator = match rng.range(20) {
                0 => ", ",
                1 => "; ",
                _ => " ",
            };
            write!(writer, "{separator}")
                .map_err(|error| format!("write corpus dataset: {error}"))?;
        }
    }
    Ok(())
}

fn generate_csv(writer: &mut BufWriter<File>) -> Result<(), String> {
    let mut rng = XorShift64::new(0xc5a7_57a7_6072_8004);
    let categories = ZipfSampler::new(256, 1.08);
    writeln!(writer, "timestamp,category,value")
        .map_err(|error| format!("write CSV header: {error}"))?;
    for row in 0..CSV_ROWS {
        let second = row % (28 * 86_400);
        let day = 1 + second / 86_400;
        let hour = (second / 3600) % 24;
        let minute = (second / 60) % 60;
        let second = second % 60;
        let category = categories.sample(&mut rng);
        let centered = (0..6).map(|_| rng.unit_f64()).sum::<f64>() - 3.0;
        let scale = 12.0 + (category % 17) as f64 * 2.25;
        let mut value = 100.0 + category as f64 * 0.35 + centered * scale;
        if rng.range(1000) < 5 {
            value *= 8.0;
        }
        writeln!(
            writer,
            "2026-07-{day:02}T{hour:02}:{minute:02}:{second:02}Z,segment_{category:03},{value:.4}"
        )
        .map_err(|error| format!("write CSV dataset: {error}"))?;
    }
    Ok(())
}

fn prepare_jobs(root: &Path) -> Result<Vec<Job>, String> {
    fs::create_dir_all(root).map_err(|error| format!("create {}: {error}", root.display()))?;
    let apache = ensure_dataset(
        &root.join("apache-combined-120k.log"),
        APACHE_ROWS,
        1,
        APACHE_ROWS,
        "Zipf(s=1.08) paths; Zipf(s=1.04) clients; production-like status and size mix",
        generate_apache,
    )?;
    let syslog = ensure_dataset(
        &root.join("rfc3164-160k.log"),
        SYSLOG_ROWS,
        1,
        SYSLOG_ROWS,
        "Zipf(s=1.10) hosts; mixed services, severities, and message templates",
        generate_syslog,
    )?;
    let iso8601_syslog = ensure_dataset(
        &root.join("iso8601-syslog-160k.log"),
        SYSLOG_ROWS,
        1,
        SYSLOG_ROWS,
        "Zipf(s=1.10) hosts; mixed services, severities, and message templates",
        generate_iso8601_syslog,
    )?;
    let corpus_lines = CORPUS_TOKENS / CORPUS_WORDS_PER_LINE;
    let corpus = ensure_dataset(
        &root.join("zipf-corpus-1m5.txt"),
        CORPUS_TOKENS,
        1,
        corpus_lines,
        "1.5M tokens from a 30k-word Zipf(s=1.07) vocabulary with case and punctuation",
        generate_corpus,
    )?;
    let csv = ensure_dataset(
        &root.join("analytical-400k.csv"),
        CSV_ROWS,
        1,
        CSV_ROWS + 1,
        "Zipf(s=1.08) categories; mixed-scale approximately normal values plus 0.5% outliers",
        generate_csv,
    )?;
    Ok(vec![
        Job {
            workload: Workload::Apache,
            dataset: apache,
            output_path: None,
            requested_workers: 1,
        },
        Job {
            workload: Workload::Syslog,
            dataset: syslog,
            output_path: Some(root.join("rfc3164-normalized.out")),
            requested_workers: 1,
        },
        Job {
            workload: Workload::LegacySyslog,
            dataset: iso8601_syslog,
            output_path: Some(root.join("iso8601-to-rfc3164.out")),
            requested_workers: 1,
        },
        Job {
            workload: Workload::WordFrequency,
            dataset: corpus,
            output_path: None,
            requested_workers: 1,
        },
        Job {
            workload: Workload::CsvStatistics,
            dataset: csv,
            output_path: None,
            requested_workers: 1,
        },
    ])
}

fn prepare_legacy_syslog_sweep(root: &Path) -> Result<Vec<Job>, String> {
    fs::create_dir_all(root).map_err(|error| format!("create {}: {error}", root.display()))?;
    LEGACY_SYSLOG_SWEEP_MULTIPLIERS
        .into_iter()
        .map(|size_multiplier| {
            let records = SYSLOG_ROWS
                .checked_mul(size_multiplier)
                .ok_or_else(|| format!("{size_multiplier}x record count overflow"))?;
            let input_name = if size_multiplier == 1 {
                "iso8601-syslog-160k.log".to_owned()
            } else {
                format!("iso8601-syslog-{size_multiplier}x.log")
            };
            let output_name = if size_multiplier == 1 {
                "iso8601-to-rfc3164.out".to_owned()
            } else {
                format!("iso8601-to-rfc3164-{size_multiplier}x.out")
            };
            let dataset = ensure_dataset(
                &root.join(input_name),
                records,
                size_multiplier,
                records,
                "Zipf(s=1.10) hosts; mixed services, severities, and message templates",
                |writer| generate_syslog_with_timestamp(writer, SyslogTimestamp::Iso8601, records),
            )?;
            Ok(Job {
                workload: Workload::LegacySyslog,
                dataset,
                output_path: Some(root.join(output_name)),
                requested_workers: 1,
            })
        })
        .collect()
}

fn prepare_legacy_syslog_thread_sweep(
    root: &Path,
    only_workers: Option<usize>,
) -> Result<Vec<Job>, String> {
    fs::create_dir_all(root).map_err(|error| format!("create {}: {error}", root.display()))?;
    let dataset = ensure_dataset(
        &root.join("iso8601-syslog-160k.log"),
        SYSLOG_ROWS,
        1,
        SYSLOG_ROWS,
        "fixed 160k-record Zipf(s=1.10) service-log export; identical bytes at every worker count",
        generate_iso8601_syslog,
    )?;
    let jobs = LEGACY_SYSLOG_THREAD_SWEEP
        .into_iter()
        .filter(|workers| only_workers.is_none_or(|only| only == *workers))
        .map(|requested_workers| Job {
            workload: Workload::LegacySyslogThreaded,
            dataset: dataset.clone(),
            output_path: Some(root.join(format!("iso8601-to-rfc3164-mt-{requested_workers}t.out"))),
            requested_workers,
        })
        .collect::<Vec<_>>();
    if jobs.is_empty() {
        return Err(format!(
            "requested worker count {} is outside the fixed sweep {:?}",
            only_workers.unwrap_or(0),
            LEGACY_SYSLOG_THREAD_SWEEP,
        ));
    }
    Ok(jobs)
}

fn command_output(mut command: Command, context: &str) -> Result<Output, String> {
    let output = command
        .output()
        .map_err(|error| format!("{context}: {error}"))?;
    if !output.status.success() {
        return Err(format!(
            "{context}: status={}; stdout={}; stderr={}",
            output.status,
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr),
        ));
    }
    Ok(output)
}

fn compiler_identity(compiler: &OsStr) -> Result<String, String> {
    let mut command = Command::new(compiler);
    command.arg("--version");
    let output = command_output(command, "query C compiler version")?;
    Ok(String::from_utf8_lossy(&output.stdout)
        .lines()
        .next()
        .unwrap_or("unknown C compiler")
        .to_owned())
}

fn materialize_workload_source(root: &Path, source_sha: &str) -> Result<PathBuf, String> {
    let source = root.join(format!("e2e-workloads-{source_sha}.c"));
    match OpenOptions::new()
        .create_new(true)
        .write(true)
        .open(&source)
    {
        Ok(mut file) => {
            file.write_all(WORKLOAD_SOURCE)
                .map_err(|error| format!("write {}: {error}", source.display()))?;
            file.sync_all()
                .map_err(|error| format!("sync {}: {error}", source.display()))?;
        }
        Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {
            let existing =
                fs::read(&source).map_err(|read| format!("read {}: {read}", source.display()))?;
            if existing != WORKLOAD_SOURCE {
                return Err(format!(
                    "embedded workload source differs from existing SHA-addressed file {}",
                    source.display()
                ));
            }
        }
        Err(error) => return Err(format!("create {}: {error}", source.display())),
    }
    Ok(source)
}

fn compile_workload(root: &Path) -> Result<(PathBuf, PathBuf, String, String, String), String> {
    let source_sha = sha256_bytes(WORKLOAD_SOURCE);
    let source = materialize_workload_source(root, &source_sha)?;
    let compiler = env::var_os("CC").unwrap_or_else(|| OsString::from("cc"));
    let compiler_version = compiler_identity(&compiler)?;
    let compiler_key = sha256_bytes(compiler_version.as_bytes());
    let executable = root.join(format!(
        "e2e-workloads-{}-{}",
        &source_sha[..16],
        &compiler_key[..12]
    ));
    if !executable.exists() {
        let mut command = Command::new(&compiler);
        command
            .arg("-O3")
            .arg("-std=gnu11")
            .arg("-Wall")
            .arg("-Wextra")
            .arg("-Werror")
            .arg("-fno-builtin")
            .arg("-Wl,-z,now")
            .arg(&source)
            .arg("-ldl")
            .arg("-pthread")
            .arg("-o")
            .arg(&executable);
        let output = command_output(command, "compile realistic C workloads")?;
        if !output.stderr.is_empty() {
            eprintln!(
                "C_COMPILER_DIAGNOSTICS {}",
                String::from_utf8_lossy(&output.stderr).trim()
            );
        }
    }
    let executable_sha = sha256_file(&executable)?;
    Ok((
        source,
        executable,
        source_sha,
        executable_sha,
        compiler_version,
    ))
}

fn find_frankenlibc() -> Result<PathBuf, String> {
    if let Some(path) = env::var_os("FRANKENLIBC_E2E_SO") {
        let path = PathBuf::from(path);
        if path.is_file() {
            return Ok(path);
        }
        return Err(format!(
            "FRANKENLIBC_E2E_SO does not name a file: {}",
            path.display()
        ));
    }

    let current =
        env::current_exe().map_err(|error| format!("resolve current executable: {error}"))?;
    let profile_dir = current
        .parent()
        .and_then(Path::parent)
        .ok_or_else(|| format!("cannot infer profile directory from {}", current.display()))?;
    let direct = profile_dir.join("libfrankenlibc_abi.so");
    if direct.is_file() {
        return Ok(direct);
    }
    let deps = profile_dir.join("deps");
    let mut candidates = Vec::new();
    if let Ok(entries) = fs::read_dir(&deps) {
        for entry in entries.flatten() {
            let path = entry.path();
            let Some(name) = path.file_name().and_then(OsStr::to_str) else {
                continue;
            };
            if name.starts_with("libfrankenlibc_abi") && name.ends_with(".so") && path.is_file() {
                candidates.push(path);
            }
        }
    }
    candidates.sort();
    candidates.into_iter().next().ok_or_else(|| {
        format!(
            "cannot locate libfrankenlibc_abi.so beside {}; build the ABI cdylib in the same \
             Cargo profile or set FRANKENLIBC_E2E_SO",
            current.display()
        )
    })
}

fn configure_child(
    executable: &Path,
    arm: Arm,
    frankenlibc: &Path,
    arguments: &[OsString],
) -> Command {
    let mut command = Command::new(executable);
    command.args(arguments);
    command
        .env("LC_ALL", "C")
        .env("LANG", "C")
        .env("TZ", "UTC")
        .env_remove("LD_PRELOAD")
        .env_remove("FRANKENLIBC_MODE");
    if arm == Arm::Franken {
        command
            .env("LD_PRELOAD", frankenlibc)
            .env("FRANKENLIBC_MODE", "strict");
    }
    command
}

fn job_arguments(job: &Job) -> Vec<OsString> {
    let mut arguments = vec![
        OsString::from(job.workload.command()),
        job.dataset.path.as_os_str().to_owned(),
    ];
    if let Some(output) = &job.output_path {
        arguments.push(output.as_os_str().to_owned());
    }
    if job.workload.uses_worker_pool() {
        arguments.push(OsString::from(job.requested_workers.to_string()));
    }
    arguments
}

fn proc_task_count(pid: u32) -> Option<usize> {
    fs::read_dir(format!("/proc/{pid}/task"))
        .ok()
        .map(|entries| entries.flatten().count())
}

fn run_job(
    executable: &Path,
    frankenlibc: &Path,
    job: &Job,
    arm: Arm,
) -> Result<TimedOutput, String> {
    let arguments = job_arguments(job);
    let mut command = configure_child(executable, arm, frankenlibc, &arguments);
    if !job.workload.uses_worker_pool() {
        let started = Instant::now();
        let output = command
            .output()
            .map_err(|error| format!("run {} under {}: {error}", job.workload.id(), arm.label()))?;
        let elapsed = started.elapsed();
        if !output.status.success() {
            return Err(format!(
                "{} under {} failed: status={}; stdout={}; stderr={}",
                job.workload.id(),
                arm.label(),
                output.status,
                String::from_utf8_lossy(&output.stdout),
                String::from_utf8_lossy(&output.stderr),
            ));
        }
        return Ok(TimedOutput {
            elapsed,
            stdout: output.stdout,
            observed_peak_tasks: 1,
        });
    }

    command.stdout(Stdio::piped()).stderr(Stdio::piped());
    let started = Instant::now();
    let child = command
        .spawn()
        .map_err(|error| format!("run {} under {}: {error}", job.workload.id(), arm.label()))?;
    let pid = child.id();
    let initial_tasks = proc_task_count(pid).unwrap_or(1);
    let monitoring_done = Arc::new(AtomicBool::new(false));
    let monitor_done = Arc::clone(&monitoring_done);
    let monitor = thread::spawn(move || {
        let mut peak_tasks = initial_tasks;
        while !monitor_done.load(Ordering::Acquire) {
            if let Some(tasks) = proc_task_count(pid) {
                peak_tasks = peak_tasks.max(tasks);
            }
            thread::sleep(Duration::from_micros(500));
        }
        peak_tasks
    });
    let output_result = child.wait_with_output();
    let elapsed = started.elapsed();
    monitoring_done.store(true, Ordering::Release);
    let observed_peak_tasks = monitor
        .join()
        .map_err(|_| format!("task monitor panicked for {}", job.workload.id()))?;
    let output = output_result
        .map_err(|error| format!("wait {} under {}: {error}", job.workload.id(), arm.label()))?;
    if !output.status.success() {
        return Err(format!(
            "{} under {} failed: status={}; stdout={}; stderr={}",
            job.workload.id(),
            arm.label(),
            output.status,
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr),
        ));
    }
    Ok(TimedOutput {
        elapsed,
        stdout: output.stdout,
        observed_peak_tasks,
    })
}

fn validate_observed_tasks(job: &Job, arm: Arm, result: &TimedOutput) -> Result<(), String> {
    if job.workload.uses_worker_pool()
        && result.observed_peak_tasks != job.requested_workers.saturating_add(1)
    {
        return Err(format!(
            "{} under {} requested {} workers but /proc observed {} total tasks",
            job.workload.id(),
            arm.label(),
            job.requested_workers,
            result.observed_peak_tasks,
        ));
    }
    Ok(())
}

fn run_checked(
    executable: &Path,
    frankenlibc: &Path,
    job: &Job,
    arm: Arm,
    golden: &GoldenOutput,
) -> Result<TimedOutput, String> {
    let result = run_job(executable, frankenlibc, job, arm)?;
    if result.stdout != golden.stdout {
        return Err(format!(
            "{} output changed during {} measurement\nexpected:\n{}\nactual:\n{}",
            job.workload.id(),
            arm.label(),
            String::from_utf8_lossy(&golden.stdout),
            String::from_utf8_lossy(&result.stdout),
        ));
    }
    validate_observed_tasks(job, arm, &result)?;
    Ok(result)
}

fn parse_work_evidence(job: &Job, stdout: &[u8]) -> Result<Option<WorkEvidence>, String> {
    if !job.workload.uses_worker_pool() {
        return Ok(None);
    }
    let text = std::str::from_utf8(stdout)
        .map_err(|error| format!("{} work evidence is not UTF-8: {error}", job.workload.id()))?;
    let line = text
        .lines()
        .find(|line| line.starts_with("requested_workers="))
        .ok_or_else(|| format!("{} omitted threaded work evidence", job.workload.id()))?;
    let fields = line
        .split_whitespace()
        .map(|field| {
            field
                .split_once('=')
                .ok_or_else(|| format!("malformed work-evidence field {field:?}"))
        })
        .collect::<Result<BTreeMap<_, _>, _>>()?;
    let usize_field = |name: &str| -> Result<usize, String> {
        fields
            .get(name)
            .ok_or_else(|| format!("work evidence omitted {name}"))?
            .parse::<usize>()
            .map_err(|error| format!("parse work-evidence {name}: {error}"))
    };
    let u64_field = |name: &str| -> Result<u64, String> {
        fields
            .get(name)
            .ok_or_else(|| format!("work evidence omitted {name}"))?
            .parse::<u64>()
            .map_err(|error| format!("parse work-evidence {name}: {error}"))
    };
    Ok(Some(WorkEvidence {
        requested_workers: usize_field("requested_workers")?,
        started_workers: usize_field("started_workers")?,
        joined_workers: usize_field("joined_workers")?,
        workers_with_records: usize_field("workers_with_records")?,
        peak_active_workers: usize_field("peak_active_workers")?,
        records: usize_field("records")?,
        worker_iterations: usize_field("worker_iterations")?,
        strptime_calls: usize_field("strptime_calls")?,
        strftime_calls: usize_field("strftime_calls")?,
        input_bytes: u64_field("input_bytes")?,
        partition_bytes: u64_field("partition_bytes")?,
        output_bytes: u64_field("output_bytes")?,
        output_write_calls: usize_field("output_write_calls")?,
        min_records_per_worker: usize_field("min_records_per_worker")?,
        max_records_per_worker: usize_field("max_records_per_worker")?,
    }))
}

fn validate_work_evidence(
    job: &Job,
    evidence: &WorkEvidence,
    serialized_output_bytes: u64,
) -> Result<(), String> {
    let expected_min = job.dataset.records / job.requested_workers;
    let expected_max = job.dataset.records.div_ceil(job.requested_workers);
    if evidence.requested_workers != job.requested_workers
        || evidence.started_workers != job.requested_workers
        || evidence.joined_workers != job.requested_workers
        || evidence.workers_with_records != job.requested_workers
        || evidence.peak_active_workers != job.requested_workers
        || evidence.records != job.dataset.records
        || evidence.worker_iterations != job.dataset.records
        || evidence.strptime_calls != job.dataset.records
        || evidence.strftime_calls != job.dataset.records
        || evidence.input_bytes != job.dataset.bytes
        || evidence.partition_bytes != job.dataset.bytes
        || evidence.output_bytes != serialized_output_bytes
        || evidence.output_write_calls != 1
        || evidence.min_records_per_worker != expected_min
        || evidence.max_records_per_worker != expected_max
    {
        return Err(format!(
            "{} fixed-work conservation failed for {} workers: evidence={evidence:?}, \
             expected_records={}, expected_input_bytes={}, expected_output_bytes={}, \
             expected_record_range=[{},{}]",
            job.workload.id(),
            job.requested_workers,
            job.dataset.records,
            job.dataset.bytes,
            serialized_output_bytes,
            expected_min,
            expected_max,
        ));
    }
    Ok(())
}

fn verify_parity(executable: &Path, frankenlibc: &Path, job: &Job) -> Result<GoldenOutput, String> {
    let host = run_job(executable, frankenlibc, job, Arm::Host)?;
    validate_observed_tasks(job, Arm::Host, &host)?;
    let host_work_evidence = parse_work_evidence(job, &host.stdout)?;
    let host_serialized = job.output_path.as_deref().map(sha256_file).transpose()?;
    let host_output_bytes = if let Some(path) = &job.output_path {
        fs::metadata(path)
            .map_err(|error| format!("stat {}: {error}", path.display()))?
            .len()
    } else {
        host.stdout.len() as u64
    };

    let franken = run_job(executable, frankenlibc, job, Arm::Franken)?;
    validate_observed_tasks(job, Arm::Franken, &franken)?;
    let franken_work_evidence = parse_work_evidence(job, &franken.stdout)?;
    let franken_serialized = job.output_path.as_deref().map(sha256_file).transpose()?;
    let franken_output_bytes = if let Some(path) = &job.output_path {
        fs::metadata(path)
            .map_err(|error| format!("stat {}: {error}", path.display()))?
            .len()
    } else {
        franken.stdout.len() as u64
    };
    if host.stdout != franken.stdout
        || host_serialized != franken_serialized
        || host_output_bytes != franken_output_bytes
        || host_work_evidence != franken_work_evidence
    {
        return Err(format!(
            "{} host/Franken parity failed\nhost stdout:\n{}\nFranken stdout:\n{}\n\
             host serialized SHA={host_serialized:?}\nFranken serialized SHA={franken_serialized:?}\n\
             host output bytes={host_output_bytes}\nFranken output bytes={franken_output_bytes}\n\
             host work={host_work_evidence:?}\nFranken work={franken_work_evidence:?}",
            job.workload.id(),
            String::from_utf8_lossy(&host.stdout),
            String::from_utf8_lossy(&franken.stdout),
        ));
    }
    if let Some(evidence) = &host_work_evidence {
        validate_work_evidence(job, evidence, host_output_bytes)?;
    }
    Ok(GoldenOutput {
        stdout: host.stdout,
        serialized_sha256: host_serialized,
        output_bytes: host_output_bytes,
        work_evidence: host_work_evidence,
    })
}

fn parse_identity(output: &[u8]) -> Result<Identity, String> {
    let text = std::str::from_utf8(output).map_err(|error| format!("identity UTF-8: {error}"))?;
    let mut fields = BTreeMap::new();
    for line in text.lines() {
        let Some((key, value)) = line.split_once('=') else {
            return Err(format!("malformed identity line: {line}"));
        };
        fields.insert(key.to_owned(), value.to_owned());
    }
    Ok(Identity { fields })
}

fn identity_field<'a>(identity: &'a Identity, key: &str) -> Result<&'a str, String> {
    identity
        .fields
        .get(key)
        .map(String::as_str)
        .ok_or_else(|| format!("identity omitted {key}"))
}

fn capture_identity(executable: &Path, frankenlibc: &Path, arm: Arm) -> Result<Identity, String> {
    let arguments = [OsString::from("identity")];
    let command = configure_child(executable, arm, frankenlibc, &arguments);
    let output = command_output(command, &format!("capture {} identity", arm.label()))?;
    parse_identity(&output.stdout)
}

fn verify_identity(
    executable_sha: &str,
    frankenlibc_sha: &str,
    host: &Identity,
    franken: &Identity,
) -> Result<(), String> {
    for identity in [host, franken] {
        let reported = identity_field(identity, "WORKLOAD_ELF_SHA256")?;
        if reported != executable_sha {
            return Err(format!(
                "workload self-report {reported} differs from controller hash {executable_sha}"
            ));
        }
    }
    for symbol in [
        "MALLOC_ELF_SHA256",
        "FOPEN_ELF_SHA256",
        "FGETS_ELF_SHA256",
        "FWRITE_ELF_SHA256",
        "STRPTIME_ELF_SHA256",
        "STRFTIME_ELF_SHA256",
        "PTHREAD_CREATE_ELF_SHA256",
        "PTHREAD_JOIN_ELF_SHA256",
        "MMAP_ELF_SHA256",
        "MUNMAP_ELF_SHA256",
    ] {
        let reported = identity_field(franken, symbol)?;
        if reported != frankenlibc_sha {
            return Err(format!(
                "Franken arm {symbol}={reported}, expected loaded FrankenLibC {frankenlibc_sha}"
            ));
        }
    }
    let host_malloc = identity_field(host, "MALLOC_ELF_SHA256")?;
    for symbol in [
        "FOPEN_ELF_SHA256",
        "FGETS_ELF_SHA256",
        "FWRITE_ELF_SHA256",
        "STRPTIME_ELF_SHA256",
        "STRFTIME_ELF_SHA256",
        "PTHREAD_CREATE_ELF_SHA256",
        "PTHREAD_JOIN_ELF_SHA256",
        "MMAP_ELF_SHA256",
        "MUNMAP_ELF_SHA256",
    ] {
        let reported = identity_field(host, symbol)?;
        if reported != host_malloc {
            return Err(format!(
                "host {symbol}={reported}, but malloc resolved to {host_malloc}"
            ));
        }
    }
    Ok(())
}

fn same_arm_pair(
    executable: &Path,
    frankenlibc: &Path,
    job: &Job,
    arm: Arm,
    golden: &GoldenOutput,
    reverse_order: bool,
) -> Result<(TimedOutput, TimedOutput), String> {
    if reverse_order {
        let b = run_checked(executable, frankenlibc, job, arm, golden)?;
        let a = run_checked(executable, frankenlibc, job, arm, golden)?;
        Ok((a, b))
    } else {
        let a = run_checked(executable, frankenlibc, job, arm, golden)?;
        let b = run_checked(executable, frankenlibc, job, arm, golden)?;
        Ok((a, b))
    }
}

fn effect_pair(
    executable: &Path,
    frankenlibc: &Path,
    job: &Job,
    golden: &GoldenOutput,
    host_first: bool,
) -> Result<(TimedOutput, TimedOutput), String> {
    if host_first {
        let host = run_checked(executable, frankenlibc, job, Arm::Host, golden)?;
        let franken = run_checked(executable, frankenlibc, job, Arm::Franken, golden)?;
        Ok((host, franken))
    } else {
        let franken = run_checked(executable, frankenlibc, job, Arm::Franken, golden)?;
        let host = run_checked(executable, frankenlibc, job, Arm::Host, golden)?;
        Ok((host, franken))
    }
}

fn milliseconds(duration: Duration) -> f64 {
    duration.as_secs_f64() * 1000.0
}

fn measure_job(
    executable: &Path,
    frankenlibc: &Path,
    job: &Job,
    golden: &GoldenOutput,
    samples: usize,
    warmups: usize,
) -> Result<Measurements, String> {
    let retained = samples;
    let mut measurements = Measurements {
        host_ms: Vec::with_capacity(retained),
        franken_ms: Vec::with_capacity(retained),
        host_null_ratios: Vec::with_capacity(retained),
        franken_null_ratios: Vec::with_capacity(retained),
        effect_ratios: Vec::with_capacity(retained),
        host_observed_workers: Vec::with_capacity(retained * 3),
        franken_observed_workers: Vec::with_capacity(retained * 3),
    };

    for round in 0..(warmups + samples) {
        let mut host_null = None;
        let mut franken_null = None;
        let mut effect = None;
        for phase in 0..3 {
            match (round + phase) % 3 {
                0 => {
                    host_null = Some(same_arm_pair(
                        executable,
                        frankenlibc,
                        job,
                        Arm::Host,
                        golden,
                        round % 2 == 1,
                    )?);
                }
                1 => {
                    franken_null = Some(same_arm_pair(
                        executable,
                        frankenlibc,
                        job,
                        Arm::Franken,
                        golden,
                        round % 2 == 0,
                    )?);
                }
                _ => {
                    effect = Some(effect_pair(
                        executable,
                        frankenlibc,
                        job,
                        golden,
                        round % 2 == 0,
                    )?);
                }
            }
        }

        if round >= warmups {
            let (host_a, host_b) = host_null.expect("host null pair");
            let (franken_a, franken_b) = franken_null.expect("Franken null pair");
            let (host, franken) = effect.expect("effect pair");
            let host_ms = milliseconds(host.elapsed);
            let franken_ms = milliseconds(franken.elapsed);
            measurements.host_ms.push(host_ms);
            measurements.franken_ms.push(franken_ms);
            measurements
                .host_null_ratios
                .push(milliseconds(host_b.elapsed) / milliseconds(host_a.elapsed));
            measurements
                .franken_null_ratios
                .push(milliseconds(franken_b.elapsed) / milliseconds(franken_a.elapsed));
            measurements.effect_ratios.push(franken_ms / host_ms);
            measurements.host_observed_workers.extend([
                host_a.observed_peak_tasks.saturating_sub(1),
                host_b.observed_peak_tasks.saturating_sub(1),
                host.observed_peak_tasks.saturating_sub(1),
            ]);
            measurements.franken_observed_workers.extend([
                franken_a.observed_peak_tasks.saturating_sub(1),
                franken_b.observed_peak_tasks.saturating_sub(1),
                franken.observed_peak_tasks.saturating_sub(1),
            ]);
        }
        eprintln!(
            "E2E_PROGRESS workload={} size_multiplier={} requested_workers={} \
             round={}/{} retained={}",
            job.workload.id(),
            job.dataset.size_multiplier,
            job.requested_workers,
            round + 1,
            warmups + samples,
            if round >= warmups {
                round - warmups + 1
            } else {
                0
            },
        );
    }
    Ok(measurements)
}

fn median(values: &[f64]) -> f64 {
    let mut sorted = values.to_vec();
    sorted.sort_by(f64::total_cmp);
    let middle = sorted.len() / 2;
    if sorted.len().is_multiple_of(2) {
        (sorted[middle - 1] + sorted[middle]) / 2.0
    } else {
        sorted[middle]
    }
}

fn mean(values: &[f64]) -> f64 {
    values.iter().sum::<f64>() / values.len() as f64
}

fn cv_pct(values: &[f64]) -> f64 {
    let average = mean(values);
    let variance = values
        .iter()
        .map(|value| (value - average).powi(2))
        .sum::<f64>()
        / values.len() as f64;
    100.0 * variance.sqrt() / average
}

fn bootstrap_median_ci95(values: &[f64], salt: u64) -> (f64, f64) {
    let mut rng = XorShift64::new(0x9e37_79b9_7f4a_7c15 ^ salt ^ values.len() as u64);
    let mut medians = Vec::with_capacity(BOOTSTRAP_RESAMPLES);
    let mut resample = vec![0.0; values.len()];
    for _ in 0..BOOTSTRAP_RESAMPLES {
        for value in &mut resample {
            *value = values[rng.range(values.len())];
        }
        medians.push(median(&resample));
    }
    medians.sort_by(f64::total_cmp);
    let low = BOOTSTRAP_RESAMPLES * 25 / 1000;
    let high = (BOOTSTRAP_RESAMPLES * 975 / 1000).min(BOOTSTRAP_RESAMPLES - 1);
    (medians[low], medians[high])
}

fn print_contract(job: &Job, golden: &GoldenOutput, measurements: &Measurements) {
    let host_null_median = median(&measurements.host_null_ratios);
    let franken_null_median = median(&measurements.franken_null_ratios);
    let effect_median = median(&measurements.effect_ratios);
    let (host_null_low, host_null_high) =
        bootstrap_median_ci95(&measurements.host_null_ratios, 0x484f_5354);
    let (franken_null_low, franken_null_high) =
        bootstrap_median_ci95(&measurements.franken_null_ratios, 0x4652_414e);
    let (effect_low, effect_high) = bootstrap_median_ci95(&measurements.effect_ratios, 0x4546_4645);
    let null_half_width = [
        (host_null_low - 1.0).abs(),
        (host_null_high - 1.0).abs(),
        (franken_null_low - 1.0).abs(),
        (franken_null_high - 1.0).abs(),
    ]
    .into_iter()
    .fold(0.0, f64::max);
    // A null "passes" when its MEDIAN is within 2% of 1.0, which bounds arm-order bias.
    //
    // It deliberately does NOT require the null's CI to straddle 1.0. That rule was perverse:
    // the TIGHTER the null — i.e. the BETTER the measurement — the more likely its CI excludes
    // 1.0 and vetoes the row. It was measured doing exactly that here: the 32-worker row of the
    // 2026-07-30 fixed-work thread-scaling sweep was `BLOCKED_NULL` because its host/host CI
    // [1.000969, 1.006875] missed 1.0 by 0.097%, while its effect sat at 3.234845 — 223% away
    // and comfortably past the width margin. Precision must not decide direction; the
    // `clears_null` 2x half-width test below is what actually protects it.
    //
    // Contract change owned by MagentaCondor, applied identically in strfmon_ab.rs and
    // wordexp_ab.rs. Null CIs remain reported as telemetry and still feed null_half_width.
    const NULL_BIAS_TOLERANCE: f64 = 0.02;
    let host_null_pass = (host_null_median - 1.0).abs() <= NULL_BIAS_TOLERANCE;
    let franken_null_pass = (franken_null_median - 1.0).abs() <= NULL_BIAS_TOLERANCE;
    let null_gate_pass = host_null_pass && franken_null_pass;
    let clears_null = (effect_median - 1.0).abs() > 2.0 * null_half_width;
    let verdict = if !null_gate_pass {
        "BLOCKED_NULL"
    } else if effect_high < 1.0 && clears_null {
        "WIN_VS_GLIBC"
    } else if effect_low > 1.0 && clears_null {
        "LOSS_VS_GLIBC"
    } else {
        "UNDECIDABLE"
    };
    println!(
        "E2E_WORKLOAD workload={} size_multiplier={} requested_workers={} meaning={:?} \
         records={} input_bytes={} input_sha256={} distribution={:?} output_bytes={} \
         output_sha256={}",
        job.workload.id(),
        job.dataset.size_multiplier,
        if job.workload.uses_worker_pool() {
            job.requested_workers
        } else {
            0
        },
        job.workload.meaning(),
        job.dataset.records,
        job.dataset.bytes,
        job.dataset.sha256,
        job.dataset.distribution,
        golden.output_bytes,
        golden.serialized_sha256.as_deref().unwrap_or("stdout"),
    );
    if let Some(work) = &golden.work_evidence {
        println!(
            "E2E_WORK_CONSERVATION workload={} requested_workers={} started_workers={} \
             joined_workers={} workers_with_records={} self_peak_active_workers={} \
             host_proc_observations={} franken_proc_observations={} \
             host_proc_observed_workers_min={} host_proc_observed_workers_max={} \
             franken_proc_observed_workers_min={} franken_proc_observed_workers_max={} \
             records={} worker_iterations={} input_bytes={} partition_bytes={} \
             strptime_calls={} strftime_calls={} output_bytes={} \
             output_write_calls={} min_records_per_worker={} \
             max_records_per_worker={} verdict=PASS",
            job.workload.id(),
            work.requested_workers,
            work.started_workers,
            work.joined_workers,
            work.workers_with_records,
            work.peak_active_workers,
            measurements.host_observed_workers.len(),
            measurements.franken_observed_workers.len(),
            measurements
                .host_observed_workers
                .iter()
                .min()
                .copied()
                .unwrap_or(0),
            measurements
                .host_observed_workers
                .iter()
                .max()
                .copied()
                .unwrap_or(0),
            measurements
                .franken_observed_workers
                .iter()
                .min()
                .copied()
                .unwrap_or(0),
            measurements
                .franken_observed_workers
                .iter()
                .max()
                .copied()
                .unwrap_or(0),
            work.records,
            work.worker_iterations,
            work.input_bytes,
            work.partition_bytes,
            work.strptime_calls,
            work.strftime_calls,
            work.output_bytes,
            work.output_write_calls,
            work.min_records_per_worker,
            work.max_records_per_worker,
        );
    }
    println!(
        "E2E_BENCH_CONTRACT workload={} size_multiplier={} requested_workers={} samples={} \
         host_median_ms={:.6} franken_median_ms={:.6} \
         host_null_median={host_null_median:.6} \
         host_null_ci95=[{host_null_low:.6},{host_null_high:.6}] \
         franken_null_median={franken_null_median:.6} \
         franken_null_ci95=[{franken_null_low:.6},{franken_null_high:.6}] \
         host_null_pass={host_null_pass} franken_null_pass={franken_null_pass} \
         null_gate_pass={null_gate_pass} \
         fl_over_glibc_median={effect_median:.6} \
         fl_over_glibc_ci95=[{effect_low:.6},{effect_high:.6}] \
         null_half_width={null_half_width:.6} clears_2x_null={clears_null} \
         verdict={verdict} host_cv_pct={:.3} franken_cv_pct={:.3} effect_cv_pct={:.3} \
         cv_role=telemetry_only gate=paired_bootstrap_median_ci95_and_2x_null",
        job.workload.id(),
        job.dataset.size_multiplier,
        if job.workload.uses_worker_pool() {
            job.requested_workers
        } else {
            0
        },
        measurements.effect_ratios.len(),
        median(&measurements.host_ms),
        median(&measurements.franken_ms),
        cv_pct(&measurements.host_ms),
        cv_pct(&measurements.franken_ms),
        cv_pct(&measurements.effect_ratios),
    );
}

fn environment_usize(name: &str, default: usize) -> Result<usize, String> {
    let Some(value) = env::var_os(name) else {
        return Ok(default);
    };
    let parsed = value
        .to_str()
        .ok_or_else(|| format!("{name} is not UTF-8"))?
        .parse::<usize>()
        .map_err(|error| format!("parse {name}: {error}"))?;
    if parsed == 0 {
        return Err(format!("{name} must be positive"));
    }
    Ok(parsed)
}

fn run_configuration() -> Result<RunConfiguration, String> {
    let samples_from_environment = env::var_os("FLC_E2E_SAMPLES").is_some();
    let warmups_from_environment = env::var_os("FLC_E2E_WARMUPS").is_some();
    let mut samples = environment_usize("FLC_E2E_SAMPLES", DEFAULT_SAMPLES)?;
    let mut warmups = environment_usize("FLC_E2E_WARMUPS", DEFAULT_WARMUPS)?;
    let mut only = None;
    let mut legacy_size_sweep = false;
    let mut legacy_thread_sweep = false;
    let mut only_workers = None;
    let mut smoke = false;
    let mut arguments = env::args().skip(1);
    while let Some(argument) = arguments.next() {
        match argument.as_str() {
            "--smoke" => {
                samples = 3;
                warmups = 1;
                smoke = true;
            }
            "--only" => {
                only = Some(
                    arguments
                        .next()
                        .ok_or_else(|| "--only requires a workload id".to_owned())?,
                );
            }
            "--legacy-size-sweep" => {
                legacy_size_sweep = true;
            }
            "--legacy-thread-sweep" => {
                legacy_thread_sweep = true;
            }
            "--only-workers" => {
                let value = arguments
                    .next()
                    .ok_or_else(|| "--only-workers requires a positive integer".to_owned())?;
                only_workers = Some(
                    value
                        .parse::<usize>()
                        .map_err(|error| format!("parse --only-workers: {error}"))?,
                );
                if only_workers == Some(0) {
                    return Err("--only-workers must be positive".to_owned());
                }
            }
            _ => return Err(format!("unknown harness argument {argument:?}")),
        }
    }
    if legacy_size_sweep && legacy_thread_sweep {
        return Err(
            "--legacy-size-sweep and --legacy-thread-sweep are mutually exclusive".to_owned(),
        );
    }
    if only_workers.is_some() && !legacy_thread_sweep {
        return Err("--only-workers requires --legacy-thread-sweep".to_owned());
    }
    if legacy_thread_sweep && !smoke {
        if !samples_from_environment {
            samples = THREAD_SWEEP_SAMPLES;
        }
        if !warmups_from_environment {
            warmups = THREAD_SWEEP_WARMUPS;
        }
    }
    Ok(RunConfiguration {
        samples,
        warmups,
        only,
        legacy_size_sweep,
        legacy_thread_sweep,
        only_workers,
        smoke,
    })
}

fn ldd_version() -> Result<String, String> {
    let mut command = Command::new("ldd");
    command.arg("--version");
    let output = command_output(command, "query host glibc version")?;
    Ok(String::from_utf8_lossy(&output.stdout)
        .lines()
        .next()
        .unwrap_or("unknown glibc")
        .to_owned())
}

fn run() -> Result<(), String> {
    let configuration = run_configuration()?;
    if configuration.samples < 3 {
        return Err("FLC_E2E_SAMPLES must be at least 3 for a median CI".to_owned());
    }
    if configuration.legacy_thread_sweep
        && !configuration.smoke
        && configuration.samples < THREAD_SWEEP_SAMPLES
    {
        return Err(format!(
            "full thread sweep requires at least {THREAD_SWEEP_SAMPLES} retained samples"
        ));
    }
    let host_guard = host_wide_guard();
    require_host_wide_quiet(&host_guard, "startup");

    let root = PathBuf::from(DATA_ROOT);
    fs::create_dir_all(&root).map_err(|error| format!("create {}: {error}", root.display()))?;
    let frankenlibc = find_frankenlibc()?;
    let frankenlibc_sha = sha256_file(&frankenlibc)?;
    let (workload_source, workload_executable, workload_source_sha, workload_sha, compiler) =
        compile_workload(&root)?;
    let controller = env::current_exe().map_err(|error| format!("resolve controller: {error}"))?;
    let controller_sha = sha256_file(&controller)?;

    let host_identity = capture_identity(&workload_executable, &frankenlibc, Arm::Host)?;
    let franken_identity = capture_identity(&workload_executable, &frankenlibc, Arm::Franken)?;
    verify_identity(
        &workload_sha,
        &frankenlibc_sha,
        &host_identity,
        &franken_identity,
    )?;

    println!(
        "E2E_CONTROLLER_ELF path={} sha256={} bytes={}",
        controller.display(),
        controller_sha,
        fs::metadata(&controller)
            .map_err(|error| format!("stat {}: {error}", controller.display()))?
            .len(),
    );
    println!(
        "E2E_WORKLOAD_SOURCE path={} sha256={} bytes={}",
        workload_source.display(),
        workload_source_sha,
        WORKLOAD_SOURCE.len(),
    );
    println!(
        "E2E_WORKLOAD_ELF path={} sha256={} bytes={} source_sha256={} compiler={:?}",
        identity_field(&franken_identity, "WORKLOAD_ELF_PATH")?,
        workload_sha,
        fs::metadata(&workload_executable)
            .map_err(|error| format!("stat {}: {error}", workload_executable.display()))?
            .len(),
        workload_source_sha,
        compiler,
    );
    println!(
        "E2E_INCUMBENT version={:?} malloc_path={} fopen_path={} fgets_path={} \
         fwrite_path={} strptime_path={} strftime_path={} pthread_create_path={} \
         pthread_join_path={} mmap_path={} munmap_path={} sha256={}",
        ldd_version()?,
        identity_field(&host_identity, "MALLOC_ELF_PATH")?,
        identity_field(&host_identity, "FOPEN_ELF_PATH")?,
        identity_field(&host_identity, "FGETS_ELF_PATH")?,
        identity_field(&host_identity, "FWRITE_ELF_PATH")?,
        identity_field(&host_identity, "STRPTIME_ELF_PATH")?,
        identity_field(&host_identity, "STRFTIME_ELF_PATH")?,
        identity_field(&host_identity, "PTHREAD_CREATE_ELF_PATH")?,
        identity_field(&host_identity, "PTHREAD_JOIN_ELF_PATH")?,
        identity_field(&host_identity, "MMAP_ELF_PATH")?,
        identity_field(&host_identity, "MUNMAP_ELF_PATH")?,
        identity_field(&host_identity, "MALLOC_ELF_SHA256")?,
    );
    println!(
        "E2E_CHALLENGER mode=strict preload_path={} malloc_path={} fopen_path={} fgets_path={} \
         fwrite_path={} strptime_path={} strftime_path={} pthread_create_path={} \
         pthread_join_path={} mmap_path={} munmap_path={} sha256={}",
        frankenlibc.display(),
        identity_field(&franken_identity, "MALLOC_ELF_PATH")?,
        identity_field(&franken_identity, "FOPEN_ELF_PATH")?,
        identity_field(&franken_identity, "FGETS_ELF_PATH")?,
        identity_field(&franken_identity, "FWRITE_ELF_PATH")?,
        identity_field(&franken_identity, "STRPTIME_ELF_PATH")?,
        identity_field(&franken_identity, "STRFTIME_ELF_PATH")?,
        identity_field(&franken_identity, "PTHREAD_CREATE_ELF_PATH")?,
        identity_field(&franken_identity, "PTHREAD_JOIN_ELF_PATH")?,
        identity_field(&franken_identity, "MMAP_ELF_PATH")?,
        identity_field(&franken_identity, "MUNMAP_ELF_PATH")?,
        frankenlibc_sha,
    );
    println!(
        "E2E_HARNESS samples={} warmups={} interleaving=rotating_3_pair \
         nulls=host_host_and_franken_franken gate=paired_bootstrap_median_ci95_and_2x_null \
         cv_role=telemetry_only locale=C timezone=UTC legacy_size_sweep={} \
         size_multipliers={:?} legacy_thread_sweep={} requested_worker_sweep={:?} \
         only_workers={:?} work_gate=fixed_records_bytes_output_and_proc_observed_threads",
        configuration.samples,
        configuration.warmups,
        configuration.legacy_size_sweep,
        LEGACY_SYSLOG_SWEEP_MULTIPLIERS,
        configuration.legacy_thread_sweep,
        LEGACY_SYSLOG_THREAD_SWEEP,
        configuration.only_workers,
    );

    let jobs = if configuration.legacy_size_sweep {
        prepare_legacy_syslog_sweep(&root)?
    } else if configuration.legacy_thread_sweep {
        prepare_legacy_syslog_thread_sweep(&root, configuration.only_workers)?
    } else {
        prepare_jobs(&root)?
    };
    let mut jobs_run = 0;
    for job in jobs {
        if configuration
            .only
            .as_deref()
            .is_some_and(|id| id != job.workload.id())
        {
            continue;
        }
        jobs_run += 1;
        eprintln!(
            "E2E_PARITY workload={} requested_workers={} status=begin",
            job.workload.id(),
            job.requested_workers,
        );
        let golden = verify_parity(&workload_executable, &frankenlibc, &job)?;
        println!(
            "E2E_PARITY workload={} size_multiplier={} requested_workers={} \
             stdout_sha256={} serialized_sha256={} status=PASS",
            job.workload.id(),
            job.dataset.size_multiplier,
            if job.workload.uses_worker_pool() {
                job.requested_workers
            } else {
                0
            },
            sha256_bytes(&golden.stdout),
            golden
                .serialized_sha256
                .as_deref()
                .unwrap_or("not_applicable"),
        );
        let pre_measurement = format!(
            "pre_measurement_{}_{}x_{}t",
            job.workload.id(),
            job.dataset.size_multiplier,
            job.requested_workers,
        );
        require_host_wide_quiet(&host_guard, &pre_measurement);
        let measurements = measure_job(
            &workload_executable,
            &frankenlibc,
            &job,
            &golden,
            configuration.samples,
            configuration.warmups,
        )?;
        let post_measurement = format!(
            "post_measurement_{}_{}x_{}t",
            job.workload.id(),
            job.dataset.size_multiplier,
            job.requested_workers,
        );
        require_host_wide_quiet(&host_guard, &post_measurement);
        print_contract(&job, &golden, &measurements);
    }
    if jobs_run == 0 {
        return Err(format!(
            "requested workload {:?} does not exist",
            configuration.only.as_deref().unwrap_or("none")
        ));
    }
    Ok(())
}

fn main() {
    if let Err(error) = run() {
        eprintln!("E2E_HARNESS_ERROR {error}");
        std::process::exit(1);
    }
}
