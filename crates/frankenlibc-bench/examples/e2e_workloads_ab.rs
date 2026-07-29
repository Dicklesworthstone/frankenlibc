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
use std::process::{Command, Output};
use std::time::{Duration, Instant};

use sha2::{Digest, Sha256};

const DEFAULT_SAMPLES: usize = 15;
const DEFAULT_WARMUPS: usize = 2;
const BOOTSTRAP_RESAMPLES: usize = 4096;
const DATA_ROOT: &str = "/data/tmp/frankenlibc-e2e-data-v1";

const APACHE_ROWS: usize = 120_000;
const SYSLOG_ROWS: usize = 160_000;
const CORPUS_TOKENS: usize = 1_500_000;
const CORPUS_WORDS_PER_LINE: usize = 50;
const CSV_ROWS: usize = 400_000;

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
    WordFrequency,
    CsvStatistics,
}

impl Workload {
    fn id(self) -> &'static str {
        match self {
            Self::Apache => "flc_e2e_apache_v1",
            Self::Syslog => "flc_e2e_rfc3164_v1",
            Self::WordFrequency => "flc_e2e_zipf_corpus_v1",
            Self::CsvStatistics => "flc_e2e_zipf_csv_v1",
        }
    }

    fn command(self) -> &'static str {
        match self {
            Self::Apache => "logparse",
            Self::Syslog => "tsreformat",
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
            Self::WordFrequency => {
                "scan a Zipf-skewed text corpus and emit a sorted word-frequency report"
            }
            Self::CsvStatistics => {
                "parse a skewed analytical CSV and emit grouped numeric statistics"
            }
        }
    }
}

struct Dataset {
    path: PathBuf,
    records: usize,
    bytes: u64,
    sha256: String,
    distribution: &'static str,
}

struct Job {
    workload: Workload,
    dataset: Dataset,
    output_path: Option<PathBuf>,
}

struct GoldenOutput {
    stdout: Vec<u8>,
    serialized_sha256: Option<String>,
    output_bytes: u64,
}

struct TimedOutput {
    elapsed: Duration,
    stdout: Vec<u8>,
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

fn generate_syslog(writer: &mut BufWriter<File>) -> Result<(), String> {
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
    for row in 0..SYSLOG_ROWS {
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
        writeln!(
            writer,
            "Jul {day:2} {hour:02}:{minute:02}:{second:02} node-{host:03} \
             {service}[{}]: severity={severity} {message} request_id={row:08x}",
            1000 + rng.range(55_000),
        )
        .map_err(|error| format!("write syslog dataset: {error}"))?;
    }
    Ok(())
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
        APACHE_ROWS,
        "Zipf(s=1.08) paths; Zipf(s=1.04) clients; production-like status and size mix",
        generate_apache,
    )?;
    let syslog = ensure_dataset(
        &root.join("rfc3164-160k.log"),
        SYSLOG_ROWS,
        SYSLOG_ROWS,
        "Zipf(s=1.10) hosts; mixed services, severities, and message templates",
        generate_syslog,
    )?;
    let corpus_lines = CORPUS_TOKENS / CORPUS_WORDS_PER_LINE;
    let corpus = ensure_dataset(
        &root.join("zipf-corpus-1m5.txt"),
        CORPUS_TOKENS,
        corpus_lines,
        "1.5M tokens from a 30k-word Zipf(s=1.07) vocabulary with case and punctuation",
        generate_corpus,
    )?;
    let csv = ensure_dataset(
        &root.join("analytical-400k.csv"),
        CSV_ROWS,
        CSV_ROWS + 1,
        "Zipf(s=1.08) categories; mixed-scale approximately normal values plus 0.5% outliers",
        generate_csv,
    )?;
    Ok(vec![
        Job {
            workload: Workload::Apache,
            dataset: apache,
            output_path: None,
        },
        Job {
            workload: Workload::Syslog,
            dataset: syslog,
            output_path: Some(root.join("rfc3164-normalized.out")),
        },
        Job {
            workload: Workload::WordFrequency,
            dataset: corpus,
            output_path: None,
        },
        Job {
            workload: Workload::CsvStatistics,
            dataset: csv,
            output_path: None,
        },
    ])
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

fn compile_workload(root: &Path) -> Result<(PathBuf, String, String), String> {
    let source = Path::new(env!("CARGO_MANIFEST_DIR")).join("workloads/e2e_workloads.c");
    let source_bytes =
        fs::read(&source).map_err(|error| format!("read {}: {error}", source.display()))?;
    let source_sha = sha256_bytes(&source_bytes);
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
    Ok((executable, executable_sha, compiler_version))
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
    arguments: &[&OsStr],
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

fn job_arguments(job: &Job) -> Vec<&OsStr> {
    let mut arguments = vec![
        OsStr::new(job.workload.command()),
        job.dataset.path.as_os_str(),
    ];
    if let Some(output) = &job.output_path {
        arguments.push(output.as_os_str());
    }
    arguments
}

fn run_job(
    executable: &Path,
    frankenlibc: &Path,
    job: &Job,
    arm: Arm,
) -> Result<TimedOutput, String> {
    let arguments = job_arguments(job);
    let mut command = configure_child(executable, arm, frankenlibc, &arguments);
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
    Ok(TimedOutput {
        elapsed,
        stdout: output.stdout,
    })
}

fn run_checked(
    executable: &Path,
    frankenlibc: &Path,
    job: &Job,
    arm: Arm,
    golden: &GoldenOutput,
) -> Result<Duration, String> {
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
    Ok(result.elapsed)
}

fn verify_parity(executable: &Path, frankenlibc: &Path, job: &Job) -> Result<GoldenOutput, String> {
    let host = run_job(executable, frankenlibc, job, Arm::Host)?;
    let host_serialized = job.output_path.as_deref().map(sha256_file).transpose()?;
    let host_output_bytes = if let Some(path) = &job.output_path {
        fs::metadata(path)
            .map_err(|error| format!("stat {}: {error}", path.display()))?
            .len()
    } else {
        host.stdout.len() as u64
    };

    let franken = run_job(executable, frankenlibc, job, Arm::Franken)?;
    let franken_serialized = job.output_path.as_deref().map(sha256_file).transpose()?;
    if host.stdout != franken.stdout || host_serialized != franken_serialized {
        return Err(format!(
            "{} host/Franken parity failed\nhost stdout:\n{}\nFranken stdout:\n{}\n\
             host serialized SHA={host_serialized:?}\nFranken serialized SHA={franken_serialized:?}",
            job.workload.id(),
            String::from_utf8_lossy(&host.stdout),
            String::from_utf8_lossy(&franken.stdout),
        ));
    }
    Ok(GoldenOutput {
        stdout: host.stdout,
        serialized_sha256: host_serialized,
        output_bytes: host_output_bytes,
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
    let arguments = [OsStr::new("identity")];
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
        "STRFTIME_ELF_SHA256",
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
        "STRFTIME_ELF_SHA256",
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
) -> Result<(Duration, Duration), String> {
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
) -> Result<(Duration, Duration), String> {
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
            let host_ms = milliseconds(host);
            let franken_ms = milliseconds(franken);
            measurements.host_ms.push(host_ms);
            measurements.franken_ms.push(franken_ms);
            measurements
                .host_null_ratios
                .push(milliseconds(host_b) / milliseconds(host_a));
            measurements
                .franken_null_ratios
                .push(milliseconds(franken_b) / milliseconds(franken_a));
            measurements.effect_ratios.push(franken_ms / host_ms);
        }
        eprintln!(
            "E2E_PROGRESS workload={} round={}/{} retained={}",
            job.workload.id(),
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
    let clears_null = (effect_median - 1.0).abs() > 2.0 * null_half_width;
    let verdict = if effect_high < 1.0 && clears_null {
        "WIN_VS_GLIBC"
    } else if effect_low > 1.0 && clears_null {
        "LOSS_VS_GLIBC"
    } else {
        "UNDECIDABLE"
    };
    println!(
        "E2E_WORKLOAD workload={} meaning={:?} records={} input_bytes={} input_sha256={} \
         distribution={:?} output_bytes={} output_sha256={}",
        job.workload.id(),
        job.workload.meaning(),
        job.dataset.records,
        job.dataset.bytes,
        job.dataset.sha256,
        job.dataset.distribution,
        golden.output_bytes,
        golden.serialized_sha256.as_deref().unwrap_or("stdout"),
    );
    println!(
        "E2E_BENCH_CONTRACT workload={} samples={} host_median_ms={:.6} \
         franken_median_ms={:.6} host_null_median={host_null_median:.6} \
         host_null_ci95=[{host_null_low:.6},{host_null_high:.6}] \
         franken_null_median={franken_null_median:.6} \
         franken_null_ci95=[{franken_null_low:.6},{franken_null_high:.6}] \
         fl_over_glibc_median={effect_median:.6} \
         fl_over_glibc_ci95=[{effect_low:.6},{effect_high:.6}] \
         null_half_width={null_half_width:.6} clears_2x_null={clears_null} \
         verdict={verdict} host_cv_pct={:.3} franken_cv_pct={:.3} effect_cv_pct={:.3} \
         cv_role=telemetry_only gate=paired_bootstrap_median_ci95_and_2x_null",
        job.workload.id(),
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

fn run_configuration() -> Result<(usize, usize, Option<String>), String> {
    let mut samples = environment_usize("FLC_E2E_SAMPLES", DEFAULT_SAMPLES)?;
    let mut warmups = environment_usize("FLC_E2E_WARMUPS", DEFAULT_WARMUPS)?;
    let mut only = None;
    let mut arguments = env::args().skip(1);
    while let Some(argument) = arguments.next() {
        match argument.as_str() {
            "--smoke" => {
                samples = 3;
                warmups = 1;
            }
            "--only" => {
                only = Some(
                    arguments
                        .next()
                        .ok_or_else(|| "--only requires a workload id".to_owned())?,
                );
            }
            _ => return Err(format!("unknown harness argument {argument:?}")),
        }
    }
    Ok((samples, warmups, only))
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
    let (samples, warmups, only) = run_configuration()?;
    if samples < 3 {
        return Err("FLC_E2E_SAMPLES must be at least 3 for a median CI".to_owned());
    }

    let root = PathBuf::from(DATA_ROOT);
    fs::create_dir_all(&root).map_err(|error| format!("create {}: {error}", root.display()))?;
    let frankenlibc = find_frankenlibc()?;
    let frankenlibc_sha = sha256_file(&frankenlibc)?;
    let (workload_executable, workload_sha, compiler) = compile_workload(&root)?;
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
        "E2E_WORKLOAD_ELF path={} sha256={} bytes={} compiler={:?}",
        identity_field(&franken_identity, "WORKLOAD_ELF_PATH")?,
        workload_sha,
        fs::metadata(&workload_executable)
            .map_err(|error| format!("stat {}: {error}", workload_executable.display()))?
            .len(),
        compiler,
    );
    println!(
        "E2E_INCUMBENT version={:?} malloc_path={} fopen_path={} fgets_path={} \
         strftime_path={} sha256={}",
        ldd_version()?,
        identity_field(&host_identity, "MALLOC_ELF_PATH")?,
        identity_field(&host_identity, "FOPEN_ELF_PATH")?,
        identity_field(&host_identity, "FGETS_ELF_PATH")?,
        identity_field(&host_identity, "STRFTIME_ELF_PATH")?,
        identity_field(&host_identity, "MALLOC_ELF_SHA256")?,
    );
    println!(
        "E2E_CHALLENGER mode=strict preload_path={} malloc_path={} fopen_path={} fgets_path={} \
         strftime_path={} sha256={}",
        frankenlibc.display(),
        identity_field(&franken_identity, "MALLOC_ELF_PATH")?,
        identity_field(&franken_identity, "FOPEN_ELF_PATH")?,
        identity_field(&franken_identity, "FGETS_ELF_PATH")?,
        identity_field(&franken_identity, "STRFTIME_ELF_PATH")?,
        frankenlibc_sha,
    );
    println!(
        "E2E_HARNESS samples={} warmups={} interleaving=rotating_3_pair \
         nulls=host_host_and_franken_franken gate=paired_bootstrap_median_ci95_and_2x_null \
         cv_role=telemetry_only locale=C timezone=UTC",
        samples, warmups,
    );

    let jobs = prepare_jobs(&root)?;
    let mut jobs_run = 0;
    for job in jobs {
        if only.as_deref().is_some_and(|id| id != job.workload.id()) {
            continue;
        }
        jobs_run += 1;
        eprintln!("E2E_PARITY workload={} status=begin", job.workload.id());
        let golden = verify_parity(&workload_executable, &frankenlibc, &job)?;
        println!(
            "E2E_PARITY workload={} stdout_sha256={} serialized_sha256={} status=PASS",
            job.workload.id(),
            sha256_bytes(&golden.stdout),
            golden
                .serialized_sha256
                .as_deref()
                .unwrap_or("not_applicable"),
        );
        let measurements = measure_job(
            &workload_executable,
            &frankenlibc,
            &job,
            &golden,
            samples,
            warmups,
        )?;
        print_contract(&job, &golden, &measurements);
    }
    if jobs_run == 0 {
        return Err(format!(
            "requested workload {:?} does not exist",
            only.as_deref().unwrap_or("none")
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
