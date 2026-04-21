//! Versioned JSONL evidence schema and bounded ring buffer for stdio evidence.

use parking_lot::Mutex;
use serde::{Deserialize, Serialize};
use std::cell::RefCell;
use std::collections::VecDeque;
use std::fs::OpenOptions;
use std::io::{self, Write as _};
use std::path::{Path, PathBuf};
use std::sync::LazyLock;
use std::sync::atomic::{AtomicU64, Ordering};

/// Current schema version for stdio evidence rows.
pub const STDIO_EVIDENCE_SCHEMA_VERSION: u32 = 1;
/// Default bounded ring size for in-process stdio evidence retention.
pub const DEFAULT_STDIO_EVIDENCE_RING_CAPACITY: usize = 256;
/// Default on-disk JSONL artifact path for stdio evidence rows.
pub const DEFAULT_STDIO_EVIDENCE_PATH: &str = "target/conformance/stdio_evidence.jsonl";

/// Event kinds for stdio evidence rows.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum StdioEventKind {
    StreamAcquired,
    StreamReleased,
    Read,
    Write,
    Seek,
    Tell,
    Flush,
    Ungetc,
    StatusQuery,
    ClearError,
    ForeignAdoption,
    HealingTriggered,
    PomdpRepair,
}

/// Origin of the observed FILE pointer.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FpOrigin {
    Native,
    Foreign,
    Standard,
    Memory,
    Unknown,
}

/// Process and thread identity attached to an evidence row.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProcessInfo {
    pub pid: u32,
    pub tid: u32,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub comm: Option<String>,
}

impl ProcessInfo {
    #[must_use]
    pub fn current(tid: u32) -> Self {
        Self {
            pid: std::process::id(),
            tid,
            comm: std::fs::read_to_string("/proc/self/comm")
                .ok()
                .map(|comm| comm.trim().to_string())
                .filter(|comm| !comm.is_empty()),
        }
    }
}

/// Function parameters captured in a stdio evidence row.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(untagged)]
pub enum StdioParams {
    Open {
        path: Option<String>,
        mode: String,
    },
    ReadWrite {
        size: usize,
        nmemb: usize,
    },
    Seek {
        offset: i64,
        whence: String,
    },
    Format {
        format: String,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        size: Option<usize>,
    },
    Ungetc {
        c: i32,
    },
    None {},
}

/// Function result summary captured in a stdio evidence row.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct StdioResult {
    pub return_value: String,
    pub errno: i32,
    pub elapsed_ns: u64,
}

/// Timing attribution for membrane validation stages.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct MembraneStages {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub null_check_ns: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub registry_lookup_ns: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub bloom_ns: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub bounds_ns: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub fingerprint_ns: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub total_ns: Option<u64>,
}

impl MembraneStages {
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.null_check_ns.is_none()
            && self.registry_lookup_ns.is_none()
            && self.bloom_ns.is_none()
            && self.bounds_ns.is_none()
            && self.fingerprint_ns.is_none()
            && self.total_ns.is_none()
    }
}

/// Runtime-math controller state attached to a stdio evidence row.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct RuntimeMathState {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub pomdp_action: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub conformal_band: Option<f64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cohomology_consistent: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cvar_alarm: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub risk_upper_bound_ppm: Option<u32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub policy_id: Option<u32>,
}

impl RuntimeMathState {
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.pomdp_action.is_none()
            && self.conformal_band.is_none()
            && self.cohomology_consistent.is_none()
            && self.cvar_alarm.is_none()
            && self.risk_upper_bound_ppm.is_none()
            && self.policy_id.is_none()
    }
}

/// Single JSONL row for stdio evidence.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct StdioEvidenceRow {
    #[serde(default = "default_stdio_schema_version")]
    pub schema_version: u32,
    pub timestamp_unix_ns: u64,
    pub process: ProcessInfo,
    pub mode: String,
    pub event_kind: StdioEventKind,
    pub function: String,
    pub fp_hex: String,
    pub fp_origin: FpOrigin,
    pub fd: i32,
    pub params: StdioParams,
    pub result: StdioResult,
    #[serde(default)]
    pub membrane_stages: MembraneStages,
    #[serde(default)]
    pub runtime_math: RuntimeMathState,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub healing_action: Option<String>,
    #[serde(default)]
    pub evidence_ring_seq: u64,
    #[serde(default)]
    pub trace_id: String,
}

impl StdioEvidenceRow {
    /// Fill fields that are assigned at emission time by the ring buffer.
    pub fn finalize_for_emission(&mut self, seq: u64) {
        self.schema_version = STDIO_EVIDENCE_SCHEMA_VERSION;
        self.evidence_ring_seq = seq;
        if self.trace_id.is_empty() {
            self.trace_id = next_stdio_trace_id();
        }
        if !self.runtime_math.conformal_band.is_some_and(f64::is_finite) {
            self.runtime_math.conformal_band = None;
        }
    }
}

fn default_stdio_schema_version() -> u32 {
    STDIO_EVIDENCE_SCHEMA_VERSION
}

#[derive(Debug)]
struct ThreadTraceState {
    stream_seed: u64,
    next_local_seq: u64,
}

impl ThreadTraceState {
    fn new() -> Self {
        Self {
            stream_seed: NEXT_TRACE_STREAM_SEED.fetch_add(1, Ordering::Relaxed),
            next_local_seq: 0,
        }
    }
}

static NEXT_TRACE_STREAM_SEED: AtomicU64 = AtomicU64::new(1);

thread_local! {
    static STDIO_TRACE_STATE: RefCell<ThreadTraceState> = RefCell::new(ThreadTraceState::new());
}

/// Generate a UUID-shaped trace identifier with thread-local sequencing.
#[must_use]
pub fn next_stdio_trace_id() -> String {
    let timestamp = current_unix_ns();
    let pid = u64::from(std::process::id());
    STDIO_TRACE_STATE.with(|state| {
        let mut state = state.borrow_mut();
        state.next_local_seq = state.next_local_seq.saturating_add(1);

        let mut bytes = [0u8; 16];
        let hi = timestamp ^ pid.rotate_left(17) ^ state.stream_seed.rotate_left(33);
        let lo = state.stream_seed.rotate_left(7) ^ state.next_local_seq ^ timestamp.rotate_left(9);

        bytes[..8].copy_from_slice(&hi.to_be_bytes());
        bytes[8..].copy_from_slice(&lo.to_be_bytes());
        bytes[6] = (bytes[6] & 0x0f) | 0x40;
        bytes[8] = (bytes[8] & 0x3f) | 0x80;

        format_uuid_bytes(bytes)
    })
}

/// Serialize a row into a single JSONL line without a trailing newline.
pub fn serialize_stdio_evidence_row(row: &StdioEvidenceRow) -> Result<String, serde_json::Error> {
    serde_json::to_string(row)
}

/// Default artifact path for stdio evidence JSONL.
#[must_use]
pub fn default_stdio_evidence_path() -> PathBuf {
    PathBuf::from(DEFAULT_STDIO_EVIDENCE_PATH)
}

/// Bounded overwrite-on-full ring buffer for stdio evidence rows.
pub struct StdioEvidenceRingBuffer {
    capacity: usize,
    next_seq: AtomicU64,
    dropped: AtomicU64,
    rows: Mutex<VecDeque<StdioEvidenceRow>>,
    output_path: PathBuf,
}

impl StdioEvidenceRingBuffer {
    #[must_use]
    pub fn new(capacity: usize) -> Self {
        Self::with_output_path(capacity, default_stdio_evidence_path())
    }

    #[must_use]
    pub fn with_output_path(capacity: usize, output_path: PathBuf) -> Self {
        let capacity = capacity.max(1);
        Self {
            capacity,
            next_seq: AtomicU64::new(0),
            dropped: AtomicU64::new(0),
            rows: Mutex::new(VecDeque::with_capacity(capacity)),
            output_path,
        }
    }

    pub fn append(&self, mut row: StdioEvidenceRow) -> io::Result<u64> {
        let seq = self.next_seq.fetch_add(1, Ordering::Relaxed) + 1;
        row.finalize_for_emission(seq);

        {
            let mut rows = self.rows.lock();
            if rows.len() >= self.capacity {
                let _ = rows.pop_front();
                self.dropped.fetch_add(1, Ordering::Relaxed);
            }
            rows.push_back(row.clone());
        }

        self.append_to_file(&row)?;
        Ok(seq)
    }

    pub fn clear(&self) -> io::Result<()> {
        self.rows.lock().clear();
        self.next_seq.store(0, Ordering::Relaxed);
        self.dropped.store(0, Ordering::Relaxed);

        if let Some(parent) = self.output_path.parent() {
            std::fs::create_dir_all(parent)?;
        }

        OpenOptions::new()
            .create(true)
            .write(true)
            .truncate(true)
            .open(&self.output_path)?;
        Ok(())
    }

    #[must_use]
    pub fn dropped_count(&self) -> u64 {
        self.dropped.load(Ordering::Relaxed)
    }

    #[must_use]
    pub fn snapshot_rows(&self) -> Vec<StdioEvidenceRow> {
        self.rows.lock().iter().cloned().collect()
    }

    pub fn snapshot_jsonl(&self) -> Result<String, serde_json::Error> {
        self.rows
            .lock()
            .iter()
            .map(serialize_stdio_evidence_row)
            .collect::<Result<Vec<_>, _>>()
            .map(|rows| rows.join("\n"))
    }

    #[must_use]
    pub fn output_path(&self) -> &Path {
        &self.output_path
    }

    fn append_to_file(&self, row: &StdioEvidenceRow) -> io::Result<()> {
        if let Some(parent) = self.output_path.parent() {
            std::fs::create_dir_all(parent)?;
        }

        let mut file = OpenOptions::new()
            .create(true)
            .append(true)
            .open(&self.output_path)?;
        let serialized = serialize_stdio_evidence_row(row).map_err(io::Error::other)?;
        file.write_all(serialized.as_bytes())?;
        file.write_all(b"\n")?;
        file.flush()
    }
}

static GLOBAL_STDIO_EVIDENCE_RING: LazyLock<StdioEvidenceRingBuffer> =
    LazyLock::new(|| StdioEvidenceRingBuffer::new(DEFAULT_STDIO_EVIDENCE_RING_CAPACITY));

/// Process-global stdio evidence ring used by ABI entrypoints.
#[must_use]
pub fn global_stdio_evidence_ring() -> &'static StdioEvidenceRingBuffer {
    &GLOBAL_STDIO_EVIDENCE_RING
}

fn current_unix_ns() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos()
        .min(u64::MAX as u128) as u64
}

fn format_uuid_bytes(bytes: [u8; 16]) -> String {
    let p0 = u32::from_be_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]);
    let p1 = u16::from_be_bytes([bytes[4], bytes[5]]);
    let p2 = u16::from_be_bytes([bytes[6], bytes[7]]);
    let p3 = u16::from_be_bytes([bytes[8], bytes[9]]);
    let p4 = u64::from_be_bytes([
        0, 0, bytes[10], bytes[11], bytes[12], bytes[13], bytes[14], bytes[15],
    ]);
    format!("{p0:08x}-{p1:04x}-{p2:04x}-{p3:04x}-{p4:012x}")
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_row() -> StdioEvidenceRow {
        StdioEvidenceRow {
            schema_version: 0,
            timestamp_unix_ns: 1_700_000_000_000_000_000,
            process: ProcessInfo {
                pid: 1234,
                tid: 5678,
                comm: Some("test".to_string()),
            },
            mode: "strict".to_string(),
            event_kind: StdioEventKind::Read,
            function: "fread".to_string(),
            fp_hex: "0x1234".to_string(),
            fp_origin: FpOrigin::Native,
            fd: 3,
            params: StdioParams::ReadWrite { size: 1, nmemb: 8 },
            result: StdioResult {
                return_value: "8".to_string(),
                errno: 0,
                elapsed_ns: 42,
            },
            membrane_stages: MembraneStages {
                total_ns: Some(42),
                ..MembraneStages::default()
            },
            runtime_math: RuntimeMathState::default(),
            healing_action: None,
            evidence_ring_seq: 0,
            trace_id: String::new(),
        }
    }

    #[test]
    fn trace_ids_are_uuid_shaped_and_unique_per_call() {
        let first = next_stdio_trace_id();
        let second = next_stdio_trace_id();

        assert_ne!(first, second);
        assert_eq!(first.len(), 36);
        assert_eq!(second.len(), 36);
        assert_eq!(first.chars().filter(|ch| *ch == '-').count(), 4);
        assert_eq!(second.chars().filter(|ch| *ch == '-').count(), 4);
    }

    #[test]
    fn ring_buffer_assigns_seq_and_drops_oldest() {
        let path = std::env::temp_dir().join(format!(
            "frankenlibc-stdio-evidence-ring-{}-{}.jsonl",
            std::process::id(),
            current_unix_ns()
        ));
        let ring = StdioEvidenceRingBuffer::with_output_path(2, path);
        ring.clear().expect("clear ring backing file");

        let mut row1 = sample_row();
        row1.function = "fread".to_string();
        ring.append(row1).expect("append row1");

        let mut row2 = sample_row();
        row2.function = "fwrite".to_string();
        ring.append(row2).expect("append row2");

        let mut row3 = sample_row();
        row3.function = "fflush".to_string();
        ring.append(row3).expect("append row3");

        let snapshot = ring.snapshot_rows();
        assert_eq!(snapshot.len(), 2);
        assert_eq!(snapshot[0].function, "fwrite");
        assert_eq!(snapshot[1].function, "fflush");
        assert_eq!(snapshot[0].evidence_ring_seq, 2);
        assert_eq!(snapshot[1].evidence_ring_seq, 3);
        assert_eq!(ring.dropped_count(), 1);
    }

    #[test]
    fn serialization_uses_schema_ordering() {
        let mut row = sample_row();
        row.finalize_for_emission(7);
        let json = serialize_stdio_evidence_row(&row).expect("serialize row");

        assert!(
            json.starts_with(
                "{\"schema_version\":1,\"timestamp_unix_ns\":1700000000000000000,\"process\":"
            ),
            "schema order must remain stable: {json}"
        );
        assert!(
            json.contains("\"runtime_math\":{}"),
            "runtime_math object should remain present even when empty: {json}"
        );
    }
}
