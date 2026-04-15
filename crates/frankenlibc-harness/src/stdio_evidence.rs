//! JSONL evidence schema for stdio entrypoints.
//!
//! Per bd-9chy.4 and Plan v4 §14: every healing event, foreign-pointer adoption,
//! POMDP repair decision, and membrane stage attribution emits a JSONL row.
//!
//! ## Compatibility Policy
//!
//! Evidence is an output artifact for external consumers. Unlike most code in this
//! project, backwards compatibility is required: the parser must support at least
//! the previous schema version (currently only v1 exists). When adding v2, keep
//! v1 parsing as a fallback for old evidence files.

use serde::{Deserialize, Serialize};
use std::fs::File;
use std::io::{BufRead, BufReader};
use std::path::Path;

/// Schema version for stdio evidence records.
pub const SCHEMA_VERSION: u32 = 1;

/// Event kinds for stdio evidence.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum StdioEventKind {
    /// fopen/fdopen/freopen acquired a stream.
    StreamAcquired,
    /// fclose released a stream.
    StreamReleased,
    /// Read operation (fread, fgetc, fgets, etc.).
    Read,
    /// Write operation (fwrite, fputc, fputs, etc.).
    Write,
    /// Seek operation (fseek, fseeko, rewind, fsetpos).
    Seek,
    /// Tell operation (ftell, ftello, fgetpos).
    Tell,
    /// Flush operation (fflush).
    Flush,
    /// ungetc pushed back a character.
    Ungetc,
    /// Error/EOF flag query (feof, ferror).
    StatusQuery,
    /// clearerr cleared flags.
    ClearError,
    /// Foreign pointer adopted (non-native FILE* used).
    ForeignAdoption,
    /// Healing action triggered.
    HealingTriggered,
    /// POMDP repair decision made.
    PomdpRepair,
}

/// Origin of the FILE pointer.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FpOrigin {
    /// Native NativeFile from fopen/fdopen/freopen.
    Native,
    /// Adopted foreign pointer from external library.
    Foreign,
    /// Standard stream (stdin/stdout/stderr).
    Standard,
    /// Memory stream (fmemopen/open_memstream).
    Memory,
    /// Unknown origin.
    Unknown,
}

/// Process identification.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProcessInfo {
    /// Process ID.
    pub pid: u32,
    /// Thread ID (gettid).
    pub tid: u32,
    /// Process command name (from /proc/self/comm).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub comm: Option<String>,
}

/// Function parameters (varies by function).
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(untagged)]
pub enum StdioParams {
    /// fopen/freopen parameters.
    Open { path: Option<String>, mode: String },
    /// fread/fwrite parameters.
    ReadWrite { size: usize, nmemb: usize },
    /// fseek parameters.
    Seek { offset: i64, whence: String },
    /// fprintf/snprintf parameters.
    Format {
        format: String,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        size: Option<usize>,
    },
    /// ungetc parameters.
    Ungetc { c: i32 },
    /// Generic/no parameters.
    None {},
}

/// Function result.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StdioResult {
    /// Return value (as string for flexibility).
    pub return_value: String,
    /// errno after call (0 if not applicable).
    pub errno: i32,
    /// Call elapsed time in nanoseconds.
    pub elapsed_ns: u64,
}

/// Per-stage membrane timing.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct MembraneStages {
    /// Null check time in ns.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub null_check_ns: Option<u64>,
    /// Registry lookup time in ns.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub registry_lookup_ns: Option<u64>,
    /// Bloom filter time in ns.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub bloom_ns: Option<u64>,
    /// Bounds check time in ns.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub bounds_ns: Option<u64>,
    /// Fingerprint verification time in ns.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub fingerprint_ns: Option<u64>,
    /// Total validation time in ns.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub total_ns: Option<u64>,
}

/// Runtime math controller state.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct RuntimeMathState {
    /// POMDP action taken.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub pomdp_action: Option<String>,
    /// Conformal prediction band.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub conformal_band: Option<f64>,
    /// Cohomology consistency check passed.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cohomology_consistent: Option<bool>,
    /// CVaR alarm triggered.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cvar_alarm: Option<bool>,
    /// Risk upper bound in PPM.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub risk_upper_bound_ppm: Option<u32>,
    /// Policy ID that made the decision.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub policy_id: Option<u32>,
}

/// A single stdio evidence row.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StdioEvidenceRow {
    /// Schema version (always 1 for now).
    pub schema_version: u32,
    /// Unix timestamp in nanoseconds.
    pub timestamp_unix_ns: u64,
    /// Process identification.
    pub process: ProcessInfo,
    /// Safety mode (strict/hardened/off).
    pub mode: String,
    /// Event kind.
    pub event_kind: StdioEventKind,
    /// Function name.
    pub function: String,
    /// FILE pointer as hex string.
    pub fp_hex: String,
    /// Origin of the FILE pointer.
    pub fp_origin: FpOrigin,
    /// Underlying file descriptor (-1 for memory streams).
    pub fd: i32,
    /// Function parameters.
    pub params: StdioParams,
    /// Function result.
    pub result: StdioResult,
    /// Membrane stage timings.
    #[serde(default, skip_serializing_if = "MembraneStages::is_empty")]
    pub membrane_stages: MembraneStages,
    /// Runtime math controller state.
    #[serde(default, skip_serializing_if = "RuntimeMathState::is_empty")]
    pub runtime_math: RuntimeMathState,
    /// Healing action if triggered.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub healing_action: Option<String>,
    /// Monotonic evidence sequence number.
    pub evidence_ring_seq: u64,
    /// Trace ID (UUID format).
    pub trace_id: String,
}

impl MembraneStages {
    /// Returns true if all fields are None.
    pub fn is_empty(&self) -> bool {
        self.null_check_ns.is_none()
            && self.registry_lookup_ns.is_none()
            && self.bloom_ns.is_none()
            && self.bounds_ns.is_none()
            && self.fingerprint_ns.is_none()
            && self.total_ns.is_none()
    }
}

impl RuntimeMathState {
    /// Returns true if all fields are None.
    pub fn is_empty(&self) -> bool {
        self.pomdp_action.is_none()
            && self.conformal_band.is_none()
            && self.cohomology_consistent.is_none()
            && self.cvar_alarm.is_none()
            && self.risk_upper_bound_ppm.is_none()
            && self.policy_id.is_none()
    }
}

/// Error types for parsing stdio evidence.
#[derive(Debug)]
pub enum ParseError {
    /// IO error reading the file.
    Io(std::io::Error),
    /// JSON deserialization error.
    Json {
        line: usize,
        error: serde_json::Error,
    },
    /// Unsupported schema version.
    UnsupportedVersion { line: usize, version: u32 },
}

impl std::fmt::Display for ParseError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ParseError::Io(e) => write!(f, "IO error: {e}"),
            ParseError::Json { line, error } => write!(f, "JSON error at line {line}: {error}"),
            ParseError::UnsupportedVersion { line, version } => {
                write!(f, "Unsupported schema version {version} at line {line}")
            }
        }
    }
}

impl std::error::Error for ParseError {}

impl From<std::io::Error> for ParseError {
    fn from(e: std::io::Error) -> Self {
        ParseError::Io(e)
    }
}

/// Iterator over stdio evidence rows from a JSONL file.
pub struct StdioEvidenceIterator<R: BufRead> {
    reader: R,
    line_number: usize,
    buffer: String,
}

impl<R: BufRead> StdioEvidenceIterator<R> {
    /// Create a new iterator from a buffered reader.
    pub fn new(reader: R) -> Self {
        Self {
            reader,
            line_number: 0,
            buffer: String::new(),
        }
    }
}

impl<R: BufRead> Iterator for StdioEvidenceIterator<R> {
    type Item = Result<StdioEvidenceRow, ParseError>;

    fn next(&mut self) -> Option<Self::Item> {
        self.buffer.clear();
        loop {
            self.line_number += 1;
            match self.reader.read_line(&mut self.buffer) {
                Ok(0) => return None, // EOF
                Ok(_) => {
                    let trimmed = self.buffer.trim();
                    if trimmed.is_empty() {
                        self.buffer.clear();
                        continue; // Skip empty lines
                    }
                    match serde_json::from_str::<StdioEvidenceRow>(trimmed) {
                        Ok(row) => {
                            // Version check for backwards compat
                            if row.schema_version > SCHEMA_VERSION {
                                return Some(Err(ParseError::UnsupportedVersion {
                                    line: self.line_number,
                                    version: row.schema_version,
                                }));
                            }
                            return Some(Ok(row));
                        }
                        Err(e) => {
                            return Some(Err(ParseError::Json {
                                line: self.line_number,
                                error: e,
                            }));
                        }
                    }
                }
                Err(e) => return Some(Err(ParseError::Io(e))),
            }
        }
    }
}

/// Open a stdio evidence JSONL file and return an iterator.
pub fn parse_stdio_evidence_file(
    path: &Path,
) -> Result<StdioEvidenceIterator<BufReader<File>>, ParseError> {
    let file = File::open(path)?;
    Ok(StdioEvidenceIterator::new(BufReader::new(file)))
}

/// Serialize a row to JSONL (single line, no trailing newline).
pub fn serialize_row(row: &StdioEvidenceRow) -> Result<String, serde_json::Error> {
    serde_json::to_string(row)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    fn sample_row() -> StdioEvidenceRow {
        StdioEvidenceRow {
            schema_version: SCHEMA_VERSION,
            timestamp_unix_ns: 1_700_000_000_000_000_000,
            process: ProcessInfo {
                pid: 1234,
                tid: 1234,
                comm: Some("test".into()),
            },
            mode: "strict".into(),
            event_kind: StdioEventKind::Read,
            function: "fread".into(),
            fp_hex: "0x7f1234567890".into(),
            fp_origin: FpOrigin::Native,
            fd: 3,
            params: StdioParams::ReadWrite {
                size: 1,
                nmemb: 256,
            },
            result: StdioResult {
                return_value: "256".into(),
                errno: 0,
                elapsed_ns: 1500,
            },
            membrane_stages: MembraneStages {
                null_check_ns: Some(5),
                registry_lookup_ns: Some(20),
                bloom_ns: None,
                bounds_ns: Some(10),
                fingerprint_ns: None,
                total_ns: Some(35),
            },
            runtime_math: RuntimeMathState::default(),
            healing_action: None,
            evidence_ring_seq: 42,
            trace_id: "550e8400-e29b-41d4-a716-446655440000".into(),
        }
    }

    #[test]
    fn round_trip_serialize_deserialize() {
        let row = sample_row();
        let json = serialize_row(&row).expect("serialize");
        let parsed: StdioEvidenceRow = serde_json::from_str(&json).expect("deserialize");

        assert_eq!(parsed.schema_version, row.schema_version);
        assert_eq!(parsed.function, row.function);
        assert_eq!(parsed.evidence_ring_seq, row.evidence_ring_seq);
        assert_eq!(parsed.trace_id, row.trace_id);
    }

    #[test]
    fn parse_jsonl_stream() {
        let row1 = sample_row();
        let mut row2 = sample_row();
        row2.evidence_ring_seq = 43;
        row2.function = "fwrite".into();

        let json1 = serialize_row(&row1).expect("serialize row1");
        let json2 = serialize_row(&row2).expect("serialize row2");
        let jsonl = format!("{json1}\n{json2}\n");

        let cursor = Cursor::new(jsonl.as_bytes());
        let iter = StdioEvidenceIterator::new(BufReader::new(cursor));
        let rows: Vec<_> = iter.collect::<Result<Vec<_>, _>>().expect("parse all");

        assert_eq!(rows.len(), 2);
        assert_eq!(rows[0].function, "fread");
        assert_eq!(rows[1].function, "fwrite");
    }

    #[test]
    fn schema_version_check() {
        let mut row = sample_row();
        row.schema_version = 99; // Future version

        let json = serde_json::to_string(&row).expect("serialize");
        let jsonl = format!("{json}\n");

        let cursor = Cursor::new(jsonl.as_bytes());
        let mut iter = StdioEvidenceIterator::new(BufReader::new(cursor));

        let result = iter.next();
        assert!(result.is_some());
        match result.unwrap() {
            Err(ParseError::UnsupportedVersion { version, .. }) => {
                assert_eq!(version, 99);
            }
            _ => panic!("Expected UnsupportedVersion error"),
        }
    }

    #[test]
    fn empty_lines_skipped() {
        let row = sample_row();
        let json = serialize_row(&row).expect("serialize");
        let jsonl = format!("\n\n{json}\n\n");

        let cursor = Cursor::new(jsonl.as_bytes());
        let iter = StdioEvidenceIterator::new(BufReader::new(cursor));
        let rows: Vec<_> = iter.collect::<Result<Vec<_>, _>>().expect("parse all");

        assert_eq!(rows.len(), 1);
    }

    #[test]
    fn trace_id_propagation() {
        let row = sample_row();
        let json = serialize_row(&row).expect("serialize");
        let parsed: StdioEvidenceRow = serde_json::from_str(&json).expect("deserialize");

        assert_eq!(
            parsed.trace_id, "550e8400-e29b-41d4-a716-446655440000",
            "trace_id must be preserved through serialization"
        );
    }
}
