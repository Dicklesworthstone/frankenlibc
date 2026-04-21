//! JSONL evidence parser facade for stdio entrypoints.
//!
//! Per bd-9chy.4 and Plan v4 §14, the schema is defined in
//! `frankenlibc-membrane` so the ABI emitter and harness parser share a single
//! source of truth. This module keeps the parser entrypoints in the harness.
//!
//! ## Compatibility Policy
//!
//! Evidence is an external artifact. The parser must continue to accept the
//! current schema version and prior compatible rows from the same major series.

pub use frankenlibc_membrane::evidence::{
    FpOrigin, MembraneStages, ProcessInfo, RuntimeMathState, STDIO_EVIDENCE_SCHEMA_VERSION,
    StdioEventKind, StdioEvidenceRow, StdioParams, StdioResult, serialize_stdio_evidence_row,
};
use serde::Deserialize;
use std::fs::File;
use std::io::{BufRead, BufReader};
use std::path::Path;

/// Schema version for stdio evidence records.
pub const SCHEMA_VERSION: u32 = STDIO_EVIDENCE_SCHEMA_VERSION;

pub use frankenlibc_membrane::evidence::{
    DEFAULT_STDIO_EVIDENCE_PATH, DEFAULT_STDIO_EVIDENCE_RING_CAPACITY, StdioEvidenceRingBuffer,
    default_stdio_evidence_path, global_stdio_evidence_ring, next_stdio_trace_id,
};

#[derive(Debug, Deserialize)]
struct SchemaEnvelope {
    #[serde(default)]
    schema_version: u32,
}

/// Error types for parsing stdio evidence.
#[derive(Debug)]
pub enum ParseError {
    Io(std::io::Error),
    Json {
        line: usize,
        error: serde_json::Error,
    },
    UnsupportedVersion {
        line: usize,
        version: u32,
    },
}

impl std::fmt::Display for ParseError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Io(error) => write!(f, "IO error: {error}"),
            Self::Json { line, error } => write!(f, "JSON error at line {line}: {error}"),
            Self::UnsupportedVersion { line, version } => {
                write!(f, "Unsupported schema version {version} at line {line}")
            }
        }
    }
}

impl std::error::Error for ParseError {}

impl From<std::io::Error> for ParseError {
    fn from(error: std::io::Error) -> Self {
        Self::Io(error)
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
    #[must_use]
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
                Ok(0) => return None,
                Ok(_) => {
                    let trimmed = self.buffer.trim();
                    if trimmed.is_empty() {
                        self.buffer.clear();
                        continue;
                    }
                    return Some(parse_stdio_evidence_line(self.line_number, trimmed));
                }
                Err(error) => return Some(Err(ParseError::Io(error))),
            }
        }
    }
}

fn parse_stdio_evidence_line(line: usize, trimmed: &str) -> Result<StdioEvidenceRow, ParseError> {
    let envelope: SchemaEnvelope =
        serde_json::from_str(trimmed).map_err(|error| ParseError::Json { line, error })?;
    if envelope.schema_version > SCHEMA_VERSION {
        return Err(ParseError::UnsupportedVersion {
            line,
            version: envelope.schema_version,
        });
    }
    serde_json::from_str(trimmed).map_err(|error| ParseError::Json { line, error })
}

/// Open a stdio evidence JSONL file and return an iterator.
pub fn parse_stdio_evidence_file(
    path: &Path,
) -> Result<StdioEvidenceIterator<BufReader<File>>, ParseError> {
    let file = File::open(path)?;
    Ok(StdioEvidenceIterator::new(BufReader::new(file)))
}

/// Serialize a row to a single JSONL line without a trailing newline.
pub fn serialize_row(row: &StdioEvidenceRow) -> Result<String, serde_json::Error> {
    serialize_stdio_evidence_row(row)
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
    fn parser_accepts_v1_rows_without_optional_fields() {
        let jsonl = concat!(
            "{\"schema_version\":1,\"timestamp_unix_ns\":1700000000000000000,",
            "\"process\":{\"pid\":1234,\"tid\":1234},",
            "\"mode\":\"strict\",\"event_kind\":\"foreign_adoption\",",
            "\"function\":\"adopt_foreign_file\",\"fp_hex\":\"0x1234\",",
            "\"fp_origin\":\"foreign\",\"fd\":3,\"params\":{},",
            "\"result\":{\"return_value\":\"0x5678\",\"errno\":0,\"elapsed_ns\":99},",
            "\"membrane_stages\":{\"total_ns\":99},",
            "\"healing_action\":null,\"evidence_ring_seq\":1,",
            "\"trace_id\":\"550e8400-e29b-41d4-a716-446655440000\"}\n"
        );

        let mut iter = StdioEvidenceIterator::new(Cursor::new(jsonl.as_bytes()));
        let row = iter
            .next()
            .expect("one row")
            .expect("parser must accept compatible v1 row");

        assert_eq!(row.process.comm, None);
        assert!(row.runtime_math.is_empty());
    }

    #[test]
    fn schema_version_check() {
        let mut row = sample_row();
        row.schema_version = 99;

        let json = serde_json::to_string(&row).expect("serialize");
        let jsonl = format!("{json}\n");

        let cursor = Cursor::new(jsonl.as_bytes());
        let mut iter = StdioEvidenceIterator::new(BufReader::new(cursor));

        match iter.next().expect("one result") {
            Err(ParseError::UnsupportedVersion { version, .. }) => {
                assert_eq!(version, 99);
            }
            other => panic!("expected UnsupportedVersion error, got {other:?}"),
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
    fn foreign_adoption_evidence_from_abi_log_parses_end_to_end() {
        frankenlibc_abi::io_internal_abi::conformance_testing::clear_stdio_evidence_log();

        let jsonl =
            frankenlibc_abi::io_internal_abi::conformance_testing::emit_foreign_adoption_via_host_tmpfile();
        assert!(
            !jsonl.trim().is_empty(),
            "stdio evidence log should contain a row"
        );

        let mut rows = StdioEvidenceIterator::new(Cursor::new(jsonl.as_bytes()));
        let row = rows
            .next()
            .expect("one row expected")
            .expect("row must parse");

        assert_eq!(row.schema_version, SCHEMA_VERSION);
        assert_eq!(row.event_kind, StdioEventKind::ForeignAdoption);
        assert_eq!(row.function, "adopt_foreign_file");
        assert_eq!(row.fp_origin, FpOrigin::Foreign);
        assert!(
            row.fp_hex.starts_with("0x"),
            "foreign pointer should be hex"
        );
        assert!(row.fd >= 0, "foreign adoption should extract a live fd");
        assert_eq!(row.result.errno, 0);
        assert!(
            row.mode == "strict" || row.mode == "hardened" || row.mode == "off",
            "unexpected mode label: {}",
            row.mode
        );
        assert!(
            row.process.comm.is_some(),
            "foreign adoption rows should record /proc/self/comm"
        );
        assert!(
            !row.result.return_value.is_empty(),
            "foreign adoption should record the adopted native pointer"
        );
        assert!(
            row.membrane_stages.total_ns.is_some(),
            "foreign adoption rows should record total_ns"
        );
        assert!(row.trace_id.contains('-'), "trace_id should be UUID-shaped");
        assert!(
            rows.next().is_none(),
            "bounded slice should emit exactly one row"
        );

        frankenlibc_abi::io_internal_abi::conformance_testing::clear_stdio_evidence_log();
    }
}
