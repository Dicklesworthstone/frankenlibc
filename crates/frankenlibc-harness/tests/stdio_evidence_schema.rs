use frankenlibc_harness::stdio_evidence::{
    FpOrigin, MembraneStages, ParseError, ProcessInfo, RuntimeMathState, SCHEMA_VERSION,
    StdioEventKind, StdioEvidenceIterator, StdioEvidenceRingBuffer, StdioEvidenceRow, StdioParams,
    StdioResult, parse_stdio_evidence_file, serialize_row,
};
use std::io::{BufReader, Cursor};
use std::sync::atomic::{AtomicU64, Ordering};

static TEMP_SEQ: AtomicU64 = AtomicU64::new(1);

fn sample_row(function: &str) -> StdioEvidenceRow {
    StdioEvidenceRow {
        schema_version: SCHEMA_VERSION,
        timestamp_unix_ns: 1_700_000_000_000_000_000,
        process: ProcessInfo {
            pid: 1234,
            tid: 5678,
            comm: Some("stdio-evidence-schema".to_string()),
        },
        mode: "strict".to_string(),
        event_kind: StdioEventKind::Read,
        function: function.to_string(),
        fp_hex: "0x7f1234567890".to_string(),
        fp_origin: FpOrigin::Native,
        fd: 3,
        params: StdioParams::ReadWrite { size: 1, nmemb: 16 },
        result: StdioResult {
            return_value: "16".to_string(),
            errno: 0,
            elapsed_ns: 250,
        },
        membrane_stages: MembraneStages {
            total_ns: Some(250),
            ..MembraneStages::default()
        },
        runtime_math: RuntimeMathState::default(),
        healing_action: None,
        evidence_ring_seq: 0,
        trace_id: String::new(),
    }
}

fn unique_temp_path() -> std::path::PathBuf {
    std::env::temp_dir().join(format!(
        "frankenlibc-stdio-evidence-schema-{}-{}.jsonl",
        std::process::id(),
        TEMP_SEQ.fetch_add(1, Ordering::Relaxed)
    ))
}

#[test]
fn ring_buffer_persists_jsonl_and_parser_reads_all_rows() {
    let path = unique_temp_path();
    let ring = StdioEvidenceRingBuffer::with_output_path(2, path.clone());
    ring.clear().expect("clear ring");

    ring.append(sample_row("fread")).expect("append row 1");
    ring.append(sample_row("fwrite")).expect("append row 2");
    ring.append(sample_row("fflush")).expect("append row 3");

    let snapshot = ring.snapshot_rows();
    assert_eq!(snapshot.len(), 2, "ring should retain only newest two rows");
    assert_eq!(snapshot[0].function, "fwrite");
    assert_eq!(snapshot[1].function, "fflush");
    assert_eq!(
        ring.dropped_count(),
        1,
        "overflow should increment drop counter"
    );

    let parsed = parse_stdio_evidence_file(&path)
        .expect("open evidence file")
        .collect::<Result<Vec<_>, _>>()
        .expect("parse persisted rows");
    assert_eq!(
        parsed.len(),
        3,
        "artifact file should retain all emitted rows"
    );
    assert_eq!(parsed[0].evidence_ring_seq, 1);
    assert_eq!(parsed[1].evidence_ring_seq, 2);
    assert_eq!(parsed[2].evidence_ring_seq, 3);
}

#[test]
fn serializer_keeps_schema_prefix_stable() {
    let json = serialize_row(&sample_row("fread")).expect("serialize row");
    assert!(
        json.starts_with(
            "{\"schema_version\":1,\"timestamp_unix_ns\":1700000000000000000,\"process\":"
        ),
        "schema prefix must remain stable: {json}"
    );
    assert!(
        json.contains("\"runtime_math\":{}"),
        "runtime_math should remain a stable object field: {json}"
    );
}

#[test]
fn parser_accepts_legacy_v1_shape() {
    let jsonl = concat!(
        "{\"schema_version\":1,\"timestamp_unix_ns\":1700000000000000000,",
        "\"process\":{\"pid\":7,\"tid\":9},\"mode\":\"strict\",",
        "\"event_kind\":\"foreign_adoption\",\"function\":\"adopt_foreign_file\",",
        "\"fp_hex\":\"0x1234\",\"fp_origin\":\"foreign\",\"fd\":3,\"params\":{},",
        "\"result\":{\"return_value\":\"0x4567\",\"errno\":0,\"elapsed_ns\":80},",
        "\"membrane_stages\":{\"total_ns\":80},\"healing_action\":null,",
        "\"evidence_ring_seq\":1,\"trace_id\":\"550e8400-e29b-41d4-a716-446655440000\"}\n"
    );

    let mut iter = StdioEvidenceIterator::new(BufReader::new(Cursor::new(jsonl.as_bytes())));
    let row = iter
        .next()
        .expect("one row")
        .expect("legacy v1 row should parse");
    assert_eq!(row.process.comm, None);
    assert!(row.runtime_math.is_empty());
}

#[test]
fn parser_rejects_future_schema_versions() {
    let mut row = sample_row("fread");
    row.schema_version = 99;
    let json = serde_json::to_string(&row).expect("serialize future row");
    let mut iter = StdioEvidenceIterator::new(BufReader::new(Cursor::new(json.as_bytes())));

    match iter.next().expect("one result") {
        Err(ParseError::UnsupportedVersion { version, .. }) => assert_eq!(version, 99),
        other => panic!("expected UnsupportedVersion, got {other:?}"),
    }
}
