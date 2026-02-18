use std::path::{Path, PathBuf};
use std::process::Command;

fn repo_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .unwrap()
        .parent()
        .unwrap()
        .to_path_buf()
}

fn load_json(path: &Path) -> serde_json::Value {
    let content = std::fs::read_to_string(path)
        .unwrap_or_else(|e| panic!("Failed to read {}: {}", path.display(), e));
    serde_json::from_str(&content)
        .unwrap_or_else(|e| panic!("Invalid JSON in {}: {}", path.display(), e))
}

fn canonical_json(value: &serde_json::Value) -> String {
    serde_json::to_string(value).expect("serialize canonical json")
}

fn sha256_str(data: &str) -> String {
    use sha2::{Digest, Sha256};
    let mut hasher = Sha256::new();
    hasher.update(data.as_bytes());
    format!("{:x}", hasher.finalize())
}

#[test]
fn iconv_table_generation_gate_script_passes() {
    let root = repo_root();
    let output = Command::new("bash")
        .arg(root.join("scripts/check_iconv_table_generation.sh"))
        .current_dir(&root)
        .output()
        .expect("failed to run iconv table generation gate");
    assert!(
        output.status.success(),
        "iconv table generation gate failed\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
}

#[test]
fn iconv_table_pack_schema_is_locked() {
    let root = repo_root();
    let pack = load_json(&root.join("tests/conformance/iconv_table_pack.v1.json"));
    let checksums = load_json(&root.join("tests/conformance/iconv_table_checksums.v1.json"));

    assert_eq!(pack["schema_version"].as_str(), Some("v1"));
    assert_eq!(pack["bead"].as_str(), Some("bd-13ya"));
    assert_eq!(checksums["schema_version"].as_str(), Some("v1"));
    assert_eq!(checksums["bead"].as_str(), Some("bd-13ya"));

    let tables = pack["included_codec_tables"]
        .as_array()
        .expect("included_codec_tables must be array");
    assert_eq!(
        tables.len(),
        4,
        "expected exactly four phase-1 codec tables"
    );

    let expected = ["UTF-8", "ISO-8859-1", "UTF-16LE", "UTF-32"];
    for canonical in expected {
        assert!(
            tables
                .iter()
                .any(|row| row["canonical"].as_str() == Some(canonical)),
            "missing codec table for {canonical}"
        );
    }
}

#[test]
fn iconv_table_checksums_are_consistent() {
    let root = repo_root();
    let pack = load_json(&root.join("tests/conformance/iconv_table_pack.v1.json"));
    let checksums = load_json(&root.join("tests/conformance/iconv_table_checksums.v1.json"));

    let tables = pack["included_codec_tables"]
        .as_array()
        .expect("included_codec_tables must be array");
    let checksum_map = checksums["codec_table_sha256"]
        .as_object()
        .expect("codec_table_sha256 must be object");

    for row in tables {
        let canonical = row["canonical"].as_str().expect("canonical must be string");
        let recorded_table_digest = row["table_sha256"]
            .as_str()
            .expect("table_sha256 must be string");

        let mut body = row.clone();
        body.as_object_mut()
            .expect("table row must be object")
            .remove("table_sha256");
        let recomputed = sha256_str(&canonical_json(&body));
        assert_eq!(
            recorded_table_digest, recomputed,
            "table_sha256 drift for codec {canonical}"
        );

        assert_eq!(
            checksum_map
                .get(canonical)
                .and_then(serde_json::Value::as_str),
            Some(recorded_table_digest),
            "checksum manifest mismatch for codec {canonical}"
        );
    }

    let mut pack_body = pack.clone();
    let recorded_pack_digest = pack_body
        .as_object_mut()
        .expect("pack must be object")
        .remove("table_pack_sha256")
        .and_then(|value| value.as_str().map(ToOwned::to_owned))
        .expect("table_pack_sha256 missing");
    let recomputed_pack_digest = sha256_str(&canonical_json(&pack_body));
    assert_eq!(recorded_pack_digest, recomputed_pack_digest);
    assert_eq!(
        checksums["table_pack_sha256"].as_str(),
        Some(recomputed_pack_digest.as_str())
    );

    let mut checksums_body = checksums.clone();
    let recorded_checksums_digest = checksums_body
        .as_object_mut()
        .expect("checksums must be object")
        .remove("checksums_sha256")
        .and_then(|value| value.as_str().map(ToOwned::to_owned))
        .expect("checksums_sha256 missing");
    checksums_body
        .as_object_mut()
        .expect("checksums must be object")
        .remove("artifact_paths");
    let recomputed_checksums_digest = sha256_str(&canonical_json(&checksums_body));
    assert_eq!(recorded_checksums_digest, recomputed_checksums_digest);
}
