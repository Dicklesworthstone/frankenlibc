use std::path::{Path, PathBuf};
use std::process::Command;

type TestResult = Result<(), String>;

fn repo_root() -> Result<PathBuf, String> {
    let manifest_dir = Path::new(env!("CARGO_MANIFEST_DIR"));
    let root = manifest_dir
        .parent()
        .and_then(Path::parent)
        .ok_or_else(|| {
            format!(
                "failed to derive workspace root from {}",
                manifest_dir.display()
            )
        })?;
    Ok(root.to_path_buf())
}

fn load_json(path: &Path) -> Result<serde_json::Value, String> {
    let content = std::fs::read_to_string(path)
        .map_err(|err| format!("failed to read {}: {err}", path.display()))?;
    serde_json::from_str(&content)
        .map_err(|err| format!("invalid JSON in {}: {err}", path.display()))
}

fn canonical_json(value: &serde_json::Value) -> Result<String, String> {
    serde_json::to_string(value).map_err(|err| format!("failed to serialize canonical JSON: {err}"))
}

fn sha256_str(data: &str) -> String {
    use sha2::{Digest, Sha256};
    let mut hasher = Sha256::new();
    hasher.update(data.as_bytes());
    hex_digest(&hasher.finalize())
}

fn hex_digest(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

#[test]
fn iconv_table_generation_gate_script_passes() -> TestResult {
    let root = repo_root()?;
    let script = root.join("scripts/check_iconv_table_generation.sh");
    let output = Command::new("bash")
        .arg(&script)
        .current_dir(&root)
        .output()
        .map_err(|err| format!("failed to run {}: {err}", script.display()))?;
    assert!(
        output.status.success(),
        "iconv table generation gate failed\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    Ok(())
}

#[test]
fn iconv_table_pack_schema_is_locked() -> TestResult {
    let root = repo_root()?;
    let pack = load_json(&root.join("tests/conformance/iconv_table_pack.v1.json"))?;
    let checksums = load_json(&root.join("tests/conformance/iconv_table_checksums.v1.json"))?;
    let ledger = load_json(&root.join("tests/conformance/iconv_codec_scope_ledger.v1.json"))?;

    assert_eq!(pack["schema_version"].as_str(), Some("v1"));
    assert_eq!(pack["bead"].as_str(), Some("bd-13ya"));
    assert_eq!(checksums["schema_version"].as_str(), Some("v1"));
    assert_eq!(checksums["bead"].as_str(), Some("bd-13ya"));

    let tables = pack["included_codec_tables"]
        .as_array()
        .ok_or_else(|| String::from("included_codec_tables must be array"))?;
    let ledger_included = ledger["included_codecs"]
        .as_array()
        .ok_or_else(|| String::from("ledger included_codecs must be array"))?;
    assert_eq!(
        tables.len(),
        ledger_included.len(),
        "phase-1 codec table count must match source ledger"
    );

    let expected = [
        "UTF-8",
        "ISO-8859-1",
        "UTF-16LE",
        "UTF-32",
        "KOI8-R",
        "KOI8-U",
        "KOI8-RU",
        "KOI8-T",
        "EUC-JP",
        "SHIFT_JIS",
        "BIG5",
        "GB18030",
    ];
    for canonical in expected {
        assert!(
            tables
                .iter()
                .any(|row| row["canonical"].as_str() == Some(canonical)),
            "missing codec table for {canonical}"
        );
    }
    Ok(())
}

#[test]
fn iconv_table_checksums_are_consistent() -> TestResult {
    let root = repo_root()?;
    let pack = load_json(&root.join("tests/conformance/iconv_table_pack.v1.json"))?;
    let checksums = load_json(&root.join("tests/conformance/iconv_table_checksums.v1.json"))?;

    let tables = pack["included_codec_tables"]
        .as_array()
        .ok_or_else(|| String::from("included_codec_tables must be array"))?;
    let checksum_map = checksums["codec_table_sha256"]
        .as_object()
        .ok_or_else(|| String::from("codec_table_sha256 must be object"))?;

    for row in tables {
        let canonical = row["canonical"]
            .as_str()
            .ok_or_else(|| String::from("canonical must be string"))?;
        let recorded_table_digest = row["table_sha256"]
            .as_str()
            .ok_or_else(|| format!("{canonical} table_sha256 must be string"))?;

        let mut body = row.clone();
        body.as_object_mut()
            .ok_or_else(|| format!("{canonical} table row must be object"))?
            .remove("table_sha256");
        let recomputed = sha256_str(&canonical_json(&body)?);
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
    let recorded_pack_digest = {
        let pack_object = pack_body
            .as_object_mut()
            .ok_or_else(|| String::from("pack must be object"))?;
        pack_object
            .remove("table_pack_sha256")
            .and_then(|value| value.as_str().map(ToOwned::to_owned))
            .ok_or_else(|| String::from("table_pack_sha256 missing"))?
    };
    let recomputed_pack_digest = sha256_str(&canonical_json(&pack_body)?);
    assert_eq!(recorded_pack_digest, recomputed_pack_digest);
    assert_eq!(
        checksums["table_pack_sha256"].as_str(),
        Some(recomputed_pack_digest.as_str())
    );

    let mut checksums_body = checksums.clone();
    let recorded_checksums_digest = {
        let checksums_object = checksums_body
            .as_object_mut()
            .ok_or_else(|| String::from("checksums must be object"))?;
        checksums_object
            .remove("checksums_sha256")
            .and_then(|value| value.as_str().map(ToOwned::to_owned))
            .ok_or_else(|| String::from("checksums_sha256 missing"))?
    };
    checksums_body
        .as_object_mut()
        .ok_or_else(|| String::from("checksums must be object"))?
        .remove("artifact_paths");
    let recomputed_checksums_digest = sha256_str(&canonical_json(&checksums_body)?);
    assert_eq!(recorded_checksums_digest, recomputed_checksums_digest);
    Ok(())
}
