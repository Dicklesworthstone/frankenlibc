use std::collections::BTreeSet;
use std::path::Path;

fn repo_root() -> std::path::PathBuf {
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

fn normalize_codec(name: &str) -> String {
    name.chars()
        .filter(|ch| !matches!(ch, '-' | '_' | ' ' | '\t'))
        .flat_map(char::to_uppercase)
        .collect()
}

#[test]
fn iconv_scope_ledger_schema_and_identity_are_locked() {
    let root = repo_root();
    let ledger_path = root.join("tests/conformance/iconv_codec_scope_ledger.v1.json");
    let ledger = load_json(&ledger_path);

    assert_eq!(
        ledger["schema_version"].as_u64(),
        Some(1),
        "unexpected iconv scope ledger schema version"
    );
    assert_eq!(
        ledger["bead"].as_str(),
        Some("bd-7cba"),
        "unexpected bead linkage for iconv scope ledger"
    );
}

#[test]
fn iconv_scope_ledger_included_set_matches_phase1_contract() {
    let root = repo_root();
    let ledger_path = root.join("tests/conformance/iconv_codec_scope_ledger.v1.json");
    let ledger = load_json(&ledger_path);
    let included = ledger["included_codecs"]
        .as_array()
        .expect("included_codecs must be an array");

    let canonical: BTreeSet<String> = included
        .iter()
        .map(|entry| {
            normalize_codec(
                entry["canonical"]
                    .as_str()
                    .expect("included codec canonical name must be present"),
            )
        })
        .collect();
    let expected: BTreeSet<String> = ["UTF-8", "ISO-8859-1", "UTF-16LE", "UTF-32"]
        .into_iter()
        .map(normalize_codec)
        .collect();

    assert_eq!(
        canonical, expected,
        "phase-1 included codec set drifted from declared contract"
    );
    for entry in included {
        let intent = entry["compatibility_intent"]
            .as_str()
            .expect("included codec entry must define compatibility_intent");
        assert!(
            !intent.trim().is_empty(),
            "included codec compatibility intent must not be empty"
        );
    }
}

#[test]
fn iconv_scope_ledger_exclusions_are_explicit_and_disjoint() {
    let root = repo_root();
    let ledger_path = root.join("tests/conformance/iconv_codec_scope_ledger.v1.json");
    let ledger = load_json(&ledger_path);
    let included = ledger["included_codecs"]
        .as_array()
        .expect("included_codecs must be an array");
    let excluded = ledger["excluded_codec_families"]
        .as_array()
        .expect("excluded_codec_families must be an array");

    let included_set: BTreeSet<String> = included
        .iter()
        .map(|entry| {
            normalize_codec(
                entry["canonical"]
                    .as_str()
                    .expect("included codec canonical name must be present"),
            )
        })
        .collect();

    for entry in excluded {
        let canonical = entry["canonical"]
            .as_str()
            .expect("excluded codec canonical name must be present");
        let reason = entry["reason"]
            .as_str()
            .expect("excluded codec reason must be present");
        let intent = entry["compatibility_intent"]
            .as_str()
            .expect("excluded codec compatibility intent must be present");
        assert!(
            !reason.trim().is_empty(),
            "excluded codec reason must not be empty for {canonical}"
        );
        assert!(
            !intent.trim().is_empty(),
            "excluded codec compatibility intent must not be empty for {canonical}"
        );
        assert!(
            !included_set.contains(&normalize_codec(canonical)),
            "codec {canonical} cannot be both included and excluded"
        );
    }
}

#[test]
fn iconv_scope_ledger_aligns_with_support_matrix_semantics() {
    let root = repo_root();
    let ledger = load_json(&root.join("tests/conformance/iconv_codec_scope_ledger.v1.json"));
    let support = load_json(&root.join("support_matrix.json"));
    let entries = support
        .as_array()
        .expect("support_matrix.json must contain a top-level array");

    let iconv_entries: Vec<&serde_json::Value> = entries
        .iter()
        .filter(|entry| {
            matches!(
                entry["symbol"].as_str(),
                Some("iconv" | "iconv_open" | "iconv_close")
            )
        })
        .collect();
    assert_eq!(iconv_entries.len(), 3, "expected 3 iconv support entries");

    let expected_strict = ledger["support_matrix_mapping"]["strict_semantics"]
        .as_str()
        .expect("support_matrix_mapping.strict_semantics must be present");
    let expected_hardened = ledger["support_matrix_mapping"]["hardened_semantics"]
        .as_str()
        .expect("support_matrix_mapping.hardened_semantics must be present");
    let expected_status = ledger["support_matrix_mapping"]["status"]
        .as_str()
        .expect("support_matrix_mapping.status must be present");

    for entry in iconv_entries {
        assert_eq!(
            entry["module"].as_str(),
            Some("iconv_abi"),
            "iconv symbols must map to iconv_abi"
        );
        assert_eq!(
            entry["status"].as_str(),
            Some(expected_status),
            "iconv symbol status drifted from scope ledger"
        );
        assert_eq!(
            entry["strict_semantics"].as_str(),
            Some(expected_strict),
            "iconv strict semantics drifted from scope ledger"
        );
        assert_eq!(
            entry["hardened_semantics"].as_str(),
            Some(expected_hardened),
            "iconv hardened semantics drifted from scope ledger"
        );
    }
}
