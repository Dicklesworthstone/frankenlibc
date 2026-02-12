//! Integration test: runtime_math feature/profile gates (bd-1iya)
//!
//! This is intentionally lightweight: it validates the mapping between the
//! production kernel manifest and Cargo feature configuration without running
//! nested `cargo` commands inside the test process (the CI gate script runs
//! the build matrix explicitly).

use std::path::{Path, PathBuf};

fn workspace_root() -> PathBuf {
    let manifest = env!("CARGO_MANIFEST_DIR");
    Path::new(manifest)
        .parent()
        .unwrap()
        .parent()
        .unwrap()
        .to_path_buf()
}

fn load_json(path: &Path) -> serde_json::Value {
    let content = std::fs::read_to_string(path).expect("json file should be readable");
    serde_json::from_str(&content).expect("json should parse")
}

#[test]
fn manifest_feature_sets_match_membrane_cargo_features() {
    let root = workspace_root();
    let manifest = load_json(&root.join("tests/runtime_math/production_kernel_manifest.v1.json"));

    let default_feature_set = manifest["default_feature_set"]
        .as_array()
        .expect("default_feature_set must be an array");
    let optional_feature_set = manifest["optional_feature_set"]
        .as_array()
        .expect("optional_feature_set must be an array");

    let default_feature_set: Vec<&str> = default_feature_set
        .iter()
        .map(|v| {
            v.as_str()
                .expect("default_feature_set entries must be strings")
        })
        .collect();
    let optional_feature_set: Vec<&str> = optional_feature_set
        .iter()
        .map(|v| {
            v.as_str()
                .expect("optional_feature_set entries must be strings")
        })
        .collect();

    assert_eq!(
        default_feature_set,
        vec!["runtime-math-production"],
        "manifest default_feature_set must be ['runtime-math-production']"
    );
    assert_eq!(
        optional_feature_set,
        vec!["runtime-math-research"],
        "manifest optional_feature_set must be ['runtime-math-research']"
    );

    let cargo_toml = std::fs::read_to_string(root.join("crates/frankenlibc-membrane/Cargo.toml"))
        .expect("membrane Cargo.toml must be readable");
    assert!(
        cargo_toml.contains("default = [\"runtime-math-production\"]"),
        "membrane Cargo.toml must default-enable runtime-math-production"
    );
    assert!(
        cargo_toml.contains("runtime-math-production = []"),
        "membrane Cargo.toml must define runtime-math-production feature"
    );
    assert!(
        cargo_toml.contains("runtime-math-research = [\"runtime-math-production\"]"),
        "membrane Cargo.toml must define runtime-math-research depending on production"
    );
}

#[test]
fn membrane_compile_error_for_missing_production_feature_is_present() {
    let root = workspace_root();
    let lib_rs = std::fs::read_to_string(root.join("crates/frankenlibc-membrane/src/lib.rs"))
        .expect("membrane lib.rs must be readable");

    assert!(
        lib_rs.contains("requires the `runtime-math-production` feature"),
        "membrane must compile_error when runtime-math-production is disabled"
    );
}

#[test]
fn gate_script_exists_and_is_executable() {
    let root = workspace_root();
    let script = root.join("scripts/check_runtime_math_profile_gates.sh");
    assert!(
        script.exists(),
        "scripts/check_runtime_math_profile_gates.sh must exist"
    );

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let perms = std::fs::metadata(&script).unwrap().permissions();
        assert!(
            perms.mode() & 0o111 != 0,
            "check_runtime_math_profile_gates.sh must be executable"
        );
    }
}
