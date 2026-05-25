//! bd-gq1kz7.14: WS8 soak artifact freshness preflight test.

use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::error::Error;
use std::fmt::Write;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};
use std::time::{SystemTime, UNIX_EPOCH};

type TestResult<T = ()> = Result<T, Box<dyn Error>>;

fn workspace_root() -> TestResult<std::path::PathBuf> {
    Ok(Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .ok_or("crate manifest should have crates parent")?
        .parent()
        .ok_or("crates directory should have workspace parent")?
        .to_path_buf())
}

fn test_error(message: impl Into<String>) -> Box<dyn Error> {
    std::io::Error::other(message.into()).into()
}

fn unique_out_dir(root: &Path, label: &str) -> TestResult<PathBuf> {
    let stamp = SystemTime::now().duration_since(UNIX_EPOCH)?.as_nanos();
    let out = root.join("target/conformance").join(format!(
        "soak_freshness_{label}_{}_{}",
        std::process::id(),
        stamp
    ));
    std::fs::create_dir_all(&out)?;
    Ok(out)
}

fn git_head(root: &Path) -> TestResult<String> {
    let output = Command::new("git")
        .args(["rev-parse", "HEAD"])
        .current_dir(root)
        .output()?;
    if !output.status.success() {
        return Err(test_error(format!(
            "git rev-parse failed: {}",
            String::from_utf8_lossy(&output.stderr)
        )));
    }
    Ok(String::from_utf8(output.stdout)?.trim().to_owned())
}

fn sha256_hex(bytes: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(bytes);
    let mut out = String::with_capacity(64);
    for byte in hasher.finalize() {
        let _ = write!(&mut out, "{byte:02x}");
    }
    out
}

fn write_artifact_fixture(dir: &Path, contents: &[u8]) -> TestResult<(PathBuf, String)> {
    let artifact = dir.join("libfrankenlibc_replace.so");
    std::fs::write(&artifact, contents)?;
    Ok((artifact, sha256_hex(contents)))
}

fn write_artifact_report(
    path: &Path,
    source_commit: &str,
    artifact: &Path,
    artifact_hash: &str,
) -> TestResult {
    let report = json!({
        "source_commit": source_commit,
        "claim_status": "artifact_current",
        "artifact_state": {
            "status": "current",
            "path": artifact.to_string_lossy(),
            "sha256": artifact_hash
        },
        "build_provenance": {
            "cargo_profile": "release",
            "build_command": [
                "cargo",
                "build",
                "--features=standalone,owned-unwind-stub,owned-tls-cache"
            ]
        }
    });
    std::fs::write(path, serde_json::to_string_pretty(&report)? + "\n")?;
    Ok(())
}

fn run_freshness_script(
    root: &Path,
    artifact: &Path,
    report: &Path,
    source_epoch: Option<&str>,
) -> TestResult<(Output, Value)> {
    let mut command = Command::new(root.join("scripts/check_soak_artifact_freshness.sh"));
    command
        .current_dir(root)
        .env("WS8_SOAK_FRESHNESS_ARTIFACT", artifact)
        .env("WS8_SOAK_FRESHNESS_REPORT", report);
    if let Some(epoch) = source_epoch {
        command.env("WS8_SOAK_FRESHNESS_SOURCE_EPOCH", epoch);
    }
    let output = command.output()?;
    let stdout = String::from_utf8_lossy(&output.stdout);
    let payload = serde_json::from_str(&stdout).map_err(|err| {
        test_error(format!(
            "freshness script did not emit JSON: {err}\nstdout:\n{stdout}\nstderr:\n{}",
            String::from_utf8_lossy(&output.stderr)
        ))
    })?;
    Ok((output, payload))
}

fn output_text(output: &Output) -> String {
    format!(
        "status={}\nstdout:\n{}\nstderr:\n{}",
        output.status,
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    )
}

#[test]
fn soak_freshness_script_exists() -> TestResult {
    let script = workspace_root()?.join("scripts/check_soak_artifact_freshness.sh");
    assert!(
        script.exists(),
        "check_soak_artifact_freshness.sh should exist"
    );
    Ok(())
}

#[test]
fn soak_freshness_script_is_executable() -> TestResult {
    use std::os::unix::fs::PermissionsExt;
    let script = workspace_root()?.join("scripts/check_soak_artifact_freshness.sh");
    let perms = std::fs::metadata(&script)?.permissions();
    assert!(perms.mode() & 0o111 != 0, "script should be executable");
    Ok(())
}

#[test]
fn freshness_preflight_accepts_current_artifact_fixture() -> TestResult {
    let root = workspace_root()?;
    let out = unique_out_dir(&root, "current")?;
    let (artifact, artifact_hash) = write_artifact_fixture(&out, b"current replacement artifact")?;
    let report = out.join("standalone_replacement_artifact.report.json");
    write_artifact_report(&report, &git_head(&root)?, &artifact, &artifact_hash)?;

    let (output, payload) = run_freshness_script(&root, &artifact, &report, Some("2"))?;
    assert!(
        output.status.success(),
        "current artifact preflight should pass: {}",
        output_text(&output)
    );
    assert_eq!(payload["status"].as_str(), Some("pass"));
    assert_eq!(payload["soak_ready"].as_bool(), Some(true));
    assert_eq!(
        payload["artifact"]["name_matches"].as_bool(),
        Some(true),
        "canonical replacement artifact name must be required"
    );
    assert_eq!(
        payload["report"]["cargo_profile_matches"].as_bool(),
        Some(true)
    );
    assert_eq!(
        payload["report"]["cargo_features_match"].as_bool(),
        Some(true)
    );
    Ok(())
}

#[test]
fn freshness_preflight_rejects_stale_artifact_fixture() -> TestResult {
    let root = workspace_root()?;
    let out = unique_out_dir(&root, "stale")?;
    let (artifact, artifact_hash) = write_artifact_fixture(&out, b"stale replacement artifact")?;
    let touch = Command::new("touch")
        .args(["-d", "@1"])
        .arg(&artifact)
        .output()?;
    assert!(
        touch.status.success(),
        "touch failed: {}",
        output_text(&touch)
    );
    let report = out.join("standalone_replacement_artifact.report.json");
    write_artifact_report(&report, &git_head(&root)?, &artifact, &artifact_hash)?;

    let (output, payload) = run_freshness_script(&root, &artifact, &report, Some("2"))?;
    assert!(
        !output.status.success(),
        "stale artifact preflight should fail: {}",
        output_text(&output)
    );
    assert_eq!(payload["status"].as_str(), Some("fail"));
    assert_eq!(payload["soak_ready"].as_bool(), Some(false));
    assert!(
        payload["failure_signatures"]
            .as_array()
            .is_some_and(|items| items
                .iter()
                .any(|item| matches!(item.as_str(), Some("stale_artifact")))),
        "stale_artifact signature missing: {payload:#}"
    );
    Ok(())
}

#[test]
fn ws8_run_rejects_missing_artifact_before_iterations() -> TestResult {
    let root = workspace_root()?;
    let out = unique_out_dir(&root, "missing-run")?;
    let report = out.join("ws8_soak.report.json");
    let log = out.join("ws8_soak.log.jsonl");
    let output = Command::new(root.join("scripts/run_ws8_soak.sh"))
        .arg("--run")
        .current_dir(&root)
        .env("WS8_SOAK_REPORT", &report)
        .env("WS8_SOAK_LOG", &log)
        .env("WS8_SOAK_TARGET_ROOT", out.join("target"))
        .env("WS8_SOAK_RUN_ID", "missing-artifact-preflight")
        .env("WS8_SOAK_DURATION_SECONDS", "86400")
        .env("WS8_SOAK_MAX_ITERATIONS", "1")
        .env(
            "WS8_SOAK_FRESHNESS_ARTIFACT",
            out.join("missing/libfrankenlibc_replace.so"),
        )
        .env(
            "WS8_SOAK_FRESHNESS_REPORT",
            out.join("missing/standalone_replacement_artifact.report.json"),
        )
        .output()?;
    assert!(
        !output.status.success(),
        "missing artifact full-run preflight should fail: {}",
        output_text(&output)
    );
    let payload: Value = serde_json::from_str(&std::fs::read_to_string(&report)?)?;
    assert_eq!(payload["mode"].as_str(), Some("--run"));
    assert_eq!(payload["iteration_count"].as_u64(), Some(0));
    assert_eq!(
        payload["artifact_freshness_preflight"]["status"].as_str(),
        Some("fail")
    );
    assert!(
        payload["failure_signatures"]
            .as_array()
            .is_some_and(|items| items.iter().any(|item| matches!(
                item.as_str(),
                Some("ws8_soak_standalone_artifact_not_current")
            ))),
        "runner must preserve WS8 fail-closed signature: {payload:#}"
    );
    Ok(())
}
