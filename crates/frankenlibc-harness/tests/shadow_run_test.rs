use frankenlibc_harness::shadow_run::{
    ShadowCommandExecutor, ShadowExecutionArtifacts, ShadowExecutionRequest, ShadowExecutionResult,
    ShadowRunConfig, ShadowRunError, ShadowRunManifest, run_shadow_manifest_with_executor,
};
use frankenlibc_harness::structured_log::ArtifactIndex;
use std::fs;
use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

fn temp_dir(name: &str) -> PathBuf {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("clock")
        .as_nanos();
    let dir = std::env::temp_dir().join(format!("frankenlibc-shadow-run-{name}-{nanos}"));
    fs::create_dir_all(&dir).expect("create temp dir");
    dir
}

#[derive(Default)]
struct PatternExecutor;

impl ShadowCommandExecutor for PatternExecutor {
    fn execute(
        &mut self,
        request: &ShadowExecutionRequest,
    ) -> Result<ShadowExecutionResult, ShadowRunError> {
        let candidate = request.env_overrides.contains_key("LD_PRELOAD");
        let args = &request.argv[1..];
        let diverges = candidate && args.iter().any(|arg| arg == "--trigger");
        let stdout = if diverges {
            "candidate-output\n".to_string()
        } else {
            format!("reference:{}\n", args.join(","))
        };
        let stderr = if diverges {
            "candidate-stderr\n".to_string()
        } else {
            String::new()
        };
        let syscall_trace = if request.capture_syscall_trace {
            if diverges {
                Some("openat(AT_FDCWD, \"/tmp/diverged\", O_RDONLY) = 3".to_string())
            } else {
                Some("openat(AT_FDCWD, \"/tmp/reference\", O_RDONLY) = 3".to_string())
            }
        } else {
            None
        };

        let exit_code = 0;
        let mut artifact_refs = Vec::new();
        if let Some(artifacts) = &request.artifacts {
            if let Some(parent) = artifacts
                .stdout_path
                .as_ref()
                .and_then(|path| path.parent())
                .or_else(|| {
                    artifacts
                        .stderr_path
                        .as_ref()
                        .and_then(|path| path.parent())
                })
                .or_else(|| {
                    artifacts
                        .syscall_path
                        .as_ref()
                        .and_then(|path| path.parent())
                })
                .or_else(|| artifacts.exit_code_path.parent())
            {
                fs::create_dir_all(parent).expect("create artifact dir");
            }
            if let Some(path) = &artifacts.stdout_path {
                fs::write(path, stdout.as_bytes()).expect("write stdout");
                artifact_refs.push(path_string(path));
            }
            if let Some(path) = &artifacts.stderr_path {
                fs::write(path, stderr.as_bytes()).expect("write stderr");
                artifact_refs.push(path_string(path));
            }
            fs::write(&artifacts.exit_code_path, format!("{exit_code}\n")).expect("write rc");
            artifact_refs.push(path_string(&artifacts.exit_code_path));
            if let (Some(trace), Some(path)) = (&syscall_trace, &artifacts.syscall_path) {
                fs::write(path, trace.as_bytes()).expect("write syscall trace");
                artifact_refs.push(path_string(path));
            }
        }

        Ok(ShadowExecutionResult {
            exit_code,
            signal: None,
            timed_out: false,
            stdout,
            stderr,
            duration_ns: 1_000,
            syscall_trace,
            artifact_refs,
        })
    }
}

struct FixedExitExecutor {
    exit_code: i32,
}

impl ShadowCommandExecutor for FixedExitExecutor {
    fn execute(
        &mut self,
        request: &ShadowExecutionRequest,
    ) -> Result<ShadowExecutionResult, ShadowRunError> {
        let stdout = format!("fixed:{}\n", request.argv.join(" "));
        let mut artifact_refs = Vec::new();
        if let Some(artifacts) = &request.artifacts {
            if let Some(parent) = artifacts
                .stdout_path
                .as_ref()
                .and_then(|path| path.parent())
                .or_else(|| {
                    artifacts
                        .stderr_path
                        .as_ref()
                        .and_then(|path| path.parent())
                })
                .or_else(|| {
                    artifacts
                        .syscall_path
                        .as_ref()
                        .and_then(|path| path.parent())
                })
                .or_else(|| artifacts.exit_code_path.parent())
            {
                fs::create_dir_all(parent).expect("create artifact dir");
            }
            if let Some(path) = &artifacts.stdout_path {
                fs::write(path, stdout.as_bytes()).expect("write stdout");
                artifact_refs.push(path_string(path));
            }
            if let Some(path) = &artifacts.stderr_path {
                fs::write(path, b"").expect("write stderr");
                artifact_refs.push(path_string(path));
            }
            fs::write(&artifacts.exit_code_path, format!("{}\n", self.exit_code))
                .expect("write rc");
            artifact_refs.push(path_string(&artifacts.exit_code_path));
        }

        Ok(ShadowExecutionResult {
            exit_code: self.exit_code,
            signal: None,
            timed_out: false,
            stdout,
            stderr: String::new(),
            duration_ns: 500,
            syscall_trace: None,
            artifact_refs,
        })
    }
}

fn path_string(path: &Path) -> String {
    path.to_string_lossy().into_owned()
}

#[test]
fn manifest_identifies_shadow_scenarios() {
    let manifest: ShadowRunManifest = serde_json::from_str(
        r#"{
          "schema_version":"v1",
          "manifest_id":"shadow-manifest",
          "generated_utc":"2026-04-06T00:00:00Z",
          "description":"shadow manifest",
          "replay_defaults":{"seed_key":"FRANKENLIBC_E2E_SEED","env_keys":["FRANKENLIBC_E2E_SEED"],"deterministic_inputs":"static"},
          "scenarios":[
            {
              "id":"smoke.coreutils_cat_shadow",
              "class":"smoke",
              "label":"coreutils_cat_shadow",
              "priority":1,
              "description":"Shadow-run parity check for cat.",
              "command":["/bin/cat","/etc/hosts"],
              "mode_expectations":{"strict":{"expected_outcome":"pass","pass_condition":"exit_code == 0","allowed_exit_codes":[0]}},
              "artifact_policy":{"capture_stdout":true,"capture_stderr":true,"capture_env_on_failure":true,"capture_bundle_on_failure":true,"required_artifacts":["baseline.stdout.txt","stdout.txt"]},
              "replay":{"seed_key":"FRANKENLIBC_E2E_SEED","env_keys":["FRANKENLIBC_E2E_SEED","FRANKENLIBC_MODE","LD_PRELOAD"],"deterministic_inputs":"static argv"}
            },
            {
              "id":"smoke.coreutils_echo",
              "class":"smoke",
              "label":"coreutils_echo",
              "priority":1,
              "description":"Simple stdout path.",
              "command":["/bin/echo","hello"],
              "mode_expectations":{"strict":{"expected_outcome":"pass","pass_condition":"exit_code == 0","allowed_exit_codes":[0]}},
              "artifact_policy":{"capture_stdout":true,"capture_stderr":true,"capture_env_on_failure":true,"capture_bundle_on_failure":true,"required_artifacts":["stdout.txt"]},
              "replay":{"seed_key":"FRANKENLIBC_E2E_SEED","env_keys":["FRANKENLIBC_E2E_SEED"],"deterministic_inputs":"static argv"}
            }
          ]
        }"#,
    )
    .expect("manifest parses");

    let ids = manifest
        .shadow_scenarios()
        .into_iter()
        .map(|scenario| scenario.id.as_str())
        .collect::<Vec<_>>();
    assert_eq!(ids, vec!["smoke.coreutils_cat_shadow"]);
}

#[test]
fn run_shadow_manifest_writes_report_log_and_replay_bundle() {
    let manifest: ShadowRunManifest = serde_json::from_str(
        r#"{
          "schema_version":"v1",
          "manifest_id":"shadow-manifest",
          "generated_utc":"2026-04-06T00:00:00Z",
          "description":"shadow manifest",
          "replay_defaults":{"seed_key":"FRANKENLIBC_E2E_SEED","env_keys":["FRANKENLIBC_E2E_SEED"],"deterministic_inputs":"static"},
          "scenarios":[
            {
              "id":"smoke.shadow_case",
              "class":"smoke",
              "label":"shadow_case",
              "priority":1,
              "description":"Shadow-run parity check for a synthetic case.",
              "command":["/bin/echo","--trigger","--noise-a","--noise-b"],
              "mode_expectations":{"strict":{"expected_outcome":"pass","pass_condition":"exit_code == 0","allowed_exit_codes":[0]}},
              "artifact_policy":{"capture_stdout":true,"capture_stderr":true,"capture_env_on_failure":true,"capture_bundle_on_failure":true,"required_artifacts":["baseline.stdout.txt","baseline.stderr.txt","baseline.exit_code","stdout.txt","stderr.txt"]},
              "replay":{"seed_key":"FRANKENLIBC_E2E_SEED","env_keys":["FRANKENLIBC_E2E_SEED","FRANKENLIBC_MODE","LD_PRELOAD"],"deterministic_inputs":"static argv"}
            }
          ]
        }"#,
    )
    .expect("manifest parses");

    let root = temp_dir("report");
    let out_dir = root.join("out");
    let report_path = root.join("shadow_run.report.json");
    let markdown_report_path = root.join("shadow_run.report.md");
    let log_path = root.join("shadow_run.log.jsonl");
    let artifact_index_path = root.join("shadow_run.artifacts.json");

    let mut config = ShadowRunConfig::new(
        root.clone(),
        out_dir.clone(),
        root.join("libfrankenlibc_abi.so"),
        Duration::from_secs(1),
    );
    config.report_path = Some(report_path.clone());
    config.log_path = Some(log_path.clone());
    config.artifact_index_path = Some(artifact_index_path.clone());
    config.run_id = "shadow-run-test".to_string();
    config.bead_id = "bd-test-shadow".to_string();

    let report = run_shadow_manifest_with_executor(
        &manifest,
        &[String::from("strict")],
        &config,
        &mut PatternExecutor,
    )
    .expect("shadow run succeeds");

    assert_eq!(report.bead, "bd-test-shadow");
    assert_eq!(report.summary.total_runs, 1);
    assert_eq!(report.summary.diverged, 1);
    assert_eq!(report.summary.skipped, 0);
    assert!(report_path.exists(), "report should be written");
    assert!(
        markdown_report_path.exists(),
        "human-readable markdown report should be written"
    );
    assert!(log_path.exists(), "log should be written");
    assert!(
        artifact_index_path.exists(),
        "artifact index should be written"
    );

    let scenario = &report.scenarios[0];
    assert_eq!(scenario.trace_id, "bd-test-shadow::shadow-run-test::001");
    assert_eq!(scenario.status, "diverged");
    assert!(scenario.diverged);
    assert_eq!(scenario.replay.mode, "strict");
    assert!(!scenario.replay.replay_key.is_empty());
    assert!(
        scenario
            .artifact_refs
            .iter()
            .any(|path| path.ends_with("shadow_replay_bundle.json")),
        "replay bundle should be persisted on divergence"
    );
    assert!(
        scenario
            .artifact_refs
            .iter()
            .any(|path| path.ends_with("shadow_divergence_report.json")),
        "divergence report should be persisted on divergence"
    );
    assert!(
        scenario
            .artifact_refs
            .iter()
            .any(|path| path.ends_with("baseline.env.json")),
        "failure env capture should persist the baseline environment"
    );
    assert!(
        scenario
            .artifact_refs
            .iter()
            .any(|path| path.ends_with("candidate.env.json")),
        "failure env capture should persist the candidate environment"
    );
    assert!(
        scenario
            .divergence
            .as_ref()
            .expect("divergence")
            .analysis_call_stack
            .as_ref()
            .is_some_and(|stack| !stack.is_empty()),
        "analysis call stack should be captured"
    );
    assert_eq!(
        scenario
            .minimization
            .as_ref()
            .expect("minimization")
            .minimized_command,
        vec!["/bin/echo".to_string(), "--trigger".to_string()]
    );

    let log_body = fs::read_to_string(&log_path).expect("read log");
    assert!(
        log_body.contains("\"event\":\"conformance.shadow_run_divergence\""),
        "log should include divergence event"
    );
    assert!(
        log_body.contains("\"trace_id\":\"bd-test-shadow::shadow-run-test::001\""),
        "log should carry the scenario trace id"
    );

    let markdown_body =
        fs::read_to_string(&markdown_report_path).expect("read markdown shadow report");
    assert!(
        markdown_body.contains("# Shadow Run Report"),
        "markdown report should include the title"
    );
    assert!(
        markdown_body.contains("`smoke.shadow_case`"),
        "markdown report should include the scenario id"
    );
    assert!(
        markdown_body.contains("stdout, stderr, syscall_trace"),
        "markdown report should summarize mismatch axes"
    );
    assert!(
        markdown_body.contains("Minimized replay command:"),
        "markdown report should include minimized replay details"
    );

    let artifact_index: ArtifactIndex = serde_json::from_str(
        &fs::read_to_string(&artifact_index_path).expect("read artifact index"),
    )
    .expect("artifact index parses");
    assert_eq!(artifact_index.run_id, "shadow-run-test");
    assert!(
        artifact_index
            .artifacts
            .iter()
            .any(|artifact| artifact.kind == "log"),
        "artifact index should include the structured log"
    );
    assert!(
        artifact_index
            .artifacts
            .iter()
            .any(|artifact| artifact.kind == "report"),
        "artifact index should include the report"
    );
    assert!(
        artifact_index
            .artifacts
            .iter()
            .any(|artifact| artifact.kind == "report_human"),
        "artifact index should include the human-readable report"
    );
    assert!(
        artifact_index.artifacts.iter().any(|artifact| {
            artifact.kind == "replay_bundle"
                && artifact
                    .join_keys
                    .as_ref()
                    .is_some_and(|join| join.trace_ids == vec![scenario.trace_id.clone()])
        }),
        "replay bundle should join back to the canonical trace id"
    );
    assert!(
        artifact_index.artifacts.iter().any(|artifact| {
            artifact.kind == "divergence_report"
                && artifact
                    .join_keys
                    .as_ref()
                    .is_some_and(|join| join.trace_ids == vec![scenario.trace_id.clone()])
        }),
        "divergence report should join back to the canonical trace id"
    );
}

#[test]
fn executor_writes_requested_artifacts() {
    let tmp = temp_dir("artifacts");
    let artifacts = ShadowExecutionArtifacts {
        stdout_path: Some(tmp.join("stdout.txt")),
        stderr_path: Some(tmp.join("stderr.txt")),
        exit_code_path: tmp.join("exit_code"),
        syscall_path: Some(tmp.join("syscall.txt")),
    };

    let request = ShadowExecutionRequest {
        argv: vec!["/bin/echo".to_string(), "--trigger".to_string()],
        cwd: tmp.clone(),
        env_overrides: [("LD_PRELOAD".to_string(), "/tmp/lib.so".to_string())]
            .into_iter()
            .collect(),
        env_remove: Default::default(),
        timeout: Duration::from_secs(1),
        capture_syscall_trace: true,
        artifacts: Some(artifacts.clone()),
    };

    let result = PatternExecutor
        .execute(&request)
        .expect("execution succeeds");
    assert_eq!(result.exit_code, 0);
    assert!(
        artifacts
            .stdout_path
            .as_ref()
            .expect("stdout path")
            .exists()
    );
    assert!(
        artifacts
            .stderr_path
            .as_ref()
            .expect("stderr path")
            .exists()
    );
    assert!(artifacts.exit_code_path.exists());
    assert!(
        artifacts
            .syscall_path
            .as_ref()
            .expect("syscall path")
            .exists()
    );
}

#[test]
fn optional_missing_binary_is_skipped_instead_of_aborting_manifest() {
    let manifest: ShadowRunManifest = serde_json::from_str(
        r#"{
          "schema_version":"v1",
          "manifest_id":"shadow-manifest",
          "generated_utc":"2026-04-06T00:00:00Z",
          "description":"shadow manifest",
          "replay_defaults":{"seed_key":"FRANKENLIBC_E2E_SEED","env_keys":["FRANKENLIBC_E2E_SEED"],"deterministic_inputs":"static"},
          "scenarios":[
            {
              "id":"smoke.optional_shadow_case",
              "class":"smoke",
              "label":"optional_shadow_case",
              "priority":1,
              "description":"Optional shadow-run parity check for a binary that may be missing.",
              "command":["frankenlibc-shadow-run-missing-binary-xyz"],
              "mode_expectations":{"strict":{"expected_outcome":"pass","pass_condition":"exit_code == 0","allowed_exit_codes":[0]}},
              "artifact_policy":{"capture_stdout":true,"capture_stderr":true,"capture_env_on_failure":true,"capture_bundle_on_failure":true,"required_artifacts":["baseline.stdout.txt","stdout.txt"]},
              "replay":{"seed_key":"FRANKENLIBC_E2E_SEED","env_keys":["FRANKENLIBC_E2E_SEED","FRANKENLIBC_MODE","LD_PRELOAD"],"deterministic_inputs":"static argv"}
            }
          ]
        }"#,
    )
    .expect("manifest parses");

    let root = temp_dir("skip");
    let config = ShadowRunConfig::new(
        root.clone(),
        root.join("out"),
        root.join("libfrankenlibc_abi.so"),
        Duration::from_secs(1),
    );

    let report = run_shadow_manifest_with_executor(
        &manifest,
        &[String::from("strict")],
        &config,
        &mut PatternExecutor,
    )
    .expect("shadow run succeeds");

    assert_eq!(report.summary.total_runs, 1);
    assert_eq!(report.summary.skipped, 1);
    assert_eq!(report.summary.errors, 0);
    assert_eq!(report.scenarios[0].status, "skipped");
}

#[test]
fn smoke_fixture_placeholder_is_resolved_into_replay_command() {
    let manifest: ShadowRunManifest = serde_json::from_str(
        r#"{
          "schema_version":"v1",
          "manifest_id":"shadow-manifest",
          "generated_utc":"2026-04-06T00:00:00Z",
          "description":"shadow manifest",
          "replay_defaults":{"seed_key":"FRANKENLIBC_E2E_SEED","env_keys":["FRANKENLIBC_E2E_SEED"],"deterministic_inputs":"static"},
          "scenarios":[
            {
              "id":"smoke.coreutils_cat_shadow",
              "class":"smoke",
              "label":"coreutils_cat_shadow",
              "priority":1,
              "description":"Shadow-run parity check for cat over deterministic smoke fixture input.",
              "command":["/bin/cat","${SMOKE_FIXTURE}"],
              "mode_expectations":{"strict":{"expected_outcome":"pass","pass_condition":"exit_code == 0 and baseline_stdout == stdout and baseline_stderr == stderr","allowed_exit_codes":[0]}},
              "artifact_policy":{"capture_stdout":true,"capture_stderr":true,"capture_env_on_failure":true,"capture_bundle_on_failure":true,"required_artifacts":["baseline.stdout.txt","stdout.txt"]},
              "replay":{"seed_key":"FRANKENLIBC_E2E_SEED","env_keys":["FRANKENLIBC_E2E_SEED","FRANKENLIBC_MODE","LD_PRELOAD"],"deterministic_inputs":"static argv"}
            }
          ]
        }"#,
    )
    .expect("manifest parses");

    let root = temp_dir("placeholder");
    let config = ShadowRunConfig::new(
        root.clone(),
        root.join("out"),
        root.join("libfrankenlibc_abi.so"),
        Duration::from_secs(1),
    );

    let report = run_shadow_manifest_with_executor(
        &manifest,
        &[String::from("strict")],
        &config,
        &mut PatternExecutor,
    )
    .expect("shadow run succeeds");

    let resolved_fixture = PathBuf::from(&report.scenarios[0].replay.command[1]);
    assert!(
        resolved_fixture.exists(),
        "placeholder fixture should be materialized"
    );
    assert!(
        resolved_fixture.ends_with("smoke_shadow_input.txt"),
        "expected deterministic smoke fixture path, got {}",
        resolved_fixture.display()
    );
}

#[test]
fn nonzero_allowed_exit_code_does_not_trigger_baseline_error() {
    let manifest: ShadowRunManifest = serde_json::from_str(
        r#"{
          "schema_version":"v1",
          "manifest_id":"shadow-manifest",
          "generated_utc":"2026-04-06T00:00:00Z",
          "description":"shadow manifest",
          "replay_defaults":{"seed_key":"FRANKENLIBC_E2E_SEED","env_keys":["FRANKENLIBC_E2E_SEED"],"deterministic_inputs":"static"},
          "scenarios":[
            {
              "id":"smoke.nonzero_exit_shadow",
              "class":"smoke",
              "label":"nonzero_exit_shadow",
              "priority":1,
              "description":"Shadow-run parity check for a command with an intentionally nonzero allowed exit.",
              "command":["/bin/echo","--allowed-nonzero"],
              "mode_expectations":{"strict":{"expected_outcome":"pass","pass_condition":"exit_code == 7","allowed_exit_codes":[7]}},
              "artifact_policy":{"capture_stdout":false,"capture_stderr":false,"capture_env_on_failure":true,"capture_bundle_on_failure":true,"required_artifacts":["baseline.exit_code","exit_code"]},
              "replay":{"seed_key":"FRANKENLIBC_E2E_SEED","env_keys":["FRANKENLIBC_E2E_SEED","FRANKENLIBC_MODE","LD_PRELOAD"],"deterministic_inputs":"static argv"}
            }
          ]
        }"#,
    )
    .expect("manifest parses");

    let root = temp_dir("allowed-nonzero");
    let config = ShadowRunConfig::new(
        root.clone(),
        root.join("out"),
        root.join("libfrankenlibc_abi.so"),
        Duration::from_secs(1),
    );

    let report = run_shadow_manifest_with_executor(
        &manifest,
        &[String::from("strict")],
        &config,
        &mut FixedExitExecutor { exit_code: 7 },
    )
    .expect("shadow run succeeds");

    assert_eq!(report.summary.passed, 1);
    assert_eq!(report.summary.errors, 0);
    assert_eq!(report.scenarios[0].status, "pass");
    assert!(
        !report.scenarios[0]
            .artifact_refs
            .iter()
            .any(|path| path.ends_with("stdout.txt") || path.ends_with("stderr.txt")),
        "disabled stdout/stderr capture should not emit those artifacts"
    );
}

#[test]
fn expected_divergence_can_satisfy_shadow_scenario_contract() {
    let manifest: ShadowRunManifest = serde_json::from_str(
        r#"{
          "schema_version":"v1",
          "manifest_id":"shadow-manifest",
          "generated_utc":"2026-04-06T00:00:00Z",
          "description":"shadow manifest",
          "replay_defaults":{"seed_key":"FRANKENLIBC_E2E_SEED","env_keys":["FRANKENLIBC_E2E_SEED"],"deterministic_inputs":"static"},
          "scenarios":[
            {
              "id":"smoke.expected_divergence_shadow",
              "class":"smoke",
              "label":"expected_divergence_shadow",
              "priority":1,
              "description":"Shadow-run divergence is the expected outcome for this synthetic case.",
              "command":["/bin/echo","--trigger"],
              "mode_expectations":{"strict":{"expected_outcome":"diverged","pass_condition":"exit_code == 0","allowed_exit_codes":[0]}},
              "artifact_policy":{"capture_stdout":true,"capture_stderr":true,"capture_env_on_failure":true,"capture_bundle_on_failure":true,"required_artifacts":["baseline.stdout.txt","stdout.txt"]},
              "replay":{"seed_key":"FRANKENLIBC_E2E_SEED","env_keys":["FRANKENLIBC_E2E_SEED","FRANKENLIBC_MODE","LD_PRELOAD"],"deterministic_inputs":"static argv"}
            }
          ]
        }"#,
    )
    .expect("manifest parses");

    let root = temp_dir("expected-divergence");
    let config = ShadowRunConfig::new(
        root.clone(),
        root.join("out"),
        root.join("libfrankenlibc_abi.so"),
        Duration::from_secs(1),
    );

    let report = run_shadow_manifest_with_executor(
        &manifest,
        &[String::from("strict")],
        &config,
        &mut PatternExecutor,
    )
    .expect("shadow run succeeds");

    assert_eq!(report.summary.passed, 1);
    assert_eq!(report.summary.diverged, 0);
    assert_eq!(report.scenarios[0].status, "pass");
    assert!(report.scenarios[0].diverged);
}

#[test]
fn missing_required_artifact_fails_shadow_manifest() {
    let manifest: ShadowRunManifest = serde_json::from_str(
        r#"{
          "schema_version":"v1",
          "manifest_id":"shadow-manifest",
          "generated_utc":"2026-04-06T00:00:00Z",
          "description":"shadow manifest",
          "replay_defaults":{"seed_key":"FRANKENLIBC_E2E_SEED","env_keys":["FRANKENLIBC_E2E_SEED"],"deterministic_inputs":"static"},
          "scenarios":[
            {
              "id":"smoke.required_artifact_shadow",
              "class":"smoke",
              "label":"required_artifact_shadow",
              "priority":1,
              "description":"Required artifact enforcement should fail when capture policy disables the file.",
              "command":["/bin/echo"],
              "mode_expectations":{"strict":{"expected_outcome":"pass","pass_condition":"exit_code == 0","allowed_exit_codes":[0]}},
              "artifact_policy":{"capture_stdout":false,"capture_stderr":false,"capture_env_on_failure":false,"capture_bundle_on_failure":false,"required_artifacts":["stdout.txt"]},
              "replay":{"seed_key":"FRANKENLIBC_E2E_SEED","env_keys":["FRANKENLIBC_E2E_SEED"],"deterministic_inputs":"static argv"}
            }
          ]
        }"#,
    )
    .expect("manifest parses");

    let root = temp_dir("required-artifact");
    let config = ShadowRunConfig::new(
        root.clone(),
        root.join("out"),
        root.join("libfrankenlibc_abi.so"),
        Duration::from_secs(1),
    );

    let err = run_shadow_manifest_with_executor(
        &manifest,
        &[String::from("strict")],
        &config,
        &mut PatternExecutor,
    )
    .unwrap_err();

    assert!(matches!(
        err,
        ShadowRunError::MissingRequiredArtifact {
            scenario,
            artifact
        } if scenario == "smoke.required_artifact_shadow" && artifact == "stdout.txt"
    ));
}
