//! bd-reality-202609-lx578q.1: Fail-closed WS8 evidence and subprocess tests.

use serde_json::Value;
use std::error::Error;
use std::path::{Path, PathBuf};
use std::process::Command;

type TestResult<T = ()> = Result<T, Box<dyn Error>>;

fn workspace_root() -> TestResult<PathBuf> {
    Ok(Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .ok_or("crate manifest should have crates parent")?
        .parent()
        .ok_or("crates directory should have workspace parent")?
        .to_path_buf())
}

fn manifest_path(root: &Path) -> PathBuf {
    root.join("tests/conformance/ws8_e2e_standalone_verification.v1.json")
}

fn script_path(root: &Path) -> PathBuf {
    root.join("scripts/check_ws8_e2e_standalone_verification.sh")
}

#[test]
fn manifest_anchors_ws8_e2e_standalone_verification() -> TestResult {
    let root = workspace_root()?;
    let manifest_file = manifest_path(&root);
    assert!(manifest_file.exists(), "manifest file must exist");

    let content = std::fs::read_to_string(&manifest_file)?;
    let json: Value = serde_json::from_str(&content)?;

    assert_eq!(
        json.get("manifest_id").and_then(Value::as_str),
        Some("ws8-e2e-standalone-verification"),
        "manifest_id must match"
    );
    assert_eq!(
        json.get("bead_id").and_then(Value::as_str),
        Some("bd-38x82.6"),
        "bead_id must match bd-38x82.6"
    );
    assert_eq!(
        json.get("parent_bead").and_then(Value::as_str),
        Some("bd-38x82"),
        "parent_bead must be bd-38x82"
    );

    Ok(())
}

#[test]
fn manifest_declares_both_architectures() -> TestResult {
    let root = workspace_root()?;
    let content = std::fs::read_to_string(manifest_path(&root))?;
    let json: Value = serde_json::from_str(&content)?;

    let archs = json
        .pointer("/scope/architectures")
        .and_then(Value::as_array)
        .ok_or("architectures array must exist")?;

    let arch_strs: Vec<&str> = archs.iter().filter_map(Value::as_str).collect();
    assert!(arch_strs.contains(&"x86_64"), "must support x86_64");
    assert!(arch_strs.contains(&"aarch64"), "must support aarch64");

    Ok(())
}

#[test]
fn manifest_anchors_all_ws8_companion_beads() -> TestResult {
    let root = workspace_root()?;
    let content = std::fs::read_to_string(manifest_path(&root))?;
    let json: Value = serde_json::from_str(&content)?;

    let companions = json
        .pointer("/scope/companion_beads")
        .and_then(Value::as_array)
        .ok_or("companion_beads array must exist")?;

    let bead_ids: Vec<&str> = companions
        .iter()
        .filter_map(|c| c.get("bead_id").and_then(Value::as_str))
        .collect();

    assert!(bead_ids.contains(&"bd-38x82.1"), "must include bd-38x82.1");
    assert!(bead_ids.contains(&"bd-38x82.2"), "must include bd-38x82.2");
    assert!(bead_ids.contains(&"bd-38x82.3"), "must include bd-38x82.3");
    assert!(bead_ids.contains(&"bd-38x82.4"), "must include bd-38x82.4");
    assert!(bead_ids.contains(&"bd-38x82.5"), "must include bd-38x82.5");

    Ok(())
}

#[test]
fn e2e_verification_script_exists_and_is_executable() -> TestResult {
    use std::os::unix::fs::PermissionsExt;
    let root = workspace_root()?;
    let script = script_path(&root);
    assert!(script.exists(), "verification script must exist");

    let perms = std::fs::metadata(&script)?.permissions();
    assert!(perms.mode() & 0o111 != 0, "script must be executable");
    Ok(())
}

// Keep test artifacts for inspection; repository policy forbids deleting even
// temporary files. Each invocation gets its own directory and child environment.
fn isolated_dir(label: &str) -> TestResult<PathBuf> {
    let nonce = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)?
        .as_nanos();
    let path =
        std::env::temp_dir().join(format!("ws8-unit-{label}-{}-{nonce}", std::process::id()));
    std::fs::create_dir(&path)?;
    Ok(path)
}

fn helper_unit_cases(label: &str, cases: &str) -> TestResult {
    let root = workspace_root()?;
    let dir = isolated_dir(label)?;
    // Synthetic helper inputs test rejection logic only. Never run the gate's
    // entrypoint with these inputs or publish them as standalone evidence.
    let loader = r#"
import pathlib, sys
root = pathlib.Path(sys.argv[1])
unit_dir = pathlib.Path(sys.argv[2])
source = (root / 'scripts/check_ws8_e2e_standalone_verification.sh').read_text()
helpers = source.split("<<'PY'\n", 1)[1].split('# Execution entrypoint.', 1)[0]
sys.argv = ['ws8-helper-unit', str(root), str(root / 'tests/conformance/ws8_e2e_standalone_verification.v1.json'), str(unit_dir), str(unit_dir / 'report.json'), str(unit_dir / 'log.jsonl'), '--preflight']
exec(compile(helpers, 'ws8-helper-unit', 'exec'), globals())
identity = {'source_commit': 'synthetic-unit-commit', 'source_hash': 'synthetic-unit-source'}
def synthetic_run(stdout='', code=0, executed=True):
    return {'stdout': stdout, 'stderr': '', 'exit_code': code, 'executed': executed}
"#;
    let output = Command::new("python3")
        .args(["-c", &format!("{loader}\n{cases}")])
        .arg(&root)
        .arg(&dir)
        .current_dir(&root)
        .env_remove("LD_PRELOAD")
        .env_remove("LD_AUDIT")
        .output()?;
    assert!(
        output.status.success(),
        "synthetic helper unit {label}: stdout={}\nstderr={}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    Ok(())
}

#[test]
fn helper_aggregation_requires_all_positive_observations() -> TestResult {
    helper_unit_cases(
        "aggregate",
        r#"
assert aggregate([]) == 'blocked'
assert aggregate([{'status': 'pass'}, {'status': 'blocked'}]) == 'blocked'
assert aggregate([{'status': 'blocked'}, {'status': 'fail'}]) == 'fail'
assert aggregate([{'status': 'pass'}, {}]) == 'blocked'
assert aggregate([{'status': 'pass'}, {'status': 'pass'}]) == 'pass'
"#,
    )
}

#[test]
fn helper_cross_runner_and_probe_receipt_cannot_fall_back_to_pass() -> TestResult {
    helper_unit_cases(
        "cross-runner",
        r#"
import types
probe = unit_dir / 'synthetic-probe'
probe.write_bytes(b'synthetic-unit-only')
os.environ['WS8_E2E_AARCH64_ARTIFACT'] = str(unit_dir / 'synthetic-aarch64.so')
os.environ['WS8_E2E_AARCH64_PROBE'] = str(probe)
inspect_artifact = lambda *args: {'status': 'pass'}
os.uname = lambda: types.SimpleNamespace(machine='x86_64')
shutil.which = lambda name: None
assert run_architecture('aarch64')['reason'] == 'probe_receipt_missing_or_invalid'
receipt = dict(identity, artifact_sha256=digest(probe), architecture='aarch64', exit_code=0, command=['synthetic-unit'])
receipt_path = pathlib.Path(str(probe) + '.ws8-build.json')
receipt_path.write_text(json.dumps(dict(receipt, source_hash='stale')))
assert run_architecture('aarch64')['reason'] == 'stale_or_wrong_probe_receipt'
receipt_path.write_text(json.dumps(receipt))
row = run_architecture('aarch64')
assert row['status'] == 'blocked' and row['reason'] == 'cross_runner_or_sysroot_missing', row
assert row['cases'] == {}
"#,
    )
}

#[test]
fn helper_artifact_rejects_missing_empty_stale_receipt_and_failed_inspection() -> TestResult {
    helper_unit_cases(
        "artifact",
        r#"
artifact = unit_dir / 'synthetic-artifact.so'
assert inspect_artifact(artifact, 'x86_64')['reason'] == 'artifact_missing_or_empty'
artifact.touch()
assert inspect_artifact(artifact, 'x86_64')['reason'] == 'artifact_missing_or_empty'
artifact.write_bytes(b'synthetic-unit-input-not-an-ELF')
assert inspect_artifact(artifact, 'x86_64')['reason'] == 'build_receipt_missing_or_invalid'
receipt_path = pathlib.Path(str(artifact) + '.ws8-build.json')
receipt = dict(identity, artifact_sha256=digest(artifact), features=FEATURES,
               profile='release', architecture='x86_64', exit_code=0, command=['synthetic-unit-command'])
for field, wrong in [('source_commit', 'old'), ('source_hash', 'old'), ('artifact_sha256', 'wrong'),
                     ('features', []), ('profile', 'debug'), ('architecture', 'aarch64'), ('exit_code', 1), ('command', [])]:
    receipt_path.write_text(json.dumps(dict(receipt, **{field: wrong})))
    assert inspect_artifact(artifact, 'x86_64')['reason'] == 'stale_or_wrong_configuration_receipt', field
receipt_path.write_text(json.dumps(receipt))
for failed_tool in ['nm', 'readelf']:
    def unit_tool(args):
        return synthetic_run('', 1 if args[0] == failed_tool else 0)
    run_cmd = unit_tool
    row = inspect_artifact(artifact, 'x86_64')
    assert row['status'] == 'fail' and row['reason'] == 'artifact_inspection_failed', row
run_cmd = lambda args: synthetic_run('')
assert inspect_artifact(artifact, 'x86_64')['reason'] == 'missing_or_wrong_elf_identity'
"#,
    )
}

#[test]
fn helper_probe_rejects_failed_missing_and_wrong_provider_observations() -> TestResult {
    helper_unit_cases(
        "probe",
        r#"
import copy
artifact = unit_dir / 'synthetic-provider.so'
case = 'string_pipeline'
names = set(REQUIRED_CHECKS[case]) | {'runtime_ready', 'child_maps_complete'}
observation = {'case_id': case, 'mode': 'strict', 'status': 'pass',
    'checks': [{'name': name, 'passed': True} for name in sorted(names)],
    'providers': [{'symbol': symbol, 'address': '0x1100'} for symbol in sorted(REQUIRED_PROVIDERS)],
    'maps': f'1000-2000 r-xp 00000000 00:00 0 {artifact}\n', 'executed': len(names)}
def evaluate(value):
    return evaluate_probe(synthetic_run(json.dumps(value)), case, 'strict', artifact)
# This acceptance is deliberately synthetic and proves only helper behavior.
assert evaluate(observation)['status'] == 'pass'
for run in [synthetic_run(json.dumps(observation), 1), synthetic_run(json.dumps(observation), executed=False),
            dict(synthetic_run(json.dumps(observation)), timed_out=True), synthetic_run('{'), synthetic_run('[]')]:
    assert evaluate_probe(run, case, 'strict', artifact)['status'] == 'fail'
for mutation in ['failed_check', 'zero_checks', 'missing_check', 'wrong_case', 'wrong_mode', 'wrong_provider', 'missing_provider', 'wrong_symbol', 'empty_maps', 'malformed_maps']:
    value = copy.deepcopy(observation)
    if mutation == 'failed_check': value['checks'][0]['passed'] = False
    elif mutation == 'zero_checks': value.update(checks=[], executed=0)
    elif mutation == 'missing_check': value['checks'].pop(); value['executed'] -= 1
    elif mutation == 'wrong_case': value['case_id'] = 'unrequested'
    elif mutation == 'wrong_mode': value['mode'] = 'hardened'
    elif mutation == 'wrong_provider': value['providers'][0]['address'] = '0x9999'
    elif mutation == 'missing_provider': value['providers'].pop()
    elif mutation == 'wrong_symbol': value['providers'][0]['symbol'] = 'invented'
    elif mutation == 'empty_maps': value['maps'] = ''
    elif mutation == 'malformed_maps': value['maps'] = 'not maps'
    assert evaluate(value)['status'] == 'fail', mutation
host = copy.deepcopy(observation)
host['maps'] += '3000-4000 r-xp 00000000 00:00 0 /lib/libc.so.6\n'
row = evaluate(host)
assert row['status'] == 'blocked' and row['reason'] == 'host_runtime_mapped', row
assert row['supported_abi_execution'] is True
"#,
    )
}

#[test]
fn helper_companion_requires_execution_and_nonzero_tests_in_every_suite() -> TestResult {
    helper_unit_cases(
        "companion",
        r#"
positive = 'test result: ok. 3 passed; 0 failed; 0 ignored;\ntest result: ok. 2 passed; 0 failed; 0 ignored;\n'
suites = ['synthetic-a', 'synthetic-b']
assert companion_result(synthetic_run(''), [])['status'] == 'fail'
row = companion_result(synthetic_run(positive), suites)
assert row['status'] == 'pass' and row['passed_tests'] == 5
for run in [synthetic_run(positive, 1), synthetic_run(positive, executed=False),
            dict(synthetic_run(positive), timed_out=True), synthetic_run(''),
            synthetic_run('test result: ok. 0 passed; 0 failed; 99 filtered out;\n' * 2),
            synthetic_run('test result: FAILED. 3 passed; 1 failed;\n' * 2),
            synthetic_run('test result: ok. 3 passed; 1 failed;\n' * 2),
            synthetic_run('test result: ok. 3 passed; 0 failed;\n')]:
    assert companion_result(run, suites)['status'] == 'fail', run
"#,
    )
}

#[test]
fn real_child_execution_rejects_nonzero_missing_malformed_and_timeout() -> TestResult {
    helper_unit_cases(
        "real-child-errors",
        r#"
artifact = unit_dir / 'unprovided-artifact.so'
nonzero = run_cmd([sys.executable, '-c', 'import sys; print("child-ran"); sys.exit(7)'])
assert nonzero['executed'] is True and nonzero['exit_code'] == 7
assert nonzero['stdout'].strip() == 'child-ran'
missing = run_cmd([str(unit_dir / 'executable-that-does-not-exist')])
assert missing['executed'] is False and missing['exit_code'] is None and missing['stderr']
malformed = run_cmd([sys.executable, '-c', 'print("not-json")'])
assert malformed['executed'] is True and malformed['exit_code'] == 0
assert malformed['stdout'].strip() == 'not-json'
timed = run_cmd([sys.executable, '-c', 'import time; time.sleep(10)'], timeout=0.05)
assert timed['executed'] is True and timed.get('timed_out') is True
assert timed['exit_code'] is not None and timed['exit_code'] != 0
for result in [nonzero, missing, malformed, timed]:
    assert evaluate_probe(result, 'string_pipeline', 'strict', artifact)['status'] == 'fail'
"#,
    )
}

fn preflight_command(root: &Path, dir: &Path) -> Command {
    let mut command = Command::new(script_path(root));
    command
        .arg("--preflight")
        .current_dir(root)
        .env("WS8_E2E_OUT_DIR", dir)
        .env("WS8_E2E_REPORT", dir.join("report.json"))
        .env("WS8_E2E_LOG", dir.join("log.jsonl"))
        .env("WS8_E2E_MANIFEST", manifest_path(root))
        .env("WS8_E2E_X86_ARTIFACT", dir.join("missing-x86.so"))
        .env("WS8_E2E_AARCH64_ARTIFACT", dir.join("missing-arm.so"))
        .env("WS8_E2E_PACKAGE", dir.join("missing.deb"))
        .env_remove("LD_PRELOAD")
        .env_remove("LD_AUDIT");
    command
}

#[test]
fn preflight_missing_artifacts_overwrites_stale_pass_with_blocked_report() -> TestResult {
    let root = workspace_root()?;
    let dir = isolated_dir("preflight")?;
    std::fs::write(
        dir.join("report.json"),
        r#"{"status":"pass","trace_id":"stale"}"#,
    )?;
    std::fs::write(
        dir.join("log.jsonl"),
        "{\"status\":\"pass\",\"trace_id\":\"stale\"}\n",
    )?;
    let output = preflight_command(&root, &dir).output()?;
    assert_eq!(
        output.status.code(),
        Some(2),
        "stdout={} stderr={}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    let report: Value = serde_json::from_slice(&output.stdout)?;
    let saved: Value = serde_json::from_str(&std::fs::read_to_string(dir.join("report.json"))?)?;
    assert_eq!(saved, report);
    assert_eq!(report["status"], "blocked");
    assert_ne!(report["trace_id"], "stale");
    assert_eq!(report["summary"]["scenarios_passed"], 0);
    assert_eq!(report["summary"]["workload_processes_executed"], 0);
    assert_eq!(report["summary"]["companion_tests_passed"], 0);
    for arch in ["x86_64", "aarch64"] {
        assert_eq!(report["architectures"][arch]["status"], "blocked");
        assert_eq!(
            report["architectures"][arch]["inspection"]["reason"],
            "artifact_missing_or_empty"
        );
    }
    let log = std::fs::read_to_string(dir.join("log.jsonl"))?;
    let entries: Vec<Value> = log
        .lines()
        .map(serde_json::from_str)
        .collect::<Result<_, _>>()?;
    assert_eq!(
        entries.len() as u64,
        report["summary"]["scenarios_evaluated"]
            .as_u64()
            .ok_or("scenario count")?
    );
    assert!(!entries.is_empty());
    for entry in entries {
        assert_eq!(entry["bead_id"], "bd-38x82.6");
        assert_eq!(entry["trace_id"], report["trace_id"]);
        assert_eq!(entry["status"], "blocked");
        assert!(entry["event"].is_string());
    }
    Ok(())
}

#[test]
fn preflight_malformed_manifest_fails_and_writes_current_diagnostics() -> TestResult {
    let root = workspace_root()?;
    let dir = isolated_dir("invalid-manifest")?;
    let manifest = dir.join("invalid.json");
    std::fs::write(&manifest, "{")?;
    let output = preflight_command(&root, &dir)
        .env("WS8_E2E_MANIFEST", manifest)
        .output()?;
    assert_eq!(output.status.code(), Some(1));
    let report: Value = serde_json::from_slice(&output.stdout)?;
    assert_eq!(report["status"], "fail");
    assert_eq!(report["scenarios"]["input_validation"]["status"], "fail");
    assert_eq!(report["summary"]["scenarios_passed"], 0);
    let log = std::fs::read_to_string(dir.join("log.jsonl"))?;
    let entry: Value = serde_json::from_str(log.trim())?;
    assert_eq!(entry["status"], "fail");
    assert_eq!(entry["trace_id"], report["trace_id"]);
    Ok(())
}
