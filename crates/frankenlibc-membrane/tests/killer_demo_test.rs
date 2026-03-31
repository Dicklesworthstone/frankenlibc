#[path = "../examples/killer_demo.rs"]
mod killer_demo;

use serde_json::Value;
use std::fs;
use std::path::PathBuf;
use std::time::{SystemTime, UNIX_EPOCH};

fn unique_tmp_dir() -> PathBuf {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("system time should be after unix epoch")
        .as_nanos();
    let dir = std::env::temp_dir().join(format!(
        "frankenlibc-killer-demo-{}-{nanos}",
        std::process::id()
    ));
    fs::create_dir_all(&dir).expect("create temp dir");
    dir
}

#[test]
fn killer_demo_emits_report_and_artifacts() {
    let run_dir = unique_tmp_dir();
    let report = killer_demo::run_demo(&run_dir, false).expect("killer demo should run");

    assert_eq!(report.bead_id, "bd-13zp");
    assert_eq!(report.scenarios.len(), 3, "expected glibc/strict/hardened");
    assert!(
        report
            .scenarios
            .iter()
            .any(|scenario| scenario.mode == "strict" && scenario.detected),
        "strict mode must detect the stale pointer"
    );
    assert!(
        report
            .scenarios
            .iter()
            .any(|scenario| scenario.mode == "hardened"
                && scenario.detected
                && scenario.repaired
                && scenario.healing_action.as_deref() == Some("ReturnSafeDefault")),
        "hardened mode must repair via ReturnSafeDefault"
    );

    for path in [
        run_dir.join("trace.jsonl"),
        run_dir.join("killer_demo.suite.json"),
        run_dir.join("summary.ftui.txt"),
        run_dir.join("killer_demo_report.json"),
        run_dir.join("artifact_index.json"),
    ] {
        assert!(path.exists(), "artifact missing: {}", path.display());
    }

    let report_json: Value = serde_json::from_str(
        &fs::read_to_string(run_dir.join("killer_demo_report.json")).expect("report file readable"),
    )
    .expect("report json parses");
    assert_eq!(report_json["bead_id"].as_str(), Some("bd-13zp"));

    let trace_body =
        fs::read_to_string(run_dir.join("trace.jsonl")).expect("trace.jsonl should be readable");
    assert!(
        trace_body.contains("killer_demo.scenario_result"),
        "trace log must contain scenario result events"
    );
    assert!(
        trace_body.contains("\"mode\":\"strict\""),
        "trace log must include strict mode rows"
    );
    assert!(
        trace_body.contains("\"mode\":\"hardened\""),
        "trace log must include hardened mode rows"
    );

    let index_json: Value = serde_json::from_str(
        &fs::read_to_string(run_dir.join("artifact_index.json")).expect("artifact index readable"),
    )
    .expect("artifact index parses");
    assert_eq!(index_json["bead_id"].as_str(), Some("bd-13zp"));
    assert!(
        index_json["artifacts"]
            .as_array()
            .is_some_and(|artifacts| artifacts.len() >= 4),
        "artifact index should enumerate the emitted artifacts"
    );

    let _ = fs::remove_dir_all(run_dir);
}
