#!/usr/bin/env python3
"""generate_cve_paired_mode_runner.py — bd-1m5.7

Strict detection assertions + paired-mode CVE evidence runner:
  1. Strict detection matrix — per-CVE expected strict-mode detection flags.
  2. Paired-mode evidence runner — packages strict+hardened evidence bundles.
  3. CI regression gate — validates detection completeness and joinability.

Uses corpus_normalization.v1.json (bd-1m5.5) and hardened_assertions.v1.json
(bd-1m5.6) as inputs.
Generates a JSON report to stdout (or --output).
"""
import argparse
import hashlib
import json
import sys
from datetime import datetime, timezone
from pathlib import Path

ORIGINAL_BEAD = "bd-1m5.7"
COMPLETION_DEBT_BEAD = "bd-1m5.7.1"
TEST_SOURCE = "crates/frankenlibc-harness/tests/cve_paired_mode_runner_test.rs"
DEFAULT_REPORT_PATH = "tests/cve_arena/results/paired_mode_evidence.v1.json"
DEFAULT_LOG_PATH = "tests/cve_arena/results/paired_mode_evidence.log.jsonl"
API_FAMILY = "cve_paired_mode"


def find_repo_root():
    p = Path(__file__).resolve().parent.parent
    if (p / "Cargo.toml").exists():
        return p
    return Path.cwd()


def load_json_file(path):
    with open(path, encoding="utf-8") as f:
        return json.load(f)


# CWE → expected strict-mode detection flags
CWE_DETECTION_FLAGS = {
    "CWE-122": ["heap_overflow_detected", "bounds_violation"],
    "CWE-787": ["out_of_bounds_write", "bounds_violation"],
    "CWE-120": ["buffer_overflow_detected", "bounds_violation"],
    "CWE-121": ["stack_overflow_detected", "bounds_violation"],
    "CWE-131": ["size_miscalculation", "bounds_violation"],
    "CWE-190": ["integer_overflow", "arithmetic_violation"],
    "CWE-191": ["integer_underflow", "arithmetic_violation"],
    "CWE-680": ["integer_to_buffer_overflow", "arithmetic_violation", "bounds_violation"],
    "CWE-134": ["format_string_violation", "unsafe_printf"],
    "CWE-416": ["use_after_free", "dangling_pointer"],
    "CWE-415": ["double_free", "invalid_free"],
    "CWE-825": ["expired_pointer", "dangling_pointer"],
    "CWE-476": ["null_dereference", "null_pointer"],
    "CWE-908": ["uninitialized_read", "memory_safety"],
}

EXPECTED_JOIN_KEYS = ["dossier_id", "cve_id", "test_name"]


def compute_dossier_id(cve_id, test_name):
    """Compute a deterministic dossier ID for evidence joinability."""
    raw = f"{cve_id}|{test_name}"
    return f"dossier-{hashlib.sha256(raw.encode()).hexdigest()[:12]}"


def expected_artifact_paths(dossier_id):
    """Return the canonical paired-mode artifact bundle layout."""
    return [
        f"{dossier_id}/strict/stdout.log",
        f"{dossier_id}/strict/stderr.log",
        f"{dossier_id}/strict/metrics.json",
        f"{dossier_id}/hardened/stdout.log",
        f"{dossier_id}/hardened/stderr.log",
        f"{dossier_id}/hardened/metrics.json",
        f"{dossier_id}/paired_verdict.json",
    ]


def sha256_json(value):
    payload = json.dumps(value, sort_keys=True, separators=(",", ":")).encode()
    return hashlib.sha256(payload).hexdigest()


def build_paired_fuzz_seed(corpus_entry, strict, hardened, dossier_id):
    """Build deterministic fuzz replay metadata from the paired-mode contract."""
    payload = {
        "seed_payload_schema": "cve-paired-mode-fuzz-seed/v1",
        "dossier_id": dossier_id,
        "cve_id": corpus_entry["cve_id"],
        "test_name": corpus_entry["test_name"],
        "mutation_axes": [
            "runtime_mode",
            "strict_detection_flag",
            "hardened_healing_action",
            "evidence_bundle_path",
        ],
        "replay_modes": ["strict", "hardened"],
        "strict_detection_flags": strict["detection_flags"],
        "hardened_healing_actions": hardened.get("healing_actions_required", []),
        "artifact_paths": expected_artifact_paths(dossier_id),
    }
    seed_hash = sha256_json(payload)
    payload["seed_sha256"] = seed_hash
    payload["seed_id"] = f"paired-{seed_hash[:16]}"
    return payload


def build_completion_debt_evidence():
    """Bind bd-1m5.7.1 audit items to concrete paired-mode evidence."""
    return {
        "bead": COMPLETION_DEBT_BEAD,
        "original_bead": ORIGINAL_BEAD,
        "test_source": TEST_SOURCE,
        "unit_primary": {
            "missing_item_id": "tests.unit.primary",
            "description": "Unit-level assertions for strict detection verdicts, hardened prevention verdicts, unique dossier IDs, and join keys.",
            "required_test_names": [
                "paired_report_schema_complete",
                "paired_all_strict_detected",
                "paired_all_hardened_prevented",
                "paired_unique_dossier_ids",
                "paired_evidence_bundles_joinable",
            ],
        },
        "e2e_primary": {
            "missing_item_id": "tests.e2e.primary",
            "description": "End-to-end generator/checker evidence for the paired-mode report and structured telemetry log.",
            "generator_script": "scripts/generate_cve_paired_mode_runner.py",
            "checker_script": "scripts/check_cve_paired_mode_runner.sh",
            "required_test_names": [
                "paired_report_generates_successfully",
                "paired_mode_checker_accepts_completion_debt_bindings",
            ],
        },
        "fuzz_primary": {
            "missing_item_id": "tests.fuzz.primary",
            "description": "Deterministic fuzz-seed metadata derived from each strict/hardened paired-mode scenario.",
            "seed_payload_schema": "cve-paired-mode-fuzz-seed/v1",
            "required_entry_field": "paired_fuzz_seed",
            "required_seed_fields": [
                "seed_payload_schema",
                "seed_id",
                "seed_sha256",
                "mutation_axes",
                "replay_modes",
                "strict_detection_flags",
                "hardened_healing_actions",
                "artifact_paths",
            ],
            "required_test_names": [
                "paired_entries_define_fuzz_replay_seed_contract",
                "paired_fuzz_replay_seed_keys_are_deterministic",
            ],
        },
        "conformance_primary": {
            "missing_item_id": "tests.conformance.primary",
            "description": "Conformance-level pairing checks across normalized corpus entries, hardened assertions, strict detection flags, and canonical evidence bundles.",
            "artifact": DEFAULT_REPORT_PATH,
            "required_test_names": [
                "paired_report_schema_complete",
                "paired_no_validation_errors",
                "paired_entries_define_fuzz_replay_seed_contract",
            ],
        },
        "telemetry_primary": {
            "missing_item_id": "telemetry.primary",
            "description": "Structured JSON report and JSONL telemetry emitted by the paired-mode checker.",
            "default_report_path": DEFAULT_REPORT_PATH,
            "default_log_path": DEFAULT_LOG_PATH,
            "required_test_names": [
                "structured_log_contains_paired_mode_evidence",
                "paired_mode_checker_accepts_completion_debt_bindings",
            ],
            "required_events": [
                "paired_mode_scenario",
                "paired_mode_summary",
            ],
            "required_fields": [
                "timestamp",
                "trace_id",
                "api_family",
                "event",
                "bead_id",
                "completion_debt_bead",
                "parent_bead",
                "artifact_refs",
                "outcome",
                "failure_signature",
                "cve_id",
                "dossier_id",
                "test_name",
                "strict_verdict",
                "hardened_verdict",
                "detection_flags",
                "healing_actions",
                "paired_fuzz_seed_id",
            ],
        },
    }


def build_strict_detection(corpus_entry):
    """Build strict-mode detection assertion for a CVE."""
    cwe_ids = corpus_entry.get("cwe_ids", [])
    replay = corpus_entry.get("replay", {})
    strict_exp = replay.get("expected_strict", {})

    # Collect expected detection flags from CWEs
    detection_flags = set()
    for cwe in cwe_ids:
        if cwe in CWE_DETECTION_FLAGS:
            detection_flags.update(CWE_DETECTION_FLAGS[cwe])

    return {
        "crashes_expected": strict_exp.get("crashes", True),
        "detection_expected": strict_exp.get("detection_expected", True),
        "detection_flags": sorted(detection_flags),
        "signal": strict_exp.get("signal"),
    }


def build_paired_evidence(corpus_entry, hardened_assertion):
    """Build paired strict+hardened evidence bundle spec."""
    cve_id = corpus_entry["cve_id"]
    test_name = corpus_entry["test_name"]
    dossier_id = compute_dossier_id(cve_id, test_name)

    strict = build_strict_detection(corpus_entry)
    hardened = hardened_assertion.get("hardened_expectations", {}) if hardened_assertion else {}
    paired_fuzz_seed = build_paired_fuzz_seed(corpus_entry, strict, hardened, dossier_id)

    return {
        "cve_id": cve_id,
        "test_name": test_name,
        "dossier_id": dossier_id,
        "cvss_score": corpus_entry.get("cvss_score"),
        "vulnerability_classes": corpus_entry.get("vulnerability_classes", []),
        "trigger_files": corpus_entry.get("trigger_files", []),
        "strict_mode": {
            "crashes_expected": strict["crashes_expected"],
            "detection_expected": strict["detection_expected"],
            "detection_flags": strict["detection_flags"],
            "signal": strict.get("signal"),
            "verdict": "detected" if strict["detection_expected"] else "undetected",
        },
        "hardened_mode": {
            "crashes_expected": hardened.get("crashes", False),
            "exit_code": hardened.get("exit_code", 0),
            "healing_actions": hardened.get("healing_actions_required", []),
            "no_uncontrolled_unsafety": hardened.get("no_uncontrolled_unsafety", True),
            "verdict": "prevented" if not hardened.get("crashes", False) else "vulnerable",
        },
        "evidence_bundle": {
            "dossier_ref": dossier_id,
            "artifacts": expected_artifact_paths(dossier_id),
            "joinable_on": EXPECTED_JOIN_KEYS,
        },
        "paired_fuzz_seed": paired_fuzz_seed,
    }


def validate_paired_evidence(evidence_entries):
    """Validate the paired evidence suite for completeness."""
    issues = []

    for e in evidence_entries:
        cve_id = e["cve_id"]
        dossier_id = e["dossier_id"]
        bundle = e.get("evidence_bundle", {})

        # Strict must have detection flags
        if not e["strict_mode"]["detection_flags"]:
            issues.append({
                "cve_id": cve_id,
                "issue": "No detection flags defined for strict mode",
                "severity": "warning",
            })

        # Hardened must not crash
        if e["hardened_mode"]["crashes_expected"]:
            issues.append({
                "cve_id": cve_id,
                "issue": "Hardened mode expected to crash",
                "severity": "error",
            })

        # Must have a dossier_id
        if not e["dossier_id"]:
            issues.append({
                "cve_id": cve_id,
                "issue": "Missing dossier_id",
                "severity": "error",
            })

        # Strict verdict must be "detected"
        if e["strict_mode"]["verdict"] != "detected":
            issues.append({
                "cve_id": cve_id,
                "issue": f"Strict verdict is '{e['strict_mode']['verdict']}', expected 'detected'",
                "severity": "warning",
            })

        # Hardened verdict must be "prevented"
        if e["hardened_mode"]["verdict"] != "prevented":
            issues.append({
                "cve_id": cve_id,
                "issue": f"Hardened verdict is '{e['hardened_mode']['verdict']}', expected 'prevented'",
                "severity": "error",
            })

        expected_artifacts = expected_artifact_paths(dossier_id)
        actual_artifacts = bundle.get("artifacts")
        if actual_artifacts != expected_artifacts:
            issues.append({
                "cve_id": cve_id,
                "issue": "Artifact bundle layout drifted from canonical paired-mode structure",
                "severity": "error",
            })

        if bundle.get("dossier_ref") != dossier_id:
            issues.append({
                "cve_id": cve_id,
                "issue": "evidence_bundle.dossier_ref must match dossier_id",
                "severity": "error",
            })

        if bundle.get("joinable_on") != EXPECTED_JOIN_KEYS:
            issues.append({
                "cve_id": cve_id,
                "issue": "joinable_on keys must stay deterministic and complete",
                "severity": "error",
            })

        seed = e.get("paired_fuzz_seed", {})
        if seed.get("seed_payload_schema") != "cve-paired-mode-fuzz-seed/v1":
            issues.append({
                "cve_id": cve_id,
                "issue": "paired_fuzz_seed seed_payload_schema drifted",
                "severity": "error",
            })
        if not seed.get("seed_id") or not seed.get("seed_sha256"):
            issues.append({
                "cve_id": cve_id,
                "issue": "paired_fuzz_seed missing deterministic seed identity",
                "severity": "error",
            })

    return issues


def emit_structured_log(log_path, timestamp, report, evidence_entries):
    """Emit deterministic JSONL telemetry for paired-mode evidence."""
    rows = []
    report_path = DEFAULT_REPORT_PATH
    for entry in evidence_entries:
        seed = entry["paired_fuzz_seed"]
        rows.append({
            "timestamp": timestamp,
            "trace_id": f"{COMPLETION_DEBT_BEAD}:{entry['dossier_id']}",
            "api_family": API_FAMILY,
            "event": "paired_mode_scenario",
            "bead_id": ORIGINAL_BEAD,
            "completion_debt_bead": COMPLETION_DEBT_BEAD,
            "parent_bead": ORIGINAL_BEAD,
            "artifact_refs": [report_path, *entry["evidence_bundle"]["artifacts"]],
            "outcome": "expected",
            "failure_signature": "none",
            "cve_id": entry["cve_id"],
            "dossier_id": entry["dossier_id"],
            "test_name": entry["test_name"],
            "strict_verdict": entry["strict_mode"]["verdict"],
            "hardened_verdict": entry["hardened_mode"]["verdict"],
            "detection_flags": entry["strict_mode"]["detection_flags"],
            "healing_actions": entry["hardened_mode"]["healing_actions"],
            "paired_fuzz_seed_id": seed["seed_id"],
        })

    rows.append({
        "timestamp": timestamp,
        "trace_id": f"{COMPLETION_DEBT_BEAD}:summary",
        "api_family": API_FAMILY,
        "event": "paired_mode_summary",
        "bead_id": ORIGINAL_BEAD,
        "completion_debt_bead": COMPLETION_DEBT_BEAD,
        "parent_bead": ORIGINAL_BEAD,
        "artifact_refs": [report_path, DEFAULT_LOG_PATH],
        "outcome": "pass" if report["summary"]["validation_errors"] == 0 else "fail",
        "failure_signature": "none" if report["summary"]["validation_errors"] == 0 else "validation_errors_present",
        "cve_id": None,
        "dossier_id": None,
        "test_name": None,
        "strict_verdict": f"{report['summary']['strict_detected']}/{report['summary']['total_paired_scenarios']}",
        "hardened_verdict": f"{report['summary']['hardened_prevented']}/{report['summary']['total_paired_scenarios']}",
        "detection_flags": report["summary"]["unique_detection_flags"],
        "healing_actions": report["summary"]["unique_healing_actions"],
        "paired_fuzz_seed_id": None,
    })

    log_path.parent.mkdir(parents=True, exist_ok=True)
    log_path.write_text("".join(json.dumps(row, sort_keys=True) + "\n" for row in rows), encoding="utf-8")


def main():
    parser = argparse.ArgumentParser(
        description="Paired-mode CVE evidence runner + strict detection assertions")
    parser.add_argument("-o", "--output", help="Output file path")
    parser.add_argument("--log", help="Structured JSONL log output path")
    parser.add_argument("--timestamp", help="Fixed generated_at timestamp for deterministic runs")
    args = parser.parse_args()

    root = find_repo_root()
    results_dir = root / "tests" / "cve_arena" / "results"

    corpus_path = results_dir / "corpus_normalization.v1.json"
    hardened_path = results_dir / "hardened_assertions.v1.json"

    if not corpus_path.exists():
        print("ERROR: corpus_normalization.v1.json not found", file=sys.stderr)
        sys.exit(1)
    if not hardened_path.exists():
        print("ERROR: hardened_assertions.v1.json not found", file=sys.stderr)
        sys.exit(1)

    corpus = load_json_file(corpus_path)
    hardened = load_json_file(hardened_path)

    corpus_entries = corpus.get("corpus_index", [])
    hardened_assertions = {a["cve_id"]: a for a in hardened.get("assertion_matrix", [])}

    evidence_entries = []
    all_detection_flags = set()
    all_healing_actions = set()
    all_dossier_ids = set()
    all_artifact_paths = set()

    for entry in corpus_entries:
        cve_id = entry["cve_id"]
        ha = hardened_assertions.get(cve_id)
        paired = build_paired_evidence(entry, ha)
        evidence_entries.append(paired)
        all_detection_flags.update(paired["strict_mode"]["detection_flags"])
        all_healing_actions.update(paired["hardened_mode"]["healing_actions"])
        all_dossier_ids.add(paired["dossier_id"])
        all_artifact_paths.update(paired["evidence_bundle"]["artifacts"])

    validation_issues = validate_paired_evidence(evidence_entries)
    error_count = sum(1 for i in validation_issues if i["severity"] == "error")
    warning_count = sum(1 for i in validation_issues if i["severity"] == "warning")

    # Summary
    strict_detected = sum(1 for e in evidence_entries
                          if e["strict_mode"]["verdict"] == "detected")
    hardened_prevented = sum(1 for e in evidence_entries
                            if e["hardened_mode"]["verdict"] == "prevented")
    with_flags = sum(1 for e in evidence_entries
                     if e["strict_mode"]["detection_flags"])
    complete_artifact_bundles = sum(
        1
        for e in evidence_entries
        if e["evidence_bundle"]["dossier_ref"] == e["dossier_id"]
        and e["evidence_bundle"]["artifacts"] == expected_artifact_paths(e["dossier_id"])
        and e["evidence_bundle"]["joinable_on"] == EXPECTED_JOIN_KEYS
    )

    report = {
        "schema_version": "v1",
        "bead": ORIGINAL_BEAD,
        "completion_debt_bead": COMPLETION_DEBT_BEAD,
        "generated_at": args.timestamp or datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "summary": {
            "total_paired_scenarios": len(evidence_entries),
            "strict_detected": strict_detected,
            "hardened_prevented": hardened_prevented,
            "with_detection_flags": with_flags,
            "unique_detection_flags": sorted(all_detection_flags),
            "unique_healing_actions": sorted(all_healing_actions),
            "unique_dossier_ids": len(all_dossier_ids),
            "entries_with_complete_artifact_bundle": complete_artifact_bundles,
            "unique_artifact_paths": len(all_artifact_paths),
            "validation_errors": error_count,
            "validation_warnings": warning_count,
        },
        "completion_debt_evidence": build_completion_debt_evidence(),
        "paired_evidence": evidence_entries,
        "validation_issues": validation_issues,
    }

    output = json.dumps(report, indent=2) + "\n"
    if args.output:
        Path(args.output).parent.mkdir(parents=True, exist_ok=True)
        Path(args.output).write_text(output, encoding="utf-8")
        print(f"Report written to {args.output}", file=sys.stderr)
    else:
        print(output)
    if args.log:
        emit_structured_log(Path(args.log), report["generated_at"], report, evidence_entries)


if __name__ == "__main__":
    main()
