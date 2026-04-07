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

    return issues


def main():
    parser = argparse.ArgumentParser(
        description="Paired-mode CVE evidence runner + strict detection assertions")
    parser.add_argument("-o", "--output", help="Output file path")
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
    all_dossier_ids = set()
    all_artifact_paths = set()

    for entry in corpus_entries:
        cve_id = entry["cve_id"]
        ha = hardened_assertions.get(cve_id)
        paired = build_paired_evidence(entry, ha)
        evidence_entries.append(paired)
        all_detection_flags.update(paired["strict_mode"]["detection_flags"])
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
        "bead": "bd-1m5.7",
        "generated_at": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "summary": {
            "total_paired_scenarios": len(evidence_entries),
            "strict_detected": strict_detected,
            "hardened_prevented": hardened_prevented,
            "with_detection_flags": with_flags,
            "unique_detection_flags": sorted(all_detection_flags),
            "unique_dossier_ids": len(all_dossier_ids),
            "entries_with_complete_artifact_bundle": complete_artifact_bundles,
            "unique_artifact_paths": len(all_artifact_paths),
            "validation_errors": error_count,
            "validation_warnings": warning_count,
        },
        "paired_evidence": evidence_entries,
        "validation_issues": validation_issues,
    }

    output = json.dumps(report, indent=2) + "\n"
    if args.output:
        Path(args.output).parent.mkdir(parents=True, exist_ok=True)
        Path(args.output).write_text(output)
        print(f"Report written to {args.output}", file=sys.stderr)
    else:
        print(output)


if __name__ == "__main__":
    main()
