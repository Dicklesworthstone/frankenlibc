#!/usr/bin/env python3
"""generate_cve_uaf_validation.py — bd-1m5.3

Validates the CVE Arena use-after-free test suite:
  1. Manifest completeness — UAF/double-free CVEs have manifests + triggers.
  2. Manifest schema — required fields present and well-typed.
  3. Healing action coverage — GenerationalArena, IgnoreDoubleFree exercised.
  4. UAF pattern coverage — simple UAF, double-free, type confusion patterns.
  5. Coverage matrix consistency.

Generates a JSON validation report to stdout (or --output).
"""
import argparse
import json
import os
import re
import signal
import subprocess
import sys
import tempfile
from datetime import datetime, timezone
from pathlib import Path

HEALING_ACTION_RE = re.compile(
    r"ClampSize|TruncateWithNull|IgnoreDoubleFree|IgnoreForeignFree|"
    r"ReallocAsMalloc|ReturnSafeDefault|UpgradeToSafeVariant|"
    r"CanaryDetection|FreedWithCanaryCorruption"
)


def find_repo_root():
    p = Path(__file__).resolve().parent.parent
    if (p / "Cargo.toml").exists():
        return p
    return Path.cwd()


def find_preload_lib(root):
    candidates = []
    env_lib = os.environ.get("FRANKENLIBC_LIB")
    if env_lib:
        candidates.append(Path(env_lib))
    candidates.extend([
        Path("/data/tmp/cargo-target/release/libfrankenlibc_abi.so"),
        root / "target" / "release" / "libfrankenlibc_abi.so",
        Path("/data/tmp/cargo-target/debug/libfrankenlibc_abi.so"),
        root / "target" / "debug" / "libfrankenlibc_abi.so",
    ])
    for cand in candidates:
        if cand.exists():
            return cand
    return None


def decode_signal(rc):
    if rc is None:
        return "SIGKILL"
    if rc < 0:
        sig_num = -rc
    elif 128 < rc <= 192:
        sig_num = rc - 128
    else:
        return None
    try:
        return signal.Signals(sig_num).name
    except ValueError:
        return f"SIG{sig_num}"


def count_healing_actions(text):
    counts = {}
    for match in HEALING_ACTION_RE.findall(text or ""):
        counts[match] = counts.get(match, 0) + 1
    return counts


def run_trigger_mode(bin_path, cwd, preload_lib=None, mode=None):
    env = os.environ.copy()
    log_file = None
    if preload_lib is not None:
        env["LD_PRELOAD"] = str(preload_lib)
        if mode is not None:
            env["FRANKENLIBC_MODE"] = mode
        fd, log_path = tempfile.mkstemp(prefix="flc_cve_heal_", suffix=".jsonl")
        os.close(fd)
        log_file = Path(log_path)
        env["FRANKENLIBC_LOG"] = str(log_file)
        env["FRANKENLIBC_LOG_FILE"] = str(log_file)
    else:
        env.pop("LD_PRELOAD", None)
        env.pop("FRANKENLIBC_MODE", None)
        env.pop("FRANKENLIBC_LOG", None)
        env.pop("FRANKENLIBC_LOG_FILE", None)

    timed_out = False
    try:
        proc = subprocess.run(
            [str(bin_path)],
            cwd=str(cwd),
            env=env,
            capture_output=True,
            text=True,
            errors="replace",
            timeout=5,
        )
        rc = proc.returncode
        stderr_text = proc.stderr or ""
    except subprocess.TimeoutExpired as exc:
        timed_out = True
        rc = None
        stderr_text = (exc.stderr.decode("utf-8", errors="replace")
                       if isinstance(exc.stderr, bytes)
                       else (exc.stderr or ""))

    log_text = ""
    if log_file is not None:
        try:
            if log_file.exists():
                log_text = log_file.read_text(encoding="utf-8", errors="replace")
                log_file.unlink()
        except OSError:
            pass

    sig = decode_signal(rc)
    heals = count_healing_actions(stderr_text + "\n" + log_text)
    return {
        "rc": rc,
        "signal": sig,
        "timed_out": timed_out,
        "crashed": timed_out or (sig is not None),
        "stderr_snippet": stderr_text.strip()[:240],
        "heal_counts": heals,
        "healing_actions_observed": sorted(heals.keys()),
    }


def execute_c_trigger_paired(test_info, root):
    trigger_c = test_info["dir"] / "trigger.c"
    if not trigger_c.exists():
        return None
    preload_lib = find_preload_lib(root)
    with tempfile.TemporaryDirectory(prefix="flc_cve_uaf_") as tmpdir:
        bin_path = Path(tmpdir) / "trigger"
        try:
            comp = subprocess.run(
                ["cc", "-O0", "-fno-builtin", "-g", "-o", str(bin_path), str(trigger_c)],
                capture_output=True,
                text=True,
                timeout=10,
            )
        except (subprocess.TimeoutExpired, FileNotFoundError) as exc:
            return {
                "compiles": False,
                "compile_error": str(exc),
            }
        if comp.returncode != 0:
            return {
                "compiles": False,
                "compile_error": (comp.stderr or "").strip()[:240],
            }
        if preload_lib is None:
            return {
                "compiles": True,
                "preload_lib": None,
                "error": "libfrankenlibc_abi.so not found",
            }
        glibc_run = run_trigger_mode(bin_path, tmpdir)
        strict_run = run_trigger_mode(bin_path, tmpdir, preload_lib, "strict")
        hardened_run = run_trigger_mode(bin_path, tmpdir, preload_lib, "hardened")
        heal_deltas = {}
        all_actions = set(glibc_run["heal_counts"]) | set(hardened_run["heal_counts"])
        for act in sorted(all_actions):
            heal_deltas[act] = hardened_run["heal_counts"].get(act, 0) - glibc_run["heal_counts"].get(act, 0)
        return {
            "compiles": True,
            "preload_lib": str(preload_lib),
            "glibc_baseline": glibc_run,
            "strict": strict_run,
            "hardened": hardened_run,
            "heal_counter_deltas": heal_deltas,
            "hardened_healed": (
                not hardened_run["crashed"]
                and sum(v for v in heal_deltas.values() if v > 0) > 0
            ),
        }


def load_json_file(path):
    with open(path, encoding="utf-8") as f:
        return json.load(f)


# UAF-relevant CWE IDs
UAF_CWES = {"CWE-416", "CWE-415"}

REQUIRED_FIELDS = ["cve_id", "test_name", "category", "description",
                   "build_cmd", "cwe_ids"]

# Key healing actions for UAF
UAF_HEALING_ACTIONS = {"IgnoreDoubleFree", "IgnoreForeignFree",
                       "GenerationalArena", "ReallocAsMalloc"}


def find_uaf_tests(arena_root):
    """Find all CVE test directories involving UAF/double-free patterns."""
    tests = []
    for category_dir in ["glibc", "synthetic", "targets"]:
        base = arena_root / category_dir
        if not base.exists():
            continue
        for test_dir in sorted(base.iterdir()):
            if not test_dir.is_dir():
                continue
            manifest_path = test_dir / "manifest.json"
            if not manifest_path.exists():
                continue
            manifest = load_json_file(manifest_path)
            cwe_ids = set(manifest.get("cwe_ids", []))

            is_uaf = bool(cwe_ids & UAF_CWES)
            if not is_uaf and "uaf" in test_dir.name.lower():
                is_uaf = True
            if is_uaf:
                tests.append({
                    "dir": test_dir,
                    "manifest_path": manifest_path,
                    "manifest": manifest,
                    "category": category_dir,
                })
    return tests


def validate_manifest(test_info):
    """Validate a single test manifest."""
    issues = []
    manifest = test_info["manifest"]

    for field in REQUIRED_FIELDS:
        if field not in manifest:
            issues.append(f"Missing required field: {field}")

    cve_id = manifest.get("cve_id", "")
    if not cve_id.startswith("CVE-"):
        issues.append(f"Invalid cve_id format: {cve_id}")

    has_expected_stock = ("expected_stock_behavior" in manifest or
                         "expected_stock" in manifest)
    has_expected_tsm = ("expected_tsm_behavior" in manifest or
                        "expected_tsm" in manifest)
    if not has_expected_stock:
        issues.append("Missing expected stock behavior section")
    if not has_expected_tsm:
        issues.append("Missing expected TSM behavior section")

    tsm = manifest.get("expected_tsm_behavior") or manifest.get("expected_tsm", {})
    healing = set(tsm.get("healing_actions", []))
    if not healing:
        issues.append("No healing actions specified")

    return issues


def check_trigger_exists(test_info):
    test_dir = test_info["dir"]
    trigger_files = []
    for name in ["trigger.c", "trigger.sh", "trigger.pl", "trigger.py"]:
        if (test_dir / name).exists():
            trigger_files.append(name)
    return trigger_files


def classify_uaf_pattern(manifest):
    """Classify the UAF pattern type from manifest metadata."""
    cwe_ids = set(manifest.get("cwe_ids", []))
    test_name = manifest.get("test_name", "").lower()
    desc = manifest.get("description", "").lower()

    patterns = []
    if "CWE-415" in cwe_ids or "double" in desc or "double_free" in test_name:
        patterns.append("double_free")
    if "CWE-416" in cwe_ids:
        patterns.append("use_after_free")
    if "type confusion" in desc or "type_confusion" in test_name:
        patterns.append("type_confusion")
    if "realloc" in desc or "realloc" in test_name:
        patterns.append("realloc_uaf")
    if "generation" in desc:
        patterns.append("generation_mismatch")

    tsm = manifest.get("expected_tsm_behavior") or manifest.get("expected_tsm", {})
    healing = set(tsm.get("healing_actions", []))
    if "IgnoreDoubleFree" in healing:
        if "double_free" not in patterns:
            patterns.append("double_free")
    if "IgnoreForeignFree" in healing:
        patterns.append("foreign_free")

    return patterns if patterns else ["use_after_free"]


def check_coverage_matrix(arena_root, uaf_tests):
    matrix_path = arena_root / "coverage_matrix.json"
    if not matrix_path.exists():
        return {"exists": False, "issues": ["coverage_matrix.json not found"]}

    matrix = load_json_file(matrix_path)
    features = matrix.get("features", {})

    matrix_cve_ids = set()
    for _feat, info in features.items():
        for cve in info.get("cves", []):
            matrix_cve_ids.add(cve.get("cve_id", ""))

    missing = []
    for test_info in uaf_tests:
        cve_id = test_info["manifest"].get("cve_id", "").split(" ")[0]
        original_cve = test_info["manifest"].get("original_cve", cve_id)
        if cve_id not in matrix_cve_ids and original_cve not in matrix_cve_ids:
            missing.append(cve_id)

    return {
        "exists": True,
        "total_cves_in_matrix": len(matrix_cve_ids),
        "uaf_cves_missing": missing,
    }


def main():
    parser = argparse.ArgumentParser(description="CVE UAF validation")
    parser.add_argument("-o", "--output", help="Output file path")
    args = parser.parse_args()

    root = find_repo_root()
    arena_root = root / "tests" / "cve_arena"

    if not arena_root.exists():
        print("ERROR: tests/cve_arena/ not found", file=sys.stderr)
        sys.exit(1)

    uaf_tests = find_uaf_tests(arena_root)

    test_results = []
    total_issues = 0
    healing_actions_seen = set()
    all_patterns = set()

    for test_info in uaf_tests:
        manifest = test_info["manifest"]
        cve_id = manifest.get("cve_id", "unknown")
        test_name = manifest.get("test_name", "unknown")

        manifest_issues = validate_manifest(test_info)
        trigger_files = check_trigger_exists(test_info)
        execution = execute_c_trigger_paired(test_info, root)
        compiles = execution["compiles"] if execution is not None else None
        patterns = classify_uaf_pattern(manifest)

        tsm = manifest.get("expected_tsm_behavior") or manifest.get("expected_tsm", {})
        healing = tsm.get("healing_actions", [])
        healing_actions_seen.update(healing)
        all_patterns.update(patterns)

        issues = list(manifest_issues)
        if not trigger_files:
            issues.append("No trigger files found")
        if execution is not None:
            if not execution.get("compiles"):
                issues.append(f"C trigger failed to compile: {execution.get('compile_error', '')}")
            elif execution.get("error"):
                issues.append(execution["error"])
            elif not execution.get("hardened_healed"):
                issues.append("Hardened mode did not heal C trigger under LD_PRELOAD")
            else:
                observed = set(execution["hardened"]["healing_actions_observed"])
                if healing and not (observed & set(healing)):
                    issues.append(
                        f"Hardened observed heals {sorted(observed)} did not match expected {healing}"
                    )
        total_issues += len(issues)

        test_results.append({
            "cve_id": cve_id,
            "test_name": test_name,
            "category": test_info["category"],
            "cwe_ids": manifest.get("cwe_ids", []),
            "cvss_score": manifest.get("cvss_score"),
            "trigger_files": trigger_files,
            "c_compiles": compiles,
            "c_execution": execution,
            "healing_actions": healing,
            "tsm_features": manifest.get("tsm_features_tested", []),
            "uaf_patterns": patterns,
            "manifest_valid": len(issues) == 0,
            "issues": issues,
        })

    matrix_check = check_coverage_matrix(arena_root, uaf_tests)

    total_tests = len(test_results)
    valid_manifests = sum(1 for t in test_results if t["manifest_valid"])
    with_triggers = sum(1 for t in test_results if t["trigger_files"])
    c_tests = [t for t in test_results if t["c_compiles"] is not None]
    c_compiles = sum(1 for t in c_tests if t["c_compiles"])
    c_healed = sum(
        1 for t in c_tests
        if t.get("c_execution") and t["c_execution"].get("hardened_healed")
    )

    report = {
        "schema_version": "v1",
        "bead": "bd-1m5.3",
        "generated_at": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "summary": {
            "total_uaf_tests": total_tests,
            "manifests_valid": valid_manifests,
            "with_trigger_files": with_triggers,
            "c_triggers_compile": c_compiles,
            "c_triggers_hardened_healed": c_healed,
            "c_triggers_total": len(c_tests),
            "unique_healing_actions": sorted(healing_actions_seen),
            "uaf_patterns_covered": sorted(all_patterns),
            "coverage_matrix_present": matrix_check.get("exists", False),
            "total_issues": total_issues,
        },
        "tests": test_results,
        "coverage_matrix_check": matrix_check,
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
