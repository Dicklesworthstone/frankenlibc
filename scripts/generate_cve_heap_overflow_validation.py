#!/usr/bin/env python3
"""generate_cve_heap_overflow_validation.py — bd-1m5.1

Validates the CVE Arena heap overflow test suite:
  1. Manifest completeness — all heap-overflow CVEs have manifests + triggers.
  2. Manifest schema — required fields present and well-typed.
  3. Healing action coverage — heap overflow CVEs exercise ClampSize/CanaryDetection.
  4. Trigger compilability — C triggers compile with cc.
  5. Coverage matrix consistency — heap overflow CVEs appear in coverage_matrix.json.

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
    with tempfile.TemporaryDirectory(prefix="flc_cve_heap_") as tmpdir:
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


# Heap-overflow-relevant CWE IDs
HEAP_OVERFLOW_CWES = {"CWE-122", "CWE-787", "CWE-120", "CWE-121", "CWE-131"}

# Expected healing actions for heap overflows
HEAP_HEALING_ACTIONS = {"ClampSize", "TruncateWithNull", "CanaryDetection",
                        "FreedWithCanaryCorruption"}

# Required manifest fields
REQUIRED_FIELDS = ["cve_id", "test_name", "category", "description",
                   "build_cmd", "cwe_ids"]


def find_heap_overflow_tests(arena_root):
    """Find all CVE test directories that involve heap overflow patterns."""
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

            # Include if any CWE is heap-overflow-related
            if cwe_ids & HEAP_OVERFLOW_CWES:
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

    # Check required fields
    for field in REQUIRED_FIELDS:
        if field not in manifest:
            issues.append(f"Missing required field: {field}")

    # Check cve_id format
    cve_id = manifest.get("cve_id", "")
    if not cve_id.startswith("CVE-"):
        issues.append(f"Invalid cve_id format: {cve_id}")

    # Check test_name format
    test_name = manifest.get("test_name", "")
    if not test_name or not all(c.isalnum() or c == "_" for c in test_name):
        issues.append(f"Invalid test_name: {test_name}")

    # Check expected behavior sections (accept both naming conventions)
    has_expected_stock = ("expected_stock_behavior" in manifest or
                         "expected_stock" in manifest)
    has_expected_tsm = ("expected_tsm_behavior" in manifest or
                        "expected_tsm" in manifest)
    if not has_expected_stock:
        issues.append("Missing expected stock behavior section")
    if not has_expected_tsm:
        issues.append("Missing expected TSM behavior section")

    # Check healing actions for heap overflow relevance
    tsm = manifest.get("expected_tsm_behavior") or manifest.get("expected_tsm", {})
    healing = set(tsm.get("healing_actions", []))
    if not healing:
        issues.append("No healing actions specified")

    # TSM features tested
    features = manifest.get("tsm_features_tested", [])
    if not features:
        issues.append("No TSM features listed")

    return issues


def check_trigger_exists(test_info):
    """Check that trigger files exist."""
    test_dir = test_info["dir"]
    trigger_files = []
    for ext in ["*.c", "*.sh", "*.pl", "*.py"]:
        trigger_files.extend(test_dir.glob(ext))

    # Also check for specific trigger files
    for name in ["trigger.c", "trigger.sh", "trigger.pl", "trigger.py"]:
        p = test_dir / name
        if p.exists():
            if p not in trigger_files:
                trigger_files.append(p)

    return [str(f.name) for f in trigger_files]


def check_coverage_matrix(arena_root, heap_tests):
    """Verify heap overflow CVEs appear in coverage_matrix.json."""
    matrix_path = arena_root / "coverage_matrix.json"
    if not matrix_path.exists():
        return {"exists": False, "issues": ["coverage_matrix.json not found"]}

    matrix = load_json_file(matrix_path)
    features = matrix.get("features", {})

    # Collect all CVE IDs from matrix
    matrix_cve_ids = set()
    for _feat, info in features.items():
        for cve in info.get("cves", []):
            matrix_cve_ids.add(cve.get("cve_id", ""))

    # Check each heap test's CVE is in the matrix
    missing = []
    for test_info in heap_tests:
        cve_id = test_info["manifest"].get("cve_id", "").split(" ")[0]
        # Also check original_cve field for synthetics
        original_cve = test_info["manifest"].get("original_cve", cve_id)
        if cve_id not in matrix_cve_ids and original_cve not in matrix_cve_ids:
            missing.append(cve_id)

    return {
        "exists": True,
        "total_cves_in_matrix": len(matrix_cve_ids),
        "heap_cves_missing": missing,
    }


def main():
    parser = argparse.ArgumentParser(description="CVE heap overflow validation")
    parser.add_argument("-o", "--output", help="Output file path")
    args = parser.parse_args()

    root = find_repo_root()
    arena_root = root / "tests" / "cve_arena"

    if not arena_root.exists():
        print("ERROR: tests/cve_arena/ not found", file=sys.stderr)
        sys.exit(1)

    # Find all heap overflow tests
    heap_tests = find_heap_overflow_tests(arena_root)

    # Validate each test
    test_results = []
    total_issues = 0
    healing_actions_seen = set()

    for test_info in heap_tests:
        manifest = test_info["manifest"]
        cve_id = manifest.get("cve_id", "unknown")
        test_name = manifest.get("test_name", "unknown")

        # Validate manifest
        manifest_issues = validate_manifest(test_info)

        # Check trigger files
        trigger_files = check_trigger_exists(test_info)

        # Compile and execute C trigger in paired mode
        execution = execute_c_trigger_paired(test_info, root)
        compiles = execution["compiles"] if execution is not None else None

        # Collect healing actions
        tsm = manifest.get("expected_tsm_behavior") or manifest.get("expected_tsm", {})
        healing = tsm.get("healing_actions", [])
        healing_actions_seen.update(healing)

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
            "manifest_valid": len(issues) == 0,
            "issues": issues,
        })

    # Check coverage matrix
    matrix_check = check_coverage_matrix(arena_root, heap_tests)

    # Compute summary
    total_tests = len(test_results)
    valid_manifests = sum(1 for t in test_results if t["manifest_valid"])
    with_triggers = sum(1 for t in test_results if t["trigger_files"])
    c_tests = [t for t in test_results if t["c_compiles"] is not None]
    c_compiles = sum(1 for t in c_tests if t["c_compiles"])
    c_healed = sum(
        1 for t in c_tests
        if t.get("c_execution") and t["c_execution"].get("hardened_healed")
    )

    # CWE coverage
    all_cwes = set()
    for t in test_results:
        all_cwes.update(t["cwe_ids"])
    heap_cwes_covered = all_cwes & HEAP_OVERFLOW_CWES

    report = {
        "schema_version": "v1",
        "bead": "bd-1m5.1",
        "generated_at": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "summary": {
            "total_heap_overflow_tests": total_tests,
            "manifests_valid": valid_manifests,
            "with_trigger_files": with_triggers,
            "c_triggers_compile": c_compiles,
            "c_triggers_hardened_healed": c_healed,
            "c_triggers_total": len(c_tests),
            "unique_healing_actions": sorted(healing_actions_seen),
            "heap_cwes_covered": sorted(heap_cwes_covered),
            "heap_cwes_target": sorted(HEAP_OVERFLOW_CWES),
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
