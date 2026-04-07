#!/usr/bin/env bash
# check_isomorphism_proof.sh — CI gate for bd-w2c3.8.2
#
# Validates that:
#   1. Isomorphism proof protocol JSON exists and is valid.
#   2. All proof categories are defined with required checks.
#   3. Proof template has required fields, replay metadata, and valid statuses.
#   4. Applicable modules reference valid ABI modules.
#   5. Proof artifacts exist, are listed, and match their golden hashes.
#   6. Summary statistics are consistent with the proof directory.
#
# Exit codes:
#   0 — all checks pass
#   1 — validation errors found
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
PROTOCOL="${ROOT}/tests/conformance/isomorphism_proof_protocol.json"
MATRIX="${ROOT}/support_matrix.json"

failures=0

echo "=== Isomorphism Proof Gate (bd-w2c3.8.2) ==="
echo ""

echo "--- Check 1: Protocol file exists and is valid ---"
if [[ ! -f "${PROTOCOL}" ]]; then
    echo "FAIL: tests/conformance/isomorphism_proof_protocol.json not found"
    echo ""
    echo "check_isomorphism_proof: FAILED"
    exit 1
fi

valid_check=$(python3 - <<PYTHON
import json
try:
    with open("${PROTOCOL}", "r", encoding="utf-8") as handle:
        proto = json.load(handle)
    if proto.get("schema_version", 0) < 2:
        print("INVALID: schema_version < 2")
    elif not proto.get("proof_categories"):
        print("INVALID: empty proof_categories")
    elif not proto.get("proof_template"):
        print("INVALID: empty proof_template")
    elif not isinstance(proto.get("existing_proofs"), list):
        print("INVALID: existing_proofs must be an array")
    else:
        print(
            f"VALID version={proto['schema_version']} "
            f"categories={len(proto['proof_categories'])} "
            f"proofs={len(proto['existing_proofs'])}"
        )
except Exception as exc:
    print(f"INVALID: {exc}")
PYTHON
)

if [[ "${valid_check}" == INVALID* ]]; then
    echo "FAIL: ${valid_check}"
    failures=$((failures + 1))
else
    echo "PASS: ${valid_check}"
fi
echo ""

echo "--- Check 2: Proof category definitions ---"
cat_check=$(python3 - <<PYTHON
import json

with open("${PROTOCOL}", "r", encoding="utf-8") as handle:
    proto = json.load(handle)

cats = proto.get("proof_categories", {})
expected = [
    "ordering",
    "tie_breaking",
    "fp_behavior",
    "rng_behavior",
    "side_effects",
    "memory_semantics",
]
errors = []

for cat_name in expected:
    cat = cats.get(cat_name)
    if cat is None:
        errors.append(f"Missing category: {cat_name}")
        continue
    if not cat.get("description"):
        errors.append(f"{cat_name}: missing description")
    if not cat.get("required_checks"):
        errors.append(f"{cat_name}: empty required_checks")
    if not cat.get("golden_format"):
        errors.append(f"{cat_name}: missing golden_format")

print(f"CATEGORY_ERRORS={len(errors)}")
print(f"CATEGORIES={len(cats)}")
for error in errors:
    print(f"  {error}")
PYTHON
)

cat_errs=$(echo "${cat_check}" | grep '^CATEGORY_ERRORS=' | cut -d= -f2)
if [[ "${cat_errs}" -gt 0 ]]; then
    echo "FAIL: ${cat_errs} category definition error(s):"
    echo "${cat_check}" | grep '  '
    failures=$((failures + 1))
else
    cat_count=$(echo "${cat_check}" | grep '^CATEGORIES=' | cut -d= -f2)
    echo "PASS: All ${cat_count} proof categories defined with checks and golden formats"
fi
echo ""

echo "--- Check 3: Proof template ---"
tmpl_check=$(python3 - <<PYTHON
import json

with open("${PROTOCOL}", "r", encoding="utf-8") as handle:
    proto = json.load(handle)

template = proto.get("proof_template", {})
required = set(template.get("required_fields", []))
statuses = set(template.get("proof_statuses", []))
example = template.get("example", {})

errors = []
for field in [
    "lever_id",
    "bead_id",
    "functions",
    "categories",
    "golden_commands",
    "golden_artifacts",
    "golden_hash",
    "proof_status",
    "rollback_instructions",
    "attribution_metadata",
]:
    if field not in required:
        errors.append(f"required_fields missing: {field}")

for status in ["pending", "verified", "failed", "waived"]:
    if status not in statuses:
        errors.append(f"proof_statuses missing: {status}")

if not example:
    errors.append("Missing example proof")
else:
    for field in required:
        if field not in example:
            errors.append(f"Example missing required field: {field}")
    if not example.get("golden_artifacts"):
        errors.append("Example golden_artifacts must not be empty")
    if not example.get("rollback_instructions"):
        errors.append("Example rollback_instructions must not be empty")
    if not example.get("attribution_metadata"):
        errors.append("Example attribution_metadata must not be empty")

print(f"TEMPLATE_ERRORS={len(errors)}")
for error in errors:
    print(f"  {error}")
PYTHON
)

tmpl_errs=$(echo "${tmpl_check}" | grep '^TEMPLATE_ERRORS=' | cut -d= -f2)
if [[ "${tmpl_errs}" -gt 0 ]]; then
    echo "FAIL: ${tmpl_errs} template error(s):"
    echo "${tmpl_check}" | grep '  '
    failures=$((failures + 1))
else
    echo "PASS: Proof template includes replay metadata and example proof"
fi
echo ""

echo "--- Check 4: Applicable modules ---"
mod_check=$(python3 - <<PYTHON
import json

with open("${PROTOCOL}", "r", encoding="utf-8") as handle:
    proto = json.load(handle)
with open("${MATRIX}", "r", encoding="utf-8") as handle:
    matrix = json.load(handle)

valid_modules = {symbol.get("module", "") for symbol in matrix.get("symbols", [])}
errors = []
all_modules = []

for priority in ["high_priority", "medium_priority", "low_priority"]:
    for entry in proto.get("applicable_modules", {}).get(priority, []):
        module = entry.get("module", "")
        all_modules.append(module)
        if module not in valid_modules:
            errors.append(f"{module} ({priority}): not a valid ABI module")
        if not entry.get("reason"):
            errors.append(f"{module} ({priority}): missing reason")

seen = set()
for module in all_modules:
    if module in seen:
        errors.append(f"{module}: duplicate entry in applicable_modules")
    seen.add(module)

print(f"MODULE_ERRORS={len(errors)}")
print(f"TOTAL_MODULES={len(all_modules)}")
for error in errors:
    print(f"  {error}")
PYTHON
)

mod_errs=$(echo "${mod_check}" | grep '^MODULE_ERRORS=' | cut -d= -f2)
if [[ "${mod_errs}" -gt 0 ]]; then
    echo "FAIL: ${mod_errs} module reference error(s):"
    echo "${mod_check}" | grep '  '
    failures=$((failures + 1))
else
    mod_total=$(echo "${mod_check}" | grep '^TOTAL_MODULES=' | cut -d= -f2)
    echo "PASS: All ${mod_total} applicable modules reference valid ABI modules"
fi
echo ""

echo "--- Check 5: Proof directory and artifact validation ---"
proof_check=$(python3 - <<PYTHON
import hashlib
import json
import os

root = "${ROOT}"
with open("${PROTOCOL}", "r", encoding="utf-8") as handle:
    proto = json.load(handle)

proof_dir = os.path.join(root, proto["enforcement"]["proof_directory"])
template_required = proto["proof_template"]["required_fields"]
valid_statuses = set(proto["proof_template"]["proof_statuses"])
valid_categories = set(proto["proof_categories"].keys())
listed = {
    item["proof_path"]: item
    for item in proto.get("existing_proofs", [])
}

errors = []
if not os.path.isdir(proof_dir):
    errors.append(f"proof directory missing: {proof_dir}")
    files = []
else:
    files = sorted(
        filename for filename in os.listdir(proof_dir) if filename.endswith(".json")
    )
    if not files:
        errors.append("proof directory must contain at least one JSON proof artifact")

discovered = []
for filename in files:
    relative_path = os.path.join(proto["enforcement"]["proof_directory"], filename)
    relative_path = relative_path.replace("\\\\", "/")
    discovered.append(relative_path)
    if relative_path not in listed:
        errors.append(f"proof artifact not listed in existing_proofs: {relative_path}")
        continue

    full_path = os.path.join(root, relative_path)
    with open(full_path, "r", encoding="utf-8") as handle:
        proof = json.load(handle)

    for field in template_required:
        if field not in proof:
            errors.append(f"{relative_path}: missing required field {field}")

    proof_status = proof.get("proof_status")
    if proof_status not in valid_statuses:
        errors.append(f"{relative_path}: invalid proof_status {proof_status}")

    categories = proof.get("categories", [])
    if not categories:
        errors.append(f"{relative_path}: categories must not be empty")
    for category in categories:
        if category not in valid_categories:
            errors.append(f"{relative_path}: invalid category {category}")

    golden_artifacts = proof.get("golden_artifacts", [])
    if not golden_artifacts:
        errors.append(f"{relative_path}: golden_artifacts must not be empty")
    for artifact in golden_artifacts:
        artifact_path = artifact.get("path")
        expected = artifact.get("sha256", "")
        if not artifact_path:
            errors.append(f"{relative_path}: golden_artifact missing path")
            continue
        full_artifact_path = os.path.join(root, artifact_path)
        if not os.path.exists(full_artifact_path):
            errors.append(f"{relative_path}: golden artifact missing: {artifact_path}")
            continue
        digest = hashlib.sha256()
        with open(full_artifact_path, "rb") as handle:
            digest.update(handle.read())
        actual = f"sha256:{digest.hexdigest()}"
        if actual != expected:
            errors.append(
                f"{relative_path}: hash mismatch for {artifact_path} "
                f"expected={expected} actual={actual}"
            )

    rollback = proof.get("rollback_instructions", {})
    if "git revert" not in rollback.get("command", ""):
        errors.append(f"{relative_path}: rollback command must contain git revert")
    if not rollback.get("artifact_regeneration_commands"):
        errors.append(f"{relative_path}: artifact_regeneration_commands must not be empty")
    if not rollback.get("expected_revert_scope", "").strip():
        errors.append(f"{relative_path}: expected_revert_scope must not be empty")

    attribution = proof.get("attribution_metadata", {})
    for field in ("baseline_artifacts", "profile_artifacts"):
        refs = attribution.get(field, [])
        if not refs:
            errors.append(f"{relative_path}: {field} must not be empty")
            continue
        for ref in refs:
            if not os.path.exists(os.path.join(root, ref)):
                errors.append(f"{relative_path}: attribution artifact missing: {ref}")

listed_paths = set(listed.keys())
if set(discovered) != listed_paths:
    missing = sorted(listed_paths - set(discovered))
    extra = sorted(set(discovered) - listed_paths)
    if missing:
        errors.append(f"existing_proofs missing files: {missing}")
    if extra:
        errors.append(f"proof directory has unlisted files: {extra}")

print(f"PROOF_ERRORS={len(errors)}")
print(f"PROOF_FILES={len(discovered)}")
for error in errors:
    print(f"  {error}")
PYTHON
)

proof_errs=$(echo "${proof_check}" | grep '^PROOF_ERRORS=' | cut -d= -f2)
if [[ "${proof_errs}" -gt 0 ]]; then
    echo "FAIL: ${proof_errs} proof artifact error(s):"
    echo "${proof_check}" | grep '  '
    failures=$((failures + 1))
else
    proof_count=$(echo "${proof_check}" | grep '^PROOF_FILES=' | cut -d= -f2)
    echo "PASS: All ${proof_count} proof artifacts are listed and hash-valid"
fi
echo ""

echo "--- Check 6: Summary consistency ---"
sum_check=$(python3 - <<PYTHON
import json

with open("${PROTOCOL}", "r", encoding="utf-8") as handle:
    proto = json.load(handle)

summary = proto.get("summary", {})
errors = []

if summary.get("total_categories") != len(proto.get("proof_categories", {})):
    errors.append(
        f"total_categories claimed={summary.get('total_categories')} "
        f"actual={len(proto.get('proof_categories', {}))}"
    )

for priority, key in [
    ("high_priority", "high_priority_modules"),
    ("medium_priority", "medium_priority_modules"),
    ("low_priority", "low_priority_modules"),
]:
    claimed = summary.get(key)
    actual = len(proto.get("applicable_modules", {}).get(priority, []))
    if claimed != actual:
        errors.append(f"{key} claimed={claimed} actual={actual}")

proof_count = len(proto.get("existing_proofs", []))
if summary.get("existing_proof_count") != proof_count:
    errors.append(
        f"existing_proof_count claimed={summary.get('existing_proof_count')} actual={proof_count}"
    )

if summary.get("enforcement_status") != "artifacts_present":
    errors.append(
        f"enforcement_status claimed={summary.get('enforcement_status')} actual=artifacts_present"
    )

print(f"SUMMARY_ERRORS={len(errors)}")
for error in errors:
    print(f"  {error}")
PYTHON
)

sum_errs=$(echo "${sum_check}" | grep '^SUMMARY_ERRORS=' | cut -d= -f2)
if [[ "${sum_errs}" -gt 0 ]]; then
    echo "FAIL: ${sum_errs} summary inconsistency(ies):"
    echo "${sum_check}" | grep '  '
    failures=$((failures + 1))
else
    echo "PASS: Summary statistics consistent with proof artifacts"
fi
echo ""

echo "=== Summary ==="
echo "Failures: ${failures}"

if [[ "${failures}" -gt 0 ]]; then
    echo ""
    echo "check_isomorphism_proof: FAILED"
    exit 1
fi

echo ""
echo "check_isomorphism_proof: PASS"
