#!/usr/bin/env bash
# check_hardened_repair_deny_matrix.sh — CI gate for bd-w2c3.3.2
#
# Validates:
# 1) hardened_repair_deny_matrix artifact shape and summary consistency.
# 2) every declared invalid_input_class is covered by at least one entry.
# 3) every entry has deterministic policy_id and valid decision/healing pair.
# 4) fixture_case_refs resolve to hardened fixture cases.
# 5) repair/deny classification aligns with fixture expectations.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
MATRIX="${ROOT}/tests/conformance/hardened_repair_deny_matrix.v1.json"
FIXTURE_DIR="${ROOT}/tests/conformance/fixtures"
HEAL_SRC="${ROOT}/crates/frankenlibc-membrane/src/heal.rs"
OUT_DIR="${ROOT}/target/conformance"
REPORT="${OUT_DIR}/hardened_repair_deny_matrix.report.json"
LOG="${OUT_DIR}/hardened_repair_deny_matrix.log.jsonl"
TRACE_ID="bd-w2c3.3.2-$(date -u +%Y%m%dT%H%M%SZ)-$$"

mkdir -p "${OUT_DIR}"

if [[ ! -f "${MATRIX}" ]]; then
  echo "FAIL: missing matrix artifact ${MATRIX}" >&2
  exit 1
fi

python3 - "${ROOT}" "${MATRIX}" "${FIXTURE_DIR}" "${HEAL_SRC}" "${REPORT}" <<'PY'
import datetime
import hashlib
import json
import pathlib
import re
import sys

root = pathlib.Path(sys.argv[1])
matrix_path = pathlib.Path(sys.argv[2])
fixture_dir = pathlib.Path(sys.argv[3])
heal_src_path = pathlib.Path(sys.argv[4])
report_path = pathlib.Path(sys.argv[5])
matrix = json.loads(matrix_path.read_text(encoding="utf-8"))

if matrix.get("schema_version") != "v1":
    raise SystemExit(f"FAIL: schema_version must be v1, got {matrix.get('schema_version')!r}")
if matrix.get("bead") != "bd-w2c3.3.2":
    raise SystemExit(f"FAIL: bead must be bd-w2c3.3.2, got {matrix.get('bead')!r}")
if not heal_src_path.exists():
    raise SystemExit(f"FAIL: missing healing action source file {heal_src_path}")

def extract_healing_action_variants(source: str) -> list[str]:
    marker = "pub enum HealingAction"
    start = source.find(marker)
    if start == -1:
        raise SystemExit("FAIL: could not find HealingAction enum declaration")
    brace_start = source.find("{", start)
    if brace_start == -1:
        raise SystemExit("FAIL: malformed HealingAction enum (missing opening brace)")

    depth = 0
    brace_end = None
    for index in range(brace_start, len(source)):
        char = source[index]
        if char == "{":
            depth += 1
        elif char == "}":
            depth -= 1
            if depth == 0:
                brace_end = index
                break
    if brace_end is None:
        raise SystemExit("FAIL: malformed HealingAction enum (missing closing brace)")

    body = source[brace_start + 1 : brace_end]
    variants: list[str] = []
    seen: set[str] = set()
    for line in body.splitlines():
        stripped = line.strip()
        if not stripped or stripped.startswith("//") or stripped.startswith("///") or stripped.startswith("#"):
            continue
        name = stripped.split("{", 1)[0].split("(", 1)[0].split(",", 1)[0].strip()
        if name and name[0].isalpha() and name not in seen:
            variants.append(name)
            seen.add(name)
    if not variants:
        raise SystemExit("FAIL: no HealingAction variants parsed from source")
    return variants

known_actions = matrix.get("known_healing_actions", [])
if not isinstance(known_actions, list) or "None" not in known_actions:
    raise SystemExit("FAIL: known_healing_actions must include 'None'")
known_action_set = set(known_actions)

enum_actions = extract_healing_action_variants(heal_src_path.read_text(encoding="utf-8"))
enum_action_set = set(enum_actions)
if "None" not in enum_action_set:
    raise SystemExit("FAIL: HealingAction enum must include None variant")

missing_from_matrix = sorted(enum_action_set - known_action_set)
extra_in_matrix = sorted(known_action_set - enum_action_set)
if missing_from_matrix or extra_in_matrix:
    raise SystemExit(
        "FAIL: known_healing_actions drift detected "
        f"(missing_from_matrix={missing_from_matrix}, extra_in_matrix={extra_in_matrix})"
    )

classes = matrix.get("invalid_input_classes", [])
if not isinstance(classes, list) or not classes:
    raise SystemExit("FAIL: invalid_input_classes must be a non-empty array")
declared_classes = {row.get("id") for row in classes if isinstance(row, dict)}
if None in declared_classes:
    raise SystemExit("FAIL: invalid_input_classes contains entry without id")

entries = matrix.get("entries", [])
if not isinstance(entries, list) or not entries:
    raise SystemExit("FAIL: entries must be a non-empty array")

fixture_cases = {}
for fixture_path in sorted(fixture_dir.glob("*.json")):
    rel = fixture_path.relative_to(root).as_posix()
    doc = json.loads(fixture_path.read_text(encoding="utf-8"))
    for case in doc.get("cases", []):
        name = case.get("name")
        if not isinstance(name, str) or not name:
            continue
        ref = f"{rel}#/cases/{name}"
        fixture_cases[ref] = case

policy_re = re.compile(r"^tsm\.(repair|deny)\.[a-z0-9_]+\.[a-z0-9_]+\.v1$")
covered_classes = set()
policy_ids = set()
repair_entries = 0
deny_entries = 0
report_entries = []
policy_rows_for_hash = []

for i, entry in enumerate(entries, 1):
    if not isinstance(entry, dict):
        raise SystemExit(f"FAIL: entry #{i} is not an object")

    for field in (
        "entry_id",
        "api_family",
        "symbol",
        "invalid_input_class",
        "decision_path",
        "healing_action",
        "policy_id",
        "fixture_case_refs",
    ):
        if field not in entry:
            raise SystemExit(f"FAIL: entry #{i} missing field {field!r}")

    invalid_class = entry["invalid_input_class"]
    if invalid_class not in declared_classes:
        raise SystemExit(
            f"FAIL: entry {entry['entry_id']} references undeclared invalid_input_class {invalid_class!r}"
        )
    covered_classes.add(invalid_class)

    decision = entry["decision_path"]
    if decision not in {"Repair", "Deny"}:
        raise SystemExit(
            f"FAIL: entry {entry['entry_id']} invalid decision_path {decision!r}; expected Repair|Deny"
        )

    action = entry["healing_action"]
    if action not in known_action_set:
        raise SystemExit(
            f"FAIL: entry {entry['entry_id']} healing_action {action!r} not in known_healing_actions"
        )
    if decision == "Repair":
        repair_entries += 1
        if action == "None":
            raise SystemExit(f"FAIL: entry {entry['entry_id']} Repair cannot use healing_action=None")
    else:
        deny_entries += 1
        if action != "None":
            raise SystemExit(f"FAIL: entry {entry['entry_id']} Deny must use healing_action=None")

    policy_id = entry["policy_id"]
    if not isinstance(policy_id, str) or not policy_re.match(policy_id):
        raise SystemExit(
            f"FAIL: entry {entry['entry_id']} policy_id {policy_id!r} is not deterministic (tsm.(repair|deny).<family>.<class>.v1)"
        )
    if policy_id in policy_ids:
        raise SystemExit(f"FAIL: duplicate policy_id detected: {policy_id}")
    policy_ids.add(policy_id)

    refs = entry["fixture_case_refs"]
    if not isinstance(refs, list) or not refs:
        raise SystemExit(f"FAIL: entry {entry['entry_id']} fixture_case_refs must be non-empty array")

    fixture_expectations = []
    for ref in refs:
        if ref not in fixture_cases:
            raise SystemExit(f"FAIL: entry {entry['entry_id']} references missing fixture case {ref}")
        case = fixture_cases[ref]
        mode = case.get("mode")
        if mode != "hardened":
            raise SystemExit(
                f"FAIL: entry {entry['entry_id']} references non-hardened fixture case {ref} (mode={mode!r})"
            )
        expected_output = str(case.get("expected_output", ""))
        expected_errno = int(case.get("expected_errno", -1))
        if decision == "Repair":
            if expected_output.startswith("open_err"):
                raise SystemExit(
                    f"FAIL: entry {entry['entry_id']} marked Repair but fixture is open_err deny-like: {ref}"
                )
        else:
            if not (expected_output.startswith("open_err") or expected_output.startswith("err errno=") or expected_errno != 0):
                raise SystemExit(
                    f"FAIL: entry {entry['entry_id']} marked Deny but fixture does not show denial semantics: {ref}"
                )
        fixture_expectations.append(
            {
                "fixture_case_ref": ref,
                "expected_output": expected_output,
                "expected_errno": expected_errno,
            }
        )

    policy_rows_for_hash.append(
        "|".join(
            [
                policy_id,
                decision,
                action,
                str(entry["api_family"]),
                str(entry["symbol"]),
                str(entry["invalid_input_class"]),
            ]
        )
    )
    report_entries.append(
        {
            "entry_id": str(entry["entry_id"]),
            "api_family": str(entry["api_family"]),
            "symbol": str(entry["symbol"]),
            "invalid_input_class": str(entry["invalid_input_class"]),
            "decision_path": decision,
            "healing_action": action,
            "policy_id": policy_id,
            "fixture_expectations": fixture_expectations,
        }
    )

missing_classes = sorted(declared_classes - covered_classes)
if missing_classes:
    raise SystemExit(
        f"FAIL: unsupported invalid_input_class(es) without hardened coverage: {missing_classes}"
    )

summary = matrix.get("summary", {})
expected = {
    "total_invalid_input_classes": len(declared_classes),
    "covered_invalid_input_classes": len(covered_classes),
    "entry_count": len(entries),
    "repair_entries": repair_entries,
    "deny_entries": deny_entries,
}
for key, actual in expected.items():
    claimed = summary.get(key)
    if claimed != actual:
        raise SystemExit(
            f"FAIL: summary.{key} mismatch claimed={claimed!r} actual={actual!r}"
        )

if deny_entries == 0:
    raise SystemExit("FAIL: matrix must include at least one Deny entry")
if repair_entries == 0:
    raise SystemExit("FAIL: matrix must include at least one Repair entry")

policy_rows_for_hash.sort()
policy_mapping_sha256 = hashlib.sha256("\n".join(policy_rows_for_hash).encode("utf-8")).hexdigest()

report = {
    "schema_version": "v1",
    "bead": "bd-249m.2",
    "source_matrix_bead": matrix.get("bead"),
    "generated_at_utc": datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
    "matrix_artifact": matrix_path.relative_to(root).as_posix(),
    "healing_action_source": heal_src_path.relative_to(root).as_posix(),
    "healing_action_variants": enum_actions,
    "summary": {
        **expected,
        "policy_mapping_sha256": policy_mapping_sha256,
    },
    "entries": report_entries,
}
report_path.write_text(json.dumps(report, indent=2, sort_keys=False) + "\n", encoding="utf-8")

print(
    "PASS: hardened repair/deny matrix validated "
    f"(entries={len(entries)}, classes={len(declared_classes)}, repair={repair_entries}, deny={deny_entries})"
)
print(
    "PASS: wrote hardened repair/deny report "
    f"({report_path.relative_to(root).as_posix()}, policy_mapping_sha256={policy_mapping_sha256})"
)
PY

python3 - "${TRACE_ID}" "${MATRIX}" "${REPORT}" <<'PY' > "${LOG}"
import json
import sys

trace_id, matrix_path, report_path = sys.argv[1:4]
matrix = json.load(open(matrix_path, "r", encoding="utf-8"))
report = json.load(open(report_path, "r", encoding="utf-8"))
summary = matrix.get("summary", {})
event = {
    "trace_id": trace_id,
    "mode": "hardened",
    "api_family": "matrix",
    "symbol": "hardened_repair_deny",
    "decision_path": "Repair|Deny",
    "healing_action": "none",
    "errno": 0,
    "latency_ns": 0,
    "artifact_refs": [matrix_path, report_path],
    "entries": int(summary.get("entry_count", 0)),
    "repair_entries": int(summary.get("repair_entries", 0)),
    "deny_entries": int(summary.get("deny_entries", 0)),
    "policy_mapping_sha256": report.get("summary", {}).get("policy_mapping_sha256", ""),
    "policy_ids": [
        row["policy_id"] for row in matrix.get("entries", []) if isinstance(row, dict) and "policy_id" in row
    ],
}
print(json.dumps(event, separators=(",", ":")))
PY

cat "${LOG}"
echo "PASS: wrote hardened repair/deny log ${LOG}"
