#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd -P)"
CONTRACT="${FIXTURE_EXECUTOR_OWNERSHIP_CONTRACT:-$ROOT/tests/conformance/fixture_executor_ownership_and_golden.v1.json}"
REPORT="${FIXTURE_EXECUTOR_OWNERSHIP_REPORT:-$ROOT/target/conformance/fixture_executor_ownership_and_golden.report.json}"
LOG="${FIXTURE_EXECUTOR_OWNERSHIP_LOG:-$ROOT/target/conformance/fixture_executor_ownership_and_golden.log.jsonl}"
VALIDATE_ONLY=0

for arg in "$@"; do
  case "$arg" in
    --validate-only) VALIDATE_ONLY=1 ;;
    *)
      echo "unknown argument: $arg" >&2
      exit 64
      ;;
  esac
done

mkdir -p "$(dirname "$REPORT")" "$(dirname "$LOG")"

source_commit="$(git -C "$ROOT" rev-parse HEAD 2>/dev/null || echo unknown)"
trace_id="fixture-executor-ownership-$(date -u +%Y%m%dT%H%M%SZ)-$$"

write_json() {
  local outcome="$1"
  local signature="$2"
  local message="$3"
  jq -n \
    --arg schema_version "fixture_executor_ownership_and_golden.report.v1" \
    --arg bead "bd-0agsk.7" \
    --arg trace_id "$trace_id" \
    --arg source_commit "$source_commit" \
    --arg outcome "$outcome" \
    --arg failure_signature "$signature" \
    --arg message "$message" \
    --arg contract "$CONTRACT" \
    --arg stable_boundary "frankenlibc-fixture-exec" \
    --arg legacy_impl "frankenlibc_conformance_compat" \
    --arg harness_consumer "frankenlibc-harness" \
    '{
      schema_version: $schema_version,
      bead: $bead,
      trace_id: $trace_id,
      source_commit: $source_commit,
      outcome: $outcome,
      failure_signature: $failure_signature,
      message: $message,
      contract: $contract,
      ownership: {
        stable_boundary: $stable_boundary,
        legacy_impl: $legacy_impl,
        harness_consumer: $harness_consumer
      }
    }' > "$REPORT"
}

log_event() {
  local event="$1"
  local outcome="$2"
  local signature="$3"
  jq -nc \
    --arg event "$event" \
    --arg bead "bd-0agsk.7" \
    --arg trace_id "$trace_id" \
    --arg outcome "$outcome" \
    --arg failure_signature "$signature" \
    --arg contract "$CONTRACT" \
    '{event:$event, bead:$bead, trace_id:$trace_id, outcome:$outcome, failure_signature:$failure_signature, contract:$contract}' >> "$LOG"
}

fail() {
  local signature="$1"
  local message="$2"
  write_json "fail" "$signature" "$message"
  log_event "fixture_executor_ownership_and_golden_failed" "fail" "$signature"
  echo "FAIL: $signature: $message" >&2
  exit 1
}

: > "$LOG"

[[ -f "$CONTRACT" ]] || fail "fixture_executor_contract_missing" "missing contract: $CONTRACT"
jq empty "$CONTRACT" || fail "fixture_executor_contract_invalid_json" "contract is not valid JSON"

schema_version="$(jq -r '.schema_version // ""' "$CONTRACT")"
[[ "$schema_version" == "fixture_executor_ownership_and_golden.v1" ]] || \
  fail "fixture_executor_contract_wrong_schema" "unexpected schema_version: $schema_version"

bead="$(jq -r '.generated_by_bead // ""' "$CONTRACT")"
[[ "$bead" == "bd-0agsk.7" ]] || \
  fail "fixture_executor_contract_wrong_bead" "unexpected generated_by_bead: $bead"

stable_manifest="$(jq -r '.ownership_contract.stable_public_boundary.manifest // ""' "$CONTRACT")"
stable_entrypoint="$(jq -r '.ownership_contract.stable_public_boundary.entrypoint // ""' "$CONTRACT")"
legacy_entrypoint="$(jq -r '.ownership_contract.legacy_implementation.entrypoint // ""' "$CONTRACT")"
legacy_manifest="$(jq -r '.ownership_contract.legacy_implementation.manifest // ""' "$CONTRACT")"
harness_manifest="$(jq -r '.ownership_contract.harness_consumer.manifest // ""' "$CONTRACT")"

for rel in "$stable_manifest" "$stable_entrypoint" "$legacy_manifest" "$legacy_entrypoint" "$harness_manifest"; do
  [[ -n "$rel" ]] || fail "fixture_executor_contract_empty_path" "ownership path is empty"
  [[ -e "$ROOT/$rel" ]] || fail "fixture_executor_contract_path_missing" "missing ownership path: $rel"
done

if grep -Fq 'frankenlibc_conformance' "$ROOT/$stable_manifest"; then
  fail "fixture_executor_adapter_dependency_leak" "fixture-exec must not depend on the legacy conformance crate"
fi

grep -Fq 'frankenlibc-core' "$ROOT/$stable_manifest" || \
  fail "fixture_executor_owned_dependency_missing" "fixture-exec must own direct core dependency for executor implementation"

grep -Fq 'frankenlibc-abi' "$ROOT/$stable_manifest" || \
  fail "fixture_executor_owned_dependency_missing" "fixture-exec must own direct ABI dependency for executor implementation"

grep -Fq '#[path = "../../frankenlibc_conformance/src/lib.rs"]' "$ROOT/$stable_entrypoint" || \
  fail "fixture_executor_owned_entrypoint_changed" "fixture-exec entrypoint must compile the migrated executor body"

grep -Fq 'pub use implementation::*;' "$ROOT/$stable_entrypoint" || \
  fail "fixture_executor_owned_entrypoint_changed" "fixture-exec entrypoint must re-export the migrated executor body"

if grep -Fq 'pub use frankenlibc_conformance' "$ROOT/$stable_entrypoint"; then
  fail "fixture_executor_adapter_export_changed" "fixture-exec must not re-export the legacy conformance crate"
fi

grep -Fq 'path = "../frankenlibc-fixture-exec/src/lib.rs"' "$ROOT/$legacy_manifest" || \
  fail "fixture_executor_compat_path_missing" "legacy compatibility package must target the fixture-exec entrypoint"

grep -Fq 'frankenlibc-fixture-exec = { workspace = true }' "$ROOT/$harness_manifest" || \
  fail "fixture_executor_harness_dependency_missing" "harness no longer depends on fixture-exec"

if grep -Fq 'frankenlibc_conformance' "$ROOT/$harness_manifest"; then
  fail "fixture_executor_harness_legacy_dependency" "harness manifest directly depends on the legacy conformance crate"
fi

case_count="$(jq '.golden_manifest.cases | length' "$CONTRACT")"
[[ "$case_count" == "7" ]] || \
  fail "fixture_executor_golden_case_count_mismatch" "expected 7 golden cases, found $case_count"

bad_hash_count="$(jq '[.golden_manifest.cases[] | select((.canonical_sha256 | test("^[0-9a-f]{64}$") | not))] | length' "$CONTRACT")"
[[ "$bad_hash_count" == "0" ]] || \
  fail "fixture_executor_golden_bad_hash" "$bad_hash_count golden cases have invalid sha256 fields"

while IFS=$'\t' read -r fixture case function; do
  fixture_path="$ROOT/tests/conformance/fixtures/$fixture.json"
  [[ -f "$fixture_path" ]] || fail "fixture_executor_golden_fixture_missing" "missing fixture file for $fixture"
  matches="$(jq --arg name "$case" --arg function "$function" '[.cases[] | select(.name == $name and .function == $function)] | length' "$fixture_path")"
  [[ "$matches" == "1" ]] || \
    fail "fixture_executor_golden_case_missing" "expected one case $fixture/$case/$function, found $matches"
done < <(jq -r '.golden_manifest.cases[] | [.fixture, .case, .function] | @tsv' "$CONTRACT")

write_json "pass" "none" "fixture executor ownership and golden manifest contract validated"
log_event "fixture_executor_ownership_and_golden_validated" "pass" "none"

if [[ "$VALIDATE_ONLY" == "1" ]]; then
  echo "PASS: fixture executor ownership and golden manifest validated cases=$case_count"
else
  echo "PASS: fixture executor ownership and golden manifest validated cases=$case_count"
fi
