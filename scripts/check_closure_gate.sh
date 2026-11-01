#!/usr/bin/env bash
# check_closure_gate.sh — CI gate for bd-4rl
#
# Validates that every closed critique bead has proper evidence:
#   1. Closure evidence schema exists and is valid.
#   2. Every non-exempt closed critique bead has a verification matrix entry.
#   3. Matrix entries have test commands (unit_cmds or e2e_cmds).
#   4. Matrix entries have artifact references.
#   5. Coverage is not "missing" and close_blockers are empty.
#   6. Post-cutoff non-epic closures have retained results bound to an explicit
#      behavior/source/build/configuration contract, rather than PASS prose.
#
# Legacy-exempt beads (closed before gate establishment) produce warnings.
#
# Source selection:
# - FRANKENLIBC_CLOSURE_GATE_SOURCE=beads uses .beads/issues.jsonl
# - default (matrix) uses verification_matrix.json for the legacy critique audit
# - the post-cutoff audit always reads the explicitly selected Beads JSONL
#
# Exit codes:
#   0 — all non-exempt beads pass evidence checks
#   1 — one or more non-exempt beads fail evidence checks
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
SCHEMA="${FRANKENLIBC_CLOSURE_SCHEMA:-${ROOT}/tests/conformance/closure_evidence_schema.json}"
MATRIX="${FRANKENLIBC_CLOSURE_MATRIX:-${ROOT}/tests/conformance/verification_matrix.json}"
BEADS="${FRANKENLIBC_BEADS_JSONL:-${ROOT}/.beads/issues.jsonl}"
SOURCE="${FRANKENLIBC_CLOSURE_GATE_SOURCE:-matrix}"

# Capture and admission share the evaluator. A receipt is an integrity record,
# not an attestation by an independent runner or a proof of test adequacy.
closure_results() {
    python3 - "$ROOT" "$SCHEMA" "$MATRIX" "$BEADS" "$@" <<'PY'
import datetime as dt
import hashlib
import json
import os
import pathlib
import platform
import re
import shutil
import subprocess
import sys

root, schema_path, matrix_path, beads_path = map(pathlib.Path, sys.argv[1:5])
action, *args = sys.argv[5:]
schema = json.loads(schema_path.read_text())
matrix = json.loads(matrix_path.read_text())
beads = {}
for line in beads_path.read_text().splitlines():
    if line.strip():
        bead = json.loads(line)
        beads[bead['id']] = bead
entries = {e['bead_id']: e for e in matrix['entries']}
policy = schema['executed_results']


def require(condition, message):
    if not condition:
        raise ValueError(message)


def sha(path):
    with path.open('rb') as stream:
        return hashlib.file_digest(stream, 'sha256').hexdigest()


def timestamp(value):
    parsed = dt.datetime.fromisoformat(value.replace('Z', '+00:00'))
    require(parsed.tzinfo is not None, 'timestamp requires timezone')
    return parsed


def now():
    return dt.datetime.now(dt.timezone.utc).isoformat()


def path(value):
    p = pathlib.Path(value)
    return p if p.is_absolute() else root / p


def contract_for(bid):
    bead = beads[bid]
    contract = entries.get(bid, {}).get('row', {}).get('closure_evidence')
    require(isinstance(contract, dict), 'missing_execution_contract (prose is not a result)')
    require(contract.get('behavior'), 'missing_behavior')
    acceptance = hashlib.sha256(bead.get('acceptance_criteria', '').encode()).hexdigest()
    require(contract.get('acceptance_sha256') == acceptance, 'wrong_acceptance_criteria')
    kind = contract.get('evidence_class')
    require(kind in ('source', 'compiled', 'executed_unit') and kind in policy['supported_classes'],
            'unsupported_evidence_class: direct evaluator required')
    require(contract.get('claim_class') == kind, 'claim_class_mismatch')
    lower_label = {'source': 'docs-only', 'compiled': 'compile-only'}.get(kind)
    if lower_label:
        require(lower_label in bead.get('labels', []), 'lower_evidence_class_requires_explicit_bead_label')
    source = contract['source']
    require(re.fullmatch('[0-9a-f]{40}', source['commit']), 'invalid_source_commit')
    files = source['files']
    require(isinstance(files, dict) and files, 'missing_source_files')
    required = contract['behavior_paths'] + contract['test_paths']
    require(required and all(p in files for p in required), 'missing_behavior_or_test_source')
    for p, digest in files.items():
        require(not pathlib.Path(p).is_absolute() and '..' not in pathlib.Path(p).parts,
                'invalid_source_path')
        require(re.fullmatch('[0-9a-f]{64}', digest), 'invalid_source_hash')
    cfg = contract['configuration']
    require(set(cfg) == {'architecture', 'mode', 'profile', 'features'}, 'incomplete_configuration')
    require(all(isinstance(cfg[k], str) and cfg[k] for k in ('architecture', 'mode', 'profile')),
            'invalid_configuration')
    require(isinstance(cfg['features'], list), 'invalid_features')
    if kind == 'source':
        require(cfg['profile'] == 'source' and cfg['features'] == [], 'invalid_source_only_configuration')
    gate = contract['gate']
    require(isinstance(gate['command'], list) and gate['command'] and
            all(isinstance(v, str) and v for v in gate['command']), 'invalid_command')
    require(set(gate['environment']) == {'FRANKENLIBC_MODE'}, 'unsupported_gate_environment')
    require(gate['environment']['FRANKENLIBC_MODE'] == cfg['mode'], 'mode_environment_mismatch')
    require(timestamp(contract['not_before']) >= timestamp(bead['created_at']), 'stale_contract_window')
    if kind != 'source':
        require(gate.get('build_command') and gate.get('artifacts'), 'missing_build_contract')
        build = gate['build_command']
        require(isinstance(build, list) and all(isinstance(v, str) and v for v in build),
                'invalid_build_command')
        require(pathlib.Path(build[0]).name in ('cargo', 'rustc'), 'unsupported_build_compiler')
        if kind == 'executed_unit' and pathlib.Path(build[0]).name == 'cargo':
            require(len(build) > 1 and build[1] == 'test' and '--no-run' in build,
                    'build_is_not_separate_test_compilation')
        require('--target' not in build and '--all-features' not in build, 'unsupported_build_configuration')
        if pathlib.Path(build[0]).name == 'rustc':
            require('--test' in build and cfg['profile'] == 'test' and cfg['features'] == [],
                    'wrong_build_configuration')
        else:
            require('--message-format=json' in build, 'cargo_build_requires_artifact_messages')
            require('-Zchecksum-freshness' in build or any(
                build[i:i + 2] == ['-Z', 'checksum-freshness'] for i in range(len(build) - 1)),
                'cargo_build_requires_content_freshness')
            require('--config=build.fingerprint="content"' in build or any(
                build[i:i + 2] == ['--config', 'build.fingerprint="content"']
                for i in range(len(build) - 1)), 'cargo_build_requires_content_fingerprint')
            profile = build[build.index('--profile') + 1] if '--profile' in build else (
                'release' if '--release' in build else 'test' if build[1] == 'test' else 'dev')
            features = build[build.index('--features') + 1].replace(',', ' ').split() if '--features' in build else []
            if '--no-default-features' not in build:
                features.insert(0, 'default')
            require(cfg['profile'] == profile and cfg['features'] == features, 'wrong_build_configuration')
            require(all(p in files for p in ('Cargo.toml', 'Cargo.lock', 'rust-toolchain.toml', '.cargo/config.toml')),
                    'missing_cargo_build_inputs')
        if kind == 'compiled' and pathlib.Path(build[0]).name == 'cargo':
            require(len(build) > 1 and build[1] in ('check', 'build', 'clippy'), 'invalid_compile_only_command')
    if kind == 'executed_unit':
        require(gate.get('required_tests'), 'missing_required_tests')
        require(gate.get('result_format') == 'libtest', 'unsupported_runtime_result_format')
        require(gate['command'][0] in gate['artifacts'], 'test_binary_not_bound_to_build')
        require(gate['command'] != gate['build_command'], 'compilation_is_not_execution')
        build = gate['build_command']
        require(isinstance(build, list) and build, 'invalid_build_command')
        compiler = pathlib.Path(build[0]).name
        if compiler == 'rustc':
            require('--test' in build and any(p in build for p in contract['test_paths']),
                    'build_does_not_compile_named_tests')
            require('-o' in build and build[build.index('-o') + 1] == gate['command'][0],
                    'build_does_not_produce_test_binary')
            require(cfg['profile'] == 'test' and cfg['features'] == [], 'wrong_build_configuration')
            require('--target' not in build, 'cross_target_requires_direct_evaluator')
        elif compiler == 'cargo':
            require('--test' in build, 'build_requires_named_test_target')
            target = build[build.index('--test') + 1]
            require(any(pathlib.Path(p).stem == target for p in contract['test_paths']),
                    'unrelated_build_target')
        else:
            raise ValueError('unsupported_test_compiler: direct evaluator required')
    return contract


def bound_files(contract):
    return {p: sha(path(p)) for p in contract['source']['files']}


def run(command, env, out, name):
    started = now()
    # No shell and no inherited preload/loader overrides. All stderr is retained.
    clean_env = os.environ.copy()
    for key in ('LD_PRELOAD', 'LD_LIBRARY_PATH', 'LD_AUDIT'):
        clean_env.pop(key, None)
    clean_env.update(env)
    with (out / (name + '.stdout')).open('xb') as stdout, (out / (name + '.stderr')).open('xb') as stderr:
        result = subprocess.run(command, cwd=root, env=clean_env, stdout=stdout, stderr=stderr,
                                timeout=1800, check=False)
    return {'command': command, 'exit_code': result.returncode, 'started_at': started,
            'finished_at': now(), 'stdout': name + '.stdout', 'stderr': name + '.stderr',
            'stdout_sha256': sha(out / (name + '.stdout')),
            'stderr_sha256': sha(out / (name + '.stderr')), 'executed_cases': None}


def capture(bid, out):
    contract = contract_for(bid)
    require(contract['configuration']['architecture'] == platform.machine(), 'wrong_runner_architecture')
    require(bound_files(contract) == contract['source']['files'], 'wrong_live_source')
    # RCH transfers source without necessarily transferring Git metadata. Do not
    # substitute worker HEAD for the caller's explicit source identity.
    declared = os.environ.get('RCH_BUILD_SOURCE', '')
    if declared:
        require(declared.removesuffix('-dirty') == contract['source']['commit'], 'wrong_rch_source')
    else:
        actual = subprocess.check_output(['git', 'rev-parse', 'HEAD'], cwd=root, text=True).strip()
        require(actual == contract['source']['commit'], 'wrong_live_commit')
    out.mkdir(parents=True, exist_ok=False)
    gate = contract['gate']
    receipt = {'schema_version': 1, 'bead_id': bid, 'contract': contract,
               'runner_architecture': platform.machine(), 'build': None, 'execution': None,
               'artifacts': {}, 'artifact_files': {}, 'source_files': bound_files(contract)}
    if gate.get('build_command'):
        receipt['build'] = run(gate['build_command'], gate['environment'], out, 'build')
    if receipt['build'] is None or receipt['build']['exit_code'] == 0:
        receipt['artifacts'] = {p: sha(path(p)) for p in gate.get('artifacts', [])}
        command = gate['command']
        executable = pathlib.Path(shutil.which(command[0]) or path(command[0]))
        receipt['executable_sha256'] = sha(executable)
        receipt['execution'] = run(command, gate['environment'], out, 'execution')
        output = (out / 'execution.stdout').read_text(errors='replace')
        counts = re.findall(r'^test result: (?:ok|FAILED)\. (\d+) passed; (\d+) failed;.*$', output, re.M)
        receipt['execution']['executed_cases'] = (
            sum(map(int, counts[0])) if len(counts) == 1 and contract['evidence_class'] == 'executed_unit' else None)
        # Keep the observed bytes outside compiler caches. Cache eviction or a
        # later build must not silently replace the artifact this result names.
        shutil.copy2(executable, out / 'executable')
        require(sha(out / 'executable') == receipt['executable_sha256'], 'executable_changed_during_run')
        for index, (p, digest) in enumerate(receipt['artifacts'].items()):
            saved = f'artifact-{index}'
            shutil.copy2(path(p), out / saved)
            require(sha(out / saved) == digest, 'build_artifact_changed_during_run')
            receipt['artifact_files'][p] = saved
    require(bound_files(contract) == receipt['source_files'], 'source_changed_during_run')
    # Retain exactly the source bytes examined. Admission does not compare an old
    # result to an unrelated, newer working tree.
    for p in contract['source']['files']:
        saved = out / 'source' / p
        saved.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(path(p), saved)
    (out / 'receipt.json').write_text(json.dumps(receipt, indent=2) + '\n')
    verify(bid, out / 'receipt.json')
    print(f'RECORDED {bid}: {out / "receipt.json"}')


def verify(bid, receipt_path):
    contract = contract_for(bid)
    receipt = json.loads(receipt_path.read_text())
    require(receipt.get('schema_version') == 1 and receipt.get('bead_id') == bid, 'wrong_receipt_identity')
    require(receipt.get('contract') == contract, 'wrong_source_config_or_gate_contract')
    require(receipt.get('source_files') == contract['source']['files'], 'wrong_source_manifest')
    require(receipt.get('runner_architecture') == contract['configuration']['architecture'],
            'wrong_runner_architecture')
    for p, digest in contract['source']['files'].items():
        require(sha(receipt_path.parent / 'source' / p) == digest, 'missing_or_changed_source_snapshot')
    gate = contract['gate']
    lower = timestamp(contract['not_before'])
    upper = timestamp(beads[bid].get('closed_at') or now())

    def phase(name, command):
        result = receipt.get(name)
        require(isinstance(result, dict), f'missing_{name}_result')
        require(result.get('command') == command, f'wrong_{name}_command')
        require(type(result.get('exit_code')) is int and result['exit_code'] == 0, f'{name}_failed')
        start, finish = timestamp(result['started_at']), timestamp(result['finished_at'])
        require(lower <= start <= finish <= upper, f'stale_or_future_{name}_result')
        for stream in ('stdout', 'stderr'):
            output = receipt_path.parent / result[stream]
            require(sha(output) == result[stream + '_sha256'], f'missing_or_changed_{name}_{stream}')
        return result, (receipt_path.parent / result['stdout']).read_text(errors='replace')

    build = None
    if gate.get('build_command'):
        build, build_stdout = phase('build', gate['build_command'])
        if pathlib.Path(gate['build_command'][0]).name == 'cargo':
            messages = [json.loads(line) for line in build_stdout.splitlines() if line.strip()]
            produced = [m for m in messages if m.get('reason') == 'compiler-artifact']
            reported = {str(path(p).resolve()) for m in produced for p in m.get('filenames', [])}
            require(all(str(path(p).resolve()) in reported for p in gate['artifacts']),
                    'artifact_not_reported_by_build')
            if contract['evidence_class'] == 'executed_unit':
                target = gate['build_command'][gate['build_command'].index('--test') + 1]
                require(any(m.get('target', {}).get('name') == target and
                            'test' in m.get('target', {}).get('kind', []) and
                            m.get('executable') and
                            path(m['executable']).resolve() == path(gate['command'][0]).resolve()
                            for m in produced), 'executed_binary_not_produced_by_named_target')
    execution, stdout = phase('execution', gate['command'])
    if build:
        require(timestamp(build['finished_at']) <= timestamp(execution['started_at']), 'build_after_execution')
    artifacts = receipt.get('artifacts', {})
    require(set(artifacts) == set(gate.get('artifacts', [])), 'missing_build_artifact')
    require(set(receipt.get('artifact_files', {})) == set(artifacts), 'missing_retained_build_artifact')
    for p, digest in artifacts.items():
        require(sha(receipt_path.parent / receipt['artifact_files'][p]) == digest, 'missing_or_changed_build_artifact')
    require(re.fullmatch('[0-9a-f]{64}', receipt.get('executable_sha256', '')), 'missing_executable_hash')
    require(sha(receipt_path.parent / 'executable') == receipt['executable_sha256'], 'wrong_executed_binary')
    if contract['evidence_class'] == 'executed_unit':
        require(receipt['executable_sha256'] == artifacts[gate['command'][0]], 'wrong_executed_binary')
        summaries = re.findall(r'^test result: ok\. (\d+) passed; (\d+) failed;.*$', stdout, re.M)
        require(len(summaries) == 1 and int(summaries[0][0]) > 0 and int(summaries[0][1]) == 0,
                'missing_nonzero_executed_result')
        require(type(execution.get('executed_cases')) is int and
                execution['executed_cases'] == int(summaries[0][0]), 'executed_count_mismatch')
        passed = re.findall(r'^test (\S+) \.\.\. ok$', stdout, re.M)
        require(len(passed) == int(summaries[0][0]), 'executed_count_mismatch')
        require(set(gate['required_tests']) <= set(passed), 'unrelated_passing_tests')
    else:
        # Source/compiled checks are deliberately not promoted to runtime proof.
        require(gate.get('expected_stdout') and all(s in stdout for s in gate['expected_stdout']),
                'missing_named_check_observation')
    return contract['evidence_class']


try:
    require(policy['cutoff'] == '2026-10-15T00:00:00Z', 'historical_cutoff_changed')
    override = os.environ.get('FRANKENLIBC_CLOSURE_CUTOFF', policy['cutoff'])
    require(override == policy['cutoff'], 'historical_cutoff_override_forbidden')
    if action == 'record':
        require(len(args) == 2, 'usage: --record BEAD_ID NEW_OUTPUT_DIRECTORY')
        capture(args[0], path(args[1]))
    else:
        require(action in ('audit', 'admit'), 'unknown_action')
        selected = [beads[args[0]]] if action == 'admit' else [
            b for b in beads.values() if b.get('status') == 'closed' and b.get('issue_type') != 'epic'
            and timestamp(b.get('closed_at') or b['updated_at']) >= timestamp(policy['cutoff'])]
        passed = deferred = failed = 0
        for bead in selected:
            bid = bead['id']
            try:
                # Deferrals must already be explicit policy, never inferred from
                # a PASS sentence, hash, or a comment claiming owner approval.
                deferral = policy.get('owner_approved_deferrals', {}).get(bid)
                if deferral:
                    require(deferral.get('owner') and deferral.get('reason') and deferral.get('approval_ref'),
                            'invalid_owner_deferral')
                    print(f'DEFERRED {bid}: {deferral["reason"]} (not executed proof)')
                    deferred += 1
                    continue
                contract_for(bid)
                refs = entries[bid]['row'].get('result_receipts', [])
                require(refs, 'missing_stored_execution_result')
                kinds = [verify(bid, path(ref)) for ref in refs]
                print(f'PASS {bid}: {", ".join(kinds)}; retained results verified')
                passed += 1
            except (ValueError, KeyError, TypeError, OSError) as error:
                print(f'UNPROVEN {bid}: {error}')
                failed += 1
        print(f'POST_TOTAL={len(selected)}')
        print(f'POST_PASS={passed}')
        print(f'POST_DEFERRED={deferred}')
        print(f'POST_FAIL={failed}')
        sys.exit(bool(failed))
except (ValueError, KeyError, TypeError, OSError, subprocess.SubprocessError) as error:
    print(f'FAIL closure results: {error}', file=sys.stderr)
    sys.exit(1)
PY
}

case "${1:-}" in
    --record) shift; closure_results record "$@"; exit $? ;;
    --admit) shift; closure_results admit "$@"; exit $? ;;
    --help|-h)
        echo 'Usage: check_closure_gate.sh [--record BEAD_ID NEW_OUTPUT_DIRECTORY | --admit BEAD_ID]'
        echo 'Default audits all selected closed beads. --record invokes the matrix gate; compile via strict RCH.'
        echo 'Receipts prove only their declared class, never adequacy of the behavior contract or independent review.'
        exit 0 ;;
    '') ;;
    *) echo "unknown argument: $1" >&2; exit 2 ;;
esac

failures=0

echo "=== Closure Evidence Gate (bd-4rl) ==="
echo ""

# ---------------------------------------------------------------------------
# Check 1: Schema file exists and is valid
# ---------------------------------------------------------------------------
echo "--- Check 1: Schema file exists ---"

if [[ ! -f "${SCHEMA}" ]]; then
    echo "FAIL: tests/conformance/closure_evidence_schema.json not found"
    failures=$((failures + 1))
    echo ""
    echo "check_closure_gate: FAILED"
    exit 1
fi

schema_valid=$(python3 -c "
import json
try:
    with open('${SCHEMA}') as f:
        schema = json.load(f)
    v = schema.get('schema_version', 0)
    reqs = schema.get('evidence_requirements', {})
    exempt = schema.get('legacy_exempt', [])
    if v < 1:
        print('INVALID: schema_version < 1')
    elif not reqs:
        print('INVALID: empty evidence_requirements')
    else:
        print(f'VALID version={v} requirements={len(reqs)} exempt={len(exempt)}')
except Exception as e:
    print(f'INVALID: {e}')
")

if [[ "${schema_valid}" == INVALID* ]]; then
    echo "FAIL: ${schema_valid}"
    failures=$((failures + 1))
else
    echo "PASS: ${schema_valid}"
fi
echo ""

# ---------------------------------------------------------------------------
# Check 2: Evidence audit for closed critique beads
# ---------------------------------------------------------------------------
echo "--- Check 2: Closed critique bead evidence audit ---"
echo "Source: ${SOURCE}"

audit_result=$(python3 -c "
import json
import os

with open('${SCHEMA}') as f:
    schema = json.load(f)
with open('${MATRIX}') as f:
    matrix = json.load(f)

source = os.environ.get('FRANKENLIBC_CLOSURE_GATE_SOURCE', 'matrix').lower()
if source not in ('matrix', 'beads'):
    print(f'INVALID: unknown source {source}')
    raise SystemExit(1)

bead_lines = []
if source == 'beads':
    with open('${BEADS}') as f:
        bead_lines = f.readlines()

legacy_exempt = set(schema.get('legacy_exempt', []))

# Parse beads (optional)
beads = {}
if bead_lines:
    for line in bead_lines:
        line = line.strip()
        if not line:
            continue
        b = json.loads(line)
        beads[b['id']] = b

# Find closed critique beads
closed_critique = {}
if source == 'beads':
    for bid, b in beads.items():
        if b.get('status') == 'closed' and 'critique' in b.get('labels', []):
            closed_critique[bid] = b
else:
    for entry in matrix.get('entries', []):
        if entry.get('status') == 'closed' and 'critique' in entry.get('labels', []):
            bid = entry.get('bead_id')
            if bid:
                closed_critique[bid] = entry

# Build matrix lookup
matrix_map = {}
for e in matrix.get('entries', []):
    matrix_map[e['bead_id']] = e

# Audit each closed critique bead
failures = []
warnings = []
stats = {'total': 0, 'exempt': 0, 'pass': 0, 'fail': 0, 'warn': 0}

for bid in sorted(closed_critique.keys()):
    stats['total'] += 1
    is_exempt = bid in legacy_exempt
    issues = []

    entry = matrix_map.get(bid)
    if not entry:
        issues.append('no_matrix_entry')
    else:
        row = entry.get('row', {})
        cs = entry.get('coverage_summary', {})

        # Check test commands
        unit_cmds = row.get('unit_cmds', [])
        e2e_cmds = row.get('e2e_cmds', [])
        if not unit_cmds and not e2e_cmds:
            issues.append('no_test_commands')

        # Check artifact references
        artifact_paths = row.get('artifact_paths', [])
        log_refs = row.get('log_schema_refs', [])
        if not artifact_paths and not log_refs:
            issues.append('no_artifact_refs')

        # Check coverage status
        overall = cs.get('overall', 'missing')
        if overall == 'missing':
            issues.append('coverage_missing')

        # Check close blockers
        blockers = row.get('close_blockers', [])
        if blockers:
            issues.append(f'close_blockers={len(blockers)}')

    if not issues:
        stats['pass'] += 1
    elif is_exempt:
        stats['exempt'] += 1
        stats['warn'] += 1
        for issue in issues:
            warnings.append(f'{bid}: {issue} (legacy-exempt)')
    else:
        stats['fail'] += 1
        for issue in issues:
            failures.append(f'{bid}: {issue}')

print(f'TOTAL={stats[\"total\"]}')
print(f'PASS={stats[\"pass\"]}')
print(f'FAIL={stats[\"fail\"]}')
print(f'EXEMPT_WARN={stats[\"warn\"]}')

if failures:
    print('')
    print('FAILURES:')
    for f in failures:
        print(f'  {f}')

if warnings:
    print('')
    print('LEGACY WARNINGS (informational):')
    for w in warnings:
        print(f'  {w}')
")

total=$(echo "${audit_result}" | grep '^TOTAL=' | cut -d= -f2)
pass_count=$(echo "${audit_result}" | grep '^PASS=' | cut -d= -f2)
fail_count=$(echo "${audit_result}" | grep '^FAIL=' | cut -d= -f2)
warn_count=$(echo "${audit_result}" | grep '^EXEMPT_WARN=' | cut -d= -f2)

echo "Closed critique beads: ${total}"
echo "Evidence complete: ${pass_count}"
echo "Evidence failures: ${fail_count}"
echo "Legacy-exempt warnings: ${warn_count}"
echo ""

if [[ "${fail_count}" -gt 0 ]]; then
    echo "FAIL: ${fail_count} non-exempt bead(s) lack required evidence:"
    echo "${audit_result}" | grep -A1000 'FAILURES:' | grep '  bd-' || true
    echo ""
    failures=$((failures + 1))
else
    echo "PASS: All non-exempt closed beads have evidence (or are legacy-exempt)"
fi

if [[ "${warn_count}" -gt 0 ]]; then
    echo ""
    echo "WARNING: ${warn_count} legacy-exempt bead(s) lack evidence (not blocking):"
    echo "${audit_result}" | grep -A1000 'LEGACY WARNINGS' | grep '  bd-' || true
fi
echo ""

# ---------------------------------------------------------------------------
# Check 3: Evidence requirement coverage
# ---------------------------------------------------------------------------
echo "--- Check 3: Evidence requirement field coverage ---"

field_check=$(python3 -c "
import json

with open('${SCHEMA}') as f:
    schema = json.load(f)
with open('${MATRIX}') as f:
    matrix = json.load(f)

reqs = schema.get('evidence_requirements', {})
entries = matrix.get('entries', [])
errors = []

# Verify the schema's required fields are present in matrix entries
for e in entries:
    bid = e.get('bead_id', '<unknown>')
    row = e.get('row', {})

    # Check row exists
    if not row:
        errors.append(f'{bid}: missing row object')
        continue

    # Check required row fields exist
    for field in ['unit_cmds', 'e2e_cmds', 'artifact_paths', 'close_blockers']:
        if field not in row:
            errors.append(f'{bid}: row missing field \"{field}\"')

    # Check coverage_summary exists
    if 'coverage_summary' not in e:
        errors.append(f'{bid}: missing coverage_summary')

print(f'FIELD_ERRORS={len(errors)}')
for err in errors[:20]:
    print(f'  {err}')
")

field_errs=$(echo "${field_check}" | grep '^FIELD_ERRORS=' | cut -d= -f2)

if [[ "${field_errs}" -gt 0 ]]; then
    echo "FAIL: ${field_errs} field error(s) in matrix entries:"
    echo "${field_check}" | grep '  ' | head -20
    failures=$((failures + 1))
else
    echo "PASS: All matrix entries have required evidence fields"
fi
echo ""

# ---------------------------------------------------------------------------
# Check 4: Coverage debt summary
# ---------------------------------------------------------------------------
echo "--- Check 4: Coverage debt summary ---"

python3 -c "
import json
import os

with open('${SCHEMA}') as f:
    schema = json.load(f)
with open('${MATRIX}') as f:
    matrix = json.load(f)

source = os.environ.get('FRANKENLIBC_CLOSURE_GATE_SOURCE', 'matrix').lower()
bead_lines = []
if source == 'beads':
    with open('${BEADS}') as f:
        bead_lines = f.readlines()

legacy_exempt = set(schema.get('legacy_exempt', []))

beads = {}
if bead_lines:
    for line in bead_lines:
        line = line.strip()
        if not line:
            continue
        b = json.loads(line)
        beads[b['id']] = b

# Count beads in each state
closed_critique = set()
if source == 'beads':
    for bid, b in beads.items():
        if b.get('status') == 'closed' and 'critique' in b.get('labels', []):
            closed_critique.add(bid)
else:
    for entry in matrix.get('entries', []):
        if entry.get('status') == 'closed' and 'critique' in entry.get('labels', []):
            bid = entry.get('bead_id')
            if bid:
                closed_critique.add(bid)

matrix_map = {}
for e in matrix.get('entries', []):
    matrix_map[e['bead_id']] = e

# Debt = closed critique beads without complete evidence
no_entry = sum(1 for bid in closed_critique if bid not in matrix_map)
has_entry = sum(1 for bid in closed_critique if bid in matrix_map)
exempt_no_entry = sum(1 for bid in closed_critique if bid in legacy_exempt and bid not in matrix_map)

complete = 0
partial = 0
missing = 0
for bid in closed_critique:
    if bid in matrix_map:
        overall = matrix_map[bid].get('coverage_summary', {}).get('overall', 'missing')
        if overall == 'complete':
            complete += 1
        elif overall == 'partial':
            partial += 1
        else:
            missing += 1

print(f'Closed critique beads: {len(closed_critique)}')
print(f'  With matrix entry: {has_entry} (complete={complete}, partial={partial}, missing={missing})')
print(f'  Without matrix entry: {no_entry} ({exempt_no_entry} legacy-exempt)')
print(f'  Coverage debt: {no_entry + missing + partial} beads need evidence improvement')
"
echo ""

# ---------------------------------------------------------------------------
# Check 5: Post-cutoff (2026-10-15T00:00:00Z) closed-bead evidence audit
# ---------------------------------------------------------------------------
echo "--- Check 5: Post-cutoff (2026-10-15T00:00:00Z) closed-bead audit ---"

if [[ -f "${BEADS}" ]]; then
    if closure_results audit; then
        echo 'PASS: Post-cutoff receipts satisfy their explicit evidence classes'
    else
        echo 'FAIL: Post-cutoff closure evidence is unproven; see retained-result diagnostics above'
        failures=$((failures + 1))
    fi
else
    echo "FAIL: ${BEADS} not present; cannot audit post-cutoff closures"
    failures=$((failures + 1))
fi
echo ""

# ---------------------------------------------------------------------------
# Summary
# ---------------------------------------------------------------------------
echo "=== Summary ==="
echo "Failures: ${failures}"

if [[ "${failures}" -gt 0 ]]; then
    echo ""
    echo "check_closure_gate: FAILED"
    exit 1
fi

echo ""
echo "check_closure_gate: PASS"
