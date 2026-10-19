#!/usr/bin/env python3
"""Execute bounded UDP duplicate-reply contracts against real service exports.

The host is characterized separately: historical glibc releases fail replay
suppression in these probes. Those failures are retained verbatim, not converted
into passes or used as candidate goldens. Existing service differential tests
remain a separate mandatory check in the workflow.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import subprocess

CASES = ['cache-basic', 'cache-peers', 'cache-eviction', 'cache-error',
         'cache-burst', 'cache-transport', 'cache-failed-encode', 'cache-body',
         'cache-credentials', 'cache-generation', 'cache-limits', 'cache-destroy',
         'cache-callback-exit', 'cache-oversized', 'cache-input-snapshot']
HOST_CASES = CASES[:7]


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('library', type=Path)
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--repeat', type=int, default=1)
    args = parser.parse_args()
    if args.repeat < 1:
        parser.error('--repeat must be positive')
    root = Path(__file__).resolve().parents[1]
    out = args.output.resolve()
    out.mkdir(parents=True, exist_ok=True)
    library = args.library.resolve(strict=True)
    fixture = out / 'fixture'
    subprocess.run([os.environ.get('CC', 'cc'), '-O2', '-Wall', '-Wextra', '-Werror',
                    str(root / 'tests/integration/fixture_rpc_svc_cache.c'),
                    '-ldl', '-pthread', '-o', str(fixture)], check=True)
    clean = {k: v for k, v in os.environ.items()
             if k != 'LD_PRELOAD' and not k.startswith(('FRANKENLIBC_', 'RPC_TRACE'))}
    report = {'library_sha256': hashlib.sha256(library.read_bytes()).hexdigest(),
              'results': []}

    def execute(label, case, env, required=True, negative=False):
        try:
            p = subprocess.run([str(fixture), case], env=env, capture_output=True, timeout=12)
            code, stdout, stderr = p.returncode, p.stdout, p.stderr
        except subprocess.TimeoutExpired as e:
            code, stdout, stderr = 124, e.stdout or b'', (e.stderr or b'') + b'TIMEOUT\n'
        passed = (code == 2 and not stdout and b'WRONG_PROVIDER' in stderr) if negative else (
            code == 0 and stdout == f'PASS {case}\n'.encode() and not stderr)
        (out / f'{label}-{case}.out').write_bytes(stdout)
        (out / f'{label}-{case}.err').write_bytes(stderr)
        report['results'].append(dict(provider=label, case=case, returncode=code,
                                      passed=passed, required=required, negative=negative))
        (out / 'report.json').write_text(json.dumps(report, indent=2) + '\n')
        print(f'{"PASS" if passed else "FAIL"} {label}/{case}', flush=True)

    for case in HOST_CASES:
        execute('host-characterization', case, clean, required=False)
    execute('wrong-provider-host', CASES[0],
            dict(clean, FRANKENLIBC_TEST_LIBRARY=str(library)), negative=True)
    execute('wrong-provider-candidate', CASES[0],
            dict(clean, LD_PRELOAD=str(library), FRANKENLIBC_TEST_LIBRARY=str(fixture),
                 FRANKENLIBC_THREAD_NATIVE='0'), negative=True)
    for mode in ['strict', 'hardened']:
        env = dict(clean, LD_PRELOAD=str(library), FRANKENLIBC_TEST_LIBRARY=str(library),
                   FRANKENLIBC_MODE=mode, FRANKENLIBC_THREAD_NATIVE='0')
        for iteration in range(args.repeat):
            for case in CASES:
                execute(f'{mode}-{iteration}', case, env)
    rows = report['results']
    report['summary'] = {
        'candidate_executions': 2 * len(CASES) * args.repeat,
        'required_passed': sum(r['required'] and r['passed'] for r in rows),
        'required_failed': sum(r['required'] and not r['passed'] for r in rows),
        'host_characterization_passed': sum(not r['required'] and r['passed'] for r in rows),
        'host_characterization_failed': sum(not r['required'] and not r['passed'] for r in rows),
    }
    (out / 'report.json').write_text(json.dumps(report, indent=2) + '\n')
    print(json.dumps(report['summary']), flush=True)
    if report['summary']['required_failed']:
        raise SystemExit(1)


if __name__ == '__main__':
    main()
