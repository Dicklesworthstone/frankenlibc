#!/usr/bin/env python3
"""Execute service replay/forced-unwind contracts against real release exports."""
from __future__ import annotations
import argparse
import hashlib
import json
import os
from pathlib import Path
import subprocess

CASES = ('dispatch-throw', 'encode-throw', 'decode-throw', 'free-throw',
         'dispatch-exit', 'encode-exit', 'decode-exit', 'destroy-exit')
CASES += tuple('tcp-' + case for case in CASES)
CASES += tuple('unix-' + case for case in CASES[:8])


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('library', type=Path)
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--repeat', type=int, default=2)
    args = parser.parse_args()
    if not 1 <= args.repeat <= 100:
        parser.error('--repeat must be between 1 and 100')
    lib = args.library.resolve(strict=True)
    root = Path(__file__).resolve().parents[1]
    out = args.output.resolve()
    out.mkdir(parents=True, exist_ok=True)
    binary = out / 'fixture'
    fixture = root / 'tests/integration/fixture_rpc_svc_unwind.cpp'
    subprocess.run([os.environ.get('CXX', 'c++'), '-std=c++17', '-O2', '-Wall',
                    '-Wextra', '-Werror', '-pthread', str(fixture), '-ldl',
                    '-o', str(binary)], check=True)
    clean = {k: v for k, v in os.environ.items()
             if k != 'LD_PRELOAD' and not k.startswith('FRANKENLIBC_')}
    report = {'library_sha256': hashlib.sha256(lib.read_bytes()).hexdigest(),
              'fixture_sha256': hashlib.sha256(fixture.read_bytes()).hexdigest(),
              'results': []}

    def run(label: str, case: str, env: dict[str, str], negative: bool = False) -> None:
        try:
            p = subprocess.run([str(binary), case], env=env, capture_output=True, timeout=12)
            stdout, stderr, rc = p.stdout, p.stderr, p.returncode
        except subprocess.TimeoutExpired as e:
            stdout, stderr, rc = e.stdout or b'', e.stderr or b'', 124
        expected_rc, expected_out, expected_err = (
            (86, b'', b'WRONG RPC SERVICE PROVIDER\n') if negative else
            (0, f'PASS {case}\n'.encode(), b''))
        ok = (rc, stdout, stderr) == (expected_rc, expected_out, expected_err)
        (out / f'{label}-{case}.out').write_bytes(stdout)
        (out / f'{label}-{case}.err').write_bytes(stderr)
        report['results'].append(dict(provider=label, case=case, negative=negative,
                                      returncode=rc, passed=ok))
        (out / 'results.json').write_text(json.dumps(report, indent=2) + '\n')
        print(f'{"PASS" if ok else "FAIL"} {label}/{case}', flush=True)

    run('provider-negative', 'dispatch-throw',
        dict(clean, FRANKENLIBC_TEST_LIBRARY=str(lib)), True)
    for mode in ('strict', 'hardened'):
        env = dict(clean, LD_PRELOAD=str(lib), FRANKENLIBC_TEST_LIBRARY=str(lib),
                   FRANKENLIBC_MODE=mode, FRANKENLIBC_THREAD_NATIVE='0')
        for iteration in range(args.repeat):
            for case in CASES:
                run(f'{mode}-{iteration}', case, env)
    failed = sum(not row['passed'] for row in report['results'])
    report['summary'] = dict(total=len(report['results']), failed=failed,
                             passed=len(report['results']) - failed)
    (out / 'results.json').write_text(json.dumps(report, indent=2) + '\n')
    print(json.dumps(report['summary']))
    return int(failed != 0)


if __name__ == '__main__':
    raise SystemExit(main())
