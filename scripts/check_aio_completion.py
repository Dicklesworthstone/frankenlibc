#!/usr/bin/env python3
"""Execute platform-header AIO contracts against actual release exports."""
import argparse
import json
import os
from pathlib import Path
import subprocess

ROOT = Path(__file__).resolve().parents[1]
REFERENCE = (
    'signal-read signal-error thread-return thread-exit batch-signal batch-thread '
    'empty errors timeout suspend-signal suspend-cancel suspend-pending '
    'suspend64-signal list-cancel list-pending list64-cancel list64-pending'
).split()
# These check the POSIX EINTR contract independently. Local glibc 2.41 crashes
# on this interrupted-LIO_WAIT probe; do not label these as glibc parity.
POSIX_ONLY = ['list-signal', 'list64-signal']
CPP_CASES = ['cpp-return', 'cpp-exit', 'cpp-cancel']


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('library', nargs='?')
    parser.add_argument('--reference-only', action='store_true')
    parser.add_argument('--output', default='target/aio-completion')
    args = parser.parse_args()
    if not args.reference_only and not args.library:
        parser.error('a candidate shared library is required')
    out = Path(args.output).resolve()
    out.mkdir(parents=True, exist_ok=True)
    binary = out / 'fixture'
    subprocess.run([os.environ.get('CC', 'cc'), '-std=c11', '-O2', '-Wall', '-Wextra',
                    '-Werror', '-pthread', str(ROOT / 'tests/integration/fixture_aio_completion.c'),
                    '-ldl', '-lrt', '-o', str(binary)], check=True)
    cpp_binary = out / 'fixture-cpp'
    subprocess.run([os.environ.get('CXX', 'c++'), '-std=c++17', '-O2', '-Wall', '-Wextra',
                    '-Werror', '-pthread', str(ROOT / 'tests/integration/fixture_aio_completion_cpp.cpp'),
                    '-ldl', '-lrt', '-o', str(cpp_binary)], check=True)
    env = dict(os.environ)
    for name in ['LD_PRELOAD', 'FRANKENLIBC_MODE', 'FRANKENLIBC_TEST_LIBRARY',
                 'FRANKENLIBC_THREAD_NATIVE']:
        env.pop(name, None)
    results = []
    failures = []

    def run(label, case, environment):
        try:
            executable = cpp_binary if case in CPP_CASES else binary
            result = subprocess.run([str(executable), case], env=environment, capture_output=True,
                                    timeout=12, check=False)
            stdout, stderr, rc = result.stdout, result.stderr, result.returncode
        except subprocess.TimeoutExpired as error:
            stdout, stderr, rc = error.stdout or b'', error.stderr or b'', 124
        (out / f'{label}-{case}.out').write_bytes(stdout)
        (out / f'{label}-{case}.err').write_bytes(stderr)
        ok = rc == 0 and stdout == f'PASS {case}\n'.encode() and stderr == b''
        results.append({'provider': label, 'case': case, 'returncode': rc, 'passed': ok})
        print(f'{"PASS" if ok else "FAIL"} {label}/{case}', flush=True)
        if not ok:
            failures.append(f'{label}/{case}')
            print(stderr.decode(errors='replace'), flush=True)
        return stdout, stderr

    host = {case: run('host', case, env) for case in REFERENCE + CPP_CASES}
    if not args.reference_only:
        library = str(Path(args.library).resolve(strict=True))
        for mode in ['strict', 'hardened']:
            candidate_env = dict(env, LD_PRELOAD=library, FRANKENLIBC_TEST_LIBRARY=library,
                                 FRANKENLIBC_MODE=mode, FRANKENLIBC_THREAD_NATIVE='0')
            for case in REFERENCE + POSIX_ONLY + CPP_CASES:
                actual = run(mode, case, candidate_env)
                if case in host and actual != host[case]:
                    failures.append(f'{mode}/{case}/reference-difference')
    report = {'reference_cases': len(REFERENCE) + len(CPP_CASES),
              'candidate_cases': 0 if args.reference_only else 2 * (len(REFERENCE) + len(POSIX_ONLY) + len(CPP_CASES)),
              'results': results, 'failures': failures}
    (out / 'summary.json').write_text(json.dumps(report, indent=2) + '\n')
    if failures:
        raise SystemExit('AIO completion failures: ' + ', '.join(failures))
    print(f'AIO completion: {report["reference_cases"]} reference and '
          f'{report["candidate_cases"]} candidate cases passed')


if __name__ == '__main__':
    main()
