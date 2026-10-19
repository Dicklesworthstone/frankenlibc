#!/usr/bin/env python3
"""Check real C++ TLS destruction on normal process termination."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import subprocess

ROOT = Path(__file__).resolve().parents[1]
CASES = {
    'empty': ('E', 23), 'return-main': ('BAE', 23), 'explicit': ('BAE', 23),
    'worker-exit': ('BAE', 23), 'worker-return': ('BAE', 23),
    'other-thread': ('BAE', 23), 'new-atexit': ('BALE', 23),
    'new-tls': ('BNAE', 23), 'recursive': ('BAE', 37),
    'pthread-key': ('BAE', 23), 'runtime-after-tls': ('BAE', 23),
    'immediate': ('', 23), 'quick': ('Q', 23),
}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('library', nargs='?')
    parser.add_argument('--reference-only', action='store_true')
    parser.add_argument('--output', default='target/exit-tls')
    args = parser.parse_args()
    if not args.reference_only and not args.library:
        parser.error('supply a candidate library or --reference-only')
    out = Path(args.output).resolve()
    out.mkdir(parents=True, exist_ok=True)
    binary = out / 'fixture'
    subprocess.run([os.environ.get('CXX', 'c++'), '-std=c++17', '-O2', '-Wall', '-Wextra',
                    '-Werror', '-pthread', str(ROOT / 'tests/integration/fixture_exit_tls.cpp'),
                    '-ldl', '-o', str(binary)], check=True)
    clean = dict(os.environ)
    for key in ['LD_PRELOAD', 'FRANKENLIBC_MODE', 'FRANKENLIBC_TEST_LIBRARY',
                'FRANKENLIBC_THREAD_NATIVE', 'FRANKENLIBC_STARTUP_DELEGATE',
                'FRANKENLIBC_DLFCN_MODE', 'TEST_EXIT_PROVIDER']:
        clean.pop(key, None)
    results = []
    failures = []

    def run(label, case, env, wrong_provider=False):
        try:
            proc = subprocess.run([str(binary), case], env=env, capture_output=True, timeout=15)
            stdout, stderr, rc = proc.stdout, proc.stderr, proc.returncode
        except subprocess.TimeoutExpired as error:
            stdout, stderr, rc = error.stdout or b'', error.stderr or b'', 124
        (out / f'{label}-{case}.out').write_bytes(stdout)
        (out / f'{label}-{case}.err').write_bytes(stderr)
        expected, status = CASES[case]
        ok = (rc == 113 and stderr == b'WRONG EXIT/TLS PROVIDER\n' and stdout == b'') if wrong_provider else (
            rc == status and stdout == expected.encode() and stderr == b'')
        results.append({'provider': label, 'case': case, 'returncode': rc, 'passed': ok})
        if not ok:
            failures.append(f'{label}/{case}')
            print(f'FAIL {label}/{case}: rc={rc} stdout={stdout!r} stderr={stderr!r}', flush=True)

    for case in CASES:
        run('host', case, clean)
    library = None
    if not args.reference_only:
        library = Path(args.library).resolve(strict=True)
        run('negative-host', 'explicit', dict(clean, FRANKENLIBC_TEST_LIBRARY=str(library)), True)
        for mode in ['strict', 'hardened']:
            for startup in ['0', '1']:
                for driver in ['native', 'host']:
                    env = dict(clean, LD_PRELOAD=str(library), FRANKENLIBC_TEST_LIBRARY=str(library),
                               FRANKENLIBC_MODE=mode, FRANKENLIBC_THREAD_NATIVE='0',
                               FRANKENLIBC_STARTUP_DELEGATE=startup, TEST_EXIT_PROVIDER=driver)
                    for case in CASES:
                        run(f'{mode}-startup{startup}-{driver}', case, env)
    report = {'results': results, 'failures': failures,
              'library_sha256': hashlib.sha256(library.read_bytes()).hexdigest() if library else None}
    (out / 'results.json').write_text(json.dumps(report, indent=2) + '\n')
    print(f'Exit TLS: {len(results) - len(failures)}/{len(results)} checks passed', flush=True)
    if failures:
        raise SystemExit('Exit TLS failures: ' + ', '.join(failures))


if __name__ == '__main__':
    main()
