#!/usr/bin/env python3
"""Exercise owned registrations through both native and host-internal exit."""
from __future__ import annotations
import argparse
import hashlib
import json
import os
from pathlib import Path
import subprocess

CASES = ('order', 'reentrant', 'finalize', 'recursive-finalize',
         'register-finalize', 'recursive-exit', 'mixed-order', 'context-null',
         'registration-stress', 'concurrent-finalize',
         'host-finalize', 'mixed-finalize', 'finalize-all')

def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('library', type=Path)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    library = args.library.resolve(strict=True)
    root = Path(__file__).resolve().parents[1]
    out = args.output.resolve(); out.mkdir(parents=True, exist_ok=True)
    binary = out / 'fixture'
    subprocess.run([os.environ.get('CC', 'cc'), '-O2', '-Wall', '-Wextra', '-Werror',
                    str(root/'tests/integration/fixture_exit_tickets.c'), '-ldl',
                    '-o', str(binary), '-pthread'], check=True)
    cxx = os.environ.get('CXX', 'c++')
    cpp = root/'tests/integration/fixture_exit_tickets_dso.cpp'
    plugin, cpp_binary = out/'plugin.so', out/'fixture-cpp'
    common = [cxx, '-O2', '-Wall', '-Wextra', '-Werror']
    subprocess.run([*common, '-shared', '-fPIC', '-DEXIT_DSO_BUILD', str(cpp),
                    '-o', str(plugin)], check=True)
    subprocess.run([*common, str(cpp), '-ldl', '-o', str(cpp_binary)], check=True)
    base = {k:v for k,v in os.environ.items()
            if k != 'LD_PRELOAD' and not k.startswith('FRANKENLIBC_')}
    report = {'library_sha256': hashlib.sha256(library.read_bytes()).hexdigest(), 'cases': []}
    for mode in ('host-reference', 'strict', 'hardened'):
        env = dict(base)
        if mode != 'host-reference':
            env.update(LD_PRELOAD=str(library), FRANKENLIBC_TEST_LIBRARY=str(library),
                       FRANKENLIBC_MODE=mode, FRANKENLIBC_THREAD_NATIVE='0')
        for endpoint in ('native', 'host'):
            for case in CASES:
                if case in ('mixed-order', 'context-null') and endpoint != 'host':
                    continue  # host registry ordering only when host drives exit
                try:
                    p = subprocess.run([str(binary), case, endpoint], env=env,
                                       capture_output=True, text=True, timeout=10)
                    row = dict(mode=mode, endpoint=endpoint, case=case, returncode=p.returncode,
                               stdout=p.stdout, stderr=p.stderr,
                               passed=p.returncode == (0 if case == 'context-null' else 23) and p.stdout == 'PASS exit-tickets\n' and not p.stderr)
                except subprocess.TimeoutExpired:
                    row = dict(mode=mode, endpoint=endpoint, case=case, passed=False, returncode='timeout')
                report['cases'].append(row)
                (out/'results.json').write_text(json.dumps(report, indent=2)+'\n')
        for endpoint in ('native', 'host'):
            try:
                p = subprocess.run([str(cpp_binary), str(plugin), endpoint], env=env,
                                   capture_output=True, text=True, timeout=10)
                row = dict(mode=mode, endpoint=endpoint, case='cpp-dso', returncode=p.returncode,
                           stdout=p.stdout, stderr=p.stderr,
                           passed=p.returncode == 23 and p.stdout == 'PASS exit-dso\n' and not p.stderr)
            except subprocess.TimeoutExpired:
                row = dict(mode=mode, endpoint=endpoint, case='cpp-dso', passed=False, returncode='timeout')
            report['cases'].append(row)
            (out/'results.json').write_text(json.dumps(report, indent=2)+'\n')
    wrong = dict(base, FRANKENLIBC_TEST_LIBRARY=str(library))
    p = subprocess.run([str(binary), 'order', 'host'], env=wrong,
                       capture_output=True, text=True, timeout=10)
    report['cases'].append(dict(mode='provider-negative', endpoint='host', case='order',
                               returncode=p.returncode, stdout=p.stdout, stderr=p.stderr,
                               passed=p.returncode == 1 and not p.stdout and
                               'a.st_dev==b.st_dev&&a.st_ino==b.st_ino' in p.stderr))
    failed = sum(not r['passed'] for r in report['cases'])
    report['summary'] = dict(total=len(report['cases']), failed=failed, passed=len(report['cases'])-failed)
    (out/'results.json').write_text(json.dumps(report, indent=2)+'\n')
    print(json.dumps(report['summary']))
    return int(failed != 0)

if __name__ == '__main__':
    raise SystemExit(main())
