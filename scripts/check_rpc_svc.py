#!/usr/bin/env python3
"""Execute real glibc-shaped RPC service exports, using isolated UDP processes."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import subprocess

HOST = ['transport', 'dispatch', 'fdset', 'poll', 'mask', 'string', 'errors',
        'auth', 'lifecycle', 'borrowed', 'run-exit']
# These are independently specified bounds/lifetime contracts, not host-parity
# claims: some historical glibc servers accept truncated UDP prefixes or keep
# their service registry in a different thread. Never label their failure green.
OWNED = ['short-args', 'destroy-dispatch', 'callback-exit', 'malformed', 'oversized']

def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('library', type=Path)
    parser.add_argument('--output', type=Path, default=Path('artifacts/rpc-svc'))
    args = parser.parse_args()
    root = Path(__file__).resolve().parents[1]
    out = args.output.resolve()
    out.mkdir(parents=True, exist_ok=True)
    library = args.library.resolve(strict=True)
    fixture = out / 'fixture'
    subprocess.run(['cc', '-O2', '-Wall', '-Wextra', '-Werror',
                    str(root / 'tests/integration/fixture_rpc_svc.c'),
                    '-ldl', '-pthread', '-o', str(fixture)], check=True)
    base = {k: v for k, v in os.environ.items()
            if k not in ('LD_PRELOAD', 'FRANKENLIBC_TEST_LIBRARY', 'RPC_TRACE')}
    base.update(FRANKENLIBC_THREAD_NATIVE='0')
    records = []
    def execute(mode, case, env, negative=False):
        name = f'{mode}-{case}'
        try:
            p = subprocess.run([str(fixture), case], env=env, capture_output=True, timeout=12)
            code, stdout, stderr = p.returncode, p.stdout, p.stderr
        except subprocess.TimeoutExpired as e:
            code, stdout, stderr = -999, e.stdout or b'', (e.stderr or b'') + b'\nTIMEOUT\n'
        passed = (code == 2 and b'WRONG_PROVIDER' in stderr) if negative else (
            code == 0 and stdout == f'PASS {case}\n'.encode() and not stderr)
        (out / f'{name}.out').write_bytes(stdout)
        (out / f'{name}.err').write_bytes(stderr)
        records.append({'mode': mode, 'case': case, 'passed': passed, 'returncode': code,
                        'negative': negative, 'host_differential': case in HOST and not negative})
        (out / 'report.json').write_text(json.dumps({
            'library_sha256': hashlib.sha256(library.read_bytes()).hexdigest(),
            'results': records}, indent=2) + '\n')
        if not passed:
            raise SystemExit(f'FAIL {name}: rc={code}: {stderr.decode(errors="replace")}')
    for case in HOST:
        execute('host', case, base)
    execute('wrong-provider-host', 'dispatch', {**base, 'FRANKENLIBC_TEST_LIBRARY': str(library)}, True)
    execute('wrong-provider-candidate', 'dispatch', {**base, 'LD_PRELOAD': str(library),
            'FRANKENLIBC_TEST_LIBRARY': str(fixture)}, True)
    for mode in ('strict', 'hardened'):
        env = {**base, 'LD_PRELOAD': str(library), 'FRANKENLIBC_TEST_LIBRARY': str(library), 'FRANKENLIBC_MODE': mode}
        for case in HOST + OWNED:
            execute(mode, case, env)
    print(f'RPC services: {len(HOST)} host, 2 negative, {2 * (len(HOST) + len(OWNED))} candidate cases passed')

if __name__ == '__main__':
    main()
