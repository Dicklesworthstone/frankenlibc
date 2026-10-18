#!/usr/bin/env python3
"""Run real platform-header AIO queue contracts against host and candidate."""
import argparse
import json
import os
from pathlib import Path
import subprocess

CASES = ('empty', 'cancel-one', 'cancel-all', 'cancel-thread', 'cancel-batch',
         'cancel-reuse', 'cancel-signal', 'fsync-barrier', 'cancel-fsync',
         'file-fsync', 'file-fdatasync', 'callback-progress', 'fifo')
RACES = ('cancel-contended', 'cancel-complete-race', 'cancel-retire')


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('library', type=Path)
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--repeat', type=int, default=1)
    args = parser.parse_args()
    library = args.library.resolve(strict=True)
    if args.repeat < 1:
        parser.error('--repeat must be positive')
    root = Path(__file__).resolve().parents[1]
    args.output.mkdir(parents=True, exist_ok=True)
    env = dict(os.environ)
    for key in ('LD_PRELOAD', 'FRANKENLIBC_MODE', 'FRANKENLIBC_TEST_LIBRARY', 'FRANKENLIBC_THREAD_NATIVE'):
        env.pop(key, None)
    results = []
    for interface, flags in [('native', []), ('largefile64', ['-D_FILE_OFFSET_BITS=64'])]:
        binary = (args.output / f'fixture-{interface}').resolve()
        subprocess.run([os.environ.get('CC', 'cc'), '-std=c11', '-O2', '-Wall', '-Wextra', '-Werror',
                        '-pthread', *flags, str(root / 'tests/integration/fixture_aio_queue.c'),
                        '-lrt', '-ldl', '-o', str(binary)], check=True, env=env)
        race_binary = (args.output / f'race-{interface}').resolve()
        subprocess.run([os.environ.get('CC', 'cc'), '-std=c11', '-O2', '-Wall', '-Wextra', '-Werror',
                        '-pthread', *flags, str(root / 'tests/integration/fixture_aio_queue_race.c'),
                        '-lrt', '-ldl', '-o', str(race_binary)], check=True, env=env)
        for case in (*CASES, *RACES):
            executable = race_binary if case in RACES else binary
            for mode in ('host', 'strict', 'hardened'):
                test_env = dict(env)
                if mode != 'host':
                    test_env.update(LD_PRELOAD=str(library), FRANKENLIBC_TEST_LIBRARY=str(library),
                                    FRANKENLIBC_MODE=mode, FRANKENLIBC_THREAD_NATIVE='0')
                for iteration in range(args.repeat):
                    name = f'{interface}-{mode}-{case}-{iteration}'
                    try:
                        run = subprocess.run([str(executable), case], env=test_env, capture_output=True, timeout=12)
                        stdout, stderr, code = run.stdout, run.stderr, run.returncode
                    except subprocess.TimeoutExpired as exc:
                        stdout, stderr, code = exc.stdout or b'', exc.stderr or b'', 124
                    (args.output / f'{name}.out').write_bytes(stdout)
                    (args.output / f'{name}.err').write_bytes(stderr)
                    ok = code == 0 and stdout == f'PASS {case}\n'.encode() and not stderr
                    results.append(dict(interface=interface, mode=mode, case=case, iteration=iteration,
                                        returncode=code, passed=ok))
                    (args.output / 'results.json').write_text(json.dumps(results, indent=2) + '\n')
                    if not ok:
                        raise SystemExit(f'FAIL {name}: rc={code}: {stderr.decode(errors="replace")}')
        # Prove provider checks do not silently accept a missing preload.
        control = subprocess.run([str(binary), 'empty'], env=dict(env, FRANKENLIBC_TEST_LIBRARY=str(binary)),
                                 capture_output=True, timeout=12)
        if control.returncode != 1 or b'AIO symbol must bind to candidate library' not in control.stderr:
            raise SystemExit(f'FAIL false-provider control: {interface}')
    host = sum(r['mode'] == 'host' for r in results)
    print(f'AIO queue: {host} host and {len(results) - host} candidate cases passed')


if __name__ == '__main__':
    main()
