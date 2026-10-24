#!/usr/bin/env python3
"""Exercise authoritative Secure RPC files and public GNU NSS module contracts.

libtirpc is the independent positive files oracle: modern glibc compatibility
exports no longer provide that legacy files backend. glibc's versioned exports
remain the independent module-policy oracle. Each fixture process enters its
own temporary root after loading its libraries; host /etc is never modified.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import subprocess


# name, source rule, first module status, expected provider, module call counts
MODULE_CASES = (
    ('default-success', 'default', 'success', 1, (1, 0)),
    ('default-fallback', 'default', 'notfound', 2, (1, 1)),
    ('success', 'rpcid_first rpcid_second', 'success', 1, (1, 0)),
    ('notfound-continue', 'rpcid_first rpcid_second', 'notfound', 2, (1, 1)),
    ('notfound-return', 'rpcid_first [NOTFOUND=return] rpcid_second', 'notfound', 0, (1, 0)),
    ('unavail-return', 'rpcid_first [UNAVAIL=return] rpcid_second', 'unavail', 0, (1, 0)),
    ('unavail-continue', 'rpcid_first [UNAVAIL=continue] rpcid_second', 'unavail', 2, (1, 1)),
    ('tryagain-return', 'rpcid_first [TRYAGAIN=return] rpcid_second', 'tryagain', 0, (1, 0)),
    ('tryagain-continue', 'rpcid_first [TRYAGAIN=continue] rpcid_second', 'tryagain', 2, (1, 1)),
    ('success-continue', 'rpcid_first [SUCCESS=continue] rpcid_second', 'success', 2, (1, 1)),
    ('negated-return', 'rpcid_first [!SUCCESS=return] rpcid_second', 'tryagain', 0, (1, 0)),
)


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def prepare_root(path, sources):
    etc = path / 'etc'
    etc.mkdir(parents=True, exist_ok=True)
    (etc / 'nsswitch.conf').write_text(
        '# built-in publickey default\n' if sources == 'default' else f'publickey: {sources}\n')
    groups = ','.join(str(group) for group in range(1, 41))
    (etc / 'netid').write_text(
        '# Network identities map to independent local credentials.\n'
        'unix.555@franken.invalid 1000:42,17,88 # primary gid is not a supplement\n'
        'unix.77@franken.invalid 2000:43\n'
        'unix.41@franken.invalid 0:7,9\n'
        'unix.4294967295@franken.invalid 4294967295:4294967295,4294967295\n'
        f'unix.40@franken.invalid 3000:44,{groups}\n'
        'unix.gateway@franken.invalid 0:node.local\n'
        'unix.overflow@franken.invalid 4294967296:42\n'
        'unix.negative@franken.invalid -1:42\n'
        'unix.badgroup@franken.invalid 1000:42,bad\n')
    (etc / 'publickey').write_text(
        '# Classical public key followed by encrypted secret material.\n'
        'unix.555@franken.invalid 0123456789abcdef0123456789ABCDEF0123456789abcdef:' + '1' * 64 + '\n'
        'nobody ABCDEF0123456789abcdef0123456789ABCDEF0123456789:' + '2' * 64 + '\n'
        'malformed ' + 'z' * 48 + ':' + '3' * 64 + '\n')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('library', nargs='?', type=Path)
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--host-only', action='store_true', help='record independent oracles without claiming candidate coverage')
    args = parser.parse_args()
    if not args.host_only and args.library is None:
        parser.error('a candidate library is required unless --host-only is explicit')
    if os.geteuid() != 0:
        parser.error('isolated chroot fixtures require root; run this test with sudo')
    library = args.library.resolve(strict=True) if args.library else None
    source_root = Path(__file__).resolve().parents[1]
    fixture = source_root / 'tests/integration/fixture_rpc_identity.c'
    module = source_root / 'tests/integration/fixture_rpc_identity_module.c'
    out = args.output.resolve()
    out.mkdir(parents=True, exist_ok=True)
    binaries = {}
    for language, compiler, standard in [('c', 'cc', 'c11'), ('cpp', 'c++', 'c++17')]:
        binary = out / f'fixture-{language}'
        subprocess.run([compiler, '-x', 'c' if language == 'c' else 'c++', f'-std={standard}',
                        '-O2', '-Wall', '-Wextra', '-Werror', str(fixture), '-ldl', '-o', str(binary)], check=True)
        binaries[language] = binary
    for name, source_id in [('rpcid_first', 1), ('rpcid_second', 2), ('nis', 1), ('nisplus', 2)]:
        subprocess.run(['cc', '-std=c11', '-shared', '-fPIC', '-O2', '-Wall', '-Wextra', '-Werror',
                        f'-DMODULE={name}', f'-DSOURCE_ID={source_id}', f'-Wl,-soname,libnss_{name}.so.2',
                        str(module), '-o', str(out / f'libnss_{name}.so.2')], check=True)
    clean = {key: value for key, value in os.environ.items()
             if key != 'LD_PRELOAD' and not key.startswith(('FRANKENLIBC_', 'RPC_IDENTITY_'))}
    report = dict(host_only=args.host_only, library_sha256=digest(library) if library else None,
                  fixture_sha256=digest(fixture), module_sha256=digest(module),
                  runner_sha256=digest(Path(__file__)), host_rows=0, candidate_rows=0,
                  provider_negative_controls=0, cases=[])

    def run(binary, provider, label, mode, sources='files', expected=0,
            status='success', runtime=None, extra=None, rows=0, calls=None, negative=False):
        root = out / ('root-' + label)
        prepare_root(root, sources)
        env = dict(clean, RPC_IDENTITY_FIRST_STATUS=status, RPC_IDENTITY_SECOND_STATUS='success')
        if runtime:
            env.update(FRANKENLIBC_MODE=runtime, FRANKENLIBC_THREAD_NATIVE='0')
        if extra:
            env.update(extra)
        completed = subprocess.run([str(binary), provider, str(library or '-'), str(root), mode,
                                    str(out), sources, str(expected)], env=env,
                                   capture_output=True, text=True, timeout=15)
        (out / (label + '.stdout')).write_text(completed.stdout)
        (out / (label + '.stderr')).write_text(completed.stderr)
        if negative:
            if completed.returncode != 113 or 'WRONG RPC IDENTITY PROVIDER' not in completed.stderr:
                raise RuntimeError(f'{label}: provider control did not fail closed: {completed.returncode} {completed.stderr}')
            report['provider_negative_controls'] += 1
            return completed.stdout
        if completed.returncode != 0:
            raise RuntimeError(f'{label}: exit {completed.returncode}\n{completed.stderr}')
        if completed.stdout.splitlines()[-1:] != [f'ROWS {rows}']:
            raise RuntimeError(f'{label}: nonzero executed-row contract missing')
        if calls is not None:
            first, second = calls
            if f'calls {first} {second} {first} {second}\n' not in completed.stdout:
                raise RuntimeError(f'{label}: wrong NSS dispatch order/count')
        counter = 'candidate_rows' if provider == 'candidate' else 'host_rows'
        report[counter] += rows
        report['cases'].append(dict(label=label, provider=provider, runtime=runtime, rows=rows,
                                    stdout_sha256=hashlib.sha256(completed.stdout.encode()).hexdigest()))
        return completed.stdout

    for language, binary in binaries.items():
        oracle_files = run(binary, 'tirpc', language + '-host-files', 'files', rows=15)
        oracles = {}
        for name, sources, status, selected, calls in MODULE_CASES:
            oracles[name] = run(binary, 'glibc', f'{language}-host-{name}', 'module',
                                sources, selected, status, rows=2, calls=calls)
        if args.host_only:
            continue
        for runtime in ('strict', 'hardened'):
            prefix = f'{language}-{runtime}'
            actual = run(binary, 'candidate', prefix + '-files', 'files', runtime=runtime, rows=15)
            if actual != oracle_files:
                raise RuntimeError(f'{prefix}: native files output differs from independent libtirpc oracle')
            for name, sources, status, selected, calls in MODULE_CASES:
                actual = run(binary, 'candidate', f'{prefix}-{name}', 'module', sources,
                             selected, status, runtime, rows=2, calls=calls)
                if actual != oracles[name]:
                    raise RuntimeError(f'{prefix}-{name}: module dispatch/output differs from GNU oracle')
            run(binary, 'candidate', prefix + '-native-failures', 'native', runtime=runtime, rows=7)
            run(binary, 'candidate', prefix + '-bounds', 'bounds', runtime=runtime, rows=5)
            for bad, mode in [('negative-count', 'module-bad-count'), ('oversize-count', 'module-bad-count'),
                              ('unterminated-key', 'module-bad-key'), ('nonhex-key', 'module-bad-key')]:
                run(binary, 'candidate', prefix + '-' + bad, mode,
                    'rpcid_first [UNAVAIL=return] rpcid_second', runtime=runtime,
                    extra={'RPC_IDENTITY_BAD_RESULT': bad}, rows=1)
            run(binary, 'candidate', prefix + '-sixth-argument', 'module',
                'rpcid_first rpcid_second', 1, runtime=runtime,
                extra={'RPC_IDENTITY_CHECK_USER_ERRNO': '1'}, rows=2, calls=(1, 0))
            # GNU 2.36's legacy compatibility entry point crashes on an empty
            # publickey source list. Native policy must safely report no match.
            run(binary, 'candidate', prefix + '-empty', 'module', '', 0,
                runtime=runtime, rows=2, calls=(0, 0))
            for name in ('netname2user', 'netname2host', 'getpublickey'):
                run(binary, 'candidate', prefix + '-wrong-' + name, 'files', runtime=runtime,
                    extra={'RPC_IDENTITY_FORCE_HOST': name}, negative=True)
    assert report['host_rows'] == 2 * (15 + 2 * len(MODULE_CASES))
    if not args.host_only:
        assert report['candidate_rows'] == 4 * (15 + 2 * len(MODULE_CASES) + 7 + 5 + 4 + 2 + 2)
        assert report['provider_negative_controls'] == 12
    (out / 'report.json').write_text(json.dumps(report, indent=2) + '\n')
    print(json.dumps({key: report[key] for key in
                      ('host_only', 'host_rows', 'candidate_rows', 'provider_negative_controls')}))


if __name__ == '__main__':
    main()
