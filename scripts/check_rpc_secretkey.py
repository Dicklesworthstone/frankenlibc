#!/usr/bin/env python3
"""Check native getsecretkey files and the public four-argument GNU NSS ABI.

GNU's versioned getsecretkey is the module/status oracle. Independent GNU
xencrypt outputs supply files ciphertext; no host files backend is required.
Every worker enters a private temporary root after loading its libraries.
The candidate symbol's owning DSO is checked before any candidate assertion.
"""
import argparse
import ctypes as C
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys


NAME = b'unix.7@franken.invalid'
KEY = b'0123456789abcdef0123456789abcdef0123456789abcdef'
PASSWORD = b'password-plus-module-tail'
SENTINEL = b'\xa5' * 49
MODULE_CASES = (
    ('default', None, 'success', False, 1, (1, 0)),
    ('default-fallback', None, 'notfound', False, 2, (1, 1)),
    ('success', 'rpcsecret_first rpcsecret_second', 'success', False, 1, (1, 0)),
    ('notfound-continue', 'rpcsecret_first rpcsecret_second', 'notfound', False, 2, (1, 1)),
    ('notfound-return', 'rpcsecret_first [NOTFOUND=return] rpcsecret_second', 'notfound', False, 0, (1, 0)),
    ('unavail-return', 'rpcsecret_first [UNAVAIL=return] rpcsecret_second', 'unavail', False, 0, (1, 0)),
    ('unavail-continue', 'rpcsecret_first [UNAVAIL=continue] rpcsecret_second', 'unavail', False, 2, (1, 1)),
    ('tryagain-return', 'rpcsecret_first [TRYAGAIN=return] rpcsecret_second', 'tryagain', False, 0, (1, 0)),
    ('tryagain-continue', 'rpcsecret_first [TRYAGAIN=continue] rpcsecret_second', 'tryagain', False, 2, (1, 1)),
    ('success-continue', 'rpcsecret_first [SUCCESS=continue] rpcsecret_second', 'success', False, 2, (1, 1)),
    ('negated-return', 'rpcsecret_first [!SUCCESS=return] rpcsecret_second', 'tryagain', False, 0, (1, 0)),
    ('empty-success', 'rpcsecret_first rpcsecret_second', 'success', True, -1, (1, 0)),
    ('empty-continue', 'rpcsecret_first [SUCCESS=continue] rpcsecret_second', 'success', True, 2, (1, 1)),
)


def versioned(library, name):
    loader = C.CDLL('libc.so.6')
    lookup = loader.dlvsym
    lookup.argtypes = [C.c_void_p, C.c_char_p, C.c_char_p]
    lookup.restype = C.c_void_p
    pointer = lookup(library._handle, name.encode(), b'GLIBC_2.2.5')
    if not pointer:
        raise RuntimeError(f'missing GNU oracle {name}@GLIBC_2.2.5')
    return pointer


def verify_provider(pointer, path):
    class DlInfo(C.Structure):
        _fields_ = [('name', C.c_char_p), ('base', C.c_void_p),
                    ('symbol', C.c_char_p), ('address', C.c_void_p)]
    loader = C.CDLL('libc.so.6')
    lookup = loader.dladdr
    lookup.argtypes = [C.c_void_p, C.POINTER(DlInfo)]
    lookup.restype = C.c_int
    info = DlInfo()
    if not lookup(pointer, C.byref(info)) or not info.name or not os.path.samefile(path, info.name):
        raise RuntimeError('WRONG SECRETKEY PROVIDER')


def worker(spec):
    libc = C.CDLL('libc.so.6')
    provider = libc if spec['provider'] == 'glibc' else C.CDLL(spec['library'])
    if spec['provider'] == 'glibc' or spec.get('force_host'):
        pointer = versioned(libc, 'getsecretkey')
    else:
        pointer = C.cast(provider.getsecretkey, C.c_void_p).value
    if spec['provider'] != 'glibc':
        verify_provider(pointer, spec['library'])
    call = C.CFUNCTYPE(C.c_int, C.c_void_p, C.c_void_p, C.c_void_p)(pointer)
    error_slot = provider.__errno_location
    error_slot.restype = C.POINTER(C.c_int)
    error = error_slot()
    counts = []
    if spec['mode'] == 'module':
        for name in (('nis', 'nisplus') if spec['sources'] is None else
                     ('rpcsecret_first', 'rpcsecret_second')):
            module = C.CDLL(str(Path(spec['module_dir']) / f'libnss_{name}.so.2'))
            count = module.rpc_secretkey_calls
            count.restype = C.c_uint
            counts.append(count)
        if spec['provider'] == 'glibc' and spec['sources'] is not None:
            configure = libc.__nss_configure_lookup
            configure.argtypes = [C.c_char_p, C.c_char_p]
            assert configure(b'publickey', spec['sources'].encode()) == 0
    # Resolve optional diagnostics and mapping entry points before chroot.
    extent = getattr(provider, 'secretkey_diagnostic_extent', None)
    if extent:
        extent.argtypes = [C.c_size_t, C.c_size_t]
    libc.mmap.argtypes = [C.c_void_p, C.c_size_t, C.c_int, C.c_int, C.c_int, C.c_long]
    libc.mmap.restype = C.c_void_p
    libc.mprotect.argtypes = [C.c_void_p, C.c_size_t, C.c_int]
    libc.munmap.argtypes = [C.c_void_p, C.c_size_t]
    page = os.sysconf('SC_PAGESIZE')
    os.chroot(spec['root'])
    os.chdir('/')
    rows = []

    def check(name, password, expected, label):
        out = C.create_string_buffer(b'\xa5' * 51, 51)
        pw = C.create_string_buffer(password)
        error[0] = 37
        result = call(name, C.addressof(out) + 1, pw)
        value = out.raw[1:50]
        assert out.raw[:1] == out.raw[50:] == b'\xa5', label
        assert pw.value == password, (label, 'caller password changed')
        if expected is None:
            assert result == 0 and value == SENTINEL, (label, result, value.hex())
        elif expected == b'':
            assert result == 1 and value == b'\0' + SENTINEL[1:], (label, result, value.hex())
        else:
            assert result == 1 and value == expected + b'\0', (label, result, value.hex())
        rows.append(dict(label=label, result=result, output=value.hex(), errno=error[0]))

    if spec['mode'] == 'module':
        selected = spec['selected']
        expected = {0: None, -1: b'', 1: b'a' * 48, 2: b'B' * 48}[selected]
        check(NAME, PASSWORD, expected, spec['label'])
        observed = [count() for count in counts]
        assert observed == spec['calls'], (observed, spec['calls'])
        return dict(rows=rows, calls=observed)

    for name, password, expected in (
        (NAME, b'password', KEY),
        (NAME, b'password-tail', KEY),
        (NAME, b'incorrect', b''),
        (b'empty', b'', KEY),
        (b'uppercase', b'password', KEY),
        (b'bad-checksum', b'password', b''),
        (b'missing', b'password', None),
        (b'unix.7@Franken.invalid', b'password', None),
        (b'unix.7@other', b'password', None),
        (b'short', b'password', None),
        (b'long', b'password', None),
        (b'nonhex', b'password', None),
        (b'bad-public', b'password', None),
        (b'duplicate', b'password', None),
        (b'last', b'password', KEY),
    ):
        check(name, password, expected, name.decode() + ':' + password.decode())

    # Invalid caller memory must fail through the checked copier, without a
    # process fault; a terminator or exact output ending at a guard page is valid.
    base = libc.mmap(None, 2 * page, 3, 0x22, -1, 0)
    assert base not in (None, C.c_void_p(-1).value)
    assert libc.mprotect(base + page, page, 0) == 0
    out = C.create_string_buffer(b'\xa5' * 49, 49)
    try:
        for label, name, password, target in (
            ('null-name', None, b'password', out),
            ('null-password', NAME, None, out),
            ('null-output', NAME, b'password', None),
            ('guard-output', NAME, b'password', base + page),
            ('long-name', b'n' * 256, b'password', out),
        ):
            assert call(name, target, password) == 0, label
            assert out.raw == SENTINEL, label
            rows.append(dict(label=label, result=0))
        target = base + page - 49
        assert call(NAME, target, b'password') == 1
        assert C.string_at(target, 49) == KEY + b'\0'
        rows.append(dict(label='exact-guard-output', result=1))
        C.memmove(base + page - 1, b'x', 1)
        assert call(base + page - 1, out, b'password') == 0
        assert call(NAME, out, base + page - 1) == 0
        assert out.raw == SENTINEL
        rows.extend([dict(label='guard-name', result=0), dict(label='guard-password', result=0)])
        C.memmove(base + page - 3, b'pw\0', 3)
        assert call(NAME, out, base + page - 3) == 1
        assert out.raw == b'\0' + SENTINEL[1:]
        rows.append(dict(label='terminated-guard-password', result=1))
        if extent:
            tracked = C.create_string_buffer(b'\xa5' * 48, 48)
            extent(C.addressof(tracked), 48)
            assert call(NAME, tracked, b'password') == 0
            assert tracked.raw == b'\xa5' * 48
            extent(0, 0)
        else:
            allocate, release = provider.malloc, provider.free
            allocate.argtypes = [C.c_size_t]
            allocate.restype = C.c_void_p
            release.argtypes = [C.c_void_p]
            tracked = allocate(48)
            assert tracked
            try:
                C.memset(tracked, 0xa5, 48)
                assert call(NAME, tracked, b'password') == 0
                assert C.string_at(tracked, 48) == b'\xa5' * 48
            finally:
                release(tracked)
        rows.append(dict(label='tracked-short-output', result=0))
    finally:
        assert libc.munmap(base, 2 * page) == 0
    return dict(rows=rows)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('library', type=Path, nargs='?')
    parser.add_argument('--output', type=Path)
    parser.add_argument('--diagnostic', action='store_true', help='explicitly label an isolated boundary build')
    parser.add_argument('--worker')
    args = parser.parse_args()
    if args.worker:
        print(json.dumps(worker(json.loads(args.worker))))
        return
    if args.library is None or args.output is None:
        parser.error('library and --output are required')
    if os.geteuid() != 0:
        parser.error('private chroot fixtures require root')
    library = args.library.resolve(strict=True)
    out = args.output.resolve()
    out.mkdir(parents=True, exist_ok=True)
    module_source = Path(__file__).resolve().parents[1] / 'tests/integration/fixture_rpc_secretkey_module.c'
    for name, source_id in [('rpcsecret_first', 1), ('rpcsecret_second', 2), ('nis', 1), ('nisplus', 2)]:
        subprocess.run(['cc', '-std=c11', '-shared', '-fPIC', '-O2', '-Wall', '-Wextra', '-Werror',
                        f'-DMODULE={name}', f'-DSOURCE_ID={source_id}', f'-Wl,-soname,libnss_{name}.so.2',
                        str(module_source), '-o', str(out / f'libnss_{name}.so.2')], check=True)
    libc = C.CDLL('libc.so.6')
    encrypt = C.CFUNCTYPE(C.c_int, C.c_void_p, C.c_void_p)(versioned(libc, 'xencrypt'))

    def ciphertext(password, checksum=KEY[:16]):
        value = C.create_string_buffer(KEY + checksum)
        assert encrypt(value, C.create_string_buffer(password)) == 1
        return value.value.decode()

    encrypted = ciphertext(b'password')
    public = KEY.decode()
    image = ('# independent GNU ciphertexts\n'
             f'{NAME.decode()} {public}:{encrypted} # valid\n'
             f'empty {public}:{ciphertext(b"")}\n'
             f'uppercase {public}:{encrypted.upper()}\n'
             f'bad-checksum {public}:{ciphertext(b"password", b"0" * 16)}\n'
             f'short {public}:{encrypted[:-1]}\n'
             f'long {public}:{encrypted}00\n'
             f'nonhex {public}:z{encrypted[1:]}\n'
             f'bad-public z{public[1:]}:{encrypted}\n'
             f'duplicate broken\nduplicate {public}:{encrypted}\n'
             f'last {public}:{encrypted}')
    clean = {key: value for key, value in os.environ.items()
             if key != 'LD_PRELOAD' and not key.startswith(('FRANKENLIBC_', 'RPC_SECRET_'))}
    report = dict(diagnostic=args.diagnostic, library_sha256=hashlib.sha256(library.read_bytes()).hexdigest(),
                  host_rows=0, candidate_rows=0, provider_negative_controls=0, cases=[])

    def run(provider, label, mode, sources='files', status='success', empty=False,
            selected=0, calls=(0, 0), bad=None, runtime='strict', force_host=False):
        root = out / ('root-' + label)
        (root / 'etc').mkdir(parents=True, exist_ok=True)
        (root / 'etc/nsswitch.conf').write_text('# default\n' if sources is None else f'publickey: {sources}\n')
        (root / 'etc/publickey').write_text(image)
        spec = dict(provider=provider, library=str(library), root=str(root), module_dir=str(out),
                    mode=mode, sources=sources, selected=selected, calls=list(calls), label=label,
                    force_host=force_host)
        env = dict(clean, RPC_SECRET_FIRST_STATUS=status, RPC_SECRET_SECOND_STATUS='success',
                   FRANKENLIBC_MODE=runtime, FRANKENLIBC_THREAD_NATIVE='0')
        if empty:
            env['RPC_SECRET_EMPTY_FIRST'] = '1'
        if bad:
            env['RPC_SECRET_BAD_RESULT'] = bad
        process = subprocess.run([sys.executable, str(Path(__file__).resolve()), '--worker', json.dumps(spec)],
                                 capture_output=True, text=True, env=env, timeout=30)
        (out / (label + '.stdout')).write_text(process.stdout)
        (out / (label + '.stderr')).write_text(process.stderr)
        if force_host:
            assert process.returncode != 0 and 'WRONG SECRETKEY PROVIDER' in process.stderr
            report['provider_negative_controls'] += 1
            return None
        if process.returncode:
            raise RuntimeError(f'{label}: exit {process.returncode}\n{process.stderr}')
        result = json.loads(process.stdout)
        assert result['rows']
        report['host_rows' if provider == 'glibc' else 'candidate_rows'] += len(result['rows'])
        report['cases'].append(dict(label=label, rows=len(result['rows'])))
        return result

    for label, sources, status, empty, selected, calls in MODULE_CASES:
        oracle = run('glibc', 'host-' + label, 'module', sources, status, empty, selected, calls)
        for runtime in ('strict', 'hardened'):
            actual = run('candidate', runtime + '-' + label, 'module', sources, status, empty, selected, calls,
                         runtime=runtime)
            # Labels identify distinct processes; the observable ABI row matches.
            actual['rows'][0]['label'] = oracle['rows'][0]['label']
            assert actual == oracle, label
    for runtime in ('strict', 'hardened'):
        run('candidate', runtime + '-files', 'files', runtime=runtime)
        for bad in ('unterminated', 'nonhex', 'short'):
            run('candidate', runtime + '-' + bad, 'module',
                'rpcsecret_first [UNAVAIL=return] rpcsecret_second',
                selected=0, calls=(1, 0), bad=bad, runtime=runtime)
        run('candidate', runtime + '-failed-write', 'module',
            'rpcsecret_first [NOTFOUND=return] rpcsecret_second', status='notfound',
            selected=0, calls=(1, 0), bad='failed-write', runtime=runtime)
        run('candidate', runtime + '-private-password', 'module',
            'rpcsecret_first rpcsecret_second', selected=1, calls=(1, 0),
            bad='mutate-password', runtime=runtime)
        run('candidate', runtime + '-empty-sources', 'module', '', selected=0, calls=(0, 0), runtime=runtime)
        run('candidate', runtime + '-wrong-provider', 'files', runtime=runtime, force_host=True)
    assert report['host_rows'] == len(MODULE_CASES)
    assert report['candidate_rows'] == 2 * (len(MODULE_CASES) + 25 + 6)
    assert report['provider_negative_controls'] == 2
    (out / 'report.json').write_text(json.dumps(report, indent=2) + '\n')
    print(json.dumps({key: report[key] for key in
                      ('diagnostic', 'host_rows', 'candidate_rows', 'provider_negative_controls')}))


if __name__ == '__main__':
    main()
