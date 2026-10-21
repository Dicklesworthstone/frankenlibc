#!/usr/bin/env python3
"""Execute real glibc-shaped RPC services in isolated UDP/TCP processes."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import subprocess
import socket
import struct
import threading

HOST = ['transport', 'dispatch', 'fdset', 'poll', 'mask', 'string', 'errors',
        'auth', 'lifecycle', 'borrowed', 'run-exit', 'authenticate-none',
        'authenticate-sys', 'authenticate-reject', 'authenticate-malformed',
        'auth-none-opaque', 'auth-verifier', 'auth-client', 'register-basic',
        'register-multi', 'register-string', 'register-decoder-error', 'register-void',
        'register-no-reply', 'register-zero', 'register-denied', 'register-reentry',
        'register-unknown', 'register-encode-error']
HOST += ['tcp-listener', 'tcp-supplied', 'tcp-fd', 'tcp-unix-fd', 'tcp-direct',
         'tcp-fragments', 'tcp-pipeline', 'tcp-string', 'tcp-large', 'tcp-errors',
         'tcp-auth', 'tcp-run', 'tcp-client', 'tcp-child', 'tcp-poll', 'tcp-fdset',
         'tcp-publish', 'tcp-empty-final']
# These are independently specified bounds/lifetime contracts, not host-parity
# claims: some historical glibc servers accept truncated UDP prefixes or keep
# their service registry in a different thread. Never label their failure green.
OWNED = ['short-args', 'destroy-dispatch', 'callback-exit', 'malformed', 'oversized',
         'auth-bounds', 'register-invalid', 'register-partial', 'register-callback-exit',
         'register-decode']
OWNED += ['tcp-invalid', 'tcp-partial', 'tcp-backpressure', 'tcp-destroy',
          'tcp-callback-exit', 'tcp-encode-failure', 'tcp-malformed', 'tcp-limit',
          'tcp-truncated', 'tcp-fragment-limit', 'tcp-fairness', 'tcp-empty-fragment',
          'tcp-rpcversion']
# glibc xdr_rec.c rejects a zero nonfinal marker. Keep that exact original
# failing host probe as an explicit native extension, rather than parity proof.


class RegistrationPeer:
    """Independent portmapper v2 peer; refuses to replace any existing listener."""
    def __init__(self, case):
        self.case = case
        self.errors = []
        self.requests = []
        self.mappings = {}
        self.stop = threading.Event()
        self.socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        try:
            self.socket.bind(('127.0.0.1', 111))
        except BaseException:
            self.socket.close()
            raise
        self.socket.settimeout(0.1)
        self.worker = threading.Thread(target=self.serve)
        self.worker.start()

    def serve(self):
        try:
            while not self.stop.is_set():
                try:
                    packet, peer = self.socket.recvfrom(4096)
                except socket.timeout:
                    continue
                if len(packet) != 56:
                    raise ValueError(f'portmapper length {len(packet)}')
                data = struct.unpack('!14I', packet)
                xid, direction, rpcvers, program, version, procedure = data[:6]
                target, revision, protocol, port = data[10:]
                if ((direction, rpcvers, program, version) != (0, 2, 100000, 2)
                        or data[6:10] != (0, 0, 0, 0)
                        or procedure not in (1, 2, 3)
                        or target not in (0x31234567, 0x31234568)
                        or revision not in (1, 2)):
                    raise ValueError(f'portmapper envelope {data}')
                self.requests.append(list(data))
                key = (target, revision)
                expected_protocol = 6 if self.case == 'tcp-publish' else 17
                if procedure == 1:
                    if protocol != expected_protocol or not 0 < port <= 65535:
                        raise ValueError(f'invalid publication {data}')
                    accepted = target != 0x31234568
                    if accepted:
                        previous = self.mappings.get(key)
                        if previous is not None and previous != port:
                            raise ValueError('publication changed without unsetting')
                        self.mappings[key] = port
                    result = int(accepted)
                elif procedure == 2:
                    if protocol != 0 or port != 0:
                        raise ValueError(f'invalid unregistration {data}')
                    self.mappings.pop(key, None)
                    result = 1
                else:
                    if protocol != expected_protocol or port != 0:
                        raise ValueError(f'invalid lookup {data}')
                    result = self.mappings.get(key, 0)
                self.socket.sendto(struct.pack('!7I', xid, 1, 0, 0, 0, 0, result), peer)
        except BaseException as error:
            self.errors.append(repr(error))

    def close(self):
        self.stop.set()
        self.worker.join(timeout=3)
        if self.worker.is_alive():
            self.errors.append('portmapper thread did not stop')
        self.socket.close()
        accepted = sum(r[5] == 1 and r[10] == 0x31234567 for r in self.requests)
        fatal = self.case in ('register-unknown', 'register-encode-error')
        expected = (1 if fatal or self.case == 'tcp-publish' else 4 if self.case == 'register-multi' else 3
                    if self.case in ('register-callback-exit', 'register-reentry') else 2)
        expected_mappings = ({(0x31234567, 1): self.requests[1][13]}
                             if fatal and len(self.requests) > 1 else {})
        if accepted != expected or self.mappings != expected_mappings:
            self.errors.append(f'publication/cleanup mismatch: accepted={accepted}, '
                               f'expected={expected}, mappings={self.mappings}')

def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('library', type=Path)
    parser.add_argument('--output', type=Path, default=Path('artifacts/rpc-svc'))
    args = parser.parse_args()
    root = Path(__file__).resolve().parents[1]
    out = args.output.resolve()
    out.mkdir(parents=True, exist_ok=False)
    library = args.library.resolve(strict=True)
    library_sha256 = hashlib.sha256(library.read_bytes()).hexdigest()
    sources = ['tests/integration/fixture_rpc_svc.c', 'scripts/check_rpc_svc.py']
    source_sha256 = {name: hashlib.sha256((root / name).read_bytes()).hexdigest()
                     for name in sources}
    fixture = out / 'fixture'
    subprocess.run(['cc', '-O2', '-Wall', '-Wextra', '-Werror',
                    str(root / 'tests/integration/fixture_rpc_svc.c'),
                    '-ldl', '-pthread', '-o', str(fixture)], check=True)
    base = {k: v for k, v in os.environ.items()
            if k not in ('LD_PRELOAD', 'FRANKENLIBC_TEST_LIBRARY', 'RPC_TRACE',
                         'FRANKENLIBC_MODE')}
    base.update(FRANKENLIBC_THREAD_NATIVE='0')
    records = []
    def execute(mode, case, env, negative=False):
        name = f'{mode}-{case}'
        peer = None
        try:
            if ((case.startswith('register-') and case not in ('register-zero', 'register-invalid'))
                    or case == 'tcp-publish'):
                peer = RegistrationPeer(case)
            p = subprocess.run([str(fixture), case], env=env, capture_output=True, timeout=12)
            code, stdout, stderr = p.returncode, p.stdout, p.stderr
        except subprocess.TimeoutExpired as e:
            code, stdout, stderr = -999, e.stdout or b'', (e.stderr or b'') + b'\nTIMEOUT\n'
        except OSError as e:
            code, stdout, stderr = -998, b'', str(e).encode()
        finally:
            if peer is not None:
                peer.close()
        expected_stderr = (b"can't reassign procedure number 0\n" if case == 'register-zero'
                           else b"couldn't register prog 824395112 vers 1\n" if case == 'register-denied'
                           else b"never registered prog 824395111\n" if case == 'register-unknown'
                           else b"trouble replying to prog 824395111\n" if case == 'register-encode-error'
                           else b'')
        fatal = case in ('register-unknown', 'register-encode-error')
        passed = (code == 2 and b'WRONG_PROVIDER' in stderr) if negative else (
            code == int(fatal) and stdout == (b'' if fatal else f'PASS {case}\n'.encode())
            and stderr == expected_stderr
            and (peer is None or not peer.errors))
        (out / f'{name}.out').write_bytes(stdout)
        (out / f'{name}.err').write_bytes(stderr)
        records.append({'mode': mode, 'case': case, 'passed': passed, 'returncode': code,
                        'negative': negative, 'host_differential': case in HOST and not negative,
                        'portmapper_requests': peer.requests if peer else [],
                        'peer_errors': peer.errors if peer else []})
        (out / 'report.json').write_text(json.dumps({
            'library_sha256': library_sha256,
            'source_sha256': source_sha256,
            'results': records}, indent=2) + '\n')
        if not passed:
            print(f'FAIL {name}: rc={code}: {stderr.decode(errors="replace")}', flush=True)
    for case in HOST:
        execute('host', case, base)
    execute('wrong-provider-host', 'dispatch', {**base, 'FRANKENLIBC_TEST_LIBRARY': str(library)}, True)
    execute('wrong-provider-candidate', 'dispatch', {**base, 'LD_PRELOAD': str(library),
            'FRANKENLIBC_TEST_LIBRARY': str(fixture)}, True)
    for mode in ('strict', 'hardened'):
        env = {**base, 'LD_PRELOAD': str(library), 'FRANKENLIBC_TEST_LIBRARY': str(library), 'FRANKENLIBC_MODE': mode}
        for case in HOST + OWNED:
            execute(mode, case, env)
    stable = (library_sha256 == hashlib.sha256(library.read_bytes()).hexdigest()
              and all(digest == hashlib.sha256((root / name).read_bytes()).hexdigest()
                      for name, digest in source_sha256.items()))
    report = {'library_sha256': library_sha256, 'source_sha256': source_sha256,
              'inputs_stable': stable, 'results': records}
    (out / 'report.json').write_text(json.dumps(report, indent=2) + '\n')
    failures = sum(not record['passed'] for record in records)
    print(f'RPC services: {len(HOST)} host, 2 negative, '
          f'{2 * (len(HOST) + len(OWNED))} candidate cases; '
          f'{failures} failures; inputs stable={stable}')
    raise SystemExit(int(bool(failures) or not stable))

if __name__ == '__main__':
    main()
