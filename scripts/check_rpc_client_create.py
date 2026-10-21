#!/usr/bin/env python3
"""Exercise the release RPC clients against bounded loopback wire peers.

The portmapper is exclusively bound, never replaced or reconfigured. Its
requests and the UDP/TCP service packets are checked independently of the
candidate serializer. A busy port 111 is a failure, never a skipped success.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import selectors
import socket
import struct
import subprocess
import threading

HOST = ('unknown-protocol', 'unregistered', 'portmapper-error', 'udp', 'tcp',
        'udp-name', 'tcp-name', 'udp-repeat', 'tcp-repeat', 'callrpc-udp',
        'callrpc-name', 'callrpc-repeat', 'callrpc-unregistered',
        'callrpc-encode-error', 'callrpc-decode-error', 'callrpc-procedure-error',
        'callrpc-high-ids', 'callrpc-high-wire-ids', 'callrpc-version-overflow',
        'callrpc-procedure-overflow')
OWNED = ('callrpc-reentrant', 'callrpc-null-host', 'callrpc-null-encode',
         'callrpc-null-decode')
UNWIND = ('callrpc-encode-throw', 'callrpc-decode-throw', 'callrpc-encode-exit',
          'callrpc-decode-exit', 'client-encode-throw', 'client-decode-throw',
          'client-free-throw', 'client-marshal-throw', 'client-validate-throw',
          'client-refresh-throw')
PROGRAM = 0x34567001
DIAGNOSTICS = ('diag-status', 'diag-text', 'diag-errno', 'diag-auth', 'diag-print',
               'diag-create', 'diag-prefix', 'diag-static', 'diag-thread',
               'diag-reentry', 'diag-native-udp', 'diag-native-tcp')
DIAGNOSTIC_UNWIND = ('diag-geterr-throw', 'diag-geterr-exit', 'diag-print-throw', 'diag-print-exit')


def words(values):
    return struct.pack('!' + 'I' * len(values), *values)


class Peers:
    def __init__(self):
        self.selector = selectors.DefaultSelector()
        self.sockets = []
        self.errors = []
        self.counts = dict(portmap=0, portmap_tcp=0, udp=0, tcp=0)
        self.stop = threading.Event()
        try:
            self.mapper = self.bind(socket.SOCK_DGRAM, 111, 'mapper')
            self.mapper_tcp = self.bind(socket.SOCK_STREAM, 111, 'mapper-listener')
            self.mapper_tcp.listen()
            self.udp = self.bind(socket.SOCK_DGRAM, 0, 'udp')
            self.tcp = self.bind(socket.SOCK_STREAM, 0, 'listener')
            self.tcp.listen()
        except BaseException:
            self.close()
            raise
        self.worker = threading.Thread(target=self.serve)
        self.worker.start()

    def bind(self, kind, port, label):
        sock = socket.socket(socket.AF_INET, kind)
        self.sockets.append(sock)
        sock.bind(('127.0.0.1', port))
        sock.setblocking(False)
        self.selector.register(sock, selectors.EVENT_READ, label)
        return sock

    def reply(self, packet, mapper=False):
        if len(packet) < 40 or len(packet) % 4:
            raise ValueError(f'invalid RPC request length {len(packet)}')
        data = list(struct.unpack('!' + 'I' * (len(packet) // 4), packet))
        xid, direction, version, program, revision, procedure = data[:6]
        if (direction, version, data[6:10]) != (0, 2, [0, 0, 0, 0]):
            raise ValueError(f'invalid RPC request envelope {data}')
        prefix = [xid, 1, 0, 0, 0]
        if mapper:
            if (program, revision, procedure, len(data)) != (100000, 2, 3, 14):
                raise ValueError(f'invalid portmapper request {data}')
            target, target_version, protocol, port = data[10:]
            if protocol not in (6, 17) or port != 0:
                raise ValueError(f'invalid mapping {data[10:]}')
            self.counts['portmap'] += 1
            if target == PROGRAM + 2:
                return words(prefix + [1])  # PROG_UNAVAIL at the mapper.
            if target == PROGRAM + 1:
                return words(prefix + [0, 0])
            expected_version = 0xfffffffe if target == 0xf4567001 else 1
            if target not in (PROGRAM, 0xf4567001) or target_version != expected_version:
                raise ValueError(f'unexpected program/version {data[10:]}')
            service = self.udp if protocol == 17 else self.tcp
            return words(prefix + [0, service.getsockname()[1]])
        expected = (0xf4567001, 0xfffffffe, 0x80000007) if program == 0xf4567001 else (PROGRAM, 1, 7)
        if procedure == 9 and (program, revision) == (PROGRAM, 1):
            return words([xid, 1, 1, 1, 2])  # AUTH_REJECTEDCRED, invokes refresh.
        if procedure == 10 and (program, revision) == (PROGRAM, 1):
            return words(prefix + [2, 1, 5])  # Program version range.
        if procedure == 11 and (program, revision) == (PROGRAM, 1):
            return words([xid, 1, 1, 0, 2, 2])  # RPC version range.
        if procedure == 8 and (program, revision) == (PROGRAM, 1):
            return words(prefix + [3])  # PROC_UNAVAIL.
        if (program, revision, procedure) != expected or len(data) != 11:
            raise ValueError(f'unexpected service call {data}')
        return words(prefix + [0, data[10] ^ 0x55aa55aa])

    def serve(self):
        try:
            while not self.stop.is_set():
                for key, _ in self.selector.select(0.1):
                    sock, label = key.fileobj, key.data
                    if label in ('listener', 'mapper-listener'):
                        connection, _ = sock.accept()
                        connection.setblocking(False)
                        self.sockets.append(connection)
                        self.selector.register(connection, selectors.EVENT_READ,
                                               dict(buffer=bytearray(), mapper=label == 'mapper-listener'))
                    elif isinstance(label, dict):
                        buffer = label['buffer']
                        packet = sock.recv(65536)
                        if not packet:
                            self.selector.unregister(sock)
                            sock.close()
                            continue
                        buffer.extend(packet)
                        while len(buffer) >= 4:
                            marker = struct.unpack('!I', buffer[:4])[0]
                            length = marker & 0x7fffffff
                            if not marker & 0x80000000 or length > 65536:
                                raise ValueError('unexpected TCP record framing')
                            if len(buffer) < length + 4:
                                break
                            response = self.reply(bytes(buffer[4:length + 4]), label['mapper'])
                            del buffer[:length + 4]
                            # The bounded replies fit one tiny loopback write.
                            framed = words([0x80000000 | len(response)]) + response
                            self.counts['portmap_tcp' if label['mapper'] else 'tcp'] += 1
                            if sock.send(framed) != len(framed):
                                raise ValueError('short TCP peer reply')
                    else:
                        packet, peer = sock.recvfrom(65536)
                        response = self.reply(packet, label == 'mapper')
                        sock.sendto(response, peer)
                        if label == 'udp':
                            self.counts['udp'] += 1
        except BaseException as error:
            self.errors.append(repr(error))

    def close(self):
        self.stop.set()
        if hasattr(self, 'worker'):
            self.worker.join(timeout=3)
            if self.worker.is_alive():
                self.errors.append('wire peer did not stop')
        self.selector.close()
        for sock in self.sockets:
            sock.close()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('library', type=Path)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    library = args.library.resolve(strict=True)
    root = Path(__file__).resolve().parents[1]
    out = args.output.resolve()
    out.mkdir(parents=True, exist_ok=True)
    fixture = root / 'tests/integration/fixture_rpc_client_create.c'
    binaries = {False: out / 'fixture', True: out / 'fixture-unwind'}
    for cpp, binary in binaries.items():
        subprocess.run(['c++' if cpp else 'cc', '-x', 'c++' if cpp else 'c',
                        '-std=c++17' if cpp else '-std=c11', '-O2', '-Wall',
                        '-Wextra', '-Werror', str(fixture), '-ldl', '-pthread',
                        '-o', str(binary)], check=True)
    clean = {k: v for k, v in os.environ.items()
             if k != 'LD_PRELOAD' and not k.startswith('FRANKENLIBC_')
             and k != 'RPC_TEST_FORCE_HOST'}
    report = dict(library_sha256=hashlib.sha256(library.read_bytes()).hexdigest(),
                  fixture_sha256=hashlib.sha256(fixture.read_bytes()).hexdigest(),
                  host=[], candidate=[], negative=[])
    peers = Peers()

    def run(provider, case, env, negative=False, cpp=False):
        before = peers.counts.copy()
        try:
            process = subprocess.run([str(binaries[cpp]), case], env=env,
                                     capture_output=True, timeout=12)
            code, stdout, stderr = process.returncode, process.stdout, process.stderr
        except subprocess.TimeoutExpired as error:
            code, stdout, stderr = 124, error.stdout or b'', error.stderr or b''
        expected = (113, b'', b'WRONG RPC PROVIDER\n') if negative else (0, f'PASS {case}\n'.encode(), b'')
        passed = (code, stdout, stderr) == expected
        wire = {key: value - before[key] for key, value in peers.counts.items()}
        if not negative and case.startswith('tcp'):
            passed = passed and wire['portmap_tcp'] > 0 and wire['tcp'] > 0
        if not negative and case in ('callrpc-high-ids', 'callrpc-version-overflow'):
            passed = passed and wire['portmap'] == 0
        stem = f'{provider}-{case}'
        (out / f'{stem}.out').write_bytes(stdout)
        (out / f'{stem}.err').write_bytes(stderr)
        bucket = 'negative' if negative else 'host' if provider == 'host' else 'candidate'
        report[bucket].append(dict(provider=provider, case=case, passed=passed,
                                   returncode=code, wire_exchanges=wire))
        (out / 'report.json').write_text(json.dumps(report, indent=2) + '\n')
        print(f'{"PASS" if passed else "FAIL"} {provider}/{case}: rc={code}', flush=True)

    try:
        for case in HOST + DIAGNOSTICS:
            run('host', case, clean)
        for case in DIAGNOSTIC_UNWIND:
            run('host', case, clean, cpp=True)
        run('wrong-provider-host', 'unknown-protocol',
            dict(clean, FRANKENLIBC_TEST_LIBRARY=str(library)), True)
        run('wrong-provider-forced', 'unknown-protocol',
            dict(clean, LD_PRELOAD=str(library), FRANKENLIBC_TEST_LIBRARY=str(library),
                 RPC_TEST_FORCE_HOST='1'), True)
        for mode in ('strict', 'hardened'):
            env = dict(clean, LD_PRELOAD=str(library), FRANKENLIBC_TEST_LIBRARY=str(library),
                       FRANKENLIBC_MODE=mode, FRANKENLIBC_THREAD_NATIVE='0')
            for case in HOST + DIAGNOSTICS + OWNED:
                run(mode, case, env)
            for case in UNWIND + DIAGNOSTIC_UNWIND:
                run(mode, case, env, cpp=True)
    finally:
        peers.close()
        report.update(wire_errors=peers.errors, wire_exchanges=peers.counts)
        report['library_sha256_after'] = hashlib.sha256(library.read_bytes()).hexdigest()
        (out / 'report.json').write_text(json.dumps(report, indent=2) + '\n')
    failed = [row for bucket in ('host', 'candidate', 'negative') for row in report[bucket]
              if not row['passed']]
    print(json.dumps(dict(failed=len(failed), wire_errors=peers.errors,
                          exchanges=peers.counts)))
    return int(bool(failed or peers.errors or report['library_sha256'] != report['library_sha256_after']))


if __name__ == '__main__':
    raise SystemExit(main())
