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
import sys
import time

HOST = ('unknown-protocol', 'unregistered', 'portmapper-error', 'udp', 'tcp',
        'udp-name', 'tcp-name', 'udp-repeat', 'tcp-repeat', 'callrpc-udp',
        'callrpc-name', 'callrpc-repeat', 'callrpc-unregistered',
        'callrpc-encode-error', 'callrpc-decode-error', 'callrpc-procedure-error',
        'callrpc-high-ids', 'callrpc-high-wire-ids', 'callrpc-version-overflow',
        'callrpc-procedure-overflow')
OWNED = ('callrpc-reentrant', 'callrpc-null-host', 'callrpc-null-encode',
         'callrpc-null-decode', 'diag-native-initial')
UNWIND = ('callrpc-encode-throw', 'callrpc-decode-throw', 'callrpc-encode-exit',
          'callrpc-decode-exit', 'client-encode-throw', 'client-decode-throw',
          'client-free-throw', 'client-marshal-throw', 'client-validate-throw',
          'client-refresh-throw')
PROGRAM = 0x34567001
DIAGNOSTICS = ('diag-status', 'diag-text', 'diag-errno', 'diag-auth', 'diag-print',
               'diag-create', 'diag-prefix', 'diag-static', 'diag-thread',
               'diag-reentry', 'diag-native-udp', 'diag-native-tcp')
DIAGNOSTIC_UNWIND = ('diag-geterr-throw', 'diag-geterr-exit', 'diag-print-throw', 'diag-print-exit')


NETNAME_ROWS = {'netname-user': 76, 'netname-host': 152, 'netname-default': 7}

BROADCAST = ('broadcast-udp', 'broadcast-multiple', 'broadcast-retry',
             'broadcast-stale', 'broadcast-malformed', 'broadcast-advisory-length',
             'broadcast-port-width', 'broadcast-verifier', 'broadcast-string',
             'broadcast-decode-error', 'broadcast-send-only', 'broadcast-encode-error',
             'broadcast-large-args', 'broadcast-high-ids', 'broadcast-reentry',
             'broadcast-timeout')
BROADCAST_UNWIND = ('broadcast-encode-throw', 'broadcast-decode-throw',
                    'broadcast-result-throw', 'broadcast-encode-exit',
                    'broadcast-decode-exit', 'broadcast-result-exit')
BROADCAST_OWNED = ('broadcast-cancel',)


class BroadcastPeer:
    """Independent CALLIT responder, used only in a private network namespace."""
    def __init__(self, case, acknowledgement=None):
        self.case = case
        self.acknowledgement = acknowledgement
        self.socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.socket.bind(('0.0.0.0', 111))
        self.socket.settimeout(0.1)
        self.stop = threading.Event()
        self.errors = []
        self.packets = []
        self.started = time.monotonic()
        self.worker = threading.Thread(target=self.serve)
        self.worker.start()

    def serve(self):
        try:
            while not self.stop.is_set():
                try:
                    packet, address = self.socket.recvfrom(65536)
                except socket.timeout:
                    continue
                if len(packet) % 4:
                    raise ValueError('unaligned CALLIT request')
                words = struct.unpack('!' + 'I' * (len(packet) // 4), packet)
                if words[1:6] != (0, 2, 100000, 2, 5):
                    raise ValueError(f'wrong CALLIT envelope: {words[:6]}')
                # AUTH_SYS must carry the caller identity, not AUTH_NONE. Walk
                # its bounded envelope independently of candidate XDR code.
                if words[6] != 1 or words[7] > 400:
                    raise ValueError('missing bounded AUTH_SYS credential')
                offset = 8 + (words[7] + 3) // 4
                name_length = words[9]
                identity = 10 + (name_length + 3) // 4
                if (name_length > 255 or identity + 3 > offset
                        or words[identity:identity + 2] != (os.geteuid(), os.getegid())
                        or words[identity + 2] > 16
                        or identity + 3 + words[identity + 2] != offset):
                    raise ValueError('incorrect AUTH_SYS identity or group extent')
                if words[offset:offset + 2] != (0, 0):
                    raise ValueError('unexpected call verifier')
                offset += 2
                argument = words[offset:]
                if argument[:4] != (PROGRAM, 1, 7, 4) or argument[4:] not in ((40,), (41,)):
                    raise ValueError(f'wrong CALLIT arguments: {argument}')
                self.packets.append((time.monotonic() - self.started, packet.hex(), argument[-1]))
                if self.case == 'broadcast-cancel':
                    if len(self.packets) == 1:
                        os.write(self.acknowledgement, b'R')
                    continue
                if argument[-1] == 41 or self.case in ('broadcast-send-only', 'broadcast-timeout'):
                    continue
                if self.case == 'broadcast-retry' and len(self.packets) == 1:
                    continue
                if self.case == 'broadcast-stale':
                    self.socket.sendto(struct.pack('!9I', words[0] ^ 0x100, 1, 0, 0, 0, 0, 33333, 4, 99), address)
                if self.case == 'broadcast-malformed':
                    self.socket.sendto(struct.pack('!2I', words[0], 1), address)
                    self.socket.sendto(struct.pack('!6I', words[0], 1, 0, 0, 0, 3), address)
                text = ('string' in self.case or 'decode-throw' in self.case or 'decode-exit' in self.case
                        or 'result-throw' in self.case or 'result-exit' in self.case)
                data = struct.pack('!I', 47)
                if text:
                    value = b'native-broadcast'
                    data = struct.pack('!I', len(value)) + value + bytes(-len(value) % 4)
                verifier = struct.pack('!2I', 99, 4) + b'auth' if self.case == 'broadcast-verifier' else bytes(8)
                port = 0xffffffff if self.case == 'broadcast-port-width' else 33333
                length = 0 if self.case == 'broadcast-advisory-length' else len(data)
                header = struct.pack('!3I', words[0], 1, 0) + verifier + struct.pack('!3I', 0, port, length)
                self.socket.sendto(header + data, address)
                if self.case in ('broadcast-multiple', 'broadcast-decode-error'):
                    second = 48 if self.case == 'broadcast-multiple' else 47
                    self.socket.sendto(header + struct.pack('!I', second), address)
        except BaseException as error:
            self.errors.append(repr(error))

    def close(self):
        self.stop.set()
        self.worker.join(timeout=2)
        if self.worker.is_alive():
            self.errors.append('broadcast peer did not stop')
        self.socket.close()


def broadcast_main(library, output, child):
    """Network configuration is permitted only after a verified namespace hop."""
    if not child:
        environment = os.environ.copy()
        environment['FRANKENLIBC_RPC_BROADCAST_PARENT_NS'] = str(os.stat('/proc/self/ns/net').st_ino)
        command = ['unshare', '--user', '--map-root-user', '--net', sys.executable,
                   str(Path(__file__).resolve()), str(library), '--output', str(output),
                   '--broadcast', '--broadcast-child']
        return subprocess.call(command, env=environment)
    parent = os.environ.get('FRANKENLIBC_RPC_BROADCAST_PARENT_NS')
    if parent is None or int(parent) == os.stat('/proc/self/ns/net').st_ino:
        raise RuntimeError('refusing broadcast setup outside a fresh network namespace')
    if socket.if_nameindex() != [(1, 'lo')]:
        raise RuntimeError('refusing broadcast setup in a namespace with existing interfaces')
    for command in (['ip', 'link', 'set', 'lo', 'up'],
                    ['ip', 'link', 'add', 'rpcprobe0', 'type', 'veth', 'peer', 'name', 'rpcprobe1'],
                    ['ip', 'address', 'add', '192.0.2.1/24', 'broadcast', '192.0.2.255', 'dev', 'rpcprobe0'],
                    ['ip', 'link', 'set', 'rpcprobe0', 'up'], ['ip', 'link', 'set', 'rpcprobe1', 'up']):
        subprocess.run(command, check=True)
    output.mkdir(parents=True, exist_ok=True)
    library_hash = hashlib.sha256(library.read_bytes()).hexdigest()
    source = Path(__file__).resolve().parents[1] / 'tests/integration/fixture_rpc_client_create.c'
    binaries = {False: output / 'fixture', True: output / 'fixture-unwind'}
    for cpp, binary in binaries.items():
        subprocess.run(['c++' if cpp else 'cc', '-x', 'c++' if cpp else 'c',
                        '-std=c++17' if cpp else '-std=c11', '-O2', '-Wall', '-Wextra', '-Werror',
                        str(source), '-ldl', '-pthread', '-o', str(binary)], check=True)
    clean = {key: value for key, value in os.environ.items()
             if not key.startswith(('FRANKENLIBC_', 'RPC_TEST_')) and key != 'LD_PRELOAD'}
    records = []

    def execute(mode, case, negative=False, cpp=False):
        env = clean.copy()
        if mode != 'host':
            env.update(FRANKENLIBC_TEST_LIBRARY=str(library), FRANKENLIBC_THREAD_NATIVE='0')
            if not negative:
                env.update(LD_PRELOAD=str(library), FRANKENLIBC_MODE=mode)
        acknowledgement = os.pipe() if case == 'broadcast-cancel' else None
        if acknowledgement:
            env['RPC_BROADCAST_ACK_FD'] = str(acknowledgement[0])
        peer = None if negative else BroadcastPeer(case, acknowledgement[1] if acknowledgement else None)
        started = time.monotonic()
        try:
            process = subprocess.run([str(binaries[cpp]), case], env=env, capture_output=True,
                                     pass_fds=(acknowledgement[0],) if acknowledgement else (),
                                     timeout=75 if case == 'broadcast-timeout' else 10)
            code, stdout, stderr = process.returncode, process.stdout, process.stderr
        except subprocess.TimeoutExpired as error:
            code, stdout, stderr = -999, error.stdout or b'', error.stderr or b''
        finally:
            if peer:
                peer.close()
            if acknowledgement:
                for descriptor in acknowledgement:
                    os.close(descriptor)
        duration = time.monotonic() - started
        if negative:
            passed = code == 113 and stderr == b'WRONG RPC PROVIDER\n'
            packets, errors = [], []
        else:
            packets, errors = peer.packets, peer.errors
            expected = 0 if ('encode-' in case or case in ('broadcast-large-args', 'broadcast-high-ids')) else (
                6 if case == 'broadcast-timeout' else 2 if case in ('broadcast-retry', 'broadcast-reentry') else 1)
            passed = (code, stdout, stderr) == (0, f'PASS {case}\n'.encode(), b'')
            passed = passed and not errors and len(packets) == expected
            if case in ('broadcast-retry', 'broadcast-timeout') and packets:
                passed = passed and len({row[1] for row in packets}) == 1
                for index, row in enumerate(packets):
                    # Scheduling can delay a send, but never authorize an early retry.
                    passed = passed and row[0] >= index * (index + 3) - 0.15
            if case == 'broadcast-timeout':
                passed = passed and 53.8 <= duration <= 65
        stem = f'{mode}-{case}'
        (output / f'{stem}.stdout').write_bytes(stdout)
        (output / f'{stem}.stderr').write_bytes(stderr)
        records.append(dict(mode=mode, case=case, passed=passed, returncode=code,
                            negative=negative, duration_seconds=duration,
                            packets=packets, peer_errors=errors))
        print(f'{"PASS" if passed else "FAIL"} {stem}: rc={code} packets={len(packets)}', flush=True)

    for case in BROADCAST:
        execute('host', case)
    execute('wrong-provider', 'broadcast-udp', negative=True)
    for mode in ('strict', 'hardened'):
        for case in BROADCAST:
            execute(mode, case)
        for case in BROADCAST_UNWIND:
            execute(mode, case, cpp=True)
        for case in BROADCAST_OWNED:
            execute(mode, case)
    final_hash = hashlib.sha256(library.read_bytes()).hexdigest()
    (output / 'results.json').write_text(json.dumps(dict(
        library=str(library), sha256=library_hash, sha256_after=final_hash,
        fixture_sha256=hashlib.sha256(source.read_bytes()).hexdigest(),
        isolated_network_namespace=os.stat('/proc/self/ns/net').st_ino,
        records=records), indent=2) + '\n')
    passed = all(row['passed'] for row in records) and library_hash == final_hash
    print(f'RPC broadcast: {"PASS" if passed else "FAIL"} ({len(BROADCAST)} live GNU cases, '
          f'{2 * (len(BROADCAST) + len(BROADCAST_UNWIND) + len(BROADCAST_OWNED))} candidate cases, 1 provider negative)', flush=True)
    return int(not passed)


def netname_transcript_rows(case, stdout):
    """Require the complete bounded C matrix before accepting a host oracle."""
    lines = stdout.splitlines()
    count = NETNAME_ROWS[case]
    if len(lines) != count + 1 or lines[-1] != f'PASS {case}'.encode():
        return 0
    for index, line in enumerate(lines[:-1]):
        fields = line.split()
        if len(fields) != 5 or fields[:2] != [b'NETNAME', str(index).encode()]:
            return 0
        try:
            status = int(fields[2])
            int(fields[3])  # errno is part of the byte-exact differential.
            payload = bytes.fromhex(fields[4].decode('ascii'))
        except (ValueError, UnicodeDecodeError):
            return 0
        if status not in (0, 1) or not payload or len(payload) > 256:
            return 0
        if len(fields[4]) != 2 * len(payload):
            return 0
        if status == 0 and len(payload) != 256:
            return 0
        if status == 1 and (payload[-1] != 0 or b'\0' in payload[:-1]):
            return 0
    return count


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
    parser.add_argument('--broadcast', action='store_true', help='run CALLIT broadcast in an isolated network namespace')
    parser.add_argument('--broadcast-child', action='store_true', help=argparse.SUPPRESS)
    args = parser.parse_args()
    library = args.library.resolve(strict=True)
    root = Path(__file__).resolve().parents[1]
    out = args.output.resolve()
    if args.broadcast:
        return broadcast_main(library, out, args.broadcast_child)
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
    netname_references = {}
    peers = Peers()

    def run(provider, case, env, negative=False, cpp=False):
        before = peers.counts.copy()
        try:
            process = subprocess.run([str(binaries[cpp]), case], env=env,
                                     capture_output=True, timeout=12)
            code, stdout, stderr = process.returncode, process.stdout, process.stderr
        except subprocess.TimeoutExpired as error:
            code, stdout, stderr = 124, error.stdout or b'', error.stderr or b''
        executed_rows = 0
        if negative:
            passed = (code, stdout, stderr) == (113, b'', b'WRONG RPC PROVIDER\n')
        elif case in NETNAME_ROWS:
            executed_rows = netname_transcript_rows(case, stdout)
            passed = code == 0 and stderr == b'' and executed_rows == NETNAME_ROWS[case]
            if provider == 'host':
                if passed:
                    netname_references[case] = stdout
            else:
                passed = passed and case in netname_references and stdout == netname_references[case]
        else:
            passed = (code, stdout, stderr) == (0, f'PASS {case}\n'.encode(), b'')
        wire = {key: value - before[key] for key, value in peers.counts.items()}
        if not negative and case.startswith('tcp'):
            passed = passed and wire['portmap_tcp'] > 0 and wire['tcp'] > 0
        if not negative and case in ('callrpc-high-ids', 'callrpc-version-overflow'):
            passed = passed and wire['portmap'] == 0
        if not negative and case in NETNAME_ROWS:
            passed = passed and all(count == 0 for count in wire.values())
        stem = f'{provider}-{case}'
        (out / f'{stem}.out').write_bytes(stdout)
        (out / f'{stem}.err').write_bytes(stderr)
        bucket = 'negative' if negative else 'host' if provider == 'host' else 'candidate'
        record = dict(provider=provider, case=case, passed=passed,
                      returncode=code, wire_exchanges=wire)
        if case in NETNAME_ROWS:
            record['netname_rows'] = executed_rows
        report[bucket].append(record)
        (out / 'report.json').write_text(json.dumps(report, indent=2) + '\n')
        print(f'{"PASS" if passed else "FAIL"} {provider}/{case}: rc={code}', flush=True)

    try:
        for case in HOST + DIAGNOSTICS + tuple(NETNAME_ROWS):
            run('host', case, clean)
        for case in DIAGNOSTIC_UNWIND:
            run('host', case, clean, cpp=True)
        for case in ('unknown-protocol',) + tuple(NETNAME_ROWS):
            run('wrong-provider-host', case,
                dict(clean, FRANKENLIBC_TEST_LIBRARY=str(library)), True)
            run('wrong-provider-forced', case,
                dict(clean, LD_PRELOAD=str(library), FRANKENLIBC_TEST_LIBRARY=str(library),
                     RPC_TEST_FORCE_HOST='1'), True)
        for mode in ('strict', 'hardened'):
            env = dict(clean, LD_PRELOAD=str(library), FRANKENLIBC_TEST_LIBRARY=str(library),
                       FRANKENLIBC_MODE=mode, FRANKENLIBC_THREAD_NATIVE='0')
            for case in HOST + DIAGNOSTICS + tuple(NETNAME_ROWS) + OWNED:
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
