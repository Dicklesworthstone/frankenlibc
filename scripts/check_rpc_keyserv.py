#!/usr/bin/env python3
"""Exercise native keyserver calls against independent Unix and UDP peers.

Each caller loads its provider before entering a private chroot. The peer parses
the actual RPC envelope and key-protocol arguments without using candidate XDR.
GNU's versioned libc is the oracle for all nine APIs. The eight credentialed
APIs use private Unix sockets. KEY_GEN uses exclusively bound loopback UDP
portmapper port 111 and an ephemeral keyserver port; a busy port fails the run.
No system keyserver, identity configuration, or existing socket is modified.
"""
import argparse
import ctypes as C
import hashlib
import json
import os
from pathlib import Path
import signal
import socket
import struct


LIBC = C.CDLL('libc.so.6')
KEY = b'0123456789abcdef' * 3
NAME = b'unix.123@franken.invalid'
OLD = b'12345678'
NEW = b'ABCDEFGH'
PUBLIC = b'public\0bytes'
APIS = {
    'key_setsecret': (1, 1),
    'key_encryptsession': (1, 2),
    'key_decryptsession': (1, 3),
    'key_gendes': (1, 4),
    'key_encryptsession_pk': (2, 6),
    'key_decryptsession_pk': (2, 7),
    'key_setnet': (2, 8),
    'key_secretkey_is_set': (2, 9),
    'key_get_conv': (2, 10),
}


class NetObject(C.Structure):
    _fields_ = [('length', C.c_uint), ('bytes', C.c_void_p)]


class NetworkArgument(C.Structure):
    _fields_ = [('private', C.c_char * 48), ('public', C.c_char * 48), ('name', C.c_char_p)]


def versioned(name):
    lookup = LIBC.dlvsym
    lookup.argtypes = [C.c_void_p, C.c_char_p, C.c_char_p]
    lookup.restype = C.c_void_p
    pointer = lookup(LIBC._handle, name.encode(), b'GLIBC_2.2.5')
    if not pointer:
        raise RuntimeError(f'missing GNU oracle {name}@GLIBC_2.2.5')
    return pointer


def verify_provider(pointer, library):
    class DlInfo(C.Structure):
        _fields_ = [('name', C.c_char_p), ('base', C.c_void_p), ('symbol', C.c_char_p), ('address', C.c_void_p)]
    lookup = LIBC.dladdr
    lookup.argtypes = [C.c_void_p, C.POINTER(DlInfo)]
    lookup.restype = C.c_int
    info = DlInfo()
    if not lookup(pointer, C.byref(info)) or not info.name or not os.path.samefile(library, info.name):
        raise RuntimeError('WRONG KEYSERVER PROVIDER')


def word(value):
    return struct.pack('!I', value)


def counted(value):
    return word(len(value)) + value + b'\0' * (-len(value) % 4)


def exact(connection, length):
    result = b''
    while len(result) < length:
        data = connection.recv(length - len(result))
        if not data:
            raise EOFError('peer closed an incomplete record')
        result += data
    return result


def receive_record(connection):
    result = b''
    for _ in range(32):
        marker = struct.unpack('!I', exact(connection, 4))[0]
        length = marker & 0x7fffffff
        if len(result) + length > 65536:
            raise RuntimeError('oversized keyserver request')
        result += exact(connection, length)
        if marker >> 31:
            return result
    raise RuntimeError('too many request fragments')


def expected_arguments(api):
    if api in ('key_setsecret', 'key_get_conv'):
        return KEY
    if api in ('key_encryptsession', 'key_decryptsession'):
        return counted(NAME) + OLD
    if api.endswith('_pk'):
        return counted(NAME) + counted(PUBLIC) + OLD
    if api == 'key_setnet':
        return KEY + b'A' * 48 + counted(NAME)
    return b''


def unpack_request(request):
    header = struct.unpack('!6I', request[:24])
    offset = 24
    credentials = []
    for _ in range(2):
        flavor, length = struct.unpack('!2I', request[offset:offset + 8])
        assert length <= 400 and offset + 8 + length <= len(request)
        credentials.append((flavor, request[offset + 8:offset + 8 + length]))
        offset += 8 + (length + 3) // 4 * 4
    return header, credentials, request[offset:]


def inspect_request(request, api, uid):
    header, credentials, arguments = unpack_request(request)
    assert header[1:] == (0, 2, 100029, *APIS[api]), (api, header)
    if api == 'key_gendes':
        assert credentials == [(0, b''), (0, b'')]
    else:
        # Ignore only the time stamp. GNU keyserv uses an empty machine name,
        # effective UID, gid zero, and no supplementary group list.
        assert credentials[0][0] == 1
        assert len(credentials[0][1]) == 20
        assert credentials[0][1][4:] == word(0) + word(uid) + word(0) + word(0)
        assert credentials[1] == (0, b'')
    assert arguments == expected_arguments(api), (api, arguments.hex())
    return header[0], {'header': header, 'arguments': arguments.hex(), 'uid': uid}


def rpc_reply(xid, payload, status=0):
    return word(xid) + word(1) + word(0) + word(0) + word(0) + word(status) + payload


def reply_payload(api, variant):
    if variant == 'error':
        return word(2)
    if api == 'key_gendes':
        result = NEW
    elif api in ('key_setsecret', 'key_setnet'):
        result = word(0)
    elif api == 'key_secretkey_is_set':
        private = b'\0' * 48 if variant == 'empty-secret' else KEY
        result = word(0) + private + b'A' * 48 + counted(NAME)
    else:
        result = word(0) + NEW
    return result[:-1] if variant == 'truncated' else result


def expected_result(api, variant):
    failed = variant in ('error', 'truncated', 'disconnect')
    if api == 'key_secretkey_is_set':
        return (int(not failed and variant != 'empty-secret'), OLD)
    if failed:
        return (-1, OLD)
    if api == 'key_setnet':
        return (1, OLD)
    if api == 'key_setsecret':
        return (0, OLD)
    return (0, NEW)


def load(spec):
    if spec['provider'] == 'gnu':
        return LIBC, versioned(spec['api'])
    provider = C.CDLL(spec['library'])
    pointer = C.cast(getattr(provider, spec['api']), C.c_void_p).value
    if spec.get('force_host'):
        pointer = versioned(spec['api'])
    verify_provider(pointer, spec['library'])
    initialize = getattr(provider, 'keyserv_diagnostic_initialize', None)
    if initialize:
        assert spec['diagnostic'], 'diagnostic DSO requires explicit --diagnostic'
        initialize()
    return provider, pointer


def invoke(pointer, api):
    output = C.create_string_buffer(b'[' + OLD + b']', 10)
    key = C.create_string_buffer(KEY, 48)
    public = C.create_string_buffer(PUBLIC, len(PUBLIC))
    netobj = NetObject(len(PUBLIC), C.addressof(public))
    network = NetworkArgument(KEY, b'A' * 48, NAME)
    block = C.addressof(output) + 1
    types, arguments = {
        'key_setsecret': ([C.c_void_p], [key]),
        'key_encryptsession': ([C.c_char_p, C.c_void_p], [NAME, block]),
        'key_decryptsession': ([C.c_char_p, C.c_void_p], [NAME, block]),
        'key_encryptsession_pk': ([C.c_char_p, C.c_void_p, C.c_void_p], [NAME, C.byref(netobj), block]),
        'key_decryptsession_pk': ([C.c_char_p, C.c_void_p, C.c_void_p], [NAME, C.byref(netobj), block]),
        'key_gendes': ([C.c_void_p], [block]),
        'key_get_conv': ([C.c_void_p, C.c_void_p], [key, block]),
        'key_setnet': ([C.c_void_p], [C.byref(network)]),
        'key_secretkey_is_set': ([], []),
    }[api]
    result = C.CFUNCTYPE(C.c_int, *types)(pointer)(*arguments)
    assert output.raw[:1] == b'[' and output.raw[9:] == b']'
    assert key.raw == KEY and public.raw == PUBLIC
    assert network.private == KEY and network.public == b'A' * 48
    return result, output.raw[1:9]


def run(spec, root):
    (root / 'var/run').mkdir(parents=True)
    udp = spec['api'] == 'key_gendes'
    generator = None
    if udp:
        listener = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        # No reuse option: never attach to or displace a running rpcbind.
        listener.bind(('127.0.0.1', 111))
        generator = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        generator.bind(('127.0.0.1', 0))
        generator.settimeout(5)
    else:
        listener = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        # A relative bind also supports arbitrarily long retained report paths.
        directory = os.open('.', os.O_RDONLY | os.O_DIRECTORY)
        try:
            os.chdir(root / 'var/run')
            listener.bind('keyservsock')
            os.chmod('keyservsock', 0o666)
        finally:
            os.fchdir(directory)
            os.close(directory)
        listener.listen(4)
    listener.settimeout(5)
    read_fd, write_fd = os.pipe()
    pid = os.fork()
    if pid == 0:
        os.close(read_fd)
        listener.close()
        if generator:
            generator.close()
        signal.alarm(12)
        try:
            os.environ['FRANKENLIBC_MODE'] = spec['mode']
            provider, pointer = load(spec)
            proc = os.open('/proc/self/fd', os.O_RDONLY | os.O_DIRECTORY)
            os.chroot(root)
            os.chdir('/')
            if spec['uid'] != os.geteuid():
                os.setegid(65533)
                os.seteuid(spec['uid'])
            before = len(os.listdir(proc))
            rows = []
            for variant in spec['variants']:
                status, block = invoke(pointer, spec['api'])
                expected = expected_result(spec['api'], variant)
                assert (status, block) == expected, (spec['api'], variant, status, block.hex(), expected)
                rows.append({'variant': variant, 'return': status, 'block': block.hex()})
            after = len(os.listdir(proc))
            # GNU caches one credentialed Unix CLIENT in caller TLS. The
            # native helper deliberately owns and closes its client per call;
            # GNU's separate generator path also destroys its UDP CLIENT.
            expected_extra = int(spec['provider'] == 'gnu' and not udp)
            assert after == before + expected_extra, ('descriptor ownership', before, after)
            os.close(proc)
            result = {'rows': rows, 'descriptors_before': before, 'descriptors_after': after}
        except BaseException as error:
            result = {'error': repr(error)}
        os.write(write_fd, json.dumps(result).encode())
        os._exit(0)
    os.close(write_fd)
    packets = []
    peer_error = None
    try:
        if not spec.get('force_host'):
            for variant in spec['variants']:
                if udp:
                    request, peer = listener.recvfrom(65536)
                    header, credentials, arguments = unpack_request(request)
                    assert header[1:] == (0, 2, 100000, 2, 3)
                    assert credentials == [(0, b''), (0, b'')]
                    assert arguments == word(100029) + word(1) + word(17) + word(0)
                    listener.sendto(rpc_reply(header[0], word(generator.getsockname()[1])), peer)
                    request, peer = generator.recvfrom(65536)
                    xid, packet = inspect_request(request, spec['api'], spec['uid'])
                    packet['portmapper_header'] = header
                    packets.append(packet)
                    reply = rpc_reply(xid, b'', 1) if variant == 'error' else rpc_reply(xid, reply_payload(spec['api'], variant))
                    generator.sendto(reply, peer)
                    continue
                connection, _ = listener.accept()
                with connection:
                    connection.settimeout(5)
                    xid, packet = inspect_request(receive_record(connection), spec['api'], spec['uid'])
                    packets.append(packet)
                    if variant == 'disconnect':
                        continue
                    reply = rpc_reply(xid, reply_payload(spec['api'], variant))
                    if variant == 'fragmented':
                        connection.sendall(word(7) + reply[:7] + word(0x80000000 | (len(reply) - 7)) + reply[7:])
                    else:
                        connection.sendall(word(0x80000000 | len(reply)) + reply)
    except BaseException as error:
        peer_error = repr(error)
    finally:
        listener.close()
        if generator:
            generator.close()
    data = b''
    while True:
        chunk = os.read(read_fd, 4096)
        if not chunk:
            break
        data += chunk
    os.close(read_fd)
    _, status = os.waitpid(pid, 0)
    result = json.loads(data) if data else {'error': 'caller produced no result'}
    return {'spec': spec, 'caller': result, 'exit_status': status, 'packets': packets, 'peer_error': peer_error}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('library', type=Path)
    parser.add_argument('--output', required=True, type=Path)
    parser.add_argument('--diagnostic', action='store_true')
    args = parser.parse_args()
    if os.geteuid() != 0:
        parser.error('root is required only for private caller chroots')
    library = args.library.resolve(strict=True)
    output = args.output.resolve()
    output.mkdir(parents=True, exist_ok=False)
    library_hash = hashlib.sha256(library.read_bytes()).hexdigest()
    rows = []
    failures = []
    sequence = 0

    def execute(provider, mode, api, variants, uid=0, force_host=False):
        nonlocal sequence
        spec = dict(provider=provider, mode=mode, api=api, variants=variants,
                    uid=uid, library=str(library), diagnostic=args.diagnostic,
                    force_host=force_host)
        row = run(spec, output / f'case-{sequence:03d}')
        sequence += 1
        rows.append(row)
        if force_host:
            passed = row['exit_status'] == 0 and 'WRONG KEYSERVER PROVIDER' in row['caller'].get('error', '') and not row['packets']
        else:
            passed = row['exit_status'] == 0 and not row['peer_error'] and 'error' not in row['caller'] and len(row['packets']) == len(variants)
        if not passed:
            failures.append(row)

    for api in APIS:
        for variant in ('success', 'error', 'truncated'):
            execute('gnu', 'strict', api, [variant])
    for mode in ('strict', 'hardened'):
        for api in APIS:
            for variant in ('success', 'error', 'truncated'):
                execute('candidate', mode, api, [variant])
        execute('candidate', mode, 'key_secretkey_is_set', ['empty-secret'])
        execute('candidate', mode, 'key_encryptsession', ['disconnect', 'fragmented', 'success'])
        execute('candidate', mode, 'key_setnet', ['success'], uid=65534)
        execute('candidate', mode, 'key_encryptsession', ['success'], force_host=True)
    assert hashlib.sha256(library.read_bytes()).hexdigest() == library_hash
    report = {'library': str(library), 'sha256': library_hash,
              'proof_class': 'diagnostic adapter' if args.diagnostic else 'release DSO',
              'gnu_calls': sum(len(row['caller'].get('rows', [])) for row in rows if row['spec']['provider'] == 'gnu'),
              'candidate_calls': sum(len(row['caller'].get('rows', [])) for row in rows if row['spec']['provider'] == 'candidate'),
              'provider_controls': sum(row['spec']['force_host'] for row in rows),
              'key_gendes_scope': 'GNU-compatible loopback UDP and AUTH_NONE with portmapper discovery',
              'failures': len(failures), 'rows': rows}
    (output / 'report.json').write_text(json.dumps(report, indent=2) + '\n')
    print(json.dumps({key: value for key, value in report.items() if key != 'rows'}, indent=2))
    if failures:
        raise SystemExit(1)


if __name__ == '__main__':
    main()
